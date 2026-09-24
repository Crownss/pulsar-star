# pulsar-star

A small Rust learning project for experimenting with **layer-2 (Ethernet) networking** and **ARP** on Linux using the [`pnet`](https://crates.io/crates/pnet) crate. It discovers hosts on the local subnet and emits ARP packets to them on a loop, with the send thread pinned to a specific CPU core.

> ⚠️ **Authorized use only.** This tool sends raw ARP frames on the network you run it on. Only use it on networks you own or are explicitly permitted to test. Sending crafted ARP traffic on networks you don't control may be illegal and can disrupt other devices.

## What it does

1. **Host discovery** — shells out to `nmap -sn <gateway_ip>/24` (the `-g` gateway, `/24`) to enumerate live hosts on the subnet, then drops the hard-coded address `192.168.1.1` from the result.
2. **Interface selection** — picks the first active, non-loopback interface that has a MAC and an IPv4 address, and reads its source IP/MAC.
3. **CPU pinning** — spawns a sender thread and pins it to the core given by `-t` (default `1`) via `sched_setaffinity` (Linux) for more consistent timing; the main thread prints a progress indicator while it runs.
4. **Send loop** — for every discovered target IP (skipping its own address), builds an Ethernet + ARP frame and broadcasts it, then sleeps for a configurable interval before repeating.

## Requirements

- Linux (uses `libc` CPU-affinity syscalls and raw layer-2 sockets)
- Rust toolchain with **edition 2024** support
- [`nmap`](https://nmap.org/) available on `PATH` (used for host discovery)
- Elevated privileges (`CAP_NET_RAW` / root) to open a raw datalink channel

## Build

```sh
cargo build --release
```

## Run

Raw socket access typically needs root:

```sh
sudo ./target/release/pulsar-star
```

### Options

| Flag                              | Description                                                      | Default       |
| --------------------------------- | ---------------------------------------------------------------- | ------------- |
| `-s`, `--sleep <µs>` (optional)   | Delay in milliseconds between each full sweep of the target list | `100`         |
| `-g`, `--gateway <ip>` (optional) | arp gateway                                                      | `192.168.1.1` |
| `-t`, `--thread <num>` (optional) | which thread to pinned the proccess                              | `1`           |

Example:

```sh
sudo ./target/release/pulsar-star -s 300 -g 192.168.0.0 -t 1
```

## Project layout

```
.
├── Cargo.toml      # package metadata and dependencies
├── src/
│   └── main.rs     # entry point + all logic
└── README.md
```

## Dependencies

- `pnet` (with the `pcap` feature) — datalink channels and packet building
- `clap` / `clap_derive` — command-line argument parsing
- `libc` — CPU affinity syscalls

## Status(No AI involved)

Early-stage / experimental personal project.
