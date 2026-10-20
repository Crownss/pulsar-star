# pulsar-star

A small Rust learning project for experimenting with **layer-2 (Ethernet) networking** and **ARP** on Linux using the [`pnet`](https://crates.io/crates/pnet) crate. It discovers hosts on the local subnet and continuously broadcasts forged **ARP replies** (gratuitous ARP) to poison their caches, with the send thread pinned to a specific CPU core.

> ⚠️ **Authorized use only.** This is an ARP cache-poisoning tool: it forges ARP replies that impersonate the gateway (and other hosts) to redirect traffic on the LAN. Only run it on networks you own or are explicitly authorized to test. Doing this on networks you don't control is almost certainly illegal and will disrupt other devices.

## What it does

1. **Host discovery** — shells out to `nmap -sn <gateway>/24` (the `-g` gateway, `/24`) to enumerate live hosts on the subnet, then drops the gateway itself, this machine's own IP, and any `-w/--whitelist` addresses from the target list. Exits if nothing is left.
2. **Interface selection** — picks the first active, non-loopback interface that has a MAC and an IPv4 address, and reads its source IP/MAC (cached in `LazyLock` statics).
3. **CPU pinning** — spawns a sender thread and pins it to the core given by `-t` (default `1`) via `sched_setaffinity`; the main thread prints a progress indicator while it runs.
4. **Poison loop** — the sender thread busy-waits (`_mm_pause`) and, every `--sleep` milliseconds, sweeps the target list. For each host it broadcasts **two** forged ARP **replies** — one aimed at the victim and one aimed at the gateway — binding the attacker's MAC to those IPs (bidirectional cache poisoning). With `--no-sleep` the interval is ignored and the sweep fires on every iteration (continuous flood).

## Requirements

- Linux (uses `libc` CPU-affinity syscalls and raw layer-2 sockets)
- **x86_64 CPU** (uses the `_mm_pause` intrinsic in the spin loop)
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

| Flag                              | Description                                                                 | Default       |
| --------------------------------- | --------------------------------------------------------------------------- | ------------- |
| `-s`, `--sleep <ms>`              | Milliseconds between each full sweep of the target list                     | `1000`        |
| `-g`, `--gateway <ip>`            | Gateway IP — also sets the `/24` subnet scanned and is excluded as a target | `192.168.1.1` |
| `-t`, `--thread <num>`            | CPU core the sender thread is pinned to                                     | `1`           |
| `-w`, `--whitelist <ip> [ip ...]` | One or more IPs to exclude from the target list                             | _(none)_      |
| `--no-sleep`                      | No time to wait for each full sweep (overflooding)                          | `false`       |

Example:

```sh
sudo ./target/release/pulsar-star -s 1000 -g 192.168.0.1 -t 1 -w 192.168.0.50 192.168.0.51
```

## Project layout

```
.
├── Cargo.toml      # package metadata, dependencies, release profile (thin LTO)
├── src/
│   └── main.rs     # entry point + all logic
└── README.md
```

## Dependencies

- `pnet` (with the `pcap` feature) — datalink channels and packet building
- `clap` / `clap_derive` — command-line argument parsing
- `libc` — CPU affinity syscalls

## Status (No AI involved)

Early-stage / experimental personal project.
