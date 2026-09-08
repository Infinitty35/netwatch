<p align="center">
  <h1 align="center">NetWatch</h1>
  <p align="center">
    <strong>A network monitor for the terminal that names the process behind every connection, reads TLS you hold the keys to, and tells you what is wrong and how to fix it.</strong>
  </p>
  <p align="center">
    <a href="https://crates.io/crates/netwatch-tui"><img src="https://img.shields.io/crates/v/netwatch-tui.svg" alt="crates.io"></a>
    <a href="https://crates.io/crates/netwatch-tui"><img src="https://img.shields.io/crates/d/netwatch-tui.svg" alt="downloads"></a>
    <a href="https://github.com/matthart1983/netwatch/releases"><img src="https://img.shields.io/github/v/release/matthart1983/netwatch" alt="Release"></a>
    <a href="https://repology.org/project/netwatch-tui/versions"><img src="https://repology.org/badge/tiny-repos/netwatch-tui.svg" alt="Packaging status"></a>
    <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue" alt="Platform">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  </p>
  <p align="center">
    <a title="Tool of The Week on Terminal Trove" href="https://terminaltrove.com/netwatch/"><img src="docs/media/terminal_trove_totw_badge.svg" alt="Terminal Trove Tool of The Week" height="54" /></a>
  </p>
</p>

<p align="center">
  <img src="docs/media/demo-dense.gif" alt="NetWatch's dense view: a mirrored braille throughput graph with download above the axis and upload below, per-interface rates with sparklines, four-hop latency budgets, and a connection table with the selected socket's kernel TCP state" width="900">
</p>

<p align="center">
  <em><code>netwatch --view dense</code>. Four boxes, no chrome, every keybind on a border. Download grows up from the axis, upload grows down.</em>
</p>

One binary, no config. `sudo netwatch` and you have live capture with L7 decode, the program behind each socket, and a diagnostic engine that opens an issue when a learned baseline breaks and closes it when the fix holds.

## Install

```bash
brew install netwatch                 # macOS / Linux
nix-shell -p netwatch                 # NixOS / Nix
paru -S netwatch-tui-bin              # Arch
scoop install netwatch                # Windows (needs Npcap)
cargo install netwatch-tui            # anywhere with Rust and libpcap headers
```

Prebuilt binaries, including static Linux builds with libpcap bundled, are on the [releases page](https://github.com/matthart1983/netwatch/releases/latest). Windows needs [Npcap](https://npcap.com/#download) installed first; building from source needs `libpcap-dev` (Debian), `libpcap-devel` (Fedora) or `libpcap` (Arch). Details in the [install reference](docs/REFERENCE.md#permissions).

## Run

```bash
netwatch              # interfaces, connections, config. No privileges.
sudo netwatch         # adds packet capture and health probes
netwatch --lite       # one 80x24 screen
netwatch --view dense # four boxes, 130x44 or larger
```

`1` to `9` and `0` switch tabs, `V` cycles the three views, `?` shows every key. To run without sudo on Linux, grant the capabilities once: `sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$(which netwatch)"` ([why and when to repeat it](docs/REFERENCE.md#running-without-sudo-linux)).

## What it does

**Diagnose (tab `9`).** Per-metric baselines learned over 30 minutes and scoped to the network that taught them. 25 rules, all active as of 0.30.3, with a suppression graph so a dead gateway is one finding with its consequences underneath. Each cause is ranked by the checks that separated it from the others. Fixes are key-bound, journal before they write, and revert on the next start if the process died mid-write. An issue closes only when the rule's own success condition has held. No model involved. [How it works](docs/REFERENCE.md#how-it-works), [the design](docs/DESIGN-0.30.md#9-9-diagnose).

<p align="center">
  <img src="docs/media/demo-diagnose.gif" alt="A slow resolver at 33 times its baseline, three ranked causes, a key-bound fix, and the issue closing itself once dns.rtt_p50 has held under 5ms for 60 seconds" width="860">
</p>

**Decrypt TLS you control.** Point any client's `SSLKEYLOGFILE` at NetWatch and the plaintext of its TLS 1.3 sessions decodes in the Packets tab. Same mechanism as Wireshark, so it only works for traffic you hold the keys to. [TLS decryption](docs/REFERENCE.md#tls-13--12-decryption).

```bash
sudo netwatch                                              # open Packets (4)
SSLKEYLOGFILE=/tmp/keys curl https://example.com           # any client that exports keys
# filter the tab with:  decrypted:true
```

**Egress drift.** The Egress tab (`0`) learns which hosts, autonomous systems and ports each process reaches. `Enter` promotes that baseline to a rule; the next new destination arrives as `drift` with an alert. It observes and never blocks. Verdicts are `sni`, `ip`, `asn`, `ech`, `drift`, `no rule` and `undeclared` under `strict = true`, because "matched by AS" admits everything a hyperscaler runs and the table should say so. [Rule language and export schema](docs/egress-linter-plan.md).

**Process attribution.** `ss`/`lsof` on every platform, PKTAP on macOS, and an optional eBPF kprobe on Linux (`ebpf` feature) that catches flows too short for polling. [Permissions](docs/REFERENCE.md#permissions).

**Threat detection.** C2 beaconing, port scans and DNS tunnelling run in the background. A critical alert freezes the flight recorder so the bundle exists before you look. JA4 fingerprints each TLS and QUIC handshake so you can pivot to every flow from the same client. [Security and forensics](docs/REFERENCE.md#security--forensics), [flight recorder](docs/REFERENCE.md#flight-recorder), [JA4](docs/REFERENCE.md#threat-hunting-with-ja4).

**Sandboxed.** After setup, NetWatch drops privileges and confines itself to a Landlock allow-list on Linux. It parses hostile traffic and cannot read your SSH keys.

## The tabs

| # | Tab | Shows |
|---|-----|-------|
| 1 | Dashboard | Latency tiles, mirrored throughput, the link carrying it, connections rolled up per process |
| 2 | Connections | Every socket with process, PID, state, GeoIP, RTT, retransmits |
| 3 | Interfaces | Addresses, MTU, rates, errors, drops |
| 4 | Packets | Live decode, TLS 1.3 decryption, JA4, stream tracking, display filters, PCAP export |
| 5 | Stats | Protocol breakdown and handshake-timing histogram |
| 6 | Topology | Machine, gateway, DNS, top hosts, traceroute |
| 7 | Timeline | Connections by TCP state, with alerts |
| 8 | Processes | Bandwidth per process |
| 9 | Diagnose | Issue, cause, fix, verified close. `report.md` from the same objects |
| 0 | Egress | Learned destinations, promoted policy, drift |

[Every keybinding](docs/REFERENCE.md#keyboard-controls), [display filters](docs/REFERENCE.md#display-filters), [decoders](docs/REFERENCE.md#deep-packet-inspection), [themes](docs/REFERENCE.md#themes), [configuration](docs/REFERENCE.md#configuration).

## Three views, one capture

`V` cycles between them without a restart; the collectors keep running.

**Full** is the ten tabs above.

**Lite** (`--lite`) fits 80x24: throughput, gateway/DNS/internet reachability, top talkers, six keys. For an SSH session to a Pi or a tmux split.

**Dense** (`--view dense`) is the hero image. It needs 130x44 and grows into anything larger. Throughput is braille at two samples per cell, coloured by height so a spike reads before you check the axis. The connection table hoists the selected row's detail, including kernel `cwnd`, `ssthresh`, `mss` and `rwnd`, into the top of its own box. `1` to `4` zoom a box to the whole screen. [Dense and Lite](docs/DESIGN-0.30.md#8-dense-and-lite).

## Docs

| | |
|---|---|
| [Reference](docs/REFERENCE.md) | Keys, filters, decoders, configuration, permissions, security |
| [Design 0.30](docs/DESIGN-0.30.md) | Why the screens look the way they do |
| [Architecture](docs/WIKI.md) | Runtime, source map, permissions model, how to build and verify |
| [Egress linting](docs/egress-linter-plan.md) | Observe, promote, warn |
| [AI Insights](docs/INSIGHTS.md) | Optional LLM commentary inside Diagnose, off by default |
| [Prometheus export](docs/observability-export.md) | Exposed metrics and scrape config |
| [Changelog](CHANGELOG.md) | Every release |

## Related

[SysWatch](https://github.com/matthart1983/syswatch) and [DiskWatch](https://github.com/matthart1983/diskwatch) share the chrome. [ESSH](https://github.com/matthart1983/essh) is a Rust SSH client with the same look. [NetWatch Cloud](https://www.netwatchlabs.com) is hosted fleet monitoring built on the MIT [agent](https://github.com/matthart1983/netwatch-agent), [SDK](https://github.com/matthart1983/netwatch-sdk) and [dashboard](https://github.com/matthart1983/netwatch-dashboard).

## Thanks

I packaged none of this. Dominiquini and kemelzaidan maintain [`netwatch-tui`](https://aur.archlinux.org/packages/netwatch-tui) and [`netwatch-tui-bin`](https://aur.archlinux.org/packages/netwatch-tui-bin) on the AUR, tomasrivera the [nixpkgs package](https://github.com/NixOS/nixpkgs/blob/nixos-unstable/pkgs/by-name/ne/netwatch/package.nix), [scillidan](https://github.com/scillidan) the [Scoop entry](https://github.com/ScoopInstaller/Main/blob/master/bucket/netwatch.json), and the Homebrew maintainers took the formula into core. File packaging problems with them and netwatch bugs here.

[@lamchau](https://github.com/lamchau), [@fdncred](https://github.com/fdncred) and [@PeteE](https://github.com/PeteE) sent patches. Everyone who opened an issue with a repro or argued with a design decision is the reason the output is right on more terminals than mine.

## Contributing

[Discussions](https://github.com/matthart1983/netwatch/discussions), [issues](https://github.com/matthart1983/netwatch/issues), [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
