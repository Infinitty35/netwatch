<p align="center">
  <h1 align="center">NetWatch</h1>
  <p align="center">
    <strong>See what your network is actually doing — live, in your terminal.</strong><br>
    <em>A network monitor that reads encrypted traffic, names the process behind every connection, catches malware calling home — and tells you what's wrong, why, and how to fix it. One binary. Zero config.</em>
  </p>
  <p align="center">
    <a href="https://crates.io/crates/netwatch-tui"><img src="https://img.shields.io/crates/v/netwatch-tui.svg" alt="crates.io"></a>
    <a href="https://crates.io/crates/netwatch-tui"><img src="https://img.shields.io/crates/d/netwatch-tui.svg" alt="downloads"></a>
    <a href="https://github.com/matthart1983/netwatch/releases"><img src="https://img.shields.io/github/v/release/matthart1983/netwatch" alt="Release"></a>
    <a href="https://repology.org/project/netwatch-tui/versions"><img src="https://repology.org/badge/tiny-repos/netwatch-tui.svg" alt="Packaging status"></a>
    <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-blue" alt="Platform">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  </p>
  <p align="center">
    <a title="Tool of The Week on Terminal Trove" href="https://terminaltrove.com/netwatch/"><img src="docs/media/terminal_trove_totw_badge.svg" alt="Terminal Trove Tool of The Week" height="54" /></a>
  </p>
</p>

<p align="center">
  <img src="docs/media/demo-diagnose.gif" alt="NetWatch Diagnose: a slow DNS resolver at 33× its learned baseline, three ranked causes with the checks that separated them, a key-bound fix that switches the session resolver, and the issue auto-closing once dns.rtt_p50 has held under 5ms for 60 seconds" width="860">
</p>

<p align="center">
  <em>The headline of v0.30. Issue → probable cause → remediation → verified close. The engine is never
  told the problem is fixed; it watches the resolver and closes the issue when
  <code>dns.rtt_p50 &lt; 5ms</code> has held for 60s. Recorded with
  <code>netwatch --demo</code>, which replays a scenario through the real engine
  and says so on every frame.</em>
</p>

---

Most network tools answer one question — *"what's using my bandwidth?"* — and stop. NetWatch keeps going. It decodes the protocols on the wire, tells you **which program** opened each connection, and watches for the patterns that mean trouble — a port scan, malware beaconing to a command server, data sneaking out over DNS. When something looks wrong, one keypress freezes a portable evidence bundle you can attach to a bug report.

And when something *is* wrong it doesn't stop at the graph. It names the issue, ranks the explanations by the checks that ruled the others out, offers the fix, and closes the issue itself once its own success condition holds.

Think of it as **one zero-config binary that does the job of a bandwidth meter, the triage view of Wireshark, a lightweight intrusion detector, and the engineer who reads the output** — without leaving the terminal.

It scales to the question you're asking — in both directions: [`--view dense`](#dense-view) fills a big terminal with four zero-chrome boxes, and `netwatch --lite` is [one 80×24 screen](#lite-view) for *"what's using my network right now?"*; the full ten-tab view is there when the answer is "something I need to investigate" — one keypress apart, sharing the same live capture.

**Made for** blue-teamers, incident responders, SREs, and homelabbers who need to see what's happening *right now* — not parse a capture file an hour later.

<samp>920+ tests · Landlock-sandboxed (Linux) · safely parses hostile traffic</samp>

And the part no other terminal tool does at all: NetWatch learns what each program on the machine talks to, turns that observed baseline into a policy with one keypress, and tells you the moment a program starts talking somewhere new.

That diagnosis is deterministic — no model involved. Baselines are learned per
metric and scoped to the network that taught them, 25 catalogued rules decide
what counts as wrong, and each explanation is ranked by the checks that
separated it from the others.

## Why NetWatch

- 🩺 **Get told what's wrong, not just what's happening** — NetWatch learns what normal looks like on *this* network, then names the issue, ranks the probable causes by the checks that ruled the others out, and offers a fix it can apply and reverse. It closes the issue itself when the rule's own success condition holds — the engine is never told the problem is fixed, it watches until it is. Deterministic: no model, no cloud, and it says which of its rules it cannot yet evaluate rather than implying full coverage.
- 🔓 **Read encrypted traffic you control** — point a browser or app's `SSLKEYLOGFILE` at NetWatch and watch the plaintext of its TLS 1.3 sessions decode live, the same way Wireshark does it. No proxy, no certificates, nothing in the middle.
- 🛰️ **Learn what every program talks to, then get told when it changes** — NetWatch watches which destinations each process reaches (hostname from the ClientHello, autonomous system, port), and one keypress promotes that observed baseline into an egress policy. From then on it warns when a program starts talking somewhere new. That is the sentence a firewall ruleset cannot express: *`curl` used to reach only `api.github.com`, and today it reached something else.* Observe-only — it never blocks.
- 🧬 **Fingerprint the software behind a connection** — JA4 turns each TLS/QUIC handshake into a stable fingerprint, so you can recognize a specific client — or a specific piece of malware — *even though the traffic is encrypted*, the way you'd recognize a browser by its user-agent. Pivot on a fingerprint to find every other flow from the same software.
- 🚨 **Catch malware calling home** — built-in detection for C2 beaconing (regular, low-jitter check-ins), port scans, and DNS tunneling runs in the background with zero setup. A critical alert auto-freezes the recorder so the evidence is already saved when you look.
- ⚙️ **Name the process behind every connection** — maps each socket to the program that opened it from `ss`/`lsof`, with an optional kernel-level eBPF kprobe (Linux, the `ebpf` feature) that also catches short-lived flows polling can miss. Works everywhere; the kprobe is an enhancement, not a requirement.
- 📡 **Decode the protocols, not just the ports** — real L7 parsing of TLS, QUIC, HTTP, and DNS (plus an SSH banner/version sniff) and a dozen more, with per-flow stream tracking and handshake timing — so you see `api.github.com` and the JA4 fingerprint, not just "port 443."
- 🎥 **Freeze the evidence** — arm a rolling recorder and freeze any incident into a portable bundle: the packets *plus* the connections, DNS, health, and alerts that explain them. Built for bug reports and post-mortems.
- 🛡️ **Safe by design** — after setup, NetWatch drops its privileges and locks itself into a Landlock filesystem allow-list (Linux). A tool that parses hostile traffic *cannot* read your SSH keys, browser profiles, or `/etc/shadow`.
- 🪟 **Scales down to one screen** — `--lite` answers *"what's using my network, and is my connection OK?"* on a single 80×24 screen with six keys, so it fits an SSH session to a Pi or a tmux split. One keypress escalates to the full forensics view with the collectors already warm.

**No config files. No setup. No flags required.**

## Install

```bash
brew install netwatch                 # macOS / Linux
nix-shell -p netwatch                 # NixOS / Nix
paru -S netwatch-tui-bin              # Arch (prebuilt; netwatch-tui builds from source)
scoop install netwatch                # Windows
cargo install netwatch-tui            # anywhere with Rust
```

Or grab a pre-built binary from [Releases](https://github.com/matthart1983/netwatch/releases/latest).

**Windows needs [Npcap](https://npcap.com/#download) installed** — the installer's defaults are fine, and without it NetWatch exits at startup saying so. **Building from source** (`cargo install`, `paru -S netwatch-tui`) needs libpcap's development headers: `libpcap-dev` on Debian/Ubuntu and Alpine, `libpcap-devel` on Fedora/RHEL, `libpcap` on Arch. Missing them shows up as `cannot find -lpcap` at link time. macOS ships libpcap; the `-static` Linux binaries below bundle it and need nothing installed.

The Nix, Arch and Scoop packages are maintained by community packagers — thank you. File
packaging issues with them; file netwatch bugs here. If a package lags a release, the
[Repology page](https://repology.org/project/netwatch-tui/versions) shows it.

<details>
<summary><strong>All platforms &amp; build-from-source</strong></summary>

| Platform | Download |
|----------|----------|
| Linux (x86_64, Debian/Ubuntu) | [`netwatch-linux-x86_64.tar.gz`](https://github.com/matthart1983/netwatch/releases/latest) |
| Linux (aarch64, Debian/Ubuntu) | [`netwatch-linux-aarch64.tar.gz`](https://github.com/matthart1983/netwatch/releases/latest) |
| Linux (x86_64, static — Arch/Fedora/Alpine/any distro) | [`netwatch-linux-x86_64-static.tar.gz`](https://github.com/matthart1983/netwatch/releases/latest) |
| Linux (aarch64, static — Arch/Fedora/Alpine/any distro) | [`netwatch-linux-aarch64-static.tar.gz`](https://github.com/matthart1983/netwatch/releases/latest) |
| macOS (Intel) | [`netwatch-macos-x86_64.tar.gz`](https://github.com/matthart1983/netwatch/releases/latest) |
| macOS (Apple Silicon) | [`netwatch-macos-aarch64.tar.gz`](https://github.com/matthart1983/netwatch/releases/latest) |
| Windows (x86_64) | [`netwatch-windows-x86_64.exe.zip`](https://github.com/matthart1983/netwatch/releases/latest) |

The `-static` Linux builds bundle libpcap and have no runtime dependencies — use these on Arch, Fedora, Alpine, or any distro where the default builds report `libpcap.so.0.8: cannot open shared object file`.

The Windows build requires [Npcap](https://npcap.com/#download) — install it before first run. The installer's defaults are fine: NetWatch looks in `System32\Npcap`, where Npcap actually puts `wpcap.dll`, so *Install Npcap in WinPcap API-compatible Mode* is not needed. With no Npcap at all you get a NetWatch message naming what's missing, not a Windows error box. (On v0.29.1 and earlier you did need that checkbox — see [#47](https://github.com/matthart1983/netwatch/issues/47).)

**From source:**

```bash
git clone https://github.com/matthart1983/netwatch.git && cd netwatch
cargo build --release
```

**Prerequisites:** Rust 1.70+ and libpcap's development headers. The same applies to `cargo install netwatch-tui`.

| Platform | Install |
|----------|---------|
| Debian / Ubuntu | `sudo apt install libpcap-dev` |
| Fedora / RHEL | `sudo dnf install libpcap-devel` |
| Arch | `sudo pacman -S libpcap` |
| Alpine | `sudo apk add libpcap-dev` |
| macOS | included with the system |
| Windows | [Npcap](https://npcap.com/#download) — the build fetches the Npcap SDK automatically, or set `NPCAP_SDK` to an extracted copy |

Without them the build fails at link time with `/usr/bin/ld: cannot find -lpcap`. If you only want to run NetWatch rather than build it, the `-static` Linux binaries above need none of this.

</details>

## Quick start

```bash
netwatch            # interface stats, connections, config — no privileges needed
sudo netwatch       # full mode — adds live packet capture + health probes
```

That's it. Switch tabs with `1`–`9`, press `?` for help, `q` to quit. The Dashboard is useful in five seconds; everything below is there when you need to go deeper.

> **Linux without `sudo`:** grant the capture capabilities once and run as your normal user —
> `sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$(which netwatch)"`. Re-run it after every upgrade ([details](docs/REFERENCE.md#running-without-sudo-linux)).

### See it decrypt TLS in 60 seconds

The fastest way to understand what NetWatch is — watch it read the plaintext of a TLS 1.3 session *you* control:

```bash
sudo netwatch                                              # 1. launch, then open the Packets tab (4)
SSLKEYLOGFILE=/tmp/sslkeylog.txt curl https://example.com  # 2. any client that exports its keys
#                                                            3. filter the Packets tab with:  decrypted:true
```

The decrypted application data renders inline. A keylog miss never breaks capture — that record just stays opaque. (`SSLKEYLOGFILE` is the same mechanism Wireshark uses; it only works for traffic *you* control, never third-party or malware traffic.)

<p align="center">
  <img src="docs/media/demo-forensics.gif" alt="NetWatch decrypting a live TLS 1.3 session — the plaintext HTTP exchange decoded in the Packets tab" width="800">
</p>

<p align="center">
  <em>Reading the plaintext out of a live <strong>TLS 1.3</strong> session — decrypted right in the terminal. No proxy, no man-in-the-middle.</em>
</p>

### See it catch egress drift in 60 seconds

<p align="center">
  <img src="docs/media/demo-egress.gif" alt="NetWatch learning what curl talks to, promoting that baseline to an egress policy, and then flagging a new destination as drift" width="820">
</p>

<p align="center">
  <em>Observe → promote → warn. The baseline becomes a policy with one keypress; the next new destination arrives as <strong>drift</strong>.</em>
</p>

The loop from the demo above, in three commands:

```bash
sudo netwatch                  # 1. launch and open the Egress tab (0). Leave it a minute
                               #    while it learns; each process grows a list of destinations
                               #    with hostnames, autonomous systems and ports
                               # 2. put the cursor on a process and press Enter — its observed
                               #    baseline becomes a rule in egress-policy.toml
curl https://example.org       # 3. same program, somewhere it has never been
```

The new destination lands with a `✗ drift` verdict and an alert. Nothing was blocked — the point is that you were *told*.

The verdicts are deliberately not a binary:

| | |
|---|---|
| `✓ sni` / `✓ ip` | Matched a declared hostname or address — precise |
| `~ asn` | Matched only by autonomous system — that admits *everything that AS operates*, which for a hyperscaler is effectively unbounded |
| `? ech` | Encrypted ClientHello: the name is hidden by design, so this is "cannot judge", not "bad" |
| `✗ drift` | Outside the allowlist |
| `— no rule` | This program was never declared — nothing was checked |
| `✗ undeclared` | No rule, under `strict = true` — the policy claims to be complete, so the *absence* is the finding |

Rules accept exact hostnames, `*.wildcards`, autonomous systems, CIDR blocks (`10.0.0.0/8`), and ports. `strict = true` is what turns the linter from "tell me when my declared software misbehaves" into "tell me when something I never declared starts talking" — which is the shape an actual compromise has.

## What you get

Ten tabs, switched with `1`–`9` and `0`:

| # | Tab | What it shows |
|---|-----|---------------|
| 1 | **Dashboard** | Interfaces, bandwidth graph, top connections, gateway/DNS health, latency heatmap. Useful in 5 seconds. |
| 2 | **Connections** | Every socket with its process + PID, protocol, state, GeoIP, and latency sparklines. |
| 3 | **Interfaces** | Per-interface IPv4/IPv6, MAC, MTU, RX/TX, errors, drops. |
| 4 | **Packets** | Live capture with real L7 decode, TLS 1.3 decryption, JA4, per-flow stream tracking, filters, PCAP export. |
| 5 | **Stats** | Protocol breakdown by bytes + TCP handshake-timing histogram. |
| 6 | **Topology** | ASCII map of machine → gateway → DNS → top hosts, with traceroute. |
| 7 | **Timeline** | Connection timeline color-coded by TCP state; security alerts land here. |
| 8 | **Processes** | Per-process bandwidth ranking with live RX/TX and connection counts. |
| 9 | **Diagnose** | What is wrong, why, and what to do about it. Baseline-driven detection over a 25-rule catalogue, ranked causes with the checks that discriminated them, key-bound reversible fixes, and a `report.md` / `report.json` generated from the same objects the screen renders. *(An opt-in AI narrative appears here as commentary — never as a source of facts.)* |
| 0 | **Egress** | Learns what each process talks to (hostname/AS/port), promotes that baseline to a policy with one keypress, then warns on drift. Observe-only, never blocks. |

The Packets tab is where the forensics live — deep protocol decoding, live TLS 1.3 decryption, JA4 threat-hunting, Wireshark-style display filters, and incident capture. **[See the full feature reference →](docs/REFERENCE.md)**

### Lite view

Ten tabs is an operator's instrument. When the question is just *"what's using my network, and is my connection OK?"* — one machine, an SSH session to a Pi, a tmux split — there's `--lite`:

```bash
netwatch --lite     # one screen, fits 80×24
```

<p align="center">
  <img src="docs/media/demo-lite.gif" alt="NetWatch Lite: one 80×24 screen showing live throughput charts, gateway/DNS/internet reachability, and top talkers by process and host — expanding a connection in place and filtering it live" width="820">
</p>

<p align="center">
  <em>One screen, six keys. Live throughput, reachability, and who's talking — expand any row in place, filter as you type.</em>
</p>

Everything on a single screen: live throughput charts, gateway/DNS/internet reachability, and the top talkers by process and host. Six keys — `q` quit, `p` pause, `/` filter, `↵` expand a talker, `L` back to the full view, `?` help.

Press `L` from either view to switch. Both share the same collectors, so escalating from "something looks off" to the full ten-tab forensics view costs one keypress — no restart, no lost history, capture still running.

### Dense view

The other direction: when you have a big terminal and want *everything* at once, `--view dense` fills it with four boxes and no chrome — no header bar, no menu bar, no status bar. Identity, sort state, page range and every keybind live inside the box borders, so every row carries data. It needs 130×44 as a floor and **grows into whatever you give it**: wider means more history in the plots and room for full hostnames, taller means more interfaces and more connections.

```bash
netwatch --view dense     # four boxes, needs 130×44
```

<p align="center">
  <img src="docs/media/demo-dense.gif" alt="NetWatch Dense: four boxes filling the terminal — a mirrored braille throughput graph with download growing up from the time axis and upload growing down from it, per-interface rates with 60-second sparklines, four-hop latency budgets, and a connection table whose selected row's detail is hoisted into the top of the same box carrying kernel cwnd / ssthresh / mss / rwnd" width="900">
</p>

The signature element is the **mirrored dual graph**: download grows up from a centre time axis, upload grows down from the same axis. Traffic symmetry becomes a shape you recognise without reading a number — a download burst is a cliff above the line, a backup job is a cliff below it. Both halves are braille at two samples per character cell, and every cell is coloured by its **height in the graph** rather than by which series it belongs to, so you see a spike's severity before you measure it against the axis.

Throughput ramps cool→bright because high bandwidth is *busy*, not *bad* — a saturated link during a backup is working. Only bounded values where high genuinely is bad — link saturation, latency budget per hop — get the green→amber→red treatment, and their meters colour by position along the bar, so the red zone is visible before you reach it.

Below the graph: per-interface rates with 60-second sparklines, four-hop latency budgets (gateway, DNS, internet, and the slowest peer you're actually talking to), and the connection table with the selected row's detail hoisted into the top of the same box — no new screen, no back button. The detail row carries kernel TCP state — `cwnd`, `ssthresh`, `mss`, `rwnd` — read straight from the kernel: `inet_diag` over netlink on Linux, the `net.inet.tcp.pcblist64` sysctl on macOS. The two kernels disagree about units (Linux counts segments, BSD counts bytes), so macOS values are normalised against the MSS and the column means the same thing on both. Windows reads `--` until `GetPerTcpConnectionEStats` is wired up.

`V` cycles `full → lite → dense`, or set it once under **Settings → View**. Below 130×44 it falls back to the same 80×24 grid Lite targets — which fills its area too — and it never scrolls sideways.

## Deeper dives

| Guide | What's in it |
|-------|--------------|
| **[Feature reference](docs/REFERENCE.md)** | Every keybinding, the display-filter language, protocol decoder list, themes, and config options. |
| **[Configuration](docs/REFERENCE.md#configuration)** | The config file's location and every key in it, with defaults — including `graph_style` / `graph_fade` for the btop-style braille charts. |
| **[TLS 1.3 decryption](docs/REFERENCE.md#tls-13-decryption)** | How `SSLKEYLOGFILE` decryption works, supported cipher suites, and what it can and can't read. |
| **[Threat hunting with JA4](docs/REFERENCE.md#threat-hunting-with-ja4)** | Fingerprinting clients and pivoting across flows. |
| **[Security &amp; the Landlock sandbox](docs/REFERENCE.md#security--forensics)** | The threat model, capability dropping, and the filesystem allow-list. |
| **[Egress policy linting](docs/egress-linter-plan.md)** | The observe → promote → warn model, the rule language, `strict` mode, and the NDJSON export schema. |
| **[Flight Recorder](docs/REFERENCE.md#flight-recorder)** | Arming, freezing, and the contents of an incident bundle. |
| **[AI Insights](docs/INSIGHTS.md)** | Optional local/cloud LLM commentary, rendered inside the Diagnose tab (off by default). |

## How it works

```
Raw bytes → Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP → L7 decoders
                                            ↓
                          Per-flow stream tracking · Handshake timing
                          TLS 1.3 decryption · JA4 · Threat detection
```

| Collector | macOS | Linux |
|-----------|-------|-------|
| Connections | `lsof` + PKTAP | `/proc/net/tcp` + eBPF kprobe |
| Packets | libpcap (BPF) | libpcap |
| Process attribution | PKTAP | `lsof`/`ss` polling, with optional eBPF kprobe overlay |

Everything degrades gracefully: features that need elevated privileges show a clear message and fall back, never crash. Full architecture notes live in [WIKI.md](docs/WIKI.md).

## Related

**Siblings:** [SysWatch](https://github.com/matthart1983/syswatch) (system) and [DiskWatch](https://github.com/matthart1983/diskwatch) (disk) — same chrome, different surface. **[ESSH](https://github.com/matthart1983/essh)** — a pure-Rust SSH client with the same TUI aesthetic; connects where NetWatch observes.

**[NetWatch Cloud](https://www.netwatchlabs.com)** — hosted fleet monitoring for the servers you run NetWatch against. A tiny Rust agent on each Linux host, a real-time dashboard, and email + Slack alerts on latency, packet loss, or hosts going offline. **Free while we grow.** The [agent](https://github.com/matthart1983/netwatch-agent), [SDK](https://github.com/matthart1983/netwatch-sdk), and [dashboard](https://github.com/matthart1983/netwatch-dashboard) are MIT; the hosted backend is proprietary.

## Thanks

**Packagers.** NetWatch is in [homebrew-core](https://formulae.brew.sh/formula/netwatch), [nixpkgs](https://search.nixos.org/packages?query=netwatch), the [AUR](https://aur.archlinux.org/packages/netwatch-tui) and the [Scoop](https://scoop.sh) main bucket — and I packaged none of it. Every one of those was done by someone who found the tool useful, did the work unasked, and has kept it current since. The Scoop entry has usually tracked a release within hours of the tag.

| | |
|---|---|
| **Dominiquini** | [`netwatch-tui`](https://aur.archlinux.org/packages/netwatch-tui) on the AUR, since March 2026 |
| **kemelzaidan** | [`netwatch-tui-bin`](https://aur.archlinux.org/packages/netwatch-tui-bin) on the AUR |
| **tomasrivera** | [`netwatch` in nixpkgs](https://github.com/NixOS/nixpkgs/blob/nixos-unstable/pkgs/by-name/ne/netwatch/package.nix) |
| **[scillidan](https://github.com/scillidan)** | [`netwatch` in the Scoop main bucket](https://github.com/ScoopInstaller/Main/blob/master/bucket/netwatch.json), since v0.15.3 |
| **Homebrew maintainers** | for taking the formula into core, and the bot that has tracked every release since |

Packaging is thankless work that only gets noticed when it breaks. If you install NetWatch through one of these, you have them to thank for it, not me.

**Contributors.** [@lamchau](https://github.com/lamchau), [@fdncred](https://github.com/fdncred) and [@PeteE](https://github.com/PeteE) have sent patches. Thank you — a pull request from a stranger is the best thing that happens to a project like this.

And to everyone who has opened an issue with a real repro, argued with a design decision, or told me the output was wrong on their terminal: that is the feedback loop this is built on.

## Contributing

Questions, ideas, and bug reports are welcome in [GitHub Discussions](https://github.com/matthart1983/netwatch/discussions) and [Issues](https://github.com/matthart1983/netwatch/issues). See [CONTRIBUTING.md](CONTRIBUTING.md) for coding conventions and [WIKI.md](docs/WIKI.md) for the architecture guide.

## License

MIT
