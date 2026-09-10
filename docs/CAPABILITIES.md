# Current capabilities and limits

This matrix describes the local implementation audited on 11 September 2026,
including the unreleased diagnostic/remediation corrections. It is not a claim
that every backend was exercised on every supported OS. Linux unit tests do not
establish macOS or Windows runtime parity.

| Capability | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Interface/configuration collection | Linux system counters and network tools | macOS network tools | PowerShell/network tools, with fallbacks |
| Packet capture | libpcap; capture permission required | libpcap/BPF; access permission required | Npcap installation and capture access required |
| Process attribution | Socket polling; SDK eBPF source disabled in sandboxed runs | `lsof` plus PKTAP where available | Windows socket/process polling |
| Kernel TCP metrics | `NETLINK_INET_DIAG` | `net.inet.tcp.pcblist64` sysctl | Not implemented; collector returns no flows |
| Diagnose | Shared detectors; available inputs determine coverage | Shared detectors; available inputs determine coverage | Shared detectors; absent TCP metrics limit socket rules |
| Netwatch sandbox | Worker entry policy with prepared filesystem grants; privileged capture acceptance pending | No backend | No backend |
| Strict sandbox startup | Rejects preflight/required entry failures; raw capture reopening may fail | Rejected: no backend | Rejected: no backend |
| Live automatic resolver edits | Temporarily disabled | Temporarily disabled | Temporarily disabled |
| AI commentary | Optional Ollama-compatible endpoint | Optional Ollama-compatible endpoint | Optional Ollama-compatible endpoint |

Attribution may be unknown or stale. Polling can miss short-lived connections;
backend identity and visibility are constrained by permissions and the observed
network scope. An `ebpf` build or granted capability alone does not prove that the
kernel accepted a program or that every flow was attributed.

## Diagnose and remediation

The [25-rule matrix](diagnostic-coverage.md) identifies 18 implemented detectors
and seven rules awaiting Diagnose integration. An implemented rule can still be
learning, unmeasured or stale. Local bufferbloat lacks a live loaded/idle test;
interface saturation lacks link capacity in the live adapter. Empty findings do
not establish host health. Baseline readiness is sample-based, not a guaranteed
30-minute elapsed window.

Live resolver changes are disabled pending durable recovery and supported resolver
adapters. Manual guidance and simulated demo remediation remain. TUI startup can
attempt recovery of legacy journal entries; the daemon does not yet have equivalent
startup reconciliation. Recovery-required outcomes preserve failures after a target
write, but the legacy journal is not a crash-durable transaction system.

## Security boundary

The [sandbox reference](REFERENCE.md#landlock-sandbox-linux) documents current
worker entry enforcement and exact file/dedicated-directory grants. The SDK eBPF
source stays disabled under enabled policy until a reader hook is available.
Network access remains unrestricted. Linux tests cover actual lookup, Insights and
keylog entries, keylog restart, export access, symlink replacement and strict entry
rejection. Privileged capture/restart and cross-platform acceptance remain pending.
Managed workers have a shared shutdown deadline; an in-flight blocking operation
may still outlive it and is reported rather than forcibly interrupted.

## Navigation and AI

The full view has ten tabs: Dashboard (`1`), Connections (`2`), Interfaces (`3`),
Packets (`4`), Stats (`5`), Topology (`6`), Timeline (`7`), Processes (`8`), Diagnose
(`9`) and Egress (`0`). Insights is commentary within Diagnose, not another tab.
The config value `default_tab = "insights"` is a legacy alias for Diagnose;
`default_tab = "egress"` is not yet recognized and falls back to Dashboard.

AI is off by default. Enabling it sends packet-derived summaries and network
metadata to the configured endpoint. Commentary is not validated against findings;
a localhost endpoint does not guarantee local-only inference. See
[AI Insights](INSIGHTS.md) for the data sent, timing and shutdown limitations.

## Source of truth and verification

This audit checked [tab/config mapping](../src/config.rs),
[application startup and dispatch](../src/app.rs),
[platform collectors](../src/platform/mod.rs),
[attribution](../src/collectors/connections.rs),
[TCP metrics](../src/collectors/tcp_info.rs),
[sandbox dispatch](../src/sandbox/mod.rs),
[Linux policy](../src/sandbox/linux.rs), and
[Insights snapshot/worker](../src/collectors/insights.rs).

PR05 implements worker entry policy and Settings reporting. A broader runtime
capability snapshot and a `doctor` command remain planned. See the [implementation progress](research/implementation-progress.md).
