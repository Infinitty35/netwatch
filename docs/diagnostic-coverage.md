# Diagnose input coverage

Implemented in the PR02 slice on 11 September 2026. The catalogue contains 25
rules: 18 have Diagnose detectors and seven await integration. An implemented
detector is not necessarily available on a running host.

The UI and exported reports use the same runtime coverage object. Each entry
is available, learning, not measured, stale, or unsupported, with an explanation.
Available means that prerequisites exist for at least one observed subject; it
does not establish coverage of every interface, flow, destination, or failure mode.
An empty issue list consequently says “no findings,” never establishes host health.
Legacy JSON reports without coverage deserialize as “coverage not recorded.”

## Input and limitation matrix

| Rule | Diagnose input / prerequisite | Live limitation or recovery evidence |
| --- | --- | --- |
| `link.down` | Interface snapshot and link state | Fresh snapshot for the same interface |
| `iface.errors` | Interface error/drop counter deltas | Fresh counters for the same interface |
| `iface.saturated` | Interface rates and link capacity | Capacity is currently absent from the live adapter; not measured |
| `wifi.weak_signal` | Wireless signal or retry measurements | Platform-dependent; fresh same-interface measurements |
| `gateway.unreachable` | Gateway outcome plus internet corroboration | Both inputs must be fresh; missing corroboration cannot open a finding |
| `gateway.rtt_spike` | Gateway RTT and usable baseline | Learning until the baseline is ready and has measurable variation |
| `dns.slow_resolver` | Resolver RTT | Absolute threshold works without a baseline; recovery needs matching resolver evidence |
| `dns.failing` | DNS query outcomes | Failed probes count as outcomes; fresh matching resolver evidence required |
| `dns.truncation_retry` | DNS reply flags and query outcomes | Fresh matching resolver evidence required |
| `dns.hijack_suspect` | Resolver cross-check | Not measured when the cross-check is absent |
| `path.changed` | Current and previous completed traces | Repeated rendering does not create a new trace; recovery requires complete comparable responding hops |
| `path.high_loss` | Responding trace hops | Recovery conservatively checks all responding hops |
| `path.rtt_spike` | Trace RTT and usable path/internet baseline | Fresh trace for the same destination required |
| `tcp.bufferbloat_local` | Explicit idle and loaded RTT observations | No live loaded test; not measured |
| `tcp.bufferbloat_remote` | Socket RTT and classification | Fresh socket snapshot, same local/remote endpoints |
| `tcp.retrans_burst` | Socket RTT/retransmission classification | Fresh socket snapshot, same local/remote endpoints |
| `tcp.zero_window` | Socket receive-window measurement | Not measured where the collector does not provide receive windows |
| `nat.symmetric` | STUN mapping observations | Fresh NAT result required |
| `tcp.connect_failures` | No Diagnose integration | Unsupported in Diagnose |
| `tcp.timewait_exhaustion` | No Diagnose integration | Unsupported in Diagnose |
| `pmtu.blackhole` | No Diagnose integration | Unsupported in Diagnose |
| `ipv6.broken` | No Diagnose integration | Unsupported in Diagnose |
| `captive.portal` | No Diagnose integration | Unsupported in Diagnose |
| `egress.drift` | No Diagnose integration | Separate Egress tab does not constitute a Diagnose detector |
| `egress.policy_violation` | No Diagnose integration | Separate Egress tab does not constitute a Diagnose detector |

## Freshness and recovery

Live evaluation excludes interface snapshots older than 15 seconds, health and
socket results older than 30 seconds, traces older than 120 seconds, and NAT
results older than 300 seconds. These are conservative validity limits, not
promises that a collector runs at those intervals. Missing results stay unknown.
Health results retain the gateway/resolver target used by the probe, so a config
change cannot relabel an old result as a measurement of the new target.

Missing verification metrics reset the recovery hold. Rendering a cached result
cannot complete recovery. Live holds use monotonic collector completion times,
and a gap exceeding the source's validity limit restarts the hold. A different
resolver cannot resolve the old resolver's issue unless its replacement was
recorded as a successful remediation (currently exercised by simulated remediation).
Closed findings remain represented in Markdown and JSON; the report describes
retained history, not a guarantee that all incidents in its window were captured.

Baseline learning consumes each completed health probe only once. Cached traces
retain their actual predecessor and completion time; cached interface snapshots
do not append repeated counter deltas. Reports retain full issue sections ahead
of the detailed coverage list.

## Verification and remaining work

`coverage.rs` tests enumerate every catalogue entry, no-data startup, absent
loaded/window inputs, and the DNS absolute-threshold alternative. `engine.rs`
tests cover true recovery, missing data, changed resolver identity, stale probes,
duplicate completions, wall-clock jumps, interrupted sampling and missing gateway
corroboration. Existing detector and scenario fixtures cover rule triggers and
remediation recovery. `report.rs` tests cover unknown legacy coverage and retained
closed findings; live sampler tests cover duplicate/stale baseline readings.

This slice does not finish all of NW-R04. Remaining work includes structured
permission/collector-failure reasons and next checks, per-subject coverage records,
explicit stale state on each open finding, and the confidence presentation audit.
Baseline readiness still uses 1,800 distinct samples rather than persisted elapsed
coverage; its duration depends on probe cadence. Interface rate windows still use
60 samples rather than elapsed-time windows. Network identity beyond resolver and
interface matching, suspend/resume integration, and platform-specific live-adapter
fixtures require further work. Freshness defaults need field validation across
supported platforms. See the [implementation plan](research/netwatch-implementation-plan.md).
