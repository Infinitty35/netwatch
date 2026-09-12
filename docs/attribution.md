# Attribution identity, freshness and coverage

A working backend does not establish who owns every captured flow. Netwatch keeps
backend readiness, individual ownership evidence and coverage separate.

## Ownership evidence

Connections carry an additive `evidence` object alongside their existing fields:

- `observed_at_utc_ms`: when the match was observed; freshness uses monotonic time
  internally and expires after five seconds.
- `process`: session UUID, PID, process-start token, executable file identity and
  network namespace when available. Linux reads `/proc/PID/stat` on both sides of
  executable discovery and descriptor enumeration. Executable identity uses device,
  inode, size and change time; it is not a binary hash or script/workload identity.
- `unknown_reason`: stable snake-case codes including `no_socket_owner`,
  `identity_unavailable`, `identity_changed`, `stale_snapshot`,
  `ambiguous_endpoint` and `incomplete_event_key`.
- `flow`: session UUID, protocol, endpoints, observation generation, optional
  capture generation and network namespace. A missing poll or changed process
  identity starts a new observation generation.
- `corroborated_by` and `event_age_at_match_ms`: supporting event evidence, separate
  from the primary socket-owner source. These do not establish packet ownership.

Linux validates protocol plus both endpoints against socket inodes, then joins
only unambiguous owners in the observer's network namespace. It rechecks the
socket descriptor and process identity before accepting an owner. TCP and UDP do
not share an index. A wildcard peer is matched only as a wildcard socket, never
as an arbitrary connection on the same local port. Shared sockets and duplicate
endpoints do not select an arbitrary PID.

The startup `/proc` snapshot expires after five seconds and requires a current
inode, descriptor and process-identity check. If sandbox policy prevents those
checks, ownership stays unknown. It is no longer an indefinite attribution cache.

The SDK's eBPF connect events omit a complete source endpoint. They can support an
independently verified socket owner but cannot supply or overwrite one from a
destination-only match. PKTAP hints likewise cannot overwrite polling ownership.
Both caches check age at lookup, even if their worker stops. Event-stream loss is
not measured by this model; capture drops are a separate counter.

Late executable-name lookup is performed only with a process-start identity.
Process byte totals are keyed by process identity; unverified PID totals are not
retained across updates. CPU samples require matching process identities before
and after the sample and expire after ten seconds. On platforms without a start
identity implementation, CPU is unavailable and polling names remain explicitly
unverified. These conservative limits currently apply to macOS and Windows.

## Capture generations and coverage

A new TCP SYN sequence, a SYN after observed close, or a UDP tuple idle for more
than 60 seconds starts a new capture generation. SYN retransmissions retain their
generation. Clearing capture does not reuse stream indices. Bytes, handshake and
protocol state from the replaced generation are discarded; old packet entries
may consequently no longer have a retained stream detail. Rate calculation never
diffs counters across capture generations.

The current coverage denominator is **captured TCP/UDP streams with payload-byte
increments in the latest completed polling interval**, including streams absent
from socket polling. The first snapshot establishes a baseline. New streams after
that baseline contribute their payload bytes, even when polling missed them.
A stream counts as attributed only with one fresh, verified process identity;
conflicting owners, including two local loopback owners, count as unknown.

Flow coverage and payload-byte coverage are separate ratios. Neither measures
wire-byte coverage, all host traffic, packets lost before capture, nor correctness
against independent ground truth. Zero eligible flows and stale/missing snapshots
show **not measured**. The UI shows coverage on separate rows in Connections,
Processes and Egress. Capture drops are shown only after a recent libpcap stats
sample; an unavailable counter is not displayed as zero. Runtime capability
snapshots include structured `attribution_coverage`; static doctor has no such
observation and reports `null`.

Five-tuple identity remains observation-limited: reuse between polls without a
captured handshake, UDP reuse within the idle window, shared descriptors,
interpreter workloads, namespaces outside the observer, and missed events require
further instrumentation. This implementation does not claim perfect flow identity.

## Controlled results — Linux, 12 September 2026

Run the independent-process polling matrix:

```sh
cargo test --offline controlled_polling_matrix_matches_independent_processes -- --nocapture
```

Each child logs its own PID, process-start token, protocol, endpoints and timestamp
as `ATTR_EXPECTED` JSON, independently of the collector. Two live children share a
destination, and a third closes its socket before polling. The parent compares two
polls and emits `ATTR_RESULT` JSON with correct, wrong and unknown counts.

| Backend | Protocol | Family | Live flows | Correct observations / eligible | Wrong | Unknown |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| Linux procfs polling | TCP | IPv4 | 2 | 4 / 4 | 0 | 0 |
| Linux procfs polling | UDP | IPv4 | 2 | 4 / 4 | 0 | 0 |
| Linux procfs polling | TCP | IPv6 | 2 | 4 / 4 | 0 | 0 |
| Linux procfs polling | UDP | IPv6 | 2 | 4 / 4 | 0 | 0 |

All four flows closed before polling retained no owner. They are outside this
matrix's live-socket denominator; this is a demonstrated polling limitation,
not successful short-lived attribution. These tests inspect sockets and send
local payloads; they do not run privileged packet capture or demonstrate 95%
correct attribution of all captured flows.

Deterministic regressions additionally cover changed start tokens, disappearance
between polls, stale startup/event caches, destination collisions, conflicting
owners, process totals after PID reuse, TCP tuple reuse, idle UDP reuse and capture
clear. The controlled matrix covers already-open sockets held across two polls,
not hours-long sessions or broad process churn.

The roadmap acceptance gate remains open for sustained and short-lived capture
workloads, privileged eBPF and missing-authority runs, sandbox restart, namespace
and shared-socket scenarios, macOS PKTAP and Windows polling. No cross-platform or
overall 95% claim is made from the Linux polling results. Cgroup/workload identity
and interpreter-aware policy remain follow-up work.
