# Netwatch implementation progress

Release update: PR01–PR05 core and the RTT timeline fixes shipped in **v0.31.0**
(`805cf71`). CI passed on Linux, macOS and Windows. The dated entries below retain
their original implementation-stage status; PR05 privileged/interactive acceptance
remains pending despite release. Current work continues with PR06 below.

## PR01 — Initial remediation corrections

Implemented locally on 11 September 2026 against `9b4597e`; not committed or published.

- Added a serialisable recovery-required outcome with operation ID, failure reason, and backup path. Target-write and completion-journal failures use this outcome; errors before the target write remain distinct.
- Invalid/unsupported and unreadable journals retain their original bytes and block subsequent mutations and shutdown persistence. Persistence failures block further writes in the current journal instance.
- Removed empty-content fallbacks for reading mutation and recovery targets. Pending changes with differing target contents require a readable matching original backup before being considered resolved.
- Prevented another edit to a target with an unresolved or retained change in the loaded journal from overwriting its backup. Cross-process locking remains PR07 work.
- Preserved recovery outcomes in UI details and Markdown/JSON reports. Journal blocks remain visible after transient status messages expire and appear in exported report timelines.
- Temporarily disabled live automatic resolver edits, as specified by R02. Manual guidance and simulated demo remediation remain available. Existing TUI startup recovery is retained.
- Loaded existing journals when constructing diagnostic state and avoided rewriting journals when there is no recovery work. This prevents the daemon's empty initial journal from overwriting existing recovery history during an otherwise idle shutdown; full shared startup reconciliation remains pending.

Validation: `cargo test --offline --quiet` passed **970 tests**, with **3 ignored**; `cargo clippy --offline --all-targets -- -D warnings`, `cargo fmt --check`, and `git diff --check` passed. Twelve regression tests were added, including partial writes, journal-completion failure, journal preservation, unreadable files, recovery failure reporting, JSON/Markdown round trips, and UI warnings. Filesystem failures use the in-memory host; no actual resolver was edited.

Known remaining work: durable/atomic journals, operation ownership and locking, resolver adapters, worker confinement, evidence-aware health summaries, and the rest of the implementation plan. The current journal remains a legacy format; a recovery-required outcome does not establish crash durability. Older report consumers may reject the new `Applied::RecoveryRequired` variant.

## PR02 — Rule prerequisites and evidence-aware summaries

Implemented locally on 11 September 2026; not committed or published. This is the
second implementation slice, not completion of all NW-R04 work.

- Added runtime coverage for all 25 catalogue entries. Eighteen have Diagnose
  detectors; seven without integration are explicitly planned. Availability is
  computed from observations and baseline prerequisites. DNS's absolute threshold
  remains usable while baselines learn. Absent loaded/idle tests and receive-window
  measurements are reported as not measured.
- Gated findings and recovery on available prerequisites. Missing verification
  values reset recovery instead of closing issues. Resolver, interface, path and
  socket evidence is matched to the finding's subject; a successful recorded
  resolver replacement can supply replacement evidence.
- Added collector completion timestamps, bounded freshness and duplicate-sample
  protection. Live recovery holds use monotonic sample times and restart after
  excessive gaps. Cached results cannot complete a hold, repeatedly train health
  baselines, append interface deltas, or become their own predecessor trace.
- Preserved gateway/resolver probe identity and cleared target-specific history
  when those targets change. Expired interface, probe, trace and socket data is
  excluded from live evaluation.
- Replaced empty-list health claims with limited/learning coverage summaries.
  TUI, report preview, Markdown and JSON carry coverage from the engine. Reports
  retain closed findings and treat missing legacy coverage as unknown.
- Added the [25-rule input matrix](../diagnostic-coverage.md), with live limitations,
  freshness rules, verification references and remaining work. Updated README and
  changelog claims.

Validation: `cargo test --offline --quiet` passed **982 tests**, with **3 ignored**;
the focused Diagnose suite passed **171 tests**. Twelve tests were added beyond
PR01. `cargo clippy --offline --all-targets -- -D warnings`, `cargo fmt --check`,
`cargo check --offline --no-default-features`, and `git diff --check` passed.
Networking tests used local socket access. No live resolver edits were performed.
Cross-platform runtime validation remains outstanding.

Remaining NW-R04 work: per-subject coverage, structured permission/collector-failure
reasons and next checks, explicit stale state per finding, confidence presentation,
persisted elapsed-time baseline readiness, elapsed-time interface windows, and
broader identity/suspend-resume/live-adapter testing. Coverage is input availability
for observed subjects, not a completeness or health score.

Next: **PR03 — Correct capability, sandbox and Insights documentation**, then
runtime/confinement implementation, following the
[implementation plan](netwatch-implementation-plan.md).


## PR03 — Capability, sandbox and Insights documentation

Completed locally on 11 September 2026; not committed or published. Documentation
and source comments only; runtime enforcement is unchanged.

- Added the [platform capability matrix](../CAPABILITIES.md), covering attribution,
  capture, TCP metrics, Diagnose inputs, sandbox availability and resolver limits.
- Corrected README, reference, security policy and architecture-tour claims about
  calling-thread Landlock enforcement, existing workers, capability-drop attempts,
  unrestricted networking and broad directory grants. Strict mode is described as
  checking reported application warnings, not proving worker confinement.
- Rewrote Insights setup around Diagnose (`9`), with the actual snapshot fields,
  retained-packet behavior, request timing, endpoint handling and shutdown limits.
  Removed unsupported model-quality claims and local-only privacy guarantees.
- Updated the architecture wiki's ten-tab navigation, platform scope and source map.
  Documented the legacy `insights` startup-tab alias and the currently unsupported
  `egress` startup-tab config value. Corrected fixed-duration baseline and
  root-required DNS-probe claims.
- Corrected stale sandbox module comments and architecture-tour examples; historical
  research/review documents remain historical records.

Validation: checked claims against application startup/dispatch, configuration,
platform/connection/TCP collectors, sandbox policy/path construction and the Insights
worker/UI. All **52 relative file links** checked in the six primary Markdown pages
resolve. `cargo fmt --check` and `git diff --check` passed. No new runtime tests were
needed for documentation/comment changes; PR02's runtime test results are recorded
above. No macOS/Windows runtime or live model inference validation is implied.

Next: **PR04 — Worker inventory and resource/start split**. This prepares the
startup boundary for actual worker enforcement in PR05; the security gaps described
in PR03 remain open implementation work.


## PR04 — Worker inventory and resource/start split

Implemented locally on 11 September 2026; not committed or published.

- Added the [runtime lifecycle inventory](../runtime-lifecycle.md), covering
  application and dependency worker creators, resource/authority and filesystem
  needs, untrusted inputs, restart paths, shutdown owners and remaining gaps.
- Split `App::prepare()` from idempotent `App::start_workers()` in TUI and daemon.
  Preparation retains synchronous platform/config/state discovery and local
  database handles, while persistent background workers start explicitly.
- Made GeoIP, WHOIS, reverse-DNS and Insights constructors inert. Lookup cache
  clones share a single start gate; pending requests are retained until start.
  Settings-created Insights replacements explicitly start their worker.
- Extracted capture device resolution/open, nonblocking configuration and BPF
  installation into `prepare_capture`, before the first packet read. Initial and
  restarted capture use the same path; resource preparation remains off the UI
  thread. Existing error messages and promiscuous-mode fallback are retained.
- Renamed active terminal/eBPF constructors to `start` and updated their callers
  and eBPF smoke examples. Kernel attribution attaches to the prepared connection
  collector without replacing its process snapshot.
- Audited locked netwatch-sdk 0.4.1: `EventSource::new()` starts an internal reader
  and exposes no separate preparation or pre-read enforcement hook. The inventory
  explicitly requires an SDK hook or suitable process boundary for PR05.

Validation: **988 tests passed**, **3 ignored**, including six new lifecycle
regressions. `cargo clippy --offline --all-targets -- -D warnings`,
`cargo check --offline --no-default-features`, `cargo fmt --check` and
`git diff --check` passed. Tests cover deferred request processing, clone-shared
start-once behavior, prepared application state, and capture preparation failure
and retry using a nonexistent Linux interface. No live capture or model endpoint
was needed for the new tests; the full suite used local socket access.

Limits: this does not enforce worker confinement. Startup still precedes the
calling-thread sandbox. Readiness, cancellation/join guarantees, narrow path
preparation, dependency-worker enforcement and cross-platform runtime validation
remain outstanding. `workers_started` records a start request, not readiness.

Next: **PR05 — Worker enforcement/readiness and narrow path defaults**.

## PR05 — Worker enforcement/readiness and narrow path defaults

Core implementation is local on 11 September 2026; **acceptance remains pending**
for privileged capture/restart and cross-platform runtime checks. Not committed or
published. Do not count this as a fully accepted fifth slice yet.

- Replaced pre-body Tokio startup with synchronous setup and a current-thread
  runtime. Policy preflight precedes optional workers. Future blocking-pool entries
  enforce policy through the runtime callback.
- Added a prepared worker policy, bounded entry/release handshake, component
  results and Settings visibility. Actual lookup, Insights, polling, metrics,
  terminal and remote workers enter policy before their processing closure runs.
  Logging's initializer is restricted before it creates its dependency worker.
- Capture opens/configures pcap, enters policy, then marks readiness before reading.
  Start requests and readiness have separate flags. Cancellation flags belong to
  each generation; restarting cannot re-enable a detached old generation. Cancelled
  preparation cannot overwrite a newer start's error. Strict startup failures
  return a nonzero CLI exit after terminal cleanup.
- eBPF is explicitly disabled under installed sandbox policy: the SDK reader has
  no pre-processing enforcement hook. Socket polling remains available; no helper
  or dependency lifecycle patch is claimed. PKTAP uses the entry wrapper, with
  macOS best-effort explicitly reporting its unavailable filesystem backend.
- Selected capability removals are checked, and effective retained capabilities
  are recorded. Linux rulesets pin opened filesystem objects once at bootstrap;
  worker entry clones those rules rather than reopening potentially replaced paths.
- Writable grants now cover owned/private application config/cache/state and
  dedicated export/scratch directories. Whole-CWD, shared `/tmp` and runtime-user
  directory grants are removed. Exports move to `cache/netwatch/exports`. Configured
  keylog/GeoIP files receive exact read grants; missing/replaced inodes need restart.
- Managed worker handles share cancellation and a two-second shutdown/join deadline.
  Queue workers stop taking new work, and metrics accepts are nonblocking. Blocking
  operations can still outlive the deadline; remaining workers are reported rather
  than forcibly terminated. Capture retains its own bounded stop/join behavior.

Validation: full offline suite **991 passed, 3 ignored**. Clippy with warnings
as errors, no-default-features checking, formatting and whitespace checks pass.
The isolated-process acceptance test exercises forbidden sentinel reads at real
GeoIP, WHOIS, reverse-DNS, Insights and keylog entries, keylog restart/read access,
permitted exports, post-preparation symlink replacement, injected strict rejection,
and bounded managed-worker shutdown. Path tests reject shared `/tmp` without
changing its permissions. Capture failure/retry tests assert that the old
cancellation flag stays false. The revised sandbox smoke example uses only a
synthetic sentinel and passes with `1/1 worker entries verified`.

**Outstanding release gates:** this environment has no CAP_NET_RAW or BPF
capabilities, so privileged capture/parser denial, capture restart under real
retained/dropped authority, and elevated capability-removal behavior have not been
validated here. macOS/Windows runtime acceptance is also outstanding. These are not
replaced by unit-test counts. The CLI's managed policy is not a general-purpose
sandbox for arbitrary library callers who never install it; network access remains
unrestricted. Review the [current lifecycle update](../runtime-lifecycle.md) before
release or expanding the confinement claim.

Next implementation slice is PR06 (common bootstrap and explicit recovery
authority); PR05's outstanding acceptance gates must remain tracked alongside it.


## PR06 — Common bootstrap and explicit recovery authority

Implemented locally after v0.31.0; not committed or released.

- TUI and daemon now share `runtime::bootstrap::start`: recovery inspection,
  worker startup/readiness and calling-thread confinement. Initial traffic,
  connection and health polling also use a common function.
- Live authority is explicitly `InspectOnly`. Legacy journal PID/path metadata
  does not establish ownership, so there are no eligible automatic rollbacks.
  Inspection does not open target/backup paths or mutate the journal. Unresolved
  temporary entries block subsequent writes and retain persistent UI/report
  warnings; daemon startup logs the same recovery details.
- Shutdown cancels pending applies and preserves legacy records even when an old
  PID matches the current process. Root and `--no-sandbox` do not enable rollback.
- Demo bootstrap skips recovery; demo shutdown also skips baseline persistence,
  preventing scenario data from replacing learned host baselines.
- Static CLI paths remain outside live bootstrap. Help/version leave application
  state untouched; config generation writes its requested config only.

Validation: **995 tests passed, 3 ignored**. New fake-host regressions cover both
live entry-point authorities, reused/dead PIDs, preservation of targets/backups/
journal bytes through later rollback attempts, corruption and permanent records.
CLI subprocess checks used isolated Linux HOME/XDG directories and verified
help/version/config-generation behavior against a synthetic corrupt journal.
Clippy with warnings denied, normal build, no-default-features check, formatting
and diff checks passed. No real resolver was edited. New cross-platform runtime
acceptance was not performed in this slice.

Next: **PR07 — Durable journal v2 and locking**, followed by PR08 resolver adapters.
The legacy low-level library transaction APIs remain available for explicit callers
and tests; no durable recovery or privileged helper is claimed here. PR05's
privileged capture/restart and interactive platform acceptance remains outstanding.

## PR07 — Recovery journal v2 and store locking

Storage core implemented locally after PR06; not committed or released. Platform
and resolver-authority limits below remain tracked acceptance work.

- Added version-2 records in durable state (`netwatch/recovery-v2`), with operation
  and session UUIDs, owner process/UID metadata, available Linux boot/start tokens,
  resource identity, timestamps, original/installed SHA-256 and explicit states.
- Unix writes hold an OS-backed exclusive store lock from load through updates.
  Backups use exclusive UUID filenames and are synced before Prepared publication.
  Journal updates use a unique temporary file, complete write, file sync, atomic
  same-directory rename and directory sync. Persistence errors poison the writer.
- Directory-relative file descriptors pin operations; private ownership/permissions,
  regular files, no symlinks and no extra hardlinks are checked. Backup reads derive
  names from UUIDs and verify digests. Unknown/corrupt records remain untouched.
- State transitions reject different recorded owners, invalid/terminal transitions
  and duplicate unresolved resources. No target file is ever opened by this store.
- Live startup discovers v2 and legacy evidence together. Observation creates no
  store and performs no migration. Corruption and unresolved v2 operations appear
  in the existing persistent recovery warnings/report and daemon logs.

Validation: **1003 tests passed, 3 ignored**. Tests include competing processes,
SIGKILL at eight partial-write/sync/rename boundaries, lock release after death,
old-or-new complete snapshots, verified referenced backups, injected persistence
failures, ownership/state checks, backup non-reuse, corruption/unknown versions,
backup tampering, symlink/hardlink and directory replacement, and combined live
legacy/v2 discovery. Clippy with warnings denied, no-default-features checking,
formatting and diff checks passed. Tests used synthetic files, not a real resolver.

Limits: the per-store lock is not a host-wide resolver lease; PR08 must implement
that at the authorized adapter boundary. Recorded owner equality does not authorize
recovery from untrusted metadata. Windows writes remain unavailable pending a
validated platform backend; macOS runtime validation is outstanding. Process-crash
tests do not demonstrate hardware power-loss durability or network-filesystem
semantics. Orphan evidence is retained, with no automatic garbage collection.
See [the store contract](../recovery-store.md).

Next implementation: **PR08 — Resolver adapter and resource authority**, while
retaining PR05/PR07 platform and privileged acceptance work. Automatic host changes
remain disabled until those authority and recovery conditions are met.


## PR08 — Linux unmanaged-file resolver authority and rollback

Implemented locally after PR07; not committed or released. Privileged disposable-VM
acceptance remains pending; managed/platform adapters are explicitly unavailable.

- Added typed `resolver status`, temporary `set <IP> --unmanaged [--seconds N]`,
  and `recover --unmanaged` commands before runtime/Npcap/application startup.
  Mutation commands require root, use fixed paths and accept no arbitrary shell,
  target, backup or journal arguments. Lifetime is bounded to 1–3600 seconds.
- Conservative ownership detection distinguishes systemd-resolved, NetworkManager,
  generated/managed files, symlinks and unconfirmed regular files. Administrator
  confirmation is mandatory; plain-file appearance alone is not ownership proof.
- The root-owned `/var/lib/netwatch/resolver-v2` store provides one cooperating
  resource lease across invoking users, retained for the entire temporary change.
  Root-owned directory ancestry and target identity/permissions are validated.
  User recovery journals are never promoted into privileged authority.
- Durable preparation precedes descriptor-based file mutation; sync/readback
  precedes Applied. Verified original bytes/identity are required for restoration.
  External edits, inode changes, invalid backups and partial writes preserve
  evidence instead of speculative rollback. Completion failures remain explicit.
- SIGINT/SIGTERM and the deadline restore a verified temporary change. SIGKILL
  leaves discoverable records for the explicit recovery command. Process ownership
  includes boot/start tokens and PID namespace; missing/cross-namespace identity
  is unknown. Automatic TUI/daemon edits and startup rollback remain disabled.
- Shared startup reports the authority store alongside legacy/per-user v2 evidence.
  Read-only status creates no store. File verification is explicitly distinguished
  from effective system DNS resolution, which this adapter does not prove.

Validation: **1013 tests passed, 3 ignored**. Ten added tests cover command/type
validation, ownership detection, temporary apply/restore with identity/permissions
preservation, resource contention, external/symlink/inode changes, invalid backups,
partial target writes, journal completion failure, process identity, and child
SIGKILL at Prepared/target-sync/Applied/restored boundaries followed by recovery.
All mutation tests used disposable files. The actual read-only status command
identified systemd-resolved on this host and no authority journal; no real resolver
was modified. Clippy, normal build, no-default-features checking, formatting and
diff checks passed.

Limits: no privileged VM/network-namespace or actual unmanaged-host validation has
been performed. The lease excludes cooperating Netwatch commands, not arbitrary
root writers. In-place updates are not atomic to DNS readers. Managed resolvers,
macOS/Windows apply, permanent changes and effective system-DNS verification remain
unavailable. See [the adapter contract](../resolver-adapter.md).

Next implementation: **PR09 — Unified capability snapshot, CLI and doctor**, while
retaining the outstanding PR05/07/08 privileged and platform acceptance work.
