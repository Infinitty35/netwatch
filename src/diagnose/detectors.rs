//! Detectors: live observations in, candidate issues out.
//!
//! Four sources feed one evaluator — baselines, socket verdicts, diffs, and
//! the on-demand pipeline. Each produces a [`Detection`], which is an issue
//! without the parts only the engine can know (its id, when it first opened,
//! how many times it has recurred). The engine merges detections into the
//! issue list, so a condition that persists for an hour stays *one* issue with
//! a growing window rather than 3,600 findings.
//!
//! Every threshold that isn't a physical constant comes from [`Thresholds`],
//! so a user ruleset can retune the engine without touching this file.

use super::baseline::BaselineStore;
use super::issue::{
    Action, Capability, Cause, CheckResult, Evidence, Scope, Severity, Step, Subject, Verify,
};
use super::rules;

/// Tunables. Defaults are the spec's: k=3σ, N=3 consecutive samples.
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    /// σ multiple that counts as a deviation.
    pub sigma_k: f64,
    /// Consecutive violating samples before an issue opens (hysteresis).
    pub consecutive_n: u32,
    /// A socket verdict must persist this long before it becomes an issue.
    pub verdict_hold_secs: u64,
    /// Absolute DNS ceiling — a resolver this slow is a problem whatever its
    /// baseline says, which is what makes the rule work on a first run.
    pub dns_ceiling_ms: f64,
    /// Socket rtt above this, with retransmits, reads as receiver-side queue.
    pub socket_rtt_ms: f64,
    /// Loaded-vs-idle rtt delta that means the uplink is bloated.
    pub loaded_rtt_delta_ms: f64,
    /// Interface utilisation counted as saturation.
    pub saturation_pct: f64,
    /// Interface *errors* per minute before the rule fires. Errors are rare
    /// and always mean something, so the floor is low.
    pub iface_error_floor: f64,
    /// Interface *drops* per minute before the rule fires. Much higher than
    /// the error floor: a wireless NIC drops multicast and management frames
    /// as a matter of course, and reporting one drop a minute as a fault
    /// trains people to ignore the tab.
    pub iface_drop_floor: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            sigma_k: 3.0,
            consecutive_n: 3,
            verdict_hold_secs: 30,
            dns_ceiling_ms: 20.0,
            socket_rtt_ms: 100.0,
            loaded_rtt_delta_ms: 100.0,
            saturation_pct: 90.0,
            iface_error_floor: 1.0,
            iface_drop_floor: 60.0,
        }
    }
}

/// One socket's kernel state, as `tcp_info` reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct SocketObs {
    pub local: String,
    pub remote: String,
    pub process: Option<String>,
    pub rtt_ms: Option<f64>,
    pub rttvar_ms: Option<f64>,
    pub retrans: u32,
    pub cwnd: Option<u32>,
    pub ssthresh: Option<u32>,
    pub rwnd: Option<u32>,
    pub mss: Option<u32>,
    pub tx_bps: f64,
    pub rx_bps: f64,
    /// Seconds this socket has been in its current verdict.
    pub verdict_age_secs: u64,
}

impl SocketObs {
    pub fn key(&self) -> String {
        format!("{} → {}", self.local, self.remote)
    }
}

/// Per-socket classification from `tcp_info`. Deliberately explicit about the
/// "nothing is wrong" case so a socket is never left unexplained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketVerdict {
    Ok,
    /// rtt far above the path's, with the socket's own tx driving it.
    Bufferbloat,
    /// cwnd is large but rwnd caps it — the peer isn't reading fast enough.
    ReceiverLimited,
    /// Neither window is the limit; the application isn't writing.
    AppLimited,
    /// cwnd collapsed to ssthresh territory — congestion control is working.
    Congestion,
    RetransBurst,
    ZeroWindow,
}

impl SocketVerdict {
    pub fn label(self) -> &'static str {
        match self {
            SocketVerdict::Ok => "ok",
            SocketVerdict::Bufferbloat => "bufferbloat",
            SocketVerdict::ReceiverLimited => "receiver-limited",
            SocketVerdict::AppLimited => "app-limited",
            SocketVerdict::Congestion => "congestion",
            SocketVerdict::RetransBurst => "retrans-burst",
            SocketVerdict::ZeroWindow => "zero-window",
        }
    }

    pub fn is_ok(self) -> bool {
        matches!(self, SocketVerdict::Ok)
    }
}

/// Classify a socket from its kernel state.
///
/// Order matters — a zero window explains everything downstream of it, so it
/// is tested before the queue-depth verdicts that it would otherwise mimic.
pub fn classify_socket(s: &SocketObs, t: &Thresholds) -> SocketVerdict {
    if s.rwnd == Some(0) {
        return SocketVerdict::ZeroWindow;
    }
    let rtt = s.rtt_ms.unwrap_or(0.0);

    // Retransmits dominate: a socket losing segments is describing the path,
    // not its own queueing, and the retrans rule carries the better causes.
    if s.retrans >= 5 && rtt < t.socket_rtt_ms {
        return SocketVerdict::RetransBurst;
    }

    // Bufferbloat: high rtt while *this* socket is the one sending. A high rtt
    // on an idle socket is just a distant peer.
    if rtt >= t.socket_rtt_ms && s.tx_bps > 0.0 {
        return SocketVerdict::Bufferbloat;
    }

    if let (Some(cwnd), Some(rwnd), Some(mss)) = (s.cwnd, s.rwnd, s.mss) {
        // cwnd is in segments, rwnd in bytes; compare like with like.
        let cwnd_bytes = cwnd as u64 * mss as u64;
        if rwnd > 0 && cwnd_bytes > 2 * rwnd as u64 {
            return SocketVerdict::ReceiverLimited;
        }
    }

    if let (Some(cwnd), Some(ssthresh)) = (s.cwnd, s.ssthresh) {
        if ssthresh != u32::MAX && cwnd <= ssthresh && s.retrans > 0 {
            return SocketVerdict::Congestion;
        }
    }

    if s.tx_bps == 0.0 && s.rx_bps == 0.0 {
        return SocketVerdict::AppLimited;
    }

    SocketVerdict::Ok
}

/// One hop of a traced path.
#[derive(Debug, Clone, PartialEq)]
pub struct HopObs {
    pub number: u8,
    pub ip: Option<String>,
    pub asn: Option<String>,
    pub rtt_p50_ms: Option<f64>,
    pub rtt_p95_ms: Option<f64>,
    pub loss_pct: f64,
    /// No ICMP reply at all. A silent hop is not a 100%-loss hop — routers
    /// that decline to answer are normal, and calling that loss is the single
    /// most common way traceroute output gets misread.
    pub silent: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PathObs {
    pub target: String,
    pub hops: Vec<HopObs>,
    /// The previous trace to the same target, for diffing.
    pub previous: Option<Vec<HopObs>>,
    pub traced_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IfaceObs {
    pub name: String,
    pub carrier: bool,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    /// Errors and drops over the last minute — a *rate*, not a lifetime
    /// counter. A NIC that logged 40 errors during boot last month is not a
    /// live fault, and a per-tick delta reported as "/min" is off by 60.
    pub errors_per_min: u64,
    pub drops_per_min: u64,
    pub link_rate_bps: Option<f64>,
    pub rx_bps: f64,
    pub tx_bps: f64,
}

impl IfaceObs {
    pub fn utilisation_pct(&self) -> Option<f64> {
        let rate = self.link_rate_bps?;
        if rate <= 0.0 {
            return None;
        }
        Some((self.rx_bps.max(self.tx_bps) / rate) * 100.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsObs {
    pub resolver: String,
    pub rtt_p50_ms: Option<f64>,
    pub rtt_p95_ms: Option<f64>,
    pub failure_rate_pct: f64,
    pub truncation_rate_pct: f64,
    pub queries: u32,
    pub failed: u32,
    pub truncated: u32,
    /// A second resolver probed over the same path, for discrimination.
    pub alt_resolver: Option<String>,
    pub alt_rtt_ms: Option<f64>,
    /// ICMP rtt to the resolver itself — separates "slow to answer" from
    /// "slow to reach".
    pub icmp_rtt_ms: Option<f64>,
    /// Cached names still answering fast points at the upstream forwarder.
    pub cached_rtt_ms: Option<f64>,
    pub window_secs: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GatewayObs {
    pub addr: Option<String>,
    pub rtt_ms: Option<f64>,
    pub loss_pct: f64,
    pub arp_ok: bool,
    pub icmp_ok: bool,
    /// Whether a host beyond the gateway answered. This is the corroborating
    /// check that makes "gateway unreachable" safe to say.
    ///
    /// A failed gateway probe on its own means very little: plenty of routers
    /// drop ICMP echo and have no open TCP port, and an unprivileged netwatch
    /// cannot always send ICMP at all. But if something on the internet
    /// answered, packets are demonstrably transiting the gateway, and calling
    /// it unreachable would be flatly wrong — a `critical` that suppresses
    /// every other finding on the screen, raised against a working router.
    /// `None` when no internet probe has completed yet.
    pub internet_reachable: Option<bool>,
}

/// Everything a detector pass gets to look at.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Observations {
    pub now: String,
    pub iface: Option<IfaceObs>,
    pub gateway: Option<GatewayObs>,
    pub dns: Option<DnsObs>,
    pub paths: Vec<PathObs>,
    pub sockets: Vec<SocketObs>,
    /// Loaded-vs-idle rtt from the bufferbloat test, when one has run.
    pub idle_rtt_ms: Option<f64>,
    pub loaded_rtt_ms: Option<f64>,
    /// Set when the http 204 probe came back redirected.
    pub captive_portal_url: Option<String>,
}

/// A candidate issue. The engine supplies identity and history.
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub rule: &'static str,
    pub severity: Severity,
    pub title: String,
    pub subject: Subject,
    pub evidence: Vec<Evidence>,
    pub scope: Scope,
    pub causes: Vec<Cause>,
    pub remediation: Vec<Step>,
    pub verify: Verify,
}

impl Detection {
    fn new(rule: &'static str, subject: Subject) -> Self {
        let r = rules::lookup(rule).expect("detector references a catalogued rule");
        Self {
            rule,
            severity: r.severity,
            title: r.title.to_string(),
            subject,
            evidence: Vec::new(),
            scope: Scope::default(),
            causes: Vec::new(),
            remediation: Vec::new(),
            verify: rules::default_verify(rule).expect("catalogued rule has a verify"),
        }
    }

    /// Stable identity for merging across ticks: one issue per (rule, subject).
    pub fn key(&self) -> String {
        format!("{}|{}", self.rule, self.subject.label())
    }
}

/// Run every detector over one set of observations.
pub fn detect(obs: &Observations, base: &BaselineStore, t: &Thresholds) -> Vec<Detection> {
    let mut out = Vec::new();
    out.extend(detect_link(obs));
    out.extend(detect_gateway(obs, base, t));
    out.extend(detect_dns(obs, base, t));
    out.extend(detect_paths(obs, base, t));
    out.extend(detect_sockets(obs, t));
    out.extend(detect_bufferbloat_local(obs, t));
    out
}

// ---------------------------------------------------------------- link

fn detect_link(obs: &Observations) -> Vec<Detection> {
    let Some(iface) = &obs.iface else {
        return vec![];
    };
    let mut out = Vec::new();

    if !iface.carrier {
        let mut d = Detection::new(
            "link.down",
            Subject::Iface {
                name: iface.name.clone(),
            },
        );
        d.evidence
            .push(Evidence::new("iface.carrier", 0.0, "").with_window(1, 1));
        d.causes = vec![
            Cause::new(
                "cable unplugged or the port is down",
                vec![CheckResult::fail("carrier", "no carrier on the interface")],
            ),
            Cause::new(
                "wifi disassociated",
                vec![CheckResult::skipped(
                    "wireless",
                    "no wireless statistics for this interface",
                )],
            ),
        ];
        d.remediation = vec![
            Step::instruct(
                "check the cable or reassociate",
                format!("ip link show {}", iface.name),
            ),
            Step::instruct(
                "bring the interface up",
                format!("ip link set {} up", iface.name),
            ),
        ];
        out.push(d);
        // Nothing else on this interface means anything while it is down.
        return out;
    }

    let t = Thresholds::default();
    if iface.errors_per_min as f64 >= t.iface_error_floor
        || iface.drops_per_min as f64 >= t.iface_drop_floor
    {
        let mut d = Detection::new(
            "iface.errors",
            Subject::Iface {
                name: iface.name.clone(),
            },
        );
        d.evidence.push(
            Evidence::new(
                "iface.error_rate",
                (iface.errors_per_min + iface.drops_per_min) as f64,
                "/min",
            )
            .with_window(60, 1),
        );
        d.causes = vec![
            Cause::new(
                "ring buffer too small for the offered rate",
                vec![if iface.drops_per_min > iface.errors_per_min {
                    CheckResult::pass(
                        "drops dominate",
                        format!(
                            "{} drops vs {} errors",
                            iface.drops_per_min, iface.errors_per_min
                        ),
                    )
                } else {
                    CheckResult::fail(
                        "drops dominate",
                        format!(
                            "{} drops vs {} errors",
                            iface.drops_per_min, iface.errors_per_min
                        ),
                    )
                }],
            ),
            Cause::new(
                "bad cable or duplex mismatch",
                vec![if iface.errors_per_min > iface.drops_per_min {
                    CheckResult::pass(
                        "errors dominate",
                        format!("{} errors this window", iface.errors_per_min),
                    )
                } else {
                    CheckResult::fail(
                        "errors dominate",
                        format!("only {} errors this window", iface.errors_per_min),
                    )
                }],
            ),
        ];
        d.remediation = vec![
            Step::instruct(
                "grow the rx ring",
                format!("ethtool -G {} rx 4096", iface.name),
            ),
            Step::instruct("check for softirq drops", "cat /proc/net/softnet_stat"),
        ];
        out.push(d);
    }

    if let Some(util) = iface.utilisation_pct() {
        if util >= Thresholds::default().saturation_pct {
            let mut d = Detection::new(
                "iface.saturated",
                Subject::Iface {
                    name: iface.name.clone(),
                },
            );
            d.evidence
                .push(Evidence::new("iface.utilisation", util, "%").with_window(30, 30));
            d.causes = vec![Cause::new(
                "the link is carrying as much as it can",
                vec![CheckResult::pass(
                    "utilisation",
                    format!("{util:.0}% of link rate"),
                )],
            )];
            d.remediation = vec![Step::instruct(
                "throttle or reschedule the top talker",
                "see the Processes tab for the flows holding the link",
            )];
            out.push(d);
        }
    }

    out
}

// ------------------------------------------------------------- gateway

fn detect_gateway(obs: &Observations, base: &BaselineStore, t: &Thresholds) -> Vec<Detection> {
    let Some(gw) = &obs.gateway else {
        return vec![];
    };
    if gw.arp_ok && gw.icmp_ok {
        return detect_gateway_rtt(gw, base, t);
    }
    // The probe failed, but the internet answered — so the gateway is
    // forwarding and simply doesn't reply to us. Not a finding.
    if gw.internet_reachable == Some(true) {
        return vec![];
    }
    let mut d = Detection::new("gateway.unreachable", Subject::Host);
    d.evidence
        .push(Evidence::new("gateway.loss", gw.loss_pct, "%").with_window(30, 30));
    let corroboration = match gw.internet_reachable {
        Some(false) => CheckResult::pass(
            "nothing beyond the gateway answers either",
            "the internet probe also failed, so this is not just a quiet router",
        )
        .weighted(3.0),
        Some(true) => CheckResult::fail(
            "nothing beyond the gateway answers either",
            "the internet is reachable through this gateway",
        )
        .weighted(3.0),
        None => CheckResult::skipped(
            "nothing beyond the gateway answers either",
            "no internet probe has completed yet",
        )
        .weighted(3.0),
    };

    d.causes = vec![
        Cause::new(
            "gateway is up but not answering icmp",
            vec![
                if gw.arp_ok {
                    CheckResult::pass("arp resolves", "the gateway answered arp")
                } else {
                    CheckResult::fail("arp resolves", "no arp reply from the gateway")
                },
                CheckResult::fail("icmp reaches the gateway", "no icmp echo reply"),
                corroboration.clone(),
            ],
        ),
        Cause::new(
            "wrong vlan or an address conflict",
            vec![
                if !gw.arp_ok {
                    CheckResult::pass("arp fails", "no arp reply — we may not be on its segment")
                } else {
                    CheckResult::fail("arp fails", "arp resolved normally")
                },
                corroboration,
            ],
        ),
    ];
    d.remediation = vec![
        Step::instruct("renew the dhcp lease", "dhclient -r && dhclient"),
        Step::instruct("confirm the default route", "ip route show default"),
    ];
    d.scope.note = Some("everything downstream is affected".into());
    vec![d]
}

/// A reachable gateway that has become slow to answer. Separates "the AP is
/// congested" from "the internet is slow", which is otherwise the hardest
/// distinction to make from a laptop.
fn detect_gateway_rtt(gw: &GatewayObs, base: &BaselineStore, t: &Thresholds) -> Vec<Detection> {
    let (Some(addr), Some(rtt)) = (gw.addr.clone(), gw.rtt_ms) else {
        return vec![];
    };
    let Some(b) = base.get(&addr, "gateway.rtt") else {
        // No usable baseline: there is no absolute rtt that means "slow
        // gateway" — 20ms is fine over wifi and terrible over ethernet — so
        // without a baseline this rule stays quiet rather than guessing.
        return vec![];
    };
    let Some(sigma) = b.sigma_above(rtt) else {
        return vec![];
    };
    if sigma < t.sigma_k {
        return vec![];
    }

    let mut d = Detection::new("gateway.rtt_spike", Subject::Iface { name: addr.clone() });
    d.subject = Subject::Host;
    d.evidence.push(
        Evidence::new("gateway.rtt", rtt, "ms")
            .with_baseline(b.mean, b.sigma())
            .with_window(30, 30),
    );
    d.evidence
        .push(Evidence::new("gateway.rtt_sigma", sigma, "σ").with_window(30, 30));
    d.causes = vec![
        Cause::new(
            "the local network or access point is congested",
            vec![CheckResult::pass(
                "gateway rtt above baseline",
                format!(
                    "{rtt:.1}ms against a {:.1}ms baseline ({sigma:.1}σ)",
                    b.mean
                ),
            )],
        ),
        Cause::new(
            "the gateway itself is loaded",
            vec![CheckResult::skipped(
                "gateway cpu",
                "netwatch cannot see inside the gateway",
            )],
        ),
    ];
    d.remediation = vec![
        Step::instruct(
            "check what is using the local link",
            "the Processes tab ranks flows by throughput",
        ),
        Step::instruct(
            "if wireless, check signal and channel",
            "a weak or contended channel shows up here first",
        ),
    ];
    vec![d]
}

// ----------------------------------------------------------------- dns

fn detect_dns(obs: &Observations, base: &BaselineStore, t: &Thresholds) -> Vec<Detection> {
    let Some(dns) = &obs.dns else {
        return vec![];
    };
    let mut out = Vec::new();

    if dns.failure_rate_pct > 5.0 {
        let mut d = Detection::new(
            "dns.failing",
            Subject::Resolver {
                addr: dns.resolver.clone(),
            },
        );
        d.evidence.push(
            Evidence::new("dns.failure_rate", dns.failure_rate_pct, "%")
                .with_window(dns.window_secs, dns.queries),
        );
        d.causes = vec![
            Cause::new(
                "resolver is down",
                vec![match dns.icmp_rtt_ms {
                    None => {
                        CheckResult::pass("resolver unreachable", "no icmp reply from the resolver")
                    }
                    Some(rtt) => CheckResult::fail(
                        "resolver unreachable",
                        format!("resolver answers icmp in {rtt:.1}ms"),
                    ),
                }],
            ),
            Cause::new(
                "resolver reachable but not answering queries",
                vec![match dns.icmp_rtt_ms {
                    Some(rtt) => CheckResult::pass(
                        "resolver reachable",
                        format!("icmp {rtt:.1}ms but queries fail — udp/53 may be filtered"),
                    ),
                    None => CheckResult::fail("resolver reachable", "no icmp reply either"),
                }],
            ),
        ];
        d.remediation = dns_remediation(dns);
        out.push(d);
        // A resolver that is failing outright makes its latency uninteresting.
        return out;
    }

    let Some(p50) = dns.rtt_p50_ms else {
        return out;
    };

    let baseline = base.get(&dns.resolver, "dns.rtt_p50");
    let over_ceiling = p50 > t.dns_ceiling_ms;
    let over_sigma = baseline
        .and_then(|b| b.sigma_above(p50))
        .map(|s| s >= t.sigma_k)
        .unwrap_or(false);

    if !over_ceiling && !over_sigma {
        return out;
    }

    let mut ev = Evidence::new("dns.rtt_p50", p50, "ms").with_window(dns.window_secs, dns.queries);
    if let Some(b) = baseline {
        ev = ev.with_baseline(b.mean, b.sigma());
    }

    let mut d = Detection::new(
        "dns.slow_resolver",
        Subject::Resolver {
            addr: dns.resolver.clone(),
        },
    );
    // Severity escalates with the multiple of baseline, not with the raw
    // number — 40ms is catastrophic against a 1.2ms LAN resolver and
    // unremarkable against a 35ms mobile one.
    d.severity = match ev.multiple_of_baseline() {
        Some(m) if m >= 20.0 => Severity::High,
        _ => Severity::Medium,
    };
    d.evidence.push(ev);
    if let Some(p95) = dns.rtt_p95_ms {
        d.evidence.push(
            Evidence::new("dns.rtt_p95", p95, "ms").with_window(dns.window_secs, dns.queries),
        );
    }

    let alt_fast = matches!(dns.alt_rtt_ms, Some(a) if a < p50 / 4.0);
    let icmp_normal = dns.icmp_rtt_ms.map(|r| r < 10.0);
    let cached_fast = matches!(dns.cached_rtt_ms, Some(c) if c < p50 / 4.0);

    d.causes = vec![
        Cause::new(
            "the resolver's upstream forwarder is slow",
            vec![
                match (dns.alt_resolver.as_deref(), dns.alt_rtt_ms) {
                    (Some(alt), Some(rtt)) if alt_fast => CheckResult::pass(
                        "alt resolver is fast",
                        format!("{alt} answered in {rtt:.1}ms"),
                    )
                    .weighted(2.0),
                    (Some(alt), Some(rtt)) => CheckResult::fail(
                        "alt resolver is fast",
                        format!("{alt} is also slow at {rtt:.1}ms"),
                    )
                    .weighted(2.0),
                    _ => {
                        CheckResult::skipped("alt resolver is fast", "no alternate resolver probed")
                            .weighted(2.0)
                    }
                },
                match (icmp_normal, dns.icmp_rtt_ms) {
                    (Some(true), Some(rtt)) => CheckResult::pass(
                        "resolver itself is reachable",
                        format!("icmp {rtt:.1}ms — the box is fine, its answers are not"),
                    ),
                    (Some(false), Some(rtt)) => CheckResult::fail(
                        "resolver itself is reachable",
                        format!("icmp {rtt:.1}ms is slow too"),
                    ),
                    _ => CheckResult::skipped("resolver itself is reachable", "no icmp probe"),
                },
                match (cached_fast, dns.cached_rtt_ms) {
                    (true, Some(c)) => CheckResult::pass(
                        "cached names still fast",
                        format!("cache hits answer in {c:.1}ms — only recursion is slow"),
                    ),
                    (false, Some(c)) => CheckResult::fail(
                        "cached names still fast",
                        format!("even cache hits take {c:.1}ms"),
                    ),
                    _ => CheckResult::skipped("cached names still fast", "no cache probe"),
                },
            ],
        ),
        Cause::new(
            "the resolver is overloaded",
            vec![
                match (icmp_normal, dns.icmp_rtt_ms) {
                    (Some(false), Some(rtt)) => CheckResult::pass(
                        "icmp rtt raised",
                        format!("icmp to the resolver is {rtt:.1}ms"),
                    ),
                    (Some(true), Some(rtt)) => CheckResult::fail(
                        "icmp rtt raised",
                        format!("icmp is normal at {rtt:.1}ms"),
                    ),
                    _ => CheckResult::skipped("icmp rtt raised", "no icmp probe"),
                },
                if dns.failed > 0 || dns.truncated > 0 {
                    CheckResult::pass(
                        "timeouts or servfail present",
                        format!("{} failed, {} truncated", dns.failed, dns.truncated),
                    )
                } else {
                    CheckResult::fail("timeouts or servfail present", "no failures, only latency")
                },
            ],
        ),
        Cause::new(
            "local: conntrack, udp buffers or nftables",
            vec![
                if alt_fast {
                    CheckResult::fail(
                        "alt resolver over the same path is also slow",
                        "the alternate resolver is fast over the same path",
                    )
                } else {
                    CheckResult::pass(
                        "alt resolver over the same path is also slow",
                        "both resolvers are slow — the problem may be local",
                    )
                },
                match obs.iface.as_ref().map(|i| i.drops_per_min) {
                    Some(d) if d > 0 => {
                        CheckResult::pass("interface drops", format!("{d} drops this window"))
                    }
                    Some(_) => CheckResult::fail("interface drops", "no drops on the interface"),
                    None => CheckResult::skipped("interface drops", "no interface counters"),
                },
            ],
        ),
    ];

    d.remediation = dns_remediation(dns);
    d.verify = Verify::below("dns.rtt_p50", 5.0, "ms").holding_for(60);
    d.scope = Scope {
        processes: vec![],
        destinations: 0,
        flows: 0,
        note: Some("every new connection pays this before it can start".into()),
    };
    out.push(d);
    out
}

fn dns_remediation(dns: &DnsObs) -> Vec<Step> {
    let mut steps = Vec::new();
    if let Some(alt) = &dns.alt_resolver {
        let detail = match dns.alt_rtt_ms {
            Some(rtt) => format!(
                "writes resolv.conf, keeps a backup, and puts it back on quit \
                 (measured {rtt:.1}ms during the check)"
            ),
            None => "writes resolv.conf, keeps a backup, and puts it back on quit".to_string(),
        };
        steps.push(Step::apply(
            '1',
            format!("switch this session's resolver to {alt}"),
            detail,
            Action::SetResolver { addr: alt.clone() },
            Capability::Root,
        ));
        steps.push(Step::instruct(
            "make it permanent",
            format!("resolvectl dns <iface> {alt}, or set it in the dhcp client"),
        ));
    }
    steps.push(Step::instruct(
        "keep watching",
        "netwatch re-evaluates every tick and closes the issue when it clears",
    ));
    steps.push(Step::escalate(
        "if you run the resolver",
        "check its upstream forwarder and consider a second one",
    ));
    steps
}

// ---------------------------------------------------------------- paths

fn detect_paths(obs: &Observations, base: &BaselineStore, t: &Thresholds) -> Vec<Detection> {
    let mut out = Vec::new();
    for path in &obs.paths {
        if let Some(d) = detect_path_change(path) {
            out.push(d);
        }
        if let Some(d) = detect_path_loss(path) {
            out.push(d);
        }
        if let Some(d) = detect_path_rtt(path, base, t) {
            out.push(d);
        }
    }
    out
}

/// End-to-end rtt drifting above what this path normally does. The last hop's
/// rtt is the whole path's rtt; earlier hops are only interesting for
/// attributing *where* the time went, which the cause list does.
fn detect_path_rtt(path: &PathObs, base: &BaselineStore, t: &Thresholds) -> Option<Detection> {
    let last = path.hops.iter().rev().find(|h| !h.silent)?;
    let rtt = last.rtt_p50_ms?;
    let b = base
        .get(&path.target, "path.rtt")
        .or_else(|| base.get("internet", "path.rtt"))?;
    let sigma = b.sigma_above(rtt)?;
    if sigma < t.sigma_k {
        return None;
    }

    // Where the extra latency entered the path: the hop with the largest
    // jump over its predecessor.
    let worst_jump = path
        .hops
        .windows(2)
        .filter_map(|w| match (w[0].rtt_p50_ms, w[1].rtt_p50_ms) {
            (Some(a), Some(c)) if !w[1].silent => Some((w[1].number, c - a)),
            _ => None,
        })
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut d = Detection::new(
        "path.rtt_spike",
        Subject::Path {
            target: path.target.clone(),
        },
    );
    d.evidence.push(
        Evidence::new("path.rtt", rtt, "ms")
            .with_baseline(b.mean, b.sigma())
            .with_window(60, 60),
    );
    d.evidence
        .push(Evidence::new("path.rtt_sigma", sigma, "σ").with_window(60, 60));
    d.causes = vec![
        Cause::new(
            match worst_jump {
                Some((hop, _)) => format!("latency enters the path at hop {hop}"),
                None => "latency is spread across the path".to_string(),
            },
            vec![match worst_jump {
                Some((hop, delta)) => CheckResult::pass(
                    "one hop dominates",
                    format!("hop {hop} adds {delta:.0}ms over its predecessor"),
                ),
                None => CheckResult::skipped(
                    "one hop dominates",
                    "not enough per-hop timing to attribute the increase",
                ),
            }],
        ),
        Cause::new(
            "a route change moved the traffic",
            vec![match &path.previous {
                Some(prev) => match first_hop_change(prev, &path.hops) {
                    Some(hop) => CheckResult::pass(
                        "the path changed",
                        format!("hop {hop} differs from the previous trace"),
                    ),
                    None => CheckResult::fail("the path changed", "the route is unchanged"),
                },
                None => CheckResult::skipped("the path changed", "no previous trace to compare"),
            }],
        ),
    ];
    d.remediation = vec![Step::instruct(
        "trace the target",
        "the hop table shows p50/p95 per hop and the diff against the last trace",
    )];
    Some(d)
}

/// Diff two traces. Returns the first hop number whose IP or ASN changed.
pub fn first_hop_change(previous: &[HopObs], current: &[HopObs]) -> Option<u8> {
    for cur in current {
        let Some(prev) = previous.iter().find(|h| h.number == cur.number) else {
            continue;
        };
        // A hop that has gone silent, or come back, is not a route change —
        // routers rate-limit ICMP and drop in and out of traces constantly.
        if prev.silent || cur.silent {
            continue;
        }
        if prev.ip != cur.ip || (prev.asn.is_some() && cur.asn.is_some() && prev.asn != cur.asn) {
            return Some(cur.number);
        }
    }
    None
}

fn detect_path_change(path: &PathObs) -> Option<Detection> {
    let previous = path.previous.as_ref()?;
    let hop_no = first_hop_change(previous, &path.hops)?;
    let cur = path.hops.iter().find(|h| h.number == hop_no)?;
    let prev = previous.iter().find(|h| h.number == hop_no)?;

    let mut d = Detection::new(
        "path.changed",
        Subject::Path {
            target: path.target.clone(),
        },
    );

    // Latency the new hop added is what turns a route change from a note into
    // a finding — and it leads the evidence, because "hop 3 changed" is the
    // headline nobody can act on while "+40ms" is the one they can. The
    // change count still rides along; it is what `verify` closes against.
    let added_latency = match (cur.rtt_p50_ms, prev.rtt_p50_ms) {
        (Some(c), Some(p)) => Some(c - p),
        _ => None,
    };
    if let Some(j) = added_latency {
        // No baseline on a delta: "+40ms" against a 12ms previous hop would
        // render as "3.3× baseline", which is a true division and a
        // meaningless statement.
        d.evidence
            .push(Evidence::new("path.hop_rtt_delta", j, "ms added").with_window(60, 1));
        if j > 20.0 {
            d.severity = Severity::Medium;
        }
    }
    d.evidence
        .push(Evidence::new("path.hop_changes", 1.0, " hop").with_window(60, 1));

    let asn_changed = prev.asn != cur.asn;
    d.causes = vec![
        Cause::new(
            if asn_changed {
                "the traffic moved to a different provider"
            } else {
                "the provider rerouted inside its own network"
            },
            vec![
                if asn_changed {
                    CheckResult::pass(
                        "asn changed",
                        format!(
                            "hop {hop_no}: {} → {}",
                            prev.asn.as_deref().unwrap_or("unknown"),
                            cur.asn.as_deref().unwrap_or("unknown")
                        ),
                    )
                } else {
                    CheckResult::pass(
                        "asn unchanged",
                        format!(
                            "hop {hop_no} stayed in {}",
                            cur.asn.as_deref().unwrap_or("the same asn")
                        ),
                    )
                },
                CheckResult::pass(
                    "hop address changed",
                    format!(
                        "{} → {}",
                        prev.ip.as_deref().unwrap_or("—"),
                        cur.ip.as_deref().unwrap_or("—")
                    ),
                ),
            ],
        ),
        Cause::new(
            "a local route or interface changed",
            vec![if hop_no <= 2 {
                CheckResult::pass("change is at hop 1 or 2", "the change is on our side")
            } else {
                CheckResult::fail(
                    "change is at hop 1 or 2",
                    format!("the change is at hop {hop_no}, upstream of us"),
                )
            }],
        ),
    ];
    d.remediation = vec![
        Step::instruct(
            "nothing to do",
            "a route change is context, not a fault — netwatch keeps it on the \
             timeline so a later issue can be correlated with it",
        ),
        Step::escalate(
            "if problems started with it",
            "send the before/after trace to the provider",
        ),
    ];
    Some(d)
}

fn detect_path_loss(path: &PathObs) -> Option<Detection> {
    // Loss only counts when it propagates. A hop that drops probes while
    // later hops are clean is rate-limiting ICMP, not losing traffic.
    let mut culprit: Option<&HopObs> = None;
    for (i, hop) in path.hops.iter().enumerate() {
        if hop.silent || hop.loss_pct < 5.0 {
            continue;
        }
        let later_also_lossy = path.hops[i + 1..]
            .iter()
            .filter(|h| !h.silent)
            .any(|h| h.loss_pct >= 5.0);
        let is_last = path.hops[i + 1..].iter().all(|h| h.silent);
        if later_also_lossy || is_last {
            culprit = Some(hop);
            break;
        }
    }
    let hop = culprit?;

    let mut d = Detection::new(
        "path.high_loss",
        Subject::Path {
            target: path.target.clone(),
        },
    );
    d.evidence
        .push(Evidence::new("path.hop_loss", hop.loss_pct, "%").with_window(60, 1));
    d.causes = vec![
        Cause::new(
            format!(
                "hop {} ({}) is dropping traffic",
                hop.number,
                hop.ip.as_deref().unwrap_or("unknown")
            ),
            vec![CheckResult::pass(
                "loss propagates to later hops",
                format!("{:.0}% at hop {} and beyond", hop.loss_pct, hop.number),
            )],
        ),
        Cause::new(
            "the hop is rate-limiting icmp rather than losing traffic",
            vec![CheckResult::fail(
                "later hops are clean",
                "later hops lose packets too, so this is real loss",
            )],
        ),
    ];
    d.remediation = vec![
        Step::instruct(
            "try a different path",
            "a vpn or alternate route avoids the hop",
        ),
        Step::escalate(
            "send the trace to the provider",
            "the exported bundle contains the full trace with per-hop loss",
        ),
    ];
    Some(d)
}

// -------------------------------------------------------------- sockets

fn detect_sockets(obs: &Observations, t: &Thresholds) -> Vec<Detection> {
    let mut out = Vec::new();
    for s in &obs.sockets {
        let verdict = classify_socket(s, t);
        if verdict.is_ok() {
            continue;
        }
        // Hysteresis: a verdict has to stick before it becomes a finding.
        // Without this, every slow-start ramp opens and closes an issue.
        if s.verdict_age_secs < t.verdict_hold_secs {
            continue;
        }
        if let Some(d) = socket_detection(s, verdict, obs) {
            out.push(d);
        }
    }
    out
}

fn socket_detection(
    s: &SocketObs,
    verdict: SocketVerdict,
    obs: &Observations,
) -> Option<Detection> {
    let subject = Subject::Socket {
        local: s.local.clone(),
        remote: s.remote.clone(),
    };
    let rtt = s.rtt_ms.unwrap_or(0.0);
    let link_test_passed = match (obs.idle_rtt_ms, obs.loaded_rtt_ms) {
        (Some(idle), Some(loaded)) => {
            Some(loaded - idle < Thresholds::default().loaded_rtt_delta_ms)
        }
        _ => None,
    };

    let mut d = match verdict {
        SocketVerdict::Bufferbloat => {
            let mut d = Detection::new("tcp.bufferbloat_remote", subject);
            d.evidence
                .push(Evidence::new("tcp.socket_rtt", rtt, "ms").with_window(30, 30));
            d.evidence
                .push(Evidence::new("tcp.retrans", s.retrans as f64, "").with_window(30, 30));
            d.causes = vec![
                Cause::new(
                    "the receiver is queueing — its buffer, not ours",
                    vec![
                        match link_test_passed {
                            Some(true) => CheckResult::pass(
                                "link-level bufferbloat test passed",
                                "our uplink stays responsive under load",
                            )
                            .weighted(2.0),
                            Some(false) => CheckResult::fail(
                                "link-level bufferbloat test passed",
                                "our own uplink bloats under load too",
                            )
                            .weighted(2.0),
                            None => CheckResult::skipped(
                                "link-level bufferbloat test passed",
                                "no loaded-rtt test has run",
                            )
                            .weighted(2.0),
                        },
                        if s.tx_bps > 0.0 {
                            CheckResult::pass(
                                "rtt tracks this socket's own tx",
                                format!("{} in flight while rtt is {rtt:.0}ms", rate(s.tx_bps)),
                            )
                        } else {
                            CheckResult::fail("rtt tracks this socket's own tx", "socket is idle")
                        },
                    ],
                ),
                Cause::new(
                    "loss on the path",
                    // Retransmit count is *not* the discriminator here: a
                    // bufferbloated socket retransmits because the queue
                    // delays its ACKs past the RTO, so "12 retransmits"
                    // supports both causes equally and ranking on it is a
                    // coin toss dressed up as analysis. What separates them
                    // is whether the path is actually losing packets — which
                    // takes a trace, and says so when it hasn't got one.
                    vec![path_loss_check(&s.remote, obs)],
                ),
            ];
            d.remediation = vec![
                Step::instruct(
                    "nothing to fix locally",
                    "the queue is on the receiver; the report names the peer",
                ),
                Step::escalate(
                    "tell whoever runs the peer",
                    "ask for fq_codel or cake on its egress",
                ),
            ];
            d
        }
        SocketVerdict::RetransBurst => {
            let mut d = Detection::new("tcp.retrans_burst", subject);
            d.evidence.push(
                Evidence::new("tcp.retrans_rate", s.retrans as f64, "/min").with_window(60, 60),
            );
            d.causes = vec![Cause::new(
                "packet loss between here and the peer",
                vec![CheckResult::pass(
                    "retransmits observed",
                    format!("{} retransmits on this socket", s.retrans),
                )],
            )];
            d.remediation = vec![Step::instruct(
                "trace the peer",
                "press t to trace and see which hop loses",
            )];
            d
        }
        SocketVerdict::ZeroWindow => {
            let mut d = Detection::new("tcp.zero_window", subject);
            d.evidence
                .push(Evidence::new("tcp.rwnd", 0.0, "B").with_window(30, 30));
            d.causes = vec![Cause::new(
                "the peer application is not reading its socket",
                vec![CheckResult::pass(
                    "rwnd is zero",
                    "the receive window has closed",
                )],
            )];
            d.remediation = vec![Step::instruct(
                "nothing to fix on this side",
                "the report names the peer and the local process",
            )];
            d
        }
        SocketVerdict::ReceiverLimited => {
            let mut d = Detection::new("tcp.zero_window", subject);
            d.severity = Severity::Info;
            d.title = "receiver-limited socket".into();
            d.evidence.push(
                Evidence::new("tcp.rwnd", s.rwnd.unwrap_or(0) as f64, "B").with_window(30, 30),
            );
            d.causes = vec![Cause::new(
                "the peer is reading slower than we can send",
                vec![CheckResult::pass(
                    "cwnd exceeds rwnd",
                    format!(
                        "cwnd {} × mss {} is more than twice rwnd {}",
                        s.cwnd.unwrap_or(0),
                        s.mss.unwrap_or(0),
                        s.rwnd.unwrap_or(0)
                    ),
                )],
            )];
            d.remediation = vec![Step::instruct(
                "nothing to fix on this side",
                "the sending side is healthy; the peer sets the pace",
            )];
            d
        }
        // Congestion and app-limited are normal states, not faults. They show
        // as verdicts in the Connections column and never open an issue.
        SocketVerdict::Congestion | SocketVerdict::AppLimited | SocketVerdict::Ok => return None,
    };

    d.scope = Scope {
        processes: s.process.iter().cloned().collect(),
        destinations: 1,
        flows: 1,
        note: None,
    };
    Some(d)
}

/// Whether a traced path to this peer is losing packets. Tri-state on
/// purpose: without a trace there is no evidence either way, and reporting
/// that as a failed check would let an untested cause be "ruled out".
fn path_loss_check(remote: &str, obs: &Observations) -> CheckResult {
    let host = remote.rsplit_once(':').map(|(h, _)| h).unwrap_or(remote);
    let Some(path) = obs.paths.iter().find(|p| p.target == host) else {
        return CheckResult::skipped(
            "the path to this peer is losing packets",
            format!("no trace to {host} — press t to run one"),
        );
    };
    match path.hops.iter().find(|h| !h.silent && h.loss_pct >= 5.0) {
        Some(hop) => CheckResult::pass(
            "the path to this peer is losing packets",
            format!("hop {} loses {:.0}%", hop.number, hop.loss_pct),
        ),
        None => CheckResult::fail(
            "the path to this peer is losing packets",
            "every hop on the traced path is clean",
        ),
    }
}

fn rate(bps: f64) -> String {
    if bps >= 1e6 {
        format!("{:.1} MB/s", bps / 1e6)
    } else if bps >= 1e3 {
        format!("{:.0} KB/s", bps / 1e3)
    } else {
        format!("{bps:.0} B/s")
    }
}

fn detect_bufferbloat_local(obs: &Observations, t: &Thresholds) -> Vec<Detection> {
    let (Some(idle), Some(loaded)) = (obs.idle_rtt_ms, obs.loaded_rtt_ms) else {
        return vec![];
    };
    let delta = loaded - idle;
    if delta < t.loaded_rtt_delta_ms {
        return vec![];
    }
    let mut d = Detection::new("tcp.bufferbloat_local", Subject::Host);
    d.evidence
        .push(Evidence::new("tcp.loaded_rtt_delta", delta, "ms").with_window(30, 30));
    d.causes = vec![Cause::new(
        "no queue management on the upstream device",
        vec![CheckResult::pass(
            "rtt rises under our own load",
            format!("idle {idle:.0}ms → loaded {loaded:.0}ms"),
        )],
    )];
    d.remediation = vec![
        Step::instruct(
            "enable fq_codel or cake on the router",
            "on Linux: tc qdisc replace dev <wan> root cake bandwidth <uplink>",
        ),
        Step::instruct(
            "or rate-limit uploads to ~95% of the uplink",
            "leaves the queue empty enough to stay responsive",
        ),
    ];
    vec![d]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::baseline::NetworkFingerprint;

    fn store() -> BaselineStore {
        BaselineStore::new(NetworkFingerprint::new(
            "eth0",
            Some("192.168.8.1".into()),
            vec!["169.254.1.1".into()],
            None,
        ))
        .with_min_samples(3)
    }

    fn slow_dns() -> DnsObs {
        DnsObs {
            resolver: "169.254.1.1".into(),
            rtt_p50_ms: Some(40.0),
            rtt_p95_ms: Some(48.0),
            failure_rate_pct: 0.0,
            truncation_rate_pct: 5.2,
            queries: 38,
            failed: 0,
            truncated: 2,
            alt_resolver: Some("192.168.8.1".into()),
            alt_rtt_ms: Some(1.4),
            icmp_rtt_ms: Some(0.1),
            cached_rtt_ms: Some(0.9),
            window_secs: 180,
        }
    }

    fn obs_with_dns(dns: DnsObs) -> Observations {
        Observations {
            now: "2026-09-03 06:51:19".into(),
            dns: Some(dns),
            ..Default::default()
        }
    }

    #[test]
    fn slow_resolver_fires_and_ranks_the_forwarder_first() {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let obs = obs_with_dns(slow_dns());

        let found = detect(&obs, &base, &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "dns.slow_resolver")
            .expect("dns.slow_resolver should fire");

        assert_eq!(
            d.severity,
            Severity::High,
            "33× baseline is a high, not a medium"
        );
        let ev = &d.evidence[0];
        assert_eq!(ev.multiple_label().unwrap(), "33× baseline");

        let mut causes = d.causes.clone();
        causes.sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap());
        assert!(
            causes[0].label.contains("upstream forwarder"),
            "expected the forwarder cause on top, got {:?}",
            causes[0].label
        );
        assert_eq!(
            causes[0].confidence(),
            super::super::issue::Confidence::Strong
        );
    }

    #[test]
    fn a_slow_alt_resolver_moves_the_blame_local() {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let mut dns = slow_dns();
        dns.alt_rtt_ms = Some(38.0); // the alternate is slow too
        dns.cached_rtt_ms = Some(37.0);
        let obs = obs_with_dns(dns);

        let found = detect(&obs, &base, &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "dns.slow_resolver")
            .unwrap();
        let mut causes = d.causes.clone();
        causes.sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap());
        assert!(
            causes[0].label.contains("local"),
            "both resolvers slow should point local, got {:?}",
            causes[0].label
        );
    }

    #[test]
    fn dns_does_not_fire_on_a_normal_resolver() {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let mut dns = slow_dns();
        dns.rtt_p50_ms = Some(1.3);
        let obs = obs_with_dns(dns);
        assert!(detect(&obs, &base, &Thresholds::default()).is_empty());
    }

    #[test]
    fn the_absolute_ceiling_fires_without_any_baseline() {
        // First run on a new network: no baseline at all, but 40ms of DNS
        // latency is still worth saying out loud.
        let base = store();
        let obs = obs_with_dns(slow_dns());
        let found = detect(&obs, &base, &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "dns.slow_resolver")
            .unwrap();
        assert_eq!(
            d.severity,
            Severity::Medium,
            "no baseline means no multiple, so no escalation"
        );
        assert!(d.evidence[0].baseline.is_none());
        assert!(d.evidence[0].multiple_label().is_none());
    }

    #[test]
    fn failing_dns_replaces_slow_dns_rather_than_joining_it() {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let mut dns = slow_dns();
        dns.failure_rate_pct = 40.0;
        dns.failed = 15;
        let found = detect(&obs_with_dns(dns), &base, &Thresholds::default());
        assert!(found.iter().any(|d| d.rule == "dns.failing"));
        assert!(
            !found.iter().any(|d| d.rule == "dns.slow_resolver"),
            "a resolver that isn't answering shouldn't also be reported as slow"
        );
    }

    // ------------------------------------------------------------ sockets

    fn bloated_socket() -> SocketObs {
        SocketObs {
            local: "10.88.0.2:52344".into(),
            remote: "10.88.0.3:9000".into(),
            process: Some("ncat".into()),
            rtt_ms: Some(184.0),
            rttvar_ms: Some(40.0),
            retrans: 12,
            cwnd: Some(10),
            ssthresh: Some(u32::MAX),
            rwnd: Some(64_000),
            mss: Some(1448),
            tx_bps: 2.4e6,
            rx_bps: 0.0,
            verdict_age_secs: 90,
        }
    }

    #[test]
    fn classifies_a_bloated_socket() {
        assert_eq!(
            classify_socket(&bloated_socket(), &Thresholds::default()),
            SocketVerdict::Bufferbloat
        );
    }

    #[test]
    fn a_zero_window_beats_every_other_verdict() {
        let mut s = bloated_socket();
        s.rwnd = Some(0);
        assert_eq!(
            classify_socket(&s, &Thresholds::default()),
            SocketVerdict::ZeroWindow
        );
    }

    #[test]
    fn an_idle_socket_with_a_distant_peer_is_not_bloated() {
        let mut s = bloated_socket();
        s.tx_bps = 0.0;
        s.rx_bps = 0.0;
        s.retrans = 0;
        assert_eq!(
            classify_socket(&s, &Thresholds::default()),
            SocketVerdict::AppLimited,
            "high rtt with nothing in flight is just distance"
        );
    }

    #[test]
    fn a_receiver_that_stops_reading_is_receiver_limited() {
        let mut s = bloated_socket();
        s.rtt_ms = Some(12.0);
        s.retrans = 0;
        s.cwnd = Some(100); // 100 × 1448 = 144KB against a 32KB window
        s.rwnd = Some(32_000);
        assert_eq!(
            classify_socket(&s, &Thresholds::default()),
            SocketVerdict::ReceiverLimited
        );
    }

    #[test]
    fn a_verdict_must_persist_before_it_becomes_an_issue() {
        let mut s = bloated_socket();
        s.verdict_age_secs = 5;
        let obs = Observations {
            sockets: vec![s.clone()],
            ..Default::default()
        };
        assert!(
            detect(&obs, &store(), &Thresholds::default()).is_empty(),
            "a 5-second-old verdict is a transient, not a finding"
        );

        s.verdict_age_secs = 45;
        let obs = Observations {
            sockets: vec![s],
            ..Default::default()
        };
        assert_eq!(detect(&obs, &store(), &Thresholds::default()).len(), 1);
    }

    #[test]
    fn retransmits_do_not_let_path_loss_tie_with_the_queue() {
        // 12 retransmits are consistent with both causes, so they must not
        // decide between them. Without a trace, path loss is untested and
        // ranks below the cause whose checks actually passed.
        let obs = Observations {
            sockets: vec![bloated_socket()],
            idle_rtt_ms: Some(12.0),
            loaded_rtt_ms: Some(18.0),
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "tcp.bufferbloat_remote")
            .unwrap();

        let queue = &d.causes[0];
        let loss = &d.causes[1];
        assert!(queue.label.contains("receiver is queueing"));
        assert_eq!(queue.confidence(), super::super::issue::Confidence::Strong);
        assert_eq!(
            loss.confidence(),
            super::super::issue::Confidence::Untested,
            "no trace means no verdict on path loss, not a strong one"
        );
        assert!(loss.checks[0].detail.contains("press t to run one"));
    }

    #[test]
    fn a_lossy_traced_path_does_support_the_loss_cause() {
        let mut hops = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
        ];
        hops[1].loss_pct = 30.0;
        let obs = Observations {
            sockets: vec![bloated_socket()],
            paths: vec![PathObs {
                target: "10.88.0.3".into(),
                hops,
                previous: None,
                traced_at: "now".into(),
            }],
            idle_rtt_ms: Some(12.0),
            loaded_rtt_ms: Some(18.0),
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "tcp.bufferbloat_remote")
            .unwrap();
        let loss = d
            .causes
            .iter()
            .find(|c| c.label.contains("loss on the path"))
            .unwrap();
        assert_eq!(loss.confidence(), super::super::issue::Confidence::Strong);
    }

    #[test]
    fn remote_bufferbloat_needs_the_local_test_to_have_passed() {
        let obs = Observations {
            sockets: vec![bloated_socket()],
            idle_rtt_ms: Some(12.0),
            loaded_rtt_ms: Some(18.0), // our uplink is fine
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "tcp.bufferbloat_remote")
            .unwrap();
        assert_eq!(
            d.causes[0].confidence(),
            super::super::issue::Confidence::Strong
        );
        assert!(!found.iter().any(|d| d.rule == "tcp.bufferbloat_local"));
    }

    #[test]
    fn a_bloated_uplink_opens_the_local_issue_too() {
        let obs = Observations {
            sockets: vec![bloated_socket()],
            idle_rtt_ms: Some(12.0),
            loaded_rtt_ms: Some(320.0),
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        assert!(found.iter().any(|d| d.rule == "tcp.bufferbloat_local"));
        // And the remote cause's discriminating check now fails.
        let remote = found
            .iter()
            .find(|d| d.rule == "tcp.bufferbloat_remote")
            .unwrap();
        assert_ne!(
            remote.causes[0].confidence(),
            super::super::issue::Confidence::Strong
        );
    }

    // ------------------------------------------------------------ gateway

    fn dead_gateway() -> GatewayObs {
        GatewayObs {
            addr: Some("192.168.8.1".into()),
            rtt_ms: None,
            loss_pct: 100.0,
            arp_ok: false,
            icmp_ok: false,
            internet_reachable: Some(false),
        }
    }

    #[test]
    fn a_gateway_that_ignores_icmp_is_not_reported_as_unreachable() {
        // The single most damaging false positive available: a `critical`
        // that suppresses every other finding, raised because an
        // unprivileged netwatch could not ping a router that is working.
        let obs = Observations {
            gateway: Some(GatewayObs {
                internet_reachable: Some(true),
                ..dead_gateway()
            }),
            ..Default::default()
        };
        assert!(
            detect(&obs, &store(), &Thresholds::default()).is_empty(),
            "the internet answered through this gateway — it is plainly up"
        );
    }

    #[test]
    fn a_genuinely_dead_gateway_still_fires() {
        let obs = Observations {
            gateway: Some(dead_gateway()),
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "gateway.unreachable")
            .expect("nothing answers anywhere — this is a real outage");
        assert_eq!(d.severity, Severity::Critical);
    }

    #[test]
    fn an_unprobed_internet_weakens_the_finding_rather_than_hiding_it() {
        let obs = Observations {
            gateway: Some(GatewayObs {
                internet_reachable: None,
                ..dead_gateway()
            }),
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "gateway.unreachable")
            .expect("still worth raising");
        // The corroborating check is weighted 3× and reports "not run", so it
        // neither props the cause up nor counts against it.
        let top = d.causes.iter().max_by(|a, b| {
            a.score()
                .unwrap_or(0.0)
                .partial_cmp(&b.score().unwrap_or(0.0))
                .unwrap()
        });
        assert!(top.is_some());
        assert!(d
            .causes
            .iter()
            .all(|c| c.checks.iter().any(|k| k.passed.is_none())));
    }

    // -------------------------------------------------------------- paths

    fn hop(n: u8, ip: &str, asn: &str, rtt: f64) -> HopObs {
        HopObs {
            number: n,
            ip: Some(ip.into()),
            asn: Some(asn.into()),
            rtt_p50_ms: Some(rtt),
            rtt_p95_ms: Some(rtt * 1.5),
            loss_pct: 0.0,
            silent: false,
        }
    }

    #[test]
    fn a_changed_hop_is_detected_and_attributed_to_the_provider() {
        let previous = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
            hop(3, "203.0.113.9", "as7545", 12.0),
        ];
        let current = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
            hop(3, "203.0.113.44", "as7545", 52.0),
        ];
        assert_eq!(first_hop_change(&previous, &current), Some(3));

        let path = PathObs {
            target: "1.1.1.1".into(),
            hops: current,
            previous: Some(previous),
            traced_at: "2026-09-03 06:44:02".into(),
        };
        let d = detect_path_change(&path).unwrap();
        assert_eq!(
            d.severity,
            Severity::Medium,
            "40ms of added rtt is not just a note"
        );
        assert!(d.causes[0]
            .label
            .contains("rerouted inside its own network"));
    }

    #[test]
    fn a_silent_hop_is_not_a_route_change() {
        let previous = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
        ];
        let mut current = previous.clone();
        current[1].silent = true;
        current[1].ip = None;
        assert_eq!(
            first_hop_change(&previous, &current),
            None,
            "a router that stopped answering icmp has not moved"
        );
    }

    #[test]
    fn a_silent_hop_is_not_reported_as_loss() {
        let mut hops = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
            hop(3, "203.0.113.9", "as7545", 12.0),
        ];
        hops[1].silent = true;
        hops[1].loss_pct = 100.0;
        hops[1].ip = None;
        let path = PathObs {
            target: "1.1.1.1".into(),
            hops,
            previous: None,
            traced_at: "now".into(),
        };
        assert!(
            detect_path_loss(&path).is_none(),
            "a silent middle hop with clean hops after it is icmp rate-limiting"
        );
    }

    #[test]
    fn loss_that_propagates_is_reported() {
        let mut hops = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
            hop(3, "203.0.113.9", "as7545", 12.0),
        ];
        hops[1].loss_pct = 22.0;
        hops[2].loss_pct = 24.0;
        let path = PathObs {
            target: "1.1.1.1".into(),
            hops,
            previous: None,
            traced_at: "now".into(),
        };
        let d = detect_path_loss(&path).unwrap();
        assert_eq!(d.rule, "path.high_loss");
        assert!(d.causes[0].label.contains("hop 2"));
    }

    // --------------------------------------------------------------- link

    #[test]
    fn a_down_link_reports_nothing_else_about_that_interface() {
        let obs = Observations {
            iface: Some(IfaceObs {
                name: "eth0".into(),
                carrier: false,
                rx_errors: 0,
                tx_errors: 0,
                rx_dropped: 0,
                tx_dropped: 0,
                errors_per_min: 40,
                drops_per_min: 12,
                link_rate_bps: Some(1e9),
                rx_bps: 0.0,
                tx_bps: 0.0,
            }),
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, "link.down");
    }

    #[test]
    fn every_detection_carries_a_verify_condition() {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let obs = Observations {
            dns: Some(slow_dns()),
            sockets: vec![bloated_socket()],
            idle_rtt_ms: Some(12.0),
            loaded_rtt_ms: Some(320.0),
            ..Default::default()
        };
        let found = detect(&obs, &base, &Thresholds::default());
        assert!(!found.is_empty());
        for d in &found {
            assert!(
                !d.verify.metric.is_empty(),
                "{} has no verify metric",
                d.rule
            );
            assert!(d.verify.hold_secs > 0, "{} closes instantly", d.rule);
        }
    }

    #[test]
    fn every_apply_step_is_reversible_and_declares_its_privilege() {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let found = detect(&obs_with_dns(slow_dns()), &base, &Thresholds::default());
        let mut applies = 0;
        for d in &found {
            for s in &d.remediation {
                if s.kind == super::super::issue::StepKind::Apply {
                    applies += 1;
                    assert!(s.reversible, "{}: apply step must be reversible", d.rule);
                    assert!(s.key.is_some(), "{}: apply step needs a hotkey", d.rule);
                    assert_ne!(
                        s.requires,
                        Capability::None,
                        "{}: writing resolv.conf needs a declared privilege",
                        d.rule
                    );
                }
            }
        }
        assert!(applies > 0, "the dns rule should offer something to apply");
    }
}
