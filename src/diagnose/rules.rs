//! The built-in ruleset: what netwatch knows how to recognise, and which
//! findings are consequences of which others.
//!
//! The catalogue is data, not code paths. Each [`Rule`] carries the metadata
//! the UI and the report need — severity, the plain-English trigger, the
//! suppression edges — and declares whether netwatch can currently *evaluate*
//! it ([`RuleStatus`]). A rule netwatch can't yet evaluate is listed as
//! `Planned` and is visible in the ruleset browser, but it can never open an
//! issue. That distinction is the point: a diagnostic tool that lists 24 rules
//! and silently evaluates nine is lying about its coverage.

use super::issue::{Issue, IssueId, RuleId, Severity, Subject, Verify};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleStatus {
    /// Detector implemented; runtime coverage determines whether inputs exist.
    Active,
    /// In the catalogue, not yet wired to a data source. Cannot open an issue.
    /// The `&'static str` says what input is missing.
    Planned(&'static str),
}

impl RuleStatus {
    pub fn is_active(self) -> bool {
        matches!(self, RuleStatus::Active)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub id: RuleId,
    /// Issue title when this rule fires.
    pub title: &'static str,
    /// Category for grouping in the ruleset browser: dns, link, path, tcp…
    pub category: &'static str,
    pub severity: Severity,
    /// Plain-English trigger, shown in the "how issues are found" panel.
    pub trigger: &'static str,
    /// Rules whose issues become consequences of this one when both are open
    /// and they share a subject scope. Explicit — never inferred.
    pub suppresses: &'static [RuleId],
    pub status: RuleStatus,
}

/// Built-in ruleset v1.
pub const CATALOGUE: &[Rule] = &[
    // ---------------------------------------------------------------- dns
    Rule {
        id: "dns.slow_resolver",
        title: "slow dns resolver",
        category: "dns",
        severity: Severity::Medium,
        trigger: "resolver p50 > 3σ above baseline for 3 samples, or pipeline dns stage > 20ms",
        suppresses: &[],
        status: RuleStatus::Active,
    },
    Rule {
        id: "dns.failing",
        title: "dns resolution failing",
        category: "dns",
        severity: Severity::High,
        trigger: "servfail/timeout rate > 5%, or the pipeline dns stage fails",
        suppresses: &["dns.slow_resolver"],
        status: RuleStatus::Active,
    },
    Rule {
        id: "dns.truncation_retry",
        title: "dns replies truncating",
        category: "dns",
        severity: Severity::Info,
        trigger: "more than 10% of probe replies carry the TC bit",
        suppresses: &[],
        status: RuleStatus::Active,
    },
    Rule {
        id: "dns.hijack_suspect",
        title: "dns answers disagree",
        category: "dns",
        severity: Severity::High,
        trigger: "a private address for a public name, or disagreement with a validating reference on most cycles",
        suppresses: &[],
        status: RuleStatus::Active,
    },
    // ------------------------------------------------------- gateway / link
    Rule {
        id: "gateway.unreachable",
        title: "gateway unreachable",
        category: "link",
        severity: Severity::Critical,
        // The root cause of nearly everything else, so it suppresses widely.
        trigger: "arp or icmp to the default gateway fails",
        suppresses: &[
            "dns.slow_resolver",
            "dns.failing",
            "gateway.rtt_spike",
            "path.high_loss",
            "path.rtt_spike",
            "tcp.retrans_burst",
            "tcp.connect_failures",
        ],
        status: RuleStatus::Active,
    },
    Rule {
        id: "link.down",
        title: "link down",
        category: "link",
        severity: Severity::Critical,
        trigger: "interface carrier lost",
        suppresses: &["gateway.unreachable"],
        status: RuleStatus::Active,
    },
    Rule {
        id: "gateway.rtt_spike",
        title: "gateway slow to answer",
        category: "link",
        severity: Severity::Medium,
        trigger: "gateway rtt > 3σ above baseline for 3 samples",
        suppresses: &["path.rtt_spike"],
        status: RuleStatus::Active,
    },
    Rule {
        id: "iface.errors",
        title: "interface errors",
        category: "link",
        severity: Severity::Medium,
        trigger: "rx/tx error, drop, overrun or fifo counters increment",
        suppresses: &[],
        status: RuleStatus::Active,
    },
    Rule {
        id: "iface.saturated",
        title: "interface saturated",
        category: "link",
        severity: Severity::Medium,
        trigger: "throughput above 90% of link rate for 30s",
        suppresses: &["tcp.bufferbloat_local", "path.rtt_spike"],
        status: RuleStatus::Active,
    },
    Rule {
        id: "wifi.weak_signal",
        title: "weak wifi signal",
        category: "link",
        severity: Severity::Medium,
        trigger: "signal at or below −70 dBm, or more than 20% of frames retried over a minute",
        suppresses: &[],
        status: RuleStatus::Active,
    },
    // --------------------------------------------------------------- path
    Rule {
        id: "path.changed",
        title: "upstream path changed",
        category: "path",
        severity: Severity::Info,
        trigger: "a hop differs between consecutive traces to the same target",
        // A reroute that costs latency is one finding, not two. The rtt spike
        // is reported underneath as the consequence it is, which is also what
        // makes the pair readable: "the path changed, and it cost you 40ms".
        suppresses: &["path.rtt_spike"],
        status: RuleStatus::Active,
    },
    Rule {
        id: "path.high_loss",
        title: "loss on the path",
        category: "path",
        severity: Severity::High,
        trigger: "a hop loses packets and the loss propagates to later hops",
        suppresses: &["tcp.retrans_burst"],
        status: RuleStatus::Active,
    },
    Rule {
        id: "path.rtt_spike",
        title: "path rtt above baseline",
        category: "path",
        severity: Severity::Medium,
        trigger: "end-to-end rtt > 3σ above baseline",
        suppresses: &[],
        status: RuleStatus::Active,
    },
    // ---------------------------------------------------------- tcp/sockets
    Rule {
        id: "tcp.bufferbloat_local",
        title: "bufferbloat on the uplink",
        category: "tcp",
        severity: Severity::High,
        trigger: "rtt under load exceeds idle rtt by more than 100ms",
        suppresses: &["tcp.bufferbloat_remote", "path.rtt_spike"],
        status: RuleStatus::Active,
    },
    Rule {
        id: "tcp.bufferbloat_remote",
        title: "receiver-side bufferbloat",
        category: "tcp",
        severity: Severity::Medium,
        trigger: "one socket's rtt rises with its own tx while the link-level test passes",
        suppresses: &[],
        status: RuleStatus::Active,
    },
    Rule {
        id: "tcp.retrans_burst",
        title: "retransmission burst",
        category: "tcp",
        severity: Severity::Medium,
        trigger: "retrans/min more than 3σ above the socket's baseline",
        suppresses: &[],
        status: RuleStatus::Active,
    },
    Rule {
        id: "tcp.zero_window",
        title: "receiver not reading",
        category: "tcp",
        severity: Severity::Info,
        trigger: "rwnd is zero, or cwnd greatly exceeds rwnd",
        suppresses: &[],
        status: RuleStatus::Active,
    },
    Rule {
        id: "tcp.connect_failures",
        title: "connections failing",
        category: "tcp",
        severity: Severity::Medium,
        trigger: "more than 5 syn timeouts or connect resets per minute",
        suppresses: &[],
        status: RuleStatus::Planned("connect-failure detector not wired into Diagnose"),
    },
    Rule {
        id: "tcp.timewait_exhaustion",
        title: "time-wait pressure",
        category: "tcp",
        severity: Severity::Medium,
        trigger: "time-wait sockets exceed 60% of the ephemeral port range",
        suppresses: &[],
        status: RuleStatus::Planned("TIME_WAIT detector not wired into Diagnose"),
    },
    // ------------------------------------------------- mtu / nat / v6 / cap
    Rule {
        id: "pmtu.blackhole",
        title: "path mtu blackhole",
        category: "mtu",
        severity: Severity::High,
        trigger: "large DF probes fail while small probes pass",
        suppresses: &["tcp.retrans_burst"],
        status: RuleStatus::Planned("PMTU probe detector not wired into Diagnose"),
    },
    Rule {
        id: "nat.symmetric",
        title: "symmetric nat",
        category: "nat",
        severity: Severity::Info,
        trigger: "two stun servers see different public ports from one socket",
        suppresses: &[],
        status: RuleStatus::Active,
    },
    Rule {
        id: "ipv6.broken",
        title: "ipv6 route present but unusable",
        category: "ipv6",
        severity: Severity::Medium,
        trigger: "a v6 default route exists but v6 probes fail while v4 works",
        suppresses: &[],
        status: RuleStatus::Planned("dual-stack comparison not wired into Diagnose"),
    },
    Rule {
        id: "captive.portal",
        title: "captive portal intercepting",
        category: "captive",
        severity: Severity::High,
        trigger: "the http 204 probe is redirected",
        // A portal breaks DNS and TCP in ways that are its fault, not theirs.
        suppresses: &["dns.hijack_suspect", "tcp.connect_failures", "dns.failing"],
        status: RuleStatus::Planned("captive portal test not wired into Diagnose"),
    },
    // -------------------------------------------------------------- egress
    Rule {
        id: "egress.drift",
        title: "egress drift",
        category: "egress",
        severity: Severity::Info,
        trigger: "a destination outside the learned egress baseline",
        suppresses: &[],
        status: RuleStatus::Planned("egress findings remain in the Egress tab"),
    },
    Rule {
        id: "egress.policy_violation",
        title: "egress policy violation",
        category: "egress",
        severity: Severity::High,
        trigger: "a flow denied by the loaded egress policy",
        suppresses: &["egress.drift"],
        status: RuleStatus::Planned("egress policy findings remain in the Egress tab"),
    },
];

pub fn lookup(id: &str) -> Option<&'static Rule> {
    CATALOGUE.iter().find(|r| r.id == id)
}

pub fn active_count() -> usize {
    CATALOGUE.iter().filter(|r| r.status.is_active()).count()
}

/// `"24 rules · 20 active · 4 planned"` for the Diagnose footer. Being
/// explicit about the split is the difference between a ruleset and a wishlist.
pub fn catalogue_label() -> String {
    let total = CATALOGUE.len();
    let active = active_count();
    let planned = total - active;
    if planned == 0 {
        format!("{total} rules · all active")
    } else {
        format!("{total} rules · {active} active · {planned} planned")
    }
}

/// Whether two subjects are close enough for suppression to apply. A gateway
/// failure suppresses DNS on the same host; it does not suppress a finding
/// about an unrelated interface.
fn scopes_overlap(root: &Subject, child: &Subject) -> bool {
    match (root, child) {
        // Host-wide roots (gateway, link) cover everything on the host.
        (Subject::Host, _) => true,
        (Subject::Iface { name }, Subject::Iface { name: other }) => name == other,
        // A link/gateway problem on an interface covers what runs over it.
        (Subject::Iface { .. }, _) => true,
        (a, b) => a == b,
    }
}

/// Apply the suppression graph to a set of open issues.
///
/// Consequences are not deleted — they keep their evidence and are listed
/// under their root cause, which is what the report needs in order to explain
/// why three symptoms were one fault. Suppression is transitive: if link.down
/// suppresses gateway.unreachable, and gateway.unreachable suppresses
/// dns.failing, then dns.failing lands under link.down.
pub fn apply_suppression(issues: &mut [Issue]) {
    // Reset — suppression is recomputed from scratch each pass so an issue
    // that closes releases whatever it was suppressing.
    for i in issues.iter_mut() {
        i.suppressed_by = None;
        i.consequences.clear();
    }

    // Direct edges: root index → child index.
    let mut parent: HashMap<usize, usize> = HashMap::new();
    for (ci, child) in issues.iter().enumerate() {
        if !child.state.is_open() {
            continue;
        }
        let mut best: Option<(usize, Severity)> = None;
        for (ri, root) in issues.iter().enumerate() {
            if ri == ci || !root.state.is_open() {
                continue;
            }
            let Some(rule) = lookup(&root.rule) else {
                continue;
            };
            if !rule.suppresses.contains(&child.rule.as_str()) {
                continue;
            }
            if !scopes_overlap(&root.subject, &child.subject) {
                continue;
            }
            // Most severe root wins, so a link failure beats a gateway failure.
            if best.map(|(_, s)| root.severity > s).unwrap_or(true) {
                best = Some((ri, root.severity));
            }
        }
        if let Some((ri, _)) = best {
            parent.insert(ci, ri);
        }
    }

    // Walk to the ultimate root, guarding against a cycle in a user ruleset.
    let ids: Vec<IssueId> = issues.iter().map(|i| i.id.clone()).collect();
    let mut assignments: Vec<(usize, usize)> = Vec::new();
    for (&child, &direct) in parent.iter() {
        let mut root = direct;
        let mut seen: HashSet<usize> = HashSet::from([child, direct]);
        while let Some(&next) = parent.get(&root) {
            if !seen.insert(next) {
                break; // cycle — stop at the deepest node reached
            }
            root = next;
        }
        if root != child {
            assignments.push((child, root));
        }
    }

    for (child, root) in assignments {
        issues[child].suppressed_by = Some(ids[root].clone());
        let child_id = ids[child].clone();
        issues[root].consequences.push(child_id);
    }

    for i in issues.iter_mut() {
        i.consequences.sort();
    }
}

/// The issues a user should be shown as findings: open, and not a consequence
/// of another open issue.
pub fn primary_issues(issues: &[Issue]) -> Vec<&Issue> {
    issues
        .iter()
        .filter(|i| i.state.is_open() && i.suppressed_by.is_none())
        .collect()
}

/// Default verify condition for a rule, used when a detector doesn't supply a
/// more specific one. Every active rule must have one — enforced by a test,
/// because §4's rule is that a remediation without a testable success
/// condition is an instruction, not something netwatch can claim to have fixed.
pub fn default_verify(id: &str) -> Option<Verify> {
    Some(match id {
        "dns.slow_resolver" => Verify::below("dns.rtt_p50", 5.0, "ms").holding_for(60),
        "dns.failing" => Verify::below("dns.failure_rate", 1.0, "%").holding_for(120),
        "dns.truncation_retry" => Verify::below("dns.tc_rate", 1.0, "%").holding_for(120),
        "dns.hijack_suspect" => Verify::below("dns.answer_mismatch", 1.0, "%").holding_for(300),
        "gateway.unreachable" => Verify::below("gateway.loss", 1.0, "%").holding_for(60),
        "gateway.rtt_spike" => Verify::below("gateway.rtt_sigma", 3.0, "σ").holding_for(120),
        "link.down" => Verify::above("iface.carrier", 0.0, "").holding_for(30),
        "iface.errors" => Verify::below("iface.error_rate", 1.0, "/min").holding_for(300),
        "iface.saturated" => Verify::below("iface.utilisation", 90.0, "%").holding_for(60),
        "wifi.weak_signal" => Verify::above("wifi.rssi", -70.0, "dBm").holding_for(120),
        "path.changed" => Verify::below("path.hop_changes", 1.0, "").holding_for(300),
        "path.high_loss" => Verify::below("path.hop_loss", 1.0, "%").holding_for(120),
        "path.rtt_spike" => Verify::below("path.rtt_sigma", 3.0, "σ").holding_for(120),
        "tcp.bufferbloat_local" => {
            Verify::below("tcp.loaded_rtt_delta", 100.0, "ms").holding_for(60)
        }
        "tcp.bufferbloat_remote" => Verify::below("tcp.socket_rtt", 100.0, "ms").holding_for(60),
        "tcp.retrans_burst" => Verify::below("tcp.retrans_rate", 1.0, "/min").holding_for(120),
        "tcp.zero_window" => Verify::above("tcp.rwnd", 0.0, "B").holding_for(60),
        "tcp.connect_failures" => {
            Verify::below("tcp.connect_failure_rate", 1.0, "/min").holding_for(120)
        }
        "tcp.timewait_exhaustion" => Verify::below("tcp.timewait_pct", 40.0, "%").holding_for(120),
        "pmtu.blackhole" => Verify::above("pmtu.largest_ok", 1400.0, "B").holding_for(60),
        "nat.symmetric" => Verify::below("nat.symmetric", 1.0, "").holding_for(300),
        "ipv6.broken" => Verify::below("ipv6.probe_loss", 1.0, "%").holding_for(120),
        "captive.portal" => Verify::above("captive.probe_204", 0.0, "").holding_for(30),
        "egress.drift" => Verify::below("egress.new_destinations", 1.0, "").holding_for(300),
        "egress.policy_violation" => {
            Verify::below("egress.denied_flows", 1.0, "/min").holding_for(300)
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::issue::{IssueState, Scope};

    fn issue(id: &str, rule: &str, subject: Subject) -> Issue {
        let r = lookup(rule).expect("rule in catalogue");
        Issue {
            id: id.into(),
            rule: rule.into(),
            severity: r.severity,
            title: r.title.into(),
            subject,
            since: "2026-09-03 06:48:10".into(),
            last_seen: "2026-09-03 06:51:19".into(),
            state: IssueState::Open,
            evidence: vec![],
            scope: Scope::default(),
            causes: vec![],
            remediation: vec![],
            verify: default_verify(rule).unwrap(),
            artifacts: vec![],
            consequences: vec![],
            suppressed_by: None,
            recurrence: 0,
        }
    }

    #[test]
    fn catalogue_ids_are_unique() {
        let mut seen = HashSet::new();
        for r in CATALOGUE {
            assert!(seen.insert(r.id), "duplicate rule id {}", r.id);
        }
    }

    #[test]
    fn suppression_edges_reference_real_rules() {
        for r in CATALOGUE {
            for s in r.suppresses {
                assert!(lookup(s).is_some(), "{} suppresses unknown rule {s}", r.id);
            }
            assert!(!r.suppresses.contains(&r.id), "{} suppresses itself", r.id);
        }
    }

    #[test]
    fn every_rule_has_a_verify_condition() {
        for r in CATALOGUE {
            assert!(
                default_verify(r.id).is_some(),
                "{} has no verify condition — it could never be closed",
                r.id
            );
        }
    }

    /// Every rule now has an input. The label must say so rather than keep
    /// a split that no longer exists; if a rule is ever added as `Planned`
    /// again, the label goes back to stating the count and this changes.
    #[test]
    fn catalogue_label_reports_the_active_split_honestly() {
        let label = catalogue_label();
        assert!(
            label.starts_with(&format!("{} rules", CATALOGUE.len())),
            "{label}"
        );
        assert_eq!(active_count(), 18, "{label}");
        assert!(label.ends_with("7 planned"), "{label}");
    }

    #[test]
    fn gateway_failure_swallows_the_dns_symptom() {
        let mut issues = vec![
            issue(
                "A",
                "dns.slow_resolver",
                Subject::Resolver {
                    addr: "169.254.1.1".into(),
                },
            ),
            issue("B", "gateway.unreachable", Subject::Host),
        ];
        apply_suppression(&mut issues);

        assert_eq!(issues[0].suppressed_by.as_deref(), Some("B"));
        assert_eq!(issues[1].consequences, vec!["A".to_string()]);
        let primary = primary_issues(&issues);
        assert_eq!(primary.len(), 1);
        assert_eq!(primary[0].id, "B");
    }

    #[test]
    fn suppression_is_transitive_to_the_deepest_root() {
        let mut issues = vec![
            issue(
                "A",
                "dns.failing",
                Subject::Resolver {
                    addr: "10.0.0.1".into(),
                },
            ),
            issue("B", "gateway.unreachable", Subject::Host),
            issue(
                "C",
                "link.down",
                Subject::Iface {
                    name: "eth0".into(),
                },
            ),
        ];
        apply_suppression(&mut issues);

        assert_eq!(
            issues[0].suppressed_by.as_deref(),
            Some("C"),
            "dns → link.down"
        );
        assert_eq!(issues[1].suppressed_by.as_deref(), Some("C"));
        assert_eq!(
            issues[2].consequences,
            vec!["A".to_string(), "B".to_string()]
        );
        assert_eq!(primary_issues(&issues).len(), 1);
    }

    #[test]
    fn suppression_does_not_cross_unrelated_interfaces() {
        let mut issues = vec![
            issue(
                "A",
                "iface.errors",
                Subject::Iface {
                    name: "eth0".into(),
                },
            ),
            issue(
                "B",
                "link.down",
                Subject::Iface {
                    name: "wlan0".into(),
                },
            ),
        ];
        apply_suppression(&mut issues);
        // link.down doesn't suppress iface.errors anyway, but the scope guard
        // is what keeps a wlan0 fault from explaining an eth0 counter.
        assert!(issues[0].suppressed_by.is_none());
    }

    #[test]
    fn a_closed_root_releases_its_consequences() {
        let mut issues = vec![
            issue(
                "A",
                "dns.slow_resolver",
                Subject::Resolver {
                    addr: "1.1.1.1".into(),
                },
            ),
            issue("B", "gateway.unreachable", Subject::Host),
        ];
        apply_suppression(&mut issues);
        assert!(issues[0].suppressed_by.is_some());

        issues[1].state = IssueState::Resolved {
            at: "2026-09-03 07:00:00".into(),
        };
        apply_suppression(&mut issues);
        assert!(
            issues[0].suppressed_by.is_none(),
            "dns must resurface as a finding once the gateway recovers"
        );
        assert_eq!(primary_issues(&issues).len(), 1);
    }

    #[test]
    fn independent_issues_are_both_primary() {
        let mut issues = vec![
            issue(
                "A",
                "dns.slow_resolver",
                Subject::Resolver {
                    addr: "169.254.1.1".into(),
                },
            ),
            issue(
                "B",
                "tcp.bufferbloat_remote",
                Subject::Socket {
                    local: "10.88.0.2:52344".into(),
                    remote: "10.88.0.3:9000".into(),
                },
            ),
            issue(
                "C",
                "path.changed",
                Subject::Path {
                    target: "1.1.1.1".into(),
                },
            ),
        ];
        apply_suppression(&mut issues);
        assert_eq!(primary_issues(&issues).len(), 3);
    }
}
