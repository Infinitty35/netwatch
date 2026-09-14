//! Every cause each rule can rank and the checks behind it, by stable id.
//!
//! The detectors build causes in code, often from runtime values; this table is
//! the fixed list a feature schema or a label vocabulary can be built from.
//! `every_emitted_id_is_catalogued` and the source scan in the tests keep it in
//! step with `detectors.rs`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CauseSpec {
    pub rule: &'static str,
    pub cause: &'static str,
    pub checks: &'static [&'static str],
}

pub const CAUSES: &[CauseSpec] = &[
    CauseSpec {
        rule: "link.down",
        cause: "unplugged_or_port_down",
        checks: &["carrier"],
    },
    CauseSpec {
        rule: "link.down",
        cause: "wifi_disassociated",
        checks: &["wireless"],
    },
    CauseSpec {
        rule: "iface.errors",
        cause: "ring_buffer_small",
        checks: &["drops_dominate"],
    },
    CauseSpec {
        rule: "iface.errors",
        cause: "bad_cable_or_duplex",
        checks: &["errors_dominate"],
    },
    CauseSpec {
        rule: "wifi.weak_signal",
        cause: "weak_signal",
        checks: &["signal_weak"],
    },
    CauseSpec {
        rule: "wifi.weak_signal",
        cause: "congested_channel",
        checks: &["retries_high", "signal_fine"],
    },
    CauseSpec {
        rule: "iface.saturated",
        cause: "link_at_capacity",
        checks: &["utilisation"],
    },
    CauseSpec {
        rule: "gateway.unreachable",
        cause: "icmp_filtered",
        checks: &[
            "arp_resolves",
            "icmp_reaches_the_gateway",
            "nothing_beyond_the_gateway_answers_either",
        ],
    },
    CauseSpec {
        rule: "gateway.unreachable",
        cause: "wrong_vlan_or_address_conflict",
        checks: &["arp_fails", "nothing_beyond_the_gateway_answers_either"],
    },
    CauseSpec {
        rule: "gateway.rtt_spike",
        cause: "local_network_congested",
        checks: &["gateway_rtt_above_baseline"],
    },
    CauseSpec {
        rule: "gateway.rtt_spike",
        cause: "gateway_loaded",
        checks: &["gateway_cpu"],
    },
    CauseSpec {
        rule: "dns.failing",
        cause: "resolver_down",
        checks: &["resolver_unreachable"],
    },
    CauseSpec {
        rule: "dns.failing",
        cause: "udp53_filtered",
        checks: &["resolver_reachable"],
    },
    CauseSpec {
        rule: "dns.truncation_retry",
        cause: "no_edns",
        checks: &["truncated_replies"],
    },
    CauseSpec {
        rule: "dns.truncation_retry",
        cause: "middlebox_clamps_udp",
        checks: &["edns_through_the_path"],
    },
    CauseSpec {
        rule: "dns.hijack_suspect",
        cause: "interceptor",
        checks: &["private_answer_for_a_public_name"],
    },
    CauseSpec {
        rule: "dns.hijack_suspect",
        cause: "forged_records",
        checks: &["disagrees_with_reference", "reference_validated"],
    },
    CauseSpec {
        rule: "dns.hijack_suspect",
        cause: "split_horizon",
        checks: &["public_name_public_answer"],
    },
    CauseSpec {
        rule: "dns.slow_resolver",
        cause: "upstream_slow",
        checks: &[
            "alt_resolver_is_fast",
            "resolver_itself_is_reachable",
            "cached_names_still_fast",
        ],
    },
    CauseSpec {
        rule: "dns.slow_resolver",
        cause: "resolver_overloaded",
        checks: &["icmp_rtt_raised", "timeouts_or_servfail_present"],
    },
    CauseSpec {
        rule: "dns.slow_resolver",
        cause: "local_udp_path",
        checks: &[
            "alt_resolver_over_the_same_path_is_also_slow",
            "interface_drops",
        ],
    },
    CauseSpec {
        rule: "path.rtt_spike",
        cause: "hop_adds_latency",
        checks: &["one_hop_dominates"],
    },
    CauseSpec {
        rule: "path.rtt_spike",
        cause: "route_change",
        checks: &["the_path_changed"],
    },
    CauseSpec {
        rule: "path.changed",
        cause: "provider_reroute",
        checks: &["asn_changed", "asn_unchanged", "hop_address_changed"],
    },
    CauseSpec {
        rule: "path.changed",
        cause: "local_route_change",
        checks: &["change_is_at_hop_1_or_2"],
    },
    CauseSpec {
        rule: "path.high_loss",
        cause: "hop_dropping",
        checks: &["loss_propagates_to_later_hops"],
    },
    CauseSpec {
        rule: "path.high_loss",
        cause: "icmp_rate_limit",
        checks: &["later_hops_are_clean"],
    },
    CauseSpec {
        rule: "tcp.bufferbloat_remote",
        cause: "receiver_queueing",
        checks: &[
            "link_level_bufferbloat_test_passed",
            "rtt_tracks_this_socket_s_own_tx",
        ],
    },
    CauseSpec {
        rule: "tcp.bufferbloat_remote",
        cause: "path_loss",
        checks: &["the_path_to_this_peer_is_losing_packets"],
    },
    CauseSpec {
        rule: "tcp.retrans_burst",
        cause: "packet_loss",
        checks: &["retransmits_observed"],
    },
    CauseSpec {
        rule: "tcp.zero_window",
        cause: "peer_not_reading",
        checks: &["rwnd_is_zero"],
    },
    CauseSpec {
        rule: "tcp.zero_window",
        cause: "peer_reading_slowly",
        checks: &["cwnd_exceeds_rwnd"],
    },
    CauseSpec {
        rule: "nat.symmetric",
        cause: "address_dependent_nat",
        checks: &["mapping_depends_on_destination"],
    },
    CauseSpec {
        rule: "nat.symmetric",
        cause: "router_symmetric_nat",
        checks: &["single_nat_layer"],
    },
    CauseSpec {
        rule: "tcp.bufferbloat_local",
        cause: "no_aqm_upstream",
        checks: &["rtt_rises_under_our_own_load"],
    },
];

pub fn lookup(rule: &str, cause: &str) -> Option<&'static CauseSpec> {
    CAUSES.iter().find(|c| c.rule == rule && c.cause == cause)
}

/// Whether a detector's output is in the catalogue: the cause under its rule,
/// and every check under that cause.
pub fn is_catalogued(rule: &str, cause: &super::issue::Cause) -> bool {
    lookup(rule, &cause.id).is_some_and(|spec| {
        cause
            .checks
            .iter()
            .all(|k| spec.checks.contains(&k.id.as_str()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn cause_keys_are_unique_and_rules_exist() {
        let mut seen = HashSet::new();
        for c in CAUSES {
            assert!(
                seen.insert((c.rule, c.cause)),
                "{}/{} listed twice",
                c.rule,
                c.cause
            );
            assert!(
                super::super::rules::lookup(c.rule).is_some(),
                "{} is not a rule",
                c.rule
            );
            let checks: HashSet<_> = c.checks.iter().collect();
            assert_eq!(
                checks.len(),
                c.checks.len(),
                "{}/{} repeats a check",
                c.rule,
                c.cause
            );
        }
    }

    /// Every literal id in the detector source is catalogued, and nothing in
    /// the catalogue is missing from the source.
    #[test]
    fn the_catalogue_matches_the_detector_source() {
        let src = include_str!("detectors.rs");
        let body = &src[..src.find("#[cfg(test)]").unwrap()];
        let literal_ids = |needle: &str| -> HashSet<String> {
            body.match_indices(needle)
                .filter_map(|(at, _)| {
                    let rest = body[at + needle.len()..].trim_start().strip_prefix('"')?;
                    Some(rest.split_once('"')?.0.to_string())
                })
                .collect()
        };
        let source_causes = literal_ids("Cause::new(");
        let mut source_checks = HashSet::new();
        for n in [
            "CheckResult::pass(",
            "CheckResult::fail(",
            "CheckResult::skipped(",
        ] {
            source_checks.extend(literal_ids(n));
        }
        let causes: HashSet<String> = CAUSES.iter().map(|c| c.cause.to_string()).collect();
        let checks: HashSet<String> = CAUSES
            .iter()
            .flat_map(|c| c.checks.iter().map(|k| k.to_string()))
            .collect();
        assert_eq!(causes, source_causes);
        assert_eq!(checks, source_checks);
    }
}
