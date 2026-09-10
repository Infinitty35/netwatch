//! Runtime input coverage for the diagnostic catalogue. Counts describe
//! available rule inputs, not proof that all traffic or subjects were observed.
use super::{
    baseline::BaselineStore,
    detectors::Observations,
    rules::{self, RuleStatus},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Learning,
    NotMeasured,
    Unsupported,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCoverage {
    pub rule: String,
    pub status: Availability,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub rules: Vec<RuleCoverage>,
}

impl Coverage {
    pub fn label(&self) -> String {
        if self.rules.is_empty() {
            return "coverage not recorded".into();
        }
        let available = self
            .rules
            .iter()
            .filter(|r| r.status == Availability::Available)
            .count();
        let learning = self
            .rules
            .iter()
            .filter(|r| r.status == Availability::Learning)
            .count();
        format!(
            "{available}/{} rule inputs available · {learning} learning · {} unavailable",
            self.rules.len(),
            self.rules.len() - available - learning
        )
    }

    pub fn mark_stale_probes(&mut self, times: &crate::collectors::health::ProbeTimes) {
        use crate::collectors::health::ProbeTimes;
        for row in &mut self.rules {
            let sample = if row.rule.starts_with("dns.") {
                Some((times.dns, 30))
            } else if row.rule.starts_with("gateway.") {
                Some((times.gateway, 30))
            } else if row.rule == "nat.symmetric" {
                Some((times.nat, 300))
            } else {
                None
            };
            if let Some((Some(at), limit)) = sample {
                if !ProbeTimes::fresh(Some(at), limit) {
                    row.status = Availability::Stale;
                    row.reason =
                        format!("probe result is older than {limit}s; excluded from evaluation");
                }
            }
        }
    }

    pub fn from_observations(obs: &Observations, base: &BaselineStore) -> Self {
        use Availability::*;
        let present = |yes, reason| {
            if yes {
                (Available, "inputs present for observed subjects")
            } else {
                (NotMeasured, reason)
            }
        };
        let baseline = |value: Option<f64>, subject: Option<&str>, metric| {
            if value.is_none() {
                return (NotMeasured, "RTT not measured");
            }
            match subject.and_then(|s| base.get(s, metric)) {
                Some(b) if b.sigma() > f64::EPSILON => {
                    (Available, "RTT and usable baseline present")
                }
                _ => (
                    Learning,
                    "baseline absent, learning, or has no measurable variation",
                ),
            }
        };
        Self { rules: rules::CATALOGUE.iter().map(|rule| {
            let (status, reason) = if let RuleStatus::Planned(reason) = rule.status {
                (Unsupported, reason)
            } else { match rule.id {
                "link.down" | "iface.errors" => present(obs.iface.is_some(), "interface counters not measured"),
                "iface.saturated" => present(obs.iface.as_ref().and_then(|i| i.utilisation_pct()).is_some(), "link rate or interface counters missing"),
                "wifi.weak_signal" => present(obs.iface.as_ref().is_some_and(|i| i.wireless && (i.signal_dbm.is_some() || i.tx_retry_pct.is_some())), "wireless signal/retries not measured"),
                "gateway.unreachable" => present(obs.gateway.as_ref().is_some_and(|g| g.addr.is_some() && g.internet_reachable.is_some()), "gateway and corroborating internet probe required"),
                "gateway.rtt_spike" => baseline(obs.gateway.as_ref().and_then(|g| g.rtt_ms), obs.gateway.as_ref().and_then(|g| g.addr.as_deref()), "gateway.rtt"),
                "dns.slow_resolver" => present(obs.dns.as_ref().and_then(|d| d.rtt_p50_ms).is_some(), "resolver RTT not measured; absolute threshold remains usable without a baseline"),
                "dns.failing" | "dns.truncation_retry" => present(obs.dns.as_ref().is_some_and(|d| d.queries > 0), "no DNS query outcomes measured"),
                "dns.hijack_suspect" => present(obs.dns.as_ref().and_then(|d| d.cross.as_ref()).is_some(), "resolver cross-check not measured"),
                "path.changed" => present(obs.paths.iter().any(|p| p.previous.is_some() && !p.hops.is_empty()), "current and previous traces required"),
                "path.high_loss" => present(obs.paths.iter().any(|p| p.hops.iter().any(|h| !h.silent)), "no responding path hops measured"),
                "path.rtt_spike" => {
                    let states: Vec<_> = obs.paths.iter().map(|p| {
                        let subject = if base.get(&p.target, "path.rtt").is_some() { p.target.as_str() } else { "internet" };
                        baseline(p.hops.iter().rev().find(|h| !h.silent).and_then(|h| h.rtt_p50_ms), Some(subject), "path.rtt")
                    }).collect();
                    if states.iter().any(|(s, _)| *s == Available) { (Available, "path RTT and usable baseline present") }
                    else if states.iter().any(|(s, _)| *s == Learning) { (Learning, "path baseline unavailable") }
                    else { (NotMeasured, "path RTT not measured") }
                },
                "tcp.bufferbloat_local" => present(obs.idle_rtt_ms.is_some() && obs.loaded_rtt_ms.is_some(), "loaded/idle RTT test has not run"),
                "tcp.bufferbloat_remote" | "tcp.retrans_burst" => present(obs.sockets.iter().any(|s| s.rtt_ms.is_some()), "socket RTT not measured"),
                "tcp.zero_window" => present(obs.sockets.iter().any(|s| s.rwnd.is_some()), "socket receive window not measured"),
                "nat.symmetric" => present(obs.nat.is_some(), "STUN mappings not measured"),
                _ => (Unsupported, "no diagnostic observation adapter"),
            }};
            RuleCoverage { rule: rule.id.into(), status, reason: reason.into() }
        }).collect() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::{baseline::NetworkFingerprint, fixture};

    #[test]
    fn every_catalogued_rule_has_explicit_runtime_coverage() {
        let c = Coverage::from_observations(&Observations::default(), &fixture::baselines());
        assert_eq!(c.rules.len(), rules::CATALOGUE.len());
        assert!(c.rules.iter().all(|r| r.status != Availability::Available));
        assert_eq!(
            c.rules
                .iter()
                .filter(|r| r.status == Availability::Unsupported)
                .count(),
            7
        );
        assert!(c
            .rules
            .iter()
            .all(|r| r.reason != "no diagnostic observation adapter"));
        assert!(c.label().starts_with("0/25"));
    }

    #[test]
    fn dns_absolute_threshold_remains_available_while_gateway_baseline_learns() {
        let base = BaselineStore::new(NetworkFingerprint::new("test", None, vec![], None));
        let obs = fixture::observations_at(300);
        let c = Coverage::from_observations(&obs, &base);
        assert_eq!(
            c.rules
                .iter()
                .find(|r| r.rule == "dns.slow_resolver")
                .unwrap()
                .status,
            Availability::Available
        );
        assert_eq!(
            c.rules
                .iter()
                .find(|r| r.rule == "gateway.rtt_spike")
                .unwrap()
                .status,
            Availability::Learning
        );
    }

    #[test]
    fn missing_loaded_test_and_receive_window_are_not_available() {
        let mut obs = fixture::observations_at(300);
        obs.loaded_rtt_ms = None;
        for s in &mut obs.sockets {
            s.rwnd = None;
        }
        let c = Coverage::from_observations(&obs, &fixture::baselines());
        for rule in ["tcp.bufferbloat_local", "tcp.zero_window"] {
            assert_eq!(
                c.rules.iter().find(|r| r.rule == rule).unwrap().status,
                Availability::NotMeasured
            );
        }
    }
}
