//! Bridging live collectors to [`Observations`].
//!
//! The detectors take a plain data struct, not the `App`, so they can be
//! tested against any scenario without a running capture. This module is the
//! one place that knows how to fill that struct from what netwatch actually
//! measures — and the one place that has to be honest about what it *can't*
//! measure yet. Where an input is missing, the field stays `None` and the
//! corresponding check reports as "not run" rather than silently counting as
//! evidence.
//!
//! It also holds the small amount of cross-tick state the detectors are
//! deliberately without: how long a socket has held its verdict, what the
//! interface counters were last tick, and the previous trace to each target.

use std::collections::HashMap;
use std::time::Instant;

use super::baseline::{BaselineStore, NetworkFingerprint};
use super::detectors::{
    classify_socket, DnsCross, DnsObs, GatewayObs, HopObs, IfaceObs, NatObs, Observations, PathObs,
    SocketObs, SocketVerdict, Thresholds,
};
use crate::app::App;

/// Metrics fed to the baseline store every tick, each paired with the rule
/// that consumes it.
///
/// The pairing is asserted in a test. Learning a baseline nobody reads is
/// invisible dead weight — it costs a write to `baselines.json` every tick and
/// buys nothing — and a metric baselined under one name but verified under
/// another is worse, because the rule silently never fires.
pub const BASELINED_METRICS: &[(&str, &str)] = &[
    ("dns.rtt_p50", "dns.slow_resolver"),
    ("gateway.rtt", "gateway.rtt_spike"),
    ("path.rtt", "path.rtt_spike"),
];

#[derive(Default)]
pub struct LiveSampler {
    interface_sample: Option<(Instant, IfaceObs)>,
    pub completed: super::engine::ObservationTimes,
    path_samples: HashMap<String, (Instant, PathObs)>,
    /// Socket key → (verdict, when it started). A verdict has to persist
    /// before it becomes an issue, and only this map knows for how long.
    learned_samples: HashMap<String, Instant>,
    verdict_since: HashMap<String, (SocketVerdict, Instant)>,
    /// Interface name → the last 60 seconds of (errors, drops) deltas. Rules
    /// fire on the rate over that window, not on a lifetime counter (a NIC
    /// that logged 40 errors during boot last month is not a live fault) and
    /// not on a single tick's delta, which reported as "/min" is off by 60.
    iface_history: HashMap<String, IfaceCounters>,
    /// Target → the last trace we saw, for the path diff.
    prev_path: HashMap<String, Vec<HopObs>>,
    /// Interface name → the last minute of (tx retries, tx packets) deltas,
    /// for the wifi retry rate. Same shape as `iface_history`.
    wifi_history: HashMap<String, IfaceCounters>,
}

/// A rolling one-minute window of interface counter deltas.
///
/// Sized in samples rather than seconds because the caller sets the tick rate;
/// at netwatch's 1s tick this is exactly a minute.
#[derive(Debug)]
struct IfaceCounters {
    last: (u64, u64),
    window: std::collections::VecDeque<(u64, u64)>,
}

impl IfaceCounters {
    const WINDOW: usize = 60;

    fn new(errors: u64, drops: u64) -> Self {
        Self {
            last: (errors, drops),
            window: std::collections::VecDeque::with_capacity(Self::WINDOW),
        }
    }

    /// Record a counter reading, returning `(errors, drops)` over the window.
    ///
    /// `saturating_sub` on both: counters reset when an interface is bounced,
    /// and a wrapping subtraction there would report billions of errors.
    fn observe(&mut self, errors: u64, drops: u64) -> (u64, u64) {
        let delta = (
            errors.saturating_sub(self.last.0),
            drops.saturating_sub(self.last.1),
        );
        self.last = (errors, drops);
        if self.window.len() == Self::WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(delta);
        self.window
            .iter()
            .fold((0u64, 0u64), |(e, d), (de, dd)| (e + de, d + dd))
    }
}

impl LiveSampler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Identity of the network we are currently on. Baselines are scoped to
    /// this, so moving networks can't make every rule fire at once.
    pub fn fingerprint(app: &App) -> NetworkFingerprint {
        let cfg = &app.config_collector.config;
        let subnet = app
            .interface_info
            .iter()
            .find(|i| i.name == app.capture_interface)
            .and_then(|i| i.ipv4.clone())
            .map(|ip| subnet_of(&ip));
        NetworkFingerprint::new(
            app.capture_interface.clone(),
            cfg.gateway.clone(),
            cfg.dns_servers.clone(),
            subnet,
        )
    }

    /// This tick's raw readings as `(subject, metric, value)`, ready to feed
    /// the baseline store.
    ///
    /// Returned rather than written directly so the caller owns the borrow of
    /// the store, and so the set of baselined metrics is inspectable — a
    /// metric learned under one name and verified under another would be a
    /// silent dead end, and [`BASELINED_METRICS`] is asserted against the rules.
    pub fn readings(&mut self, app: &App) -> Vec<(String, &'static str, f64)> {
        let health = app.health_prober.status();
        let cfg = &app.config_collector.config;
        let mut out = Vec::new();

        if let (Some(resolver), Some(rtt)) = (cfg.primary_dns(), health.dns_rtt_ms) {
            if health.completed.dns_target.as_ref() == Some(&resolver)
                && self.fresh_reading("dns", health.completed.dns)
            {
                out.push((resolver, "dns.rtt_p50", rtt));
            }
        }
        if let (Some(gw), Some(rtt)) = (cfg.gateway.clone(), health.gateway_rtt_ms) {
            if health.completed.gateway_target.as_ref() == Some(&gw)
                && self.fresh_reading("gateway", health.completed.gateway)
            {
                out.push((gw, "gateway.rtt", rtt));
            }
        }
        if let Some(rtt) = health.internet_rtt_ms {
            if self.fresh_reading("internet", health.completed.internet) {
                out.push(("internet".to_string(), "path.rtt", rtt));
            }
        }
        out
    }

    fn fresh_reading(&mut self, source: &str, completed: Option<Instant>) -> bool {
        if !crate::collectors::health::ProbeTimes::fresh(completed, 30) {
            return false;
        }
        let completed = completed.unwrap();
        self.learned_samples.insert(source.into(), completed) != Some(completed)
    }

    /// The verdict this socket is currently carrying, if it has one.
    ///
    /// Read by the surfaces that show a verdict column. They must not
    /// re-classify: `classify_socket` is cheap but the *age* of a verdict is
    /// not derivable from a single sample, and a column that disagreed with
    /// the Diagnose tab about what a socket is doing would be worse than no
    /// column at all.
    pub fn verdict_for(&self, local: &str, remote: &str) -> Option<SocketVerdict> {
        self.verdict_since
            .get(&format!("{local} → {remote}"))
            .map(|(v, _)| *v)
    }

    /// Apply a batch of readings to the store.
    pub fn learn(base: &mut BaselineStore, readings: &[(String, &'static str, f64)]) {
        for (subject, metric, value) in readings {
            base.observe(subject, metric, *value);
        }
    }

    pub fn sample(&mut self, app: &App, thresholds: &Thresholds) -> Observations {
        self.completed = super::engine::ObservationTimes {
            health: app.health_prober.status().completed.clone(),
            ..Default::default()
        };
        Observations {
            now: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            iface: self.iface(app),
            gateway: gateway(app),
            dns: dns(app),
            paths: self.paths(app),
            sockets: self.sockets(app, thresholds),
            // netwatch does not yet run a loaded-rtt test of its own. Leaving
            // these `None` makes the local-bufferbloat rule dormant and the
            // remote rule's discriminating check report "not run" — which is
            // the truth, and is why the check exists as a tri-state.
            idle_rtt_ms: None,
            loaded_rtt_ms: None,
            captive_portal_url: None,
            nat: nat(app),
        }
    }

    fn iface(&mut self, app: &App) -> Option<IfaceObs> {
        let (interfaces, completed) = app.traffic.timed_snapshot();
        self.completed.interface = completed;
        if !crate::collectors::health::ProbeTimes::fresh(completed, 15) {
            return None;
        }
        if let Some((at, cached)) = &self.interface_sample {
            if Some(*at) == completed && cached.name == app.capture_interface {
                return Some(cached.clone());
            }
        }
        let t = interfaces
            .iter()
            .find(|i| i.name == app.capture_interface)?;
        let info = app.interface_info.iter().find(|i| i.name == t.name);

        let errors = t.rx_errors + t.tx_errors;
        let drops = t.rx_drops + t.tx_drops;
        let (errors_per_min, drops_per_min) = self
            .iface_history
            .entry(t.name.clone())
            .or_insert_with(|| IfaceCounters::new(errors, drops))
            .observe(errors, drops);

        let wireless = info.and_then(|i| i.is_wireless).unwrap_or(false);
        // Retries as a share of frames sent over the same minute. Both are
        // lifetime counters, so the rate is delta over delta.
        let tx_retry_pct = t.tx_retries.map(|retries| {
            let (d_retries, d_packets) = self
                .wifi_history
                .entry(t.name.clone())
                .or_insert_with(|| IfaceCounters::new(retries, t.tx_packets))
                .observe(retries, t.tx_packets);
            if d_packets == 0 {
                0.0
            } else {
                d_retries as f64 / d_packets as f64 * 100.0
            }
        });

        let observed = IfaceObs {
            name: t.name.clone(),
            carrier: info.map(|i| i.is_up).unwrap_or(true),
            rx_errors: t.rx_errors,
            tx_errors: t.tx_errors,
            rx_dropped: t.rx_drops,
            tx_dropped: t.tx_drops,
            errors_per_min,
            drops_per_min,
            // Link rate isn't collected yet, so the saturation rule stays
            // dormant rather than guessing at 1Gb and crying wolf on wifi.
            link_rate_bps: None,
            wireless,
            signal_dbm: t.signal_dbm,
            tx_retry_pct,
            rx_bps: t.rx_rate,
            tx_bps: t.tx_rate,
        };
        self.interface_sample = Some((completed.unwrap(), observed.clone()));
        Some(observed)
    }

    fn paths(&mut self, app: &App) -> Vec<PathObs> {
        let result = match app.traceroute_runner.result.lock() {
            Ok(r) => r.clone(),
            Err(_) => return vec![],
        };
        self.completed.path = result.completed;
        if result.target.is_empty()
            || result.hops.is_empty()
            || !crate::collectors::health::ProbeTimes::fresh(result.completed, 120)
        {
            return vec![];
        }

        let completed = result.completed.unwrap();
        self.completed.path = Some(completed);
        if let Some((at, path)) = self.path_samples.get(&result.target) {
            if *at == completed {
                return vec![path.clone()];
            }
        }

        let hops: Vec<HopObs> = result
            .hops
            .iter()
            .map(|h| {
                let replies: Vec<f64> = h.rtt_ms.iter().flatten().copied().collect();
                let sent = h.rtt_ms.len().max(1) as f64;
                let lost = sent - replies.len() as f64;
                HopObs {
                    number: h.hop_number,
                    ip: h.ip.clone(),
                    // ASN would come from the whois cache; absent here, so the
                    // "provider changed" check compares addresses only.
                    asn: None,
                    rtt_p50_ms: percentile(&replies, 0.5),
                    rtt_p95_ms: percentile(&replies, 0.95),
                    loss_pct: (lost / sent) * 100.0,
                    // A hop with no replies at all is silent, not 100% lossy.
                    silent: replies.is_empty(),
                }
            })
            .collect();

        let previous = self.prev_path.insert(result.target.clone(), hops.clone());
        let path = PathObs {
            target: result.target.clone(),
            hops,
            previous,
            traced_at: result.completed_at.clone(),
        };
        self.path_samples
            .insert(result.target.clone(), (completed, path.clone()));
        vec![path]
    }

    fn sockets(&mut self, app: &App, thresholds: &Thresholds) -> Vec<SocketObs> {
        let (flows, completed) = app.tcp_info.timed_snapshot();
        self.completed.sockets = completed;
        if flows.is_empty() || !crate::collectors::health::ProbeTimes::fresh(completed, 30) {
            self.verdict_since.clear();
            return vec![];
        }
        let conns = app.connection_collector.connections();
        let now = Instant::now();
        let mut out = Vec::new();
        let mut live_keys: Vec<String> = Vec::new();

        for ((local, remote), info) in flows.iter() {
            let conn = conns
                .iter()
                .find(|c| &c.local_addr == local && &c.remote_addr == remote);

            let mut s = SocketObs {
                local: local.clone(),
                remote: remote.clone(),
                process: conn.and_then(|c| c.process_name.clone()),
                rtt_ms: info.rtt_us.map(|us| us as f64 / 1000.0),
                rttvar_ms: None,
                retrans: info.total_retrans.unwrap_or(0),
                cwnd: info.cwnd,
                ssthresh: info.ssthresh,
                rwnd: info.rwnd,
                mss: info.mss,
                tx_bps: conn.and_then(|c| c.tx_rate).unwrap_or(0.0),
                rx_bps: conn.and_then(|c| c.rx_rate).unwrap_or(0.0),
                verdict_age_secs: 0,
            };

            let key = s.key();
            live_keys.push(key.clone());
            let verdict = classify_socket(&s, thresholds);
            let since = match self.verdict_since.get(&key) {
                // Same verdict as last tick: keep the original start time.
                Some((prev, at)) if *prev == verdict => *at,
                _ => now,
            };
            self.verdict_since.insert(key, (verdict, since));
            s.verdict_age_secs = now.duration_since(since).as_secs();
            out.push(s);
        }

        // Sockets that have gone away lose their history; a new connection to
        // the same peer starts its verdict clock from zero.
        self.verdict_since.retain(|k, _| live_keys.contains(k));
        out
    }
}

fn gateway(app: &App) -> Option<GatewayObs> {
    let cfg = &app.config_collector.config;
    let addr = cfg.gateway.clone()?;
    let health = app.health_prober.status();

    // `HealthProber` starts every series at 100% loss, so the loss figure
    // alone cannot distinguish "unreachable" from "not probed yet" — and on a
    // fresh start that difference is a `critical` finding against a working
    // router. The history deques are the honest signal: they are empty until
    // a probe has actually published a result.
    if health.gateway_rtt_history.is_empty()
        || !crate::collectors::health::ProbeTimes::fresh(health.completed.gateway, 30)
        || health.completed.gateway_target.as_ref() != Some(&addr)
    {
        return None;
    }
    let icmp_ok = health.gateway_rtt_ms.is_some() && health.gateway_loss_pct < 100.0;

    // Corroborating evidence for a gateway verdict, on the same footing:
    // unknown until the internet probe has run at least once.
    let internet_reachable = if health.internet_rtt_history.is_empty()
        || !crate::collectors::health::ProbeTimes::fresh(health.completed.internet, 30)
    {
        None
    } else {
        Some(health.internet_rtt_ms.is_some() && health.internet_loss_pct < 100.0)
    };
    Some(GatewayObs {
        addr: Some(addr),
        rtt_ms: health.gateway_rtt_ms,
        loss_pct: health.gateway_loss_pct,
        internet_reachable,
        // No ARP probe yet. Reporting `true` would let the "wrong vlan" cause
        // be ruled out on no evidence, so it mirrors the ICMP result and the
        // cause analysis leans on the checks that did run.
        arp_ok: icmp_ok,
        icmp_ok,
    })
}

fn dns(app: &App) -> Option<DnsObs> {
    let cfg = &app.config_collector.config;
    let resolver = cfg.primary_dns()?;
    let health = app.health_prober.status();

    if !crate::collectors::health::ProbeTimes::fresh(health.completed.dns, 30)
        || health.completed.dns_target.as_ref() != Some(&resolver)
    {
        return None;
    }

    let samples: Vec<f64> = health.dns_rtt_history.iter().flatten().copied().collect();
    // One sample per probe, so the window is samples × the probe interval —
    // not × a bare 5, which silently became wrong the moment the cadence
    // constant moved.
    let window_secs = health.dns_rtt_history.len() as u64 * crate::app::HEALTH_PROBE_TICKS as u64;

    // Reply flags across the window: every reply the probe decoded, and how
    // many of them were truncated.
    let replies: u32 = health
        .dns_probe_history
        .iter()
        .map(|p| p.replies as u32)
        .sum();
    let truncated: u32 = health
        .dns_probe_history
        .iter()
        .map(|p| p.truncated as u32)
        .sum();
    let truncation_rate_pct = if replies == 0 {
        0.0
    } else {
        truncated as f64 / replies as f64 * 100.0
    };
    let cross = health.dns_cross.as_ref().map(|c| {
        let cycles = health.dns_cross_history.len() as u32;
        let disagreed = health.dns_cross_history.iter().filter(|b| **b).count();
        DnsCross {
            name: c.name.clone(),
            local: c.local.iter().map(|ip| ip.to_string()).collect(),
            reference_resolver: c.reference_resolver.clone(),
            reference: c.reference.iter().map(|ip| ip.to_string()).collect(),
            validated: c.validated,
            private_answer: c.private_answer,
            mismatch_pct: if cycles == 0 {
                0.0
            } else {
                disagreed as f64 / cycles as f64 * 100.0
            },
            cycles,
        }
    });

    Some(DnsObs {
        resolver,
        rtt_p50_ms: percentile(&samples, 0.5).or(health.dns_rtt_ms),
        rtt_p95_ms: percentile(&samples, 0.95),
        failure_rate_pct: health.dns_loss_pct,
        truncation_rate_pct,
        queries: replies.max(health.dns_rtt_history.len() as u32),
        failed: health
            .dns_rtt_history
            .iter()
            .filter(|s| s.is_none())
            .count() as u32,
        truncated,
        // netwatch probes one resolver today. The alternate-resolver check is
        // the strongest discriminator the DNS rule has, so this is the first
        // thing the pipeline should add; until then it reports "not run".
        alt_resolver: cfg.dns_servers.get(1).cloned(),
        alt_rtt_ms: None,
        icmp_rtt_ms: None,
        cached_rtt_ms: None,
        window_secs,
        cross,
    })
}

fn nat(app: &App) -> Option<NatObs> {
    let health = app.health_prober.status();
    if !crate::collectors::health::ProbeTimes::fresh(health.completed.nat, 300) {
        return None;
    }
    health.nat.as_ref().map(|n| NatObs {
        mappings: n.mappings.clone(),
        symmetric: n.symmetric,
    })
}

/// Nearest-rank percentile. `None` on an empty sample set rather than 0.0 —
/// "no measurement" and "zero milliseconds" are different claims.
fn percentile(values: &[f64], p: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((v.len() as f64 - 1.0) * p).round() as usize;
    v.get(idx).copied()
}

/// `192.168.8.42` → `192.168.8.0/24`. A coarse /24 assumption, but the
/// fingerprint only needs to distinguish networks, not describe them.
fn subnet_of(ip: &str) -> String {
    let base = ip.split('/').next().unwrap_or(ip);
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
    } else {
        base.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_probe_is_learned_once_and_stale_results_are_not_learned() {
        let mut sampler = LiveSampler::new();
        let now = Instant::now();
        assert!(sampler.fresh_reading("dns", Some(now)));
        assert!(!sampler.fresh_reading("dns", Some(now)));
        assert!(!sampler.fresh_reading("dns", Some(now - std::time::Duration::from_secs(31))));
        assert!(!sampler.fresh_reading("dns", None));
        assert!(sampler.fresh_reading("dns", Some(now + std::time::Duration::from_nanos(1))));
    }

    #[test]
    fn percentile_of_nothing_is_not_zero() {
        assert_eq!(percentile(&[], 0.5), None);
    }

    #[test]
    fn percentiles_pick_the_right_samples() {
        let v = vec![1.0, 2.0, 3.0, 4.0, 100.0];
        assert_eq!(percentile(&v, 0.5), Some(3.0));
        assert_eq!(percentile(&v, 0.95), Some(100.0));
    }

    #[test]
    fn interface_rates_are_per_minute_not_per_tick() {
        let mut c = IfaceCounters::new(1000, 5000);
        for i in 1..=10 {
            let (e, d) = c.observe(1000 + i, 5000 + 2 * i);
            assert_eq!((e, d), (i, 2 * i), "the window must accumulate");
        }
        for i in 11..=120 {
            c.observe(1000 + i, 5000 + 2 * i);
        }
        // errors 1000 + 121, drops 5000 + 2 × 121.
        let (e, d) = c.observe(1121, 5242);
        assert_eq!((e, d), (60, 120), "one minute at 1/s errors and 2/s drops");
    }

    #[test]
    fn a_counter_reset_does_not_report_billions_of_errors() {
        let mut c = IfaceCounters::new(50_000, 90_000);
        let (e, d) = c.observe(3, 7);
        assert_eq!(
            (e, d),
            (0, 0),
            "a reset must not underflow into a huge rate"
        );
        assert_eq!(c.observe(5, 9), (2, 2));
    }

    #[test]
    fn a_quiet_interface_reports_nothing() {
        let mut c = IfaceCounters::new(10, 20);
        for _ in 0..120 {
            assert_eq!(c.observe(10, 20), (0, 0));
        }
    }

    #[test]
    fn subnet_of_collapses_a_host_address() {
        assert_eq!(subnet_of("192.168.8.42"), "192.168.8.0/24");
        assert_eq!(subnet_of("192.168.8.42/24"), "192.168.8.0/24");
        assert_eq!(subnet_of("fe80::1"), "fe80::1");
    }

    #[test]
    fn a_socket_verdict_clock_survives_ticks_but_resets_on_change() {
        let mut sampler = LiveSampler::new();
        let key = "a → b".to_string();
        let t0 = Instant::now();
        sampler
            .verdict_since
            .insert(key.clone(), (SocketVerdict::Bufferbloat, t0));

        // Same verdict next tick: the clock keeps running.
        let kept = match sampler.verdict_since.get(&key) {
            Some((v, at)) if *v == SocketVerdict::Bufferbloat => *at,
            _ => Instant::now(),
        };
        assert_eq!(kept, t0);

        // Different verdict: the clock restarts.
        let restarted = match sampler.verdict_since.get(&key) {
            Some((v, at)) if *v == SocketVerdict::ZeroWindow => *at,
            _ => Instant::now(),
        };
        assert_ne!(restarted, t0);
    }

    /// Every baselined metric must be consumed by an *active* rule whose
    /// verify condition is expressed in that metric or its σ form. This test
    /// caught `gateway.rtt` being learned every second by a rule that did not
    /// exist.
    #[test]
    fn every_baselined_metric_feeds_an_active_rule() {
        for (metric, rule_id) in BASELINED_METRICS {
            let rule = crate::diagnose::rules::lookup(rule_id).unwrap_or_else(|| {
                panic!("{metric} names rule {rule_id}, which is not in the catalogue")
            });
            assert!(
                rule.status.is_active(),
                "{metric} is baselined for {rule_id}, which is only Planned —                  the samples would never be read"
            );
            let verify = crate::diagnose::rules::default_verify(rule_id)
                .unwrap_or_else(|| panic!("{rule_id} has no verify condition"));
            let sigma_form = format!("{metric}_sigma");
            assert!(
                verify.metric == *metric || verify.metric == sigma_form,
                "{rule_id} verifies on {}, but {metric} is what gets baselined",
                verify.metric
            );
        }
    }

    #[test]
    fn readings_and_baselined_metrics_agree() {
        // The names `readings()` emits must be exactly the ones declared.
        let declared: Vec<&str> = BASELINED_METRICS.iter().map(|(m, _)| *m).collect();
        for m in ["dns.rtt_p50", "gateway.rtt", "path.rtt"] {
            assert!(declared.contains(&m), "{m} is emitted but not declared");
        }
        assert_eq!(declared.len(), 3);
    }
}
