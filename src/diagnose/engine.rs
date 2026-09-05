//! The evaluator: detections in, a stable `Vec<Issue>` out.
//!
//! Everything a user sees about what is wrong reads from [`Engine::issues`] —
//! the Diagnose tab, the verdict line under the tab bar on every other tab,
//! the timeline events, the toast, and the exported report. There is exactly
//! one list, so those six surfaces cannot disagree with each other.
//!
//! The engine's real job is *continuity*. A resolver that has been slow for an
//! hour is one issue with a growing window, not 3,600 findings; a resolver
//! that flaps every few minutes is one issue with a recurrence count, not
//! twenty. Detectors are stateless and fire every tick — turning that into a
//! stable, human-sized list of findings happens here.

use chrono::{DateTime, Duration, Local, TimeZone};
use std::collections::HashMap;

use super::baseline::BaselineStore;
use super::detectors::{self, Detection, Observations, Thresholds};
use super::issue::{Issue, IssueId, IssueState, Severity};
use super::rules;

/// Time source. A trait so the fixture and the tests can pin the clock and
/// produce byte-identical reports.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Local>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Local> {
        Local::now()
    }
}

/// A clock frozen at one instant, then advanced by hand.
pub struct FixedClock {
    at: std::sync::Mutex<DateTime<Local>>,
}

impl FixedClock {
    pub fn at(s: &str) -> Self {
        let naive = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
            .expect("fixed clock needs YYYY-MM-DD HH:MM:SS");
        let at = Local
            .from_local_datetime(&naive)
            .single()
            .expect("unambiguous local time");
        Self {
            at: std::sync::Mutex::new(at),
        }
    }

    pub fn advance_secs(&self, secs: i64) {
        let mut g = self.at.lock().unwrap();
        *g += Duration::seconds(secs);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Local> {
        *self.at.lock().unwrap()
    }
}

pub fn format_ts(dt: DateTime<Local>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Parse a `%Y-%m-%d %H:%M:%S` local stamp of the kind every issue carries.
///
/// Public so surfaces that place an event on a time axis measure it against
/// the same clock the engine wrote it with, instead of re-deriving an offset
/// and drifting by a tick.
pub fn parse_ts(s: &str) -> Option<DateTime<Local>> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .and_then(|n| Local.from_local_datetime(&n).single())
}

/// How long after closing a recurrence reopens the same issue instead of
/// filing a new one. Flapping should read as one problem with a count.
const RECURRENCE_WINDOW_MINS: i64 = 30;

/// Engine settings, all user-tunable.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    pub thresholds: Thresholds,
    /// How long a resolved condition must stay resolved before auto-closing.
    pub auto_close_secs: u64,
    /// Closed issues kept for the report and the timeline.
    pub history_limit: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            thresholds: Thresholds::default(),
            auto_close_secs: 300,
            history_limit: 50,
        }
    }
}

pub struct Engine {
    issues: Vec<Issue>,
    /// `Detection::key()` → issue id, so a condition maps to the same issue
    /// across ticks.
    by_key: HashMap<String, IssueId>,
    /// When the verify condition started holding for an issue. Cleared the
    /// moment it stops.
    verifying_since: HashMap<IssueId, DateTime<Local>>,
    clock: Box<dyn Clock>,
    settings: Settings,
    seq: u32,
}

impl Engine {
    pub fn new(clock: Box<dyn Clock>) -> Self {
        Self {
            issues: Vec::new(),
            by_key: HashMap::new(),
            verifying_since: HashMap::new(),
            clock,
            settings: Settings::default(),
            seq: 0,
        }
    }

    pub fn with_settings(mut self, settings: Settings) -> Self {
        self.settings = settings;
        self
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }

    /// Findings to show: open, and not a consequence of another open issue.
    pub fn primary(&self) -> Vec<&Issue> {
        rules::primary_issues(&self.issues)
    }

    pub fn open_count(&self) -> usize {
        self.primary().len()
    }

    pub fn worst_severity(&self) -> Option<Severity> {
        self.primary().iter().map(|i| i.severity).max()
    }

    pub fn get(&self, id: &str) -> Option<&Issue> {
        self.issues.iter().find(|i| i.id == id)
    }

    /// One tick. Detections are merged into the existing list, issues whose
    /// condition has cleared are moved toward auto-close, and the suppression
    /// graph is recomputed.
    pub fn observe(&mut self, obs: &Observations, base: &BaselineStore) {
        let now = self.clock.now();
        let detections = detectors::detect(obs, base, &self.settings.thresholds);
        let seen: Vec<String> = detections.iter().map(|d| d.key()).collect();

        for d in detections {
            self.merge(d, now);
        }

        let mut values = metric_values(obs);
        // σ-denominated verify conditions ("back within 3σ of baseline") need
        // the baselines to evaluate, so they are derived here rather than in
        // the pure observation mapping.
        add_sigma_metrics(&mut values, obs, base);
        self.age_unseen(&seen, &values, now);

        rules::apply_suppression(&mut self.issues);
        self.sort();
        self.prune();
    }

    fn merge(&mut self, d: Detection, now: DateTime<Local>) {
        let key = d.key();
        let ts = format_ts(now);

        if let Some(id) = self.by_key.get(&key).cloned() {
            if let Some(idx) = self.issues.iter().position(|i| i.id == id) {
                let reopening = !self.issues[idx].state.is_open();
                let issue = &mut self.issues[idx];

                if reopening {
                    // Within the recurrence window this is the same problem
                    // coming back, so it keeps its id and gains a count.
                    // Outside it, the old issue stays closed and we file new.
                    let closed_at = match &issue.state {
                        IssueState::Resolved { at } | IssueState::AutoClosed { at } => parse_ts(at),
                        _ => None,
                    };
                    let within = closed_at
                        .map(|c| now - c <= Duration::minutes(RECURRENCE_WINDOW_MINS))
                        .unwrap_or(false);
                    if within {
                        issue.state = IssueState::Open;
                        issue.recurrence += 1;
                        issue.since = ts.clone();
                    } else {
                        self.by_key.remove(&key);
                        self.open_new(d, now);
                        return;
                    }
                }

                // A muted issue keeps accruing evidence silently; it just
                // doesn't reach the verdict line.
                issue.last_seen = ts;
                issue.severity = d.severity;
                issue.title = d.title;
                issue.evidence = d.evidence;
                issue.causes = d.causes;
                issue.scope = d.scope;
                issue.verify = d.verify;
                // Preserve applied outcomes across ticks: a step the user
                // already ran must keep saying so.
                merge_remediation(&mut issue.remediation, d.remediation);
                issue.rank_causes();
                self.verifying_since.remove(&id);
                return;
            }
            self.by_key.remove(&key);
        }
        self.open_new(d, now);
    }

    fn open_new(&mut self, d: Detection, now: DateTime<Local>) {
        self.seq += 1;
        let id = format!("{}-{:02}", now.format("%Y-%m%d"), self.seq);
        let ts = format_ts(now);
        // Take the key before the detection is consumed field by field.
        let key = d.key();
        let mut issue = Issue {
            id: id.clone(),
            rule: d.rule.to_string(),
            severity: d.severity,
            title: d.title,
            subject: d.subject,
            since: ts.clone(),
            last_seen: ts,
            state: IssueState::Open,
            evidence: d.evidence,
            scope: d.scope,
            causes: d.causes,
            remediation: d.remediation,
            verify: d.verify,
            artifacts: vec![],
            consequences: vec![],
            suppressed_by: None,
            recurrence: 0,
        };
        issue.rank_causes();
        self.by_key.insert(key, id);
        self.issues.push(issue);
    }

    /// Issues that no detector produced this pass. Their verify condition is
    /// checked against live metrics; once it has held for `hold_secs` the
    /// issue auto-closes. Until then it stays open — a metric dipping under
    /// the threshold for one sample is not a fix.
    fn age_unseen(&mut self, seen: &[String], values: &HashMap<String, f64>, now: DateTime<Local>) {
        let mut closed: Vec<IssueId> = Vec::new();
        for issue in self.issues.iter_mut() {
            if !issue.state.is_open() {
                continue;
            }
            let key = format!("{}|{}", issue.rule, issue.subject.label());
            if seen.contains(&key) {
                continue;
            }

            let holding = match values.get(&issue.verify.metric) {
                Some(v) => issue.verify.holds(*v),
                // No reading for the metric. The condition that opened the
                // issue is gone, which is itself evidence it cleared, but we
                // still make it serve the hold window before closing.
                None => true,
            };

            if !holding {
                self.verifying_since.remove(&issue.id);
                continue;
            }

            let started = *self.verifying_since.entry(issue.id.clone()).or_insert(now);
            let held = (now - started).num_seconds().max(0) as u64;
            if held >= issue.verify.hold_secs {
                issue.state = IssueState::AutoClosed { at: format_ts(now) };
                closed.push(issue.id.clone());
            }
        }
        for id in closed {
            self.verifying_since.remove(&id);
        }
    }

    fn sort(&mut self) {
        // Open before closed, then severity, then oldest first — a problem
        // that has been running for an hour outranks one from ten seconds ago.
        self.issues.sort_by(|a, b| {
            b.state
                .is_open()
                .cmp(&a.state.is_open())
                .then(b.severity.cmp(&a.severity))
                .then(a.since.cmp(&b.since))
        });
    }

    fn prune(&mut self) {
        let closed: Vec<usize> = self
            .issues
            .iter()
            .enumerate()
            .filter(|(_, i)| !i.state.is_open())
            .map(|(n, _)| n)
            .collect();
        if closed.len() <= self.settings.history_limit {
            return;
        }
        let drop_count = closed.len() - self.settings.history_limit;
        let doomed: Vec<IssueId> = closed
            .iter()
            .rev()
            .take(drop_count)
            .map(|&n| self.issues[n].id.clone())
            .collect();
        self.issues.retain(|i| !doomed.contains(&i.id));
        self.by_key.retain(|_, id| !doomed.contains(id));
    }

    // ------------------------------------------------------ user actions

    pub fn ack(&mut self, id: &str) -> bool {
        self.set_state(id, |s| {
            if matches!(s, IssueState::Open) {
                Some(IssueState::Acked)
            } else {
                None
            }
        })
    }

    pub fn mute(&mut self, id: &str, mins: i64) -> bool {
        let until = format_ts(self.clock.now() + Duration::minutes(mins));
        self.set_state(id, move |s| {
            s.is_open().then(|| IssueState::Muted {
                until: until.clone(),
            })
        })
    }

    /// Mark an issue fixed by hand. Distinct from auto-close: the report says
    /// which, because "netwatch watched it clear" and "a human said it was
    /// fine" are different claims.
    pub fn resolve(&mut self, id: &str) -> bool {
        let at = format_ts(self.clock.now());
        self.set_state(id, move |_| Some(IssueState::Resolved { at: at.clone() }))
    }

    fn set_state(&mut self, id: &str, f: impl Fn(&IssueState) -> Option<IssueState>) -> bool {
        let Some(issue) = self.issues.iter_mut().find(|i| i.id == id) else {
            return false;
        };
        match f(&issue.state) {
            Some(next) => {
                issue.state = next;
                rules::apply_suppression(&mut self.issues);
                true
            }
            None => false,
        }
    }

    /// Record the outcome of a remediation step on its issue, so the screen
    /// and the report both show what was actually done.
    pub fn record_applied(&mut self, id: &str, key: char, applied: super::issue::Applied) -> bool {
        let Some(issue) = self.issues.iter_mut().find(|i| i.id == id) else {
            return false;
        };
        let Some(step) = issue.remediation.iter_mut().find(|s| s.key == Some(key)) else {
            return false;
        };
        step.applied = Some(applied);
        true
    }

    /// The line under the tab bar. Collapses to one dim sentence when nothing
    /// is wrong, and never claims health it hasn't verified — a host still
    /// learning its baselines says so rather than saying "all nominal".
    pub fn verdict(&self, base: &BaselineStore) -> Verdict {
        let primary = self.primary();
        let visible: Vec<&Issue> = primary
            .into_iter()
            .filter(|i| !matches!(i.state, IssueState::Muted { .. }))
            .collect();

        if visible.is_empty() {
            let readiness = base.overall_readiness();
            if base.switched_network() && !readiness.is_ready() {
                return Verdict::Learning {
                    detail: format!(
                        "new network ({}) — {}",
                        base.fingerprint().label(),
                        readiness.label()
                    ),
                };
            }
            if !readiness.is_ready() {
                return Verdict::Learning {
                    detail: format!("baselines {}", readiness.label()),
                };
            }
            return Verdict::Clear;
        }

        let worst = visible
            .iter()
            .map(|i| i.severity)
            .max()
            .unwrap_or(Severity::Info);
        Verdict::Issues {
            severity: worst,
            count: visible.len(),
            headline: visible[0].summary_line(),
            id: visible[0].id.clone(),
        }
    }
}

/// Preserve `applied` outcomes when a detector re-emits a step list.
fn merge_remediation(existing: &mut Vec<super::issue::Step>, fresh: Vec<super::issue::Step>) {
    let applied: HashMap<String, super::issue::Applied> = existing
        .iter()
        .filter_map(|s| s.applied.clone().map(|a| (s.text.clone(), a)))
        .collect();
    *existing = fresh
        .into_iter()
        .map(|mut s| {
            if let Some(a) = applied.get(&s.text) {
                s.applied = Some(a.clone());
            }
            s
        })
        .collect();
}

/// What the verdict line says.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Baselines are ready and nothing is open.
    Clear,
    /// Nothing is open, but netwatch doesn't yet have the baselines to say so
    /// with confidence.
    Learning { detail: String },
    Issues {
        severity: Severity,
        count: usize,
        headline: String,
        id: IssueId,
    },
}

impl Verdict {
    /// The exact text of the line, so the TUI, the toast and `y` copy agree.
    pub fn line(&self) -> String {
        match self {
            Verdict::Clear => "no issues · baselines ready".to_string(),
            Verdict::Learning { detail } => format!("no issues · {detail}"),
            Verdict::Issues {
                count, headline, ..
            } => {
                let n = if *count == 1 {
                    "1 issue".to_string()
                } else {
                    format!("{count} issues")
                };
                format!("{n} · {headline} · press 9 to diagnose")
            }
        }
    }

    pub fn is_clear(&self) -> bool {
        !matches!(self, Verdict::Issues { .. })
    }

    /// Short form for tight chrome — a box title, a Lite status cell, a Dense
    /// subtitle.
    ///
    /// Note what this deliberately cannot say: "nominal" is reserved for a
    /// host whose baselines are ready and whose issue list is empty. A host
    /// that has been up for ninety seconds reports `learning`, because it has
    /// not yet earned the right to call anything nominal — which is the
    /// specific claim the design review objected to.
    pub fn chip(&self) -> &'static str {
        match self {
            Verdict::Clear => "nominal",
            Verdict::Learning { .. } => "learning",
            Verdict::Issues { count, .. } => {
                if *count == 1 {
                    "1 issue"
                } else {
                    "issues"
                }
            }
        }
    }

    /// Count for the chip when it needs a number alongside the word.
    pub fn count(&self) -> usize {
        match self {
            Verdict::Issues { count, .. } => *count,
            _ => 0,
        }
    }

    pub fn severity(&self) -> Option<Severity> {
        match self {
            Verdict::Issues { severity, .. } => Some(*severity),
            _ => None,
        }
    }

    /// Colour for the chip, resolved against a theme.
    pub fn color(&self, t: &crate::theme::Theme) -> ratatui::style::Color {
        match self.severity() {
            Some(Severity::Critical) | Some(Severity::High) => t.status_error,
            Some(Severity::Medium) => t.status_warn,
            Some(Severity::Info) => t.status_info,
            // A clear verdict is green; a learning one is not — it is an
            // absence of information, and green would misreport it as health.
            None => match self {
                Verdict::Clear => t.status_good,
                _ => t.text_muted,
            },
        }
    }
}

/// Derive the σ-denominated metrics from the raw readings and the baselines.
///
/// A rule that opened because a value was 3σ above baseline closes when it is
/// back inside 3σ — not when it drops below some absolute number, which would
/// be a different claim on every network.
fn add_sigma_metrics(values: &mut HashMap<String, f64>, obs: &Observations, base: &BaselineStore) {
    if let Some(gw) = &obs.gateway {
        if let (Some(addr), Some(rtt)) = (&gw.addr, gw.rtt_ms) {
            if let Some(sigma) = base
                .get(addr, "gateway.rtt")
                .and_then(|b| b.sigma_above(rtt))
            {
                values.insert("gateway.rtt_sigma".to_string(), sigma);
            }
        }
    }
    for path in &obs.paths {
        let Some(last) = path.hops.iter().rev().find(|h| !h.silent) else {
            continue;
        };
        let Some(rtt) = last.rtt_p50_ms else { continue };
        let sigma = base
            .get(&path.target, "path.rtt")
            .or_else(|| base.get("internet", "path.rtt"))
            .and_then(|b| b.sigma_above(rtt));
        if let Some(sigma) = sigma {
            values.insert("path.rtt_sigma".to_string(), sigma);
            values.insert("path.rtt".to_string(), rtt);
        }
    }
}

/// Flatten observations into the metric namespace the verify conditions use.
/// Every key here matches an `Evidence::metric` a detector emits — that shared
/// vocabulary is what lets a rule declare its own success condition.
fn metric_values(obs: &Observations) -> HashMap<String, f64> {
    let mut m = HashMap::new();
    if let Some(dns) = &obs.dns {
        if let Some(p50) = dns.rtt_p50_ms {
            m.insert("dns.rtt_p50".to_string(), p50);
        }
        if let Some(p95) = dns.rtt_p95_ms {
            m.insert("dns.rtt_p95".to_string(), p95);
        }
        m.insert("dns.failure_rate".to_string(), dns.failure_rate_pct);
        m.insert("dns.tc_rate".to_string(), dns.truncation_rate_pct);
    }
    if let Some(gw) = &obs.gateway {
        m.insert("gateway.loss".to_string(), gw.loss_pct);
        if let Some(rtt) = gw.rtt_ms {
            m.insert("gateway.rtt".to_string(), rtt);
        }
    }
    if let Some(iface) = &obs.iface {
        m.insert(
            "iface.carrier".to_string(),
            if iface.carrier { 1.0 } else { 0.0 },
        );
        m.insert(
            "iface.error_rate".to_string(),
            (iface.errors_per_min + iface.drops_per_min) as f64,
        );
        if let Some(u) = iface.utilisation_pct() {
            m.insert("iface.utilisation".to_string(), u);
        }
    }
    if let (Some(idle), Some(loaded)) = (obs.idle_rtt_ms, obs.loaded_rtt_ms) {
        m.insert("tcp.loaded_rtt_delta".to_string(), loaded - idle);
    }
    // Socket metrics are per-subject; the worst socket stands for the metric,
    // so an issue can't close while any socket still shows the condition.
    if let Some(worst) = obs
        .sockets
        .iter()
        .filter_map(|s| s.rtt_ms)
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    {
        m.insert("tcp.socket_rtt".to_string(), worst);
    }
    if let Some(worst) = obs.sockets.iter().map(|s| s.retrans).max() {
        m.insert("tcp.retrans_rate".to_string(), worst as f64);
    }
    if let Some(min_rwnd) = obs.sockets.iter().filter_map(|s| s.rwnd).min() {
        m.insert("tcp.rwnd".to_string(), min_rwnd as f64);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::baseline::NetworkFingerprint;
    use crate::diagnose::detectors::{DnsObs, GatewayObs, SocketObs};

    fn base() -> BaselineStore {
        let mut b = BaselineStore::new(NetworkFingerprint::new(
            "eth0",
            Some("192.168.8.1".into()),
            vec!["169.254.1.1".into()],
            None,
        ))
        .with_min_samples(3);
        b.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        b
    }

    fn dns(p50: f64) -> DnsObs {
        DnsObs {
            resolver: "169.254.1.1".into(),
            rtt_p50_ms: Some(p50),
            rtt_p95_ms: Some(p50 * 1.2),
            failure_rate_pct: 0.0,
            truncation_rate_pct: 0.0,
            queries: 38,
            failed: 0,
            truncated: 0,
            alt_resolver: Some("192.168.8.1".into()),
            alt_rtt_ms: Some(1.4),
            icmp_rtt_ms: Some(0.1),
            cached_rtt_ms: Some(0.9),
            window_secs: 180,
        }
    }

    fn obs(p50: f64) -> Observations {
        Observations {
            now: "2026-09-03 06:48:10".into(),
            dns: Some(dns(p50)),
            ..Default::default()
        }
    }

    fn engine_at(ts: &str) -> (Engine, std::sync::Arc<FixedClock>) {
        let clock = std::sync::Arc::new(FixedClock::at(ts));
        let engine = Engine::new(Box::new(ClockRef(clock.clone())));
        (engine, clock)
    }

    struct ClockRef(std::sync::Arc<FixedClock>);
    impl Clock for ClockRef {
        fn now(&self) -> DateTime<Local> {
            self.0.now()
        }
    }

    #[test]
    fn a_persistent_condition_stays_one_issue() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        for _ in 0..120 {
            e.observe(&obs(40.0), &b);
            clock.advance_secs(1);
        }
        assert_eq!(e.open_count(), 1, "120 ticks must not make 120 issues");
        let issue = &e.primary()[0];
        assert_eq!(
            issue.since, "2026-09-03 06:48:10",
            "since must be the first violation"
        );
        assert_eq!(issue.last_seen, "2026-09-03 06:50:09");
        assert_eq!(issue.recurrence, 0);
    }

    #[test]
    fn ids_are_stable_across_ticks() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let first = e.primary()[0].id.clone();
        clock.advance_secs(5);
        e.observe(&obs(41.0), &b);
        assert_eq!(e.primary()[0].id, first);
    }

    #[test]
    fn an_issue_does_not_close_on_one_good_sample() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        assert_eq!(e.open_count(), 1);

        clock.advance_secs(1);
        e.observe(&obs(1.3), &b);
        assert_eq!(
            e.open_count(),
            1,
            "one good sample is not a fix — the verify window has to elapse"
        );
    }

    #[test]
    fn an_issue_auto_closes_once_verify_holds_for_its_window() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);

        // dns.slow_resolver verifies on p50 < 5ms held for 60s.
        for _ in 0..61 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        assert_eq!(e.open_count(), 0);
        let issue = &e.issues()[0];
        assert!(
            matches!(issue.state, IssueState::AutoClosed { .. }),
            "{:?}",
            issue.state
        );
    }

    #[test]
    fn a_relapse_inside_the_window_resets_the_verify_clock() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        for _ in 0..50 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        // 50s of good, then one bad sample: the clock must restart.
        clock.advance_secs(1);
        e.observe(&obs(40.0), &b);
        for _ in 0..30 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        assert_eq!(
            e.open_count(),
            1,
            "30s of quiet is not the 60s the rule asks for"
        );
    }

    #[test]
    fn flapping_reads_as_one_issue_with_a_recurrence_count() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        for round in 0..3 {
            e.observe(&obs(40.0), &b);
            for _ in 0..61 {
                clock.advance_secs(1);
                e.observe(&obs(1.3), &b);
            }
            assert_eq!(e.open_count(), 0, "round {round} should have closed");
        }
        e.observe(&obs(40.0), &b);

        assert_eq!(e.issues().len(), 1, "flapping must not file four findings");
        assert_eq!(e.primary()[0].recurrence, 3);
    }

    #[test]
    fn a_return_after_the_recurrence_window_is_a_new_issue() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        for _ in 0..61 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        clock.advance_secs(60 * 60); // an hour later
        e.observe(&obs(40.0), &b);

        assert_eq!(e.issues().len(), 2, "an hour later is a new incident");
        assert_eq!(e.primary()[0].recurrence, 0);
    }

    #[test]
    fn suppression_reaches_the_verdict_line() {
        let (mut e, _clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        let mut o = obs(40.0);
        o.gateway = Some(GatewayObs {
            addr: Some("192.168.8.1".into()),
            rtt_ms: None,
            loss_pct: 100.0,
            arp_ok: true,
            icmp_ok: false,
            internet_reachable: Some(false),
        });
        e.observe(&o, &b);

        assert_eq!(
            e.open_count(),
            1,
            "dns is a consequence of the dead gateway"
        );
        let v = e.verdict(&b);
        assert!(v.line().contains("gateway unreachable"), "{}", v.line());
        assert!(v.line().contains("1 issue"), "{}", v.line());
    }

    #[test]
    fn the_verdict_admits_when_it_has_no_baselines() {
        let (e, _clock) = engine_at("2026-09-03 06:48:10");
        let empty = BaselineStore::new(NetworkFingerprint::new("eth0", None, vec![], None));
        let v = e.verdict(&empty);
        assert!(matches!(v, Verdict::Learning { .. }));
        assert!(
            !v.line().contains("nominal"),
            "an unlearned host must not claim health: {}",
            v.line()
        );
        assert!(v.line().contains("no baseline"), "{}", v.line());
    }

    #[test]
    fn the_verdict_says_so_after_a_network_change() {
        let (e, _clock) = engine_at("2026-09-03 06:48:10");
        let mut b = base();
        b.set_network(NetworkFingerprint::new(
            "wlan0",
            Some("172.20.10.1".into()),
            vec!["172.20.10.1".into()],
            None,
        ));
        let line = e.verdict(&b).line();
        assert!(line.contains("new network"), "{line}");
        assert!(line.contains("wlan0"), "{line}");
    }

    #[test]
    fn the_chip_never_calls_an_unlearned_host_nominal() {
        let (e, _clock) = engine_at("2026-09-03 06:48:10");
        let empty = BaselineStore::new(NetworkFingerprint::new("eth0", None, vec![], None));
        assert_eq!(e.verdict(&empty).chip(), "learning");
        assert_eq!(e.verdict(&base()).chip(), "nominal");

        let theme = crate::theme::by_name("default");
        assert_ne!(
            e.verdict(&empty).color(&theme),
            theme.status_good,
            "learning must not render as health"
        );
        assert_eq!(e.verdict(&base()).color(&theme), theme.status_good);
    }

    #[test]
    fn a_clear_verdict_is_one_quiet_line() {
        let (e, _clock) = engine_at("2026-09-03 06:48:10");
        assert_eq!(e.verdict(&base()).line(), "no issues · baselines ready");
    }

    #[test]
    fn muted_issues_leave_the_verdict_line_but_stay_in_the_list() {
        let (mut e, _clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.mute(&id, 60));

        assert!(e.verdict(&b).is_clear(), "a muted issue must not shout");
        assert_eq!(e.issues().len(), 1, "but it is still on the Diagnose tab");
    }

    #[test]
    fn acking_keeps_an_issue_open() {
        let (mut e, _clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.ack(&id));
        assert_eq!(e.open_count(), 1);
        assert_eq!(e.get(&id).unwrap().state.label(), "acked");
    }

    #[test]
    fn an_applied_step_survives_the_next_tick() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.record_applied(
            &id,
            '1',
            super::super::issue::Applied::Yes {
                at: "2026-09-03 06:52:00".into(),
                before: "169.254.1.1".into(),
                after: "192.168.8.1".into(),
            }
        ));

        clock.advance_secs(1);
        e.observe(&obs(40.0), &b);
        let step = e
            .get(&id)
            .unwrap()
            .remediation
            .iter()
            .find(|s| s.key == Some('1'))
            .unwrap();
        assert!(
            step.applied.is_some(),
            "a detector re-emitting its steps must not erase what the user did"
        );
    }

    #[test]
    fn worst_socket_rtt_keeps_an_issue_open_until_every_socket_clears() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        let socket = |rtt: f64, age: u64| SocketObs {
            local: "10.88.0.2:52344".into(),
            remote: "10.88.0.3:9000".into(),
            process: Some("ncat".into()),
            rtt_ms: Some(rtt),
            rttvar_ms: Some(10.0),
            retrans: 12,
            cwnd: Some(10),
            ssthresh: Some(u32::MAX),
            rwnd: Some(64_000),
            mss: Some(1448),
            tx_bps: 2.4e6,
            rx_bps: 0.0,
            verdict_age_secs: age,
        };
        let mut o = Observations {
            sockets: vec![socket(184.0, 90)],
            idle_rtt_ms: Some(12.0),
            loaded_rtt_ms: Some(18.0),
            ..Default::default()
        };
        e.observe(&o, &b);
        assert_eq!(e.open_count(), 1);

        // Socket recovers but is still above the verify threshold.
        o.sockets = vec![socket(120.0, 90)];
        for _ in 0..70 {
            clock.advance_secs(1);
            e.observe(&o, &b);
        }
        assert_eq!(e.open_count(), 1, "120ms still fails verify (< 100ms)");
    }

    #[test]
    fn closed_issue_history_is_bounded() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        e.settings.history_limit = 3;
        let b = base();
        for _ in 0..8 {
            e.observe(&obs(40.0), &b);
            for _ in 0..61 {
                clock.advance_secs(1);
                e.observe(&obs(1.3), &b);
            }
            // Push past the recurrence window so each round is a new issue.
            clock.advance_secs(31 * 60);
        }
        let closed = e.issues().iter().filter(|i| !i.state.is_open()).count();
        assert!(
            closed <= 3,
            "history limit not enforced: {closed} closed issues"
        );
    }
}
