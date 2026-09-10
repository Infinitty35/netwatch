//! The `Issue` object: one source of truth for the Diagnose tab, the verdict
//! line on every other tab, the timeline event, and the exported report.
//!
//! The rule the whole module is built around: **if the screen and the report
//! are generated from the same object they cannot disagree.** Nothing here
//! stores a pre-rendered sentence containing a number. Every ratio, delta and
//! multiple shown to a user is computed from [`Evidence`] at render time by
//! the helpers on these types, so a report can never claim "100×" while the
//! evidence says 33×.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable identifier, `YYYY-MMDD-NN`. Assigned by the engine in the order
/// issues first opened within a session.
pub type IssueId = String;

/// Which rule in the catalogue fired, e.g. `dns.slow_resolver`. Rule ids are
/// stable strings because they appear in user rulesets and exported reports.
pub type RuleId = &'static str;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Medium => "med",
            Severity::High => "high",
            Severity::Critical => "crit",
        }
    }

    /// Long form for the report, where column width isn't a constraint.
    pub fn long_label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.long_label())
    }
}

/// What the issue is about. Drives drill-through (`t` trace, `p` packets) and
/// the scope line, and is what the suppression graph matches on when deciding
/// whether one issue is a consequence of another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Subject {
    /// The host itself — no narrower subject applies.
    Host,
    Resolver {
        addr: String,
    },
    Path {
        target: String,
    },
    Socket {
        local: String,
        remote: String,
    },
    Iface {
        name: String,
    },
    Process {
        name: String,
        pid: Option<u32>,
    },
}

impl Subject {
    /// One-line rendering used in issue titles and the report.
    pub fn label(&self) -> String {
        match self {
            Subject::Host => "host".to_string(),
            Subject::Resolver { addr } => addr.clone(),
            Subject::Path { target } => target.clone(),
            Subject::Socket { local, remote } => format!("{local} → {remote}"),
            Subject::Iface { name } => name.clone(),
            Subject::Process { name, pid } => match pid {
                Some(p) => format!("{name}[{p}]"),
                None => name.clone(),
            },
        }
    }

    /// Traceable subjects get a `t` key; the rest don't.
    pub fn trace_target(&self) -> Option<&str> {
        match self {
            Subject::Resolver { addr } => Some(addr),
            Subject::Path { target } => Some(target),
            Subject::Socket { remote, .. } => Some(remote),
            _ => None,
        }
    }
}

/// A measurement that justifies the issue. Carries the *numbers*, never a
/// sentence — sentences are rendered from these so screen and report agree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Metric name as the rest of netwatch knows it, e.g. `dns.rtt_p50`.
    pub metric: String,
    pub value: f64,
    /// Unit suffix for display: "ms", "%", "/min", "" …
    pub unit: String,
    /// Learned baseline for this metric on this subject, when one exists.
    pub baseline: Option<f64>,
    /// Standard deviation of the baseline. Present iff `baseline` is.
    pub sigma: Option<f64>,
    /// Seconds of data the value summarises.
    pub window_secs: u64,
    /// How many samples went into `value`.
    pub samples: u32,
}

impl Evidence {
    pub fn new(metric: impl Into<String>, value: f64, unit: impl Into<String>) -> Self {
        Self {
            metric: metric.into(),
            value,
            unit: unit.into(),
            baseline: None,
            sigma: None,
            window_secs: 0,
            samples: 0,
        }
    }

    pub fn with_baseline(mut self, baseline: f64, sigma: f64) -> Self {
        self.baseline = Some(baseline);
        self.sigma = Some(sigma);
        self
    }

    pub fn with_window(mut self, window_secs: u64, samples: u32) -> Self {
        self.window_secs = window_secs;
        self.samples = samples;
        self
    }

    /// How many σ above baseline the value sits. `None` without a baseline, or
    /// when σ is zero (a metric that has never varied can't be scored in σ).
    pub fn sigma_above(&self) -> Option<f64> {
        match (self.baseline, self.sigma) {
            (Some(b), Some(s)) if s > f64::EPSILON => Some((self.value - b) / s),
            _ => None,
        }
    }

    /// Multiple of baseline, e.g. 33.3 for 40ms against a 1.2ms baseline.
    /// This is the *only* place a "N×" figure is produced. Screen and report
    /// both call it, so they cannot print different multiples for one issue.
    pub fn multiple_of_baseline(&self) -> Option<f64> {
        match self.baseline {
            Some(b) if b.abs() > f64::EPSILON => Some(self.value / b),
            _ => None,
        }
    }

    /// `"33× baseline"` — rounded the way the UI shows it, with a shared
    /// rounding rule so 33.3 never renders as "33×" here and "33.3×" there.
    pub fn multiple_label(&self) -> Option<String> {
        self.multiple_of_baseline().map(|m| {
            if m >= 10.0 {
                format!("{}× baseline", m.round() as i64)
            } else {
                format!("{m:.1}× baseline")
            }
        })
    }

    /// `"40ms"` — value with its unit, at the precision the magnitude warrants.
    pub fn value_label(&self) -> String {
        format!("{}{}", round_for_display(self.value), self.unit)
    }

    /// `"baseline 1.2ms σ0.4"`, or `None` when the metric has no baseline yet.
    pub fn baseline_label(&self) -> Option<String> {
        let b = self.baseline?;
        match self.sigma {
            Some(s) => Some(format!(
                "baseline {}{} σ{}",
                round_for_display(b),
                self.unit,
                round_for_display(s)
            )),
            None => Some(format!("baseline {}{}", round_for_display(b), self.unit)),
        }
    }
}

/// Display rounding shared by every renderer: three significant-ish figures,
/// no trailing `.0`. Centralised so the same number never appears with two
/// different precisions on one screen.
pub fn round_for_display(v: f64) -> String {
    let a = v.abs();
    // Three-ish significant figures: whole numbers past 100 (184ms), one
    // decimal in the middle (1.2ms), two below one (0.42ms).
    let s = if a >= 100.0 {
        format!("{v:.0}")
    } else if a >= 1.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.2}")
    };
    // 40.0 → 40, 1.20 → 1.2
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

/// One discriminating test that ranks a cause. `passed: None` means the check
/// could not be run (no data, no capability) — which is different from failing
/// and must not count against the cause.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub passed: Option<bool>,
    /// Short factual detail, e.g. "alt resolver 1.1.1.1 answered in 1.4ms".
    pub detail: String,
    /// Relative importance within the cause. Defaults to 1.0.
    #[serde(default = "one")]
    pub weight: f64,
}

fn one() -> f64 {
    1.0
}

impl CheckResult {
    pub fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: Some(true),
            detail: detail.into(),
            weight: 1.0,
        }
    }

    pub fn fail(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: Some(false),
            detail: detail.into(),
            weight: 1.0,
        }
    }

    /// Check couldn't run. Neither evidence for nor against.
    pub fn skipped(name: impl Into<String>, why: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: None,
            detail: why.into(),
            weight: 1.0,
        }
    }

    pub fn weighted(mut self, weight: f64) -> Self {
        self.weight = weight;
        self
    }

    pub fn glyph(&self) -> &'static str {
        match self.passed {
            Some(true) => "✓",
            Some(false) => "✗",
            None => "·",
        }
    }
}

/// How well a cause's checks held up. Deliberately four buckets and not a
/// percentage: the underlying number is a weighted check-pass fraction, not a
/// calibrated probability, and printing "92%" invites people to read it as
/// one. Ranking still uses the continuous score; only the *display* is coarse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// No check for this cause could be run.
    Untested,
    Weak,
    Possible,
    Likely,
    Strong,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Untested => "untested",
            Confidence::Weak => "weak",
            Confidence::Possible => "possible",
            Confidence::Likely => "likely",
            Confidence::Strong => "strong",
        }
    }
}

/// A ranked explanation for an issue, with the checks that put it there.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cause {
    pub label: String,
    pub checks: Vec<CheckResult>,
}

impl Cause {
    pub fn new(label: impl Into<String>, checks: Vec<CheckResult>) -> Self {
        Self {
            label: label.into(),
            checks,
        }
    }

    /// Weighted fraction of *runnable* checks that passed, 0..=1.
    /// `None` when no check could be run.
    pub fn score(&self) -> Option<f64> {
        let mut total = 0.0;
        let mut passed = 0.0;
        for c in &self.checks {
            match c.passed {
                Some(true) => {
                    total += c.weight;
                    passed += c.weight;
                }
                Some(false) => total += c.weight,
                None => {}
            }
        }
        if total <= f64::EPSILON {
            None
        } else {
            Some(passed / total)
        }
    }

    pub fn confidence(&self) -> Confidence {
        match self.score() {
            None => Confidence::Untested,
            Some(s) if s >= 0.85 => Confidence::Strong,
            Some(s) if s >= 0.6 => Confidence::Likely,
            Some(s) if s >= 0.3 => Confidence::Possible,
            Some(_) => Confidence::Weak,
        }
    }

    /// `"3 of 4 checks"` — the honest denominator, excluding skipped checks.
    pub fn checks_label(&self) -> String {
        let run = self.checks.iter().filter(|c| c.passed.is_some()).count();
        let passed = self
            .checks
            .iter()
            .filter(|c| c.passed == Some(true))
            .count();
        let skipped = self.checks.len() - run;
        if skipped > 0 {
            format!("{passed} of {run} checks ({skipped} not run)")
        } else {
            format!("{passed} of {run} checks")
        }
    }
}

/// Privilege a remediation step needs before netwatch will offer to apply it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    None,
    Root,
    CapNetAdmin,
}

impl Capability {
    pub fn label(self) -> &'static str {
        match self {
            Capability::None => "no privileges",
            Capability::Root => "root",
            Capability::CapNetAdmin => "CAP_NET_ADMIN",
        }
    }
}

/// What netwatch would actually do for an `Apply` step. Anything that mutates
/// host state names the file it touches so the journal can back it up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// Rewrite the session resolver in /etc/resolv.conf. Reversible.
    SetResolver { addr: String },
    /// Persist the resolver through the system's resolver manager.
    /// Not reversible by netwatch — it's an instruct step for that reason.
    PersistResolver { addr: String },
    /// Re-run the diagnose pipeline (or one stage of it).
    RunTest { stage: String },
    /// Drop a socket. Reversible only in the sense that it's not persistent.
    KillSocket { local: String, remote: String },
    /// Keep the issue open and re-evaluate after `secs`.
    Watch { secs: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    /// netwatch performs it, key-bound.
    Apply,
    /// Exact command or setting for the operator to run.
    Instruct,
    /// What to send to whom, with artifacts attached.
    Escalate,
}

/// Outcome of an apply, recorded on the step so the report can state it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Applied {
    /// Applied at this local timestamp, with before/after for the report.
    Yes {
        at: String,
        before: String,
        after: String,
    },
    /// Deliberately not applied. Carries the reason, e.g. "needs root".
    No { reason: String },
    /// Applied and then reverted (by the user, on quit, or by reconciliation).
    Reverted { at: String, reason: String },
    /// A write was attempted but its completion or recording failed.
    RecoveryRequired {
        operation_id: String,
        reason: String,
        backup: String,
    },
}

impl Applied {
    /// Shared wording for persistent UI details, status, and reports.
    pub fn recovery_summary(&self) -> Option<String> {
        match self {
            Self::RecoveryRequired {
                operation_id,
                reason,
                backup,
            } => Some(format!(
                "recovery required · {operation_id}: {reason}; backup: {backup}"
            )),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    /// Hotkey when netwatch can apply it. `None` for instruct/escalate steps.
    pub key: Option<char>,
    pub text: String,
    /// Second line: exactly what netwatch would do, or the literal command.
    pub detail: String,
    pub kind: StepKind,
    pub action: Option<Action>,
    /// netwatch keeps a backup and can put it back.
    pub reversible: bool,
    pub requires: Capability,
    #[serde(default)]
    pub applied: Option<Applied>,
}

impl Step {
    pub fn instruct(text: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            key: None,
            text: text.into(),
            detail: detail.into(),
            kind: StepKind::Instruct,
            action: None,
            reversible: false,
            requires: Capability::None,
            applied: None,
        }
    }

    pub fn escalate(text: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind: StepKind::Escalate,
            ..Self::instruct(text, detail)
        }
    }

    pub fn apply(
        key: char,
        text: impl Into<String>,
        detail: impl Into<String>,
        action: Action,
        requires: Capability,
    ) -> Self {
        Self {
            key: Some(key),
            text: text.into(),
            detail: detail.into(),
            kind: StepKind::Apply,
            action: Some(action),
            reversible: true,
            requires,
            applied: None,
        }
    }

    /// Apply steps are hidden — not greyed — when the capability is missing.
    /// The reason still reaches the report, so a reader can tell the
    /// difference between "we didn't try" and "there was nothing to try".
    pub fn available(&self, have: Capability) -> bool {
        match self.requires {
            Capability::None => true,
            Capability::Root => have == Capability::Root,
            Capability::CapNetAdmin => matches!(have, Capability::Root | Capability::CapNetAdmin),
        }
    }
}

/// The testable condition that closes an issue. Mandatory: §4's rule is that a
/// remediation without a verify condition is an instruct step, not an apply
/// step, and [`crate::diagnose::rules`] enforces it in a test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verify {
    /// Metric to re-check — matches an [`Evidence::metric`].
    pub metric: String,
    pub predicate: Predicate,
    pub threshold: f64,
    pub unit: String,
    /// Condition must hold for this long before the issue auto-closes.
    pub hold_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    Below,
    Above,
}

impl Verify {
    pub fn below(metric: impl Into<String>, threshold: f64, unit: impl Into<String>) -> Self {
        Self {
            metric: metric.into(),
            predicate: Predicate::Below,
            threshold,
            unit: unit.into(),
            hold_secs: 60,
        }
    }

    pub fn above(metric: impl Into<String>, threshold: f64, unit: impl Into<String>) -> Self {
        Self {
            predicate: Predicate::Above,
            ..Self::below(metric, threshold, unit)
        }
    }

    pub fn holding_for(mut self, secs: u64) -> Self {
        self.hold_secs = secs;
        self
    }

    pub fn holds(&self, value: f64) -> bool {
        match self.predicate {
            Predicate::Below => value < self.threshold,
            Predicate::Above => value > self.threshold,
        }
    }

    /// `"dns.rtt_p50 < 5ms for 60s"`.
    pub fn label(&self) -> String {
        let op = match self.predicate {
            Predicate::Below => "<",
            Predicate::Above => ">",
        };
        format!(
            "{} {} {}{} for {}s",
            self.metric,
            op,
            round_for_display(self.threshold),
            self.unit,
            self.hold_secs
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum IssueState {
    Open,
    Acked,
    /// Muted until this local timestamp.
    Muted {
        until: String,
    },
    Resolved {
        at: String,
    },
    AutoClosed {
        at: String,
    },
}

impl IssueState {
    pub fn is_open(&self) -> bool {
        matches!(self, IssueState::Open | IssueState::Acked)
    }

    pub fn label(&self) -> &'static str {
        match self {
            IssueState::Open => "open",
            IssueState::Acked => "acked",
            IssueState::Muted { .. } => "muted",
            IssueState::Resolved { .. } => "resolved",
            IssueState::AutoClosed { .. } => "auto-closed",
        }
    }
}

/// What the issue touches. Rendered as the `scope` line.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Scope {
    pub processes: Vec<String>,
    pub destinations: u32,
    pub flows: u32,
    /// Free-text qualifier, e.g. "not affecting established flows".
    pub note: Option<String>,
}

impl Scope {
    /// `"all processes · 6 destinations · not affecting established flows"`.
    pub fn label(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.processes.is_empty() {
            parts.push("all processes".to_string());
        } else if self.processes.len() <= 3 {
            parts.push(self.processes.join(", "));
        } else {
            parts.push(format!("{} processes", self.processes.len()));
        }
        if self.destinations > 0 {
            parts.push(format!("{} destinations", self.destinations));
        }
        if self.flows > 0 {
            parts.push(format!("{} flows", self.flows));
        }
        if let Some(n) = &self.note {
            parts.push(n.clone());
        }
        parts.join(" · ")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Issue {
    pub id: IssueId,
    pub rule: String,
    pub severity: Severity,
    pub title: String,
    pub subject: Subject,
    /// Local timestamp of the first sample that violated the rule.
    pub since: String,
    pub last_seen: String,
    pub state: IssueState,
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub scope: Scope,
    pub causes: Vec<Cause>,
    pub remediation: Vec<Step>,
    pub verify: Verify,
    #[serde(default)]
    pub artifacts: Vec<String>,
    /// Issues suppressed by this one — consequences of the same root cause.
    /// They are reported *under* this issue, never as separate findings.
    #[serde(default)]
    pub consequences: Vec<IssueId>,
    /// Set when this issue is itself suppressed by another.
    #[serde(default)]
    pub suppressed_by: Option<IssueId>,
    /// Times this issue has reopened within the recurrence window. A flapping
    /// condition is one issue with a count, not N issues.
    #[serde(default)]
    pub recurrence: u32,
}

impl Issue {
    /// The evidence entry a rule considers primary — by convention the first.
    /// Titles and one-line summaries quote this one.
    pub fn headline(&self) -> Option<&Evidence> {
        self.evidence.first()
    }

    /// Highest-ranked cause. Causes are stored pre-sorted by the engine.
    pub fn top_cause(&self) -> Option<&Cause> {
        self.causes.first()
    }

    /// Sort causes best-first. Untestable causes sink below tested ones so a
    /// cause nothing could rule out never outranks one with passing checks.
    pub fn rank_causes(&mut self) {
        self.causes.sort_by(|a, b| {
            let sa = a.score().unwrap_or(-1.0);
            let sb = b.score().unwrap_or(-1.0);
            sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    /// One-line summary: severity, title, subject, and the headline number
    /// with its multiple of baseline. This is the string the toast shows, `y`
    /// copies, the verdict line renders and the report's summary quotes —
    /// one function, so all four agree by construction.
    pub fn summary_line(&self) -> String {
        let mut s = format!("{} {}", self.severity.long_label(), self.title);
        let subject = self.subject.label();
        if !subject.is_empty() && subject != "host" {
            s.push_str(&format!(" · {subject}"));
        }
        if let Some(e) = self.headline() {
            s.push_str(&format!(" · {}", e.value_label()));
            if let Some(m) = e.multiple_label() {
                s.push_str(&format!(" ({m})"));
            }
        }
        s.push_str(&format!(" · since {}", short_time(&self.since)));
        s
    }

    /// Steps netwatch can actually offer given the privileges it holds.
    pub fn offered_steps(&self, have: Capability) -> Vec<&Step> {
        self.remediation
            .iter()
            .filter(|s| s.kind != StepKind::Apply || s.available(have))
            .collect()
    }
}

/// `189` → `"3m 9s"`. One renderer, used by the tab and the report, because
/// the same evidence field showing as `189s` on screen and `3m` in the export
/// is exactly the sort of small disagreement this module exists to prevent.
pub fn format_duration(secs: u64) -> String {
    match (secs / 3600, (secs % 3600) / 60, secs % 60) {
        (0, 0, s) => format!("{s}s"),
        (0, m, 0) => format!("{m}m"),
        (0, m, s) => format!("{m}m {s}s"),
        (h, 0, _) => format!("{h}h"),
        (h, m, _) => format!("{h}h {m}m"),
    }
}

/// `"2026-09-03 06:48:10"` → `"06:48:10"`. Reports keep the full stamp; the
/// TUI has 80 columns and shows the time only.
pub fn short_time(ts: &str) -> &str {
    ts.split(' ').next_back().unwrap_or(ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_evidence() -> Evidence {
        // The exact numbers from the handover fixture: 40ms observed against a
        // 1.2ms baseline. The bundle's mockup called this "100×".
        Evidence::new("dns.rtt_p50", 40.0, "ms")
            .with_baseline(1.2, 0.4)
            .with_window(180, 38)
    }

    #[test]
    fn multiple_of_baseline_is_computed_not_asserted() {
        let e = dns_evidence();
        let m = e.multiple_of_baseline().unwrap();
        assert!(
            (m - 33.333).abs() < 0.01,
            "40/1.2 is 33.3×, not 100× — got {m}"
        );
        assert_eq!(e.multiple_label().unwrap(), "33× baseline");
    }

    #[test]
    fn sigma_above_matches_the_rule_threshold() {
        let e = dns_evidence();
        // (40 - 1.2) / 0.4 = 97σ. Far past the k=3 trigger.
        assert!(e.sigma_above().unwrap() > 3.0);
    }

    #[test]
    fn sigma_is_none_when_baseline_never_varied() {
        let e = Evidence::new("x", 5.0, "ms").with_baseline(1.0, 0.0);
        assert_eq!(e.sigma_above(), None, "zero σ must not divide by zero");
        // A multiple is still meaningful without variance.
        assert_eq!(e.multiple_of_baseline(), Some(5.0));
    }

    #[test]
    fn durations_render_the_same_everywhere() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(189), "3m 9s");
        assert_eq!(format_duration(180), "3m");
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(3900), "1h 5m");
    }

    #[test]
    fn display_rounding_is_stable() {
        assert_eq!(round_for_display(40.0), "40");
        assert_eq!(round_for_display(1.2), "1.2");
        assert_eq!(round_for_display(0.42), "0.42");
        assert_eq!(round_for_display(184.0), "184");
    }

    #[test]
    fn skipped_checks_do_not_count_against_a_cause() {
        let all_pass = Cause::new(
            "c",
            vec![
                CheckResult::pass("a", ""),
                CheckResult::pass("b", ""),
                CheckResult::skipped("c", "no data"),
            ],
        );
        assert_eq!(all_pass.score(), Some(1.0));
        assert_eq!(all_pass.confidence(), Confidence::Strong);
        assert_eq!(all_pass.checks_label(), "2 of 2 checks (1 not run)");
    }

    #[test]
    fn a_cause_with_no_runnable_checks_is_untested_not_certain() {
        let c = Cause::new("c", vec![CheckResult::skipped("a", "no data")]);
        assert_eq!(c.score(), None);
        assert_eq!(c.confidence(), Confidence::Untested);
    }

    #[test]
    fn untested_causes_rank_below_tested_ones() {
        let mut issue = test_issue();
        issue.causes = vec![
            Cause::new("untested", vec![CheckResult::skipped("a", "")]),
            Cause::new(
                "half",
                vec![CheckResult::pass("a", ""), CheckResult::fail("b", "")],
            ),
        ];
        issue.rank_causes();
        assert_eq!(issue.causes[0].label, "half");
    }

    #[test]
    fn verify_predicates() {
        let v = Verify::below("dns.rtt_p50", 5.0, "ms").holding_for(60);
        assert!(v.holds(1.4));
        assert!(!v.holds(40.0));
        assert_eq!(v.label(), "dns.rtt_p50 < 5ms for 60s");
    }

    #[test]
    fn capability_gating_hides_root_steps_for_unprivileged_runs() {
        let s = Step::apply(
            '1',
            "switch resolver",
            "",
            Action::SetResolver {
                addr: "1.1.1.1".into(),
            },
            Capability::Root,
        );
        assert!(!s.available(Capability::None));
        assert!(s.available(Capability::Root));
        // CAP_NET_ADMIN is satisfied by root but not the other way round.
        let n = Step::apply(
            '1',
            "x",
            "",
            Action::Watch { secs: 1 },
            Capability::CapNetAdmin,
        );
        assert!(n.available(Capability::Root));
        assert!(!n.available(Capability::None));
    }

    #[test]
    fn summary_line_quotes_the_computed_multiple() {
        let issue = test_issue();
        let s = issue.summary_line();
        assert!(s.contains("33× baseline"), "{s}");
        assert!(!s.contains("100×"), "{s}");
        assert!(s.contains("06:48:10"), "{s}");
    }

    fn test_issue() -> Issue {
        Issue {
            id: "2026-0903-01".into(),
            rule: "dns.slow_resolver".into(),
            severity: Severity::High,
            title: "slow dns resolver".into(),
            subject: Subject::Resolver {
                addr: "169.254.1.1".into(),
            },
            since: "2026-09-03 06:48:10".into(),
            last_seen: "2026-09-03 06:51:19".into(),
            state: IssueState::Open,
            evidence: vec![dns_evidence()],
            scope: Scope::default(),
            causes: vec![],
            remediation: vec![],
            verify: Verify::below("dns.rtt_p50", 5.0, "ms"),
            artifacts: vec![],
            consequences: vec![],
            suppressed_by: None,
            recurrence: 0,
        }
    }

    #[test]
    fn issue_json_round_trips() {
        let issue = test_issue();
        let json = serde_json::to_string(&issue).unwrap();
        let back: Issue = serde_json::from_str(&json).unwrap();
        assert_eq!(issue, back, "report.json must reload into the same object");
    }
}
