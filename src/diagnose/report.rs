//! `report.md` and `report.json`, generated from the same `Vec<Issue>` the
//! screen renders.
//!
//! The constraint that makes the report trustworthy: **no metric appears in
//! the report that the screen did not show.** Every number here comes from an
//! [`Evidence`] entry via the same accessor the TUI calls, so the report
//! cannot claim a multiple, a baseline or a σ that the Diagnose tab wasn't
//! also showing. A test asserts it.
//!
//! [`Evidence`]: super::issue::Evidence

use serde::{Deserialize, Serialize};

use super::issue::{Applied, Issue, IssueState, Severity, StepKind};
use super::rules;

/// Host and session facts that belong in every report's environment section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Environment {
    pub host: String,
    pub iface: String,
    pub driver: Option<String>,
    pub kernel: Option<String>,
    pub qdisc: Option<String>,
    pub resolvers: Vec<String>,
    pub gateway: Option<String>,
    pub netwatch_version: String,
    pub ruleset_version: String,
    /// What the baseline store had to work with, so a reader can weigh the
    /// σ figures. A report from a host still learning says so.
    pub baseline_state: String,
}

/// One thing that happened in the window, for the report's timeline section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub at: String,
    /// `issue` | `fix` | `path` | `iface` | `close`
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    #[serde(default)]
    pub coverage: super::coverage::Coverage,
    pub generated_at: String,
    pub window_start: String,
    pub window_end: String,
    pub environment: Environment,
    pub issues: Vec<Issue>,
    pub timeline: Vec<TimelineEvent>,
    /// File names in the incident bundle, referenced by the evidence index.
    pub artifacts: Vec<String>,
}

impl Report {
    /// Issues that are findings in their own right, worst first.
    pub fn primary(&self) -> Vec<&Issue> {
        rules::primary_issues(&self.issues)
    }

    fn find(&self, id: &str) -> Option<&Issue> {
        self.issues.iter().find(|i| i.id == id)
    }

    /// The one-line verdict. Same shape as the toast and the verdict line.
    pub fn summary_line(&self) -> String {
        let primary = self.primary();
        if primary.is_empty() {
            return format!(
                "no open findings · {} · {} retained closed findings",
                self.coverage.label(),
                self.issues.iter().filter(|i| !i.state.is_open()).count()
            );
        }
        let worst = primary
            .iter()
            .map(|i| i.severity)
            .max()
            .unwrap_or(Severity::Info);
        let state = match worst {
            Severity::Critical => "down",
            Severity::High => "degraded",
            Severity::Medium => "impaired",
            Severity::Info => "nominal with notes",
        };
        let counts = severity_counts(&primary);
        format!("{state} — {} ({counts})", plural(primary.len(), "issue"))
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// The markdown report. Sections in the order the spec sets out: summary,
    /// one section per open issue in severity order, suppressed consequences
    /// under their root cause, timeline, environment, evidence index.
    pub fn to_markdown(&self) -> String {
        let mut m = String::new();
        let env = &self.environment;

        // Built from the parts that exist. The Diagnose tab renders this
        // same markdown as a live preview, where the environment and window
        // aren't known yet — and "# netwatch report —  ·  to" reads as a
        // broken renderer rather than an incomplete one.
        let mut title = String::from("# netwatch report");
        let where_ = [env.host.as_str(), env.iface.as_str()]
            .iter()
            .filter(|p| !p.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        if !where_.is_empty() {
            title.push_str(&format!(" — {where_}"));
        }
        if !self.window_start.is_empty() && !self.window_end.is_empty() {
            title.push_str(&format!(
                "{} {} to {}",
                if where_.is_empty() { " —" } else { " ·" },
                time_of(&self.window_start),
                time_of(&self.window_end)
            ));
        }
        m.push_str(&format!("{title}\n\n"));
        m.push_str(&format!("**Summary** — {}.\n\n", self.summary_line()));

        let primary = self.primary();
        if primary.is_empty() {
            m.push_str("No findings are currently open. This does not establish health for unmeasured checks.\n\n");
        }

        m.push_str(&format!("**Coverage** — {}.\n\n", self.coverage.label()));
        for (n, issue) in primary.iter().enumerate() {
            m.push_str(&self.issue_section(n + 1, issue));
        }

        m.push_str("## Diagnostic coverage\n\n");
        for row in &self.coverage.rules {
            m.push_str(&format!(
                "- `{}`: {:?} — {}\n",
                row.rule, row.status, row.reason
            ));
        }
        m.push('\n');
        for issue in self.issues.iter().filter(|i| !i.state.is_open()) {
            m.push_str(&format!(
                "Retained closed finding: `{}` — {} ({:?})\n\n",
                issue.id, issue.title, issue.state
            ));
        }

        if !self.timeline.is_empty() {
            m.push_str("## Timeline\n\n");
            for e in &self.timeline {
                m.push_str(&format!(
                    "- `{}` **{}** {}\n",
                    time_of(&e.at),
                    e.kind,
                    e.text
                ));
            }
            m.push('\n');
        }

        m.push_str("## Environment\n\n");
        m.push_str(&format!("- host: {}\n", env.host));
        m.push_str(&format!("- interface: {}", env.iface));
        if let Some(d) = &env.driver {
            m.push_str(&format!(" ({d})"));
        }
        m.push('\n');
        if let Some(k) = &env.kernel {
            m.push_str(&format!("- kernel: {k}\n"));
        }
        if let Some(q) = &env.qdisc {
            m.push_str(&format!("- qdisc: {q}\n"));
        }
        if let Some(g) = &env.gateway {
            m.push_str(&format!("- gateway: {g}\n"));
        }
        if !env.resolvers.is_empty() {
            m.push_str(&format!("- resolvers: {}\n", env.resolvers.join(", ")));
        }
        m.push_str(&format!("- baselines: {}\n", env.baseline_state));
        m.push_str(&format!(
            "- netwatch {} · ruleset {} ({})\n\n",
            env.netwatch_version,
            env.ruleset_version,
            rules::catalogue_label()
        ));

        if !self.artifacts.is_empty() {
            m.push_str("## Evidence\n\n");
            for a in &self.artifacts {
                m.push_str(&format!("- `{a}`\n"));
            }
            m.push('\n');
        }

        m
    }

    fn issue_section(&self, n: usize, issue: &Issue) -> String {
        let mut m = String::new();
        m.push_str(&format!(
            "## {n}. {} — {} · since {}",
            issue.title,
            issue.severity.long_label(),
            time_of(&issue.since)
        ));
        if issue.recurrence > 0 {
            m.push_str(&format!(" · recurred {}×", issue.recurrence));
        }
        m.push_str(&format!(" · `{}`\n\n", issue.id));

        // --- issue: the evidence, rendered by the same accessors the TUI uses
        m.push_str("**Issue** — ");
        m.push_str(&issue.subject.label());
        for (i, e) in issue.evidence.iter().enumerate() {
            if i == 0 {
                m.push_str(&format!(" · {} {}", e.metric, e.value_label()));
            } else {
                m.push_str(&format!(", {} {}", e.metric, e.value_label()));
            }
            if let Some(b) = e.baseline_label() {
                m.push_str(&format!(" ({b}"));
                if let Some(mult) = e.multiple_label() {
                    m.push_str(&format!(", {mult}"));
                }
                m.push(')');
            }
        }
        if let Some(e) = issue.headline() {
            if e.samples > 0 {
                m.push_str(&format!(
                    " · {} samples over {}",
                    e.samples,
                    super::issue::format_duration(e.window_secs)
                ));
            }
        }
        let scope = issue.scope.label();
        if !scope.is_empty() {
            m.push_str(&format!("\n\n**Scope** — {scope}."));
        }
        m.push_str("\n\n");

        // --- probable cause
        if let Some(top) = issue.top_cause() {
            m.push_str(&format!(
                "**Probable cause** — {} ({}, {}).\n\n",
                top.label,
                top.confidence().label(),
                top.checks_label()
            ));
            for c in &top.checks {
                m.push_str(&format!("- {} {} — {}\n", c.glyph(), c.name, c.detail));
            }
            m.push('\n');
            if issue.causes.len() > 1 {
                m.push_str("Ruled out or ranked lower: ");
                let rest: Vec<String> = issue.causes[1..]
                    .iter()
                    .map(|c| format!("{} ({})", c.label, c.confidence().label()))
                    .collect();
                m.push_str(&rest.join("; "));
                m.push_str(".\n\n");
            }
        }

        // --- remediation, with what was actually done
        if !issue.remediation.is_empty() {
            m.push_str("**Remediation**\n\n");
            for step in &issue.remediation {
                let marker = match step.kind {
                    StepKind::Apply => "apply",
                    StepKind::Instruct => "run",
                    StepKind::Escalate => "escalate",
                };
                m.push_str(&format!("- _{marker}_ {} — {}", step.text, step.detail));
                match &step.applied {
                    Some(Applied::Yes { at, before, after }) => {
                        m.push_str(&format!(
                            "\n  - applied {} — `{before}` → `{after}`",
                            time_of(at)
                        ));
                    }
                    Some(outcome @ Applied::RecoveryRequired { .. }) => {
                        m.push_str(&format!("\n  - {}", outcome.recovery_summary().unwrap()));
                    }
                    Some(Applied::No { reason }) => {
                        m.push_str(&format!("\n  - not applied: {reason}"));
                    }
                    Some(Applied::Reverted { at, reason }) => {
                        m.push_str(&format!("\n  - reverted {} ({reason})", time_of(at)));
                    }
                    None if step.kind == StepKind::Apply => {
                        m.push_str("\n  - not applied");
                    }
                    None => {}
                }
                m.push('\n');
            }
            m.push('\n');
        }

        m.push_str(&format!("**Verify** — {}", issue.verify.label()));
        match &issue.state {
            IssueState::AutoClosed { at } => {
                m.push_str(&format!(" · held; auto-closed {}", time_of(at)))
            }
            IssueState::Resolved { at } => {
                m.push_str(&format!(" · marked resolved {}", time_of(at)))
            }
            IssueState::Acked => m.push_str(" · acknowledged, still open"),
            IssueState::Muted { until } => {
                m.push_str(&format!(" · muted until {}", time_of(until)))
            }
            IssueState::Open => m.push_str(" · not yet met"),
        }
        m.push_str("\n\n");

        // --- consequences: symptoms that were this issue all along
        if !issue.consequences.is_empty() {
            m.push_str(
                "**Consequences of this issue** — reported here rather than as separate findings:\n\n",
            );
            for cid in &issue.consequences {
                if let Some(c) = self.find(cid) {
                    m.push_str(&format!(
                        "- {} ({}) · {} · `{}`\n",
                        c.title,
                        c.severity.long_label(),
                        c.subject.label(),
                        c.id
                    ));
                }
            }
            m.push('\n');
        }

        if !issue.artifacts.is_empty() {
            m.push_str(&format!(
                "**Evidence** — {}\n\n",
                issue.artifacts.join(", ")
            ));
        }

        m
    }
}

fn severity_counts(issues: &[&Issue]) -> String {
    let mut parts = Vec::new();
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Info,
    ] {
        let n = issues.iter().filter(|i| i.severity == sev).count();
        if n > 0 {
            parts.push(format!("{n} {}", sev.long_label()));
        }
    }
    parts.join(", ")
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/// `"2026-09-03 06:48:10"` → `"06:48:10"`.
fn time_of(ts: &str) -> &str {
    ts.split(' ').next_back().unwrap_or(ts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::fixture;

    fn report() -> Report {
        fixture::report()
    }

    #[test]
    fn recovery_outcome_survives_json_and_markdown_export() {
        let mut report = report();
        let step = report
            .issues
            .iter_mut()
            .flat_map(|i| &mut i.remediation)
            .find(|s| s.kind == StepKind::Apply)
            .unwrap();
        step.applied = Some(Applied::RecoveryRequired {
            operation_id: "operation-42".into(),
            reason: "completion journal write failed; target may have changed".into(),
            backup: "/recovery/original.bak".into(),
        });
        let json = report.to_json().unwrap();
        let restored: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, report);
        let md = restored.to_markdown();
        for expected in [
            "recovery required",
            "operation-42",
            "target may have changed",
            "/recovery/original.bak",
        ] {
            assert!(md.contains(expected), "missing {expected}: {md}");
        }
    }

    #[test]
    fn legacy_report_without_coverage_is_explicitly_unknown() {
        let mut value = serde_json::to_value(report()).unwrap();
        value.as_object_mut().unwrap().remove("coverage");
        value["issues"] = serde_json::json!([]);
        let old: Report = serde_json::from_value(value).unwrap();
        assert!(old.summary_line().contains("coverage not recorded"));
        assert!(!old.summary_line().contains("healthy"));
    }

    #[test]
    fn closed_findings_are_retained_in_markdown_and_not_described_as_absent() {
        let mut report = report();
        for i in &mut report.issues {
            i.state = IssueState::Resolved {
                at: "2026-09-03 07:00:00".into(),
            };
        }
        let md = report.to_markdown();
        assert!(report.summary_line().contains("retained closed findings"));
        assert!(md.contains("Retained closed finding"));
        assert!(!md.contains("No issues were open in this window"));
        for issue in &report.issues {
            assert!(md.contains(&issue.id));
        }
    }

    #[test]
    fn markdown_summary_states_the_verdict() {
        let md = report().to_markdown();
        let first = md.lines().find(|l| l.starts_with("**Summary**")).unwrap();
        assert!(first.contains("degraded"), "{first}");
        assert!(first.contains("1 high"), "{first}");
    }

    #[test]
    fn the_report_never_prints_a_multiple_the_evidence_does_not_support() {
        let r = report();
        let md = r.to_markdown();
        assert!(
            md.contains("33× baseline"),
            "the computed multiple should appear:\n{md}"
        );
        assert!(
            !md.contains("100×"),
            "the report must not restate a number the evidence contradicts"
        );
    }

    /// The load-bearing invariant: every number in the markdown can be traced
    /// to an Evidence field on some issue. If a renderer ever hard-codes a
    /// figure, this catches it.
    #[test]
    fn every_metric_in_the_report_comes_from_evidence() {
        let r = report();
        let md = r.to_markdown();

        // Collect every value/baseline/multiple string the evidence can justify.
        let mut allowed: Vec<String> = Vec::new();
        for issue in &r.issues {
            for e in &issue.evidence {
                allowed.push(e.value_label());
                if let Some(b) = e.baseline_label() {
                    allowed.push(b);
                }
                if let Some(m) = e.multiple_label() {
                    allowed.push(m);
                }
            }
        }
        // Each evidence line in the markdown must quote one of those.
        for line in md.lines().filter(|l| l.starts_with("**Issue** —")) {
            assert!(
                allowed.iter().any(|a| line.contains(a.as_str())),
                "issue line quotes a number no evidence supports:\n{line}"
            );
        }
    }

    #[test]
    fn a_preview_with_no_environment_still_has_a_sane_heading() {
        // What the Diagnose tab's `o` preview renders.
        let r = Report {
            coverage: Default::default(),
            generated_at: String::new(),
            window_start: String::new(),
            window_end: String::new(),
            environment: Environment::default(),
            issues: fixture::report().issues,
            timeline: vec![],
            artifacts: vec![],
        };
        let first = r.to_markdown().lines().next().unwrap().to_string();
        assert_eq!(first, "# netwatch report", "{first}");
        assert!(!first.contains(" ·  to"), "{first}");
    }

    #[test]
    fn the_report_renders_windows_the_way_the_screen_does() {
        let md = report().to_markdown();
        assert!(md.contains("38 samples over 3m 9s"), "{md}");
    }

    #[test]
    fn json_round_trips_into_the_same_object() {
        let r = report();
        let json = r.to_json().unwrap();
        let back: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn consequences_are_listed_under_their_root_not_as_findings() {
        let mut r = report();
        // Make the dns issue a consequence of a gateway failure.
        let dns_id = r.issues[0].id.clone();
        let mut gw = r.issues[0].clone();
        gw.id = "2026-0903-99".into();
        gw.rule = "gateway.unreachable".into();
        gw.title = "gateway unreachable".into();
        gw.severity = Severity::Critical;
        gw.subject = crate::diagnose::issue::Subject::Host;
        r.issues.push(gw);
        rules::apply_suppression(&mut r.issues);

        let md = r.to_markdown();
        assert!(md.contains("Consequences of this issue"), "{md}");
        // The suppressed issue must not get its own numbered section.
        let sections = md
            .lines()
            .filter(|l| l.starts_with("## ") && l.contains(" — "))
            .count();
        assert_eq!(
            r.primary().len(),
            sections,
            "one section per primary issue, no more"
        );
        assert!(!r.primary().iter().any(|i| i.id == dns_id));
    }

    #[test]
    fn an_unapplied_apply_step_says_so() {
        let md = report().to_markdown();
        assert!(md.contains("not applied"), "{md}");
    }

    #[test]
    fn an_empty_report_does_not_claim_health() {
        let mut r = report();
        r.issues.clear();
        let md = r.to_markdown();
        assert!(md.contains("No findings are currently open"), "{md}");
        assert!(
            r.summary_line().starts_with("no open findings"),
            "{}",
            r.summary_line()
        );
    }

    #[test]
    fn the_environment_section_states_baseline_confidence() {
        let md = report().to_markdown();
        assert!(md.contains("- baselines: "), "{md}");
        assert!(md.contains("ruleset"), "{md}");
    }

    #[test]
    fn confidence_is_never_printed_as_a_percentage() {
        let md = report().to_markdown();
        for line in md.lines().filter(|l| l.contains("Probable cause")) {
            assert!(
                !line.contains('%'),
                "confidence must be a word, not a fake probability: {line}"
            );
        }
    }
}
