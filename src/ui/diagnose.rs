//! The Diagnose tab: issues → probable cause → remediation → report.
//!
//! Rendering takes a [`View`] rather than the `App`, so the whole screen can
//! be drawn from a fixture with no capture running. That is what makes the
//! demo and the snapshot tests possible, and it means the screenshots in the
//! docs are produced by the same code path a user sees.
//!
//! Colour vocabulary, applied strictly here and nowhere overloaded:
//! green/amber/red mean *status only*; blue is a key hint; selection is an
//! inverted row. Nothing is green unless it is healthy.

use ratatui::{
    prelude::*,
    widgets::{Paragraph, Wrap},
};

use crate::diagnose::baseline::BaselineStore;
use crate::diagnose::engine::{Engine, Verdict};
use crate::diagnose::issue::{Applied, Capability, Issue, IssueState, Severity, Step, StepKind};
use crate::diagnose::rules;
use crate::theme::Theme;
use crate::ui::widgets;

/// Everything the tab needs to draw itself.
pub struct View<'a> {
    pub engine: &'a Engine,
    pub baselines: &'a BaselineStore,
    pub theme: &'a Theme,
    /// Index into [`Engine::primary`].
    pub selected: usize,
    pub show_report: bool,
    /// Privileges netwatch holds, so unavailable apply steps are hidden
    /// rather than dangled.
    pub capability: Capability,
    /// Optional AI commentary. `None` when the feature is switched off;
    /// `Some` whenever it is on, *including* while it is failing — see [`Ai`].
    pub ai: Option<Ai>,
    /// Where the model is configured to live, for the failure message.
    pub endpoint: String,
    /// Transient status line (export path, applied confirmation, reconciliation).
    pub status: Option<&'a str>,
    /// Set when the engine is replaying a recorded scenario rather than
    /// watching the network. Rendered on every frame and not suppressible —
    /// a demo a viewer can mistake for live measurement is worse than none.
    pub demo_banner: Option<String>,
}

/// The AI commentary block's state.
///
/// Carries the collector's status, not just its output, because those are
/// different things and only one of them was being shown. When the Insights
/// tab folded into Diagnose, the narrative came with it and the status did
/// not — so a user with the feature enabled and no model running got total
/// silence: no paragraph, no error, no hint that anything had been attempted.
/// A feature that fails invisibly is worse than one that is off.
pub struct Ai {
    pub status: crate::collectors::insights::InsightsStatus,
    pub narrative: Option<String>,
}

impl Ai {
    /// The line shown when there is no narrative to show, or above one that
    /// is stale. Says what the model is doing and, when it has gone wrong,
    /// what to do about it.
    pub fn status_line(&self, endpoint: &str) -> String {
        use crate::collectors::insights::InsightsStatus as S;
        match &self.status {
            S::Idle => "waiting for the first analysis".to_string(),
            S::Analyzing => "analysing…".to_string(),
            S::Available => "commentary on the findings above, not a source of facts".to_string(),
            S::OllamaUnavailable => format!(
                "no model answering at {} — start ollama, or switch this off in settings (,)",
                crate::collectors::insights::resolve_endpoint(endpoint)
            ),
            S::Error(e) => format!("model error: {e}"),
        }
    }

    /// Whether the block is reporting a problem rather than a result.
    pub fn is_failing(&self) -> bool {
        use crate::collectors::insights::InsightsStatus as S;
        matches!(self.status, S::OllamaUnavailable | S::Error(_))
    }
}

impl<'a> View<'a> {
    /// The issue the cursor is on.
    pub fn current(&self) -> Option<&'a Issue> {
        let primary = self.engine.primary();
        primary
            .get(self.selected.min(primary.len().saturating_sub(1)))
            .copied()
    }
}

pub fn render(f: &mut Frame, app: &crate::app::App, area: Rect) {
    // Present whenever the feature is enabled — a collector that exists but
    // cannot reach a model still has something to tell the user.
    let ai = app.insights_collector.as_ref().map(|c| Ai {
        status: (*c.get_status()).clone(),
        narrative: c.latest_narrative(),
    });
    let view = View {
        engine: &app.diagnose.engine,
        baselines: &app.diagnose.baselines,
        theme: &app.theme,
        selected: app.diagnose.selected,
        show_report: app.diagnose.show_report,
        capability: app.diagnose.capability,
        ai,
        endpoint: app.user_config.insights_endpoint.clone(),
        status: app.diagnose.status.as_deref(),
        demo_banner: app.diagnose.demo.as_ref().map(|d| d.banner()),
    };
    // The header's verdict row is suppressed here: this tab *is* the verdict,
    // and the body renders it in full a line below. Two copies of the same
    // sentence, stacked, reads as a rendering bug.
    crate::ui::widgets::render_header_without_verdict(f, app, chunk_header(area));
    render_body(f, &view, chunk_body(area));
    crate::ui::widgets::render_footer(f, app, chunk_footer(area), footer_hints(&view));
}

fn chunk_header(area: Rect) -> Rect {
    Rect {
        height: 3.min(area.height),
        ..area
    }
}

fn chunk_body(area: Rect) -> Rect {
    let top = 3.min(area.height);
    let bottom = 3.min(area.height.saturating_sub(top));
    Rect {
        y: area.y + top,
        height: area.height.saturating_sub(top + bottom),
        ..area
    }
}

fn chunk_footer(area: Rect) -> Rect {
    let h = 3.min(area.height);
    Rect {
        y: area.y + area.height - h,
        height: h,
        ..area
    }
}

pub fn footer_hints(view: &View) -> Vec<crate::ui::widgets::Hint> {
    use crate::ui::widgets::hint;
    let mut hints = vec![hint("↑↓", "issue")];
    if view
        .current()
        .map(|i| has_applicable_step(i, view.capability))
        .unwrap_or(false)
    {
        hints.push(hint("↵", "apply fix"));
    }
    hints.push(hint("a", "ack"));
    hints.push(hint("m", "mute"));
    // The same words the report panel puts on this key. Two labels for one
    // key is the defect the footer's deduplication exists to prevent; it
    // catches a key bound twice, not a key named twice.
    hints.push(hint(
        "o",
        if view.show_report {
            "back to issues"
        } else {
            "report"
        },
    ));
    hints.push(hint("e", "export report"));
    hints.push(hint("y", "copy summary"));
    hints
}

/// Whether `↵` would do anything on this issue.
///
/// A step netwatch has already run is not applicable — the screen shows
/// `applied 06:51:56 · 169.254.1.1 → 192.168.8.1` right next to a footer still
/// offering to apply it, which is the same defect as a key hint for a key that
/// does nothing. A step that was applied and then reverted is applicable
/// again.
fn has_applicable_step(issue: &Issue, cap: Capability) -> bool {
    issue.remediation.iter().any(|s| {
        s.kind == StepKind::Apply
            && s.available(cap)
            && !matches!(
                s.applied,
                Some(Applied::Yes { .. }) | Some(Applied::No { .. })
            )
    })
}

/// Draw everything between the header and the footer.
pub fn render_body(f: &mut Frame, view: &View, area: Rect) {
    let status_rows = if view.status.is_some() { 1 } else { 0 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),           // verdict line
            Constraint::Length(3),           // engine status strip
            Constraint::Min(6),              // issues + detail, or the report
            Constraint::Length(status_rows), // transient status
        ])
        .split(area);

    render_verdict(f, view, chunks[0]);
    render_engine_strip(f, view, chunks[1]);
    // `o` swaps the working view for the whole report rather than opening a
    // nine-row slot under it. The preview already fills whatever the detail
    // pane leaves, so a toggle that merely revealed it would be showing the
    // same thing twice; what it is for is reading the report at length.
    if view.show_report {
        render_report_preview(f, view, chunks[2]);
    } else {
        render_main(f, view, chunks[2]);
    }
    if let Some(s) = view.status {
        render_status(f, view, s, chunks[3]);
    }
}

// ─────────────────────────────────────────────────── verdict

fn severity_color(sev: Severity, t: &Theme) -> Color {
    match sev {
        Severity::Critical | Severity::High => t.status_error,
        Severity::Medium => t.status_warn,
        Severity::Info => t.status_info,
    }
}

fn render_verdict(f: &mut Frame, view: &View, area: Rect) {
    let t = view.theme;
    let verdict = view.engine.verdict(view.baselines);

    let spans: Vec<Span> = match &verdict {
        Verdict::Clear => vec![
            Span::styled("● ", Style::default().fg(t.status_good)),
            Span::styled(
                "no issues open · baselines ready",
                Style::default().fg(t.text_muted),
            ),
        ],
        // Not a health claim. A host that hasn't learned its network yet says
        // so, rather than rendering the reassuring green it hasn't earned.
        Verdict::Learning { detail } => vec![
            Span::styled("◌ ", Style::default().fg(t.text_muted)),
            Span::styled(
                format!("no issues detected · {detail}"),
                Style::default().fg(t.text_muted),
            ),
        ],
        Verdict::Issues {
            severity,
            count,
            headline,
            ..
        } => {
            let c = severity_color(*severity, t);
            vec![
                Span::styled("▌ ", Style::default().fg(c).bold()),
                Span::styled(
                    format!(
                        "{} ",
                        if *count == 1 {
                            "1 issue".into()
                        } else {
                            format!("{count} issues")
                        }
                    ),
                    Style::default().fg(c).bold(),
                ),
                Span::styled("· ", Style::default().fg(t.separator)),
                Span::styled(headline.clone(), Style::default().fg(t.text_primary)),
            ]
        }
    };

    f.render_widget(Paragraph::new(Line::from(spans)), inset(area));
}

fn inset(area: Rect) -> Rect {
    Rect {
        x: area.x + 1,
        width: area.width.saturating_sub(2),
        ..area
    }
}

// ────────────────────────────────────────────── engine strip

/// What the engine is running on. This replaces the mockup's pipeline strip
/// with something netwatch can actually stand behind: which detectors have
/// inputs, how far along the baselines are, and how much of the ruleset is
/// live. A user who sees no issues deserves to know whether that means
/// "healthy" or "not looking yet".
fn render_engine_strip(f: &mut Frame, view: &View, area: Rect) {
    let t = view.theme;
    let readiness = view.baselines.overall_readiness();

    // In demo mode the strip leads with what the data is, before anything
    // about what it says. Inverted, not merely coloured, so it survives a
    // palette-deferring theme and a screenshot at any size.
    if let Some(banner) = &view.demo_banner {
        let block = widgets::panel_block(t).border_style(Style::default().fg(t.status_warn));
        let line = Line::from(vec![
            Span::styled(
                format!(" {banner} "),
                Style::default().fg(t.text_inverse).bg(t.status_warn).bold(),
            ),
            Span::styled(
                format!("  ruleset {}", rules::catalogue_label()),
                Style::default().fg(t.text_muted),
            ),
        ]);
        f.render_widget(Paragraph::new(line).block(block), area);
        return;
    }

    let mut spans = vec![
        Span::styled("baselines ", Style::default().fg(t.text_muted)),
        Span::styled(
            readiness.label(),
            Style::default().fg(if readiness.is_ready() {
                t.status_good
            } else {
                t.text_secondary
            }),
        ),
        Span::styled("  network ", Style::default().fg(t.text_muted)),
        Span::styled(
            view.baselines.fingerprint().label(),
            Style::default().fg(t.text_secondary),
        ),
    ];
    if view.baselines.switched_network() {
        spans.push(Span::styled(
            "  (changed — relearning)",
            Style::default().fg(t.status_warn),
        ));
    }
    spans.push(Span::styled(
        "  ruleset ",
        Style::default().fg(t.text_muted),
    ));
    spans.push(Span::styled(
        rules::catalogue_label(),
        Style::default().fg(t.text_secondary),
    ));

    let block = widgets::panel_block(t).title(Span::styled(
        " engine ",
        Style::default().fg(t.text_secondary),
    ));
    f.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

// ──────────────────────────────────────────── issues + detail

fn render_main(f: &mut Frame, view: &View, area: Rect) {
    // Panels size to content in both directions. The list takes the width its
    // widest row actually needs (capped at 40% so the detail pane always has
    // room) and the height its rows need; whatever is left goes to something
    // useful rather than to an empty box. A list panel that is 90% blank is
    // the most common way a TUI wastes a screen.
    let issues = view.engine.primary();
    // The 40% cap can fall below the 28-column floor on a narrow terminal, so
    // the cap wins and `clamp` is not used — `clamp(28, 24)` panics.
    let cap = ((area.width as usize * 2) / 5).max(1);
    let widest = issues
        .iter()
        .map(issue_row_width)
        .max()
        .unwrap_or(28)
        .max(28)
        .min(cap) as u16;

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(widest + 4), Constraint::Min(30)])
        .split(area);

    // Both panels are sized to their own content, and whatever is left over
    // stays empty rather than being padded into one of them. A list panel
    // stretched to fill a column is the layout bug the v0.29 review found on
    // four tabs at once.
    let chrono_rows = chronology_height(view);
    let catalogue_rows = explainer_height();
    let list_needed = (issues.len().max(1) * ROWS_PER_ISSUE) as u16 + 2;
    let list_height = list_needed.min(
        area.height
            .saturating_sub((chrono_rows + catalogue_rows).min(area.height)),
    );

    // The catalogue anchors to the bottom of the column. Every panel is still
    // sized to its own content — the slack just sits between two boxes instead
    // of trailing off the last one, which reads as spacing rather than as a
    // column that ran out.
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(list_height),
            Constraint::Length(chrono_rows),
            Constraint::Min(0),
            Constraint::Length(catalogue_rows),
        ])
        .split(columns[0]);

    render_issue_list(f, view, &issues, left[0]);
    if left[1].height >= MIN_CHRONOLOGY_ROWS {
        render_chronology(f, view, left[1]);
    }
    if left[3].height >= MIN_EXPLAINER_ROWS {
        render_explainer(f, view, left[3]);
    }

    // The detail pane takes the rows it needs; the report preview takes the
    // rest. It is generated from the same `Vec<Issue>` the pane above it is
    // reading, so the filler is the screen's own conclusions rather than
    // padding — and there is always more of it than there is room.
    let used = render_detail(f, view, columns[1]);
    let rest = Rect {
        y: columns[1].y + used,
        height: columns[1].height.saturating_sub(used),
        ..columns[1]
    };
    if rest.height >= MIN_REPORT_ROWS {
        render_report_preview(f, view, rest);
    }
}

const ROWS_PER_ISSUE: usize = 3;
/// Below this the catalogue cannot say anything useful, so it is not drawn.
const MIN_EXPLAINER_ROWS: u16 = 6;
/// Two borders and a row: below this the chronology has nowhere to draw.
const MIN_CHRONOLOGY_ROWS: u16 = 4;
/// Below this the report preview shows a heading and nothing under it, which
/// is worse than leaving the space alone.
const MIN_REPORT_ROWS: u16 = 5;

/// Rows the catalogue panel needs: one per active category, the `?` line, and
/// the two borders. Derived from the catalogue so adding a category cannot
/// silently clip the panel.
fn explainer_height() -> u16 {
    let mut categories: Vec<&str> = rules::CATALOGUE
        .iter()
        .filter(|r| r.status.is_active())
        .map(|r| r.category)
        .collect();
    categories.dedup();
    categories.len() as u16 + 3
}

/// Width the widest row of an issue actually needs, so the column is sized to
/// its content instead of to a guess.
fn issue_row_width(i: &&Issue) -> usize {
    // +1 throughout for the selection rail in column zero.
    let title = i.title.len() + 7;
    let mut value = i.subject.label().len() + 6;
    if let Some(e) = i.headline() {
        value += e.value_label().len() + 3;
        if let Some(m) = e.multiple_label() {
            value += m.len() + 3;
        }
    }
    title.max(value)
}

/// What the engine is looking for, in the space the issue list doesn't need.
///
/// A user staring at an empty or short list deserves to know what netwatch
/// would have caught. One line per category — the count, then the rule names
/// in that category — derived from the catalogue so it cannot drift from what
/// actually runs.
///
/// It used to print every rule's full plain-English trigger. In a column
/// sized to the issue list that meant twenty-five lines, every one of them
/// ending in `…`, which is a worse answer than a shorter one: the reader
/// learns nothing from a truncated sentence and the panel outgrew the issues
/// it sits beneath. The full triggers live behind `?`, where there is width
/// for them.
fn render_explainer(f: &mut Frame, view: &View, area: Rect) {
    let t = view.theme;

    let mut categories: Vec<&str> = rules::CATALOGUE
        .iter()
        .filter(|r| r.status.is_active())
        .map(|r| r.category)
        .collect();
    categories.dedup();

    // `dns` + count + two spaces of gutter, sized to the widest category so
    // the name column lines up without a hardcoded width.
    let label_w = categories.iter().map(|c| c.len()).max().unwrap_or(4);
    let inner = area.width.saturating_sub(2) as usize;

    let mut lines: Vec<Line> = Vec::new();
    for category in categories {
        let rules_in: Vec<&rules::Rule> = rules::CATALOGUE
            .iter()
            .filter(|r| r.category == category && r.status.is_active())
            .collect();
        if rules_in.is_empty() {
            continue;
        }
        // The rule id minus its category prefix: `dns.slow_resolver` is
        // already under the `dns` label, so repeating it wastes the width
        // this panel is short of.
        let names: Vec<&str> = rules_in
            .iter()
            .map(|r| r.id.split_once('.').map(|(_, n)| n).unwrap_or(r.id))
            .collect();
        let count = rules_in.len().to_string();
        // Leading space + category + space + count + two-space gutter.
        let prefix_w = 1 + label_w + 1 + count.len() + 2;
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {category:<label_w$} "),
                Style::default().fg(t.text_secondary),
            ),
            Span::styled(count, Style::default().fg(t.text_muted)),
            Span::styled(
                format!(
                    "  {}",
                    ellipsise(&names.join(" · "), inner.saturating_sub(prefix_w))
                ),
                Style::default().fg(t.text_muted),
            ),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled(" ?", Style::default().fg(t.key_hint).bold()),
        Span::styled(
            " every rule and what triggers it",
            Style::default().fg(t.text_muted),
        ),
    ]));

    let block = widgets::Panel::new("watching for")
        .meta(rules::catalogue_label())
        .fit(area.width)
        .block(t);
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Every tracked issue in the window, oldest first.
///
/// The issue list answers "what is wrong"; this answers "in what order did it
/// happen", which is the question the whole screen exists to settle. The
/// reroute at 06:44 preceded the resolver slowdown at 06:48 — that ordering is
/// the correlation a reader has to see to believe the ranking, and reading it
/// off three separate `since` lines is work the screen should have done.
///
/// It also includes issues that are no longer open: suppressed consequences,
/// and anything the engine has closed. The close is the payoff of a
/// remediation, and an incident log that drops it stops one beat early.
fn render_chronology(f: &mut Frame, view: &View, area: Rect) {
    let t = view.theme;

    let mut tracked: Vec<&Issue> = view.engine.issues().iter().collect();
    tracked.sort_by(|a, b| a.since.cmp(&b.since));

    let selected_id = view.current().map(|i| i.id.clone());
    let inner = area.width.saturating_sub(2) as usize;

    let mut lines: Vec<Line> = Vec::new();
    for issue in tracked {
        let is_selected = selected_id.as_deref() == Some(issue.id.as_str());
        let open = issue.state.is_open();

        // A closed issue keeps its place in the order but stops shouting: the
        // severity colour is what "still wrong" looks like.
        let (marker, marker_style) = if !open {
            ("✓", Style::default().fg(t.status_good))
        } else if issue.suppressed_by.is_some() {
            ("└", Style::default().fg(t.text_muted))
        } else {
            ("▪", Style::default().fg(severity_color(issue.severity, t)))
        };

        let title_style = if !open {
            Style::default().fg(t.text_muted)
        } else if is_selected {
            Style::default().fg(t.text_primary).bold()
        } else {
            Style::default().fg(t.text_secondary)
        };

        // `since` is a full `%Y-%m-%d %H:%M:%S`; the date is the same for
        // every row in a window and the seconds are in the detail pane, so
        // the column carries `06:48` and spends the rest on the title.
        let stamp: String = crate::diagnose::issue::short_time(&issue.since)
            .chars()
            .take(5)
            .collect();
        let used = 1 + stamp.chars().count() + 2 + 2;
        let mut spans = vec![
            Span::styled(
                if is_selected { "▌" } else { " " }.to_string(),
                Style::default().fg(if is_selected {
                    severity_color(issue.severity, t)
                } else {
                    t.bg
                }),
            ),
            Span::styled(format!("{stamp}  "), Style::default().fg(t.text_muted)),
            Span::styled(format!("{marker} "), marker_style),
            Span::styled(
                ellipsise(&issue.title, inner.saturating_sub(used)),
                title_style,
            ),
        ];
        if !open {
            let closed = format!("  {}", issue.state.label());
            if used + issue.title.chars().count() + closed.chars().count() <= inner {
                spans.push(Span::styled(closed, Style::default().fg(t.status_good)));
            }
        }
        lines.push(Line::from(spans));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " nothing tracked yet",
            Style::default().fg(t.text_muted),
        )));
    }

    let block = widgets::Panel::new("chronology")
        .meta(format!("{} tracked", view.engine.issues().len()))
        .fit(area.width)
        .block(t);
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Rows the chronology needs: one per tracked issue, plus borders.
fn chronology_height(view: &View) -> u16 {
    view.engine.issues().len().max(1) as u16 + 2
}

fn render_issue_list(f: &mut Frame, view: &View, issues: &[&Issue], area: Rect) {
    let t = view.theme;
    let mut lines: Vec<Line> = Vec::new();

    if issues.is_empty() {
        lines.push(Line::from(Span::styled(
            "nothing open",
            Style::default().fg(t.text_muted),
        )));
    }

    for (n, issue) in issues.iter().enumerate() {
        let selected = n == view.selected.min(issues.len().saturating_sub(1));
        let sev_color = severity_color(issue.severity, t);
        // Selection is a rail down the left edge and bolder text, not a
        // background fill. `selection_bg` is ANSI 8 in the palette-deferring
        // theme, and what a terminal renders for ANSI 8 is anyone's guess —
        // several map it to a mid blue that swallows the severity colours
        // sitting on top of it, leaving the selected row the one row nobody
        // can read. A rail costs one column and works in every palette.
        let rail = |c: Color| {
            Span::styled(
                if selected { "▌" } else { " " }.to_string(),
                Style::default().fg(c),
            )
        };
        let title_style = if selected {
            Style::default().fg(t.text_primary).bold()
        } else {
            Style::default().fg(t.text_primary)
        };

        let mut head = vec![
            rail(sev_color),
            Span::styled(
                format!("{:<4} ", issue.severity.label()),
                Style::default().fg(sev_color).bold(),
            ),
            Span::styled(issue.title.clone(), title_style),
        ];
        if issue.recurrence > 0 {
            head.push(Span::styled(
                format!(" ×{}", issue.recurrence + 1),
                Style::default().fg(t.status_warn),
            ));
        }
        if !matches!(issue.state, IssueState::Open) {
            head.push(Span::styled(
                format!(" [{}]", issue.state.label()),
                Style::default().fg(t.text_muted),
            ));
        }
        lines.push(Line::from(head));

        // Second row: the subject and the headline number, both from evidence.
        let mut detail = vec![
            rail(sev_color),
            Span::styled(
                format!("     {}", issue.subject.label()),
                Style::default().fg(t.text_secondary),
            ),
        ];
        if let Some(e) = issue.headline() {
            detail.push(Span::styled(
                format!(" · {}", e.value_label()),
                Style::default().fg(t.text_primary),
            ));
            if let Some(m) = e.multiple_label() {
                detail.push(Span::styled(
                    format!(" · {m}"),
                    Style::default().fg(sev_color),
                ));
            }
        }
        lines.push(Line::from(detail));

        lines.push(Line::from(vec![
            rail(sev_color),
            Span::styled(
                format!(
                    "     since {}",
                    crate::diagnose::issue::short_time(&issue.since)
                ),
                Style::default().fg(t.text_muted),
            ),
        ]));
    }

    let block = widgets::Panel::new("issues")
        .meta_styled(vec![Span::raw(match issues.len() {
            0 => "nothing open".to_string(),
            1 => "1 open".to_string(),
            n => format!("{n} open"),
        })])
        .fit(area.width)
        .block(t);
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Draw the detail pane and return the rows it used.
///
/// The caller needs the height back: the pane is content-sized, and the space
/// it does not need goes to the report preview rather than staying blank.
fn render_detail(f: &mut Frame, view: &View, area: Rect) -> u16 {
    let t = view.theme;
    let Some(issue) = view.current() else {
        let height = 4.min(area.height);
        let block = widgets::Panel::new("detail").block(t);
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "No open issues. netwatch keeps watching; the verdict line above says what it is basing that on.",
                Style::default().fg(t.text_muted),
            )))
            .wrap(Wrap { trim: true })
            .block(block),
            Rect { height, ..area },
        );
        return height;
    };

    let mut lines: Vec<Line> = Vec::new();

    // ── issue ────────────────────────────────────────────────
    lines.push(section(t, "issue"));
    let mut ev_line = vec![Span::styled(
        issue.subject.label(),
        Style::default().fg(t.text_primary).bold(),
    )];
    for e in &issue.evidence {
        ev_line.push(Span::styled(
            format!(" · {} {}", e.metric, e.value_label()),
            Style::default().fg(t.text_primary),
        ));
        if let Some(b) = e.baseline_label() {
            ev_line.push(Span::styled(
                format!(" ({b}"),
                Style::default().fg(t.text_muted),
            ));
            if let Some(m) = e.multiple_label() {
                ev_line.push(Span::styled(
                    format!(", {m}"),
                    Style::default().fg(severity_color(issue.severity, t)),
                ));
            }
            ev_line.push(Span::styled(")", Style::default().fg(t.text_muted)));
        }
    }
    lines.push(Line::from(ev_line));

    if let Some(e) = issue.headline() {
        if e.samples > 0 {
            lines.push(Line::from(Span::styled(
                format!(
                    "  {} over {} · since {} · {}",
                    plural(e.samples as usize, "sample"),
                    crate::diagnose::issue::format_duration(e.window_secs),
                    crate::diagnose::issue::short_time(&issue.since),
                    issue.state.label()
                ),
                Style::default().fg(t.text_muted),
            )));
        }
    }
    let scope = issue.scope.label();
    if !scope.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("  scope  {scope}"),
            Style::default().fg(t.text_secondary),
        )));
    }
    lines.push(Line::from(""));

    // ── probable cause ───────────────────────────────────────
    if !issue.causes.is_empty() {
        lines.push(section(t, "probable cause"));
        for (n, cause) in issue.causes.iter().enumerate() {
            let strong = n == 0;
            lines.push(Line::from(vec![
                Span::styled(format!("{}. ", n + 1), Style::default().fg(t.text_muted)),
                Span::styled(
                    cause.label.clone(),
                    if strong {
                        Style::default().fg(t.text_primary).bold()
                    } else {
                        Style::default().fg(t.text_secondary)
                    },
                ),
                // A word, never a percentage — the underlying score is a
                // check-pass fraction, not a calibrated probability.
                Span::styled(
                    format!(
                        "  {} · {}",
                        cause.confidence().label(),
                        cause.checks_label()
                    ),
                    Style::default().fg(t.text_muted),
                ),
            ]));
            if strong {
                for c in &cause.checks {
                    let color = match c.passed {
                        Some(true) => t.status_good,
                        Some(false) => t.status_error,
                        None => t.text_muted,
                    };
                    lines.push(Line::from(vec![
                        Span::styled(format!("   {} ", c.glyph()), Style::default().fg(color)),
                        Span::styled(c.name.clone(), Style::default().fg(t.text_secondary)),
                        Span::styled(
                            format!(" — {}", c.detail),
                            Style::default().fg(t.text_muted),
                        ),
                    ]));
                }
            }
        }
        lines.push(Line::from(""));
    }

    // ── remediation ──────────────────────────────────────────
    let steps: Vec<&Step> = issue.offered_steps(view.capability);
    if !steps.is_empty() {
        lines.push(section(t, "recommended remediation"));
        for step in &steps {
            let mut row = Vec::new();
            match (step.kind, step.key) {
                (StepKind::Apply, Some(k)) => row.push(Span::styled(
                    format!("{k} "),
                    Style::default().fg(t.key_hint).bold(),
                )),
                (StepKind::Escalate, _) => {
                    row.push(Span::styled("→ ", Style::default().fg(t.text_muted)))
                }
                _ => row.push(Span::styled("· ", Style::default().fg(t.text_muted))),
            }
            row.push(Span::styled(
                step.text.clone(),
                Style::default().fg(t.text_primary),
            ));
            lines.push(Line::from(row));
            lines.push(Line::from(Span::styled(
                format!("  {}", step.detail),
                Style::default().fg(t.text_muted),
            )));
            match &step.applied {
                Some(Applied::Yes { at, before, after }) => lines.push(Line::from(Span::styled(
                    format!(
                        "  applied {} · {before} → {after}",
                        crate::diagnose::issue::short_time(at)
                    ),
                    Style::default().fg(t.status_good),
                ))),
                Some(Applied::Reverted { at, reason }) => lines.push(Line::from(Span::styled(
                    format!(
                        "  reverted {} · {reason}",
                        crate::diagnose::issue::short_time(at)
                    ),
                    Style::default().fg(t.status_warn),
                ))),
                Some(Applied::No { reason }) => lines.push(Line::from(Span::styled(
                    format!("  not applied · {reason}"),
                    Style::default().fg(t.text_muted),
                ))),
                None => {}
            }
        }
        // Steps netwatch is holding back, and why. Hidden, not greyed — but
        // never silently dropped.
        let withheld = issue.remediation.len() - steps.len();
        if withheld > 0 {
            lines.push(Line::from(Span::styled(
                format!(
                    "  {withheld} step{} hidden: netwatch is running with {}",
                    if withheld == 1 { "" } else { "s" },
                    view.capability.label()
                ),
                Style::default().fg(t.text_muted),
            )));
        }
        lines.push(Line::from(""));
    }

    // ── verify ───────────────────────────────────────────────
    lines.push(Line::from(vec![
        Span::styled("verify  ", Style::default().fg(t.text_secondary).bold()),
        Span::styled(issue.verify.label(), Style::default().fg(t.text_primary)),
        Span::styled(
            "  · the issue closes itself when this holds",
            Style::default().fg(t.text_muted),
        ),
    ]));

    // ── consequences ─────────────────────────────────────────
    if !issue.consequences.is_empty() {
        lines.push(Line::from(""));
        lines.push(section(t, "explained by this issue"));
        for cid in &issue.consequences {
            if let Some(c) = view.engine.get(cid) {
                lines.push(Line::from(Span::styled(
                    format!("  {} · {}", c.title, c.subject.label()),
                    Style::default().fg(t.text_secondary),
                )));
            }
        }
    }

    // ── optional AI commentary ───────────────────────────────
    //
    // Rendered whenever the feature is on, whatever state it is in. The
    // heading always says what this is; the second line says either what the
    // model is doing or what it said. Silence is not an option here — an
    // enabled feature that shows nothing is indistinguishable from a broken
    // one, and that is exactly what it was.
    if let Some(ai) = &view.ai {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("ai narrative", Style::default().fg(t.text_muted).italic()),
            Span::styled(
                format!("  {}", ai.status_line(&view.endpoint)),
                Style::default()
                    .fg(if ai.is_failing() {
                        t.status_warn
                    } else {
                        t.text_muted
                    })
                    .italic(),
            ),
        ]));
        if let Some(n) = &ai.narrative {
            lines.push(Line::from(Span::styled(
                n.clone(),
                Style::default().fg(t.text_secondary),
            )));
        }
    }

    let sev = severity_color(issue.severity, t);
    let block = widgets::Panel::styled(vec![
        Span::styled(issue.title.clone(), Style::default().fg(sev).bold()),
        Span::styled(
            format!(" · {}", issue.severity.long_label()),
            Style::default().fg(sev),
        ),
    ])
    .meta(issue.id.to_string())
    .border(sev)
    .fit(area.width)
    .block(t);
    // Content-sized, like every other panel: a box with fourteen blank rows
    // under its last sentence reads as a pane that failed to load. Wrapped
    // lines are counted at the pane's own width so the box does not clip the
    // text it just measured.
    let inner_w = area.width.saturating_sub(2) as usize;
    let rows: usize = lines
        .iter()
        .map(|l| {
            let w: usize = l.spans.iter().map(|s| s.content.chars().count()).sum();
            if inner_w == 0 {
                1
            } else {
                w.div_ceil(inner_w).max(1)
            }
        })
        .sum();
    let height = (rows as u16 + 2).min(area.height);

    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        Rect { height, ..area },
    );
    height
}

/// `1 sample` / `2 samples`. English pluralisation, in one place, because
/// "1 samples" on a diagnostic screen undermines every other number on it.
fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/// Truncate on a character boundary, marking the cut. Widths here are column
/// counts, and the triggers are ASCII, so chars are the right unit.
fn ellipsise(text: &str, max: usize) -> String {
    if max < 2 || text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max - 1).collect();
    out.push('…');
    out
}

fn section(t: &Theme, label: &str) -> Line<'static> {
    Line::from(Span::styled(
        label.to_string(),
        Style::default().fg(t.text_secondary).bold(),
    ))
}

// ────────────────────────────────────────────── report preview

fn render_report_preview(f: &mut Frame, view: &View, area: Rect) {
    let t = view.theme;
    let report = crate::diagnose::report::Report {
        generated_at: String::new(),
        window_start: String::new(),
        window_end: String::new(),
        environment: Default::default(),
        issues: view.engine.issues().to_vec(),
        timeline: vec![],
        artifacts: vec![],
    };
    let md = report.to_markdown();
    let lines: Vec<Line> = md
        .lines()
        .take(area.height.saturating_sub(2) as usize)
        .map(|l| {
            Line::from(Span::styled(
                l.to_string(),
                Style::default().fg(if l.starts_with('#') {
                    t.text_primary
                } else {
                    t.text_secondary
                }),
            ))
        })
        .collect();

    let block = widgets::Panel::new("report.md")
        .meta_styled(vec![
            Span::styled("o", Style::default().fg(t.key_hint).bold()),
            Span::styled(
                if view.show_report {
                    " back to issues  "
                } else {
                    " read in full  "
                },
                Style::default().fg(t.text_muted),
            ),
            Span::styled("e", Style::default().fg(t.key_hint).bold()),
            Span::styled(" export bundle", Style::default().fg(t.text_muted)),
        ])
        .fit(area.width)
        .block(t);
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// The transient line under the panels: what an apply, export or copy just
/// did. Same `✓` / `✕` vocabulary as the footer toast, because a user cannot
/// be expected to learn two confirmations for the same class of event.
fn render_status(f: &mut Frame, view: &View, status: &str, area: Rect) {
    let t = view.theme;
    let lower = status.to_lowercase();
    let (glyph, color) = if lower.contains("failed") || lower.contains("error") {
        ("✕", t.status_error)
    } else {
        ("✓", t.status_good)
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!(" {glyph} "), Style::default().fg(color).bold()),
            Span::styled(status.to_string(), Style::default().fg(color)),
        ])),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::fixture;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// Render the fixture and return the screen as text.
    fn draw(width: u16, height: u16, mutate: impl Fn(&mut View)) -> String {
        let (engine, baselines) = fixture::run();
        let theme = crate::theme::by_name("default");
        let mut view = View {
            engine: &engine,
            baselines: &baselines,
            theme: &theme,
            selected: 0,
            show_report: false,
            capability: Capability::Root,
            ai: None,
            endpoint: "local".to_string(),
            status: None,
            demo_banner: None,
        };
        mutate(&mut view);

        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| render_body(f, &view, f.size())).unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf.get(x, y).symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_verdict_line_leads_with_the_worst_issue() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("3 issues"), "{s}");
        assert!(s.contains("slow dns resolver"), "{s}");
    }

    #[test]
    fn the_screen_shows_the_computed_multiple_and_never_a_wrong_one() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("33× baseline"), "{s}");
        assert!(!s.contains("100×"), "{s}");
    }

    #[test]
    fn confidence_is_a_word_not_a_percentage() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("strong") || s.contains("likely"), "{s}");
        // No cause line may carry a percent sign.
        for line in s.lines().filter(|l| l.contains("checks")) {
            assert!(
                !line.contains('%'),
                "confidence rendered as a probability: {line}"
            );
        }
    }

    #[test]
    fn the_detail_pane_shows_cause_checks_for_the_top_cause() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("probable cause"), "{s}");
        assert!(s.contains("upstream forwarder"), "{s}");
        assert!(s.contains("✓") || s.contains("✗"), "{s}");
    }

    #[test]
    fn every_issue_shows_its_verify_condition() {
        let (engine, _) = fixture::run();
        for n in 0..engine.primary().len() {
            let s = draw(150, 44, |v| v.selected = n);
            assert!(s.contains("verify"), "issue {n} has no verify line:\n{s}");
        }
    }

    #[test]
    fn selecting_a_different_issue_changes_the_detail_pane() {
        let a = draw(150, 44, |v| v.selected = 0);
        let b = draw(150, 44, |v| v.selected = 1);
        assert_ne!(a, b);
    }

    #[test]
    fn an_unprivileged_run_hides_apply_steps_and_says_why() {
        let s = draw(150, 44, |v| v.capability = Capability::None);
        assert!(
            s.contains("hidden: netwatch is running with no privileges"),
            "an unprivileged run must explain the missing step:\n{s}"
        );
    }

    #[test]
    fn a_privileged_run_offers_the_key_bound_fix() {
        let s = draw(150, 44, |v| v.capability = Capability::Root);
        assert!(s.contains("switch this session's resolver"), "{s}");
        assert!(!s.contains("hidden:"), "{s}");
    }

    #[test]
    fn the_engine_strip_states_baseline_and_ruleset_coverage() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("baselines"), "{s}");
        assert!(s.contains("ruleset"), "{s}");
        assert!(
            s.contains("all active"),
            "coverage must be stated honestly:\n{s}"
        );
    }

    #[test]
    fn a_clear_engine_does_not_claim_health_it_has_not_earned() {
        use crate::diagnose::baseline::NetworkFingerprint;
        use crate::diagnose::engine::{Engine, SystemClock};

        let engine = Engine::new(Box::new(SystemClock));
        let baselines = BaselineStore::new(NetworkFingerprint::new("eth0", None, vec![], None));
        let theme = crate::theme::by_name("default");
        let view = View {
            engine: &engine,
            baselines: &baselines,
            theme: &theme,
            selected: 0,
            show_report: false,
            capability: Capability::None,
            ai: None,
            endpoint: "local".to_string(),
            status: None,
            demo_banner: None,
        };
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|f| render_body(f, &view, f.size())).unwrap();
        let buf = terminal.backend().buffer().clone();
        let s: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(s.contains("no baseline"), "{s}");
        assert!(!s.contains("nominal"), "{s}");
    }

    #[test]
    fn the_report_preview_renders_the_same_numbers_as_the_screen() {
        let s = draw(150, 44, |v| v.show_report = true);
        assert!(s.contains("report.md"), "{s}");
        assert!(s.contains("netwatch report"), "{s}");
    }

    #[test]
    fn narrative_is_labelled_as_commentary() {
        use crate::collectors::insights::InsightsStatus;
        let s = draw(150, 44, |v| {
            v.ai = Some(Ai {
                status: InsightsStatus::Available,
                narrative: Some("The resolver change lines up with the reroute.".into()),
            })
        });
        assert!(s.contains("ai narrative"), "{s}");
        assert!(s.contains("not a source of facts"), "{s}");
        assert!(s.contains("lines up with the reroute"), "{s}");
    }

    /// The regression this whole investigation was about: with the feature
    /// enabled and no model reachable, the tab said nothing at all.
    #[test]
    fn a_failing_model_says_so_instead_of_going_silent() {
        use crate::collectors::insights::InsightsStatus;
        let s = draw(150, 44, |v| {
            v.ai = Some(Ai {
                status: InsightsStatus::OllamaUnavailable,
                narrative: None,
            })
        });
        assert!(
            s.contains("ai narrative"),
            "the block must still appear:\n{s}"
        );
        assert!(s.contains("no model answering"), "{s}");
        assert!(
            s.contains("localhost:11434"),
            "it must name the address it tried, not the config word:\n{s}"
        );
        // A fragment short enough to survive the wrap: the advice runs past
        // the detail pane's width, and the panel border sits between the
        // wrapped halves, so the full sentence never appears contiguously.
        assert!(s.contains("switch this off"), "{s}");
    }

    #[test]
    fn every_model_state_produces_a_line() {
        use crate::collectors::insights::InsightsStatus as S;
        for (status, expect) in [
            (S::Idle, "waiting for the first analysis"),
            (S::Analyzing, "analysing"),
            (S::Error("timed out".into()), "timed out"),
            (S::OllamaUnavailable, "no model answering"),
        ] {
            let s = draw(150, 44, |v| {
                v.ai = Some(Ai {
                    status: status.clone(),
                    narrative: None,
                })
            });
            assert!(
                s.contains(expect),
                "{status:?} should mention {expect:?}:\n{s}"
            );
        }
    }

    #[test]
    fn the_block_is_absent_when_the_feature_is_off() {
        let s = draw(150, 44, |_| {});
        assert!(
            !s.contains("ai narrative"),
            "nothing about AI belongs on screen when it is disabled:\n{s}"
        );
    }

    #[test]
    fn selection_is_visible_without_a_background_fill() {
        let a = draw(150, 44, |v| v.selected = 0);
        let b = draw(150, 44, |v| v.selected = 1);
        assert!(a.contains('▌'), "the selected row needs a rail:\n{a}");
        assert_ne!(a, b, "moving the cursor must change the screen");

        // The verdict strip above the list draws its own severity rail, so
        // the cursor's rail is the first one *inside* the issues panel.
        let rail_line = |s: &str| {
            // The panel's top border, not the verdict line — which also
            // says "3 issues" and draws a rail of its own.
            let panel_top = s
                .lines()
                .position(|l| l.contains("issues") && l.contains('╮'))
                .expect("an issues panel");
            s.lines()
                .skip(panel_top)
                .position(|l| l.contains('▌'))
                .expect("a rail in the issue list")
                + panel_top
        };
        assert!(
            rail_line(&b) > rail_line(&a),
            "the rail must follow the cursor down the list"
        );
    }

    #[test]
    fn demo_mode_says_so_on_every_frame() {
        let s = draw(150, 44, |v| {
            v.demo_banner = Some("DEMO — recorded scenario, 6× · 250 of 439s".into())
        });
        assert!(s.contains("DEMO"), "{s}");
        assert!(s.contains("recorded scenario"), "{s}");
        // And it does not simultaneously claim to know the live network.
        assert!(!s.contains("network eth0"), "{s}");
    }

    #[test]
    fn sample_counts_are_pluralised() {
        assert_eq!(plural(1, "sample"), "1 sample");
        assert_eq!(plural(0, "sample"), "0 samples");
        assert_eq!(plural(38, "sample"), "38 samples");
    }

    #[test]
    fn ellipsise_never_splits_mid_character_or_overflows() {
        assert_eq!(ellipsise("short", 20), "short");
        assert_eq!(ellipsise("abcdefghij", 5), "abcd…");
        assert_eq!(ellipsise("abcdefghij", 5).chars().count(), 5);
        // Degenerate widths must not panic.
        assert_eq!(ellipsise("abc", 0), "abc");
        assert_eq!(ellipsise("σσσσσ", 3).chars().count(), 3);
    }

    /// The catalogue summarises; it does not compete with the issue list.
    ///
    /// It used to print every rule's full trigger sentence into a column
    /// sized to the issue titles, which produced twenty-five lines that all
    /// ended in `…`. A truncated sentence teaches nothing, so the panel now
    /// names categories and rule names and sends the reader to `?`.
    #[test]
    fn the_catalogue_summarises_instead_of_ellipsising_every_line() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("watching for"), "{s}");
        // Real categories and real rule names, derived from the catalogue.
        assert!(s.contains("dns"), "{s}");
        assert!(s.contains("slow_resolver"), "{s}");
        // And it points at where the full triggers live.
        assert!(s.contains("every rule and what triggers it"), "{s}");

        // No more than a couple of lines may need truncating; the old panel
        // truncated every single one.
        let cut = s.lines().filter(|l| l.contains('…')).count();
        assert!(
            cut <= 3,
            "{cut} truncated lines is the old panel again:\n{s}"
        );
    }

    /// The chronology is the ordering argument the ranking rests on: the
    /// reroute came first, the resolver slowed four minutes later.
    #[test]
    fn the_chronology_runs_oldest_first() {
        let s = draw(150, 44, |_| {});
        let rows: Vec<&str> = s
            .lines()
            .skip_while(|l| !l.contains("chronology"))
            .skip(1)
            .take_while(|l| !l.starts_with('╰'))
            .collect();
        assert!(rows.len() >= 2, "expected a chronology:\n{s}");

        // The row starts with the panel border and, on the selected row, the
        // cursor rail — neither is part of the timestamp.
        let stamps: Vec<String> = rows
            .iter()
            .filter_map(|l| {
                l.split_whitespace()
                    .map(|w| w.trim_matches(|c| c == '│' || c == '▌'))
                    .find(|w| w.contains(':'))
                    .map(str::to_string)
            })
            .collect();
        let mut sorted = stamps.clone();
        sorted.sort_unstable();
        assert_eq!(stamps, sorted, "out of order: {stamps:?}\n{s}");
    }

    /// A consequence is filed under its root cause in the issue list, which
    /// means the list is the one place it cannot be seen in time order. The
    /// chronology carries it.
    #[test]
    fn the_chronology_includes_suppressed_consequences() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("path rtt above baseline"), "{s}");
        // And the issue list above it still does not list it as a finding.
        let list: String = s
            .lines()
            .skip_while(|l| !(l.contains("issues") && l.contains('╮')))
            .take_while(|l| !l.contains("chronology"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !list.contains("path rtt above baseline"),
            "a consequence must not also be a finding:\n{list}"
        );
    }

    /// `↵ apply fix` must not survive the apply. The detail pane says
    /// `applied 06:51:56 · 169.254.1.1 → 192.168.8.1` while the footer went on
    /// offering to apply it — a key hint for a key with nothing left to do.
    #[test]
    fn the_apply_hint_disappears_once_the_step_has_run() {
        use crate::diagnose::issue::Applied;

        let (engine, _) = fixture::run();
        let issue = engine
            .primary()
            .into_iter()
            .find(|i| i.remediation.iter().any(|s| s.kind == StepKind::Apply))
            .expect("the fixture has an appliable issue")
            .clone();

        assert!(
            has_applicable_step(&issue, Capability::Root),
            "before the apply, ↵ does something"
        );

        let mut applied = issue.clone();
        for step in applied.remediation.iter_mut() {
            if step.kind == StepKind::Apply {
                step.applied = Some(Applied::Yes {
                    at: "2026-09-03 06:51:56".into(),
                    before: "169.254.1.1".into(),
                    after: "192.168.8.1".into(),
                });
            }
        }
        assert!(
            !has_applicable_step(&applied, Capability::Root),
            "after the apply, ↵ has nothing left to do"
        );

        // Reverted is applicable again — the fix is off the box.
        let mut reverted = applied.clone();
        for step in reverted.remediation.iter_mut() {
            if step.kind == StepKind::Apply {
                step.applied = Some(Applied::Reverted {
                    at: "2026-09-03 06:55:00".into(),
                    reason: "user".into(),
                });
            }
        }
        assert!(has_applicable_step(&reverted, Capability::Root));
    }

    /// The tab uses the screen it is given. Panels stay content-sized, so
    /// the space the detail pane does not need goes to the report — which is
    /// generated from the same issues and is always longer than the room for
    /// it, rather than being padding.
    #[test]
    fn the_report_fills_what_the_detail_pane_leaves() {
        let s = draw(150, 44, |_| {});
        assert!(s.contains("report.md"), "no preview on a tall screen:\n{s}");
        // Both columns reach the bottom: the last row carries two closing
        // corners, not one panel and a run of blank space beside it.
        let last = s
            .lines()
            .rfind(|l| l.contains('╯'))
            .expect("a closed panel");
        assert_eq!(
            last.matches('╯').count(),
            2,
            "only one column reaches the bottom:\n{last}"
        );
    }

    /// A short screen has nothing to spare, so the preview stays away rather
    /// than squeezing the pane it is meant to be filling around.
    #[test]
    fn a_short_screen_gets_no_preview() {
        let s = draw(150, 26, |_| {});
        assert!(!s.contains("report.md"), "{s}");
        assert!(
            s.contains("slow dns resolver"),
            "the working view survives:\n{s}"
        );
    }

    /// `o` swaps the working view for the whole report. Revealing a preview
    /// that is already on screen would be showing the same thing twice; what
    /// the key is for is reading the report at length.
    #[test]
    fn o_replaces_the_working_view_with_the_full_report() {
        let s = draw(150, 44, |v| v.show_report = true);
        assert!(s.contains("netwatch report"), "{s}");
        assert!(
            !s.contains("watching for"),
            "the working view must give way to the report:\n{s}"
        );
        assert!(s.contains("back to issues"), "the way out is named:\n{s}");
        // And the footer names it the same way — one key, one label.
        let view_hints = {
            let (engine, baselines) = fixture::run();
            let theme = crate::theme::by_name("default");
            let v = View {
                engine: &engine,
                baselines: &baselines,
                theme: &theme,
                selected: 0,
                show_report: true,
                capability: Capability::Root,
                ai: None,
                endpoint: "local".to_string(),
                status: None,
                demo_banner: None,
            };
            footer_hints(&v)
        };
        let o = view_hints
            .iter()
            .find(|(k, _)| k == "o")
            .expect("the report key");
        assert_eq!(o.1, "back to issues", "panel and footer disagree on `o`");
    }

    /// Panels are sized to their content. The detail pane used to be stretched
    /// to the full column height, leaving fourteen blank rows under its last
    /// sentence — which reads as a pane that failed to load.
    #[test]
    fn the_detail_pane_ends_where_its_content_ends() {
        let s = draw(150, 44, |_| {});
        let lines: Vec<&str> = s.lines().collect();
        let close = lines
            .iter()
            .rposition(|l| l.contains('╯'))
            .expect("a closed panel");
        // Whatever sits above the closing corner must be content, not a run
        // of empty rows padding the box out to the bottom of the screen.
        let blank_tail = lines[..close]
            .iter()
            .rev()
            .take_while(|l| l.trim_matches(|c| c == '│' || c == ' ').is_empty())
            .count();
        assert!(
            blank_tail <= 2,
            "{blank_tail} blank rows before the corner:\n{s}"
        );
    }

    #[test]
    fn it_renders_without_panicking_at_awkward_sizes() {
        // 20x5 is smaller than netwatch supports, but a resize passes through
        // every intermediate size on the way down, so none of them may panic.
        for (w, h) in [
            (80, 24),
            (100, 30),
            (200, 60),
            (60, 15),
            (40, 10),
            (20, 5),
            (1, 1),
        ] {
            for report in [false, true] {
                let s = draw(w, h, |v| v.show_report = report);
                let _ = s;
            }
        }
    }
}
