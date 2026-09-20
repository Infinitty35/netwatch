//! `netwatch diagnose run` — one bounded diagnosis, for a script or a ticket.
//!
//! The TUI answers "what is wrong with my network right now" interactively.
//! This answers it once, within a budget, and says so in an exit status a
//! shell can branch on. The distinction that matters is between *no finding*
//! and *not enough evidence*: a run that could not gather what it needed must
//! never be read as a healthy host, which is why those are different exits.

use crate::diagnose::issue::Issue;
use std::time::{Duration, Instant};

/// What a run concluded, and the exit status it reports.
///
/// Documented and stable: scripts branch on these, so the numbers are part of
/// the interface, not an implementation detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The run completed and found nothing. Not a claim that the host is
    /// healthy — only that the rules that could be evaluated did not fire.
    NoFinding = 0,
    /// The run completed and found at least one open issue.
    Finding = 1,
    /// The budget ran out before enough evidence existed to decide. The
    /// caller should retry with a longer budget rather than read this as
    /// health.
    Incomplete = 2,
    /// Bad arguments, or the session could not start.
    Error = 3,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Outcome::NoFinding => "no_finding",
            Outcome::Finding => "finding",
            Outcome::Incomplete => "incomplete",
            Outcome::Error => "error",
        }
    }
}

/// Decide the outcome of a finished run.
///
/// `evidence` is whether the run ever saw a usable observation for what it
/// was asked about. Without one there is nothing to conclude, however quiet
/// the issue list looks.
pub fn outcome(issues: &[&Issue], evidence: bool) -> Outcome {
    if !issues.is_empty() {
        Outcome::Finding
    } else if evidence {
        Outcome::NoFinding
    } else {
        Outcome::Incomplete
    }
}

struct Options {
    target: Option<String>,
    budget: Duration,
    json: bool,
}

fn parse(args: &[String]) -> anyhow::Result<Options> {
    let mut opts = Options {
        target: None,
        budget: Duration::from_secs(30),
        json: false,
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" => {
                opts.target = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--target requires a configured name"))?
                        .clone(),
                )
            }
            "--budget" => {
                let raw = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--budget requires a duration, e.g. 30s"))?;
                opts.budget = parse_budget(raw)?;
            }
            "--format" => {
                let fmt = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--format requires json or text"))?;
                match fmt.as_str() {
                    "json" => opts.json = true,
                    "text" => opts.json = false,
                    other => anyhow::bail!("unknown format: {other} (json or text)"),
                }
            }
            "--json" => opts.json = true,
            other => anyhow::bail!("unknown run option: {other}"),
        }
    }
    Ok(opts)
}

/// `30s`, `2m`, or a bare number of seconds. Bounded at both ends: a run
/// shorter than a probe interval cannot gather evidence, and one longer than
/// ten minutes is a session, not a one-shot.
pub fn parse_budget(raw: &str) -> anyhow::Result<Duration> {
    let (value, scale) = match raw.strip_suffix('s') {
        Some(v) => (v, 1),
        None => match raw.strip_suffix('m') {
            Some(v) => (v, 60),
            None => (raw, 1),
        },
    };
    let secs: u64 = value
        .parse()
        .map_err(|_| anyhow::anyhow!("budget must be a duration like 30s or 2m"))?;
    let secs = secs * scale;
    anyhow::ensure!(
        (5..=600).contains(&secs),
        "budget must be between 5s and 10m"
    );
    Ok(Duration::from_secs(secs))
}

pub fn command(args: &[String]) -> anyhow::Result<()> {
    // Exit codes are the interface here, so the error path owns its own
    // status rather than inheriting whatever main does with an `Err`.
    let outcome = match parse(args).and_then(run) {
        Ok(outcome) => outcome,
        Err(e) => {
            eprintln!("error: {e}");
            Outcome::Error
        }
    };
    std::process::exit(outcome as i32);
}

fn run(opts: Options) -> anyhow::Result<Outcome> {
    use crate::{app::App, config::NetwatchConfig, diagnose::live::LiveSampler};

    let config = NetwatchConfig {
        insights_enabled: false,
        diagnose_record_episodes: false,
        ..NetwatchConfig::load()
    };
    if let Some(name) = &opts.target {
        anyhow::ensure!(
            config.diagnose_targets.iter().any(|t| &t.name == name),
            "no configured target named {name}"
        );
    }
    let mode = crate::sandbox::Mode::from_config(&config.sandbox);
    let mut app = App::prepare_with_config(config);
    crate::runtime::bootstrap::start(
        &mut app,
        crate::runtime::bootstrap::SessionKind::Daemon,
        mode,
    )?;
    crate::runtime::bootstrap::prime_collectors(&mut app);

    let started_at = chrono::Local::now();
    let started = Instant::now();
    let mut sampler = LiveSampler::new();
    let mut samples = 0usize;
    let mut saw_evidence = false;

    loop {
        app.traffic.update();
        app.connection_collector.update();
        app.tcp_info.update();
        let network = &app.config_collector.config;
        app.health_prober
            .probe(network.gateway.as_deref(), network.primary_dns().as_deref());
        app.diagnose.target_prober.probe_due(
            &app.user_config.diagnose_targets,
            super::targets::ProbeEnv {
                resolvers: network
                    .dns_servers
                    .iter()
                    .filter_map(|d| d.parse().ok())
                    .collect(),
                vpn_ifaces: app
                    .interface_info
                    .iter()
                    .filter(|i| i.is_up && super::targets::is_vpn_iface(&i.name))
                    .map(|i| i.name.clone())
                    .collect(),
            },
        );
        let fingerprint = LiveSampler::fingerprint(&app);
        app.diagnose.baselines.set_network(fingerprint);
        let observations = sampler.sample(&app, &app.diagnose.engine.settings().thresholds);
        saw_evidence |= match &opts.target {
            // Asked about one target: only that target's own probe counts.
            // Another target completing says nothing about this one.
            Some(name) => observations.targets.iter().any(|t| &t.name == name),
            None => sampler.completed.health.gateway.is_some() || !observations.targets.is_empty(),
        };
        app.diagnose.engine.observe_live_at(
            &observations,
            &app.diagnose.baselines,
            &sampler.completed,
            Instant::now(),
        );
        samples += 1;
        if started.elapsed() >= opts.budget {
            break;
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
    app.packet_collector.stop_capture();

    let all = app.diagnose.engine.primary();
    let issues: Vec<&Issue> = match &opts.target {
        Some(name) => all
            .into_iter()
            .filter(|i| i.subject.label() == *name)
            .collect(),
        None => all,
    };
    let outcome = outcome(&issues, saw_evidence);

    if opts.json {
        let report = serde_json::json!({
            "schema": 1,
            "version": env!("CARGO_PKG_VERSION"),
            "ruleset": super::rules::CATALOGUE.len(),
            "outcome": outcome.label(),
            "exit": outcome as i32,
            "target": opts.target,
            "started_at": started_at.to_rfc3339(),
            "window_seconds": started.elapsed().as_secs_f64(),
            "samples": samples,
            "evidence": saw_evidence,
            "completeness": if saw_evidence {
                "the rules that could be evaluated were; an empty list is not a health claim"
            } else {
                "no usable observation arrived inside the budget; nothing was concluded"
            },
            "coverage": app.diagnose.engine.coverage(),
            "issues": issues,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{} · {samples} samples in {:.0}s",
            outcome.label(),
            started.elapsed().as_secs_f64()
        );
        for issue in &issues {
            println!("  {}", issue.summary_line());
            if let Some(cause) = issue.top_cause() {
                println!(
                    "    {} ({}, {})",
                    cause.label,
                    cause.confidence().label(),
                    cause.checks_label()
                );
                if let Some(missing) = cause.missing_discriminator() {
                    println!("    not measured: {} — {}", missing.name, missing.detail);
                }
            }
        }
        if outcome == Outcome::Incomplete {
            println!("  no usable observation arrived inside the budget");
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_parse_and_are_bounded() {
        assert_eq!(parse_budget("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_budget("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_budget("45").unwrap(), Duration::from_secs(45));
        assert!(parse_budget("1s").is_err(), "shorter than a probe interval");
        assert!(parse_budget("30m").is_err(), "that is a session, not a run");
        assert!(parse_budget("soon").is_err());
    }

    #[test]
    fn an_empty_list_without_evidence_is_incomplete_not_healthy() {
        // The distinction the exit statuses exist for. A run that gathered
        // nothing has not established that anything is well.
        assert_eq!(outcome(&[], false), Outcome::Incomplete);
        assert_eq!(outcome(&[], true), Outcome::NoFinding);
        assert_eq!(Outcome::Incomplete as i32, 2);
        assert_eq!(Outcome::NoFinding as i32, 0);
    }

    #[test]
    fn a_finding_outranks_the_evidence_question() {
        let issue = crate::diagnose::fixture::report().issues.remove(0);
        assert_eq!(outcome(&[&issue], true), Outcome::Finding);
        assert_eq!(outcome(&[&issue], false), Outcome::Finding);
        assert_eq!(Outcome::Finding as i32, 1);
    }

    #[test]
    fn unknown_options_are_refused_rather_than_ignored() {
        assert!(parse(&["--target".into(), "api".into()]).is_ok());
        assert!(parse(&["--nope".into()]).is_err());
        assert!(parse(&["--target".into()]).is_err());
        assert!(parse(&["--format".into(), "yaml".into()]).is_err());
    }
}
