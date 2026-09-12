//! Command routing and validation, before any application side effects.
use crate::{app::ViewMode, sandbox::Mode};
#[derive(Debug)]
pub enum Command {
    Help,
    Version,
    GenerateConfig,
    Doctor {
        json: bool,
        check_capture: bool,
        interface: Option<String>,
    },
    Resolver(Vec<String>),
    CaptureChild {
        interface: String,
        mode: Mode,
    },
    Run(Run),
}
#[derive(Debug, Default)]
pub struct Run {
    pub daemon: bool,
    pub demo: bool,
    pub view: Option<ViewMode>,
    pub sandbox: Option<Mode>,
    pub remote: Option<String>,
    pub api_key: Option<String>,
    pub metrics: bool,
    pub metrics_addr: Option<String>,
}
// One option catalogue supplies both accepted spellings and help text.
const OPTIONS: &[(&str, bool, &str)] = &[
    ("--remote", true, "Remote URL (requires API key)"),
    ("--api-key", true, "Remote API key"),
    ("--view", true, "full, lite, or dense"),
    ("--lite", false, "Start in Lite view"),
    ("--demo", false, "Replay the Diagnose demo"),
    ("--no-sandbox", false, "Disable sandbox"),
    ("--sandbox-strict", false, "Require sandbox enforcement"),
    ("--metrics", false, "Daemon metrics on 127.0.0.1:9464"),
    ("--metrics-addr", true, "Daemon metrics address"),
    ("--daemon", false, "Headless mode (alias: --headless)"),
];
pub fn help() -> String {
    let mut text = format!("netwatch {}\n\nUsage: netwatch [OPTIONS] | daemon [OPTIONS]\n       netwatch doctor [--json] [--check-capture] [--interface NAME]\n       netwatch resolver status\n       netwatch resolver set <IP> --unmanaged [--seconds 1..3600]\n       netwatch resolver recover --unmanaged\n\nOptions:\n", env!("CARGO_PKG_VERSION"));
    for (name, value, description) in OPTIONS {
        text.push_str(&format!(
            "  {name:<19} {}{description}\n",
            if *value { "<value> " } else { "" }
        ));
    }
    text.push_str("  --generate-config    Write default config and exit\n  --help, -h           Show help\n  --version, -V        Show version\n\nKeys: 1–9,0 tabs; V view; L Lite; q quit; Shift+R/F/E recorder\n");
    text
}
pub fn parse(args: &[String]) -> anyhow::Result<Command> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Command::Help);
    }
    if args == ["--version"] || args == ["-V"] {
        return Ok(Command::Version);
    }
    if args == ["--generate-config"] {
        return Ok(Command::GenerateConfig);
    }
    if args.first().map(String::as_str) == Some("resolver") {
        return Ok(Command::Resolver(args[1..].to_vec()));
    }
    if args.first().map(String::as_str) == Some("__capture-check") {
        if args.len() != 3 || !["off", "strict", "best-effort"].contains(&args[2].as_str()) {
            anyhow::bail!("invalid capture check arguments");
        }
        return Ok(Command::CaptureChild {
            interface: args[1].clone(),
            mode: Mode::from_config(&args[2]),
        });
    }
    if args.first().map(String::as_str) == Some("doctor") {
        let (mut json, mut check_capture, mut interface) = (false, false, None);
        let mut rest = args[1..].iter();
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "--json" if !json => json = true,
                "--check-capture" if !check_capture => check_capture = true,
                "--interface" if interface.is_none() => interface = Some(value(&mut rest, arg)?),
                _ => anyhow::bail!("unknown or repeated doctor option: {arg}"),
            }
        }
        return Ok(Command::Doctor {
            json,
            check_capture,
            interface,
        });
    }
    let mut run = Run::default();
    let mut seen = std::collections::HashSet::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let key = match arg.as_str() {
            "daemon" | "--headless" => "--daemon",
            s => s,
        };
        if !OPTIONS.iter().any(|o| o.0 == key) {
            anyhow::bail!("unknown option: {arg}; see --help");
        }
        if !seen.insert(key) {
            anyhow::bail!("repeated option: {arg}");
        }
        match key {
            "--daemon" => run.daemon = true,
            "--demo" => run.demo = true,
            "--remote" => run.remote = Some(value(&mut rest, arg)?),
            "--api-key" => run.api_key = Some(value(&mut rest, arg)?),
            "--view" | "--lite" => {
                if run.view.is_some() {
                    anyhow::bail!("choose only one view option");
                }
                let name = if key == "--lite" {
                    "lite".to_owned()
                } else {
                    value(&mut rest, arg)?
                };
                if !["full", "lite", "dense"].contains(&name.as_str()) {
                    anyhow::bail!("--view expects full, lite, or dense");
                }
                run.view = Some(ViewMode::by_name(&name));
            }
            "--no-sandbox" | "--sandbox-strict" => {
                if run.sandbox.is_some() {
                    anyhow::bail!("sandbox flags conflict");
                }
                run.sandbox = Some(if key == "--no-sandbox" {
                    Mode::Disabled
                } else {
                    Mode::Strict
                });
            }
            "--metrics" => run.metrics = true,
            "--metrics-addr" => run.metrics_addr = Some(value(&mut rest, arg)?),
            _ => unreachable!(),
        }
    }
    if run.daemon && (run.demo || run.view.is_some()) {
        anyhow::bail!("daemon cannot use demo or view options");
    }
    if !run.daemon && (run.metrics || run.metrics_addr.is_some()) {
        anyhow::bail!("metrics options require daemon mode");
    }
    if run.metrics && run.metrics_addr.is_some() {
        anyhow::bail!("choose --metrics or --metrics-addr");
    }
    Ok(Command::Run(run))
}
fn value<'a>(rest: &mut impl Iterator<Item = &'a String>, flag: &str) -> anyhow::Result<String> {
    rest.next()
        .filter(|s| !s.is_empty() && !s.starts_with('-'))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn command(s: &str) -> anyhow::Result<Command> {
        parse(&s.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
    }
    #[test]
    fn aliases_and_existing_views_are_preserved() {
        for s in ["daemon", "--daemon", "--headless"] {
            assert!(matches!(
                command(s).unwrap(),
                Command::Run(Run { daemon: true, .. })
            ));
        }
        assert!(matches!(
            command("--view dense").unwrap(),
            Command::Run(Run {
                view: Some(ViewMode::Dense),
                ..
            })
        ));
        assert!(matches!(
            command("--lite").unwrap(),
            Command::Run(Run {
                view: Some(ViewMode::Lite),
                ..
            })
        ));
    }
    #[test]
    fn ambiguous_or_missing_values_fail_before_startup() {
        for s in [
            "--remote",
            "--api-key --demo",
            "--view typo",
            "--lite --view full",
            "--no-sandbox --sandbox-strict",
            "daemon --demo",
            "--metrics",
            "--typo",
            "doctor --remote secret",
            "doctor --interface",
        ] {
            assert!(command(s).is_err(), "{s}");
        }
        assert!(matches!(
            command("doctor --json --check-capture --interface eth0").unwrap(),
            Command::Doctor {
                json: true,
                check_capture: true,
                ..
            }
        ));
    }
}
