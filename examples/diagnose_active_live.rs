//! Real sandboxed active-runner → live sampler → engine → recorded replay test.
use anyhow::{ensure, Context, Result};
use netwatch::{
    app::App,
    config::NetwatchConfig,
    diagnose::{active, episode, export},
    runtime::bootstrap::{self, SessionKind},
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
fn main() -> Result<()> {
    let root = PathBuf::from(std::env::args().nth(1).context("new scratch directory")?);
    ensure!(!root.exists(), "scratch must be new");
    for (key, dir) in [
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
    ] {
        let p = root.join(dir);
        std::fs::create_dir_all(&p)?;
        std::env::set_var(key, p);
    }
    let portal = Arc::new(AtomicBool::new(true));
    let stop = Arc::new(AtomicBool::new(false));
    let listener = TcpListener::bind("0.0.0.0:0")?;
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    let mode = portal.clone();
    let stopping = stop.clone();
    let server = std::thread::spawn(move || {
        while !stopping.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut s, _)) => {
                    let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
                    let mut b = [0; 4096];
                    if s.read(&mut b).is_ok() {
                        let response = if mode.load(Ordering::Relaxed) {
                            "HTTP/1.1 302 Found\r\nLocation: http://login.invalid/private?token=secret\r\nContent-Length: 0\r\n\r\n"
                        } else {
                            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
                        };
                        let _ = s.write_all(response.as_bytes());
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    });
    let mut config = NetwatchConfig {
        diagnose_record_episodes: true,
        insights_enabled: false,
        ..Default::default()
    };
    config.diagnose_probes.portal_endpoints = ["127.0.0.1", "127.0.0.2"]
        .iter()
        .map(|h| active::HttpEndpoint {
            url: format!("http://{h}:{port}/"),
            expect_status: 204,
        })
        .collect();
    config.save()?;
    let mut app = App::prepare_with_config(config);
    bootstrap::start(
        &mut app,
        SessionKind::Daemon,
        netwatch::sandbox::Mode::from_config("on"),
    )?;
    bootstrap::prime_collectors(&mut app);
    app.tick();
    app.diagnose
        .active_prober
        .start("captive.portal", &app.user_config.diagnose_probes)
        .map_err(anyhow::Error::msg)?;
    let start = Instant::now();
    let mut repairing = false;
    let mut recovered = false;
    while start.elapsed() < Duration::from_secs(100) {
        app.tick();
        let issue = app
            .diagnose
            .engine
            .issues()
            .iter()
            .find(|i| i.rule == "captive.portal");
        if !repairing && issue.is_some_and(|i| i.state.is_open()) {
            portal.store(false, Ordering::Relaxed);
            if app
                .diagnose
                .active_prober
                .start("captive.portal", &app.user_config.diagnose_probes)
                .is_ok()
            {
                repairing = true;
                println!(
                    "{}s: confirmed interception; checking restored expected responses",
                    start.elapsed().as_secs()
                );
            }
        }
        if repairing && issue.is_some_and(|i| !i.state.is_open()) {
            recovered = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
    app.shutdown_diagnose();
    app.packet_collector.stop_capture();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
    ensure!(
        repairing && recovered,
        "active probe did not confirm and recover: {:?}",
        app.diagnose.active_prober.snapshot()
    );
    let dir = episode::default_dir().context("episode directory")?;
    let files = episode::list(&dir);
    ensure!(!files.is_empty(), "episode missing");
    for file in files {
        let ep = episode::load(&file)?;
        ensure!(episode::replay(&ep).matches(), "live replay differs");
        let safe = export::Redactor::new(b"active-live").episode(&ep);
        ensure!(episode::replay(&safe).matches(), "redacted replay differs");
        ensure!(
            !serde_json::to_string(&safe)?.contains("secret"),
            "redirect secret retained"
        );
    }
    println!("PASS: sandboxed active probe, distinct samples, recovery, full and redacted replay in {:.1}s",start.elapsed().as_secs_f64());
    Ok(())
}
