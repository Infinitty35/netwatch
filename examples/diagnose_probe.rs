//! Bounded experiment driver for the isolated fault lab.
use anyhow::{Context, Result};
use netwatch::diagnose::{active, kernel, probe_io::Cancel};
use std::time::{Duration, Instant};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let rule = args
        .get(1)
        .context("rule or kernel, optional config JSON")?;
    if rule == "kernel" {
        let secs = args
            .get(2)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
            .min(600);
        let mut c = kernel::Collector::default();
        let start = Instant::now();
        loop {
            let (_, o) = c.sample().map_err(anyhow::Error::msg)?;
            if start.elapsed().as_secs() >= secs {
                println!("{}", serde_json::to_string(&o)?);
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    } else {
        let cfg = if let Some(path) = args.get(2) {
            serde_json::from_str(&std::fs::read_to_string(path)?)?
        } else {
            active::Config::default()
        };
        let r = active::run(rule, &cfg, &Cancel::default());
        println!("{}", serde_json::to_string(&r)?);
    }
    Ok(())
}
