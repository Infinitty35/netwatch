//! Linux namespace TCP counters. These include passive handshakes; they do not
//! identify a process, errno, or prove that the ephemeral range is exhausted.
use super::{
    coverage::Availability,
    detectors::Detection,
    issue::{Cause, CheckResult, Evidence, Subject},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub failures_per_minute: Option<f64>,
    pub timewait_port_pct: Option<f64>,
    pub timewait_sockets: u64,
    pub ephemeral_ports: u32,
}
impl Observation {
    pub fn coverage(&self, rule: &str) -> (Availability, &'static str) {
        if rule == "tcp.connect_failures" && self.failures_per_minute.is_none() {
            (
                Availability::Learning,
                "collecting a full minute of namespace TCP handshake counters",
            )
        } else if rule == "tcp.timewait_exhaustion" && self.timewait_port_pct.is_none() {
            (
                Availability::CollectorFailed,
                "complete namespace TCP tables and ephemeral range required",
            )
        } else {
            (Availability::Available, "current network namespace only; no per-process failure attribution or exhaustion proof")
        }
    }
}

#[derive(Default)]
pub struct Collector {
    history: VecDeque<(Instant, u64)>,
    cached: Option<(Instant, Observation)>,
}
impl Collector {
    pub fn sample(&mut self) -> Result<(Instant, Observation), String> {
        let now = Instant::now();
        if let Some((at, obs)) = &self.cached {
            if now.duration_since(*at) < Duration::from_secs(1) {
                return Ok((*at, obs.clone()));
            }
        }
        if !cfg!(target_os = "linux") {
            return Err("Linux /proc TCP accounting required".into());
        }
        let snmp = std::fs::read_to_string("/proc/net/snmp").map_err(|e| e.to_string())?;
        let count = attempt_fails(&snmp).ok_or("Tcp AttemptFails counter absent or malformed")?;
        let failures_per_minute = self.observe(now, count);
        let tables = ["/proc/net/tcp", "/proc/net/tcp6"].map(read_table);
        let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range");
        let mut obs = Observation {
            failures_per_minute,
            ..Default::default()
        };
        if let ([Ok(v4), Ok(v6)], Ok(range)) = (tables, range) {
            if let Some((pct, sockets, ports)) = timewait(&v4, &v6, &range) {
                obs.timewait_port_pct = Some(pct);
                obs.timewait_sockets = sockets;
                obs.ephemeral_ports = ports;
            }
        }
        self.cached = Some((now, obs.clone()));
        Ok((now, obs))
    }
    fn observe(&mut self, now: Instant, count: u64) -> Option<f64> {
        if self.history.back().is_some_and(|(at, old)| {
            count < *old || now.saturating_duration_since(*at).as_secs() > 15
        }) {
            self.history.clear();
        }
        self.history.push_back((now, count));
        while self.history.len() > 1
            && now.saturating_duration_since(self.history[1].0).as_secs() >= 60
        {
            self.history.pop_front();
        }
        let (at, old) = self.history.front()?;
        let secs = now.saturating_duration_since(*at).as_secs_f64();
        (60.0..=75.0)
            .contains(&secs)
            .then(|| (count - old) as f64 * 60.0 / secs)
    }
}
fn read_table(path: &str) -> std::io::Result<String> {
    use std::io::Read;
    const MAX: usize = 4 * 1024 * 1024;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((MAX + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX {
        return Err(std::io::Error::other(
            "TCP table exceeds 4 MiB snapshot limit",
        ));
    }
    String::from_utf8(bytes).map_err(std::io::Error::other)
}
fn attempt_fails(text: &str) -> Option<u64> {
    let mut lines = text.lines().filter(|s| s.starts_with("Tcp:"));
    let header: Vec<_> = lines.next()?.split_whitespace().collect();
    let values: Vec<_> = lines.next()?.split_whitespace().collect();
    if header.len() != values.len() {
        return None;
    }
    values
        .get(header.iter().position(|s| *s == "AttemptFails")?)?
        .parse()
        .ok()
}
fn timewait(v4: &str, v6: &str, range: &str) -> Option<(f64, u64, u32)> {
    let r: Vec<u16> = range
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if r.len() != 2 || r[0] == 0 || r[1] < r[0] {
        return None;
    }
    let ports = u32::from(r[1]) - u32::from(r[0]) + 1;
    let mut occupied: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
    let mut sockets = 0;
    for (family, table) in [(4, v4), (6, v6)] {
        let mut rows = table.lines();
        if !rows.next()?.contains("local_address") {
            return None;
        }
        for row in rows {
            let f: Vec<_> = row.split_whitespace().collect();
            if f.len() < 4 {
                return None;
            }
            if f[3] != "06" {
                continue;
            }
            sockets += 1;
            let (addr, port) = f[1].split_once(':')?;
            let port = u16::from_str_radix(port, 16).ok()?;
            if (r[0]..=r[1]).contains(&port) {
                occupied
                    .entry(format!("{family}:{addr}"))
                    .or_default()
                    .insert(port);
            }
        }
    }
    let largest = occupied.values().map(BTreeSet::len).max().unwrap_or(0);
    Some((100.0 * largest as f64 / ports as f64, sockets, ports))
}
pub fn detect(obs: Option<&Observation>) -> Vec<Detection> {
    let Some(obs) = obs else {
        return vec![];
    };
    let mut out = vec![];
    if let Some(rate) = obs.failures_per_minute.filter(|v| *v > 5.0) {
        let mut d = Detection::new("tcp.connect_failures", Subject::Host);
        d.title = "TCP handshakes failing in this network namespace".into();
        d.evidence
            .push(Evidence::new("tcp.connect_failure_rate", rate, "/min"));
        d.causes.push(Cause::new(
            "namespace_handshake_failures",
            "kernel recorded failed active or passive TCP handshakes",
            vec![CheckResult::pass(
                "attempt_fails_increased",
                "AttemptFails counter increased",
                "Includes SYN_SENT and SYN_RECV failures; no process or errno attribution",
            )],
        ));
        out.push(d);
    }
    if let Some(pct) = obs.timewait_port_pct.filter(|v| *v > 60.0) {
        let mut d = Detection::new("tcp.timewait_exhaustion", Subject::Host);
        d.evidence.push(Evidence::new("tcp.timewait_pct", pct, "%"));
        d.causes.push(Cause::new("ephemeral_timewait_pressure", "many ephemeral ports have TIME_WAIT sockets", vec![CheckResult::pass("distinct_timewait_ports", "distinct local ephemeral ports exceed 60% for one local address", "Tuple reuse and other sockets affect allocation; this does not prove port exhaustion")]));
        out.push(d);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_named_counter_not_a_position() {
        assert_eq!(
            attempt_fails("Tcp: ActiveOpens AttemptFails Other\nTcp: 90 7 8\n"),
            Some(7)
        );
        assert_eq!(attempt_fails("Tcp: AttemptFails\nTcp: x\n"), None);
    }
    #[test]
    fn full_elapsed_minute_reset_and_gap() {
        let mut c = Collector::default();
        let start = Instant::now();
        for s in 0..60 {
            assert_eq!(c.observe(start + Duration::from_secs(s), 10 + s), None);
        }
        assert_eq!(c.observe(start + Duration::from_secs(60), 70), Some(60.0));
        assert_eq!(c.observe(start + Duration::from_secs(61), 1), None);
        assert_eq!(c.observe(start + Duration::from_secs(90), 100), None);
    }
    #[test]
    fn ports_are_distinct_per_address_and_in_range() {
        let table = "sl local_address rem_address st\n0: 0100007F:8000 0200007F:0050 06\n1: 0100007F:8000 0300007F:0050 06\n2: 0200007F:8001 0300007F:0050 06\n3: 0100007F:0050 0300007F:0050 06\n";
        assert_eq!(
            timewait(table, "sl local_address rem_address st\n", "32768 32769"),
            Some((50.0, 4, 2))
        );
        assert!(timewait("bad", table, "1 2").is_none());
    }
    #[test]
    fn matched_positive_negative_and_unknown() {
        assert!(detect(None).is_empty());
        assert!(detect(Some(&Observation::default())).is_empty());
        let mut o = Observation {
            failures_per_minute: Some(6.0),
            timewait_port_pct: Some(61.0),
            ..Default::default()
        };
        assert_eq!(detect(Some(&o)).len(), 2);
        o.failures_per_minute = Some(5.0);
        o.timewait_port_pct = Some(60.0);
        assert!(detect(Some(&o)).is_empty());
    }
}
