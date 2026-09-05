//! Per-metric, per-subject baselines: EWMA mean and standard deviation,
//! learned over a minimum window and persisted across runs.
//!
//! ## Why baselines are scoped to a network
//!
//! A baseline is only meaningful on the network it was learned on. Carry a
//! laptop from a 1.2ms office resolver to a hotel hotspot and every
//! baseline-derived rule fires at once — dns, gateway rtt, path, throughput —
//! producing a screen full of red that describes nothing but the fact that the
//! user moved. A persisted `baselines.json` makes that worse, because the
//! wrong baselines survive the reboot too.
//!
//! So every sample is recorded under a [`NetworkFingerprint`] (interface,
//! gateway, resolver set, local subnet). Changing networks doesn't discard
//! anything — the old fingerprint's baselines stay on disk and come back when
//! the user returns to that network — but rules only ever see baselines
//! learned on the network that is currently up, and a freshly-seen network
//! starts in `Learning` where no baseline rule can fire.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Default EWMA smoothing factor. At one sample/second this puts the
/// half-life at roughly 35 samples, so a baseline tracks slow drift (a
/// congested evening) without absorbing the spike it is supposed to detect.
pub const DEFAULT_ALPHA: f64 = 0.02;

/// Samples required before a metric's baseline may be used by a rule.
/// 30 minutes at one sample/second, matching the spec's minimum.
pub const DEFAULT_MIN_SAMPLES: u32 = 1_800;

/// Identity of the network a baseline was learned on. Two runs on the same
/// network produce the same fingerprint; changing any component produces a
/// different one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkFingerprint {
    pub iface: String,
    pub gateway: Option<String>,
    /// Sorted so resolver order can't change the fingerprint.
    pub resolvers: Vec<String>,
    /// Local network in CIDR-ish form, e.g. "192.168.8.0/24".
    pub subnet: Option<String>,
}

impl NetworkFingerprint {
    pub fn new(
        iface: impl Into<String>,
        gateway: Option<String>,
        mut resolvers: Vec<String>,
        subnet: Option<String>,
    ) -> Self {
        resolvers.sort();
        resolvers.dedup();
        Self {
            iface: iface.into(),
            gateway,
            resolvers,
            subnet,
        }
    }

    /// Stable key for the on-disk map. Human-readable on purpose: someone
    /// opening `baselines.json` should be able to tell which network is which.
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.iface,
            self.gateway.as_deref().unwrap_or("-"),
            if self.resolvers.is_empty() {
                "-".to_string()
            } else {
                self.resolvers.join(",")
            },
            self.subnet.as_deref().unwrap_or("-")
        )
    }

    /// Short label for the UI, e.g. `eth0 via 192.168.8.1`.
    pub fn label(&self) -> String {
        match &self.gateway {
            Some(gw) => format!("{} via {}", self.iface, gw),
            None => self.iface.clone(),
        }
    }
}

/// One metric's learned distribution on one subject.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    pub mean: f64,
    /// EWMA of squared deviation. `sigma()` is its square root.
    pub variance: f64,
    pub samples: u32,
    /// Highest value ever accepted into the baseline, for context in reports.
    pub max_seen: f64,
}

impl Baseline {
    fn new(first: f64) -> Self {
        Self {
            mean: first,
            variance: 0.0,
            samples: 1,
            max_seen: first,
        }
    }

    pub fn sigma(&self) -> f64 {
        self.variance.max(0.0).sqrt()
    }

    /// How many σ above the mean `value` sits. `None` when σ is zero — a
    /// metric that has never varied cannot be scored in σ, and dividing by
    /// zero would make every sample infinitely anomalous.
    pub fn sigma_above(&self, value: f64) -> Option<f64> {
        let s = self.sigma();
        if s <= f64::EPSILON {
            None
        } else {
            Some((value - self.mean) / s)
        }
    }

    fn update(&mut self, value: f64, alpha: f64) {
        let delta = value - self.mean;
        self.mean += alpha * delta;
        // EWMA variance (West's incremental form): tracks the same window as
        // the mean, so σ widens during genuinely noisy periods instead of
        // staying pinned to whatever the first minute looked like.
        self.variance = (1.0 - alpha) * (self.variance + alpha * delta * delta);
        self.samples = self.samples.saturating_add(1);
        if value > self.max_seen {
            self.max_seen = value;
        }
    }
}

/// Whether a metric's baseline is usable yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Never seen on this network.
    Unknown,
    /// Seen, but fewer than `min_samples`. Rules must not fire.
    Learning {
        samples: u32,
        need: u32,
    },
    Ready,
}

impl Readiness {
    pub fn is_ready(self) -> bool {
        matches!(self, Readiness::Ready)
    }

    /// `"learning 412/1800"` — what the Diagnose header shows so a user is
    /// never left wondering why nothing has fired yet.
    pub fn label(self) -> String {
        match self {
            Readiness::Unknown => "no baseline".to_string(),
            Readiness::Learning { samples, need } => format!("learning {samples}/{need}"),
            Readiness::Ready => "ready".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct NetworkBaselines {
    /// Serialised as `"subject\u{1f}metric"` because JSON object keys are
    /// strings; the unit separator can't occur in an address or metric name.
    #[serde(default)]
    metrics: HashMap<String, Baseline>,
    /// Human-readable record of which network this block belongs to.
    #[serde(default)]
    label: String,
}

fn encode(subject: &str, metric: &str) -> String {
    format!("{subject}\u{1f}{metric}")
}

/// The baseline store. Holds every network the host has learned, but only
/// serves reads for the one that is currently up.
#[derive(Debug, Clone)]
pub struct BaselineStore {
    networks: HashMap<String, NetworkBaselines>,
    current: NetworkFingerprint,
    alpha: f64,
    min_samples: u32,
    /// Set when `current` changed since load — the UI says so, and rules stay
    /// quiet until the new network's baselines are ready.
    switched: bool,
    dirty: bool,
}

impl BaselineStore {
    pub fn new(current: NetworkFingerprint) -> Self {
        Self {
            networks: HashMap::new(),
            current,
            alpha: DEFAULT_ALPHA,
            min_samples: DEFAULT_MIN_SAMPLES,
            switched: false,
            dirty: false,
        }
    }

    pub fn with_min_samples(mut self, min_samples: u32) -> Self {
        self.min_samples = min_samples;
        self
    }

    pub fn with_alpha(mut self, alpha: f64) -> Self {
        self.alpha = alpha;
        self
    }

    pub fn fingerprint(&self) -> &NetworkFingerprint {
        &self.current
    }

    /// True when the live network differs from the one the last samples were
    /// recorded on. The Diagnose header shows this; it's the difference
    /// between "nothing is wrong" and "I have nothing to compare against".
    pub fn switched_network(&self) -> bool {
        self.switched
    }

    /// Point the store at a different network. Existing baselines are kept —
    /// walking back to the office restores the office baselines — but reads
    /// now resolve against the new fingerprint, so no rule can compare a
    /// hotspot's latency to an office baseline.
    pub fn set_network(&mut self, fp: NetworkFingerprint) {
        if fp == self.current {
            return;
        }
        self.current = fp;
        self.switched = true;
        self.dirty = true;
    }

    /// Record a sample for the current network.
    pub fn observe(&mut self, subject: &str, metric: &str, value: f64) {
        if !value.is_finite() {
            return;
        }
        let key = self.current.key();
        let label = self.current.label();
        let net = self
            .networks
            .entry(key)
            .or_insert_with(|| NetworkBaselines {
                metrics: HashMap::new(),
                label,
            });
        let alpha = self.alpha;
        net.metrics
            .entry(encode(subject, metric))
            .and_modify(|b| b.update(value, alpha))
            .or_insert_with(|| Baseline::new(value));
        self.dirty = true;
    }

    /// Baseline for a metric, **only if it is usable**. Returns `None` while
    /// learning, so a caller cannot accidentally compare against a two-sample
    /// mean. Use [`Self::readiness`] to tell "not ready" from "no such metric".
    pub fn get(&self, subject: &str, metric: &str) -> Option<&Baseline> {
        let b = self
            .networks
            .get(&self.current.key())?
            .metrics
            .get(&encode(subject, metric))?;
        (b.samples >= self.min_samples).then_some(b)
    }

    pub fn readiness(&self, subject: &str, metric: &str) -> Readiness {
        match self
            .networks
            .get(&self.current.key())
            .and_then(|n| n.metrics.get(&encode(subject, metric)))
        {
            None => Readiness::Unknown,
            Some(b) if b.samples >= self.min_samples => Readiness::Ready,
            Some(b) => Readiness::Learning {
                samples: b.samples,
                need: self.min_samples,
            },
        }
    }

    /// Least-ready metric across everything learned on this network — what the
    /// Diagnose header reports as overall baseline state.
    pub fn overall_readiness(&self) -> Readiness {
        let Some(net) = self.networks.get(&self.current.key()) else {
            return Readiness::Unknown;
        };
        if net.metrics.is_empty() {
            return Readiness::Unknown;
        }
        let min = net.metrics.values().map(|b| b.samples).min().unwrap_or(0);
        if min >= self.min_samples {
            Readiness::Ready
        } else {
            Readiness::Learning {
                samples: min,
                need: self.min_samples,
            }
        }
    }

    /// Seed a ready-made baseline. Used by the fixture and by tests; nothing
    /// on the live path calls it.
    pub fn seed(&mut self, subject: &str, metric: &str, mean: f64, sigma: f64, samples: u32) {
        let key = self.current.key();
        let label = self.current.label();
        let net = self
            .networks
            .entry(key)
            .or_insert_with(|| NetworkBaselines {
                metrics: HashMap::new(),
                label,
            });
        net.metrics.insert(
            encode(subject, metric),
            Baseline {
                mean,
                variance: sigma * sigma,
                samples,
                max_seen: mean + 3.0 * sigma,
            },
        );
        self.dirty = true;
    }

    pub fn load(path: &Path, current: NetworkFingerprint) -> Self {
        let mut store = Self::new(current);
        let Ok(text) = std::fs::read_to_string(path) else {
            return store;
        };
        match serde_json::from_str::<Persisted>(&text) {
            Ok(p) => {
                store.networks = p.networks;
                // A run that comes up on a different network than the one last
                // written is exactly the case this whole module exists for.
                store.switched = p
                    .last_network
                    .map(|last| last != store.current.key())
                    .unwrap_or(false);
                store
            }
            Err(_) => store,
        }
    }

    /// Atomic write: temp file then rename, so a kill mid-write can't leave a
    /// truncated `baselines.json` that reads as "no baselines" forever.
    pub fn save(&mut self, path: &Path) -> std::io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let payload = Persisted {
            version: 1,
            last_network: Some(self.current.key()),
            networks: self.networks.clone(),
        };
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&payload)?)?;
        std::fs::rename(&tmp, path)?;
        self.dirty = false;
        Ok(())
    }

    /// Default location: alongside the rest of netwatch's cache.
    pub fn default_path() -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("netwatch")
            .join("baselines.json")
    }
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    version: u32,
    #[serde(default)]
    last_network: Option<String>,
    #[serde(default)]
    networks: HashMap<String, NetworkBaselines>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn office() -> NetworkFingerprint {
        NetworkFingerprint::new(
            "eth0",
            Some("192.168.8.1".into()),
            vec!["169.254.1.1".into()],
            Some("192.168.8.0/24".into()),
        )
    }

    fn hotspot() -> NetworkFingerprint {
        NetworkFingerprint::new(
            "wlan0",
            Some("172.20.10.1".into()),
            vec!["172.20.10.1".into()],
            Some("172.20.10.0/28".into()),
        )
    }

    #[test]
    fn fingerprint_ignores_resolver_order() {
        let a =
            NetworkFingerprint::new("eth0", None, vec!["1.1.1.1".into(), "8.8.8.8".into()], None);
        let b =
            NetworkFingerprint::new("eth0", None, vec!["8.8.8.8".into(), "1.1.1.1".into()], None);
        assert_eq!(a.key(), b.key());
    }

    #[test]
    fn baseline_is_withheld_until_it_has_enough_samples() {
        let mut s = BaselineStore::new(office()).with_min_samples(10);
        for _ in 0..5 {
            s.observe("169.254.1.1", "dns.rtt_p50", 1.2);
        }
        assert!(s.get("169.254.1.1", "dns.rtt_p50").is_none());
        assert_eq!(
            s.readiness("169.254.1.1", "dns.rtt_p50"),
            Readiness::Learning {
                samples: 5,
                need: 10
            }
        );
        for _ in 0..5 {
            s.observe("169.254.1.1", "dns.rtt_p50", 1.2);
        }
        assert!(s.get("169.254.1.1", "dns.rtt_p50").is_some());
    }

    #[test]
    fn moving_networks_does_not_leak_the_old_baseline() {
        let mut s = BaselineStore::new(office()).with_min_samples(3);
        for _ in 0..10 {
            s.observe("resolver", "dns.rtt_p50", 1.2);
        }
        assert!(s.get("resolver", "dns.rtt_p50").is_some());

        s.set_network(hotspot());
        assert!(
            s.get("resolver", "dns.rtt_p50").is_none(),
            "a hotspot must not be judged against the office baseline"
        );
        assert!(s.switched_network());
        assert_eq!(s.readiness("resolver", "dns.rtt_p50"), Readiness::Unknown);
    }

    #[test]
    fn returning_to_a_known_network_restores_its_baseline() {
        let mut s = BaselineStore::new(office()).with_min_samples(3);
        for _ in 0..10 {
            s.observe("resolver", "dns.rtt_p50", 1.2);
        }
        s.set_network(hotspot());
        for _ in 0..10 {
            s.observe("resolver", "dns.rtt_p50", 45.0);
        }
        s.set_network(office());
        let b = s
            .get("resolver", "dns.rtt_p50")
            .expect("office baseline back");
        assert!(
            (b.mean - 1.2).abs() < 0.01,
            "office baseline was polluted by the hotspot: {}",
            b.mean
        );
    }

    #[test]
    fn sigma_is_none_for_a_metric_that_never_varied() {
        let mut s = BaselineStore::new(office()).with_min_samples(2);
        for _ in 0..10 {
            s.observe("r", "m", 5.0);
        }
        let b = s.get("r", "m").unwrap();
        assert_eq!(b.sigma_above(500.0), None);
    }

    #[test]
    fn variance_tracks_a_noisy_metric() {
        let mut s = BaselineStore::new(office())
            .with_min_samples(2)
            .with_alpha(0.2);
        for i in 0..200 {
            s.observe("r", "m", if i % 2 == 0 { 8.0 } else { 12.0 });
        }
        let b = s.get("r", "m").unwrap();
        assert!((b.mean - 10.0).abs() < 1.0, "mean {}", b.mean);
        assert!(
            b.sigma() > 0.5,
            "σ should reflect the ±2 swing, got {}",
            b.sigma()
        );
        // A 12ms sample on a ±2 metric is not a 3σ event.
        assert!(b.sigma_above(12.0).unwrap() < 3.0);
    }

    #[test]
    fn persists_and_reloads_per_network() {
        let dir = std::env::temp_dir().join(format!("nw-baseline-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("baselines.json");

        let mut s = BaselineStore::new(office()).with_min_samples(3);
        for _ in 0..10 {
            s.observe("r", "m", 1.2);
        }
        s.save(&path).unwrap();

        let back = BaselineStore::load(&path, office()).with_min_samples(3);
        assert!(back.get("r", "m").is_some());
        assert!(!back.switched_network());

        // Same file, different network: baselines invisible, switch flagged.
        let moved = BaselineStore::load(&path, hotspot()).with_min_samples(3);
        assert!(moved.get("r", "m").is_none());
        assert!(moved.switched_network());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_truncated_file_degrades_to_empty_not_panic() {
        let dir = std::env::temp_dir().join(format!("nw-baseline-bad-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("baselines.json");
        std::fs::write(&path, "{\"version\": 1, \"netw").unwrap();
        let s = BaselineStore::load(&path, office());
        assert_eq!(s.overall_readiness(), Readiness::Unknown);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
