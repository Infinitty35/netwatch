//! Integration contract for the five remaining rules: independent completed
//! samples, missing-data recovery safety, recurrence and both replay forms.
use netwatch::diagnose::{
    active::{Observation as Active, Outcome, ResultObs},
    baseline::{BaselineStore, NetworkFingerprint},
    detectors::Observations,
    engine::{Clock, Engine, FixedClock, ObservationTimes},
    episode::{self, Recorder, Tick},
    export::Redactor,
    kernel,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
fn result(outcome: Outcome) -> ResultObs {
    ResultObs {
        outcome,
        target: Some("192.0.2.9".into()),
        successes: 0,
        failures: 0,
        detail: "test result".into(),
    }
}
fn observation(fault: bool, missing: bool) -> Observations {
    if missing {
        return Observations::default();
    }
    let outcome = if fault {
        Outcome::Fault
    } else {
        Outcome::Healthy
    };
    Observations {
        kernel: Some(kernel::Observation {
            failures_per_minute: Some(if fault { 20.0 } else { 0.0 }),
            timewait_port_pct: Some(if fault { 80.0 } else { 0.0 }),
            ..Default::default()
        }),
        active: Active {
            ipv6: Some(result(outcome)),
            portal: Some(result(outcome)),
            pmtu: Some(result(outcome)),
        },
        ..Default::default()
    }
}
#[test]
fn five_rules_recover_recur_and_replay_with_distinct_samples() {
    let clock = Arc::new(FixedClock::at("2026-09-16 12:00:00"));
    let mut engine = Engine::new(Box::new(clock.clone()));
    let base = BaselineStore::new(NetworkFingerprint::new("lab", None, vec![], None));
    let mut rec = Recorder::new(
        episode::EnvProfile::detect("isolated test", 1000),
        1_790_000_000.0,
    );
    rec.schedule_quiet_sample(f64::MAX);
    let start = Instant::now() + Duration::from_secs(86400);
    let mut episodes = vec![];
    for t in 0..=500 {
        let now = start + Duration::from_secs(t);
        let at = start + Duration::from_secs(t / 10 * 10);
        let times = ObservationTimes {
            kernel: Some(at),
            ipv6: Some(at),
            portal: Some(at),
            pmtu: Some(at),
            ..Default::default()
        };
        let obs = observation(t < 30 || (200..230).contains(&t), (40..60).contains(&t));
        engine.observe_live_at(&obs, &base, &times, now);
        if t == 9 {
            assert_eq!(
                engine.open_count(),
                0,
                "cached ticks cannot confirm a fault"
            );
        }
        if [20, 59, 220].contains(&t) {
            assert_eq!(
                engine.open_count(),
                5,
                "t={t}: missing evidence cannot close issues; faults recur"
            );
        }
        if [190, 400].contains(&t) {
            assert_eq!(
                engine.open_count(),
                0,
                "fresh measured recovery closes all five"
            );
        }
        if let Some(ep) = rec.record(Tick {
            at: 1_790_000_000.0 + t as f64,
            ts: netwatch::diagnose::engine::format_ts(clock.now()),
            now,
            obs: &obs,
            times: &times,
            readings: &[],
            engine: &engine,
            baselines: &base,
            events: vec![],
        }) {
            episodes.push(ep);
        }
        clock.advance_secs(1);
    }
    if let Some(ep) = rec.flush(&engine, &netwatch::diagnose::engine::format_ts(clock.now())) {
        episodes.push(ep);
    }
    assert!(!episodes.is_empty());
    for ep in episodes {
        let report = episode::replay(&ep);
        assert!(report.matches(), "{:?}", report.divergences.first());
        let safe = Redactor::new(b"remaining-tests").episode(&ep);
        assert!(!serde_json::to_string(&safe).unwrap().contains("192.0.2.9"));
        let report = episode::replay(&safe);
        assert!(report.matches(), "{:?}", report.divergences.first());
    }
}
#[test]
fn pmtu_recovery_is_scoped_to_the_tested_endpoint() {
    let clock = Arc::new(FixedClock::at("2026-09-16 12:00:00"));
    let mut e = Engine::new(Box::new(clock.clone()));
    let b = BaselineStore::new(NetworkFingerprint::new("lab", None, vec![], None));
    let mut o = Observations {
        active: Active {
            pmtu: Some(result(Outcome::Fault)),
            ..Default::default()
        },
        ..Default::default()
    };
    for _ in 0..3 {
        e.observe(&o, &b);
        clock.advance_secs(1);
    }
    assert_eq!(e.open_count(), 1);
    o.active.pmtu = Some(ResultObs {
        target: Some("192.0.2.10".into()),
        ..result(Outcome::Healthy)
    });
    for _ in 0..120 {
        e.observe(&o, &b);
        clock.advance_secs(1);
    }
    assert_eq!(
        e.open_count(),
        1,
        "a different path cannot verify the original path"
    );
}

#[test]
fn changed_target_configuration_cannot_verify_an_old_endpoint() {
    use netwatch::diagnose::targets::{Stage, StageError, TargetContext, TargetObs};
    let clock = Arc::new(FixedClock::at("2026-09-16 12:00:00"));
    let mut e = Engine::new(Box::new(clock.clone()));
    let b = BaselineStore::new(NetworkFingerprint::new("lab", None, vec![], None));
    let fail = Stage {
        ms: None,
        error: Some(StageError::Refused),
    };
    let target = TargetObs {
        baseline_key: Some("target-config:old".into()),
        name: "api".into(),
        host: "127.0.0.1".into(),
        port: 8080,
        tls: false,
        http: false,
        expect_status: None,
        probed_at: String::new(),
        resolve: Stage {
            ms: Some(0.0),
            error: None,
        },
        addresses: vec!["127.0.0.1".into()],
        lookups: vec![],
        connect: Some(fail.clone()),
        connect_v4: Some(fail),
        connect_v6: None,
        tls_stage: None,
        http_stage: None,
        status: None,
        context: TargetContext::default(),
    };
    let mut o = Observations {
        targets: vec![target],
        ..Default::default()
    };
    for _ in 0..3 {
        e.observe(&o, &b);
        clock.advance_secs(1);
    }
    assert_eq!(e.open_count(), 1);
    o.targets[0].baseline_key = Some("target-config:replacement".into());
    o.targets[0].connect = Some(Stage {
        ms: Some(1.0),
        error: None,
    });
    o.targets[0].connect_v4 = Some(Stage {
        ms: Some(1.0),
        error: None,
    });
    for _ in 0..130 {
        e.observe(&o, &b);
        clock.advance_secs(1);
    }
    assert_eq!(
        e.open_count(),
        1,
        "replacing a configured endpoint is not a measured fix"
    );
    o.targets[0].baseline_key = Some("target-config:old".into());
    for _ in 0..130 {
        e.observe(&o, &b);
        clock.advance_secs(1);
    }
    assert_eq!(
        e.open_count(),
        0,
        "matching configuration can verify measured recovery"
    );
}
