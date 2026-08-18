use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::sysfs::test_backend::{Model, ModelRegion, ModelSchemeStats, Mutation};
use crate::sysfs::{
    AccessCountRange, AccessPattern, AgeRange, ContextConfig, FilterConfig, IntervalsGoalConfig,
    KdamondConfig, QuotaGoalConfig, QuotaGoalMetric, RegionSizeRange, SchemeConfig,
    SchemeFilterType, TargetConfig,
};

mod hierarchy;
mod ownership;
mod runtime;
mod session;
mod workflow;

fn configure_runtime_results(model: &Model) {
    model.set_tried_regions(vec![ModelRegion {
        start: 4_096,
        end: 8_192,
        nr_accesses: 7,
        age: 3,
        filter_passed_units: Some(4_096),
        probe_hits: vec![2, 5],
    }]);
    model.set_scheme_stats(vec![ModelSchemeStats {
        nr_tried: 3,
        sz_tried: 12_288,
        nr_applied: 2,
        sz_applied: 8_192,
        sz_ops_filter_passed: 4_096,
        qt_exceeds: 1,
        nr_snapshots: 9,
    }]);
    model.set_effective_quota_bytes(vec![16_384]);
}

fn exercise_session_runtime(model: &Model, session: &mut ExclusiveSession) {
    session.start().expect("start session");
    assert!(session.is_running().expect("read running state"));
    let writes = model.write_count();
    assert!(matches!(
        session.scheme_stats(0, 1),
        Err(Error::IndexOutOfBounds {
            kind: "scheme",
            index: 1,
            count: 1
        })
    ));
    assert_eq!(model.write_count(), writes, "invalid index must not write");

    model.after_next_write(
        "kdamonds/0/state",
        b"update_tuned_intervals".to_vec(),
        vec![
            Mutation::SetFile {
                path: "kdamonds/0/contexts/0/monitoring_attrs/intervals/sample_us".into(),
                value: b"4000\n".to_vec(),
            },
            Mutation::SetFile {
                path: "kdamonds/0/contexts/0/monitoring_attrs/intervals/aggr_us".into(),
                value: b"80000\n".to_vec(),
            },
        ],
    );
    session
        .update_tuned_intervals()
        .expect("refresh tuned intervals");
    session.pause_context(0).expect("pause context");
    assert_eq!(
        model.active_value("kdamonds/0/contexts/0/pause").as_deref(),
        Some("Y")
    );
    session.resume().expect("resume context");
    assert_eq!(
        model.active_value("kdamonds/0/contexts/0/pause").as_deref(),
        Some("N")
    );
    session.commit().expect("commit staged inputs");
    session
        .update_scheme_quota_goals(0, 0, &[])
        .expect("commit quota goals");

    let stats = session.scheme_stats(0, 0).expect("read scheme stats");
    assert_eq!(stats.regions_tried, 3);
    assert_eq!(stats.size_applied_units, 8_192);
    assert_eq!(stats.snapshots, Some(9));
    let snapshot = session.tried_regions(0, 0, 1).expect("read tried regions");
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot.total_units(), 4_096);
    assert_eq!(
        session.tried_bytes_units(0, 0).expect("read tried bytes"),
        4_096
    );
    assert_eq!(
        session.effective_quota_units(0, 0).expect("read quota"),
        16_384
    );
    session.clear_tried_regions().expect("clear tried regions");
    session.stop().expect("stop while retaining staged state");
    assert!(!session.is_running().expect("read stopped state"));
    session.start().expect("restart retained session");
}

fn match_all_pattern() -> AccessPattern {
    AccessPattern::new(
        RegionSizeRange::new(0, u64::MAX).expect("valid size range"),
        AccessCountRange::new(0, u32::MAX).expect("valid access range"),
        AgeRange::new(0, u32::MAX).expect("valid age range"),
    )
}

fn transaction_config(pid: u32, action: Action) -> DamonConfig {
    let mut context = ContextConfig::new(Operation::VirtualAddress);
    context
        .targets
        .push(TargetConfig::for_pid(Pid::new(pid).expect("valid pid")));
    context
        .schemes
        .push(SchemeConfig::new(action, match_all_pattern()));

    let mut kdamond = KdamondConfig::default();
    kdamond.contexts.push(context);
    let mut config = DamonConfig::default();
    config.kdamonds.push(kdamond);
    config
}

fn multi_transaction_config() -> DamonConfig {
    let mut config = transaction_config(41, Action::Stat);
    config
        .kdamonds
        .push(transaction_config(43, Action::Cold).kdamonds.remove(0));
    config
}

fn os_error(code: i32) -> Error {
    Error::Io {
        operation: "test",
        path: PathBuf::from("fixture"),
        source: io::Error::from_raw_os_error(code),
    }
}

struct TestLock {
    path: PathBuf,
}

impl TestLock {
    fn new() -> Self {
        static NEXT_LOCK: AtomicU64 = AtomicU64::new(0);
        Self {
            path: std::env::temp_dir().join(format!(
                "damon-rs-model-lock-{}-{}",
                std::process::id(),
                NEXT_LOCK.fetch_add(1, Ordering::Relaxed)
            )),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
