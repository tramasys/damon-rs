//! Opt-in semantic checks against a real DAMON sysfs hierarchy.
//!
//! These scenarios are independently implemented from behavior exercised by
//! the upstream Linux DAMON selftests that `damon-tests` runs. They use only
//! the non-destructive `stat` action and restore the preceding hierarchy.

#![cfg(target_os = "linux")]

use std::env;
use std::fs;
use std::hint::black_box;
use std::io;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use damon::{
    AccessCountRange, AccessPattern, Action, AgeRange, ContextConfig, Damon, DamonConfig,
    KdamondConfig, MonitoringIntervals, Operation, Pid, RegionBounds, RegionSizeRange,
    SchemeConfig, TargetConfig,
};

const RUN_KERNEL_TESTS: &str = "DAMON_RS_RUN_KERNEL_TESTS";
const WORKLOAD_READY: &str = "DAMON_RS_KERNEL_WORKLOAD_READY";
const REGION_COUNT: usize = 14;
const REGION_SIZE: usize = 10 * 1024 * 1024;
const PAGE_SIZE: usize = 4_096;

static KERNEL_TEST_LOCK: Mutex<()> = Mutex::new(());

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Workload {
    child: Child,
    ready_path: std::path::PathBuf,
}

impl Workload {
    fn spawn() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let ready_path = env::temp_dir().join(format!(
            "damon-rs-kernel-workload-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let child = Command::new(env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "patterned_memory_workload",
                "--test-threads=1",
            ])
            .env(WORKLOAD_READY, &ready_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut workload = Self { child, ready_path };
        workload.wait_until_ready()?;
        Ok(workload)
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn wait_until_ready(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if self.ready_path.exists() {
                return Ok(());
            }
            if let Some(status) = self.child.try_wait()? {
                return Err(io::Error::other(format!(
                    "memory workload exited before becoming ready: {status}"
                )));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "memory workload did not become ready",
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Workload {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.ready_path);
    }
}

fn kernel_tests_enabled() -> bool {
    matches!(env::var(RUN_KERNEL_TESTS).as_deref(), Ok("1"))
}

fn match_all_pattern() -> AccessPattern {
    AccessPattern::new(
        RegionSizeRange::new(0, u64::MAX).expect("valid size range"),
        AccessCountRange::new(0, u32::MAX).expect("valid access range"),
        AgeRange::new(0, u32::MAX).expect("valid age range"),
    )
}

fn monitoring_config(pid: Pid, bounds: RegionBounds, schemes: Vec<SchemeConfig>) -> DamonConfig {
    let mut context = ContextConfig::new(Operation::VirtualAddress);
    context.intervals = MonitoringIntervals::new(
        Duration::from_millis(5),
        Duration::from_millis(100),
        Duration::from_secs(60),
    )
    .expect("valid monitoring intervals");
    context.region_bounds = bounds;
    context.targets.push(TargetConfig::for_pid(pid));
    context.schemes = schemes;

    let mut kdamond = KdamondConfig::default();
    kdamond.contexts.push(context);
    let mut config = DamonConfig::default();
    config.kdamonds.push(kdamond);
    config
}

fn collect_region_counts(min: u64, max: u64) -> TestResult<Vec<usize>> {
    let workload = Workload::spawn()?;
    let damon = Damon::new()?;
    let mut monitor = damon
        .monitor_pid(Pid::new(workload.pid())?)
        .sample_interval(Duration::from_millis(5))
        .aggregation_interval(Duration::from_millis(100))
        .region_bounds(min, max)
        .start()?;
    thread::sleep(Duration::from_millis(500));

    let mut counts = Vec::with_capacity(11);
    for _ in 0..11 {
        counts.push(monitor.materialize_snapshot()?.snapshot().len());
        thread::sleep(Duration::from_millis(100));
    }
    monitor.stop()?;
    Ok(counts)
}

#[test]
#[ignore = "requires root, DAMON sysfs, and DAMON_RS_RUN_KERNEL_TESTS=1"]
fn kernel_keeps_configured_region_bounds() -> TestResult {
    if !kernel_tests_enabled() {
        return Ok(());
    }
    let _serial = KERNEL_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let minimum_limited = collect_region_counts(20, 100)?;
    assert!(
        minimum_limited
            .iter()
            .all(|count| (20..=100).contains(count)),
        "region counts outside 20..=100: {minimum_limited:?}"
    );

    let maximum_limited = collect_region_counts(3, 10)?;
    assert!(
        maximum_limited.iter().all(|count| (3..=10).contains(count)),
        "region counts outside 3..=10: {maximum_limited:?}"
    );
    Ok(())
}

#[test]
#[ignore = "requires root, DAMON sysfs, and DAMON_RS_RUN_KERNEL_TESTS=1"]
fn kernel_honors_per_scheme_apply_intervals() -> TestResult {
    if !kernel_tests_enabled() {
        return Ok(());
    }
    let _serial = KERNEL_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let workload = Workload::spawn()?;
    let pid = Pid::new(workload.pid())?;
    let slow = SchemeConfig::new(Action::Stat, match_all_pattern());
    let mut fast = SchemeConfig::new(Action::Stat, match_all_pattern());
    fast.apply_interval = Duration::from_millis(10);
    let config = monitoring_config(pid, RegionBounds::new(10, 1_000)?, vec![slow, fast]);
    let damon = Damon::new()?;
    let mut session = damon.exclusive_session(&config)?;
    session.start()?;
    thread::sleep(Duration::from_secs(4));

    let (slow_stats, fast_stats) = session.runtime_batch(|batch| {
        let slow_stats = batch.scheme_stats(0, 0)?;
        let fast_stats = batch.cached_scheme_stats(0, 1)?;
        Ok((slow_stats, fast_stats))
    })?;
    session.close()?;

    assert!(slow_stats.regions_tried > 0, "slow scheme was never tried");
    assert!(fast_stats.regions_tried > 0, "fast scheme was never tried");
    assert!(
        fast_stats.regions_tried >= slow_stats.regions_tried.saturating_mul(9),
        "10 ms scheme was tried {} times versus {} for the 100 ms scheme",
        fast_stats.regions_tried,
        slow_stats.regions_tried
    );
    Ok(())
}

#[test]
#[ignore = "requires root, DAMON sysfs, and DAMON_RS_RUN_KERNEL_TESTS=1"]
fn kernel_enforces_scheme_size_quota_for_tried_bytes() -> TestResult {
    if !kernel_tests_enabled() {
        return Ok(());
    }
    let _serial = KERNEL_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let workload = Workload::spawn()?;
    let pid = Pid::new(workload.pid())?;
    let quota_bytes = 1024 * 1024;
    let mut scheme = SchemeConfig::new(Action::Stat, match_all_pattern());
    scheme.quota.size_units = quota_bytes;
    scheme.quota.reset_interval = Duration::from_millis(100);
    let config = monitoring_config(pid, RegionBounds::new(10, 1_000)?, vec![scheme]);
    let damon = Damon::new()?;
    let mut session = damon.exclusive_session(&config)?;
    session.start()?;

    let mut tried_bytes = Vec::with_capacity(20);
    let mut quota_exceeds = 0;
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        let (bytes, stats) = session.runtime_batch(|batch| {
            let bytes = batch.tried_bytes_units(0, 0)?;
            let stats = batch.scheme_stats(0, 0)?;
            Ok((bytes, stats))
        })?;
        tried_bytes.push(bytes);
        quota_exceeds = stats.quota_exceeds;
    }
    session.close()?;

    assert!(
        tried_bytes.iter().any(|bytes| *bytes > 0),
        "quota scenario produced no tried bytes"
    );
    assert!(
        tried_bytes.iter().all(|bytes| *bytes <= quota_bytes),
        "tried bytes exceeded the {quota_bytes}-byte quota: {tried_bytes:?}"
    );
    let saturated_samples = tried_bytes
        .iter()
        .filter(|bytes| **bytes == quota_bytes)
        .count() as u64;
    assert!(
        saturated_samples > 0,
        "the workload never reached the configured quota: {tried_bytes:?}"
    );
    assert!(
        quota_exceeds > 0,
        "kernel reported no quota exceedances for {saturated_samples} saturated samples"
    );
    Ok(())
}

#[test]
#[ignore = "workload helper for the opt-in real-kernel tests"]
fn patterned_memory_workload() {
    let Some(ready_path) = env::var_os(WORKLOAD_READY) else {
        return;
    };
    let mut memory = vec![0_u8; REGION_COUNT * REGION_SIZE];
    for offset in (0..memory.len()).step_by(PAGE_SIZE) {
        memory[offset] = 1;
    }
    fs::write(ready_path, b"ready").expect("signal initialized workload");

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        for region in (0..REGION_COUNT).step_by(2) {
            let start = region * REGION_SIZE;
            let end = start + REGION_SIZE;
            for offset in (start..end).step_by(PAGE_SIZE) {
                let value = black_box(&mut memory[offset]);
                *value = value.wrapping_add(1);
            }
        }
        thread::yield_now();
    }
    black_box(memory);
}
