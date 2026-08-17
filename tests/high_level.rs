//! High-level API tests against a filesystem fixture.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use damon::sysfs::{
    AccessPattern, AccessPatternRange, Action, DamonAdmin, MAX_PROBES, ProbeFilterType,
};
use damon::{Damon, Error, MonitoringIntervals, Operation, Pid, RegionBounds, SysfsFeature};

#[test]
fn low_level_context_attributes_round_trip() {
    let fixture = Fixture::new("vaddr\nfvaddr\npaddr\n");
    let admin = DamonAdmin::open(fixture.path()).expect("open fixture");
    let kdamond = admin.kdamond(0);
    assert_eq!(kdamond.pid().expect("read stopped PID"), None);
    kdamond
        .set_refresh_interval(Duration::from_millis(250))
        .expect("set refresh interval");
    assert_eq!(
        kdamond.refresh_interval().expect("read refresh interval"),
        Duration::from_millis(250)
    );

    let context = kdamond.context(0);
    context
        .set_operation(&Operation::FixedVirtualAddress)
        .expect("set operation");
    assert_eq!(
        context.operation().expect("read operation"),
        Operation::FixedVirtualAddress
    );
    context.set_address_unit(4_096).expect("set address unit");
    assert_eq!(context.address_unit().expect("read address unit"), 4_096);
    context.set_paused(true).expect("pause context");
    assert!(context.is_paused().expect("read pause state"));

    let intervals = MonitoringIntervals::new(
        Duration::from_micros(10),
        Duration::from_micros(100),
        Duration::from_secs(1),
    )
    .expect("valid intervals");
    context.set_intervals(intervals).expect("set intervals");
    assert_eq!(context.intervals().expect("read intervals"), intervals);
    let bounds = RegionBounds::new(3, 128).expect("valid bounds");
    context.set_region_bounds(bounds).expect("set bounds");
    assert_eq!(context.region_bounds().expect("read bounds"), bounds);
}

#[test]
fn low_level_probe_attributes_and_capabilities_are_individual() {
    let fixture = Fixture::new("vaddr\n");
    fixture.add_probe_filter_files();
    let admin = DamonAdmin::open(fixture.path()).expect("open fixture");
    let kdamond = admin.kdamond(0);
    let context = kdamond.context(0);

    context.set_probe_count(1).expect("stage probe");
    assert_eq!(context.probe_count().expect("read probe count"), 1);
    assert!(context.set_probe_count(MAX_PROBES + 1).is_err());
    let probe = context.probe(0);
    probe.set_filter_count(1).expect("stage probe filter");
    assert_eq!(probe.filter_count().expect("read filter count"), 1);
    let filter = probe.filter(0);
    filter
        .set_filter_type(&ProbeFilterType::MemoryControlGroup)
        .expect("set filter type");
    filter.set_matching(true).expect("set matching");
    filter.set_allowed(true).expect("set allow");
    filter
        .set_cgroup_path("/sys/fs/cgroup/workload")
        .expect("set cgroup path");
    assert_eq!(
        filter.filter_type().expect("read filter type"),
        ProbeFilterType::MemoryControlGroup
    );
    assert!(filter.matching().expect("read matching"));
    assert!(filter.allowed().expect("read allow"));
    assert_eq!(
        filter.cgroup_path().expect("read cgroup path"),
        "/sys/fs/cgroup/workload"
    );

    let capabilities = kdamond.capabilities(0, 0).expect("discover features");
    for feature in [
        SysfsFeature::PeriodicRefresh,
        SysfsFeature::AvailableOperations,
        SysfsFeature::AddressUnit,
        SysfsFeature::ContextPause,
        SysfsFeature::AttributeProbeCount,
        SysfsFeature::ProbeFilterCount,
        SysfsFeature::ProbeFilterType,
        SysfsFeature::ProbeFilterMatching,
        SysfsFeature::ProbeFilterAllow,
        SysfsFeature::ProbeFilterPath,
        SysfsFeature::SchemeApplyInterval,
        SysfsFeature::TriedRegions,
        SysfsFeature::TriedRegionsTotalBytes,
    ] {
        assert!(capabilities.has(feature), "missing {feature:?}");
    }

    fixture.remove("kdamonds/0/contexts/0/monitoring_attrs/probes/0/filters/0/allow");
    let capabilities = kdamond
        .capabilities(0, 0)
        .expect("rediscover individual paths");
    assert!(!capabilities.has(SysfsFeature::ProbeFilterAllow));
    assert!(capabilities.has(SysfsFeature::ProbeFilterMatching));
}

#[test]
fn low_level_target_and_scheme_attributes_round_trip() {
    let fixture = Fixture::new("vaddr\n");
    let admin = DamonAdmin::open(fixture.path()).expect("open fixture");
    let context = admin.kdamond(0).context(0);

    let target = context.target(0);
    let pid = Pid::new(42).expect("valid PID");
    target.set_pid(pid).expect("set target PID");
    assert_eq!(target.pid().expect("read target PID"), Some(pid));
    target.clear_pid().expect("clear target PID");
    assert_eq!(target.pid().expect("read cleared PID"), None);

    let scheme = context.scheme(0);
    let future_action = Action::Unknown("future_action".into());
    scheme
        .set_action(&future_action)
        .expect("set future action in fixture");
    assert_eq!(scheme.action().expect("read action"), future_action);
    let pattern = AccessPattern::new(
        AccessPatternRange::new(1, 10).expect("valid size range"),
        AccessPatternRange::new(2, 20).expect("valid access range"),
        AccessPatternRange::new(3, 30).expect("valid age range"),
    );
    scheme.set_access_pattern(pattern).expect("set pattern");
    assert_eq!(scheme.access_pattern().expect("read pattern"), pattern);
    scheme.set_match_all().expect("set match-all pattern");
    assert_eq!(
        scheme
            .access_pattern()
            .expect("read match-all pattern")
            .size()
            .max(),
        u64::MAX
    );
    scheme
        .set_apply_interval(Duration::from_micros(500))
        .expect("set apply interval");
    assert_eq!(
        scheme.apply_interval().expect("read apply interval"),
        Duration::from_micros(500)
    );
}

#[test]
fn stages_queries_and_cleans_up_a_monitor() {
    let fixture = Fixture::new("vaddr\npaddr\nfuture_ops\n");
    fixture.add_snapshot_regions();

    let damon = Damon::at(fixture.path()).expect("open fixture");
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .region_bounds(10, 128)
        .start()
        .expect("start monitor");

    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "1");
    assert_eq!(fixture.read("kdamonds/0/contexts/0/operations"), "vaddr");
    assert_eq!(
        fixture.read("kdamonds/0/contexts/0/targets/0/pid_target"),
        "42"
    );
    assert!(
        monitor
            .capabilities()
            .supports_operation(&Operation::VirtualAddress)
    );
    assert!(monitor.capabilities().has(SysfsFeature::ContextPause));
    assert!(
        monitor
            .capabilities()
            .has(SysfsFeature::AttributeProbeCount)
    );
    assert!(monitor.capabilities().has(SysfsFeature::TriedRegions));
    assert!(
        monitor
            .capabilities()
            .has(SysfsFeature::TriedRegionsTotalBytes)
    );
    assert_eq!(
        monitor.capabilities().operations()[2],
        Operation::Unknown("future_ops".into())
    );

    let snapshot = monitor.snapshot().expect("query snapshot");
    assert_eq!(snapshot.total_bytes(), 6_144);
    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot.regions()[0].start(), 4_096);
    assert_eq!(snapshot.regions()[0].end(), 8_192);
    assert_eq!(snapshot.regions()[0].len(), 4_096);
    assert_eq!(snapshot.regions()[0].nr_accesses(), 7);
    assert_eq!(snapshot.regions()[0].age(), 3);
    assert_eq!(snapshot.regions()[0].filter_passed_bytes(), Some(4_096));
    assert_eq!(snapshot.regions()[1].filter_passed_bytes(), None);

    fixture.write("kdamonds/0/state", "on\n");
    monitor.stop().expect("stop monitor");
    assert_eq!(fixture.read("kdamonds/0/state"), "off");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

#[test]
fn refuses_to_replace_an_existing_configuration() {
    let fixture = Fixture::new("vaddr\n");
    fixture.write("kdamonds/nr_kdamonds", "2\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");

    let error = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect_err("existing configuration must be preserved");

    assert!(matches!(error, Error::InUse { kdamonds: 2 }));
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "2\n");
}

#[test]
fn rolls_back_when_virtual_address_operations_are_missing() {
    let fixture = Fixture::new("paddr\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");

    let error = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect_err("vaddr must be checked at runtime");

    assert!(matches!(
        error,
        Error::UnsupportedOperation {
            operation: Operation::VirtualAddress
        }
    ));
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

#[test]
fn cleans_up_after_the_kernel_thread_has_already_stopped() {
    let fixture = Fixture::new("vaddr\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");
    let monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/0/state", "off\n");
    monitor.stop().expect("clean up stopped monitor");

    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

#[test]
fn validates_before_mutating_the_global_interface() {
    let fixture = Fixture::new("vaddr\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");

    let error = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .region_bounds(2, 100)
        .start()
        .expect_err("invalid bounds must fail");

    assert!(matches!(
        error,
        Error::InvalidConfiguration {
            field: "minimum regions",
            ..
        }
    ));
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0\n");
}

#[test]
fn supports_tried_regions_without_total_bytes() {
    let fixture = Fixture::new("vaddr\n");
    fixture.add_snapshot_regions();
    fixture.remove("kdamonds/0/contexts/0/schemes/0/tried_regions/total_bytes");
    let damon = Damon::at(fixture.path()).expect("open fixture");
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("tried-region directory provides query support");

    assert!(monitor.capabilities().has(SysfsFeature::TriedRegions));
    assert!(
        !monitor
            .capabilities()
            .has(SysfsFeature::TriedRegionsTotalBytes)
    );
    let snapshot = monitor.snapshot().expect("query snapshot");
    assert_eq!(snapshot.total_bytes(), 6_144);

    fixture.write("kdamonds/0/state", "on\n");
    monitor.stop().expect("stop monitor");
}

#[test]
fn rolls_back_when_tried_region_queries_are_unsupported() {
    let fixture = Fixture::new("vaddr\n");
    fixture.remove_dir("kdamonds/0/contexts/0/schemes/0/tried_regions");
    let damon = Damon::at(fixture.path()).expect("open fixture");

    let error = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect_err("query support must be detected");

    assert!(matches!(
        error,
        Error::UnsupportedFeature {
            feature: "DAMOS tried-region queries"
        }
    ));
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

#[test]
fn snapshot_detects_a_kernel_thread_that_stopped() {
    let fixture = Fixture::new("vaddr\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/0/state", "off\n");
    let error = monitor
        .snapshot()
        .expect_err("stopped kernel thread cannot produce a snapshot");

    assert!(matches!(error, Error::NotRunning));
    assert!(!monitor.is_running().expect("read cached stopped state"));
    assert_eq!(fixture.read("kdamonds/0/state"), "off\n");
    monitor.stop().expect("remove stopped monitor");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

#[test]
fn reports_an_unexpected_kernel_state() {
    let fixture = Fixture::new("vaddr\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");
    let monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/0/state", "future-state\n");
    let error = monitor
        .is_running()
        .expect_err("unknown state must not be treated as running");

    assert!(matches!(
        error,
        Error::UnexpectedKdamondState { state } if &*state == "future-state"
    ));
    fixture.write("kdamonds/0/state", "off\n");
    monitor.stop().expect("remove stopped monitor");
}

#[test]
fn cleanup_preserves_an_externally_changed_configuration() {
    let fixture = Fixture::new("vaddr\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");
    let monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/nr_kdamonds", "2\n");
    let error = monitor
        .stop()
        .expect_err("externally changed configuration must be preserved");

    assert!(matches!(error, Error::InUse { kdamonds: 2 }));
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "2\n");
}

#[test]
fn rejects_invalid_regions_materialized_by_the_kernel() {
    let fixture = Fixture::new("vaddr\n");
    fixture.add_snapshot_regions();
    fixture.write(
        "kdamonds/0/contexts/0/schemes/0/tried_regions/0/end",
        "1024\n",
    );
    let damon = Damon::at(fixture.path()).expect("open fixture");
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    let error = monitor
        .snapshot()
        .expect_err("invalid kernel region must fail");
    assert!(matches!(
        error,
        Error::InvalidRegion {
            start: 4_096,
            end: 1_024
        }
    ));

    fixture.write("kdamonds/0/state", "on\n");
    monitor.stop().expect("stop monitor");
}

#[test]
fn rejects_overflow_in_a_computed_snapshot_total() {
    let fixture = Fixture::new("vaddr\n");
    fixture.add_snapshot_regions();
    fixture.remove("kdamonds/0/contexts/0/schemes/0/tried_regions/total_bytes");
    fixture.write(
        "kdamonds/0/contexts/0/schemes/0/tried_regions/0/start",
        "0\n",
    );
    fixture.write(
        "kdamonds/0/contexts/0/schemes/0/tried_regions/0/end",
        "18446744073709551615\n",
    );
    fixture.write(
        "kdamonds/0/contexts/0/schemes/0/tried_regions/1/start",
        "0\n",
    );
    fixture.write("kdamonds/0/contexts/0/schemes/0/tried_regions/1/end", "1\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    let error = monitor
        .snapshot()
        .expect_err("overflowing snapshot total must fail");
    assert!(matches!(error, Error::SnapshotSizeOverflow));

    fixture.write("kdamonds/0/state", "on\n");
    monitor.stop().expect("stop monitor");
}

#[test]
fn bounds_eager_snapshot_allocation() {
    let fixture = Fixture::new("vaddr\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .region_bounds(3, usize::MAX)
        .start()
        .expect("start monitor");

    let snapshot = monitor
        .snapshot()
        .expect("large maximum remains only an allocation hint");
    assert!(snapshot.is_empty());
    assert_eq!(snapshot.total_bytes(), 0);

    fixture.write("kdamonds/0/state", "on\n");
    monitor.stop().expect("stop monitor");
}

#[test]
fn drop_performs_best_effort_cleanup() {
    let fixture = Fixture::new("vaddr\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");

    {
        let _monitor = damon
            .monitor_pid(Pid::new(42).expect("valid pid"))
            .start()
            .expect("start monitor");
    }

    assert_eq!(fixture.read("kdamonds/0/state"), "off");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(available_operations: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "damon-rs-integration-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let fixture = Self { root };

        for (path, value) in [
            ("kdamonds/nr_kdamonds", "0\n"),
            ("kdamonds/0/state", "off\n"),
            ("kdamonds/0/pid", "-1\n"),
            ("kdamonds/0/refresh_ms", "0\n"),
            ("kdamonds/0/contexts/nr_contexts", "0\n"),
            (
                "kdamonds/0/contexts/0/avail_operations",
                available_operations,
            ),
            ("kdamonds/0/contexts/0/operations", "\n"),
            ("kdamonds/0/contexts/0/addr_unit", "1\n"),
            ("kdamonds/0/contexts/0/pause", "0\n"),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/intervals/sample_us",
                "5000\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/intervals/aggr_us",
                "100000\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/intervals/update_us",
                "60000000\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/nr_regions/min",
                "10\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/nr_regions/max",
                "1000\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/probes/nr_probes",
                "0\n",
            ),
            ("kdamonds/0/contexts/0/targets/nr_targets", "0\n"),
            ("kdamonds/0/contexts/0/targets/0/pid_target", "0\n"),
            ("kdamonds/0/contexts/0/schemes/nr_schemes", "0\n"),
            ("kdamonds/0/contexts/0/schemes/0/action", "stat\n"),
            ("kdamonds/0/contexts/0/schemes/0/apply_interval_us", "0\n"),
            (
                "kdamonds/0/contexts/0/schemes/0/tried_regions/total_bytes",
                "0\n",
            ),
        ] {
            fixture.write(path, value);
        }

        for range in ["sz", "nr_accesses", "age"] {
            fixture.write(
                &format!("kdamonds/0/contexts/0/schemes/0/access_pattern/{range}/min"),
                "0\n",
            );
            fixture.write(
                &format!("kdamonds/0/contexts/0/schemes/0/access_pattern/{range}/max"),
                "0\n",
            );
        }

        fixture
    }

    fn add_probe_filter_files(&self) {
        for (path, value) in [
            (
                "kdamonds/0/contexts/0/monitoring_attrs/probes/0/filters/nr_filters",
                "0\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/probes/0/filters/0/type",
                "anon\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/probes/0/filters/0/matching",
                "N\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/probes/0/filters/0/allow",
                "N\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/probes/0/filters/0/path",
                "\n",
            ),
        ] {
            self.write(path, value);
        }
    }

    fn add_snapshot_regions(&self) {
        self.write(
            "kdamonds/0/contexts/0/schemes/0/tried_regions/total_bytes",
            "6144\n",
        );
        for (index, start, end, accesses, age) in
            [(0, 4_096, 8_192, 7, 3), (1, 8_192, 10_240, 2, 8)]
        {
            let base = format!("kdamonds/0/contexts/0/schemes/0/tried_regions/{index}");
            self.write(&format!("{base}/start"), &format!("{start}\n"));
            self.write(&format!("{base}/end"), &format!("{end}\n"));
            self.write(&format!("{base}/nr_accesses"), &format!("{accesses}\n"));
            self.write(&format!("{base}/age"), &format!("{age}\n"));
        }
        self.write(
            "kdamonds/0/contexts/0/schemes/0/tried_regions/0/sz_filter_passed",
            "4096\n",
        );
    }

    fn path(&self) -> &Path {
        self.root.as_path()
    }

    fn write(&self, path: &str, value: &str) {
        let path = self.root.join(path);
        fs::create_dir_all(path.parent().expect("fixture path has parent"))
            .expect("create fixture directory");
        fs::write(path, value).expect("write fixture value");
    }

    fn read(&self, path: &str) -> String {
        fs::read_to_string(self.root.join(path)).expect("read fixture value")
    }

    fn remove(&self, path: &str) {
        fs::remove_file(self.root.join(path)).expect("remove fixture value");
    }

    fn remove_dir(&self, path: &str) {
        fs::remove_dir_all(self.root.join(path)).expect("remove fixture directory");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
