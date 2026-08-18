use super::*;

#[test]
fn snapshot_parses_sparse_kernel_indexes_and_reports_partial_materialization() {
    let fixture = Fixture::new("vaddr\n");
    fixture.disable_online_commits();
    fixture.add_snapshot_regions();
    fixture.remove_dir("kdamonds/0/contexts/0/schemes/0/tried_regions/1");
    let region = "kdamonds/0/contexts/0/schemes/0/tried_regions/4";
    for (name, value) in [
        ("start", "8192\n"),
        ("end", "10240\n"),
        ("nr_accesses", "2\n"),
        ("age", "8\n"),
    ] {
        fixture.write(&format!("{region}/{name}"), value);
    }
    fixture.remove_dir("kdamonds/0/contexts/0/schemes/0/tried_regions/0/probes/1");
    fixture.write(
        "kdamonds/0/contexts/0/schemes/0/tried_regions/0/probes/5/hits",
        "9\n",
    );
    fixture.write(
        "kdamonds/0/contexts/0/schemes/0/tried_regions/total_bytes",
        "7000\n",
    );

    let mut monitor = fixture
        .damon()
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");
    let snapshot = monitor.materialize_snapshot().expect("read sparse results");
    let snapshot = snapshot.snapshot();

    assert_eq!(snapshot.len(), 2);
    assert_eq!(
        snapshot
            .region(1)
            .expect("second sparse region")
            .start_units(),
        8192
    );
    let first = snapshot.region(0).expect("first region");
    assert_eq!(first.probe_indices(), &[0, 5]);
    assert_eq!(first.probe_hits(), &[3, 9]);
    assert_eq!(
        snapshot.completeness(),
        SnapshotCompleteness::Partial {
            reported_units: 7000,
            materialized_units: 6144,
        }
    );
    assert_eq!(snapshot.total_units(), 7000);

    fixture.write("kdamonds/0/state", "on\n");
    monitor.stop().expect("stop monitor");
}

#[test]
fn supports_tried_regions_without_total_bytes() {
    let fixture = Fixture::new("vaddr\n");
    fixture.disable_online_commits();
    fixture.add_snapshot_regions();
    fixture.remove("kdamonds/0/contexts/0/schemes/0/tried_regions/total_bytes");
    let damon = fixture.damon();
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("tried-region directory provides query support");

    assert_eq!(
        monitor
            .capabilities()
            .feature_support(SysfsFeature::TriedRegions),
        CapabilitySupport::Supported
    );
    assert_eq!(
        monitor
            .capabilities()
            .feature_support(SysfsFeature::TriedRegionsTotalBytes),
        CapabilitySupport::Unsupported
    );
    let snapshot = monitor.materialize_snapshot().expect("query snapshot");
    let snapshot = snapshot.snapshot();
    assert_eq!(snapshot.total_bytes().expect("convert total"), 6_144);

    fixture.write("kdamonds/0/state", "on\n");
    monitor.stop().expect("stop monitor");
}

#[test]
fn monitoring_works_without_optional_tried_region_queries() {
    let fixture = Fixture::new("vaddr\n");
    fixture.remove_dir("kdamonds/0/contexts/0/schemes/0/tried_regions");
    let damon = fixture.damon();

    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("monitoring does not require optional query support");
    assert_eq!(
        monitor
            .capabilities()
            .feature_support(SysfsFeature::TriedRegions),
        CapabilitySupport::Unsupported
    );

    let error = monitor
        .materialize_snapshot()
        .expect_err("snapshot query support must be detected before its command");

    assert!(matches!(
        error,
        Error::UnsupportedFeature {
            feature: "DAMOS tried-region queries"
        }
    ));
    monitor.stop().expect("stop monitor without query support");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

#[test]
fn snapshot_detects_a_kernel_thread_that_stopped() {
    let fixture = Fixture::new("vaddr\n");
    let damon = fixture.damon();
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/0/state", "off\n");
    let error = monitor
        .materialize_snapshot()
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
    let damon = fixture.damon();
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
    let damon = fixture.damon();
    let monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/nr_kdamonds", "2\n");
    let error = monitor
        .stop()
        .expect_err("externally changed configuration must be preserved");

    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the staged kdamond count changed"
        }
    ));
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "2\n");
}

#[test]
fn rejects_invalid_regions_materialized_by_the_kernel() {
    let fixture = Fixture::new("vaddr\n");
    fixture.disable_online_commits();
    fixture.add_snapshot_regions();
    fixture.write(
        "kdamonds/0/contexts/0/schemes/0/tried_regions/0/end",
        "1024\n",
    );
    let damon = fixture.damon();
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    let error = monitor
        .materialize_snapshot()
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
    fixture.disable_online_commits();
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
    let damon = fixture.damon();
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    let error = monitor
        .materialize_snapshot()
        .expect_err("overflowing snapshot total must fail");
    assert!(matches!(error, Error::SnapshotSizeOverflow));

    fixture.write("kdamonds/0/state", "on\n");
    monitor.stop().expect("stop monitor");
}

#[test]
fn bounds_eager_snapshot_allocation() {
    let fixture = Fixture::new("vaddr\n");
    fixture.disable_online_commits();
    let damon = fixture.damon();
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .region_bounds(3, u64::MAX)
        .start()
        .expect("start monitor");

    let snapshot = monitor
        .materialize_snapshot()
        .expect("large maximum remains only an allocation hint");
    let snapshot = snapshot.snapshot();
    assert!(snapshot.is_empty());
    assert_eq!(snapshot.total_bytes().expect("convert total"), 0);

    fixture.write("kdamonds/0/state", "on\n");
    monitor.stop().expect("stop monitor");
}
