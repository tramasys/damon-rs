//! High-level API tests against a filesystem fixture.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use damon::sysfs::{
    AccessCountRange, AccessPattern, Action, AgeRange, ContextConfig, DamonAdmin, DamonConfig,
    InitialRegionConfig, KdamondConfig, ProbeFilterType, RegionSizeRange,
};
use damon::{
    AddressUnit, CapabilitySupport, Damon, Error, MonitoringIntervals, Operation, Pid,
    RegionBounds, SnapshotCompleteness, SysfsFeature,
};

#[test]
fn transactional_owned_staging_uses_the_filesystem_backend() {
    let fixture = Fixture::new("vaddr\n");
    let mut context = ContextConfig::new(Operation::VirtualAddress);
    context.intervals = MonitoringIntervals::new(
        Duration::from_millis(2),
        Duration::from_millis(20),
        Duration::from_secs(1),
    )
    .expect("valid intervals");
    context.region_bounds = RegionBounds::new(5, 500).expect("valid bounds");
    let mut kdamond = KdamondConfig::default();
    kdamond.contexts.push(context);
    let mut config = DamonConfig::default();
    config.kdamonds.push(kdamond);

    fixture
        .damon()
        .stage_configuration(&config)
        .expect("stage filesystem configuration transactionally");

    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "1");
    assert_eq!(
        fixture.read("kdamonds/0/contexts/0/monitoring_attrs/intervals/sample_us"),
        "2000"
    );
    assert_eq!(
        fixture.read("kdamonds/0/contexts/0/monitoring_attrs/nr_regions/max"),
        "500"
    );
}

#[test]
fn transactional_filesystem_failure_restores_the_previous_hierarchy() {
    let fixture = Fixture::new("vaddr\n");
    fixture.remove("kdamonds/0/contexts/0/monitoring_attrs/nr_regions/max");
    let mut context = ContextConfig::new(Operation::VirtualAddress);
    context.intervals = MonitoringIntervals::new(
        Duration::from_millis(2),
        Duration::from_millis(20),
        Duration::from_secs(1),
    )
    .expect("valid intervals");
    context.region_bounds = RegionBounds::new(5, 500).expect("valid bounds");
    let mut kdamond = KdamondConfig::default();
    kdamond.contexts.push(context);
    let mut config = DamonConfig::default();
    config.kdamonds.push(kdamond);

    let error = fixture
        .damon()
        .stage_configuration(&config)
        .expect_err("missing late attribute must fail staging");

    assert!(matches!(error, Error::Io { .. }));
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
    assert_eq!(
        fixture.read("kdamonds/0/contexts/0/monitoring_attrs/intervals/sample_us"),
        "5000"
    );
}

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
    let address_unit = AddressUnit::new(4_096).expect("valid address unit");
    context
        .set_address_unit(address_unit)
        .expect("set address unit");
    assert_eq!(
        context.address_unit().expect("read address unit"),
        address_unit
    );
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
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    context.set_scheme_count(1).expect("stage scheme");
    context.set_target_count(1).expect("stage target");

    context.set_probe_count(1).expect("stage probe");
    assert_eq!(context.probe_count().expect("read probe count"), 1);
    context
        .set_probe_count(5)
        .expect("defer the supported probe limit to the running kernel");
    assert_eq!(context.probe_count().expect("read future probe count"), 5);
    context.set_probe_count(1).expect("restore staged probe");
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
        SysfsFeature::ObsoleteTarget,
        SysfsFeature::InitialRegions,
        SysfsFeature::TriedRegions,
        SysfsFeature::TriedRegionsTotalBytes,
    ] {
        assert_eq!(
            capabilities.feature_support(feature),
            CapabilitySupport::Supported,
            "missing {feature:?}"
        );
    }

    fixture.remove("kdamonds/0/contexts/0/monitoring_attrs/probes/0/filters/0/allow");
    let capabilities = kdamond
        .capabilities(0, 0)
        .expect("rediscover individual paths");
    assert_eq!(
        capabilities.feature_support(SysfsFeature::ProbeFilterAllow),
        CapabilitySupport::Unsupported
    );
    assert_eq!(
        capabilities.feature_support(SysfsFeature::ProbeFilterMatching),
        CapabilitySupport::Supported
    );
}

#[test]
fn capability_discovery_marks_unstaged_probe_children() {
    let fixture = Fixture::new("vaddr\n");
    let admin = DamonAdmin::open(fixture.path()).expect("open fixture");
    let kdamond = admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    context.set_scheme_count(1).expect("stage scheme");

    let capabilities = kdamond.capabilities(0, 0).expect("discover features");
    assert_eq!(
        capabilities.feature_support(SysfsFeature::AttributeProbeCount),
        CapabilitySupport::Supported
    );
    for feature in [
        SysfsFeature::ProbeFilterCount,
        SysfsFeature::ProbeFilterType,
        SysfsFeature::ProbeFilterMatching,
        SysfsFeature::ProbeFilterAllow,
        SysfsFeature::ProbeFilterPath,
    ] {
        assert_eq!(
            capabilities.feature_support(feature),
            CapabilitySupport::RequiresStaging,
            "{feature:?} must not be reported as unsupported"
        );
    }
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
    target.set_obsolete(true).expect("mark target obsolete");
    assert!(target.is_obsolete().expect("read obsolete target"));
    target.set_obsolete(false).expect("retain target");

    let scheme = context.scheme(0);
    let future_action = Action::Unknown("future_action".into());
    scheme
        .set_action(&future_action)
        .expect("set future action in fixture");
    assert_eq!(scheme.action().expect("read action"), future_action);
    let pattern = AccessPattern::new(
        RegionSizeRange::new(1, 10).expect("valid size range"),
        AccessCountRange::new(2, 20).expect("valid access range"),
        AgeRange::new(3, 30).expect("valid age range"),
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
    assert_eq!(
        scheme
            .access_pattern()
            .expect("read match-all pattern")
            .accesses()
            .max(),
        u32::MAX
    );
    assert_eq!(
        scheme
            .access_pattern()
            .expect("read match-all pattern")
            .age()
            .max(),
        u32::MAX
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
fn snapshot_preserves_raw_address_units_and_checks_byte_conversions() {
    let fixture = Fixture::new("paddr\n");
    fixture.add_snapshot_regions();
    fixture.write(
        "kdamonds/0/contexts/0/schemes/0/tried_regions/total_bytes",
        "6144\n",
    );
    let admin = DamonAdmin::open(fixture.path()).expect("open fixture");
    let context = admin.kdamond(0).context(0);
    let unit = AddressUnit::new(4_096).expect("valid address unit");
    context.set_address_unit(unit).expect("set address unit");

    let raw_snapshot = context
        .scheme(0)
        .tried_regions(2)
        .expect("read raw snapshot");
    assert_eq!(raw_snapshot.total_units(), 6_144);
    let snapshot = raw_snapshot.with_effective_address_unit(unit);
    assert_eq!(snapshot.address_unit(), unit);
    assert_eq!(
        snapshot.total_bytes().expect("checked byte conversion"),
        25_165_824
    );
    let region = snapshot.region(0).expect("first region");
    assert_eq!(region.start_units(), 4_096);
    assert_eq!(region.start_bytes().expect("convert start"), 16_777_216);
    assert_eq!(region.len_units(), 4_096);
    assert_eq!(region.len_bytes().expect("convert length"), 16_777_216);
    assert_eq!(region.filter_passed_units(), Some(4_096));
    assert_eq!(
        region.filter_passed_bytes().expect("convert filtered size"),
        Some(16_777_216)
    );
}

#[test]
fn snapshot_reports_address_conversion_overflow() {
    let fixture = Fixture::new("paddr\n");
    fixture.add_snapshot_regions();
    let admin = DamonAdmin::open(fixture.path()).expect("open fixture");
    let context = admin.kdamond(0).context(0);
    context
        .set_address_unit(AddressUnit::new(u64::MAX).expect("valid unit"))
        .expect("set address unit");

    let snapshot = context
        .scheme(0)
        .tried_regions(2)
        .expect("read raw snapshot")
        .with_effective_address_unit(AddressUnit::new(u64::MAX).expect("valid unit"));
    assert!(matches!(
        snapshot.total_bytes(),
        Err(Error::AddressConversionOverflow { .. })
    ));
}

#[test]
fn access_and_age_ranges_reject_values_the_active_kernel_type_cannot_hold() {
    let fixture = Fixture::new("vaddr\n");
    fixture.write(
        "kdamonds/0/contexts/0/schemes/0/access_pattern/nr_accesses/max",
        "4294967296\n",
    );
    let scheme = DamonAdmin::open(fixture.path())
        .expect("open fixture")
        .kdamond(0)
        .context(0)
        .scheme(0);

    assert!(matches!(
        scheme.access_pattern(),
        Err(Error::InvalidKernelValue {
            expected: "u32",
            ..
        })
    ));
}

#[test]
fn stages_queries_and_cleans_up_a_monitor() {
    let fixture = Fixture::new("vaddr\npaddr\nfuture_ops\n");
    fixture.add_snapshot_regions();
    fixture.write("kdamonds/0/refresh_ms", "250\n");

    let damon = fixture.damon();
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .region_bounds(10, 128)
        .start()
        .expect("start monitor");

    assert_eq!(monitor.operation(), &Operation::VirtualAddress);
    assert_eq!(monitor.effective_address_unit(), AddressUnit::ONE);
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "1");
    assert_eq!(fixture.read("kdamonds/0/refresh_ms"), "0");
    assert_eq!(fixture.read("kdamonds/0/contexts/0/operations"), "vaddr");
    assert_eq!(fixture.read("kdamonds/0/contexts/0/pause"), "N");
    assert_eq!(
        fixture
            .read("kdamonds/0/contexts/0/monitoring_attrs/probes/nr_probes")
            .trim(),
        "0"
    );
    assert_eq!(
        fixture.read("kdamonds/0/contexts/0/targets/0/pid_target"),
        "42"
    );
    assert_eq!(
        fixture.read("kdamonds/0/contexts/0/targets/0/obsolete_target"),
        "N"
    );
    assert_eq!(
        fixture
            .read("kdamonds/0/contexts/0/targets/0/regions/nr_regions")
            .trim(),
        "0"
    );
    assert_eq!(
        fixture.read("kdamonds/0/contexts/0/schemes/0/apply_interval_us"),
        "0"
    );
    assert!(
        monitor
            .capabilities()
            .supports_operation(&Operation::VirtualAddress)
    );
    assert_eq!(
        monitor
            .capabilities()
            .feature_support(SysfsFeature::ContextPause),
        CapabilitySupport::Supported
    );
    assert_eq!(
        monitor
            .capabilities()
            .feature_support(SysfsFeature::AttributeProbeCount),
        CapabilitySupport::Supported
    );
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
        CapabilitySupport::Supported
    );
    assert_eq!(
        monitor
            .capabilities()
            .operation_support(&Operation::Unknown("future_ops".into())),
        Some(CapabilitySupport::Supported)
    );

    let snapshot = monitor.snapshot().expect("query snapshot");
    assert_eq!(snapshot.total_bytes().expect("convert total"), 6_144);
    assert_eq!(snapshot.len(), 2);
    let first = snapshot.region(0).expect("first region");
    let second = snapshot.region(1).expect("second region");
    assert_eq!(first.start_units(), 4_096);
    assert_eq!(first.end_units(), 8_192);
    assert_eq!(first.len_units(), 4_096);
    assert_eq!(first.len_bytes().expect("convert length"), 4_096);
    assert_eq!(first.nr_accesses(), 7);
    assert_eq!(first.age(), 3);
    assert_eq!(
        first.filter_passed_bytes().expect("convert filtered size"),
        Some(4_096)
    );
    assert_eq!(
        second.filter_passed_bytes().expect("convert filtered size"),
        None
    );
    assert_eq!(first.probe_hits(), &[3, 7]);

    fixture.write("kdamonds/0/state", "on\n");
    monitor.stop().expect("stop monitor");
    assert_eq!(fixture.read("kdamonds/0/state"), "off");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

#[test]
fn high_level_staging_adapts_to_legacy_optional_attributes() {
    let fixture = Fixture::new("vaddr\n");
    for path in [
        "kdamonds/0/refresh_ms",
        "kdamonds/0/contexts/0/avail_operations",
        "kdamonds/0/contexts/0/addr_unit",
        "kdamonds/0/contexts/0/pause",
        "kdamonds/0/contexts/0/monitoring_attrs/probes/nr_probes",
        "kdamonds/0/contexts/0/targets/0/obsolete_target",
        "kdamonds/0/contexts/0/targets/0/regions/nr_regions",
        "kdamonds/0/contexts/0/schemes/0/apply_interval_us",
    ] {
        fixture.remove(path);
    }
    fixture.remove_dir("kdamonds/0/contexts/0/schemes/0/tried_regions");

    let monitor = fixture
        .damon()
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("legacy default attributes may be absent");

    assert_eq!(monitor.operation(), &Operation::VirtualAddress);
    assert!(
        monitor
            .capabilities()
            .supports_operation(&Operation::VirtualAddress)
    );
    for feature in [
        SysfsFeature::PeriodicRefresh,
        SysfsFeature::AvailableOperations,
        SysfsFeature::AddressUnit,
        SysfsFeature::ContextPause,
        SysfsFeature::AttributeProbeCount,
        SysfsFeature::ObsoleteTarget,
        SysfsFeature::InitialRegions,
        SysfsFeature::SchemeApplyInterval,
        SysfsFeature::TriedRegions,
        SysfsFeature::TriedRegionsTotalBytes,
    ] {
        assert_eq!(
            monitor.capabilities().feature_support(feature),
            CapabilitySupport::Unsupported,
            "unexpected support for {feature:?}"
        );
    }

    monitor.stop().expect("stop legacy-compatible monitor");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

#[test]
fn paddr_workflow_uses_unit_one_when_legacy_sysfs_has_no_address_unit() {
    let fixture = Fixture::new("paddr\n");
    fixture.remove("kdamonds/0/contexts/0/addr_unit");
    fixture.write("kdamonds/0/contexts/0/targets/0/regions/0/start", "4096\n");
    fixture.write("kdamonds/0/contexts/0/targets/0/regions/0/end", "8192\n");

    let monitor = fixture
        .damon()
        .paddr()
        .region_units(InitialRegionConfig::new(4_096, 8_192).expect("valid region"))
        .start()
        .expect("legacy paddr workflow with the neutral unit");

    assert_eq!(monitor.operation(), &Operation::PhysicalAddress);
    assert_eq!(monitor.effective_address_unit(), AddressUnit::ONE);
    assert_eq!(
        monitor
            .capabilities()
            .feature_support(SysfsFeature::AddressUnit),
        CapabilitySupport::Unsupported
    );
    monitor.stop().expect("restore legacy hierarchy");
}

#[test]
fn paddr_workflow_rejects_non_default_unit_when_legacy_attribute_is_absent() {
    let fixture = Fixture::new("paddr\n");
    fixture.remove("kdamonds/0/contexts/0/addr_unit");
    fixture.write("kdamonds/0/contexts/0/targets/0/regions/0/start", "1\n");
    fixture.write("kdamonds/0/contexts/0/targets/0/regions/0/end", "2\n");

    let error = fixture
        .damon()
        .paddr()
        .address_unit(AddressUnit::new(4_096).expect("valid unit"))
        .region_units(InitialRegionConfig::new(1, 2).expect("valid region"))
        .start()
        .expect_err("missing non-default address-unit control must fail");

    assert!(matches!(
        error,
        Error::UnsupportedFeature {
            feature: "DAMON address units"
        }
    ));
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

#[test]
fn snapshot_parses_sparse_kernel_indexes_and_reports_partial_materialization() {
    let fixture = Fixture::new("vaddr\n");
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
    let snapshot = monitor.snapshot().expect("read sparse results");

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
fn restores_an_existing_stopped_configuration() {
    let fixture = Fixture::new("vaddr\n");
    fixture.write("kdamonds/nr_kdamonds", "1\n");
    fixture.write("kdamonds/0/contexts/nr_contexts", "1\n");
    fixture.write("kdamonds/0/contexts/0/operations", "vaddr\n");
    fixture.write("kdamonds/0/contexts/0/targets/nr_targets", "1\n");
    fixture.write("kdamonds/0/contexts/0/targets/0/pid_target", "77\n");
    fixture.write("kdamonds/0/contexts/0/schemes/nr_schemes", "0\n");
    let damon = fixture.damon();

    let monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("replace a stopped configuration transactionally");
    monitor.stop().expect("restore preceding configuration");

    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "1");
    assert_eq!(fixture.read("kdamonds/0/contexts/nr_contexts"), "1");
    assert_eq!(
        fixture.read("kdamonds/0/contexts/0/targets/0/pid_target"),
        "77"
    );
    assert_eq!(
        fixture.read("kdamonds/0/contexts/0/schemes/nr_schemes"),
        "0"
    );
}

#[test]
fn serializes_high_level_sessions_with_the_advisory_lock() {
    let fixture = Fixture::new("vaddr\n");
    let first = fixture.damon();
    let second = fixture.damon();
    let monitor = first
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start first monitor");

    let error = second
        .monitor_pid(Pid::new(43).expect("valid pid"))
        .start()
        .expect_err("a second cooperating session must not race");
    assert!(matches!(error, Error::SessionLockBusy { .. }));

    monitor.stop().expect("stop first monitor");
}

#[test]
fn refuses_to_stop_a_replaced_kdamond_thread() {
    let fixture = Fixture::new("vaddr\n");
    let damon = fixture.damon();
    let monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/0/pid", "9002\n");
    let error = monitor
        .stop()
        .expect_err("a replacement thread must be preserved");
    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the kdamond kernel-thread ID changed"
        }
    ));
    assert_eq!(fixture.read("kdamonds/0/state"), "on");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "1");
}

#[test]
fn refuses_to_stop_an_externally_reconfigured_slot() {
    let fixture = Fixture::new("vaddr\n");
    let damon = fixture.damon();
    let monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/0/contexts/0/targets/0/pid_target", "77\n");
    let error = monitor
        .stop()
        .expect_err("a replacement configuration must be preserved");
    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the staged writable configuration changed"
        }
    ));
    assert_eq!(fixture.read("kdamonds/0/state"), "on");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "1");
}

#[test]
fn refuses_to_stop_when_extended_typed_configuration_changes() {
    for (path, value, expected_reason) in [
        (
            "kdamonds/0/refresh_ms",
            "100\n",
            "the staged writable configuration changed",
        ),
        (
            "kdamonds/0/contexts/0/pause",
            "Y\n",
            "the staged writable configuration changed",
        ),
        (
            "kdamonds/0/contexts/0/monitoring_attrs/probes/nr_probes",
            "1\n",
            "the staged writable configuration changed",
        ),
        (
            "kdamonds/0/contexts/0/targets/0/obsolete_target",
            "Y\n",
            "the staged writable configuration changed",
        ),
        (
            "kdamonds/0/contexts/0/targets/0/regions/nr_regions",
            "1\n",
            "the staged writable configuration changed",
        ),
        (
            "kdamonds/0/contexts/0/schemes/0/apply_interval_us",
            "100\n",
            "the staged writable configuration changed",
        ),
    ] {
        let fixture = Fixture::new("vaddr\n");
        let monitor = fixture
            .damon()
            .monitor_pid(Pid::new(42).expect("valid pid"))
            .start()
            .expect("start monitor");

        fixture.write(path, value);
        let error = monitor
            .stop()
            .expect_err("changed staged input must invalidate ownership");

        match error {
            Error::OwnershipLost { reason } => assert_eq!(reason, expected_reason, "{path}"),
            other => panic!("unexpected ownership error for {path}: {other:?}"),
        }
        assert_eq!(fixture.read("kdamonds/0/state"), "on");
    }
}

#[test]
fn refuses_to_stop_when_auxiliary_scheme_configuration_changes() {
    let fixture = Fixture::new("vaddr\n");
    let monitor = fixture
        .damon()
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/0/contexts/0/schemes/0/target_nid", "7\n");
    let error = monitor
        .stop()
        .expect_err("changed auxiliary scheme input must invalidate ownership");

    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the staged writable configuration changed"
        }
    ));
    assert_eq!(fixture.read("kdamonds/0/state"), "on");
}

#[test]
fn ownership_tracks_unknown_future_configuration_attributes() {
    let fixture = Fixture::new("vaddr\n");
    fixture.write("kdamonds/0/contexts/0/future_kernel_tunable", "enabled\n");
    let monitor = fixture
        .damon()
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/0/contexts/0/future_kernel_tunable", "disabled\n");
    let error = monitor
        .stop()
        .expect_err("an unknown writable input must invalidate ownership");

    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the staged writable configuration changed"
        }
    ));
}

#[test]
fn rolls_back_when_virtual_address_operations_are_missing() {
    let fixture = Fixture::new("paddr\n");
    let damon = fixture.damon();

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
fn setup_rollback_preserves_a_concurrently_started_slot() {
    let fixture = Fixture::new("paddr\n");
    let damon = fixture.damon();
    fixture.write("kdamonds/0/state", "on\n");
    fixture.write("kdamonds/0/pid", "9002\n");
    assert_eq!(fixture.read("kdamonds/0/state"), "on\n");

    let error = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect_err("a concurrently started replacement must be preserved");

    assert!(
        matches!(
            error,
            Error::Rollback {
                ref operation,
                ref rollback,
            } if matches!(**operation, Error::KdamondRunning { index: 0 })
                && matches!(**rollback, Error::KdamondRunning { index: 0 })
        ),
        "unexpected error: {error:?}, state: {:?}, count: {:?}",
        fixture.read("kdamonds/0/state"),
        fixture.read("kdamonds/nr_kdamonds")
    );
    assert_eq!(fixture.read("kdamonds/0/state"), "on\n");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "1");
}

#[test]
fn cleans_up_after_the_kernel_thread_has_already_stopped() {
    let fixture = Fixture::new("vaddr\n");
    let damon = fixture.damon();
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
    let damon = fixture.damon();

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
    let snapshot = monitor.snapshot().expect("query snapshot");
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
        .snapshot()
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
    let damon = fixture.damon();
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
    let damon = fixture.damon();
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .region_bounds(3, u64::MAX)
        .start()
        .expect("start monitor");

    let snapshot = monitor
        .snapshot()
        .expect("large maximum remains only an allocation hint");
    assert!(snapshot.is_empty());
    assert_eq!(snapshot.total_bytes().expect("convert total"), 0);

    fixture.write("kdamonds/0/state", "on\n");
    monitor.stop().expect("stop monitor");
}

#[test]
fn drop_performs_best_effort_cleanup() {
    let fixture = Fixture::new("vaddr\n");
    let damon = fixture.damon();

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
            ("kdamonds/0/contexts/0/targets/0/obsolete_target", "N\n"),
            ("kdamonds/0/contexts/0/targets/0/regions/nr_regions", "0\n"),
            ("kdamonds/0/contexts/0/schemes/nr_schemes", "0\n"),
            ("kdamonds/0/contexts/0/schemes/0/action", "stat\n"),
            ("kdamonds/0/contexts/0/schemes/0/target_nid", "-1\n"),
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
        fixture.add_scheme_defaults();

        fixture
    }

    fn add_scheme_defaults(&self) {
        for (path, value) in [
            ("quotas/ms", "0\n"),
            ("quotas/bytes", "0\n"),
            ("quotas/reset_interval_ms", "0\n"),
            ("quotas/effective_bytes", "0\n"),
            ("quotas/weights/sz_permil", "0\n"),
            ("quotas/weights/nr_accesses_permil", "0\n"),
            ("quotas/weights/age_permil", "0\n"),
            ("watermarks/metric", "none\n"),
            ("watermarks/interval_us", "0\n"),
            ("watermarks/high", "0\n"),
            ("watermarks/mid", "0\n"),
            ("watermarks/low", "0\n"),
            ("filters/nr_filters", "0\n"),
            ("stats/nr_tried", "0\n"),
            ("stats/sz_tried", "0\n"),
            ("stats/nr_applied", "0\n"),
            ("stats/sz_applied", "0\n"),
            ("stats/qt_exceeds", "0\n"),
        ] {
            self.write(&format!("kdamonds/0/contexts/0/schemes/0/{path}"), value);
        }
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
        self.write(
            "kdamonds/0/contexts/0/schemes/0/tried_regions/0/probes/0/hits",
            "3\n",
        );
        self.write(
            "kdamonds/0/contexts/0/schemes/0/tried_regions/0/probes/1/hits",
            "7\n",
        );
    }

    fn damon(&self) -> Damon {
        self.write("kdamonds/0/pid", "9001\n");
        Damon::at_with_lock(self.path(), self.root.join("damon-rs.lock")).expect("open fixture")
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
