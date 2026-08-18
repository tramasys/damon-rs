use super::*;

#[test]
fn stages_queries_and_cleans_up_a_monitor() {
    let fixture = Fixture::new("vaddr\npaddr\nfuture_ops\n");
    fixture.disable_online_commits();
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
        None
    );

    let snapshot = monitor.materialize_snapshot().expect("query snapshot");
    let snapshot = snapshot.snapshot();
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
