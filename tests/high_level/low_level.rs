use super::*;

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
