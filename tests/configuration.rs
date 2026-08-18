//! Public API checks for owned DAMON configurations.

use std::time::Duration;

use damon::sysfs::{
    AccessCountRange, AccessPattern, Action, ByteSizeRange, ContextConfig, DamonConfig,
    FilterConfig, FilterLayer, InitialRegionConfig, KdamondConfig, Operation,
    OperationAttributesConfig, ProbeConfig, ProbePreparationAction, ProbePreparationConfig,
    QuotaConfig, QuotaGoalConfig, QuotaGoalMetric, RegionSizeRange, SampleControlConfig,
    SampleFilterConfig, SamplePrimitivesConfig, SchemeConfig, SchemeFilterType, TargetConfig,
};
use damon::{
    AddressUnit, Damon, Error, ManagedHierarchy, ManagedKdamond, Pid, ProcessTarget, RegionBounds,
};

#[test]
fn managed_hierarchy_lifecycle_is_exposed_by_the_public_api() {
    let api = (
        Damon::managed_hierarchy as fn(&Damon, &DamonConfig) -> Result<ManagedHierarchy, Error>,
        ManagedHierarchy::kdamond_count as fn(&ManagedHierarchy) -> usize,
        ManagedHierarchy::start_all as fn(&mut ManagedHierarchy) -> Result<(), Error>,
        ManagedHierarchy::stop_all as fn(&mut ManagedHierarchy) -> Result<(), Error>,
        ManagedHierarchy::is_running as fn(&ManagedHierarchy, usize) -> Result<bool, Error>,
        ManagedHierarchy::configuration as fn(&ManagedHierarchy) -> Result<DamonConfig, Error>,
        ManagedHierarchy::update_configuration
            as fn(&mut ManagedHierarchy, &DamonConfig, &[usize]) -> Result<(), Error>,
        ManagedHierarchy::runtime
            as for<'a> fn(&'a mut ManagedHierarchy, usize) -> Result<ManagedKdamond<'a>, Error>,
        ManagedHierarchy::close as fn(ManagedHierarchy) -> Result<(), Error>,
    );
    std::hint::black_box(api);
}

#[test]
fn process_targets_are_constructible_from_the_public_api() {
    let pid = Pid::new(42).expect("valid pid");
    let target =
        ProcessTarget::new(pid).region(InitialRegionConfig::new(100, 200).expect("valid region"));

    assert_eq!(target.pid(), pid);
}

#[test]
fn owned_configuration_is_constructible_from_the_public_api() {
    let pattern = AccessPattern::new(
        RegionSizeRange::new(0, u64::MAX).expect("valid size range"),
        AccessCountRange::new(0, u32::MAX).expect("valid access range"),
        damon::sysfs::AgeRange::new(0, u32::MAX).expect("valid age range"),
    );
    let mut scheme = SchemeConfig::new(Action::Stat, pattern);
    let mut quota = QuotaConfig::default();
    quota.time = Duration::from_millis(10);
    quota.size_units = 1 << 20;
    quota.reset_interval = Duration::from_secs(1);
    quota.weights.accesses_per_thousand = 500;
    quota.weights.age_per_thousand = 500;
    scheme.quota = quota;
    scheme.filters = vec![FilterConfig::new(SchemeFilterType::Anonymous, true, false)];
    scheme.filters.push(FilterConfig::huge_page_size(
        ByteSizeRange::new(2 << 20, 1 << 30).expect("valid byte-size range"),
        true,
        true,
    ));
    scheme
        .validate_for(1)
        .expect("standalone scheme validation");
    scheme.filters[0]
        .validate_for(FilterLayer::Operations, 1)
        .expect("standalone filter validation");

    let mut target = TargetConfig::for_pid(Pid::new(42).expect("valid pid"));
    target.initial_regions =
        vec![InitialRegionConfig::new(0x1_0000, 0x2_0000).expect("valid initial region")];

    let mut context = ContextConfig::new(damon::sysfs::Operation::VirtualAddress);
    context.operation_attributes = OperationAttributesConfig::default();
    let mut probe = ProbeConfig::default();
    probe.weight = 1;
    probe.preparations.push(ProbePreparationConfig::new(
        ProbePreparationAction::SetPageIdle,
    ));
    context.probes.push(probe);
    let mut sample_control = SampleControlConfig::default();
    sample_control.primitives = SamplePrimitivesConfig::default();
    sample_control
        .filters
        .push(SampleFilterConfig::write(true, true));
    context.sample_control = sample_control;
    context.region_bounds = RegionBounds::new(10, 1_000).expect("valid region bounds");
    context.targets.push(target);
    context.schemes.push(scheme);
    context.validate().expect("valid context");

    let mut kdamond = KdamondConfig::default();
    kdamond.contexts.push(context);
    kdamond.validate().expect("valid kdamond configuration");

    let mut config = DamonConfig::default();
    config.kdamonds.push(kdamond);
    config.validate().expect("valid admin configuration");
}

#[test]
fn runnable_validation_is_stricter_than_staged_shape_validation() {
    let context = ContextConfig::new(damon::sysfs::Operation::VirtualAddress);
    context
        .validate()
        .expect("incomplete context can be staged");
    assert!(context.validate_runnable().is_err());

    let mut config = DamonConfig::default();
    let mut kdamond = KdamondConfig::default();
    kdamond.contexts.push(context);
    config.kdamonds.push(kdamond);
    config
        .validate()
        .expect("incomplete hierarchy can be staged");
    assert!(config.validate_runnable().is_err());
}

#[test]
fn runnable_validation_defers_probe_count_and_checks_weighted_overflow() {
    let mut context = ContextConfig::new(damon::sysfs::Operation::VirtualAddress);
    context
        .targets
        .push(TargetConfig::for_pid(Pid::new(42).expect("valid pid")));
    context.probes = vec![ProbeConfig::default(); 5];
    assert!(context.validate().is_ok());
    context
        .validate_runnable()
        .expect("the running kernel owns its probe-count limit");

    context.probes.truncate(1);
    context.probes[0].weight = 1;
    context.intervals = damon::MonitoringIntervals::new(
        Duration::from_micros(1),
        Duration::from_micros(256),
        Duration::from_secs(1),
    )
    .expect("valid intervals");
    assert!(context.validate_runnable().is_err());

    context.intervals = damon::MonitoringIntervals::new(
        Duration::from_micros(1),
        Duration::from_micros(2),
        Duration::from_secs(1),
    )
    .expect("valid intervals");
    context.probes[0].weight = u32::MAX;
    assert!(context.validate_runnable().is_err());
}

#[test]
fn damon_next_values_have_typed_operation_and_metric_validation() {
    let pattern = AccessPattern::new(
        RegionSizeRange::new(0, u64::MAX).expect("valid size range"),
        AccessCountRange::new(0, u32::MAX).expect("valid access range"),
        damon::sysfs::AgeRange::new(0, u32::MAX).expect("valid age range"),
    );
    let mut scheme = SchemeConfig::new(Action::DamosAllocate, pattern);
    scheme.quota.goals.push(QuotaGoalConfig::new(
        QuotaGoalMetric::HugePageMemoryBasisPoints,
        10_001,
    ));
    scheme.quota.reset_interval = Duration::from_secs(1);
    assert!(scheme.validate_for(1).is_err());

    scheme.quota.goals[0].target_value = 10_000;
    let mut physical = ContextConfig::new(Operation::PhysicalAddress);
    let mut target = TargetConfig::address_space();
    target.initial_regions =
        vec![InitialRegionConfig::new(0, 4_096).expect("valid physical region")];
    physical.targets.push(target);
    physical.schemes.push(scheme.clone());
    physical
        .validate_runnable()
        .expect("ACMA actions are physical-address operations");

    let mut virtual_context = ContextConfig::new(Operation::VirtualAddress);
    virtual_context
        .targets
        .push(TargetConfig::for_pid(Pid::new(42).expect("valid pid")));
    virtual_context.schemes.push(scheme);
    assert!(virtual_context.validate_runnable().is_err());
}

#[test]
fn runnable_validation_enforces_effective_sample_controls() {
    let mut virtual_context = ContextConfig::new(Operation::VirtualAddress);
    virtual_context
        .targets
        .push(TargetConfig::for_pid(Pid::new(42).expect("valid pid")));

    virtual_context.sample_control.primitives.page_table = false;
    assert!(virtual_context.validate().is_ok());
    assert!(virtual_context.validate_runnable().is_err());

    virtual_context.sample_control.primitives.page_table = true;
    virtual_context.sample_control.primitives.page_fault = true;
    assert!(virtual_context.validate_runnable().is_err());

    virtual_context.sample_control.primitives.page_table = false;
    assert!(virtual_context.validate_runnable().is_err());

    virtual_context.sample_control.primitives = SamplePrimitivesConfig::default();
    virtual_context
        .sample_control
        .filters
        .push(SampleFilterConfig::write(true, true));
    assert!(virtual_context.validate_runnable().is_err());

    let mut physical_context = ContextConfig::new(Operation::PhysicalAddress);
    let mut target = TargetConfig::address_space();
    target.initial_regions =
        vec![InitialRegionConfig::new(0, 4096).expect("valid physical-address region")];
    physical_context.targets.push(target);
    physical_context.sample_control.primitives.page_table = false;
    physical_context.sample_control.primitives.page_fault = true;
    physical_context
        .sample_control
        .filters
        .push(SampleFilterConfig::write(true, true));
    physical_context
        .validate_runnable()
        .expect("physical-address page-fault sampling is effective");

    let mut future_context = physical_context;
    future_context.operation = Operation::Unknown("future_operation".into());
    future_context
        .validate_runnable()
        .expect("unknown future operations remain forward-compatible");
}

#[test]
fn obsolete_targets_are_not_valid_initial_running_state() {
    let mut context = ContextConfig::new(Operation::VirtualAddress);
    let mut target = TargetConfig::for_pid(Pid::new(42).expect("valid pid"));
    target.obsolete = true;
    context.targets.push(target);

    context
        .validate()
        .expect("obsolete markers remain representable while stopped");
    assert!(context.validate_runnable().is_err());
}

#[test]
fn physical_initial_regions_reject_byte_scaling_overflow() {
    let mut context = ContextConfig::new(Operation::PhysicalAddress);
    context.address_unit = AddressUnit::new(u64::MAX).expect("nonzero address unit");
    let mut target = TargetConfig::address_space();
    target.initial_regions = vec![InitialRegionConfig::new(1, 2).expect("valid raw region")];
    context.targets.push(target);

    let error = context.validate().expect_err("scaling must overflow");
    assert!(
        matches!(
            error,
            Error::AddressConversionOverflow {
                units: 2,
                unit_bytes: u64::MAX
            }
        ),
        "{error:?}"
    );
}

#[test]
fn initial_regions_reject_overlap_after_kernel_alignment() {
    let page_size = rustix::param::page_size() as u64;
    let mut context = ContextConfig::new(Operation::FixedVirtualAddress);
    let mut target = TargetConfig::for_pid(Pid::new(42).expect("valid pid"));
    target.initial_regions = vec![
        InitialRegionConfig::new(1, 2).expect("valid raw region"),
        InitialRegionConfig::new(page_size - 1, page_size).expect("valid raw region"),
    ];
    context.targets.push(target);

    let error = context.validate().expect_err("aligned ranges must overlap");
    assert!(
        matches!(
            error,
            Error::InvalidConfiguration {
                field: "initial regions",
                reason: "regions overlap after kernel minimum-region alignment"
            }
        ),
        "{error:?}"
    );
}
