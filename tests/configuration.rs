//! Public API checks for owned DAMON configurations.

use std::time::Duration;

use damon::sysfs::{
    AccessCountRange, AccessPattern, Action, ByteSizeRange, ContextConfig, DamonConfig,
    FilterConfig, FilterLayer, InitialRegionConfig, KdamondConfig, OperationAttributesConfig,
    ProbeConfig, ProbePreparationAction, ProbePreparationConfig, QuotaConfig, RegionSizeRange,
    SampleControlConfig, SampleFilterConfig, SamplePrimitivesConfig, SchemeConfig,
    SchemeFilterType, TargetConfig,
};
use damon::{Pid, RegionBounds};

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
fn runnable_validation_enforces_current_weighted_probe_limits() {
    let mut context = ContextConfig::new(damon::sysfs::Operation::VirtualAddress);
    context
        .targets
        .push(TargetConfig::for_pid(Pid::new(42).expect("valid pid")));
    context.probes = vec![ProbeConfig::default(); 5];
    assert!(context.validate().is_ok());
    assert!(context.validate_runnable().is_err());

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
