use super::*;

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
