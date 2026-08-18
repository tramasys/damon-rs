use super::*;

#[test]
fn owned_linux_7_2_configuration_round_trips_every_input() {
    let model = test_backend::Model::new("vaddr\nfvaddr\npaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);

    let mut probe = ProbeConfig::default();
    probe.filters.push(ProbeFilterConfig::new(
        ProbeFilterType::Anonymous,
        true,
        true,
    ));
    probe.filters.push(ProbeFilterConfig::memory_control_group(
        "/workload",
        false,
        true,
    ));

    let pattern = AccessPattern::new(
        RegionSizeRange::new(4_096, 1 << 30).expect("valid size range"),
        AccessCountRange::new(1, 200).expect("valid access range"),
        AgeRange::new(2, 300).expect("valid age range"),
    );
    let mut scheme = SchemeConfig::new(Action::MigrateHot, pattern);
    scheme.apply_interval = Duration::from_millis(250);
    scheme.target_node = Some(2);
    scheme.quota = QuotaConfig {
        time: Duration::from_millis(10),
        size_units: 1 << 20,
        reset_interval: Duration::from_secs(1),
        weights: QuotaWeights {
            size_per_thousand: 100,
            accesses_per_thousand: 300,
            age_per_thousand: 600,
        },
        goals: vec![QuotaGoalConfig {
            metric: QuotaGoalMetric::NodeMemoryControlGroupFreeBasisPoints,
            target_value: 2_000,
            current_value: 1_500,
            node_id: Some(1),
            cgroup_path: Some("/workload".to_owned()),
        }],
        goal_tuner: QuotaGoalTuner::Temporal,
        failure_charge_numerator: 1,
        failure_charge_denominator: 4,
    };
    scheme.watermarks = WatermarksConfig {
        metric: WatermarkMetric::FreeMemoryRate,
        interval: Duration::from_secs(5),
        high: 800,
        middle: 500,
        low: 200,
    };
    scheme.filters = vec![
        FilterConfig::address(0, 65_536, true, true),
        FilterConfig::target(0, true, false),
        FilterConfig::huge_page_size(
            ByteSizeRange::new(2 << 20, 1 << 30).expect("valid huge-page range"),
            false,
            true,
        ),
    ];
    scheme.destinations = vec![DestinationConfig {
        node_id: 3,
        weight: 17,
    }];
    scheme.maximum_snapshots = 64;

    let mut context = ContextConfig::new(Operation::VirtualAddress);
    context.address_unit = AddressUnit::ONE;
    context.paused = false;
    context.intervals = MonitoringIntervals::new(
        Duration::from_millis(5),
        Duration::from_millis(100),
        Duration::from_secs(1),
    )
    .expect("valid intervals");
    context.intervals_goal = IntervalsGoalConfig {
        access_basis_points: 5_000,
        aggregation_intervals: 10,
        minimum_sample: Duration::from_millis(1),
        maximum_sample: Duration::from_millis(10),
    };
    context.region_bounds = RegionBounds::new(10, 10_000).expect("valid bounds");
    context.probes = vec![probe];
    context.targets.push(complete_test_target());
    context.schemes.push(scheme);

    let config = KdamondConfig {
        refresh_interval: Duration::from_millis(25),
        contexts: vec![context],
    };
    kdamond
        .stage_configuration(&config)
        .expect("stage complete configuration");
    let observed = kdamond
        .configuration()
        .expect("read complete configuration");
    assert_kdamond_configs_equivalent(config, observed);
}

#[test]
fn owned_configuration_preserves_all_filter_layers_and_execution_order() {
    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    context.set_target_count(1).expect("stage target");
    context.set_scheme_count(1).expect("stage scheme");

    let mut config = kdamond.configuration().expect("read defaults");
    config.contexts[0].targets[0].pid = Some(Pid::new(42).expect("valid pid"));
    let filters = &mut config.contexts[0].schemes[0].filters;
    let mut core = FilterConfig::address(0, 4_096, true, true);
    core.placement = FilterPlacement::Core;
    let mut operations = FilterConfig::new(SchemeFilterType::Anonymous, true, false);
    operations.placement = FilterPlacement::Operations;
    let mut unified = FilterConfig::new(SchemeFilterType::Active, false, true);
    unified.placement = FilterPlacement::Unified;
    *filters = vec![core, operations, unified];

    kdamond
        .stage_configuration(&config)
        .expect("stage every filter layer");
    let observed = kdamond.configuration().expect("read every filter layer");
    let placements = observed.contexts[0].schemes[0]
        .filters
        .iter()
        .map(|filter| filter.placement)
        .collect::<Vec<_>>();
    assert_eq!(
        placements,
        vec![
            FilterPlacement::Core,
            FilterPlacement::Operations,
            FilterPlacement::Unified
        ]
    );
    assert_eq!(observed, config);
}

#[test]
fn owned_configuration_round_trips_current_damo_probe_and_sample_controls() {
    let model = test_backend::Model::new("vaddr\n");
    model.enable_current_damo_extensions();
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);

    let mut probe = ProbeConfig {
        filters: vec![ProbeFilterConfig::new(
            ProbeFilterType::PageIdleUnset,
            true,
            true,
        )],
        weight: 7,
        preparations: vec![ProbePreparationConfig::new(
            ProbePreparationAction::SetPageIdle,
        )],
    };
    probe.filters.push(ProbeFilterConfig::memory_control_group(
        "/workload",
        false,
        true,
    ));

    let mut context = ContextConfig::new(Operation::VirtualAddress);
    context.operation_attributes = OperationAttributesConfig {
        use_reports: true,
        write_only: true,
        cpus: "0-3".to_owned(),
        thread_ids: "41 42".to_owned(),
    };
    context.probes.push(probe);
    context.sample_control = SampleControlConfig {
        primitives: SamplePrimitivesConfig {
            page_table: false,
            page_fault: true,
        },
        filters: vec![
            SampleFilterConfig::cpu_mask("0-3", true, true),
            SampleFilterConfig::threads("41 42", false, true),
            SampleFilterConfig::write(true, false),
        ],
    };
    context
        .targets
        .push(TargetConfig::for_pid(Pid::new(42).expect("valid pid")));

    let config = KdamondConfig {
        refresh_interval: Duration::ZERO,
        contexts: vec![context],
    };
    kdamond
        .stage_configuration(&config)
        .expect("stage current damo controls");

    assert_eq!(
        kdamond.configuration().expect("read current damo controls"),
        config
    );
}

#[test]
fn modeled_kernel_rejects_invalid_sample_primitives_on_start_and_commit() {
    let model = test_backend::Model::new("vaddr\n");
    model.enable_current_damo_extensions();
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);

    let mut context = ContextConfig::new(Operation::VirtualAddress);
    context
        .targets
        .push(TargetConfig::for_pid(Pid::new(42).expect("valid pid")));
    context.sample_control.primitives = SamplePrimitivesConfig {
        page_table: true,
        page_fault: true,
    };
    let config = KdamondConfig {
        refresh_interval: Duration::ZERO,
        contexts: vec![context],
    };
    kdamond
        .stage_configuration(&config)
        .expect("stage structurally valid primitive combination");
    assert!(kdamond.command(&KdamondCommand::On).is_err());

    let mut valid = config.clone();
    valid.contexts[0].sample_control.primitives = SamplePrimitivesConfig::default();
    kdamond
        .stage_configuration(&valid)
        .expect("stage valid primitive combination");
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/monitoring_attrs/sample/primitives/page_table")
            .as_deref(),
        Some("Y")
    );
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/monitoring_attrs/sample/primitives/page_fault")
            .as_deref(),
        Some("N")
    );
    kdamond.command(&KdamondCommand::On).expect("start kdamond");

    let mut invalid_update = valid;
    invalid_update.contexts[0].sample_control.primitives = SamplePrimitivesConfig {
        page_table: false,
        page_fault: false,
    };
    kdamond
        .stage_configuration(&invalid_update)
        .expect("stage invalid running update");
    assert!(kdamond.command(&KdamondCommand::Commit).is_err());
}

#[test]
fn owned_admin_configuration_round_trips_multiple_kdamonds() {
    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    let config = DamonConfig {
        kdamonds: vec![
            KdamondConfig {
                refresh_interval: Duration::from_millis(10),
                contexts: Vec::new(),
            },
            KdamondConfig {
                refresh_interval: Duration::from_millis(20),
                contexts: Vec::new(),
            },
        ],
    };

    admin
        .stage_configuration(&config)
        .expect("stage complete admin hierarchy");

    assert_eq!(admin.configuration().expect("read admin hierarchy"), config);
}

fn complete_test_target() -> TargetConfig {
    TargetConfig {
        pid: Some(Pid::new(42).expect("valid pid")),
        obsolete: false,
        initial_regions: vec![
            InitialRegionConfig::new(0x1_0000, 0x2_0000).expect("valid region"),
            InitialRegionConfig::new(0x3_0000, 0x4_0000).expect("valid region"),
        ],
    }
}

fn assert_kdamond_configs_equivalent(expected: KdamondConfig, observed: KdamondConfig) {
    assert!(
        DamonConfig {
            kdamonds: vec![expected]
        }
        .equivalent_after_kernel_normalization(&DamonConfig {
            kdamonds: vec![observed]
        })
    );
}

#[test]
fn owned_configuration_validation_precedes_every_write() {
    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    let mut context = ContextConfig::new(Operation::VirtualAddress);
    let mut target = TargetConfig::for_pid(Pid::new(42).expect("valid pid"));
    target.initial_regions = vec![
        InitialRegionConfig::new(100, 200).expect("valid region"),
        InitialRegionConfig::new(150, 250).expect("valid region"),
    ];
    context.targets.push(target);
    let config = KdamondConfig {
        refresh_interval: Duration::from_millis(99),
        contexts: vec![context],
    };

    let error = kdamond
        .stage_configuration(&config)
        .expect_err("overlapping regions must be rejected");
    assert!(matches!(error, Error::InvalidConfiguration { .. }));
    assert_eq!(
        kdamond.refresh_interval().expect("refresh stays unchanged"),
        Duration::ZERO
    );
    assert_eq!(
        kdamond
            .context_count()
            .expect("context count stays unchanged"),
        0
    );
}

#[cfg(target_os = "linux")]
#[test]
fn physical_address_staging_rejects_invalid_subpage_address_units_before_writing() {
    let model = test_backend::Model::new("paddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    let writes = model.write_count();

    let mut context = ContextConfig::new(Operation::PhysicalAddress);
    context.address_unit = AddressUnit::new(3).expect("non-zero unit");
    context.targets.push(TargetConfig::address_space());
    let config = KdamondConfig {
        refresh_interval: Duration::ZERO,
        contexts: vec![context],
    };

    let error = kdamond
        .stage_configuration(&config)
        .expect_err("subpage units must be powers of two");
    assert!(matches!(
        error,
        Error::InvalidConfiguration {
            field: "address unit",
            ..
        }
    ));
    assert_eq!(model.write_count(), writes);
}

#[test]
fn indexed_counts_reject_values_wider_than_the_kernel_abi() {
    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    let error = admin
        .set_kdamond_count(i32::MAX as usize + 1)
        .expect_err("kernel count overflow must be rejected");
    assert!(matches!(error, Error::InvalidConfiguration { .. }));
    assert_eq!(admin.kdamond_count().expect("count remains unchanged"), 0);
}

#[test]
fn owned_configuration_preserves_absent_optional_attributes() {
    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    context.set_target_count(1).expect("stage target");
    context
        .target(0)
        .set_pid(Pid::new(42).expect("valid pid"))
        .expect("stage pid");
    context.set_scheme_count(1).expect("stage scheme");

    for path in [
        "kdamonds/0/refresh_ms",
        "kdamonds/0/contexts/0/addr_unit",
        "kdamonds/0/contexts/0/pause",
        "kdamonds/0/contexts/0/monitoring_attrs/intervals/intervals_goal",
        "kdamonds/0/contexts/0/monitoring_attrs/probes",
        "kdamonds/0/contexts/0/targets/0/obsolete_target",
        "kdamonds/0/contexts/0/targets/0/regions",
        "kdamonds/0/contexts/0/schemes/0/apply_interval_us",
        "kdamonds/0/contexts/0/schemes/0/target_nid",
        "kdamonds/0/contexts/0/schemes/0/quotas/goals",
        "kdamonds/0/contexts/0/schemes/0/quotas/goal_tuner",
        "kdamonds/0/contexts/0/schemes/0/quotas/fail_charge_num",
        "kdamonds/0/contexts/0/schemes/0/quotas/fail_charge_denom",
        "kdamonds/0/contexts/0/schemes/0/filters",
        "kdamonds/0/contexts/0/schemes/0/core_filters",
        "kdamonds/0/contexts/0/schemes/0/ops_filters",
        "kdamonds/0/contexts/0/schemes/0/dests",
        "kdamonds/0/contexts/0/schemes/0/stats/sz_ops_filter_passed",
        "kdamonds/0/contexts/0/schemes/0/stats/nr_snapshots",
        "kdamonds/0/contexts/0/schemes/0/stats/max_nr_snapshots",
    ] {
        model.remove_tree(path);
    }

    let config = kdamond.configuration().expect("read legacy configuration");
    assert_eq!(config.refresh_interval, Duration::ZERO);
    let context_config = &config.contexts[0];
    assert_eq!(context_config.address_unit, AddressUnit::ONE);
    assert_eq!(
        context_config.intervals_goal,
        IntervalsGoalConfig::default()
    );
    assert!(context_config.probes.is_empty());
    assert!(context_config.targets[0].initial_regions.is_empty());
    assert!(context_config.schemes[0].destinations.is_empty());
    let stats = context.scheme(0).stats().expect("read legacy scheme stats");
    assert_eq!(stats.operations_filter_passed_units, None);
    assert_eq!(stats.snapshots, None);
    assert_eq!(stats.maximum_snapshots, None);
    kdamond
        .stage_configuration(&config)
        .expect("restage configuration without unavailable attributes");
}

#[test]
fn owned_configuration_supports_damo_legacy_attribute_aliases() {
    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    context.set_target_count(1).expect("stage target");
    context
        .target(0)
        .set_pid(Pid::new(42).expect("valid pid"))
        .expect("stage pid");
    context.set_scheme_count(1).expect("stage scheme");
    let scheme = context.scheme(0);
    model.remove_tree("kdamonds/0/contexts/0/schemes/0/core_filters");
    model.remove_tree("kdamonds/0/contexts/0/schemes/0/ops_filters");
    scheme
        .set_filter_count(FilterLayer::Unified, 1)
        .expect("stage filter");
    scheme.quotas().set_goal_count(1).expect("stage quota goal");

    let filter_path = "kdamonds/0/contexts/0/schemes/0/filters/0";
    model.remove_tree(format!("{filter_path}/allow"));
    model.set_file(format!("{filter_path}/pass"), b"Y\n");
    let goal_metric = "kdamonds/0/contexts/0/schemes/0/quotas/goals/0/target_metric";
    model.remove_tree(goal_metric);

    assert_eq!(
        kdamond
            .capabilities(0, 0)
            .expect("discover legacy filter control")
            .feature_support(SysfsFeature::SchemeFilterAllow),
        CapabilitySupport::Supported
    );
    let config = kdamond.configuration().expect("read legacy aliases");
    assert!(config.contexts[0].schemes[0].filters[0].allow);
    assert_eq!(
        config.contexts[0].schemes[0].quota.goals[0].metric,
        QuotaGoalMetric::UserInput
    );
    kdamond
        .stage_configuration(&config)
        .expect("restage legacy aliases");
    assert_eq!(
        model.value(format!("{filter_path}/pass")),
        Some("Y".to_owned())
    );
    assert_eq!(model.value(goal_metric), None);
}

#[test]
fn owned_configuration_rejects_kernel_commit_invariants() {
    let pattern = AccessPattern::new(
        RegionSizeRange::new(0, 1).expect("valid size range"),
        AccessCountRange::new(0, 1).expect("valid access range"),
        AgeRange::new(0, 1).expect("valid age range"),
    );
    let mut context = ContextConfig::new(Operation::PhysicalAddress);
    context.targets = vec![TargetConfig::address_space(), TargetConfig::address_space()];
    assert!(context.validate_runnable().is_err());

    context.targets.truncate(1);
    context.targets[0].initial_regions = vec![
        InitialRegionConfig::new(100, 200).expect("valid region"),
        InitialRegionConfig::new(150, 250).expect("valid region"),
    ];
    assert!(context.validate().is_err());

    context.targets[0].initial_regions.clear();
    let mut scheme = SchemeConfig::new(Action::Stat, pattern);
    scheme.filters = vec![FilterConfig::new(SchemeFilterType::Anonymous, true, false)];
    context.schemes.push(scheme);
    context
        .validate()
        .expect("semantic filters are assigned to the supported ABI layer");
}

#[test]
fn owned_configuration_rejects_overflow_prone_ratios_and_weights() {
    let intervals = MonitoringIntervals::default();
    let goal = IntervalsGoalConfig {
        access_basis_points: 10_001,
        aggregation_intervals: 1,
        minimum_sample: intervals.sample(),
        maximum_sample: intervals.sample(),
    };
    assert!(goal.validate_for(intervals).is_err());

    let mut quota = QuotaConfig::default();
    quota.weights.size_per_thousand = 1_001;
    assert!(quota.validate().is_err());
    quota.weights.size_per_thousand = 1_000;
    quota.time = Duration::from_millis(1);
    assert!(quota.validate().is_err());

    let pattern = AccessPattern::new(
        RegionSizeRange::new(0, 1).expect("valid size range"),
        AccessCountRange::new(0, 1).expect("valid access range"),
        AgeRange::new(0, 1).expect("valid age range"),
    );
    let mut scheme = SchemeConfig::new(Action::MigrateCold, pattern);
    scheme.destinations = vec![
        DestinationConfig::new(0, u32::MAX),
        DestinationConfig::new(1, 1),
    ];
    assert!(scheme.validate_for(1).is_err());
}

#[test]
fn disabled_controls_preserve_kernel_staged_values() {
    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    context
        .set_intervals_goal(IntervalsGoalConfig {
            access_basis_points: 10_001,
            aggregation_intervals: 0,
            minimum_sample: Duration::from_micros(20),
            maximum_sample: Duration::from_micros(10),
        })
        .expect("disabled interval goal ignores inactive thresholds");
    context.set_scheme_count(1).expect("stage scheme");
    let scheme = context.scheme(0);
    let watermarks = scheme.watermarks();
    watermarks
        .set_metric(&WatermarkMetric::None)
        .expect("disable watermarks");
    watermarks.set_high(1).expect("stage inactive high");
    watermarks.set_middle(3).expect("stage inactive middle");
    watermarks.set_low(2).expect("stage inactive low");
    let quotas = scheme.quotas();
    quotas.set_goal_count(1).expect("stage quota goal");
    let goal = quotas.goal(0);
    goal.set_metric(&QuotaGoalMetric::NodeMemoryControlGroupUsedBasisPoints)
        .expect("stage goal metric");
    goal.set_target_value(0).expect("disable quota goal");

    let config = kdamond.configuration().expect("read staged controls");
    config
        .validate()
        .expect("disabled controls must remain representable");
    kdamond
        .stage_configuration(&config)
        .expect("disabled controls must round-trip");
}

#[test]
fn migration_without_an_explicit_node_matches_kernel_and_damo() {
    let pattern = AccessPattern::new(
        RegionSizeRange::new(0, u64::MAX).expect("valid size range"),
        AccessCountRange::new(0, u32::MAX).expect("valid access range"),
        AgeRange::new(0, u32::MAX).expect("valid age range"),
    );
    let scheme = SchemeConfig::new(Action::MigrateCold, pattern);
    scheme
        .validate_for(0)
        .expect("NUMA_NO_NODE is a kernel-representable migration target");
}

#[test]
fn owned_validation_does_not_hardcode_the_kernel_context_limit() {
    let model = test_backend::Model::new("future_ops\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    let config = KdamondConfig {
        refresh_interval: Duration::ZERO,
        contexts: vec![
            ContextConfig::new(Operation::Unknown("future_ops".into())),
            ContextConfig::new(Operation::Unknown("future_ops".into())),
        ],
    };

    config
        .validate()
        .expect("future kernels may support multiple contexts");
    let error = kdamond
        .stage_configuration(&config)
        .expect_err("the Linux 7.2 model enforces its own limit");
    assert!(matches!(error, Error::Io { .. }));
    assert_eq!(kdamond.context_count().expect("read context count"), 0);
}

#[test]
fn owned_configuration_round_trips_unknown_future_tokens() {
    let model = test_backend::Model::new("future_ops\n");
    model.set_supported_scheme_filter_types("future_filter\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    context
        .set_operation(&Operation::Unknown("future_ops".into()))
        .expect("select future operation");
    context.set_scheme_count(1).expect("stage scheme");
    let scheme = context.scheme(0);
    scheme
        .set_action(&Action::Unknown("future_action".into()))
        .expect("select future action");
    scheme
        .set_filter_count(FilterLayer::Unified, 1)
        .expect("stage future filter");
    scheme
        .filter(FilterLayer::Unified, 0)
        .set_filter_type(&SchemeFilterType::Unknown("future_filter".into()))
        .expect("select future filter type");
    let quotas = scheme.quotas();
    quotas.set_goal_count(1).expect("stage future quota goal");
    quotas
        .goal(0)
        .set_metric(&QuotaGoalMetric::Unknown("future_metric".into()))
        .expect("select future goal metric");
    quotas
        .set_goal_tuner(&QuotaGoalTuner::Unknown("future_tuner".into()))
        .expect("select future goal tuner");
    let watermarks = scheme.watermarks();
    watermarks
        .set_metric(&WatermarkMetric::Unknown("future_watermark".into()))
        .expect("select future watermark metric");
    watermarks.set_high(1).expect("stage future threshold");
    watermarks.set_middle(3).expect("stage future threshold");
    watermarks.set_low(2).expect("stage future threshold");

    let config = kdamond.configuration().expect("read future configuration");
    config
        .validate()
        .expect("unknown future tokens remain representable");
    kdamond
        .stage_configuration(&config)
        .expect("restage future configuration");
    assert_eq!(
        kdamond
            .configuration()
            .expect("read restaged configuration"),
        config
    );
}

#[test]
fn typed_string_setters_reject_non_atomic_sysfs_values() {
    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    let error = context
        .set_operation(&Operation::Unknown("vaddr\nfuture".into()))
        .expect_err("operation must be one sysfs token");
    assert!(matches!(error, Error::InvalidConfiguration { .. }));
    assert_eq!(
        context.operation().expect("operation remains intact"),
        Operation::VirtualAddress
    );

    context.set_probe_count(1).expect("stage probe");
    let probe = context.probe(0);
    probe.set_filter_count(1).expect("stage probe filter");
    let filter = probe.filter(0);
    let error = filter
        .set_cgroup_path("/workload\0replacement")
        .expect_err("cgroup path must not contain a NUL");
    assert!(matches!(error, Error::InvalidConfiguration { .. }));
    assert_eq!(filter.cgroup_path().expect("path remains intact"), "");

    context.set_scheme_count(1).expect("stage scheme");
    let scheme = context.scheme(0);
    let error = scheme
        .set_action(&Action::Unknown("stat future".into()))
        .expect_err("action must be one sysfs token");
    assert!(matches!(error, Error::InvalidConfiguration { .. }));
    assert_eq!(
        scheme.action().expect("action remains intact"),
        Action::Stat
    );
}

#[test]
fn huge_page_filter_sizes_are_bytes_independent_of_address_unit() {
    let model = test_backend::Model::new("paddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    context
        .set_operation(&Operation::PhysicalAddress)
        .expect("select paddr");
    context
        .set_address_unit(AddressUnit::new(4_096).expect("valid unit"))
        .expect("stage non-one address unit");
    context.set_scheme_count(1).expect("stage scheme");
    let scheme = context.scheme(0);
    scheme
        .set_filter_count(FilterLayer::Operations, 1)
        .expect("stage filter");
    let filter = scheme.filter(FilterLayer::Operations, 0);
    let config = FilterConfig::huge_page_size(
        ByteSizeRange::new(2 << 20, 1 << 30).expect("valid byte-size range"),
        true,
        true,
    );
    filter
        .set_filter_type(&SchemeFilterType::HugePageSize)
        .expect("select huge-page-size filter");
    filter.set_matching(true).expect("stage matching");
    filter.set_allowed(true).expect("stage allow");
    filter
        .set_minimum_size_bytes(2 << 20)
        .expect("stage minimum");
    filter
        .set_maximum_size_bytes(1 << 30)
        .expect("stage maximum");

    assert_eq!(filter.minimum_size_bytes().expect("read minimum"), 2 << 20);
    assert_eq!(filter.maximum_size_bytes().expect("read maximum"), 1 << 30);
    assert_eq!(filter.configuration().expect("read filter"), config);
}

#[test]
fn nested_attribute_handles_are_symmetric() {
    let model = test_backend::Model::new("paddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    context.set_target_count(1).expect("stage target");
    let target = context.target(0);
    target
        .set_initial_region_count(1)
        .expect("stage initial region");
    let region = target.initial_region(0);
    region.set_start(100).expect("write start");
    region.set_end(200).expect("write end");
    assert_eq!(region.start().expect("read start"), 100);
    assert_eq!(region.end().expect("read end"), 200);

    context.set_scheme_count(1).expect("stage scheme");
    let scheme = context.scheme(0);
    scheme.set_target_node(3).expect("write target node");
    assert_eq!(scheme.target_node().expect("read target node"), 3);
    scheme
        .set_filter_count(FilterLayer::Core, 1)
        .expect("stage filter");
    let filter = scheme.filter(FilterLayer::Core, 0);
    filter
        .set_filter_type(&SchemeFilterType::Address)
        .expect("write filter type");
    filter.set_matching(true).expect("write matching");
    filter.set_allowed(false).expect("write allow");
    filter
        .set_address_start(1_000)
        .expect("write address start");
    filter.set_address_end(2_000).expect("write address end");
    assert_eq!(
        filter.filter_type().expect("read filter type"),
        SchemeFilterType::Address
    );
    assert!(filter.matching().expect("read matching"));
    assert!(!filter.allowed().expect("read allow"));
    assert_eq!(filter.address_start().expect("read address start"), 1_000);
    assert_eq!(filter.address_end().expect("read address end"), 2_000);

    let quotas = scheme.quotas();
    quotas
        .set_failure_charge_numerator(2)
        .expect("write numerator");
    quotas
        .set_failure_charge_denominator(7)
        .expect("write denominator");
    assert_eq!(
        quotas.failure_charge_numerator().expect("read numerator"),
        2
    );
    assert_eq!(
        quotas
            .failure_charge_denominator()
            .expect("read denominator"),
        7
    );
    quotas.set_goal_count(1).expect("stage quota goal");
    let goal = quotas.goal(0);
    goal.set_metric(&QuotaGoalMetric::UserInput)
        .expect("write metric");
    goal.set_target_value(12).expect("write target value");
    goal.set_current_value(9).expect("write current value");
    assert_eq!(
        goal.metric().expect("read metric"),
        QuotaGoalMetric::UserInput
    );
    assert_eq!(goal.target_value().expect("read target"), 12);
    assert_eq!(goal.current_value().expect("read current"), 9);

    scheme.set_destination_count(1).expect("stage destination");
    let destination = scheme.destination(0);
    destination.set_node_id(4).expect("write node");
    destination.set_weight(11).expect("write weight");
    assert_eq!(destination.node_id().expect("read node"), 4);
    assert_eq!(destination.weight().expect("read weight"), 11);
}
