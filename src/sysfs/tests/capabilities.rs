use super::*;

#[test]
fn operation_parser_preserves_new_kernel_values() {
    assert_eq!(Operation::parse("vaddr"), Operation::VirtualAddress);
    assert_eq!(
        Operation::parse("future"),
        Operation::Unknown("future".into())
    );
}

#[test]
fn action_parser_preserves_new_kernel_values() {
    assert_eq!(Action::parse("stat"), Action::Stat);
    assert_eq!(
        Action::parse("future_action"),
        Action::Unknown("future_action".into())
    );
}

#[test]
fn command_values_preserve_future_kernel_tokens() {
    let command = KdamondCommand::Unknown("future_command".into());
    assert_eq!(command.kernel_name(), "future_command");

    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let error = admin
        .kdamond(0)
        .command(&KdamondCommand::Unknown("invalid\ncommand".into()))
        .expect_err("multi-line command must be rejected before writing");
    assert!(matches!(error, Error::InvalidConfiguration { .. }));
}

#[test]
fn commands_match_linux_7_2_abi() {
    assert_eq!(
        KdamondCommand::UpdateSchemesTriedRegions.kernel_name(),
        "update_schemes_tried_regions"
    );
    assert_eq!(Action::LruDeprioritize.kernel_name(), "lru_deprio");
}

#[test]
#[allow(clippy::too_many_lines)]
fn semantic_features_match_the_official_damo_sysfs_map() {
    let expected = [
        (SysfsFeature::VirtualAddressOperation, "sysfs/vaddr"),
        (SysfsFeature::SchemeTimeQuota, "sysfs/schemes_time_quota"),
        (SysfsFeature::PhysicalAddressOperation, "sysfs/paddr"),
        (SysfsFeature::InitialRegions, "sysfs/init_regions"),
        (SysfsFeature::Schemes, "sysfs/schemes"),
        (
            SysfsFeature::SchemeSuccessfulStats,
            "sysfs/schemes_stat_succ",
        ),
        (SysfsFeature::SchemeSizeQuota, "sysfs/schemes_size_quota"),
        (
            SysfsFeature::SchemeQuotaExceededStats,
            "sysfs/schemes_stat_qt_exceed",
        ),
        (SysfsFeature::SchemeWatermarks, "sysfs/schemes_wmarks"),
        (
            SysfsFeature::SchemePrioritization,
            "sysfs/schemes_prioritization",
        ),
        (SysfsFeature::AvailableOperations, "sysfs/avail_ops"),
        (SysfsFeature::FixedVirtualAddressOperation, "sysfs/fvaddr"),
        (
            SysfsFeature::OnlineParametersCommit,
            "sysfs/online_params_commit",
        ),
        (SysfsFeature::TriedRegions, "sysfs/schemes_tried_regions"),
        (SysfsFeature::SchemeFilters, "sysfs/schemes_filters"),
        (
            SysfsFeature::SchemeFilterAnonymous,
            "sysfs/schemes_filters_anon",
        ),
        (
            SysfsFeature::SchemeFilterMemoryControlGroup,
            "sysfs/schemes_filters_memcg",
        ),
        (
            SysfsFeature::TriedRegionsTotalBytes,
            "sysfs/schemes_tried_regions_sz",
        ),
        (
            SysfsFeature::SchemeFilterAddress,
            "sysfs/schemes_filters_addr",
        ),
        (
            SysfsFeature::SchemeFilterTarget,
            "sysfs/schemes_filters_target",
        ),
        (
            SysfsFeature::SchemeApplyInterval,
            "sysfs/schemes_apply_interval",
        ),
        (SysfsFeature::SchemeQuotaGoals, "sysfs/schemes_quota_goals"),
        (
            SysfsFeature::SchemeQuotaEffectiveBytes,
            "sysfs/schemes_quota_effective_bytes",
        ),
        (
            SysfsFeature::SchemeQuotaGoalMetric,
            "sysfs/schemes_quota_goal_metric",
        ),
        (
            SysfsFeature::SchemeQuotaGoalSomePsi,
            "sysfs/schemes_quota_goal_some_psi",
        ),
        (
            SysfsFeature::SchemeFilterYoung,
            "sysfs/schemes_filters_young",
        ),
        (SysfsFeature::SchemeMigration, "sysfs/schemes_migrate"),
        (
            SysfsFeature::SchemeOperationsFilterPassedBytes,
            "sysfs/sz_ops_filter_passed",
        ),
        (SysfsFeature::SchemeFilterAllow, "sysfs/allow_filter"),
        (
            SysfsFeature::SchemeFilterHugePageSize,
            "sysfs/schemes_filters_hugepage_size",
        ),
        (
            SysfsFeature::SchemeFilterUnmapped,
            "sysfs/schemes_filters_unmapped",
        ),
        (
            SysfsFeature::MonitoringIntervalsGoal,
            "sysfs/intervals_goal",
        ),
        (
            SysfsFeature::SeparateSchemeFilterDirectories,
            "sysfs/schemes_filters_core_ops_dirs",
        ),
        (
            SysfsFeature::SchemeFilterActive,
            "sysfs/schemes_filters_active",
        ),
        (
            SysfsFeature::SchemeQuotaGoalNodeMemory,
            "sysfs/schemes_quota_goal_node_mem_used_free",
        ),
        (SysfsFeature::SchemeDestinations, "sysfs/schemes_dests"),
        (SysfsFeature::PeriodicRefresh, "sysfs/refresh_ms"),
        (SysfsFeature::AddressUnit, "sysfs/addr_unit"),
        (
            SysfsFeature::SchemeQuotaGoalNodeMemoryControlGroup,
            "sysfs/schemes_quota_goal_node_memcg_used_free",
        ),
        (SysfsFeature::ObsoleteTarget, "sysfs/obsolete_target"),
        (
            SysfsFeature::SchemeSnapshotCount,
            "sysfs/damos_stat_nr_snapshots",
        ),
        (
            SysfsFeature::SchemeMaximumSnapshotCount,
            "sysfs/damos_max_nr_snapshots",
        ),
        (
            SysfsFeature::SchemeQuotaGoalActiveMemory,
            "sysfs/damos_quota_goal_in_active_mem_bp",
        ),
        (
            SysfsFeature::SchemeQuotaGoalTuner,
            "sysfs/damos_quota_goal_tuner",
        ),
        (SysfsFeature::CollapseAction, "sysfs/damos_action_collapse"),
        (
            SysfsFeature::SchemeQuotaGoalNodeEligibleMemory,
            "sysfs/damos_quota_goal_node_eligible_mem_bp",
        ),
        (SysfsFeature::ContextPause, "sysfs/ctx_pause"),
        (
            SysfsFeature::SchemeQuotaFailureChargeRatio,
            "sysfs/damos_quota_fail_charge_ratio",
        ),
        (SysfsFeature::AttributeMonitoring, "sysfs/attrs_monitoring"),
        (SysfsFeature::ProbeTypeAnonymous, "sysfs/probe_type_anon"),
        (
            SysfsFeature::ProbeTypeMemoryControlGroup,
            "sysfs/probe_type_memcg",
        ),
        (SysfsFeature::ProbeWeight, "sysfs/probe_weights"),
        (SysfsFeature::ProbePreparations, "sysfs/probe_preps"),
        (
            SysfsFeature::ProbePreparationSetPageIdle,
            "sysfs/probe_prep_set_pgidle",
        ),
        (
            SysfsFeature::ProbeTypePageIdleUnset,
            "sysfs/probe_type_pgidle_unset",
        ),
        (SysfsFeature::SampleControl, "sysfs/damon_sample_control"),
        (SysfsFeature::OperationAttributes, "sysfs/ops_attrs"),
    ];

    assert_eq!(expected.len(), 57);
    let names = expected
        .iter()
        .map(|(feature, expected_name)| {
            assert_eq!(feature.damo_name(), Some(*expected_name));
            *expected_name
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(names.len(), expected.len());
}
