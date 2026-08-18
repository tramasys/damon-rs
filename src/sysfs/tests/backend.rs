use super::*;

#[test]
fn modeled_sysfs_reconstructs_children_and_separates_active_inputs() {
    let model = test_backend::Model::new("vaddr\nfvaddr\npaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    assert_eq!(admin.kdamond_count().expect("read initial count"), 0);

    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    context
        .set_operation(&Operation::PhysicalAddress)
        .expect("stage operation");
    context
        .set_address_unit(AddressUnit::new(4_096).expect("valid unit"))
        .expect("stage address unit");

    kdamond.command(&KdamondCommand::On).expect("start model");
    let first_pid = kdamond.pid().expect("read modeled pid");
    assert!(first_pid.is_some());
    assert_eq!(
        model.active_value("kdamonds/0/contexts/0/addr_unit"),
        Some("4096".to_owned())
    );

    context
        .set_address_unit(AddressUnit::ONE)
        .expect("change only staged unit");
    assert_eq!(
        context.address_unit().expect("read staged unit"),
        AddressUnit::ONE
    );
    assert_eq!(
        model.active_value("kdamonds/0/contexts/0/addr_unit"),
        Some("4096".to_owned())
    );

    kdamond
        .command(&KdamondCommand::UpdateSchemesStats)
        .expect("state command is accepted");
    assert_eq!(
        kdamond.state().expect("state remains running"),
        KdamondState::On
    );
    kdamond
        .command(&KdamondCommand::Commit)
        .expect("commit staged values");
    assert_eq!(
        model.active_value("kdamonds/0/contexts/0/addr_unit"),
        Some("1".to_owned())
    );

    kdamond.command(&KdamondCommand::Off).expect("stop model");
    assert_eq!(kdamond.pid().expect("read stopped pid"), None);
    kdamond.set_context_count(0).expect("remove context");
    assert!(!path_exists(context.path()).expect("inspect removed child"));
}

#[test]
fn modeled_quota_goal_commit_does_not_commit_other_staged_inputs() {
    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    context.set_scheme_count(1).expect("stage scheme");
    kdamond.command(&KdamondCommand::On).expect("start model");

    let scheme = context.scheme(0);
    write_bytes(&scheme.path().join("quotas/ms"), b"99").expect("stage non-goal quota");
    write_bytes(&scheme.path().join("quotas/goals/nr_goals"), b"1")
        .expect("stage quota goal count");
    kdamond
        .command(&KdamondCommand::CommitSchemesQuotaGoals)
        .expect("commit only quota goals");

    assert_eq!(
        model.active_value("kdamonds/0/contexts/0/schemes/0/quotas/ms"),
        Some("0".to_owned())
    );
    assert_eq!(
        model.active_value("kdamonds/0/contexts/0/schemes/0/quotas/goals/nr_goals"),
        Some("1".to_owned())
    );
}

#[test]
fn modeled_output_commands_materialize_stats_and_effective_quotas() {
    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    context.set_scheme_count(2).expect("stage schemes");
    let first = context.scheme(0);
    let second = context.scheme(1);
    write_value(&first.path().join("stats/max_nr_snapshots"), 19).expect("stage maximum snapshots");
    kdamond.command(&KdamondCommand::On).expect("start model");

    model.set_scheme_stats(vec![
        test_backend::ModelSchemeStats {
            nr_tried: 1,
            sz_tried: 2,
            nr_applied: 3,
            sz_applied: 4,
            sz_ops_filter_passed: 5,
            qt_exceeds: 6,
            nr_snapshots: 7,
        },
        test_backend::ModelSchemeStats {
            nr_tried: 11,
            sz_tried: 12,
            nr_applied: 13,
            sz_applied: 14,
            sz_ops_filter_passed: 15,
            qt_exceeds: 16,
            nr_snapshots: 17,
        },
    ]);
    model.set_effective_quota_bytes(vec![4_096, 8_192]);

    assert_eq!(
        read_u64(&first.path().join("stats/nr_tried")).expect("read stale stats"),
        0
    );
    assert_eq!(
        read_u64(&first.path().join("quotas/effective_bytes")).expect("read stale effective quota"),
        0
    );

    kdamond
        .command(&KdamondCommand::UpdateSchemesStats)
        .expect("refresh modeled stats");
    for (scheme, expected) in [
        (&first, [1, 2, 3, 4, 5, 6, 7]),
        (&second, [11, 12, 13, 14, 15, 16, 17]),
    ] {
        for (name, value) in [
            "nr_tried",
            "sz_tried",
            "nr_applied",
            "sz_applied",
            "sz_ops_filter_passed",
            "qt_exceeds",
            "nr_snapshots",
        ]
        .into_iter()
        .zip(expected)
        {
            assert_eq!(
                read_u64(&scheme.path().join("stats").join(name)).expect("read refreshed stats"),
                value
            );
        }
    }
    assert_eq!(
        read_u64(&first.path().join("stats/max_nr_snapshots"))
            .expect("read configured maximum snapshots"),
        19
    );
    assert_eq!(
        read_u64(&first.path().join("quotas/effective_bytes"))
            .expect("stats command must not update quota"),
        0
    );

    kdamond
        .command(&KdamondCommand::UpdateSchemesEffectiveQuotas)
        .expect("refresh modeled effective quotas");
    assert_eq!(
        read_u64(&first.path().join("quotas/effective_bytes")).expect("read first effective quota"),
        4_096
    );
    assert_eq!(
        read_u64(&second.path().join("quotas/effective_bytes"))
            .expect("read second effective quota"),
        8_192
    );
    assert_typed_scheme_output(&first, &second);
}

fn assert_typed_scheme_output(first: &Scheme, second: &Scheme) {
    assert_eq!(
        first.stats().expect("read typed scheme stats"),
        SchemeStats {
            regions_tried: 1,
            size_tried_units: 2,
            regions_applied: 3,
            size_applied_units: 4,
            operations_filter_passed_units: Some(5),
            quota_exceeds: 6,
            snapshots: Some(7),
            maximum_snapshots: Some(19),
        }
    );
    assert_eq!(
        second
            .quotas()
            .effective_size_units()
            .expect("read typed effective quota"),
        8_192
    );
}

#[test]
fn modeled_kdamond_reconstruction_is_busy_while_running() {
    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    kdamond.command(&KdamondCommand::On).expect("start model");

    let error = admin
        .set_kdamond_count(0)
        .expect_err("running kdamond reconstruction must be busy");
    assert!(error.is_resource_busy());
    assert_eq!(admin.kdamond_count().expect("preserve count"), 1);

    kdamond.command(&KdamondCommand::Off).expect("stop model");
    admin.set_kdamond_count(0).expect("remove stopped model");
}

#[test]
fn modeled_state_transitions_match_linux_errors() {
    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let kdamond = admin.kdamond(0);

    let error = kdamond
        .command(&KdamondCommand::On)
        .expect_err("starting without one context must fail");
    assert!(matches!(
        error,
        Error::Io { source, .. } if source.raw_os_error() == Some(22)
    ));

    kdamond.set_context_count(1).expect("stage context");
    kdamond.command(&KdamondCommand::On).expect("start model");
    let error = kdamond
        .command(&KdamondCommand::On)
        .expect_err("starting an active kdamond must be busy");
    assert!(error.is_resource_busy());

    kdamond.command(&KdamondCommand::Off).expect("stop model");
    let error = kdamond
        .command(&KdamondCommand::Off)
        .expect_err("stopping an inactive context must fail");
    assert!(matches!(
        error,
        Error::Io { source, .. } if source.raw_os_error() == Some(1)
    ));
}

#[test]
fn modeled_indexed_children_match_linux_7_2_layout() {
    let model = test_backend::Model::new("vaddr\n");
    let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
    admin.set_kdamond_count(1).expect("stage kdamond");
    let context = admin.kdamond(0).context(0);
    admin
        .kdamond(0)
        .set_context_count(1)
        .expect("stage context");
    context.set_scheme_count(1).expect("stage scheme");
    let scheme = context.scheme(0);

    assert_eq!(
        read_text(&scheme.path().join("target_nid")).expect("read target node"),
        "-1\n"
    );

    let goals = scheme.path().join("quotas/goals");
    write_value(&goals.join("nr_goals"), 1).expect("stage quota goal");
    assert!(path_exists(&goals.join("0/target_metric")).expect("inspect quota goal"));
    assert!(path_exists(&goals.join("0/path")).expect("inspect quota goal path"));

    for name in ["filters", "core_filters", "ops_filters"] {
        let filters = scheme.path().join(name);
        write_value(&filters.join("nr_filters"), 1).expect("stage scheme filter");
        assert!(path_exists(&filters.join("0/memcg_path")).expect("inspect scheme filter"));
        assert!(!path_exists(&filters.join("0/path")).expect("distinguish probe filter"));
    }

    let dests = scheme.path().join("dests");
    write_value(&dests.join("nr_dests"), 1).expect("stage destination");
    assert!(path_exists(&dests.join("0/id")).expect("inspect destination id"));
    assert!(path_exists(&dests.join("0/weight")).expect("inspect destination weight"));

    context.set_probe_count(1).expect("stage probe");
    let probe = context.probe(0);
    probe.set_filter_count(1).expect("stage probe filter");
    assert!(path_exists(&probe.filter(0).path().join("path")).expect("inspect probe filter"));
    assert!(
        !path_exists(&probe.filter(0).path().join("memcg_path"))
            .expect("distinguish scheme filter")
    );
}
