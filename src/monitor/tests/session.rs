use super::*;

#[test]
fn busy_operations_are_retried() {
    let mut attempts = 0;
    let value = retry_busy(|| {
        attempts += 1;
        if attempts < 3 {
            Err(os_error(16))
        } else {
            Ok(42)
        }
    })
    .expect("eventual success");

    assert_eq!(value, 42);
    assert_eq!(attempts, 3);
}

#[test]
fn busy_retries_are_bounded() {
    let mut attempts = 0;
    let error = retry_busy(|| {
        attempts += 1;
        Err::<(), _>(os_error(16))
    })
    .expect_err("persistent busy error");

    assert!(error.is_resource_busy());
    assert_eq!(attempts, 6);
}

#[test]
fn other_io_errors_are_not_retried() {
    let mut attempts = 0;
    let error = retry_busy(|| {
        attempts += 1;
        Err::<(), _>(os_error(13))
    })
    .expect_err("permission error");

    assert!(!error.is_resource_busy());
    assert_eq!(attempts, 1);
}

#[test]
fn transactional_staging_verifies_readback_and_skips_a_matching_hierarchy() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let config = transaction_config(42, Action::Stat);

    damon
        .stage_configuration(&config)
        .expect("stage configuration transactionally");
    assert_eq!(
        damon
            .admin
            .configuration()
            .expect("read staged configuration"),
        config
    );

    let writes = model.write_count();
    damon
        .stage_configuration(&config)
        .expect("matching configuration is a no-op");
    assert_eq!(model.write_count(), writes);
}

#[test]
fn transactional_staging_writes_only_changed_leaf_fields() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = transaction_config(42, Action::Stat);
    damon
        .stage_configuration(&original)
        .expect("stage original configuration");
    let writes = model.write_count();

    let replacement = transaction_config(77, Action::PageOut);
    damon
        .stage_configuration(&replacement)
        .expect("stage two changed leaves");

    assert_eq!(model.write_count() - writes, 2);
    assert_eq!(
        damon.admin.configuration().expect("read replacement"),
        replacement
    );
}

#[test]
fn transactional_staging_accepts_split_filter_order_normalization() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut config = transaction_config(42, Action::Stat);
    config.kdamonds[0].contexts[0].schemes[0].filters = vec![
        FilterConfig::new(SchemeFilterType::Anonymous, true, true),
        FilterConfig::address(0, 4096, true, true),
    ];

    damon
        .stage_configuration(&config)
        .expect("split layout may canonicalize filter order");
    let writes = model.write_count();
    damon
        .stage_configuration(&config)
        .expect("canonicalized readback is a no-op");

    assert_eq!(model.write_count(), writes);
    let observed = damon.admin.configuration().expect("read canonical filters");
    assert_eq!(
        observed.kdamonds[0].contexts[0].schemes[0].filters[0].filter_type,
        SchemeFilterType::Address
    );
}

#[test]
fn exclusive_capability_probe_observes_current_damo_controls() {
    let model = Model::new("vaddr\n");
    model.enable_current_damo_extensions();
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

    let capabilities = damon.capabilities().expect("probe current controls");

    for feature in [
        SysfsFeature::ProbeWeight,
        SysfsFeature::ProbePreparations,
        SysfsFeature::ProbePreparationSetPageIdle,
        SysfsFeature::ProbeTypePageIdleUnset,
        SysfsFeature::SampleControl,
        SysfsFeature::OperationAttributes,
    ] {
        assert_eq!(
            capabilities.feature_support(feature),
            CapabilitySupport::Supported,
            "unexpected support for {feature:?}"
        );
    }
}

#[test]
fn transactional_staging_repairs_a_malformed_stopped_configuration() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let config = transaction_config(42, Action::Stat);
    damon
        .stage_configuration(&config)
        .expect("stage original configuration");
    model.set_file(
        "kdamonds/0/contexts/0/monitoring_attrs/intervals/sample_us",
        b"malformed\n",
    );

    damon
        .stage_configuration(&config)
        .expect("replace malformed staged input");

    assert_eq!(
        damon
            .admin
            .configuration()
            .expect("read repaired configuration"),
        config
    );
}

#[test]
fn transactional_staging_retries_a_transient_kernel_busy_error() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = transaction_config(42, Action::Stat);
    damon
        .stage_configuration(&original)
        .expect("stage original configuration");
    model.fail_next_write("kdamonds/0/contexts/0/schemes/0/watermarks/low", 16);
    let replacement = transaction_config(77, Action::PageOut);

    damon
        .stage_configuration(&replacement)
        .expect("retry transient EBUSY");

    assert_eq!(
        damon
            .admin
            .configuration()
            .expect("read replacement configuration"),
        replacement
    );
}

#[test]
fn transactional_staging_validates_before_locking_or_writing() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let _held_lock = SessionLock::acquire(lock.path()).expect("hold session lock");
    let mut invalid = transaction_config(42, Action::Stat);
    invalid.kdamonds[0].contexts[0].targets[0].initial_regions = vec![
        crate::sysfs::InitialRegionConfig::new(100, 200).expect("valid region"),
        crate::sysfs::InitialRegionConfig::new(150, 250).expect("valid region"),
    ];
    let writes = model.write_count();

    let error = damon
        .stage_configuration(&invalid)
        .expect_err("validation must precede lock acquisition");

    assert!(matches!(error, Error::InvalidConfiguration { .. }));
    assert_eq!(model.write_count(), writes);
}

#[test]
fn transactional_staging_uses_the_session_lock() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let _held_lock = SessionLock::acquire(lock.path()).expect("hold session lock");

    let error = damon
        .stage_configuration(&transaction_config(42, Action::Stat))
        .expect_err("cooperating transaction must honor the lock");

    assert!(matches!(error, Error::SessionLockBusy { .. }));
    assert_eq!(damon.admin.kdamond_count().expect("read count"), 0);
}

#[test]
fn transactional_staging_restores_typed_and_unknown_values_after_io_failure() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = transaction_config(42, Action::Stat);
    damon
        .stage_configuration(&original)
        .expect("stage original configuration");
    let unknown = "kdamonds/0/contexts/0/schemes/0/future_policy";
    model.set_file(unknown, b"preserve\n");
    model.after_next_write(
        "kdamonds/0/contexts/0/schemes/0/action",
        b"pageout".to_vec(),
        vec![Mutation::SetFile {
            path: unknown.into(),
            value: b"changed\n".to_vec(),
        }],
    );
    model.fail_next_write("kdamonds/0/contexts/0/schemes/0/watermarks/low", 5);

    let mut replacement = transaction_config(77, Action::PageOut);
    replacement.kdamonds[0].contexts[0].schemes[0]
        .watermarks
        .low = 1;
    let error = damon
        .stage_configuration(&replacement)
        .expect_err("late write failure must roll back");

    assert!(
        matches!(error, Error::Io { .. }),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        damon
            .admin
            .configuration()
            .expect("read restored configuration"),
        original
    );
    assert_eq!(model.value(unknown).as_deref(), Some("preserve"));
}

#[test]
fn transactional_staging_restores_after_kernel_readback_mismatch() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = transaction_config(42, Action::Stat);
    damon
        .stage_configuration(&original)
        .expect("stage original configuration");
    model.after_next_write(
        "kdamonds/0/contexts/0/schemes/0/watermarks/low",
        b"1".to_vec(),
        vec![Mutation::SetFile {
            path: "kdamonds/0/contexts/0/schemes/0/action".into(),
            value: b"cold\n".to_vec(),
        }],
    );

    let mut replacement = transaction_config(77, Action::PageOut);
    replacement.kdamonds[0].contexts[0].schemes[0]
        .watermarks
        .low = 1;
    let error = damon
        .stage_configuration(&replacement)
        .expect_err("mismatched readback must roll back");

    match error {
        Error::ConfigurationMismatch {
            path,
            expected,
            observed,
        } => {
            assert_eq!(path.as_ref(), "kdamonds/0/contexts/0/schemes/0/action");
            assert_eq!(expected.as_ref(), "PageOut");
            assert_eq!(observed.as_ref(), "Cold");
        }
        error => panic!("unexpected error: {error:?}"),
    }
    assert_eq!(
        damon
            .admin
            .configuration()
            .expect("read restored configuration"),
        original
    );
}

#[test]
fn transactional_rollback_reconstructs_the_original_indexed_hierarchy() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = transaction_config(42, Action::Stat);
    damon
        .stage_configuration(&original)
        .expect("stage original configuration");
    let mut replacement = transaction_config(77, Action::PageOut);
    replacement
        .kdamonds
        .push(transaction_config(88, Action::Cold).kdamonds.remove(0));
    model.fail_next_write("kdamonds/1/contexts/0/schemes/0/watermarks/low", 5);

    let error = damon
        .stage_configuration(&replacement)
        .expect_err("second kdamond failure must restore the first hierarchy");

    assert!(matches!(error, Error::Io { .. }));
    assert_eq!(damon.admin.kdamond_count().expect("read count"), 1);
    assert_eq!(
        damon
            .admin
            .configuration()
            .expect("read reconstructed configuration"),
        original
    );
}

#[test]
fn transactional_rollback_restores_an_empty_sysfs_string() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut original = transaction_config(42, Action::Stat);
    original.kdamonds[0].contexts[0].schemes[0].quota.goals =
        vec![QuotaGoalConfig::new(QuotaGoalMetric::UserInput, 0)];
    damon
        .stage_configuration(&original)
        .expect("stage empty quota-goal path");

    let mut replacement = transaction_config(77, Action::PageOut);
    replacement.kdamonds[0].contexts[0].schemes[0].quota.goals = vec![QuotaGoalConfig {
        metric: QuotaGoalMetric::NodeMemoryControlGroupFreeBasisPoints,
        target_value: 0,
        current_value: 0,
        node_id: Some(1),
        cgroup_path: Some("/workload".to_owned()),
    }];
    replacement.kdamonds[0].contexts[0].schemes[0]
        .watermarks
        .low = 1;
    model.fail_next_write("kdamonds/0/contexts/0/schemes/0/watermarks/low", 5);

    let error = damon
        .stage_configuration(&replacement)
        .expect_err("late failure must restore an empty path");

    assert!(matches!(error, Error::Io { .. }));
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/schemes/0/quotas/goals/0/path")
            .as_deref(),
        Some("")
    );
    assert_eq!(
        damon
            .admin
            .configuration()
            .expect("read restored configuration"),
        original
    );
}

#[test]
fn transactional_staging_never_replaces_a_running_kdamond() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = transaction_config(42, Action::Stat);
    damon
        .stage_configuration(&original)
        .expect("stage original configuration");
    let kdamond = damon.admin.kdamond(0);
    kdamond.command(&KdamondCommand::On).expect("start kdamond");

    let error = damon
        .stage_configuration(&transaction_config(77, Action::PageOut))
        .expect_err("running hierarchy must not be replaced");

    assert!(matches!(error, Error::KdamondRunning { index: 0 }));
    assert_eq!(kdamond.state().expect("read state"), KdamondState::On);
    kdamond.command(&KdamondCommand::Off).expect("stop fixture");
}

#[test]
fn external_start_during_transaction_prevents_destructive_rollback() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    damon
        .stage_configuration(&transaction_config(42, Action::Stat))
        .expect("stage original configuration");
    model.after_next_write(
        "kdamonds/0/contexts/0/schemes/0/action",
        b"pageout".to_vec(),
        vec![Mutation::StartKdamond {
            path: "kdamonds/0".into(),
        }],
    );

    let error = damon
        .stage_configuration(&transaction_config(77, Action::PageOut))
        .expect_err("external start must prevent rollback");

    assert!(matches!(
        error,
        Error::Rollback {
            operation,
            rollback,
        } if matches!(*operation, Error::KdamondRunning { index: 0 })
            && matches!(*rollback, Error::KdamondRunning { index: 0 })
    ));
    let kdamond = damon.admin.kdamond(0);
    assert_eq!(kdamond.state().expect("read state"), KdamondState::On);
    kdamond.command(&KdamondCommand::Off).expect("stop fixture");
}

#[test]
fn exclusive_session_setup_failure_restores_the_empty_hierarchy() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    model.fail_next_write("kdamonds/0/contexts/0/schemes/0/watermarks/low", 5);

    let error = damon
        .exclusive_session(&transaction_config(42, Action::Stat))
        .expect_err("late staging failure must fail session setup");

    assert!(
        matches!(error, Error::Io { .. }),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        damon.admin.kdamond_count().expect("read rolled-back count"),
        0
    );
}

#[test]
fn failed_on_does_not_stop_an_external_kdamond() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut session = damon
        .exclusive_session(&transaction_config(42, Action::Stat))
        .expect("stage session");
    model.after_next_read(
        "kdamonds/0/state",
        vec![Mutation::StartKdamond {
            path: "kdamonds/0".into(),
        }],
    );

    let operation = session
        .start()
        .expect_err("external start must prevent ownership");
    let error = with_rollback(operation, session.close());

    assert!(matches!(
        error,
        Error::Rollback {
            operation,
            rollback,
        } if operation.is_resource_busy()
            && matches!(*rollback, Error::OwnershipLost {
                reason: "the staged kdamond was started by another controller"
            })
    ));
    let kdamond = damon.admin.kdamond(0);
    assert_eq!(
        kdamond.state().expect("read external state"),
        KdamondState::On
    );
    assert!(kdamond.pid().expect("read external pid").is_some());

    kdamond.command(&KdamondCommand::Off).expect("stop fixture");
    damon.admin.set_kdamond_count(0).expect("remove fixture");
}

#[test]
fn exclusive_session_restores_a_multi_kdamond_hierarchy_after_runtime_commands() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut original = transaction_config(41, Action::Stat);
    original
        .kdamonds
        .push(transaction_config(43, Action::Cold).kdamonds.remove(0));
    damon
        .stage_configuration(&original)
        .expect("stage preceding hierarchy");
    let future_attribute = "kdamonds/0/contexts/0/future_session_input";
    model.set_file(future_attribute, b"preserve\n");

    let mut replacement = transaction_config(42, Action::Stat);
    replacement.kdamonds[0].contexts[0].intervals_goal = IntervalsGoalConfig {
        access_basis_points: 100,
        aggregation_intervals: 1,
        minimum_sample: Duration::from_millis(1),
        maximum_sample: Duration::from_millis(10),
    };
    let mut session = damon
        .exclusive_session(&replacement)
        .expect("stage exclusive replacement");
    assert_eq!(damon.admin.kdamond_count().expect("read count"), 1);
    assert!(matches!(
        damon.exclusive_session(&replacement),
        Err(Error::SessionLockBusy { .. })
    ));

    configure_runtime_results(&model);
    exercise_session_runtime(&model, &mut session);
    session
        .close()
        .expect("stop and restore preceding hierarchy");

    assert_eq!(
        damon
            .admin
            .configuration()
            .expect("read restored hierarchy"),
        original
    );
    assert_eq!(model.value(future_attribute).as_deref(), Some("preserve"));
}
