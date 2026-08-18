use super::*;

#[test]
fn exclusive_session_shape_validation_precedes_locking_and_writes() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let _held_lock = SessionLock::acquire(lock.path()).expect("hold session lock");
    let writes = model.write_count();

    let error = damon
        .exclusive_session(&DamonConfig::default())
        .expect_err("empty session configuration must fail before locking");

    assert!(matches!(
        error,
        Error::InvalidConfiguration {
            field: "exclusive session kdamond count",
            ..
        }
    ));
    assert_eq!(model.write_count(), writes);
}

#[test]
fn paddr_scaling_validation_precedes_locking_and_writes() {
    let model = Model::new("paddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let _held_lock = SessionLock::acquire(lock.path()).expect("hold session lock");
    let writes = model.write_count();

    let error = damon
        .paddr()
        .address_unit(AddressUnit::new(u64::MAX).expect("nonzero unit"))
        .region_units(InitialRegionConfig::new(1, 2).expect("valid raw region"))
        .start()
        .expect_err("scaled end must overflow before locking");

    assert!(matches!(
        error,
        Error::AddressConversionOverflow {
            units: 2,
            unit_bytes: u64::MAX
        }
    ));
    assert_eq!(model.write_count(), writes);
}

#[test]
fn pid_replacement_prevents_started_monitor_rollback() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    model.after_next_read(
        "kdamonds/0/pid",
        vec![Mutation::StartKdamond {
            path: "kdamonds/0".into(),
        }],
    );

    let error = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect_err("replacement pid must prevent ownership");

    assert!(matches!(
        error,
        Error::Rollback {
            operation,
            rollback,
        } if matches!(*operation, Error::OwnershipLost {
                reason: "the kdamond kernel-thread ID changed"
            })
            && matches!(*rollback, Error::OwnershipLost {
                reason: "the kdamond kernel-thread ID changed"
            })
    ));
    let kdamond = damon.admin.kdamond(0);
    assert_eq!(
        kdamond.state().expect("read replacement state"),
        KdamondState::On
    );
    assert!(kdamond.pid().expect("read replacement pid").is_some());

    kdamond.command(&KdamondCommand::Off).expect("stop fixture");
    damon.admin.set_kdamond_count(0).expect("remove fixture");
}

#[test]
fn stop_detects_an_immediate_kdamond_restart() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut session = damon
        .exclusive_session(&transaction_config(42, Action::Stat))
        .expect("stage session");
    session.start().expect("start session");
    model.after_next_write(
        "kdamonds/0/state",
        b"off".to_vec(),
        vec![Mutation::StartKdamond {
            path: "kdamonds/0".into(),
        }],
    );

    let error = session
        .stop()
        .expect_err("an immediate replacement start must be detected");

    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the kdamond restarted while it was being stopped"
        }
    ));
    let kdamond = damon.admin.kdamond(0);
    kdamond
        .command(&KdamondCommand::Off)
        .expect("stop replacement fixture");
    session.close().expect("restore after replacement stopped");
}

#[test]
fn missing_startup_pid_does_not_trigger_unidentified_stop() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    model.after_next_write(
        "kdamonds/0/state",
        b"on".to_vec(),
        vec![Mutation::SetFile {
            path: "kdamonds/0/pid".into(),
            value: b"-1\n".to_vec(),
        }],
    );

    let error = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect_err("missing kernel-thread ID must fail startup");

    assert!(matches!(
        error,
        Error::Rollback {
            operation,
            rollback,
        } if matches!(*operation, Error::OwnershipLost {
                reason: "a running kdamond did not expose a kernel-thread ID"
            })
            && matches!(*rollback, Error::OwnershipLost {
                reason: "cannot safely stop a kdamond before its kernel-thread ID was captured"
            })
    ));
    let kdamond = damon.admin.kdamond(0);
    assert_eq!(
        kdamond.state().expect("read running state"),
        KdamondState::On
    );

    kdamond.command(&KdamondCommand::Off).expect("stop fixture");
    damon.admin.set_kdamond_count(0).expect("remove fixture");
}

#[test]
fn snapshot_rechecks_ownership_after_materialization_command() {
    let model = Model::new("vaddr\nfvaddr\npaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start modeled monitor");
    model.after_next_write(
        "kdamonds/0/state",
        b"update_schemes_tried_regions".to_vec(),
        vec![Mutation::SetFile {
            path: "kdamonds/0/contexts/0/targets/0/pid_target".into(),
            value: b"77\n".to_vec(),
        }],
    );

    let error = monitor
        .materialize_snapshot()
        .expect_err("post-command ownership change must discard results");
    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the staged writable configuration changed"
        }
    ));
}

#[test]
fn snapshot_rechecks_ownership_after_reading_results() {
    let model = Model::new("vaddr\nfvaddr\npaddr\n");
    model.set_tried_regions(vec![ModelRegion {
        start: 4_096,
        end: 8_192,
        nr_accesses: 7,
        age: 3,
        filter_passed_units: Some(4_096),
        probe_hits: vec![2, 5],
    }]);
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start modeled monitor");
    model.after_next_read(
        "kdamonds/0/contexts/0/schemes/0/tried_regions/0/age",
        vec![Mutation::SetFile {
            path: "kdamonds/0/contexts/0/targets/0/pid_target".into(),
            value: b"77\n".to_vec(),
        }],
    );

    let error = monitor
        .materialize_snapshot()
        .expect_err("post-read ownership change must discard results");
    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the staged writable configuration changed"
        }
    ));
}

#[test]
fn exclusive_capability_probe_materializes_nested_attributes_and_restores_empty_state() {
    let model = Model::new("vaddr\nfvaddr\npaddr\nfuture_operation\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

    let capabilities = damon.capabilities().expect("probe modeled capabilities");

    assert_eq!(damon.admin.kdamond_count().expect("read restored count"), 0);
    assert_eq!(
        capabilities.damo_feature_support("sysfs/ctx_pause"),
        Some(CapabilitySupport::Supported)
    );
    assert_eq!(capabilities.damo_feature_support("sysfs/not_known"), None);
    assert_eq!(
        capabilities.feature_support(SysfsFeature::ProbeFilterPath),
        CapabilitySupport::Supported
    );
    assert!(capabilities.has_attribute("contexts/0/monitoring_attrs/probes/0/filters/0/path"));
    assert!(capabilities.has_attribute("contexts/0/schemes/0/quotas/goals/0/target_metric"));
    assert!(capabilities.operations().iter().any(|capability| {
        capability.operation() == &Operation::Unknown("future_operation".into())
            && capability.support() == CapabilitySupport::Supported
    }));
    assert_eq!(
        capabilities
            .features()
            .iter()
            .filter(|capability| capability.feature().damo_name().is_some())
            .count(),
        57
    );
}

#[test]
fn exclusive_capability_probe_preserves_an_existing_hierarchy() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = transaction_config(42, Action::Stat);
    damon
        .stage_configuration(&original)
        .expect("stage external hierarchy");
    model.set_file("kdamonds/0/contexts/0/future_input", b"preserve\n");

    damon
        .capabilities()
        .expect("probe around stopped configuration");

    assert_eq!(damon.admin.kdamond_count().expect("preserve count"), 1);
    assert_eq!(
        damon
            .admin
            .configuration()
            .expect("read restored hierarchy"),
        original
    );
    assert_eq!(
        model.value("kdamonds/0/contexts/0/future_input").as_deref(),
        Some("preserve")
    );
}

#[test]
fn exclusive_capability_probe_tests_operations_when_listing_is_absent() {
    let model = Model::without_available_operations_file("vaddr\npaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

    let capabilities = damon.capabilities().expect("probe modeled operations");

    assert_eq!(
        capabilities.feature_support(SysfsFeature::AvailableOperations),
        CapabilitySupport::Unsupported
    );
    assert_eq!(
        capabilities.operation_support(&Operation::VirtualAddress),
        Some(CapabilitySupport::Unverified)
    );
    assert_eq!(
        capabilities.operation_support(&Operation::PhysicalAddress),
        Some(CapabilitySupport::Unverified)
    );
    assert_eq!(
        capabilities.operation_support(&Operation::FixedVirtualAddress),
        Some(CapabilitySupport::Unsupported)
    );
    assert!(!capabilities.supports_operation(&Operation::VirtualAddress));
    assert_eq!(damon.admin.kdamond_count().expect("read restored count"), 0);
}

#[test]
fn legacy_operation_writes_do_not_claim_registered_support() {
    let model = Model::with_legacy_operation_sets("vaddr\n", "vaddr\npaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

    let capabilities = damon.capabilities().expect("probe legacy operations");

    assert_eq!(
        capabilities.operation_support(&Operation::PhysicalAddress),
        Some(CapabilitySupport::Unverified)
    );
    assert!(!capabilities.supports_operation(&Operation::PhysicalAddress));
}

#[test]
fn recognized_but_unregistered_operation_fails_start_and_rolls_back() {
    let model = Model::with_legacy_operation_sets("paddr\n", "vaddr\npaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

    let error = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect_err("an unregistered vaddr implementation must not start");

    assert!(matches!(error, Error::Io { .. }));
    assert_eq!(damon.admin.kdamond_count().expect("read restored count"), 0);
}

#[test]
fn exclusive_capability_probe_checks_semantic_filter_values() {
    let model = Model::new("vaddr\npaddr\nfvaddr\n");
    model.set_supported_scheme_filter_types("anon\nmemcg\naddr\ntarget\n");
    model.set_supported_probe_filter_types("anon\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

    let capabilities = damon.capabilities().expect("probe semantic values");

    assert_eq!(
        capabilities.feature_support(SysfsFeature::SchemeFilterYoung),
        CapabilitySupport::Unsupported
    );
    assert_eq!(
        capabilities.feature_support(SysfsFeature::SchemeFilterAddress),
        CapabilitySupport::Supported
    );
    assert_eq!(
        capabilities.feature_support(SysfsFeature::ProbeTypeAnonymous),
        CapabilitySupport::Supported
    );
    assert_eq!(
        capabilities.feature_support(SysfsFeature::ProbeTypeMemoryControlGroup),
        CapabilitySupport::Unsupported
    );
}

#[test]
fn exclusive_capability_probe_checks_actions_and_quota_metrics_directly() {
    let model = Model::new("vaddr\npaddr\nfvaddr\n");
    model.enable_current_damo_extensions();
    model.set_supported_scheme_actions("stat\n");
    model.set_supported_quota_goal_metrics("user_input\nsome_mem_psi_us\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

    let capabilities = damon.capabilities().expect("probe semantic values");

    assert_eq!(
        capabilities.feature_support(SysfsFeature::CollapseAction),
        CapabilitySupport::Unsupported
    );
    assert_eq!(
        capabilities.feature_support(SysfsFeature::SchemeQuotaGoalSomePsi),
        CapabilitySupport::Supported
    );
    assert_eq!(
        capabilities.feature_support(SysfsFeature::SchemeQuotaGoalNodeEligibleMemory),
        CapabilitySupport::Unsupported
    );
    assert_eq!(
        capabilities.feature_support(SysfsFeature::SchemeQuotaFailureChargeRatio),
        CapabilitySupport::Supported,
        "the unrelated structural feature remains independently observable"
    );
}

#[test]
fn exclusive_capability_probe_recognizes_damon_next_values() {
    let model = Model::new("vaddr\npaddr\nfvaddr\n");
    model.enable_current_damo_extensions();
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

    let capabilities = damon.capabilities().expect("probe damon-next values");

    for feature in [
        SysfsFeature::DamosAllocateAction,
        SysfsFeature::DamosFreeAction,
        SysfsFeature::SchemeQuotaGoalHugePageMemory,
        SysfsFeature::ProbeTypePageIdleSet,
        SysfsFeature::ProbePreparationSetPageIdle,
    ] {
        assert_eq!(
            capabilities.feature_support(feature),
            CapabilitySupport::Supported,
            "unexpected support for {feature:?}"
        );
    }
}

#[test]
fn passive_capability_probe_does_not_claim_unchecked_filter_values() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    damon
        .admin
        .set_kdamond_count(1)
        .expect("stage modeled kdamond");
    let kdamond = damon.admin.kdamond(0);
    kdamond.set_context_count(1).expect("stage context");
    let context = kdamond.context(0);
    context.set_target_count(1).expect("stage target");
    context.set_scheme_count(1).expect("stage scheme");
    kdamond
        .stage_optional_capability_children(0, 0, 0)
        .expect("stage optional children");

    let capabilities = kdamond.capabilities(0, 0).expect("inspect paths");

    assert_eq!(
        capabilities.feature_support(SysfsFeature::SchemeFilterYoung),
        CapabilitySupport::Unverified
    );
}
