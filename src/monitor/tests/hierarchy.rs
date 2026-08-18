use super::*;

#[test]
fn managed_hierarchy_starts_stops_and_restores_every_kdamond() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let preceding = multi_transaction_config();
    damon
        .stage_configuration(&preceding)
        .expect("stage preceding hierarchy");
    let future_attribute = "kdamonds/1/contexts/0/future_session_input";
    model.set_file(future_attribute, b"preserve\n");

    let mut requested = multi_transaction_config();
    requested.kdamonds[0].contexts[0].targets[0].pid = Some(Pid::new(47).expect("valid pid"));
    requested.kdamonds[1].contexts[0].targets[0].pid = Some(Pid::new(53).expect("valid pid"));
    let mut managed = damon
        .managed_hierarchy(&requested)
        .expect("stage managed hierarchy");

    assert_eq!(managed.kdamond_count(), 2);
    assert!(matches!(
        damon.managed_hierarchy(&requested),
        Err(Error::SessionLockBusy { .. })
    ));
    managed.start_all().expect("start all kdamonds");
    assert!(managed.is_running(0).expect("read first state"));
    assert!(managed.is_running(1).expect("read second state"));
    let first_pid = damon
        .admin
        .kdamond(0)
        .pid()
        .expect("read first pid")
        .expect("first pid");
    let second_pid = damon
        .admin
        .kdamond(1)
        .pid()
        .expect("read second pid")
        .expect("second pid");
    assert_ne!(first_pid, second_pid);

    managed.stop_all().expect("stop all kdamonds");
    assert!(!managed.is_running(0).expect("read first stopped state"));
    assert!(!managed.is_running(1).expect("read second stopped state"));
    managed.start_all().expect("restart all kdamonds");
    managed.close().expect("restore preceding hierarchy");

    assert_eq!(
        damon
            .admin
            .configuration()
            .expect("read restored hierarchy"),
        preceding
    );
    assert_eq!(model.value(future_attribute).as_deref(), Some("preserve"));
}

#[test]
fn managed_hierarchy_runtime_targets_one_owned_kdamond() {
    let model = Model::new("vaddr\n");
    configure_runtime_results(&model);
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut managed = damon
        .managed_hierarchy(&multi_transaction_config())
        .expect("stage managed hierarchy");
    managed.start_all().expect("start all kdamonds");
    model.after_next_write(
        "kdamonds/1/state",
        b"update_schemes_stats".to_vec(),
        vec![Mutation::SetFile {
            path: "kdamonds/1/contexts/0/schemes/0/stats/nr_tried".into(),
            value: b"77\n".to_vec(),
        }],
    );

    let stats = managed
        .runtime(1)
        .expect("borrow second runtime")
        .runtime_batch(|batch| {
            assert_eq!(batch.kdamond_index(), 1);
            batch.scheme_stats(0, 0)
        })
        .expect("read second kdamond stats");

    assert_eq!(stats.regions_tried, 77);
    assert!(matches!(
        managed.runtime(2),
        Err(Error::IndexOutOfBounds { .. })
    ));
    managed.close().expect("close hierarchy");
}

#[test]
fn later_start_failure_rolls_back_identified_kdamonds() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut managed = damon
        .managed_hierarchy(&multi_transaction_config())
        .expect("stage managed hierarchy");
    model.fail_next_write("kdamonds/1/state", 22);

    let error = managed
        .start_all()
        .expect_err("second start must fail and roll back the first");

    assert!(matches!(error, Error::Io { .. }));
    for index in 0..2 {
        assert_eq!(
            damon.admin.kdamond(index).state().expect("read state"),
            KdamondState::Off
        );
        assert!(!managed.is_running(index).expect("read managed state"));
    }
    managed.close().expect("restore empty hierarchy");
    assert_eq!(damon.admin.kdamond_count().expect("read count"), 0);
}

#[test]
fn later_configuration_replacement_prevents_start_and_rolls_back() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut managed = damon
        .managed_hierarchy(&multi_transaction_config())
        .expect("stage managed hierarchy");
    let changed_path = "kdamonds/1/contexts/0/schemes/0/action";
    model.after_next_write(
        "kdamonds/0/state",
        b"on".to_vec(),
        vec![Mutation::SetFile {
            path: changed_path.into(),
            value: b"pageout\n".to_vec(),
        }],
    );

    let error = managed
        .start_all()
        .expect_err("replacement configuration must prevent the later start");

    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the staged writable configuration changed"
        }
    ));
    for index in 0..2 {
        assert_eq!(
            damon.admin.kdamond(index).state().expect("read state"),
            KdamondState::Off
        );
    }
    model.set_file(changed_path, b"cold\n");
    managed.close().expect("close repaired hierarchy");
}

#[test]
fn partial_pid_replacement_never_stops_the_replacement() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut managed = damon
        .managed_hierarchy(&multi_transaction_config())
        .expect("stage managed hierarchy");
    managed.start_all().expect("start all kdamonds");
    model.set_file("kdamonds/1/pid", b"99999\n");

    let error = managed
        .stop_all()
        .expect_err("replacement identity must be rejected");

    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the kdamond kernel-thread ID changed"
        }
    ));
    assert_eq!(
        damon.admin.kdamond(0).state().expect("read first state"),
        KdamondState::Off
    );
    assert_eq!(
        damon
            .admin
            .kdamond(1)
            .state()
            .expect("read replacement state"),
        KdamondState::On
    );
    assert!(managed.close().is_err());

    damon
        .admin
        .kdamond(1)
        .command(&KdamondCommand::Off)
        .expect("stop external replacement fixture");
    damon.admin.set_kdamond_count(0).expect("remove fixture");
}

#[test]
fn partial_configuration_replacement_is_detected_before_restore() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut managed = damon
        .managed_hierarchy(&multi_transaction_config())
        .expect("stage managed hierarchy");
    managed.start_all().expect("start all kdamonds");
    model.set_file("kdamonds/1/contexts/0/schemes/0/action", b"pageout\n");

    let error = managed
        .close()
        .expect_err("changed configuration must not be restored over");

    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the staged writable configuration changed"
        }
    ));
    assert_eq!(
        damon.admin.kdamond(0).state().expect("read owned state"),
        KdamondState::Off
    );
    assert_eq!(
        damon
            .admin
            .kdamond(1)
            .state()
            .expect("read replacement state"),
        KdamondState::On
    );
    assert_eq!(
        model
            .value("kdamonds/1/contexts/0/schemes/0/action")
            .as_deref(),
        Some("pageout")
    );
    damon
        .admin
        .kdamond(1)
        .command(&KdamondCommand::Off)
        .expect("stop external replacement fixture");
    damon.admin.set_kdamond_count(0).expect("remove fixture");
}

#[test]
fn managed_hierarchy_validates_before_locking_or_writing() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let _held_lock = SessionLock::acquire(lock.path()).expect("hold session lock");
    let mut invalid = multi_transaction_config();
    invalid.kdamonds[1].contexts.clear();
    let writes = model.write_count();

    let error = damon
        .managed_hierarchy(&invalid)
        .expect_err("validation must precede lock acquisition");

    assert!(matches!(error, Error::InvalidConfiguration { .. }));
    assert_eq!(model.write_count(), writes);
}

#[test]
fn selected_running_update_commits_only_selected_kdamonds() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = multi_transaction_config();
    let mut managed = damon
        .managed_hierarchy(&original)
        .expect("stage managed hierarchy");
    managed.start_all().expect("start all kdamonds");
    let mut updated = original.clone();
    updated.kdamonds[1].contexts[0].schemes[0].action = Action::PageOut;

    managed
        .update_configuration(&updated, &[1])
        .expect("commit selected update");

    assert_eq!(
        managed.configuration().expect("read staged update"),
        updated
    );
    assert_eq!(
        model
            .active_value("kdamonds/0/contexts/0/schemes/0/action")
            .as_deref(),
        Some("stat")
    );
    assert_eq!(
        model
            .active_value("kdamonds/1/contexts/0/schemes/0/action")
            .as_deref(),
        Some("pageout")
    );
    managed.close().expect("close hierarchy");
}

#[test]
fn selected_running_update_rejects_unselected_changes_before_writing() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = multi_transaction_config();
    let mut managed = damon
        .managed_hierarchy(&original)
        .expect("stage managed hierarchy");
    managed.start_all().expect("start all kdamonds");
    let mut updated = original.clone();
    updated.kdamonds[0].contexts[0].schemes[0].action = Action::WillNeed;
    updated.kdamonds[1].contexts[0].schemes[0].action = Action::PageOut;
    let writes = model.write_count();

    let error = managed
        .update_configuration(&updated, &[1])
        .expect_err("unselected change must fail");

    assert!(matches!(error, Error::InvalidConfiguration { .. }));
    assert_eq!(model.write_count(), writes);
    managed.close().expect("close hierarchy");
}

#[test]
fn selected_running_update_does_not_adopt_changes_during_readback() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = multi_transaction_config();
    let mut managed = damon
        .managed_hierarchy(&original)
        .expect("stage managed hierarchy");
    managed.start_all().expect("start all kdamonds");
    let changed_path = "kdamonds/0/contexts/0/targets/0/pid_target";
    model.after_next_read("kdamonds/1/contexts/0/schemes/0/action", Vec::new());
    model.after_next_read(
        "kdamonds/1/contexts/0/schemes/0/action",
        vec![Mutation::SetFile {
            path: changed_path.into(),
            value: b"77\n".to_vec(),
        }],
    );
    let mut updated = original;
    updated.kdamonds[1].contexts[0].schemes[0].action = Action::PageOut;
    let writes = model.write_count();

    let error = managed
        .update_configuration(&updated, &[1])
        .expect_err("concurrent change must not become the rollback baseline");

    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the staged writable configuration changed"
        }
    ));
    assert_eq!(model.write_count(), writes);
    model.set_file(changed_path, b"41\n");
    managed.close().expect("close repaired hierarchy");
}

#[test]
fn selected_running_update_rolls_back_every_committed_kdamond() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = multi_transaction_config();
    let mut managed = damon
        .managed_hierarchy(&original)
        .expect("stage managed hierarchy");
    managed.start_all().expect("start all kdamonds");
    let mut updated = original.clone();
    updated.kdamonds[0].contexts[0].schemes[0].action = Action::WillNeed;
    updated.kdamonds[1].contexts[0].schemes[0].action = Action::PageOut;
    model.fail_next_write("kdamonds/1/state", 22);

    let error = managed
        .update_configuration(&updated, &[0, 1])
        .expect_err("second commit must fail");

    assert!(matches!(error, Error::Io { .. }));
    assert_eq!(
        managed.configuration().expect("read rolled-back staging"),
        original
    );
    assert_eq!(
        model
            .active_value("kdamonds/0/contexts/0/schemes/0/action")
            .as_deref(),
        Some("stat")
    );
    assert_eq!(
        model
            .active_value("kdamonds/1/contexts/0/schemes/0/action")
            .as_deref(),
        Some("cold")
    );
    managed.close().expect("close hierarchy");
}

#[test]
fn selected_running_update_validates_indexes_before_writing() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let config = multi_transaction_config();
    let mut managed = damon
        .managed_hierarchy(&config)
        .expect("stage managed hierarchy");
    managed.start_all().expect("start all kdamonds");

    for indices in [&[][..], &[0, 0][..], &[2][..]] {
        let writes = model.write_count();
        let error = managed
            .update_configuration(&config, indices)
            .expect_err("invalid selection must fail");
        assert!(matches!(
            error,
            Error::InvalidConfiguration { .. } | Error::IndexOutOfBounds { .. }
        ));
        assert_eq!(model.write_count(), writes);
    }
    managed.close().expect("close hierarchy");
}

#[test]
fn selected_running_update_preserves_unselected_tuned_intervals() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut original = multi_transaction_config();
    original.kdamonds[0].contexts[0].intervals_goal = IntervalsGoalConfig {
        access_basis_points: 100,
        aggregation_intervals: 1,
        minimum_sample: Duration::from_millis(1),
        maximum_sample: Duration::from_millis(10),
    };
    let mut managed = damon
        .managed_hierarchy(&original)
        .expect("stage managed hierarchy");
    managed.start_all().expect("start all kdamonds");
    let sample_path = "kdamonds/0/contexts/0/monitoring_attrs/intervals/sample_us";
    model.set_file(sample_path, b"4000\n");
    model.set_file(
        "kdamonds/0/contexts/0/monitoring_attrs/intervals/aggr_us",
        b"80000\n",
    );
    model.fail_next_write(sample_path, 22);
    let mut updated = original;
    updated.kdamonds[1].contexts[0].schemes[0].action = Action::PageOut;

    managed
        .update_configuration(&updated, &[1])
        .expect("update must preserve unselected tuned leaves");

    assert_eq!(model.value(sample_path).as_deref(), Some("4000"));
    assert_eq!(
        model
            .active_value("kdamonds/1/contexts/0/schemes/0/action")
            .as_deref(),
        Some("pageout")
    );
    managed.close().expect("close hierarchy");
}

#[test]
fn unidentified_running_state_is_reported_as_ownership_loss() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut managed = damon
        .managed_hierarchy(&transaction_config(42, Action::Stat))
        .expect("stage managed hierarchy");
    model.after_next_write(
        "kdamonds/0/state",
        b"on".to_vec(),
        vec![Mutation::SetFile {
            path: "kdamonds/0/pid".into(),
            value: b"-1\n".to_vec(),
        }],
    );

    assert!(managed.start_all().is_err());
    assert!(matches!(
        managed.runtime(0),
        Err(Error::OwnershipLost {
            reason: "the kdamond started but its identity was not captured"
        })
    ));
    assert!(matches!(
        managed.is_running(0),
        Err(Error::OwnershipLost {
            reason: "the kdamond started but its identity was not captured"
        })
    ));

    damon
        .admin
        .kdamond(0)
        .command(&KdamondCommand::Off)
        .expect("stop unidentified model kdamond");
    managed.close().expect("restore hierarchy");
}

#[test]
fn running_state_check_performs_one_complete_fingerprint_scan() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut managed = damon
        .managed_hierarchy(&transaction_config(42, Action::Stat))
        .expect("stage managed hierarchy");
    managed.start_all().expect("start hierarchy");

    let reads = model.read_count();
    managed.verify_running(0).expect("verify running state");
    let verification_reads = model.read_count() - reads;
    let reads = model.read_count();
    assert!(managed.is_running(0).expect("read running state"));
    let state_reads = model.read_count() - reads;

    assert_eq!(state_reads, verification_reads);
    managed.close().expect("close hierarchy");
}

#[test]
fn hierarchy_runtime_batch_avoids_repeated_cross_kdamond_scans() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut managed = damon
        .managed_hierarchy(&multi_transaction_config())
        .expect("stage managed hierarchy");
    managed.start_all().expect("start hierarchy");

    let reads = model.read_count();
    managed
        .runtime(0)
        .expect("first runtime")
        .cached_scheme_stats(0, 0)
        .expect("read first stats");
    managed
        .runtime(1)
        .expect("second runtime")
        .cached_scheme_stats(0, 0)
        .expect("read second stats");
    let ordinary_reads = model.read_count() - reads;

    let reads = model.read_count();
    managed
        .runtime_batch(|batch| {
            batch.kdamond(0)?.cached_scheme_stats(0, 0)?;
            batch.kdamond(1)?.cached_scheme_stats(0, 0)?;
            Ok(())
        })
        .expect("read hierarchy batch");
    let batched_reads = model.read_count() - reads;

    assert!(batched_reads < ordinary_reads);
    managed.close().expect("close hierarchy");
}

#[test]
fn managed_capabilities_are_available_before_start() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let managed = damon
        .managed_hierarchy(&transaction_config(42, Action::Stat))
        .expect("stage managed hierarchy");

    let capabilities = managed
        .capabilities(0, 0, 0)
        .expect("discover staged capabilities");

    assert!(capabilities.supports_operation(&Operation::VirtualAddress));
    managed.close().expect("close hierarchy");
}
