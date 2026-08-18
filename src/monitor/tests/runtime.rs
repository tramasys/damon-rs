use super::*;

#[test]
fn exclusive_session_drop_best_effort_restores_the_previous_hierarchy() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = transaction_config(41, Action::Stat);
    damon
        .stage_configuration(&original)
        .expect("stage preceding hierarchy");

    {
        let mut session = damon
            .exclusive_session(&transaction_config(42, Action::PageOut))
            .expect("stage replacement");
        session.start().expect("start replacement");
    }

    assert_eq!(
        damon
            .admin
            .configuration()
            .expect("read restored hierarchy"),
        original
    );
}

#[test]
fn synchronous_refresh_is_explicit_even_with_periodic_refresh_enabled() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut config = transaction_config(42, Action::Stat);
    config.kdamonds[0].refresh_interval = Duration::from_millis(100);
    let mut session = damon.exclusive_session(&config).expect("stage session");
    session.start().expect("start session");
    let writes = model.write_count();

    session.scheme_stats(0, 0).expect("read periodic stats");
    session
        .effective_quota_units(0, 0)
        .expect("read periodic quota");
    session
        .update_tuned_intervals()
        .expect("read periodic tuned intervals");

    assert_eq!(model.write_count(), writes + 3);
    let writes = model.write_count();
    session
        .cached_scheme_stats(0, 0)
        .expect("read cached periodic stats");
    session
        .cached_effective_quota_units(0, 0)
        .expect("read cached periodic quota");
    assert_eq!(model.write_count(), writes);
    session.close().expect("close session");
}

#[test]
fn exclusive_session_transactionally_updates_a_running_configuration() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = transaction_config(42, Action::Stat);
    let mut session = damon.exclusive_session(&original).expect("stage session");
    session.start().expect("start session");
    let mut updated = original.clone();
    updated.kdamonds[0].contexts[0].schemes[0].action = Action::PageOut;

    session
        .update_configuration(&updated)
        .expect("commit running update");

    assert_eq!(
        model
            .active_value("kdamonds/0/contexts/0/schemes/0/action")
            .as_deref(),
        Some("pageout")
    );
    assert_eq!(
        session.configuration().expect("read updated ownership"),
        updated
    );
    session.close().expect("close updated session");
}

#[test]
fn running_target_removals_are_cleaned_before_consecutive_updates() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut original = transaction_config(42, Action::Stat);
    original.kdamonds[0].contexts[0]
        .targets
        .push(TargetConfig::for_pid(Pid::new(43).expect("valid pid")));
    let mut session = damon.exclusive_session(&original).expect("stage session");
    session.start().expect("start session");

    let mut remove_first = original.clone();
    remove_first.kdamonds[0].contexts[0].targets[0].obsolete = true;
    let mut stale_filter_index = remove_first.clone();
    stale_filter_index.kdamonds[0].contexts[0].schemes[0]
        .filters
        .push(FilterConfig::target(1, true, false));
    assert!(matches!(
        session.update_configuration(&stale_filter_index),
        Err(Error::InvalidConfiguration { .. })
    ));
    session
        .update_configuration(&remove_first)
        .expect("commit target removal");

    let cleaned = session
        .configuration()
        .expect("read cleaned staged hierarchy");
    assert_eq!(cleaned.kdamonds[0].contexts[0].targets.len(), 1);
    assert_eq!(
        cleaned.kdamonds[0].contexts[0].targets[0].pid,
        Some(Pid::new(43).expect("valid pid"))
    );
    assert!(!cleaned.kdamonds[0].contexts[0].targets[0].obsolete);
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/targets/nr_targets")
            .as_deref(),
        Some("1")
    );

    let mut consecutive = cleaned.clone();
    consecutive.kdamonds[0].contexts[0].schemes[0].action = Action::PageOut;
    session
        .update_configuration(&consecutive)
        .expect("commit consecutive update from cleaned state");
    assert_eq!(
        model
            .active_value("kdamonds/0/contexts/0/targets/0/pid_target")
            .as_deref(),
        Some("43")
    );

    let error = session
        .update_configuration(&remove_first)
        .expect_err("a stale obsolete marker must not target the replacement index");
    assert!(matches!(error, Error::InvalidConfiguration { .. }));
    assert_eq!(
        model
            .active_value("kdamonds/0/contexts/0/schemes/0/action")
            .as_deref(),
        Some("pageout")
    );
    session.close().expect("close updated session");
}

#[test]
fn failed_obsolete_target_cleanup_restores_the_preceding_active_targets() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut original = transaction_config(42, Action::Stat);
    original.kdamonds[0].contexts[0]
        .targets
        .push(TargetConfig::for_pid(Pid::new(43).expect("valid pid")));
    let mut session = damon.exclusive_session(&original).expect("stage session");
    session.start().expect("start session");

    let mut remove_first = original.clone();
    remove_first.kdamonds[0].contexts[0].targets[0].obsolete = true;
    model.fail_next_write("kdamonds/0/contexts/0/targets/nr_targets", 5);
    let error = session
        .update_configuration(&remove_first)
        .expect_err("failed cleanup must roll back the active removal");

    assert!(matches!(error, Error::Io { .. }));
    assert_eq!(
        session.configuration().expect("read rolled-back hierarchy"),
        original
    );
    assert_eq!(
        model
            .active_value("kdamonds/0/contexts/0/targets/0/pid_target")
            .as_deref(),
        Some("42")
    );
    session.close().expect("close rolled-back session");
}

#[test]
fn running_configuration_update_rolls_back_after_commit_failure() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let original = transaction_config(42, Action::Stat);
    let mut session = damon.exclusive_session(&original).expect("stage session");
    session.start().expect("start session");
    let mut updated = original.clone();
    updated.kdamonds[0].contexts[0].schemes[0].action = Action::PageOut;
    model.fail_next_write("kdamonds/0/state", 5);

    let error = session
        .update_configuration(&updated)
        .expect_err("failed commit must roll back");

    assert!(matches!(error, Error::Io { .. }));
    assert_eq!(
        model
            .active_value("kdamonds/0/contexts/0/schemes/0/action")
            .as_deref(),
        Some("stat")
    );
    assert_eq!(
        session.configuration().expect("retain original ownership"),
        original
    );
    session.close().expect("close rolled-back session");
}

#[test]
fn running_update_accepts_kernel_tuned_interval_races() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut original = transaction_config(42, Action::Stat);
    original.kdamonds[0].contexts[0].intervals_goal = IntervalsGoalConfig {
        access_basis_points: 100,
        aggregation_intervals: 1,
        minimum_sample: Duration::from_millis(1),
        maximum_sample: Duration::from_millis(10),
    };
    let mut session = damon.exclusive_session(&original).expect("stage session");
    session.start().expect("start session");
    let mut updated = original.clone();
    updated.kdamonds[0].contexts[0].schemes[0].action = Action::PageOut;
    model.after_next_write(
        "kdamonds/0/contexts/0/schemes/0/action",
        b"pageout".to_vec(),
        vec![
            Mutation::SetFile {
                path: "kdamonds/0/contexts/0/monitoring_attrs/intervals/sample_us".into(),
                value: b"4000\n".to_vec(),
            },
            Mutation::SetFile {
                path: "kdamonds/0/contexts/0/monitoring_attrs/intervals/aggr_us".into(),
                value: b"80000\n".to_vec(),
            },
        ],
    );

    session
        .update_configuration(&updated)
        .expect("accept tuned read-back values");
    assert_eq!(
        model
            .active_value("kdamonds/0/contexts/0/schemes/0/action")
            .as_deref(),
        Some("pageout")
    );
    session.close().expect("close tuned session");
}

#[test]
fn runtime_batch_avoids_repeated_full_fingerprint_scans() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let config = transaction_config(42, Action::Stat);
    let mut session = damon.exclusive_session(&config).expect("stage session");
    session.start().expect("start session");

    let reads = model.read_count();
    session.scheme_stats(0, 0).expect("first ordinary read");
    session.scheme_stats(0, 0).expect("second ordinary read");
    let ordinary_reads = model.read_count() - reads;

    let reads = model.read_count();
    session
        .runtime_batch(|batch| {
            batch.scheme_stats(0, 0)?;
            batch.scheme_stats(0, 0)?;
            Ok(())
        })
        .expect("batched reads");
    let batched_reads = model.read_count() - reads;

    assert!(batched_reads < ordinary_reads);
    session.close().expect("close session");
}

#[test]
fn quota_goal_updates_stage_values_and_roll_back_a_failed_commit() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut config = transaction_config(42, Action::Stat);
    let mut initial_goal = QuotaGoalConfig::new(QuotaGoalMetric::UserInput, 100);
    initial_goal.current_value = 1;
    config.kdamonds[0].contexts[0].schemes[0]
        .quota
        .reset_interval = Duration::from_secs(1);
    config.kdamonds[0].contexts[0].schemes[0].quota.goals = vec![initial_goal.clone()];
    let mut session = damon.exclusive_session(&config).expect("stage session");
    session.start().expect("start session");
    let current_value = "kdamonds/0/contexts/0/schemes/0/quotas/goals/0/current_value";

    let mut invalid_goal = QuotaGoalConfig::new(QuotaGoalMetric::ActiveMemoryBasisPoints, 10_001);
    invalid_goal.current_value = 2;
    let writes = model.write_count();
    assert!(matches!(
        session.update_scheme_quota_goals(0, 0, &[invalid_goal]),
        Err(Error::InvalidConfiguration { .. })
    ));
    assert_eq!(model.write_count(), writes);

    let mut updated_goal = initial_goal.clone();
    updated_goal.current_value = 9;
    session
        .update_scheme_quota_goals(0, 0, &[updated_goal])
        .expect("commit updated quota goal");
    assert_eq!(model.value(current_value).as_deref(), Some("9"));
    assert_eq!(model.active_value(current_value).as_deref(), Some("9"));

    let mut unstaged_goal = initial_goal.clone();
    unstaged_goal.current_value = 13;
    model.fail_next_write(current_value, 5);
    let error = session
        .update_scheme_quota_goals(0, 0, &[unstaged_goal])
        .expect_err("failed goal staging must roll back");
    assert!(matches!(error, Error::Io { .. }));
    assert_eq!(model.value(current_value).as_deref(), Some("9"));
    assert_eq!(model.active_value(current_value).as_deref(), Some("9"));

    let mut failed_goal = initial_goal.clone();
    failed_goal.current_value = 17;
    model.fail_next_write("kdamonds/0/state", 5);
    let error = session
        .update_scheme_quota_goals(0, 0, &[failed_goal])
        .expect_err("failed specialized commit must roll back");
    assert!(matches!(error, Error::Io { .. }));
    assert_eq!(model.value(current_value).as_deref(), Some("9"));
    assert_eq!(model.active_value(current_value).as_deref(), Some("9"));
    session.close().expect("close session");
}

#[test]
fn idempotent_pause_rechecks_ownership_after_reading_pause_state() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut session = damon
        .exclusive_session(&transaction_config(42, Action::Stat))
        .expect("stage session");
    session.start().expect("start session");
    let action = "kdamonds/0/contexts/0/schemes/0/action";
    model.after_next_read(
        "kdamonds/0/contexts/0/pause",
        vec![Mutation::SetFile {
            path: action.into(),
            value: b"pageout\n".to_vec(),
        }],
    );

    let error = session
        .resume()
        .expect_err("an idempotent resume must retain its exit ownership check");

    assert!(matches!(error, Error::OwnershipLost { .. }));
    model.set_file(action, b"stat\n");
    session.close().expect("close repaired session");
}

#[test]
fn quota_goal_update_does_not_adopt_an_unrelated_concurrent_change() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut config = transaction_config(42, Action::Stat);
    let mut initial_goal = QuotaGoalConfig::new(QuotaGoalMetric::UserInput, 100);
    initial_goal.current_value = 1;
    config.kdamonds[0].contexts[0].schemes[0]
        .quota
        .reset_interval = Duration::from_secs(1);
    config.kdamonds[0].contexts[0].schemes[0].quota.goals = vec![initial_goal.clone()];
    let mut session = damon.exclusive_session(&config).expect("stage session");
    session.start().expect("start session");
    let current_value = "kdamonds/0/contexts/0/schemes/0/quotas/goals/0/current_value";
    let action = "kdamonds/0/contexts/0/schemes/0/action";
    model.after_next_write(
        current_value,
        b"9".to_vec(),
        vec![Mutation::SetFile {
            path: action.into(),
            value: b"pageout\n".to_vec(),
        }],
    );
    let mut updated_goal = initial_goal;
    updated_goal.current_value = 9;

    let error = session
        .update_scheme_quota_goals(0, 0, &[updated_goal])
        .expect_err("concurrent non-goal change must not become owned");

    assert!(matches!(error, Error::Rollback { .. }));
    assert_eq!(model.value(current_value).as_deref(), Some("1"));
    assert_eq!(model.active_value(current_value).as_deref(), Some("1"));
    assert_eq!(model.value(action).as_deref(), Some("pageout"));
    model.set_file(action, b"stat\n");
    session.close().expect("close repaired session");
}

#[test]
fn quota_goal_update_does_not_adopt_unknown_goal_attribute_changes() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut config = transaction_config(42, Action::Stat);
    let mut initial_goal = QuotaGoalConfig::new(QuotaGoalMetric::UserInput, 100);
    initial_goal.current_value = 1;
    config.kdamonds[0].contexts[0].schemes[0]
        .quota
        .reset_interval = Duration::from_secs(1);
    config.kdamonds[0].contexts[0].schemes[0].quota.goals = vec![initial_goal.clone()];
    damon
        .stage_configuration(&config)
        .expect("stage preceding hierarchy");
    let future_attribute = "kdamonds/0/contexts/0/schemes/0/quotas/goals/0/future_goal_attribute";
    model.set_file(future_attribute, b"preserve\n");
    let mut session = damon.exclusive_session(&config).expect("stage session");
    session.start().expect("start session");
    let current_value = "kdamonds/0/contexts/0/schemes/0/quotas/goals/0/current_value";
    model.after_next_write(
        current_value,
        b"9".to_vec(),
        vec![Mutation::SetFile {
            path: future_attribute.into(),
            value: b"changed\n".to_vec(),
        }],
    );
    let mut updated_goal = initial_goal;
    updated_goal.current_value = 9;

    let error = session
        .update_scheme_quota_goals(0, 0, &[updated_goal])
        .expect_err("unknown goal attribute change must not become owned");

    assert!(matches!(error, Error::Rollback { .. }));
    assert_eq!(model.value(current_value).as_deref(), Some("1"));
    assert_eq!(model.value(future_attribute).as_deref(), Some("changed"));
    model.set_file(future_attribute, b"preserve\n");
    session.close().expect("close repaired session");
}

#[test]
fn quota_goal_update_handles_count_changes_without_full_configuration_rebuilds() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut config = transaction_config(42, Action::Stat);
    let initial_goal = QuotaGoalConfig::new(QuotaGoalMetric::UserInput, 100);
    config.kdamonds[0].contexts[0].schemes[0]
        .quota
        .reset_interval = Duration::from_secs(1);
    config.kdamonds[0].contexts[0].schemes[0].quota.goals = vec![initial_goal.clone()];
    let mut session = damon.exclusive_session(&config).expect("stage session");
    session.start().expect("start session");
    let goal_count = "kdamonds/0/contexts/0/schemes/0/quotas/goals/nr_goals";

    session
        .update_scheme_quota_goals(0, 0, &[])
        .expect("remove quota goal");
    assert_eq!(model.value(goal_count).as_deref(), Some("0"));
    assert_eq!(model.active_value(goal_count).as_deref(), Some("0"));

    session
        .update_scheme_quota_goals(0, 0, &[initial_goal])
        .expect("recreate quota goal");
    assert_eq!(model.value(goal_count).as_deref(), Some("1"));
    assert_eq!(model.active_value(goal_count).as_deref(), Some("1"));
    session.close().expect("close session");
}

#[test]
fn cached_tried_results_do_not_issue_refresh_commands() {
    let model = Model::new("vaddr\n");
    configure_runtime_results(&model);
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut session = damon
        .exclusive_session(&transaction_config(42, Action::Stat))
        .expect("stage session");
    session.start().expect("start session");
    session
        .tried_regions(0, 0, 1)
        .expect("materialize tried regions");
    session
        .tried_bytes_units(0, 0)
        .expect("materialize tried bytes");
    let writes = model.write_count();

    let snapshot = session
        .cached_tried_regions(0, 0, 1)
        .expect("read cached regions");
    let bytes = session
        .cached_tried_bytes_units(0, 0)
        .expect("read cached bytes");

    assert_eq!(snapshot.total_units(), 4_096);
    assert_eq!(bytes, 4_096);
    assert_eq!(model.write_count(), writes);
    session.close().expect("close session");
}

#[test]
fn runtime_updates_work_without_the_optional_refresh_attribute() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let config = transaction_config(42, Action::Stat);
    damon
        .stage_configuration(&config)
        .expect("stage preceding configuration");
    model.remove_tree("kdamonds/0/refresh_ms");
    let mut session = damon.exclusive_session(&config).expect("stage session");
    session.start().expect("start session");
    let writes = model.write_count();

    session.scheme_stats(0, 0).expect("refresh legacy stats");

    assert_eq!(model.write_count(), writes + 1);
    session.close().expect("close session");
}

#[test]
fn exclusive_session_does_not_adopt_concurrent_changes_during_pause() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut session = damon
        .exclusive_session(&transaction_config(42, Action::Stat))
        .expect("stage session");
    session.start().expect("start session");
    model.after_next_write(
        "kdamonds/0/contexts/0/pause",
        b"Y".to_vec(),
        vec![Mutation::SetFile {
            path: "kdamonds/0/contexts/0/targets/0/pid_target".into(),
            value: b"77\n".to_vec(),
        }],
    );

    let error = session
        .pause()
        .expect_err("unrelated change must not enter the ownership fingerprint");
    assert!(matches!(
        error,
        Error::Rollback {
            operation,
            rollback,
        } if matches!(*operation, Error::OwnershipLost {
            reason: "the staged writable configuration changed"
        }) && matches!(*rollback, Error::OwnershipLost {
            reason: "the staged writable configuration changed"
        })
    ));

    model.set_file("kdamonds/0/contexts/0/targets/0/pid_target", b"42\n");
    session
        .close()
        .expect("restore after repairing external change");
}
