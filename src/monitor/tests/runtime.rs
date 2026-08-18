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
