use super::*;

#[test]
fn restores_an_existing_stopped_configuration() {
    let fixture = Fixture::new("vaddr\n");
    fixture.write("kdamonds/nr_kdamonds", "1\n");
    fixture.write("kdamonds/0/contexts/nr_contexts", "1\n");
    fixture.write("kdamonds/0/contexts/0/operations", "vaddr\n");
    fixture.write("kdamonds/0/contexts/0/targets/nr_targets", "1\n");
    fixture.write("kdamonds/0/contexts/0/targets/0/pid_target", "77\n");
    fixture.write("kdamonds/0/contexts/0/schemes/nr_schemes", "0\n");
    let damon = fixture.damon();

    let monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("replace a stopped configuration transactionally");
    monitor.stop().expect("restore preceding configuration");

    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "1");
    assert_eq!(fixture.read("kdamonds/0/contexts/nr_contexts"), "1");
    assert_eq!(
        fixture.read("kdamonds/0/contexts/0/targets/0/pid_target"),
        "77"
    );
    assert_eq!(
        fixture.read("kdamonds/0/contexts/0/schemes/nr_schemes"),
        "0"
    );
}

#[test]
fn serializes_high_level_sessions_with_the_advisory_lock() {
    let fixture = Fixture::new("vaddr\n");
    let first = fixture.damon();
    let second = fixture.damon();
    let monitor = first
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start first monitor");

    let error = second
        .monitor_pid(Pid::new(43).expect("valid pid"))
        .start()
        .expect_err("a second cooperating session must not race");
    assert!(matches!(error, Error::SessionLockBusy { .. }));

    monitor.stop().expect("stop first monitor");
}

#[test]
fn refuses_to_stop_a_replaced_kdamond_thread() {
    let fixture = Fixture::new("vaddr\n");
    let damon = fixture.damon();
    let monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/0/pid", "9002\n");
    let error = monitor
        .stop()
        .expect_err("a replacement thread must be preserved");
    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the kdamond kernel-thread ID changed"
        }
    ));
    assert_eq!(fixture.read("kdamonds/0/state"), "on");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "1");
}

#[test]
fn refuses_to_stop_an_externally_reconfigured_slot() {
    let fixture = Fixture::new("vaddr\n");
    let damon = fixture.damon();
    let monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/0/contexts/0/targets/0/pid_target", "77\n");
    let error = monitor
        .stop()
        .expect_err("a replacement configuration must be preserved");
    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the staged writable configuration changed"
        }
    ));
    assert_eq!(fixture.read("kdamonds/0/state"), "on");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "1");
}

#[test]
fn refuses_to_stop_when_extended_typed_configuration_changes() {
    for (path, value, expected_reason) in [
        (
            "kdamonds/0/refresh_ms",
            "100\n",
            "the staged writable configuration changed",
        ),
        (
            "kdamonds/0/contexts/0/pause",
            "Y\n",
            "the staged writable configuration changed",
        ),
        (
            "kdamonds/0/contexts/0/monitoring_attrs/probes/nr_probes",
            "1\n",
            "the staged writable configuration changed",
        ),
        (
            "kdamonds/0/contexts/0/targets/0/obsolete_target",
            "Y\n",
            "the staged writable configuration changed",
        ),
        (
            "kdamonds/0/contexts/0/targets/0/regions/nr_regions",
            "1\n",
            "the staged writable configuration changed",
        ),
        (
            "kdamonds/0/contexts/0/schemes/0/apply_interval_us",
            "100\n",
            "the staged writable configuration changed",
        ),
    ] {
        let fixture = Fixture::new("vaddr\n");
        let monitor = fixture
            .damon()
            .monitor_pid(Pid::new(42).expect("valid pid"))
            .start()
            .expect("start monitor");

        fixture.write(path, value);
        let error = monitor
            .stop()
            .expect_err("changed staged input must invalidate ownership");

        match error {
            Error::OwnershipLost { reason } => assert_eq!(reason, expected_reason, "{path}"),
            other => panic!("unexpected ownership error for {path}: {other:?}"),
        }
        assert_eq!(fixture.read("kdamonds/0/state"), "on");
    }
}

#[test]
fn refuses_to_stop_when_auxiliary_scheme_configuration_changes() {
    let fixture = Fixture::new("vaddr\n");
    let monitor = fixture
        .damon()
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/0/contexts/0/schemes/0/target_nid", "7\n");
    let error = monitor
        .stop()
        .expect_err("changed auxiliary scheme input must invalidate ownership");

    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the staged writable configuration changed"
        }
    ));
    assert_eq!(fixture.read("kdamonds/0/state"), "on");
}

#[test]
fn ownership_tracks_unknown_future_configuration_attributes() {
    let fixture = Fixture::new("vaddr\n");
    fixture.write("kdamonds/0/contexts/0/future_kernel_tunable", "enabled\n");
    let monitor = fixture
        .damon()
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/0/contexts/0/future_kernel_tunable", "disabled\n");
    let error = monitor
        .stop()
        .expect_err("an unknown writable input must invalidate ownership");

    assert!(matches!(
        error,
        Error::OwnershipLost {
            reason: "the staged writable configuration changed"
        }
    ));
}

#[test]
fn rolls_back_when_virtual_address_operations_are_missing() {
    let fixture = Fixture::new("paddr\n");
    let damon = fixture.damon();

    let error = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect_err("vaddr must be checked at runtime");

    assert!(matches!(
        error,
        Error::UnsupportedOperation {
            operation: Operation::VirtualAddress
        }
    ));
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

#[test]
fn setup_rollback_preserves_a_concurrently_started_slot() {
    let fixture = Fixture::new("paddr\n");
    let damon = fixture.damon();
    fixture.write("kdamonds/0/state", "on\n");
    fixture.write("kdamonds/0/pid", "9002\n");
    assert_eq!(fixture.read("kdamonds/0/state"), "on\n");

    let error = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect_err("a concurrently started replacement must be preserved");

    assert!(
        matches!(
            error,
            Error::Rollback {
                ref operation,
                ref rollback,
            } if matches!(**operation, Error::KdamondRunning { index: 0 })
                && matches!(**rollback, Error::KdamondRunning { index: 0 })
        ),
        "unexpected error: {error:?}, state: {:?}, count: {:?}",
        fixture.read("kdamonds/0/state"),
        fixture.read("kdamonds/nr_kdamonds")
    );
    assert_eq!(fixture.read("kdamonds/0/state"), "on\n");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "1");
}

#[test]
fn cleans_up_after_the_kernel_thread_has_already_stopped() {
    let fixture = Fixture::new("vaddr\n");
    let damon = fixture.damon();
    let monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    fixture.write("kdamonds/0/state", "off\n");
    monitor.stop().expect("clean up stopped monitor");

    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

#[test]
fn validates_before_mutating_the_global_interface() {
    let fixture = Fixture::new("vaddr\n");
    let damon = fixture.damon();

    let error = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .region_bounds(2, 100)
        .start()
        .expect_err("invalid bounds must fail");

    assert!(matches!(
        error,
        Error::InvalidConfiguration {
            field: "minimum regions",
            ..
        }
    ));
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0\n");
}
