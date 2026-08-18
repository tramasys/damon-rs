use super::*;

#[test]
fn vaddr_workflow_composes_regions_probes_schemes_and_snapshot_query() {
    let model = Model::new("vaddr\nfvaddr\npaddr\n");
    model.set_tried_regions(vec![ModelRegion {
        start: 4_096,
        end: 8_192,
        nr_accesses: 7,
        age: 3,
        filter_passed_units: Some(4_096),
        probe_hits: vec![5],
    }]);
    model.set_scheme_stats(vec![ModelSchemeStats {
        nr_tried: 11,
        sz_tried: 12,
        nr_applied: 13,
        sz_applied: 14,
        sz_ops_filter_passed: 15,
        qt_exceeds: 16,
        nr_snapshots: 17,
    }]);
    model.set_effective_quota_bytes(vec![18]);
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let initial = InitialRegionConfig::new(0x1_0000, 0x2_0000).expect("valid region");
    let mut monitor = damon
        .vaddr()
        .pid(Pid::new(42).expect("valid pid"))
        .region(initial)
        .result_refresh_interval(Duration::from_millis(250))
        .probe(ProbeConfig::default())
        .scheme(SchemeConfig::new(Action::PageOut, match_all_pattern()))
        .start()
        .expect("start vaddr workflow");

    assert_eq!(monitor.operation(), &Operation::VirtualAddress);
    assert_eq!(monitor.effective_address_unit(), AddressUnit::ONE);
    assert_eq!(monitor.scheme_count(), 1);
    assert_eq!(
        monitor.result_refresh_interval(),
        Duration::from_millis(250)
    );
    assert_eq!(model.value("kdamonds/0/refresh_ms").as_deref(), Some("250"));
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/monitoring_attrs/probes/nr_probes")
            .as_deref(),
        Some("1")
    );
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/targets/0/regions/0/start")
            .as_deref(),
        Some("65536")
    );
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/schemes/0/action")
            .as_deref(),
        Some("pageout")
    );
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/schemes/nr_schemes")
            .as_deref(),
        Some("1")
    );

    let snapshot = monitor
        .materialize_snapshot()
        .expect("query private snapshot scheme");
    let snapshot = snapshot.snapshot();
    assert_eq!(snapshot.total_bytes().expect("byte total"), 4_096);
    assert_eq!(snapshot.region(0).expect("region").nr_accesses(), 7);
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/schemes/nr_schemes")
            .as_deref(),
        Some("1")
    );
    let stats = monitor.scheme_stats(0).expect("custom scheme stats");
    assert_eq!(stats.size_tried_units, 12);
    assert_eq!(monitor.effective_quota_units(0).expect("custom quota"), 18);
    assert!(matches!(
        monitor.scheme_stats(1),
        Err(Error::IndexOutOfBounds {
            kind: "custom scheme",
            ..
        })
    ));
    monitor.pause().expect("pause workflow");
    monitor.resume().expect("resume workflow");
    monitor.stop().expect("restore hierarchy");
}

#[test]
fn owned_snapshot_request_returns_monitor_and_completion_timing() {
    let model = Model::new("vaddr\n");
    model.set_tried_regions(vec![ModelRegion {
        start: 1,
        end: 2,
        nr_accesses: 1,
        age: 1,
        filter_passed_units: None,
        probe_hits: Vec::new(),
    }]);
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");
    let mut request = monitor.request_snapshot().expect("start snapshot request");
    assert_eq!(
        request
            .wait_until(std::time::Instant::now() + Duration::from_secs(1))
            .expect("wait for request"),
        SnapshotWait::Ready
    );
    let outcome = request.finish().expect("finish request");
    let (monitor, snapshots) = outcome.into_parts();
    let snapshots = snapshots.expect("materialize snapshots");
    assert_eq!(snapshots.len(), 1);
    let timing = snapshots[0].timing();
    assert!(timing.completed_at() >= timing.requested_at());
    assert!(monitor.cached_snapshots().is_empty());
    monitor.stop().expect("stop monitor");
}

#[test]
fn snapshot_worker_start_failure_returns_the_running_monitor() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    let failure = monitor
        .request_snapshot_with_spawn_error(io::Error::from_raw_os_error(11))
        .expect_err("worker creation must fail");

    assert!(matches!(
        failure.error(),
        Error::SnapshotWorkerSpawn { source } if source.raw_os_error() == Some(11)
    ));
    let (_, monitor) = failure.into_parts();
    assert!(monitor.is_running().expect("monitor remains running"));
    monitor.stop().expect("stop recovered monitor");
}

#[test]
fn owned_snapshot_extraction_reuses_the_cached_allocation() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    let snapshot = monitor
        .materialize_snapshot_owned()
        .expect("take owned snapshot");
    assert!(monitor.cached_snapshots().is_empty());
    let (_, _, _, scope, _, scaled) = snapshot.into_parts();
    assert!(matches!(scope, SnapshotScope::Target(_)));
    let (raw, unit) = scaled.into_parts();
    assert_eq!(unit, AddressUnit::ONE);
    let (regions, reported, materialized) = raw.into_parts();
    assert!(regions.is_empty());
    assert_eq!(reported, Some(0));
    assert_eq!(materialized, 0);
    monitor.stop().expect("stop monitor");
}

#[test]
fn multi_target_snapshots_are_target_scoped_when_filters_are_supported() {
    let model = Model::new("vaddr\n");
    model.set_tried_regions(vec![ModelRegion {
        start: 4_096,
        end: 8_192,
        nr_accesses: 3,
        age: 1,
        filter_passed_units: Some(4_096),
        probe_hits: Vec::new(),
    }]);
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let first_pid = Pid::new(41).expect("valid pid");
    let second_pid = Pid::new(43).expect("valid pid");
    let mut slow_scheme = SchemeConfig::new(Action::Stat, match_all_pattern());
    slow_scheme.apply_interval = Duration::from_millis(250);
    let mut monitor = damon
        .vaddr()
        .targets([first_pid, second_pid])
        .scheme(slow_scheme)
        .start()
        .expect("start multi-target workflow");

    assert_eq!(
        monitor.maximum_snapshot_apply_interval(),
        Some(Duration::from_millis(250))
    );
    let writes = model.write_count();
    assert!(matches!(
        monitor.materialize_snapshot(),
        Err(Error::MultipleSnapshotResults { count: 2 })
    ));
    assert_eq!(model.write_count(), writes);
    assert!(monitor.cached_snapshots().is_empty());
    {
        let snapshots = monitor
            .materialize_snapshots()
            .expect("materialize scoped snapshots");
        assert_eq!(snapshots.len(), 2);
        assert_eq!(
            snapshots[0].scope(),
            SnapshotScope::Target(TargetIdentity::new(0, Some(first_pid)))
        );
        assert_eq!(
            snapshots[1].scope(),
            SnapshotScope::Target(TargetIdentity::new(1, Some(second_pid)))
        );
        assert_eq!(snapshots[0].snapshot().total_units(), 4_096);
        assert_eq!(snapshots[1].snapshot().total_units(), 4_096);
    }
    let writes = model.write_count();
    assert_eq!(monitor.cached_snapshots().len(), 2);
    assert!(matches!(
        monitor.cached_snapshot(),
        Err(Error::MultipleSnapshotResults { count: 2 })
    ));
    assert_eq!(model.write_count(), writes);
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/schemes/nr_schemes")
            .as_deref(),
        Some("1")
    );
    monitor.stop().expect("stop workflow");
}

#[test]
fn multi_target_snapshots_fall_back_to_honest_scheme_scoped_results() {
    let model = Model::new("vaddr\n");
    model.set_supported_scheme_filter_types(
        "anon\nmemcg\nyoung\naddr\nhugepage_size\nunmapped\nactive\n",
    );
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut monitor = damon
        .vaddr()
        .targets([
            Pid::new(41).expect("valid pid"),
            Pid::new(43).expect("valid pid"),
        ])
        .start()
        .expect("start fallback workflow");

    assert_eq!(
        monitor
            .capabilities()
            .feature_support(SysfsFeature::SchemeFilterTarget),
        CapabilitySupport::Unsupported
    );
    let snapshot = monitor
        .materialize_snapshot()
        .expect("materialize ungrouped snapshot");
    assert_eq!(snapshot.scope(), SnapshotScope::Scheme);
    assert_eq!(monitor.cached_snapshots().len(), 1);
    monitor.stop().expect("stop workflow");
}

#[test]
fn fvaddr_targets_accept_distinct_fixed_regions() {
    let model = Model::new("fvaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let first = ProcessTarget::new(Pid::new(41).expect("valid pid"))
        .region(InitialRegionConfig::new(100, 200).expect("valid region"));
    let second = ProcessTarget::new(Pid::new(43).expect("valid pid"))
        .region(InitialRegionConfig::new(300, 400).expect("valid region"));
    let monitor = damon
        .fvaddr()
        .targets([first, second])
        .start()
        .expect("start multi-target fvaddr workflow");

    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/targets/0/regions/0/start")
            .as_deref(),
        Some("100")
    );
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/targets/1/regions/0/start")
            .as_deref(),
        Some("300")
    );
    monitor.stop().expect("stop workflow");
}

#[test]
fn fvaddr_workflow_requires_pid_and_fixed_regions_before_writing() {
    let model = Model::new("vaddr\nfvaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let writes = model.write_count();

    assert!(matches!(
        damon.fvaddr().start(),
        Err(Error::InvalidConfiguration {
            field: "fixed virtual-address targets",
            ..
        })
    ));
    assert!(matches!(
        damon.fvaddr().pid(Pid::new(42).expect("valid pid")).start(),
        Err(Error::InvalidConfiguration {
            field: "fixed virtual-address target regions",
            ..
        })
    ));
    assert_eq!(model.write_count(), writes);

    let monitor = damon
        .fvaddr()
        .pid(Pid::new(42).expect("valid pid"))
        .regions([InitialRegionConfig::new(100, 200).expect("valid region")])
        .start()
        .expect("start fvaddr workflow");
    assert_eq!(monitor.operation(), &Operation::FixedVirtualAddress);
    assert_eq!(monitor.effective_address_unit(), AddressUnit::ONE);
    assert_eq!(
        model.value("kdamonds/0/contexts/0/operations").as_deref(),
        Some("fvaddr")
    );
    monitor.stop().expect("restore hierarchy");
}

#[test]
fn paddr_workflow_keeps_core_units_and_checked_byte_scale() {
    let model = Model::new("paddr\n");
    model.set_tried_regions(vec![ModelRegion {
        start: 2,
        end: 4,
        nr_accesses: 1,
        age: 1,
        filter_passed_units: Some(2),
        probe_hits: Vec::new(),
    }]);
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let writes = model.write_count();
    assert!(matches!(
        damon.paddr().start(),
        Err(Error::InvalidConfiguration {
            field: "physical-address target regions",
            ..
        })
    ));
    assert_eq!(model.write_count(), writes);

    let address_unit = AddressUnit::new(4_096).expect("valid page-size unit");
    let mut monitor = damon
        .paddr()
        .address_unit(address_unit)
        .region_units(InitialRegionConfig::new(2, 4).expect("valid raw region"))
        .start()
        .expect("start paddr workflow");
    assert_eq!(monitor.operation(), &Operation::PhysicalAddress);
    assert_eq!(monitor.effective_address_unit(), address_unit);
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/targets/0/pid_target")
            .as_deref(),
        Some("0")
    );
    let snapshot = monitor
        .materialize_snapshot()
        .expect("query paddr snapshot");
    let snapshot = snapshot.snapshot();
    let region = snapshot.region(0).expect("physical region");
    assert_eq!(region.start_units(), 2);
    assert_eq!(region.start_bytes().expect("start bytes"), 8_192);
    assert_eq!(region.end_bytes().expect("end bytes"), 16_384);
    assert_eq!(snapshot.total_units(), 2);
    assert_eq!(snapshot.total_bytes().expect("total bytes"), 8_192);
    monitor.stop().expect("restore hierarchy");
}

#[test]
fn current_kernels_install_snapshot_query_only_on_demand() {
    let model = Model::new("vaddr\n");
    model.set_tried_regions(vec![ModelRegion {
        start: 4_096,
        end: 8_192,
        nr_accesses: 1,
        age: 1,
        filter_passed_units: None,
        probe_hits: Vec::new(),
    }]);
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start monitor");

    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/schemes/nr_schemes")
            .as_deref(),
        Some("0")
    );
    assert_eq!(
        monitor
            .materialize_snapshot()
            .expect("query snapshot")
            .snapshot()
            .raw_regions()
            .len(),
        1
    );
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/schemes/nr_schemes")
            .as_deref(),
        Some("0")
    );
    monitor.stop().expect("restore hierarchy");
}

#[test]
fn legacy_kernels_retain_the_snapshot_query_scheme() {
    let model = Model::without_available_operations_file("vaddr\n");
    model.set_tried_regions(vec![ModelRegion {
        start: 4_096,
        end: 8_192,
        nr_accesses: 1,
        age: 1,
        filter_passed_units: None,
        probe_hits: Vec::new(),
    }]);
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect("start legacy monitor");

    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/schemes/nr_schemes")
            .as_deref(),
        Some("1")
    );
    assert_eq!(
        monitor
            .materialize_snapshot()
            .expect("query legacy snapshot")
            .snapshot()
            .raw_regions()
            .len(),
        1
    );
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/schemes/nr_schemes")
            .as_deref(),
        Some("1")
    );
    monitor.stop().expect("restore hierarchy");
}

#[test]
fn explicit_empty_process_regions_do_not_inherit_builder_regions() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let common = InitialRegionConfig::new(4_096, 8_192).expect("valid common region");
    let first = ProcessTarget::new(Pid::new(41).expect("valid first pid"));
    let second = ProcessTarget::new(Pid::new(42).expect("valid second pid"))
        .regions(Vec::<InitialRegionConfig>::new());
    assert_eq!(first.initial_regions(), None);
    assert_eq!(second.initial_regions(), Some(&[][..]));
    let monitor = damon
        .vaddr()
        .regions([common])
        .targets([first, second])
        .start()
        .expect("start workflow");

    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/targets/0/regions/nr_regions")
            .as_deref(),
        Some("1")
    );
    assert_eq!(
        model
            .value("kdamonds/0/contexts/0/targets/1/regions/nr_regions")
            .as_deref(),
        Some("0")
    );
    monitor.stop().expect("stop workflow");
}

#[test]
fn high_level_capabilities_include_custom_scheme_children() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut scheme = SchemeConfig::new(Action::Stat, match_all_pattern());
    scheme
        .filters
        .push(FilterConfig::new(SchemeFilterType::Anonymous, true, true));
    let monitor = damon
        .vaddr()
        .pid(Pid::new(42).expect("valid pid"))
        .scheme(scheme)
        .start()
        .expect("start monitor with filter");

    assert_eq!(
        monitor
            .capabilities()
            .feature_support(SysfsFeature::SchemeFilterAnonymous),
        CapabilitySupport::Unverified
    );
    assert_eq!(
        monitor
            .capabilities()
            .feature_support(SysfsFeature::SchemeFilterAllow),
        CapabilitySupport::Supported
    );
    monitor.stop().expect("restore hierarchy");
}

#[test]
fn high_level_effective_quota_reads_are_capability_gated() {
    let model = Model::new("vaddr\n");
    model.disable_effective_quota();
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut monitor = damon
        .vaddr()
        .pid(Pid::new(42).expect("valid pid"))
        .scheme(SchemeConfig::new(Action::Stat, match_all_pattern()))
        .start()
        .expect("start monitor without effective quotas");
    let writes = model.write_count();

    assert!(matches!(
        monitor.effective_quota_units(0),
        Err(Error::UnsupportedFeature {
            feature: "DAMOS effective quota reporting"
        })
    ));
    assert!(matches!(
        monitor.cached_effective_quota_units(0),
        Err(Error::UnsupportedFeature {
            feature: "DAMOS effective quota reporting"
        })
    ));
    assert_eq!(model.write_count(), writes);
    monitor.stop().expect("restore hierarchy");
}

#[test]
fn high_level_all_scheme_reads_share_refresh_and_ownership_scans() {
    let model = Model::new("vaddr\n");
    model.set_scheme_stats(vec![
        ModelSchemeStats {
            nr_tried: 1,
            ..ModelSchemeStats::default()
        },
        ModelSchemeStats {
            nr_tried: 2,
            ..ModelSchemeStats::default()
        },
        ModelSchemeStats {
            nr_tried: 3,
            ..ModelSchemeStats::default()
        },
    ]);
    model.set_effective_quota_bytes(vec![4, 5, 6]);
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let mut builder = damon.vaddr().pid(Pid::new(42).expect("valid pid"));
    for _ in 0..3 {
        builder = builder.scheme(SchemeConfig::new(Action::Stat, match_all_pattern()));
    }
    let mut monitor = builder.start().expect("start three-scheme monitor");

    let ordinary_start = model.read_count();
    for scheme_index in 0..3 {
        monitor
            .scheme_stats(scheme_index)
            .expect("ordinary scheme read");
    }
    let ordinary_reads = model.read_count() - ordinary_start;
    let batch_start = model.read_count();
    let stats = monitor.scheme_stats_all().expect("batched scheme reads");
    let batch_reads = model.read_count() - batch_start;

    assert_eq!(
        stats
            .iter()
            .map(|stats| stats.regions_tried)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(batch_reads < ordinary_reads);
    assert_eq!(
        monitor
            .effective_quota_units_all()
            .expect("batched effective quotas"),
        vec![4, 5, 6]
    );
    monitor.stop().expect("restore hierarchy");
}

#[test]
fn workflow_operation_support_and_staging_failures_restore_state() {
    let model = Model::new("vaddr\n");
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let region = InitialRegionConfig::new(100, 200).expect("valid region");

    let error = damon
        .fvaddr()
        .pid(Pid::new(42).expect("valid pid"))
        .region(region)
        .start()
        .expect_err("unsupported operation must be classified");
    assert!(matches!(
        error,
        Error::UnsupportedOperation {
            operation: Operation::FixedVirtualAddress
        }
    ));
    assert_eq!(model.value("kdamonds/nr_kdamonds").as_deref(), Some("0"));

    let model = Model::new("vaddr\nfvaddr\n");
    model.fail_next_write("kdamonds/0/contexts/0/targets/0/regions/0/end", 5);
    let lock = TestLock::new();
    let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
    let error = damon
        .fvaddr()
        .pid(Pid::new(42).expect("valid pid"))
        .region(region)
        .start()
        .expect_err("late staging failure must roll back");
    assert!(matches!(error, Error::Io { .. }));
    assert_eq!(model.value("kdamonds/nr_kdamonds").as_deref(), Some("0"));
}
