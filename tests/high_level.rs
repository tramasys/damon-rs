//! High-level API tests against a filesystem fixture.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use damon::{Damon, Error, Operation, Pid};

#[test]
fn stages_queries_and_cleans_up_a_monitor() {
    let fixture = Fixture::new("vaddr\npaddr\nfuture_ops\n");
    fixture.add_snapshot_regions();

    let damon = Damon::at(fixture.path()).expect("open fixture");
    let mut monitor = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .region_bounds(10, 128)
        .start()
        .expect("start monitor");

    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "1");
    assert_eq!(fixture.read("kdamonds/0/contexts/0/operations"), "vaddr");
    assert_eq!(
        fixture.read("kdamonds/0/contexts/0/targets/0/pid_target"),
        "42"
    );
    assert!(monitor.capabilities().supports(&Operation::VirtualAddress));
    assert!(monitor.capabilities().has_pause());
    assert!(monitor.capabilities().has_probes());
    assert!(monitor.capabilities().has_tried_regions());
    assert_eq!(
        monitor.capabilities().operations()[2],
        Operation::Unknown("future_ops".into())
    );

    let snapshot = monitor.snapshot().expect("query snapshot");
    assert_eq!(snapshot.total_bytes(), 6_144);
    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot.regions()[0].start(), 4_096);
    assert_eq!(snapshot.regions()[0].end(), 8_192);
    assert_eq!(snapshot.regions()[0].len(), 4_096);
    assert_eq!(snapshot.regions()[0].nr_accesses(), 7);
    assert_eq!(snapshot.regions()[0].age(), 3);
    assert_eq!(snapshot.regions()[0].filter_passed_bytes(), Some(4_096));
    assert_eq!(snapshot.regions()[1].filter_passed_bytes(), None);

    monitor.stop().expect("stop monitor");
    assert_eq!(fixture.read("kdamonds/0/state"), "off");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

#[test]
fn refuses_to_replace_an_existing_configuration() {
    let fixture = Fixture::new("vaddr\n");
    fixture.write("kdamonds/nr_kdamonds", "2\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");

    let error = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect_err("existing configuration must be preserved");

    assert!(matches!(error, Error::InUse { kdamonds: 2 }));
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "2\n");
}

#[test]
fn rolls_back_when_virtual_address_operations_are_missing() {
    let fixture = Fixture::new("paddr\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");

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
fn cleans_up_after_the_kernel_thread_has_already_stopped() {
    let fixture = Fixture::new("vaddr\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");
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
    let damon = Damon::at(fixture.path()).expect("open fixture");

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

#[test]
fn rolls_back_when_query_results_are_unsupported() {
    let fixture = Fixture::new("vaddr\n");
    fixture.remove("kdamonds/0/contexts/0/schemes/0/tried_regions/total_bytes");
    let damon = Damon::at(fixture.path()).expect("open fixture");

    let error = damon
        .monitor_pid(Pid::new(42).expect("valid pid"))
        .start()
        .expect_err("query support must be detected");

    assert!(matches!(
        error,
        Error::UnsupportedFeature {
            feature: "DAMOS tried-region queries"
        }
    ));
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

#[test]
fn drop_performs_best_effort_cleanup() {
    let fixture = Fixture::new("vaddr\n");
    let damon = Damon::at(fixture.path()).expect("open fixture");

    {
        let _monitor = damon
            .monitor_pid(Pid::new(42).expect("valid pid"))
            .start()
            .expect("start monitor");
    }

    assert_eq!(fixture.read("kdamonds/0/state"), "off");
    assert_eq!(fixture.read("kdamonds/nr_kdamonds"), "0");
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(available_operations: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "damon-rs-integration-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let fixture = Self { root };

        for (path, value) in [
            ("kdamonds/nr_kdamonds", "0\n"),
            ("kdamonds/0/state", "off\n"),
            ("kdamonds/0/refresh_ms", "0\n"),
            ("kdamonds/0/contexts/nr_contexts", "0\n"),
            (
                "kdamonds/0/contexts/0/avail_operations",
                available_operations,
            ),
            ("kdamonds/0/contexts/0/operations", "\n"),
            ("kdamonds/0/contexts/0/addr_unit", "1\n"),
            ("kdamonds/0/contexts/0/pause", "0\n"),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/intervals/sample_us",
                "5000\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/intervals/aggr_us",
                "100000\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/intervals/update_us",
                "60000000\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/nr_regions/min",
                "10\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/nr_regions/max",
                "1000\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/probes/nr_probes",
                "0\n",
            ),
            ("kdamonds/0/contexts/0/targets/nr_targets", "0\n"),
            ("kdamonds/0/contexts/0/targets/0/pid_target", "0\n"),
            ("kdamonds/0/contexts/0/schemes/nr_schemes", "0\n"),
            ("kdamonds/0/contexts/0/schemes/0/action", "stat\n"),
            ("kdamonds/0/contexts/0/schemes/0/apply_interval_us", "0\n"),
            (
                "kdamonds/0/contexts/0/schemes/0/tried_regions/total_bytes",
                "0\n",
            ),
        ] {
            fixture.write(path, value);
        }

        for range in ["sz", "nr_accesses", "age"] {
            fixture.write(
                &format!("kdamonds/0/contexts/0/schemes/0/access_pattern/{range}/min"),
                "0\n",
            );
            fixture.write(
                &format!("kdamonds/0/contexts/0/schemes/0/access_pattern/{range}/max"),
                "0\n",
            );
        }

        fixture
    }

    fn add_snapshot_regions(&self) {
        self.write(
            "kdamonds/0/contexts/0/schemes/0/tried_regions/total_bytes",
            "6144\n",
        );
        for (index, start, end, accesses, age) in
            [(0, 4_096, 8_192, 7, 3), (1, 8_192, 10_240, 2, 8)]
        {
            let base = format!("kdamonds/0/contexts/0/schemes/0/tried_regions/{index}");
            self.write(&format!("{base}/start"), &format!("{start}\n"));
            self.write(&format!("{base}/end"), &format!("{end}\n"));
            self.write(&format!("{base}/nr_accesses"), &format!("{accesses}\n"));
            self.write(&format!("{base}/age"), &format!("{age}\n"));
        }
        self.write(
            "kdamonds/0/contexts/0/schemes/0/tried_regions/0/sz_filter_passed",
            "4096\n",
        );
    }

    fn path(&self) -> &Path {
        self.root.as_path()
    }

    fn write(&self, path: &str, value: &str) {
        let path = self.root.join(path);
        fs::create_dir_all(path.parent().expect("fixture path has parent"))
            .expect("create fixture directory");
        fs::write(path, value).expect("write fixture value");
    }

    fn read(&self, path: &str) -> String {
        fs::read_to_string(self.root.join(path)).expect("read fixture value")
    }

    fn remove(&self, path: &str) {
        fs::remove_file(self.root.join(path)).expect("remove fixture value");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
