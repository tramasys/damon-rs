//! Shared filesystem-backed DAMON fixture.

use super::*;

pub(super) struct Fixture {
    root: PathBuf,
}

impl Fixture {
    pub(super) fn new(available_operations: &str) -> Self {
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
            ("kdamonds/0/pid", "-1\n"),
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
            ("kdamonds/0/contexts/0/targets/0/obsolete_target", "N\n"),
            ("kdamonds/0/contexts/0/targets/0/regions/nr_regions", "0\n"),
            ("kdamonds/0/contexts/0/schemes/nr_schemes", "0\n"),
            ("kdamonds/0/contexts/0/schemes/0/action", "stat\n"),
            ("kdamonds/0/contexts/0/schemes/0/target_nid", "-1\n"),
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
        fixture.add_scheme_defaults();

        fixture
    }

    pub(super) fn add_scheme_defaults(&self) {
        for (path, value) in [
            ("quotas/ms", "0\n"),
            ("quotas/bytes", "0\n"),
            ("quotas/reset_interval_ms", "0\n"),
            ("quotas/effective_bytes", "0\n"),
            ("quotas/weights/sz_permil", "0\n"),
            ("quotas/weights/nr_accesses_permil", "0\n"),
            ("quotas/weights/age_permil", "0\n"),
            ("watermarks/metric", "none\n"),
            ("watermarks/interval_us", "0\n"),
            ("watermarks/high", "0\n"),
            ("watermarks/mid", "0\n"),
            ("watermarks/low", "0\n"),
            ("filters/nr_filters", "0\n"),
            ("stats/nr_tried", "0\n"),
            ("stats/sz_tried", "0\n"),
            ("stats/nr_applied", "0\n"),
            ("stats/sz_applied", "0\n"),
            ("stats/qt_exceeds", "0\n"),
        ] {
            self.write(&format!("kdamonds/0/contexts/0/schemes/0/{path}"), value);
        }
    }

    pub(super) fn disable_online_commits(&self) {
        self.remove("kdamonds/0/contexts/0/avail_operations");
    }

    pub(super) fn add_probe_filter_files(&self) {
        for (path, value) in [
            (
                "kdamonds/0/contexts/0/monitoring_attrs/probes/0/filters/nr_filters",
                "0\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/probes/0/filters/0/type",
                "anon\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/probes/0/filters/0/matching",
                "N\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/probes/0/filters/0/allow",
                "N\n",
            ),
            (
                "kdamonds/0/contexts/0/monitoring_attrs/probes/0/filters/0/path",
                "\n",
            ),
        ] {
            self.write(path, value);
        }
    }

    pub(super) fn add_snapshot_regions(&self) {
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
        self.write(
            "kdamonds/0/contexts/0/schemes/0/tried_regions/0/probes/0/hits",
            "3\n",
        );
        self.write(
            "kdamonds/0/contexts/0/schemes/0/tried_regions/0/probes/1/hits",
            "7\n",
        );
    }

    pub(super) fn damon(&self) -> Damon {
        self.write("kdamonds/0/pid", "9001\n");
        Damon::at_with_lock(self.path(), self.root.join("damon-rs.lock")).expect("open fixture")
    }

    pub(super) fn path(&self) -> &Path {
        self.root.as_path()
    }

    pub(super) fn write(&self, path: &str, value: &str) {
        let path = self.root.join(path);
        fs::create_dir_all(path.parent().expect("fixture path has parent"))
            .expect("create fixture directory");
        fs::write(path, value).expect("write fixture value");
    }

    pub(super) fn read(&self, path: &str) -> String {
        fs::read_to_string(self.root.join(path)).expect("read fixture value")
    }

    pub(super) fn remove(&self, path: &str) {
        fs::remove_file(self.root.join(path)).expect("remove fixture value");
    }

    pub(super) fn remove_dir(&self, path: &str) {
        fs::remove_dir_all(self.root.join(path)).expect("remove fixture directory");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
