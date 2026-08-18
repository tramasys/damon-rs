//! In-memory DAMON sysfs hierarchy and kernel behavior model.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Node {
    Directory,
    File(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ModelRegion {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) nr_accesses: u32,
    pub(crate) age: u32,
    pub(crate) filter_passed_units: Option<u64>,
    pub(crate) probe_hits: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ModelSchemeStats {
    pub(crate) nr_tried: u64,
    pub(crate) sz_tried: u64,
    pub(crate) nr_applied: u64,
    pub(crate) sz_applied: u64,
    pub(crate) sz_ops_filter_passed: u64,
    pub(crate) qt_exceeds: u64,
    pub(crate) nr_snapshots: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Mutation {
    SetFile { path: PathBuf, value: Vec<u8> },
    RemoveTree { path: PathBuf },
    StartKdamond { path: PathBuf },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum HookEvent {
    Read(PathBuf),
    Write(PathBuf, Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Hook {
    pub(super) event: HookEvent,
    pub(super) mutations: Vec<Mutation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct WriteFailure {
    pub(super) path: PathBuf,
    pub(super) raw_os_error: i32,
}

#[derive(Debug)]
pub(super) struct State {
    pub(super) nodes: BTreeMap<PathBuf, Node>,
    pub(super) extension_files: BTreeMap<PathBuf, Vec<u8>>,
    pub(super) available_operations: Vec<u8>,
    pub(super) recognized_operations: Vec<u8>,
    pub(super) expose_available_operations: bool,
    pub(super) expose_current_damo_extensions: bool,
    pub(super) expose_effective_quota: bool,
    pub(super) supported_scheme_filter_types: Vec<u8>,
    pub(super) supported_probe_filter_types: Vec<u8>,
    pub(super) supported_scheme_actions: Vec<u8>,
    pub(super) supported_quota_goal_metrics: Vec<u8>,
    pub(super) supported_probe_preparation_actions: Vec<u8>,
    pub(super) active_files: Option<BTreeMap<PathBuf, Vec<u8>>>,
    pub(super) next_kdamond_pid: u32,
    pub(super) tried_regions: Vec<ModelRegion>,
    pub(super) scheme_stats: Vec<ModelSchemeStats>,
    pub(super) effective_quota_bytes: Vec<u64>,
    pub(super) hooks: Vec<Hook>,
    pub(super) write_failures: Vec<WriteFailure>,
    pub(super) read_count: usize,
    pub(super) write_count: usize,
}

impl State {
    pub(super) fn new(
        available_operations: &str,
        recognized_operations: &str,
        expose_available_operations: bool,
    ) -> Self {
        let mut state = Self {
            nodes: BTreeMap::new(),
            extension_files: BTreeMap::new(),
            available_operations: available_operations.as_bytes().to_vec(),
            recognized_operations: recognized_operations.as_bytes().to_vec(),
            expose_available_operations,
            expose_current_damo_extensions: false,
            expose_effective_quota: true,
            supported_scheme_filter_types:
                b"anon\nmemcg\nyoung\naddr\ntarget\nhugepage_size\nunmapped\nactive\n".to_vec(),
            supported_probe_filter_types: b"anon\nmemcg\n".to_vec(),
            supported_scheme_actions: b"willneed\ncold\npageout\nhugepage\nnohugepage\ncollapse\nlru_prio\nlru_deprio\nmigrate_hot\nmigrate_cold\nstat\n".to_vec(),
            supported_quota_goal_metrics: b"user_input\nsome_mem_psi_us\nnode_mem_used_bp\nnode_mem_free_bp\nnode_memcg_used_bp\nnode_memcg_free_bp\nactive_mem_bp\ninactive_mem_bp\nnode_eligible_mem_bp\n".to_vec(),
            supported_probe_preparation_actions: b"set_pgidle\n".to_vec(),
            active_files: None,
            next_kdamond_pid: 10_000,
            tried_regions: Vec::new(),
            scheme_stats: Vec::new(),
            effective_quota_bytes: Vec::new(),
            hooks: Vec::new(),
            write_failures: Vec::new(),
            read_count: 0,
            write_count: 0,
        };
        state.directory("");
        state.directory("kdamonds");
        state.file("kdamonds/nr_kdamonds", b"0\n");
        state
    }

    pub(super) fn directory(&mut self, path: impl Into<PathBuf>) {
        self.nodes.insert(path.into(), Node::Directory);
    }

    pub(super) fn file(&mut self, path: impl Into<PathBuf>, value: &[u8]) {
        self.nodes.insert(path.into(), Node::File(value.to_vec()));
    }

    pub(super) fn remove_tree(&mut self, path: &Path) {
        self.nodes
            .retain(|candidate, _| candidate != path && !candidate.starts_with(path));
    }

    pub(super) fn remove_indexed_children(&mut self, parent: &Path) {
        self.nodes.retain(|candidate, _| {
            let Ok(relative) = candidate.strip_prefix(parent) else {
                return true;
            };
            let Some(first) = relative.components().next() else {
                return true;
            };
            first
                .as_os_str()
                .to_str()
                .is_none_or(|component| component.parse::<usize>().is_err())
        });
    }

    pub(super) fn restore_extension_files(&mut self) {
        let files = self.extension_files.clone();
        for (path, value) in files {
            if path
                .parent()
                .is_some_and(|parent| matches!(self.nodes.get(parent), Some(Node::Directory)))
            {
                self.file(path, &value);
            }
        }
    }

    pub(super) fn finish_reconstruction(&mut self) -> bool {
        self.restore_extension_files();
        true
    }

    pub(super) fn create_kdamond(&mut self, index: usize) {
        let base = PathBuf::from(format!("kdamonds/{index}"));
        self.directory(&base);
        self.file(base.join("state"), b"off\n");
        self.file(base.join("pid"), b"-1\n");
        self.file(base.join("refresh_ms"), b"0\n");
        self.directory(base.join("contexts"));
        self.file(base.join("contexts/nr_contexts"), b"0\n");
    }

    pub(super) fn create_context(&mut self, base: &Path, index: usize) {
        let base = base.join(index.to_string());
        self.directory(&base);
        if self.expose_available_operations {
            let operations = self.available_operations.clone();
            self.file(base.join("avail_operations"), &operations);
        }
        self.file(base.join("operations"), b"vaddr\n");
        self.file(base.join("addr_unit"), b"1\n");
        self.file(base.join("pause"), b"N\n");
        self.directory(base.join("monitoring_attrs"));
        self.directory(base.join("monitoring_attrs/intervals"));
        self.file(base.join("monitoring_attrs/intervals/sample_us"), b"5000\n");
        self.file(base.join("monitoring_attrs/intervals/aggr_us"), b"100000\n");
        self.file(
            base.join("monitoring_attrs/intervals/update_us"),
            b"60000000\n",
        );
        self.directory(base.join("monitoring_attrs/intervals/intervals_goal"));
        for name in ["access_bp", "aggrs", "min_sample_us", "max_sample_us"] {
            self.file(
                base.join("monitoring_attrs/intervals/intervals_goal")
                    .join(name),
                b"0\n",
            );
        }
        self.directory(base.join("monitoring_attrs/nr_regions"));
        self.file(base.join("monitoring_attrs/nr_regions/min"), b"10\n");
        self.file(base.join("monitoring_attrs/nr_regions/max"), b"1000\n");
        self.directory(base.join("monitoring_attrs/probes"));
        self.file(base.join("monitoring_attrs/probes/nr_probes"), b"0\n");
        if self.expose_current_damo_extensions {
            self.directory(base.join("operations_attrs"));
            self.file(base.join("operations_attrs/use_reports"), b"N\n");
            self.file(base.join("operations_attrs/write_only"), b"N\n");
            self.file(base.join("operations_attrs/cpus"), b"all\n");
            self.file(base.join("operations_attrs/tids"), b"\n");
            self.directory(base.join("monitoring_attrs/sample"));
            self.directory(base.join("monitoring_attrs/sample/primitives"));
            self.file(
                base.join("monitoring_attrs/sample/primitives/page_table"),
                b"Y\n",
            );
            self.file(
                base.join("monitoring_attrs/sample/primitives/page_fault"),
                b"N\n",
            );
            self.directory(base.join("monitoring_attrs/sample/filters"));
            self.file(
                base.join("monitoring_attrs/sample/filters/nr_filters"),
                b"0\n",
            );
        }
        self.directory(base.join("targets"));
        self.file(base.join("targets/nr_targets"), b"0\n");
        self.directory(base.join("schemes"));
        self.file(base.join("schemes/nr_schemes"), b"0\n");
    }

    pub(super) fn create_target(&mut self, base: &Path, index: usize) {
        let base = base.join(index.to_string());
        self.directory(&base);
        self.file(base.join("pid_target"), b"0\n");
        self.file(base.join("obsolete_target"), b"N\n");
        self.directory(base.join("regions"));
        self.file(base.join("regions/nr_regions"), b"0\n");
    }

    pub(super) fn create_target_region(&mut self, base: &Path, index: usize) {
        let base = base.join(index.to_string());
        self.directory(&base);
        self.file(base.join("start"), b"0\n");
        self.file(base.join("end"), b"0\n");
    }

    pub(super) fn create_scheme(&mut self, base: &Path, index: usize) {
        let base = base.join(index.to_string());
        self.directory(&base);
        self.file(base.join("action"), b"stat\n");
        self.file(base.join("target_nid"), b"-1\n");
        self.file(base.join("apply_interval_us"), b"0\n");
        self.directory(base.join("access_pattern"));
        for range in ["sz", "nr_accesses", "age"] {
            self.directory(base.join("access_pattern").join(range));
            self.file(base.join("access_pattern").join(range).join("min"), b"0\n");
            self.file(base.join("access_pattern").join(range).join("max"), b"0\n");
        }
        self.directory(base.join("quotas"));
        for name in [
            "ms",
            "bytes",
            "reset_interval_ms",
            "fail_charge_num",
            "fail_charge_denom",
        ] {
            self.file(base.join("quotas").join(name), b"0\n");
        }
        if self.expose_effective_quota {
            self.file(base.join("quotas/effective_bytes"), b"0\n");
        }
        self.file(base.join("quotas/goal_tuner"), b"consist\n");
        self.directory(base.join("quotas/weights"));
        for name in ["sz_permil", "nr_accesses_permil", "age_permil"] {
            self.file(base.join("quotas/weights").join(name), b"0\n");
        }
        self.directory(base.join("quotas/goals"));
        self.file(base.join("quotas/goals/nr_goals"), b"0\n");
        self.directory(base.join("watermarks"));
        self.file(base.join("watermarks/metric"), b"none\n");
        for name in ["interval_us", "high", "mid", "low"] {
            self.file(base.join("watermarks").join(name), b"0\n");
        }
        for filters in ["core_filters", "ops_filters", "filters"] {
            self.directory(base.join(filters));
            self.file(base.join(filters).join("nr_filters"), b"0\n");
        }
        self.directory(base.join("dests"));
        self.file(base.join("dests/nr_dests"), b"0\n");
        self.directory(base.join("stats"));
        for name in [
            "nr_tried",
            "sz_tried",
            "nr_applied",
            "sz_applied",
            "sz_ops_filter_passed",
            "qt_exceeds",
            "nr_snapshots",
            "max_nr_snapshots",
        ] {
            self.file(base.join("stats").join(name), b"0\n");
        }
        self.directory(base.join("tried_regions"));
        self.file(base.join("tried_regions/total_bytes"), b"0\n");
    }

    pub(super) fn create_probe(&mut self, base: &Path, index: usize) {
        let base = base.join(index.to_string());
        self.directory(&base);
        self.directory(base.join("filters"));
        self.file(base.join("filters/nr_filters"), b"0\n");
        if self.expose_current_damo_extensions {
            self.file(base.join("weight"), b"0\n");
            self.directory(base.join("preps"));
            self.file(base.join("preps/nr_preps"), b"0\n");
        }
    }

    pub(super) fn create_probe_preparation(&mut self, base: &Path, index: usize) {
        let base = base.join(index.to_string());
        self.directory(&base);
        self.file(base.join("prep_action"), b"set_pgidle\n");
    }

    pub(super) fn create_sample_filter(&mut self, base: &Path, index: usize) {
        let base = base.join(index.to_string());
        self.directory(&base);
        self.file(base.join("type"), b"write\n");
        self.file(base.join("matching"), b"N\n");
        self.file(base.join("allow"), b"N\n");
        self.file(base.join("cpumask"), b"\n");
        self.file(base.join("tid_arr"), b"\n");
    }

    pub(super) fn create_probe_filter(&mut self, base: &Path, index: usize) {
        let base = base.join(index.to_string());
        self.directory(&base);
        self.file(base.join("type"), b"anon\n");
        self.file(base.join("matching"), b"N\n");
        self.file(base.join("allow"), b"N\n");
        self.file(base.join("path"), b"\n");
    }

    pub(super) fn create_scheme_filter(&mut self, base: &Path, index: usize) {
        let base = base.join(index.to_string());
        self.directory(&base);
        self.file(base.join("type"), b"anon\n");
        self.file(base.join("matching"), b"N\n");
        self.file(base.join("allow"), b"N\n");
        self.file(base.join("memcg_path"), b"\n");
        for name in ["addr_start", "addr_end", "damon_target_idx", "min", "max"] {
            self.file(base.join(name), b"0\n");
        }
    }

    pub(super) fn create_quota_goal(&mut self, base: &Path, index: usize) {
        let base = base.join(index.to_string());
        self.directory(&base);
        self.file(base.join("target_metric"), b"user_input\n");
        for name in ["target_value", "current_value", "nid"] {
            self.file(base.join(name), b"0\n");
        }
        self.file(base.join("path"), b"\n");
    }

    pub(super) fn create_destination(&mut self, base: &Path, index: usize) {
        let base = base.join(index.to_string());
        self.directory(&base);
        self.file(base.join("id"), b"0\n");
        self.file(base.join("weight"), b"0\n");
    }

    pub(super) fn parse_count(value: &[u8]) -> io::Result<usize> {
        let value = std::str::from_utf8(value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 count"))?
            .trim()
            .parse::<usize>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid count"))?;
        if value > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "test model count limit exceeded",
            ));
        }
        Ok(value)
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn reconstruct_count(&mut self, path: &Path, count: usize) -> io::Result<bool> {
        let path_text = path.to_string_lossy();
        if path_text == "kdamonds/nr_kdamonds" {
            if self.nodes.iter().any(|(candidate, node)| {
                candidate.file_name().is_some_and(|name| name == "state")
                    && matches!(node, Node::File(value) if value == b"on\n")
            }) {
                return Err(io::Error::from_raw_os_error(16));
            }
            let parent = Path::new("kdamonds");
            self.remove_indexed_children(parent);
            self.active_files = None;
            for index in 0..count {
                self.create_kdamond(index);
            }
            return Ok(self.finish_reconstruction());
        }
        if path_text.ends_with("/contexts/nr_contexts") {
            if count > 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Linux 7.2 supports at most one context",
                ));
            }
            let parent = path.parent().expect("count path has parent");
            self.remove_indexed_children(parent);
            for index in 0..count {
                self.create_context(parent, index);
            }
            return Ok(self.finish_reconstruction());
        }
        if path_text.ends_with("/targets/nr_targets") {
            let parent = path.parent().expect("count path has parent");
            self.remove_indexed_children(parent);
            for index in 0..count {
                self.create_target(parent, index);
            }
            return Ok(self.finish_reconstruction());
        }
        if path_text.ends_with("/schemes/nr_schemes") {
            let parent = path.parent().expect("count path has parent");
            self.remove_indexed_children(parent);
            for index in 0..count {
                self.create_scheme(parent, index);
            }
            return Ok(self.finish_reconstruction());
        }
        if path_text.ends_with("/monitoring_attrs/probes/nr_probes") {
            let parent = path.parent().expect("count path has parent");
            self.remove_indexed_children(parent);
            for index in 0..count {
                self.create_probe(parent, index);
            }
            return Ok(self.finish_reconstruction());
        }
        if path_text.ends_with("/preps/nr_preps") {
            let parent = path.parent().expect("count path has parent");
            self.remove_indexed_children(parent);
            for index in 0..count {
                self.create_probe_preparation(parent, index);
            }
            return Ok(self.finish_reconstruction());
        }
        if path_text.ends_with("/filters/nr_filters")
            || path_text.ends_with("/core_filters/nr_filters")
            || path_text.ends_with("/ops_filters/nr_filters")
        {
            let parent = path.parent().expect("count path has parent");
            self.remove_indexed_children(parent);
            for index in 0..count {
                if path_text.contains("/monitoring_attrs/sample/filters/") {
                    self.create_sample_filter(parent, index);
                } else if path_text.contains("/monitoring_attrs/probes/") {
                    self.create_probe_filter(parent, index);
                } else {
                    self.create_scheme_filter(parent, index);
                }
            }
            return Ok(self.finish_reconstruction());
        }
        if path_text.ends_with("/quotas/goals/nr_goals") {
            let parent = path.parent().expect("count path has parent");
            self.remove_indexed_children(parent);
            for index in 0..count {
                self.create_quota_goal(parent, index);
            }
            return Ok(self.finish_reconstruction());
        }
        if path_text.ends_with("/dests/nr_dests") {
            let parent = path.parent().expect("count path has parent");
            self.remove_indexed_children(parent);
            for index in 0..count {
                self.create_destination(parent, index);
            }
            return Ok(self.finish_reconstruction());
        }
        if path_text.ends_with("/regions/nr_regions") {
            let parent = path.parent().expect("count path has parent");
            self.remove_indexed_children(parent);
            for index in 0..count {
                self.create_target_region(parent, index);
            }
            return Ok(self.finish_reconstruction());
        }
        Ok(false)
    }

    pub(super) fn capture_active_files(&mut self) {
        self.active_files = Some(
            self.nodes
                .iter()
                .filter_map(|(path, node)| match node {
                    Node::File(value) => Some((path.clone(), value.clone())),
                    Node::Directory => None,
                })
                .collect(),
        );
    }

    pub(super) fn validate_sample_primitives(&self, kdamond: &Path) -> io::Result<()> {
        let base = kdamond.join("contexts/0/monitoring_attrs/sample/primitives");
        let enabled = |name: &str| match self.nodes.get(&base.join(name)) {
            Some(Node::File(value)) => match std::str::from_utf8(value).map(str::trim) {
                Ok("Y" | "1") => Ok(Some(true)),
                Ok("N" | "0") => Ok(Some(false)),
                _ => Err(io::Error::from_raw_os_error(22)),
            },
            Some(Node::Directory) => Err(io::Error::from(io::ErrorKind::IsADirectory)),
            None => Ok(None),
        };
        let (Some(page_table), Some(page_fault)) = (enabled("page_table")?, enabled("page_fault")?)
        else {
            return Ok(());
        };
        if page_table == page_fault {
            return Err(io::Error::from_raw_os_error(22));
        }
        Ok(())
    }

    pub(super) fn commit_quota_goals(&mut self) {
        let staged_goals: Vec<_> = self
            .nodes
            .iter()
            .filter_map(|(path, node)| {
                if !path.to_string_lossy().contains("/quotas/goals/") {
                    return None;
                }
                match node {
                    Node::File(value) => Some((path.clone(), value.clone())),
                    Node::Directory => None,
                }
            })
            .collect();
        let active = self
            .active_files
            .as_mut()
            .expect("running model has active files");
        active.retain(|path, _| !path.to_string_lossy().contains("/quotas/goals/"));
        active.extend(staged_goals);
    }

    pub(super) fn materialize_tried_regions(&mut self, kdamond: &Path) -> io::Result<()> {
        let regions = self.tried_regions.clone();
        let total = regions.iter().try_fold(0_u64, |total, region| {
            let size = region.end.checked_sub(region.start).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid modeled region")
            })?;
            total
                .checked_add(size)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "modeled total overflow"))
        })?;
        for scheme_index in 0..self.scheme_count(kdamond)? {
            let base = kdamond
                .join("contexts/0/schemes")
                .join(scheme_index.to_string())
                .join("tried_regions");
            if !self.nodes.contains_key(&base) {
                return Err(not_found(&base));
            }
            self.remove_indexed_children(&base);
            self.file(base.join("total_bytes"), format!("{total}\n").as_bytes());
            for (index, region) in regions.iter().enumerate() {
                let region_base = base.join(index.to_string());
                self.directory(&region_base);
                self.file(
                    region_base.join("start"),
                    format!("{}\n", region.start).as_bytes(),
                );
                self.file(
                    region_base.join("end"),
                    format!("{}\n", region.end).as_bytes(),
                );
                self.file(
                    region_base.join("nr_accesses"),
                    format!("{}\n", region.nr_accesses).as_bytes(),
                );
                self.file(
                    region_base.join("age"),
                    format!("{}\n", region.age).as_bytes(),
                );
                if let Some(units) = region.filter_passed_units {
                    self.file(
                        region_base.join("sz_filter_passed"),
                        format!("{units}\n").as_bytes(),
                    );
                }
                self.directory(region_base.join("probes"));
                for (probe_index, hits) in region.probe_hits.iter().enumerate() {
                    let probe_base = region_base.join("probes").join(probe_index.to_string());
                    self.directory(&probe_base);
                    self.file(probe_base.join("hits"), format!("{hits}\n").as_bytes());
                }
            }
        }
        Ok(())
    }

    pub(super) fn scheme_count(&self, kdamond: &Path) -> io::Result<usize> {
        let path = kdamond.join("contexts/0/schemes/nr_schemes");
        match self.nodes.get(&path) {
            Some(Node::File(value)) => Self::parse_count(value),
            _ => Err(not_found(&path)),
        }
    }

    pub(super) fn clear_materialized_tried_regions(&mut self, kdamond: &Path) -> io::Result<()> {
        for scheme_index in 0..self.scheme_count(kdamond)? {
            let base = kdamond
                .join("contexts/0/schemes")
                .join(scheme_index.to_string())
                .join("tried_regions");
            if !self.nodes.contains_key(&base) {
                return Err(not_found(&base));
            }
            self.remove_indexed_children(&base);
            self.file(base.join("total_bytes"), b"0\n");
        }
        Ok(())
    }

    pub(super) fn materialize_scheme_stats(&mut self, kdamond: &Path) {
        let stats = self.scheme_stats.clone();
        for (index, stats) in stats.iter().enumerate() {
            let base = kdamond
                .join("contexts/0/schemes")
                .join(index.to_string())
                .join("stats");
            if !self.nodes.contains_key(&base) {
                break;
            }
            for (name, value) in [
                ("nr_tried", stats.nr_tried),
                ("sz_tried", stats.sz_tried),
                ("nr_applied", stats.nr_applied),
                ("sz_applied", stats.sz_applied),
                ("sz_ops_filter_passed", stats.sz_ops_filter_passed),
                ("qt_exceeds", stats.qt_exceeds),
                ("nr_snapshots", stats.nr_snapshots),
            ] {
                self.file(base.join(name), format!("{value}\n").as_bytes());
            }
        }
    }

    pub(super) fn materialize_effective_quotas(&mut self, kdamond: &Path) {
        let quotas = self.effective_quota_bytes.clone();
        for (index, effective_bytes) in quotas.into_iter().enumerate() {
            let path = kdamond
                .join("contexts/0/schemes")
                .join(index.to_string())
                .join("quotas/effective_bytes");
            if !self.nodes.contains_key(&path) {
                break;
            }
            self.file(path, format!("{effective_bytes}\n").as_bytes());
        }
    }

    pub(super) fn start_kdamond(&mut self, kdamond: &Path) -> io::Result<()> {
        let operations = kdamond.join("contexts/0/operations");
        let selected = match self.nodes.get(&operations) {
            Some(Node::File(value)) => std::str::from_utf8(value)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?
                .trim(),
            _ => return Err(io::Error::from_raw_os_error(22)),
        };
        if !listed_value_contains(&self.available_operations, selected) {
            return Err(io::Error::from_raw_os_error(22));
        }
        self.validate_sample_primitives(kdamond)?;
        self.capture_active_files();
        self.next_kdamond_pid += 1;
        self.file(kdamond.join("state"), b"on\n");
        self.file(
            kdamond.join("pid"),
            format!("{}\n", self.next_kdamond_pid).as_bytes(),
        );
        Ok(())
    }

    pub(super) fn write_state(&mut self, path: &Path, value: &[u8]) -> io::Result<()> {
        let command = std::str::from_utf8(value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 command"))?
            .trim();
        let kdamond = path.parent().expect("state path has parent");
        match command {
            "on" => {
                let context_count = kdamond.join("contexts/nr_contexts");
                if !matches!(
                    self.nodes.get(&context_count),
                    Some(Node::File(value)) if value == b"1\n"
                ) {
                    return Err(io::Error::from_raw_os_error(22));
                }
                if matches!(self.nodes.get(path), Some(Node::File(value)) if value == b"on\n") {
                    return Err(io::Error::from_raw_os_error(16));
                }
                self.start_kdamond(kdamond)?;
            }
            "off" => {
                if self.active_files.is_none() {
                    return Err(io::Error::from_raw_os_error(22));
                }
                if !matches!(self.nodes.get(path), Some(Node::File(value)) if value == b"on\n") {
                    return Err(io::Error::from_raw_os_error(1));
                }
                self.file(path, b"off\n");
                self.file(kdamond.join("pid"), b"-1\n");
            }
            "commit" => {
                self.ensure_running(path)?;
                self.validate_sample_primitives(kdamond)?;
                self.capture_active_files();
            }
            "commit_schemes_quota_goals" => {
                self.ensure_running(path)?;
                self.commit_quota_goals();
            }
            "update_schemes_tried_regions" => {
                self.ensure_running(path)?;
                self.materialize_tried_regions(kdamond)?;
            }
            "update_schemes_tried_bytes" => {
                self.ensure_running(path)?;
                self.materialize_tried_regions(kdamond)?;
                for scheme_index in 0..self.scheme_count(kdamond)? {
                    let base = kdamond
                        .join("contexts/0/schemes")
                        .join(scheme_index.to_string())
                        .join("tried_regions");
                    self.remove_indexed_children(&base);
                }
            }
            "clear_schemes_tried_regions" => {
                self.ensure_running(path)?;
                self.clear_materialized_tried_regions(kdamond)?;
            }
            "update_schemes_stats" => {
                self.ensure_running(path)?;
                self.materialize_scheme_stats(kdamond);
            }
            "update_schemes_effective_quotas" => {
                self.ensure_running(path)?;
                self.materialize_effective_quotas(kdamond);
            }
            "update_tuned_intervals" => self.ensure_running(path)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown modeled state command",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn ensure_running(&self, state_path: &Path) -> io::Result<()> {
        match self.nodes.get(state_path) {
            Some(Node::File(value)) if value == b"on\n" => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "modeled kdamond is not running",
            )),
        }
    }

    pub(super) fn write(&mut self, path: &Path, value: &[u8]) -> io::Result<()> {
        if let Some(index) = self
            .write_failures
            .iter()
            .position(|failure| failure.path == path)
        {
            let failure = self.write_failures.remove(index);
            return Err(io::Error::from_raw_os_error(failure.raw_os_error));
        }

        match self.nodes.get(path) {
            Some(Node::File(_)) => {}
            Some(Node::Directory) => return Err(io::Error::from(io::ErrorKind::IsADirectory)),
            None => return Err(not_found(path)),
        }

        if path.file_name().is_some_and(|name| name == "state") {
            return self.write_state(path, value);
        }

        if path.file_name().is_some_and(|name| name == "operations") {
            let requested = std::str::from_utf8(value)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?
                .trim();
            if !listed_value_contains(&self.recognized_operations, requested) {
                return Err(io::Error::from_raw_os_error(22));
            }
        }

        if path.file_name().is_some_and(|name| name == "action")
            && path.to_string_lossy().contains("/schemes/")
        {
            let requested = std::str::from_utf8(value)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?
                .trim();
            if !listed_value_contains(&self.supported_scheme_actions, requested) {
                return Err(io::Error::from_raw_os_error(22));
            }
        }

        if path.file_name().is_some_and(|name| name == "target_metric") {
            let requested = std::str::from_utf8(value)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?
                .trim();
            if !listed_value_contains(&self.supported_quota_goal_metrics, requested) {
                return Err(io::Error::from_raw_os_error(22));
            }
        }

        if path.file_name().is_some_and(|name| name == "prep_action") {
            let requested = std::str::from_utf8(value)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?
                .trim();
            if !listed_value_contains(&self.supported_probe_preparation_actions, requested) {
                return Err(io::Error::from_raw_os_error(22));
            }
        }

        if path.file_name().is_some_and(|name| name == "type") {
            let requested = std::str::from_utf8(value)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?
                .trim();
            let path_text = path.to_string_lossy();
            let supported = if path_text.contains("/monitoring_attrs/probes/") {
                listed_value_contains(&self.supported_probe_filter_types, requested)
            } else if path_text.contains("/schemes/")
                && (path_text.contains("/filters/")
                    || path_text.contains("/core_filters/")
                    || path_text.contains("/ops_filters/"))
            {
                listed_value_contains(&self.supported_scheme_filter_types, requested)
            } else {
                true
            };
            if !supported {
                return Err(io::Error::from_raw_os_error(22));
            }
        }

        let path_text = path.to_string_lossy();
        if path_text == "kdamonds/nr_kdamonds"
            || path_text.ends_with("/contexts/nr_contexts")
            || path_text.ends_with("/targets/nr_targets")
            || path_text.ends_with("/schemes/nr_schemes")
            || path_text.ends_with("/monitoring_attrs/probes/nr_probes")
            || path_text.ends_with("/preps/nr_preps")
            || path_text.ends_with("/filters/nr_filters")
            || path_text.ends_with("/core_filters/nr_filters")
            || path_text.ends_with("/ops_filters/nr_filters")
            || path_text.ends_with("/quotas/goals/nr_goals")
            || path_text.ends_with("/dests/nr_dests")
            || path_text.ends_with("/regions/nr_regions")
        {
            let count = Self::parse_count(value)?;
            if self.reconstruct_count(path, count)? {
                self.file(path, format!("{count}\n").as_bytes());
                return Ok(());
            }
        }

        self.file(path, value);
        Ok(())
    }

    pub(super) fn apply_hooks(&mut self, event: &HookEvent) {
        let Some(index) = self.hooks.iter().position(|hook| &hook.event == event) else {
            return;
        };
        let hook = self.hooks.remove(index);
        for mutation in hook.mutations {
            match mutation {
                Mutation::SetFile { path, value } => self.file(path, &value),
                Mutation::RemoveTree { path } => self.remove_tree(&path),
                Mutation::StartKdamond { path } => self
                    .start_kdamond(&path)
                    .expect("modeled external kdamond start must be valid"),
            }
        }
    }
}
