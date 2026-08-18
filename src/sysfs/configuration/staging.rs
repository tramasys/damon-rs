//! Configuration read-back and adaptive staging.

use super::{
    AddressUnit, Context, ContextConfig, DamonAdmin, DamonConfig, DestinationConfig, Duration,
    Error, FilterConfig, FilterLayer, FilterPlacement, InitialRegion, IntervalsGoalConfig, Kdamond,
    KdamondConfig, MigrationDestination, OperationAttributes, OperationAttributesConfig, Probe,
    ProbeConfig, ProbeFilter, ProbeFilterConfig, ProbeFilterType, ProbePreparation, Result,
    SampleControl, SampleControlConfig, Scheme, SchemeConfig, SchemeFilter, SchemeQuotas,
    SchemeStats, SchemeWatermarks, Target, TargetConfig, ensure_count, needs_stage, optional_read,
    path_exists, read_i32, read_indexed, read_u32, read_u64, read_usize, semantic_filters_match,
    stage_optional_default, validate_count, write_value,
};

impl Context {
    /// Returns a handle to operation-specific attributes.
    #[must_use]
    pub fn operation_attributes(&self) -> OperationAttributes {
        OperationAttributes {
            path: self.path.join("operations_attrs"),
        }
    }

    /// Returns a handle to access-sample controls.
    #[must_use]
    pub fn sample_control(&self) -> SampleControl {
        SampleControl {
            path: self.path.join("monitoring_attrs/sample"),
        }
    }

    /// Reads the optional automatic sampling-interval goal.
    pub fn intervals_goal(&self) -> Result<IntervalsGoalConfig> {
        let path = self.path.join("monitoring_attrs/intervals/intervals_goal");
        Ok(IntervalsGoalConfig {
            access_basis_points: read_u64(&path.join("access_bp"))?,
            aggregation_intervals: read_u64(&path.join("aggrs"))?,
            minimum_sample: Duration::from_micros(read_u64(&path.join("min_sample_us"))?),
            maximum_sample: Duration::from_micros(read_u64(&path.join("max_sample_us"))?),
        })
    }

    /// Writes the automatic sampling-interval goal.
    pub fn set_intervals_goal(&self, goal: IntervalsGoalConfig) -> Result<()> {
        goal.validate_for(self.intervals()?)?;
        self.write_intervals_goal(goal)
    }

    fn write_intervals_goal(&self, goal: IntervalsGoalConfig) -> Result<()> {
        let (access, aggregations, minimum, maximum) = goal.values()?;
        let path = self.path.join("monitoring_attrs/intervals/intervals_goal");
        write_value(&path.join("access_bp"), access)?;
        write_value(&path.join("aggrs"), aggregations)?;
        write_value(&path.join("min_sample_us"), minimum)?;
        write_value(&path.join("max_sample_us"), maximum)
    }

    /// Reads this complete staged context into owned data.
    pub fn configuration(&self) -> Result<ContextConfig> {
        let targets = read_indexed(self.target_count()?, |index| {
            self.target(index).configuration()
        })?;
        let schemes = read_indexed(self.scheme_count()?, |index| {
            self.scheme(index).configuration()
        })?;
        let probe_count_path = self.path.join("monitoring_attrs/probes/nr_probes");
        let probes = if path_exists(&probe_count_path)? {
            read_indexed(self.probe_count()?, |index| {
                self.probe(index).configuration()
            })?
        } else {
            Vec::new()
        };
        Ok(ContextConfig {
            operation: self.operation()?,
            address_unit: optional_read(&self.path.join("addr_unit"), || self.address_unit())?
                .unwrap_or(AddressUnit::ONE),
            paused: optional_read(&self.path.join("pause"), || self.is_paused())?.unwrap_or(false),
            operation_attributes: if path_exists(&self.path.join("operations_attrs"))? {
                self.operation_attributes().configuration()?
            } else {
                OperationAttributesConfig::default()
            },
            intervals: self.intervals()?,
            intervals_goal: optional_read(
                &self
                    .path
                    .join("monitoring_attrs/intervals/intervals_goal/access_bp"),
                || self.intervals_goal(),
            )?
            .unwrap_or_default(),
            region_bounds: self.region_bounds()?,
            probes,
            sample_control: if path_exists(&self.path.join("monitoring_attrs/sample"))? {
                self.sample_control().configuration()?
            } else {
                SampleControlConfig::default()
            },
            targets,
            schemes,
        })
    }

    /// Validates and stages a complete owned context configuration.
    ///
    /// Validation completes before the first sysfs write. A later I/O error
    /// can still leave a partially staged hierarchy. Transactional restoration
    /// belongs to the exclusive session layer.
    pub fn stage_configuration(&self, config: &ContextConfig) -> Result<()> {
        config.validate()?;
        self.stage_validated_configuration_from(config, None)
    }

    fn stage_validated_configuration_from(
        &self,
        config: &ContextConfig,
        observed: Option<&ContextConfig>,
    ) -> Result<()> {
        if observed == Some(config) {
            return Ok(());
        }
        self.stage_scalar_configuration_from(config, observed)?;
        self.stage_child_configuration_from(config, observed)
    }

    fn stage_scalar_configuration_from(
        &self,
        config: &ContextConfig,
        observed: Option<&ContextConfig>,
    ) -> Result<()> {
        if needs_stage(observed.map(|value| &value.operation), &config.operation) {
            self.set_operation(&config.operation)?;
        }
        if needs_stage(
            observed.map(|value| &value.address_unit),
            &config.address_unit,
        ) {
            stage_optional_default(
                &self.path.join("addr_unit"),
                &config.address_unit,
                &AddressUnit::ONE,
                "DAMON address units",
                || self.set_address_unit(config.address_unit),
            )?;
        }
        if needs_stage(observed.map(|value| &value.paused), &config.paused) {
            stage_optional_default(
                &self.path.join("pause"),
                &config.paused,
                &false,
                "DAMON context pause",
                || self.set_paused(config.paused),
            )?;
        }
        if needs_stage(
            observed.map(|value| &value.operation_attributes),
            &config.operation_attributes,
        ) {
            stage_optional_default(
                &self.path.join("operations_attrs"),
                &config.operation_attributes,
                &OperationAttributesConfig::default(),
                "DAMON operation attributes",
                || {
                    self.operation_attributes()
                        .stage_configuration(&config.operation_attributes)
                },
            )?;
        }
        if needs_stage(observed.map(|value| &value.intervals), &config.intervals) {
            self.set_intervals(config.intervals)?;
        }
        if needs_stage(
            observed.map(|value| &value.intervals_goal),
            &config.intervals_goal,
        ) {
            stage_optional_default(
                &self
                    .path
                    .join("monitoring_attrs/intervals/intervals_goal/access_bp"),
                &config.intervals_goal,
                &IntervalsGoalConfig::default(),
                "DAMON monitoring intervals goal",
                || self.write_intervals_goal(config.intervals_goal),
            )?;
        }
        if needs_stage(
            observed.map(|value| &value.region_bounds),
            &config.region_bounds,
        ) {
            self.set_region_bounds(config.region_bounds)?;
        }
        Ok(())
    }

    fn stage_child_configuration_from(
        &self,
        config: &ContextConfig,
        observed: Option<&ContextConfig>,
    ) -> Result<()> {
        let probes_path = self.path.join("monitoring_attrs/probes/nr_probes");
        if path_exists(&probes_path)? {
            ensure_count(&probes_path, config.probes.len())?;
            let observed_probes = observed
                .map(|value| value.probes.as_slice())
                .filter(|probes| probes.len() == config.probes.len());
            for (index, probe) in config.probes.iter().enumerate() {
                self.probe(index).stage_configuration_from(
                    probe,
                    observed_probes.map(|values| &values[index]),
                )?;
            }
        } else if !config.probes.is_empty() {
            return Err(Error::UnsupportedFeature {
                feature: "DAMON monitoring probes",
            });
        }
        if needs_stage(
            observed.map(|value| &value.sample_control),
            &config.sample_control,
        ) {
            stage_optional_default(
                &self.path.join("monitoring_attrs/sample"),
                &config.sample_control,
                &SampleControlConfig::default(),
                "DAMON sample controls",
                || {
                    self.sample_control()
                        .stage_configuration(&config.sample_control)
                },
            )?;
        }
        ensure_count(&self.path.join("targets/nr_targets"), config.targets.len())?;
        let observed_targets = observed
            .map(|value| value.targets.as_slice())
            .filter(|targets| targets.len() == config.targets.len());
        for (index, target) in config.targets.iter().enumerate() {
            self.target(index)
                .stage_configuration_from(target, observed_targets.map(|values| &values[index]))?;
        }
        ensure_count(&self.path.join("schemes/nr_schemes"), config.schemes.len())?;
        let observed_schemes = observed
            .map(|value| value.schemes.as_slice())
            .filter(|schemes| schemes.len() == config.schemes.len());
        for (index, scheme) in config.schemes.iter().enumerate() {
            self.scheme(index)
                .stage_configuration_from(scheme, observed_schemes.map(|values| &values[index]))?;
        }
        Ok(())
    }
}

impl Target {
    /// Returns a typed handle for one staged initial region.
    #[must_use]
    pub fn initial_region(&self, index: usize) -> InitialRegion {
        InitialRegion {
            path: self.path.join("regions").join(index.to_string()),
        }
    }

    /// Reads this complete staged target into owned data.
    pub fn configuration(&self) -> Result<TargetConfig> {
        let count_path = self.path.join("regions/nr_regions");
        let initial_regions = if path_exists(&count_path)? {
            read_indexed(self.initial_region_count()?, |index| {
                self.initial_region(index).configuration()
            })?
        } else {
            Vec::new()
        };
        Ok(TargetConfig {
            pid: self.pid()?,
            obsolete: optional_read(&self.path.join("obsolete_target"), || self.is_obsolete())?
                .unwrap_or(false),
            initial_regions,
        })
    }

    fn stage_configuration_from(
        &self,
        config: &TargetConfig,
        observed: Option<&TargetConfig>,
    ) -> Result<()> {
        if observed == Some(config) {
            return Ok(());
        }
        if needs_stage(observed.map(|value| &value.pid), &config.pid) {
            if let Some(pid) = config.pid {
                self.set_pid(pid)?;
            } else {
                self.clear_pid()?;
            }
        }
        if needs_stage(observed.map(|value| &value.obsolete), &config.obsolete) {
            stage_optional_default(
                &self.path.join("obsolete_target"),
                &config.obsolete,
                &false,
                "obsolete DAMON targets",
                || self.set_obsolete(config.obsolete),
            )?;
        }
        let regions_path = self.path.join("regions/nr_regions");
        if path_exists(&regions_path)? {
            ensure_count(&regions_path, config.initial_regions.len())?;
            let observed_regions = observed
                .map(|value| value.initial_regions.as_slice())
                .filter(|regions| regions.len() == config.initial_regions.len());
            for (index, region) in config.initial_regions.iter().copied().enumerate() {
                if observed_regions.is_none_or(|values| values[index] != region) {
                    self.initial_region(index).stage_configuration(region)?;
                }
            }
        } else if !config.initial_regions.is_empty() {
            return Err(Error::UnsupportedFeature {
                feature: "DAMON initial regions",
            });
        }
        Ok(())
    }
}

impl Probe {
    /// Reads the relative probe weight.
    pub fn weight(&self) -> Result<u32> {
        read_u32(&self.path.join("weight"))
    }

    /// Sets the relative probe weight.
    pub fn set_weight(&self, value: u32) -> Result<()> {
        write_value(&self.path.join("weight"), value)
    }

    /// Reads the number of staged preparations.
    pub fn preparation_count(&self) -> Result<usize> {
        read_usize(&self.path.join("preps/nr_preps"))
    }

    /// Reconstructs the staged preparation directories.
    pub fn set_preparation_count(&self, count: usize) -> Result<()> {
        validate_count("probe preparation count", count)?;
        write_value(&self.path.join("preps/nr_preps"), count)
    }

    /// Returns a typed handle to one preparation.
    #[must_use]
    pub fn preparation(&self, index: usize) -> ProbePreparation {
        ProbePreparation {
            path: self.path.join("preps").join(index.to_string()),
        }
    }

    /// Reads this staged probe into owned data.
    pub fn configuration(&self) -> Result<ProbeConfig> {
        Ok(ProbeConfig {
            filters: read_indexed(self.filter_count()?, |index| {
                self.filter(index).configuration()
            })?,
            weight: optional_read(&self.path.join("weight"), || self.weight())?.unwrap_or(0),
            preparations: if path_exists(&self.path.join("preps/nr_preps"))? {
                read_indexed(self.preparation_count()?, |index| {
                    self.preparation(index).configuration()
                })?
            } else {
                Vec::new()
            },
        })
    }

    fn stage_configuration_from(
        &self,
        config: &ProbeConfig,
        observed: Option<&ProbeConfig>,
    ) -> Result<()> {
        if observed == Some(config) {
            return Ok(());
        }
        ensure_count(&self.path.join("filters/nr_filters"), config.filters.len())?;
        let observed_filters = observed
            .map(|value| value.filters.as_slice())
            .filter(|filters| filters.len() == config.filters.len());
        for (index, filter) in config.filters.iter().enumerate() {
            if observed_filters.is_none_or(|values| values[index] != *filter) {
                self.filter(index).stage_configuration(filter)?;
            }
        }
        if needs_stage(observed.map(|value| &value.weight), &config.weight) {
            stage_optional_default(
                &self.path.join("weight"),
                &config.weight,
                &0,
                "DAMON probe weights",
                || self.set_weight(config.weight),
            )?;
        }
        let preparations_path = self.path.join("preps/nr_preps");
        if path_exists(&preparations_path)? {
            ensure_count(&preparations_path, config.preparations.len())?;
            let observed_preparations = observed
                .map(|value| value.preparations.as_slice())
                .filter(|preparations| preparations.len() == config.preparations.len());
            for (index, preparation) in config.preparations.iter().enumerate() {
                if observed_preparations.is_none_or(|values| values[index] != *preparation) {
                    self.preparation(index).stage_configuration(preparation)?;
                }
            }
        } else if !config.preparations.is_empty() {
            return Err(Error::UnsupportedFeature {
                feature: "DAMON probe preparations",
            });
        }
        Ok(())
    }
}

impl ProbeFilter {
    /// Reads this staged probe filter into owned data.
    pub fn configuration(&self) -> Result<ProbeFilterConfig> {
        let filter_type = self.filter_type()?;
        let cgroup_path = if matches!(
            filter_type,
            ProbeFilterType::MemoryControlGroup | ProbeFilterType::Unknown(_)
        ) {
            Some(self.cgroup_path()?)
        } else {
            None
        };
        Ok(ProbeFilterConfig {
            filter_type,
            matching: self.matching()?,
            allow: self.allowed()?,
            cgroup_path,
        })
    }

    fn stage_configuration(&self, config: &ProbeFilterConfig) -> Result<()> {
        self.set_filter_type(&config.filter_type)?;
        self.set_matching(config.matching)?;
        self.set_allowed(config.allow)?;
        if let Some(path) = &config.cgroup_path {
            self.set_cgroup_path(path)?;
        }
        Ok(())
    }
}

impl Scheme {
    /// Reads the legacy migration target node, with `-1` meaning no node.
    pub fn target_node(&self) -> Result<i32> {
        read_i32(&self.path.join("target_nid"))
    }

    /// Sets the legacy migration target node.
    pub fn set_target_node(&self, node: i32) -> Result<()> {
        write_value(&self.path.join("target_nid"), node)
    }

    /// Returns a typed handle for this scheme's quota attributes.
    #[must_use]
    pub fn quotas(&self) -> SchemeQuotas {
        SchemeQuotas {
            path: self.path.join("quotas"),
        }
    }

    /// Returns a typed handle for this scheme's watermark attributes.
    #[must_use]
    pub fn watermarks(&self) -> SchemeWatermarks {
        SchemeWatermarks {
            path: self.path.join("watermarks"),
        }
    }

    /// Reads the number of filters staged in one filter layer.
    pub fn filter_count(&self, layer: FilterLayer) -> Result<usize> {
        read_usize(&self.path.join(layer.directory()).join("nr_filters"))
    }

    /// Reconstructs one layer's staged filter directories.
    pub fn set_filter_count(&self, layer: FilterLayer, count: usize) -> Result<()> {
        validate_count("scheme filter count", count)?;
        write_value(&self.path.join(layer.directory()).join("nr_filters"), count)
    }

    /// Returns a typed handle for one staged filter.
    #[must_use]
    pub fn filter(&self, layer: FilterLayer, index: usize) -> SchemeFilter {
        SchemeFilter {
            path: self.path.join(layer.directory()).join(index.to_string()),
        }
    }

    /// Reads the number of weighted migration destinations.
    pub fn destination_count(&self) -> Result<usize> {
        read_usize(&self.path.join("dests/nr_dests"))
    }

    /// Reconstructs the staged weighted migration destinations.
    pub fn set_destination_count(&self, count: usize) -> Result<()> {
        validate_count("migration destination count", count)?;
        write_value(&self.path.join("dests/nr_dests"), count)
    }

    /// Returns a typed handle for one migration destination.
    #[must_use]
    pub fn destination(&self, index: usize) -> MigrationDestination {
        MigrationDestination {
            path: self.path.join("dests").join(index.to_string()),
        }
    }

    /// Reads all scheme statistics currently materialized in sysfs.
    pub fn stats(&self) -> Result<SchemeStats> {
        let path = self.path.join("stats");
        Ok(SchemeStats {
            regions_tried: read_u64(&path.join("nr_tried"))?,
            size_tried_units: read_u64(&path.join("sz_tried"))?,
            regions_applied: read_u64(&path.join("nr_applied"))?,
            size_applied_units: read_u64(&path.join("sz_applied"))?,
            operations_filter_passed_units: optional_read(
                &path.join("sz_ops_filter_passed"),
                || read_u64(&path.join("sz_ops_filter_passed")),
            )?,
            quota_exceeds: read_u64(&path.join("qt_exceeds"))?,
            snapshots: optional_read(&path.join("nr_snapshots"), || {
                read_u64(&path.join("nr_snapshots"))
            })?,
            maximum_snapshots: optional_read(&path.join("max_nr_snapshots"), || {
                read_u64(&path.join("max_nr_snapshots"))
            })?,
        })
    }

    /// Reads the configured maximum number of retained snapshots.
    pub fn maximum_snapshots(&self) -> Result<u64> {
        read_u64(&self.path.join("stats/max_nr_snapshots"))
    }

    /// Sets the maximum number of retained snapshots.
    pub fn set_maximum_snapshots(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("stats/max_nr_snapshots"), value)
    }

    /// Reads this complete staged scheme into owned data.
    pub fn configuration(&self) -> Result<SchemeConfig> {
        let mut filters = self.read_filter_layer(FilterLayer::Core)?;
        filters.extend(self.read_filter_layer(FilterLayer::Operations)?);
        filters.extend(self.read_filter_layer(FilterLayer::Unified)?);
        Ok(SchemeConfig {
            action: self.action()?,
            access_pattern: self.access_pattern()?,
            apply_interval: optional_read(&self.path.join("apply_interval_us"), || {
                self.apply_interval()
            })?
            .unwrap_or(Duration::ZERO),
            target_node: optional_read(&self.path.join("target_nid"), || self.target_node())?
                .and_then(|node| (node != -1).then_some(node)),
            quota: self.quotas().configuration()?,
            watermarks: self.watermarks().configuration()?,
            filters,
            destinations: self.read_destinations()?,
            maximum_snapshots: optional_read(&self.path.join("stats/max_nr_snapshots"), || {
                self.maximum_snapshots()
            })?
            .unwrap_or(0),
        })
    }

    fn read_filter_layer(&self, layer: FilterLayer) -> Result<Vec<FilterConfig>> {
        let count_path = self.path.join(layer.directory()).join("nr_filters");
        if !path_exists(&count_path)? {
            return Ok(Vec::new());
        }
        read_indexed(self.filter_count(layer)?, |index| {
            let mut config = self.filter(layer, index).configuration()?;
            config.placement = FilterPlacement::from_layer(layer);
            Ok(config)
        })
    }

    fn read_destinations(&self) -> Result<Vec<DestinationConfig>> {
        let count_path = self.path.join("dests/nr_dests");
        if !path_exists(&count_path)? {
            return Ok(Vec::new());
        }
        read_indexed(self.destination_count()?, |index| {
            self.destination(index).configuration()
        })
    }

    fn stage_configuration_from(
        &self,
        config: &SchemeConfig,
        observed: Option<&SchemeConfig>,
    ) -> Result<()> {
        if observed == Some(config) {
            return Ok(());
        }
        if needs_stage(observed.map(|value| &value.action), &config.action) {
            self.set_action(&config.action)?;
        }
        if observed.is_none_or(|value| {
            !config
                .access_pattern
                .equivalent_after_kernel_normalization(value.access_pattern)
        }) {
            self.set_access_pattern_adaptive(config.access_pattern)?;
        }
        if needs_stage(
            observed.map(|value| &value.apply_interval),
            &config.apply_interval,
        ) {
            stage_optional_default(
                &self.path.join("apply_interval_us"),
                &config.apply_interval,
                &Duration::ZERO,
                "DAMOS apply intervals",
                || self.set_apply_interval(config.apply_interval),
            )?;
        }
        if needs_stage(
            observed.map(|value| &value.target_node),
            &config.target_node,
        ) {
            let target_node_path = self.path.join("target_nid");
            if path_exists(&target_node_path)? {
                self.set_target_node(config.target_node.unwrap_or(-1))?;
            } else if config.target_node.is_some() {
                return Err(Error::UnsupportedFeature {
                    feature: "DAMOS migration",
                });
            }
        }
        self.quotas()
            .stage_configuration_from(&config.quota, observed.map(|value| &value.quota))?;
        self.watermarks().stage_configuration_from(
            &config.watermarks,
            observed.map(|value| &value.watermarks),
        )?;
        if observed.is_none_or(|value| !semantic_filters_match(&config.filters, &value.filters)) {
            self.stage_semantic_filters(&config.filters)?;
        }
        if needs_stage(
            observed.map(|value| &value.destinations),
            &config.destinations,
        ) {
            let destinations_path = self.path.join("dests/nr_dests");
            if path_exists(&destinations_path)? {
                ensure_count(&destinations_path, config.destinations.len())?;
                let observed_destinations = observed
                    .map(|value| value.destinations.as_slice())
                    .filter(|destinations| destinations.len() == config.destinations.len());
                for (index, destination) in config.destinations.iter().copied().enumerate() {
                    if observed_destinations.is_none_or(|values| values[index] != destination) {
                        self.destination(index).stage_configuration(destination)?;
                    }
                }
            } else if !config.destinations.is_empty() {
                return Err(Error::UnsupportedFeature {
                    feature: "DAMOS migration destinations",
                });
            }
        }
        if needs_stage(
            observed.map(|value| &value.maximum_snapshots),
            &config.maximum_snapshots,
        ) {
            stage_optional_default(
                &self.path.join("stats/max_nr_snapshots"),
                &config.maximum_snapshots,
                &0,
                "DAMOS maximum snapshot count",
                || self.set_maximum_snapshots(config.maximum_snapshots),
            )?;
        }
        Ok(())
    }

    fn stage_semantic_filters(&self, filters: &[FilterConfig]) -> Result<()> {
        let has_core = path_exists(&self.path.join("core_filters/nr_filters"))?;
        let has_operations = path_exists(&self.path.join("ops_filters/nr_filters"))?;
        let has_unified = path_exists(&self.path.join("filters/nr_filters"))?;
        if has_core || has_operations {
            let mut core = Vec::new();
            let mut operations = Vec::new();
            let mut unified = Vec::new();
            for filter in filters {
                match filter.placement {
                    FilterPlacement::Core => core.push(filter),
                    FilterPlacement::Operations => operations.push(filter),
                    FilterPlacement::Unified => unified.push(filter),
                    FilterPlacement::Adaptive => {
                        if filter.filter_type.handled_by_operations() == Some(false) {
                            core.push(filter);
                        } else {
                            operations.push(filter);
                        }
                    }
                }
            }
            self.stage_filter_layer_if_present(FilterLayer::Core, &core, has_core)?;
            self.stage_filter_layer_if_present(
                FilterLayer::Operations,
                &operations,
                has_operations,
            )?;
            self.stage_filter_layer_if_present(FilterLayer::Unified, &unified, has_unified)
        } else if has_unified {
            if filters.iter().any(|filter| {
                matches!(
                    filter.placement,
                    FilterPlacement::Core | FilterPlacement::Operations
                )
            }) {
                return Err(Error::UnsupportedFeature {
                    feature: "split DAMOS filter placement",
                });
            }
            let unified = filters.iter().collect::<Vec<_>>();
            self.stage_filter_layer(FilterLayer::Unified, &unified)
        } else if filters.is_empty() {
            Ok(())
        } else {
            Err(Error::UnsupportedFeature {
                feature: "DAMOS filters",
            })
        }
    }

    fn stage_filter_layer_if_present(
        &self,
        layer: FilterLayer,
        filters: &[&FilterConfig],
        present: bool,
    ) -> Result<()> {
        if present {
            self.stage_filter_layer(layer, filters)
        } else if filters.is_empty() {
            Ok(())
        } else {
            Err(Error::UnsupportedFeature {
                feature: match layer {
                    FilterLayer::Unified => "unified DAMOS filters",
                    FilterLayer::Core => "core DAMOS filters",
                    FilterLayer::Operations => "operations DAMOS filters",
                },
            })
        }
    }

    fn stage_filter_layer(&self, layer: FilterLayer, filters: &[&FilterConfig]) -> Result<()> {
        let count_path = self.path.join(layer.directory()).join("nr_filters");
        ensure_count(&count_path, filters.len())?;
        for (index, filter) in filters.iter().enumerate() {
            self.filter(layer, index).stage_configuration(filter)?;
        }
        Ok(())
    }
}

impl DamonAdmin {
    /// Reads the complete staged DAMON admin configuration.
    ///
    /// Runtime state and materialized result files are intentionally excluded.
    pub fn configuration(&self) -> Result<DamonConfig> {
        Ok(DamonConfig {
            kdamonds: read_indexed(self.kdamond_count()?, |index| {
                self.kdamond(index).configuration()
            })?,
        })
    }

    /// Validates and stages a complete DAMON admin configuration.
    ///
    /// This low-level method does not acquire an advisory lock and cannot
    /// restore the old hierarchy after an I/O failure. Prefer
    /// [`crate::Damon::stage_configuration`] when replacing global state.
    pub fn stage_configuration(&self, config: &DamonConfig) -> Result<()> {
        config.validate()?;
        self.stage_validated_configuration(config)
    }

    pub(crate) fn stage_validated_configuration(&self, config: &DamonConfig) -> Result<()> {
        self.stage_validated_configuration_from(config, None)
    }

    pub(crate) fn stage_validated_configuration_from(
        &self,
        config: &DamonConfig,
        observed: Option<&DamonConfig>,
    ) -> Result<()> {
        if observed == Some(config) {
            return Ok(());
        }
        ensure_count(
            &self.path().join("kdamonds/nr_kdamonds"),
            config.kdamonds.len(),
        )?;
        let observed_kdamonds = observed
            .map(|value| value.kdamonds.as_slice())
            .filter(|kdamonds| kdamonds.len() == config.kdamonds.len());
        for (index, kdamond) in config.kdamonds.iter().enumerate() {
            self.kdamond(index).stage_validated_configuration_from(
                kdamond,
                observed_kdamonds.map(|values| &values[index]),
            )?;
        }
        Ok(())
    }
}

impl Kdamond {
    /// Reads the complete staged kdamond configuration into owned data.
    pub fn configuration(&self) -> Result<KdamondConfig> {
        Ok(KdamondConfig {
            refresh_interval: optional_read(&self.path.join("refresh_ms"), || {
                self.refresh_interval()
            })?
            .unwrap_or(Duration::ZERO),
            contexts: read_indexed(self.context_count()?, |index| {
                self.context(index).configuration()
            })?,
        })
    }

    /// Validates and stages a complete owned kdamond configuration.
    ///
    /// Validation completes before the first sysfs write. A later I/O error
    /// can still leave a partially staged hierarchy. Transactional restoration
    /// belongs to the exclusive session layer.
    pub fn stage_configuration(&self, config: &KdamondConfig) -> Result<()> {
        config.validate()?;
        self.stage_validated_configuration(config)
    }

    fn stage_validated_configuration(&self, config: &KdamondConfig) -> Result<()> {
        self.stage_validated_configuration_from(config, None)
    }

    fn stage_validated_configuration_from(
        &self,
        config: &KdamondConfig,
        observed: Option<&KdamondConfig>,
    ) -> Result<()> {
        if observed == Some(config) {
            return Ok(());
        }
        if needs_stage(
            observed.map(|value| &value.refresh_interval),
            &config.refresh_interval,
        ) {
            stage_optional_default(
                &self.path.join("refresh_ms"),
                &config.refresh_interval,
                &Duration::ZERO,
                "periodic DAMON sysfs refresh",
                || self.set_refresh_interval(config.refresh_interval),
            )?;
        }
        ensure_count(
            &self.path.join("contexts/nr_contexts"),
            config.contexts.len(),
        )?;
        let observed_contexts = observed
            .map(|value| value.contexts.as_slice())
            .filter(|contexts| contexts.len() == config.contexts.len());
        for (index, context) in config.contexts.iter().enumerate() {
            self.context(index).stage_validated_configuration_from(
                context,
                observed_contexts.map(|values| &values[index]),
            )?;
        }
        Ok(())
    }
}
