//! DAMOS scheme, quota, filter, and watermark configuration values.

use super::{
    AccessPattern, Action, ByteSizeRange, Duration, Error, FilterLayer, FilterPlacement, Operation,
    QuotaGoalMetric, QuotaGoalTuner, Result, SchemeFilterType, WatermarkMetric, exact_micros,
    exact_millis, invalid, validate_count, validate_required_path, validate_sysfs_string,
    validate_token,
};

/// Configuration for a DAMOS filter.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct FilterConfig {
    /// Directory placement, or adaptive selection for newly built filters.
    pub placement: FilterPlacement,
    /// Filter type.
    pub filter_type: SchemeFilterType,
    /// Whether the filter matches or negates its criterion.
    pub matching: bool,
    /// Whether matching memory is allowed through the filter.
    pub allow: bool,
    /// Cgroup path for a memory-control-group filter.
    pub cgroup_path: Option<String>,
    /// Inclusive-start, exclusive-end range for an address filter.
    pub address_range: Option<(u64, u64)>,
    /// Byte-size range for a huge-page-size filter.
    pub size_range: Option<ByteSizeRange>,
    /// Target index for a target filter.
    pub target_index: Option<usize>,
}

impl FilterConfig {
    /// Creates a filter without type-specific data.
    #[must_use]
    pub fn new(filter_type: SchemeFilterType, matching: bool, allow: bool) -> Self {
        Self {
            placement: FilterPlacement::Adaptive,
            filter_type,
            matching,
            allow,
            cgroup_path: None,
            address_range: None,
            size_range: None,
            target_index: None,
        }
    }

    /// Creates an address-range filter.
    #[must_use]
    pub fn address(start: u64, end: u64, matching: bool, allow: bool) -> Self {
        Self {
            address_range: Some((start, end)),
            ..Self::new(SchemeFilterType::Address, matching, allow)
        }
    }

    /// Creates a memory-control-group filter.
    #[must_use]
    pub fn memory_control_group(path: impl Into<String>, matching: bool, allow: bool) -> Self {
        Self {
            cgroup_path: Some(path.into()),
            ..Self::new(SchemeFilterType::MemoryControlGroup, matching, allow)
        }
    }

    /// Creates a huge-page-size filter.
    #[must_use]
    pub fn huge_page_size(range: ByteSizeRange, matching: bool, allow: bool) -> Self {
        Self {
            size_range: Some(range),
            ..Self::new(SchemeFilterType::HugePageSize, matching, allow)
        }
    }

    /// Creates a target-index filter.
    #[must_use]
    pub fn target(index: usize, matching: bool, allow: bool) -> Self {
        Self {
            target_index: Some(index),
            ..Self::new(SchemeFilterType::Target, matching, allow)
        }
    }

    /// Validates this filter for a directory layer and configured target count.
    pub fn validate_for(&self, layer: FilterLayer, target_count: usize) -> Result<()> {
        if self
            .placement
            .exact_layer()
            .is_some_and(|placement| placement != layer)
        {
            return invalid(
                "scheme filter placement",
                "does not match the directory layer selected for validation",
            );
        }
        self.validate_in_layer(layer, target_count)
    }

    fn validate(&self, target_count: usize) -> Result<()> {
        self.validate_in_layer(
            self.placement.exact_layer().unwrap_or(FilterLayer::Unified),
            target_count,
        )
    }

    fn validate_in_layer(&self, layer: FilterLayer, target_count: usize) -> Result<()> {
        validate_token("scheme filter type", self.filter_type.kernel_name())?;
        match (layer, self.filter_type.handled_by_operations()) {
            (FilterLayer::Core, Some(true)) => {
                return invalid(
                    "scheme filter layer",
                    "operations-handled filter cannot be staged in core_filters",
                );
            }
            (FilterLayer::Operations, Some(false)) => {
                return invalid(
                    "scheme filter layer",
                    "core-handled filter cannot be staged in ops_filters",
                );
            }
            _ => {}
        }

        match self.filter_type {
            SchemeFilterType::MemoryControlGroup => {
                validate_required_path("scheme filter cgroup path", self.cgroup_path.as_deref())?;
            }
            SchemeFilterType::Address => {
                let Some((start, end)) = self.address_range else {
                    return invalid("scheme address filter", "requires an address range");
                };
                if start > end {
                    return invalid(
                        "scheme address filter",
                        "start must not exceed the exclusive end boundary",
                    );
                }
            }
            SchemeFilterType::HugePageSize => {
                if self.size_range.is_none() {
                    return invalid("huge-page-size filter", "requires a size range");
                }
            }
            SchemeFilterType::Target => {
                let Some(index) = self.target_index else {
                    return invalid("target filter", "requires a target index");
                };
                validate_count("target filter index", index)?;
                if index >= target_count {
                    return invalid("target filter index", "must refer to a configured target");
                }
            }
            _ => {}
        }

        if let Some(path) = &self.cgroup_path {
            validate_sysfs_string("scheme filter cgroup path", path)?;
        }
        if let Some(index) = self.target_index {
            validate_count("target filter index", index)?;
        }
        Ok(())
    }
}

/// Prioritization weights for a DAMOS quota.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct QuotaWeights {
    /// Region-size weight in parts per thousand.
    pub size_per_thousand: u32,
    /// Access-count weight in parts per thousand.
    pub accesses_per_thousand: u32,
    /// Region-age weight in parts per thousand.
    pub age_per_thousand: u32,
}

/// Configuration for one DAMOS quota goal.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct QuotaGoalConfig {
    /// Goal metric.
    pub metric: QuotaGoalMetric,
    /// Target value in the metric's kernel-defined unit.
    pub target_value: u64,
    /// Current userspace-fed value.
    pub current_value: u64,
    /// NUMA node identifier for node metrics.
    pub node_id: Option<i32>,
    /// Cgroup path for node-cgroup metrics.
    pub cgroup_path: Option<String>,
}

impl QuotaGoalConfig {
    /// Creates a quota goal with no metric-specific selectors.
    #[must_use]
    pub fn new(metric: QuotaGoalMetric, target_value: u64) -> Self {
        Self {
            metric,
            target_value,
            current_value: 0,
            node_id: None,
            cgroup_path: None,
        }
    }

    /// Validates this quota goal without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_token("quota goal metric", self.metric.kernel_name())?;
        let enabled = self.target_value != 0;
        if enabled && self.metric.uses_basis_points() && self.target_value > 10_000 {
            return invalid(
                "quota goal target value",
                "basis-point metrics must not exceed 10000",
            );
        }
        if enabled && self.metric.requires_node() && self.node_id.is_none() {
            return invalid("quota goal node", "is required by the selected metric");
        }
        if self.node_id.is_some_and(|node| node < 0) {
            return invalid("quota goal node", "must be non-negative");
        }
        if enabled && self.metric.requires_cgroup_path() {
            validate_required_path("quota goal cgroup path", self.cgroup_path.as_deref())?;
        } else if let Some(path) = &self.cgroup_path {
            validate_sysfs_string("quota goal cgroup path", path)?;
        }
        Ok(())
    }
}

/// DAMOS time, size, goal, and prioritization quota settings.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct QuotaConfig {
    /// Time quota per reset interval.
    pub time: Duration,
    /// Size quota in DAMON core address units.
    pub size_units: u64,
    /// Quota reset interval.
    pub reset_interval: Duration,
    /// Prioritization weights.
    pub weights: QuotaWeights,
    /// Quota goals.
    pub goals: Vec<QuotaGoalConfig>,
    /// Quota-goal tuner.
    pub goal_tuner: QuotaGoalTuner,
    /// Numerator for charging failed action applications.
    pub failure_charge_numerator: u32,
    /// Denominator for charging failed action applications, or zero to disable it.
    pub failure_charge_denominator: u32,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            time: Duration::ZERO,
            size_units: 0,
            reset_interval: Duration::ZERO,
            weights: QuotaWeights::default(),
            goals: Vec::new(),
            goal_tuner: QuotaGoalTuner::Consistent,
            failure_charge_numerator: 0,
            failure_charge_denominator: 0,
        }
    }
}

impl QuotaConfig {
    /// Validates this quota and its goals without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        exact_millis("quota time", self.time)?;
        exact_millis("quota reset interval", self.reset_interval)?;
        if self.weights.size_per_thousand > 1_000
            || self.weights.accesses_per_thousand > 1_000
            || self.weights.age_per_thousand > 1_000
        {
            return invalid(
                "quota prioritization weights",
                "each weight must be at most 1000 parts per thousand",
            );
        }
        validate_count("quota goal count", self.goals.len())?;
        for goal in &self.goals {
            goal.validate()?;
        }
        let has_active_goal = self.goals.iter().any(|goal| goal.target_value != 0);
        if (self.time != Duration::ZERO || self.size_units != 0 || has_active_goal)
            && self.reset_interval == Duration::ZERO
        {
            return invalid(
                "quota reset interval",
                "must be non-zero when a time, size, or goal quota is enabled",
            );
        }
        validate_token("quota goal tuner", self.goal_tuner.kernel_name())?;
        Ok(())
    }
}

/// DAMOS watermark settings.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct WatermarksConfig {
    /// Watermark metric.
    pub metric: WatermarkMetric,
    /// Metric check interval.
    pub interval: Duration,
    /// High watermark in the metric's unit.
    pub high: u64,
    /// Middle watermark in the metric's unit.
    pub middle: u64,
    /// Low watermark in the metric's unit.
    pub low: u64,
}

impl Default for WatermarksConfig {
    fn default() -> Self {
        Self {
            metric: WatermarkMetric::None,
            interval: Duration::ZERO,
            high: 0,
            middle: 0,
            low: 0,
        }
    }
}

impl WatermarksConfig {
    /// Validates these watermarks without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_token("watermark metric", self.metric.kernel_name())?;
        exact_micros("watermark interval", self.interval)?;
        if matches!(self.metric, WatermarkMetric::FreeMemoryRate) {
            if self.interval == Duration::ZERO {
                return invalid(
                    "watermark interval",
                    "must be non-zero when free-memory watermarks are enabled",
                );
            }
            if self.high > 1_000 || self.middle > 1_000 || self.low > 1_000 {
                return invalid(
                    "free-memory watermarks",
                    "values must be at most 1000 parts per thousand",
                );
            }
            if self.high < self.middle || self.middle < self.low {
                return invalid("watermarks", "values must be ordered high >= middle >= low");
            }
        }
        Ok(())
    }
}

/// One weighted migration destination.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct DestinationConfig {
    /// Kernel NUMA node identifier.
    pub node_id: u32,
    /// Relative destination weight.
    pub weight: u32,
}

impl DestinationConfig {
    /// Creates a weighted migration destination.
    #[must_use]
    pub const fn new(node_id: u32, weight: u32) -> Self {
        Self { node_id, weight }
    }
}

/// Configuration for one DAMOS scheme.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SchemeConfig {
    /// Scheme action.
    pub action: Action,
    /// Target access pattern.
    pub access_pattern: AccessPattern,
    /// Minimum application interval, or zero to use the aggregation interval.
    pub apply_interval: Duration,
    /// Optional legacy migration target node, with `-1` meaning no node.
    pub target_node: Option<i32>,
    /// Quota settings.
    pub quota: QuotaConfig,
    /// Watermark settings.
    pub watermarks: WatermarksConfig,
    /// Semantic filter list, adapted to unified or split kernel directories.
    pub filters: Vec<FilterConfig>,
    /// Weighted migration destinations.
    pub destinations: Vec<DestinationConfig>,
    /// Maximum number of retained snapshots, or zero for the kernel default.
    pub maximum_snapshots: u64,
}

impl SchemeConfig {
    /// Creates a scheme with disabled quotas and watermarks.
    #[must_use]
    pub fn new(action: Action, access_pattern: AccessPattern) -> Self {
        Self {
            action,
            access_pattern,
            apply_interval: Duration::ZERO,
            target_node: None,
            quota: QuotaConfig::default(),
            watermarks: WatermarksConfig::default(),
            filters: Vec::new(),
            destinations: Vec::new(),
            maximum_snapshots: 0,
        }
    }

    /// Validates this scheme for the configured context target count.
    pub fn validate_for(&self, target_count: usize) -> Result<()> {
        validate_token("scheme action", self.action.kernel_name())?;
        exact_micros("scheme apply interval", self.apply_interval)?;
        self.quota.validate()?;
        self.watermarks.validate()?;
        validate_count("scheme filter count", self.filters.len())?;
        for filter in &self.filters {
            filter.validate(target_count)?;
        }
        validate_count("migration destination count", self.destinations.len())?;
        let mut total_weight = 0_u32;
        for destination in &self.destinations {
            if destination.node_id > i32::MAX as u32 {
                return invalid(
                    "migration destination node",
                    "must fit the kernel's signed NUMA node identifier",
                );
            }
            total_weight = total_weight.checked_add(destination.weight).ok_or(
                Error::InvalidConfiguration {
                    field: "migration destination weights",
                    reason: "sum must fit the kernel's unsigned-int accumulator",
                },
            )?;
        }
        if !self.destinations.is_empty() && total_weight == 0 {
            return invalid(
                "migration destination weights",
                "at least one destination must have non-zero weight",
            );
        }
        if self.target_node.is_some_and(|node| node < 0) {
            return invalid(
                "migration target node",
                "must be non-negative, or None for NUMA_NO_NODE",
            );
        }
        Ok(())
    }

    pub(super) fn validate_runnable_for(
        &self,
        operation: &Operation,
        target_count: usize,
    ) -> Result<()> {
        self.validate_for(target_count)?;
        let known_supported = match operation {
            Operation::VirtualAddress | Operation::FixedVirtualAddress => matches!(
                self.action,
                Action::WillNeed
                    | Action::Cold
                    | Action::PageOut
                    | Action::HugePage
                    | Action::NoHugePage
                    | Action::Collapse
                    | Action::MigrateHot
                    | Action::MigrateCold
                    | Action::Stat
                    | Action::Unknown(_)
            ),
            Operation::PhysicalAddress => matches!(
                self.action,
                Action::PageOut
                    | Action::LruPrioritize
                    | Action::LruDeprioritize
                    | Action::MigrateHot
                    | Action::MigrateCold
                    | Action::DamosAllocate
                    | Action::DamosFree
                    | Action::Stat
                    | Action::Unknown(_)
            ),
            Operation::Unknown(_) => true,
        };
        if !known_supported {
            return invalid(
                "scheme action",
                "is not supported by the selected monitoring operation",
            );
        }
        let migration = matches!(self.action, Action::MigrateHot | Action::MigrateCold);
        if !migration && (self.target_node.is_some() || !self.destinations.is_empty()) {
            return invalid(
                "migration destination",
                "requires a migrate_hot or migrate_cold scheme action",
            );
        }
        if !matches!(
            operation,
            Operation::PhysicalAddress | Operation::Unknown(_)
        ) && self
            .quota
            .goals
            .iter()
            .any(|goal| matches!(goal.metric, QuotaGoalMetric::NodeEligibleMemoryBasisPoints))
        {
            return invalid(
                "quota goal metric",
                "node_eligible_mem_bp requires physical-address monitoring",
            );
        }
        Ok(())
    }
}
