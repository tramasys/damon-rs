//! Owned DAMON configurations and typed access to nested sysfs attributes.
//!
//! An optional field is `None` when an older kernel does not expose that
//! attribute. Staging also treats `None` as "leave the attribute untouched".
//! Integer fields backed by the kernel's `unsigned long` use `u64` so a 32-bit
//! process can configure a 64-bit kernel. The running kernel rejects values
//! wider than its own ABI during the write.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{
    AccessPattern, Action, AddressUnit, ByteSizeRange, Context, DamonAdmin, Kdamond,
    MonitoringIntervals, Operation, Pid, Probe, ProbeFilter, ProbeFilterType, RegionBounds, Scheme,
    Target, path_exists, read_bool, read_i32, read_text, read_u32, read_u64, read_usize,
    write_bool, write_bytes, write_value,
};
use crate::{Error, Result};

const KERNEL_INDEX_MAX: usize = i32::MAX as usize;
const MAX_EAGER_READ_CAPACITY: usize = 4_096;
const CURRENT_MAX_PROBES: usize = 4;

trait KernelName {
    fn kernel_name(&self) -> &str;
}

macro_rules! kernel_string_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $kernel_name:literal,
            )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        #[non_exhaustive]
        pub enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
            /// A value introduced by a newer kernel.
            Unknown(Box<str>),
        }

        impl $name {
            /// Returns the value used by the kernel ABI.
            #[must_use]
            pub fn kernel_name(&self) -> &str {
                match self {
                    $(Self::$variant => $kernel_name,)+
                    Self::Unknown(value) => value,
                }
            }

            fn parse(value: &str) -> Self {
                match value {
                    $($kernel_name => Self::$variant,)+
                    other => Self::Unknown(other.into()),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.kernel_name())
            }
        }

        impl KernelName for $name {
            fn kernel_name(&self) -> &str {
                self.kernel_name()
            }
        }
    };
}

kernel_string_enum! {
    /// A Linux 7.2 DAMOS filter type.
    pub enum SchemeFilterType {
        /// Anonymous memory.
        Anonymous => "anon",
        /// Active memory.
        Active => "active",
        /// Memory belonging to a control group.
        MemoryControlGroup => "memcg",
        /// Young pages.
        Young => "young",
        /// Huge-page sizes.
        HugePageSize => "hugepage_size",
        /// Unmapped memory.
        Unmapped => "unmapped",
        /// A core address range.
        Address => "addr",
        /// A DAMON target index.
        Target => "target",
    }
}

kernel_string_enum! {
    /// An action performed before a monitoring probe is sampled.
    pub enum ProbePreparationAction {
        /// Set the page-idle state used by the following probe.
        SetPageIdle => "set_pgidle",
    }
}

kernel_string_enum! {
    /// A filter for selecting access samples.
    pub enum SampleFilterType {
        /// Match the CPU mask supplied by [`SampleFilterConfig::cpu_mask`].
        CpuMask => "cpumask",
        /// Match the thread list supplied by [`SampleFilterConfig::thread_ids`].
        Threads => "threads",
        /// Match write accesses.
        Write => "write",
    }
}

impl SchemeFilterType {
    fn handled_by_operations(&self) -> Option<bool> {
        match self {
            Self::Address | Self::Target => Some(false),
            Self::Anonymous
            | Self::Active
            | Self::MemoryControlGroup
            | Self::Young
            | Self::HugePageSize
            | Self::Unmapped => Some(true),
            Self::Unknown(_) => None,
        }
    }
}

kernel_string_enum! {
    /// A DAMOS watermark metric.
    pub enum WatermarkMetric {
        /// Disable watermarks.
        None => "none",
        /// System free-memory rate in parts per thousand.
        FreeMemoryRate => "free_mem_rate",
    }
}

kernel_string_enum! {
    /// A DAMOS quota goal metric.
    pub enum QuotaGoalMetric {
        /// A value supplied by userspace.
        UserInput => "user_input",
        /// Some-memory PSI time in microseconds.
        SomeMemoryPressureMicroseconds => "some_mem_psi_us",
        /// Used memory on a NUMA node in basis points.
        NodeMemoryUsedBasisPoints => "node_mem_used_bp",
        /// Free memory on a NUMA node in basis points.
        NodeMemoryFreeBasisPoints => "node_mem_free_bp",
        /// Used memory of a cgroup on a NUMA node in basis points.
        NodeMemoryControlGroupUsedBasisPoints => "node_memcg_used_bp",
        /// Free memory of a cgroup on a NUMA node in basis points.
        NodeMemoryControlGroupFreeBasisPoints => "node_memcg_free_bp",
        /// System active memory in basis points.
        ActiveMemoryBasisPoints => "active_mem_bp",
        /// System inactive memory in basis points.
        InactiveMemoryBasisPoints => "inactive_mem_bp",
        /// Eligible memory on a NUMA node in basis points.
        NodeEligibleMemoryBasisPoints => "node_eligible_mem_bp",
    }
}

impl QuotaGoalMetric {
    fn requires_node(&self) -> bool {
        matches!(
            self,
            Self::NodeMemoryUsedBasisPoints
                | Self::NodeMemoryFreeBasisPoints
                | Self::NodeMemoryControlGroupUsedBasisPoints
                | Self::NodeMemoryControlGroupFreeBasisPoints
                | Self::NodeEligibleMemoryBasisPoints
        )
    }

    fn requires_cgroup_path(&self) -> bool {
        matches!(
            self,
            Self::NodeMemoryControlGroupUsedBasisPoints
                | Self::NodeMemoryControlGroupFreeBasisPoints
        )
    }

    fn uses_basis_points(&self) -> bool {
        matches!(
            self,
            Self::NodeMemoryUsedBasisPoints
                | Self::NodeMemoryFreeBasisPoints
                | Self::NodeMemoryControlGroupUsedBasisPoints
                | Self::NodeMemoryControlGroupFreeBasisPoints
                | Self::ActiveMemoryBasisPoints
                | Self::InactiveMemoryBasisPoints
                | Self::NodeEligibleMemoryBasisPoints
        )
    }
}

kernel_string_enum! {
    /// A DAMOS quota-goal tuning algorithm.
    pub enum QuotaGoalTuner {
        /// Prefer a stable long-term quota.
        Consistent => "consist",
        /// Aim to reach a zero quota quickly.
        Temporal => "temporal",
    }
}

#[allow(clippy::derivable_impls)]
impl Default for QuotaGoalTuner {
    fn default() -> Self {
        Self::Consistent
    }
}

/// Selects one of Linux's DAMOS filter directory layers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FilterLayer {
    /// The original unified `filters` directory.
    Unified,
    /// Filters handled by DAMON core.
    Core,
    /// Filters handled by the monitoring operations implementation.
    Operations,
}

/// Requested or observed placement of a DAMOS filter.
///
/// [`Self::Adaptive`] lets staging select the directory used by the running
/// kernel. The other variants preserve an exact layer when a configuration is
/// read back or when execution order matters.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FilterPlacement {
    /// Select the appropriate unified or split directory at staging time.
    #[default]
    Adaptive,
    /// Use the original unified `filters` directory.
    Unified,
    /// Use the `core_filters` directory.
    Core,
    /// Use the `ops_filters` directory.
    Operations,
}

impl FilterPlacement {
    const fn exact_layer(self) -> Option<FilterLayer> {
        match self {
            Self::Adaptive => None,
            Self::Unified => Some(FilterLayer::Unified),
            Self::Core => Some(FilterLayer::Core),
            Self::Operations => Some(FilterLayer::Operations),
        }
    }

    const fn from_layer(layer: FilterLayer) -> Self {
        match layer {
            FilterLayer::Unified => Self::Unified,
            FilterLayer::Core => Self::Core,
            FilterLayer::Operations => Self::Operations,
        }
    }
}

impl FilterLayer {
    const fn directory(self) -> &'static str {
        match self {
            Self::Unified => "filters",
            Self::Core => "core_filters",
            Self::Operations => "ops_filters",
        }
    }
}

/// Auto-tuning settings for the monitoring sampling interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct IntervalsGoalConfig {
    /// Target access rate in basis points.
    pub access_basis_points: u64,
    /// Number of aggregation intervals used for tuning, or zero to disable it.
    pub aggregation_intervals: u64,
    /// Minimum sampling interval.
    pub minimum_sample: Duration,
    /// Maximum sampling interval.
    pub maximum_sample: Duration,
}

impl Default for IntervalsGoalConfig {
    fn default() -> Self {
        Self {
            access_basis_points: 0,
            aggregation_intervals: 0,
            minimum_sample: Duration::ZERO,
            maximum_sample: Duration::ZERO,
        }
    }
}

impl IntervalsGoalConfig {
    fn values(self) -> Result<(u64, u64, u64, u64)> {
        let minimum = exact_micros("minimum sample interval", self.minimum_sample)?;
        let maximum = exact_micros("maximum sample interval", self.maximum_sample)?;
        Ok((
            self.access_basis_points,
            self.aggregation_intervals,
            minimum,
            maximum,
        ))
    }

    /// Validates the goal against the context's current monitoring intervals.
    pub fn validate_for(self, intervals: MonitoringIntervals) -> Result<()> {
        let (access_basis_points, aggregation_intervals, minimum, maximum) = self.values()?;
        if aggregation_intervals == 0 {
            return Ok(());
        }
        if access_basis_points > 10_000 {
            return invalid(
                "monitoring intervals goal access rate",
                "must be at most 10000 basis points",
            );
        }
        if minimum > maximum {
            return invalid(
                "monitoring intervals goal",
                "minimum sample interval must not exceed maximum",
            );
        }
        let sample = intervals.sample().as_micros();
        if sample < u128::from(minimum) || sample > u128::from(maximum) {
            return invalid(
                "monitoring intervals goal",
                "current sample interval must be within the tuning range",
            );
        }
        Ok(())
    }
}

/// An initial target address range in DAMON core address units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InitialRegionConfig {
    /// Inclusive start address.
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
}

impl InitialRegionConfig {
    /// Creates a non-empty initial region.
    pub const fn new(start: u64, end: u64) -> Result<Self> {
        if start >= end {
            return invalid_const(
                "initial region",
                "start must be less than the exclusive end",
            );
        }
        Ok(Self { start, end })
    }
}

/// Configuration for one monitoring-probe filter.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ProbeFilterConfig {
    /// Filter type.
    pub filter_type: ProbeFilterType,
    /// Whether the filter matches or negates its criterion.
    pub matching: bool,
    /// Whether matching pages contribute probe hits.
    pub allow: bool,
    /// Cgroup path used by a `memcg` filter.
    pub cgroup_path: Option<String>,
}

impl ProbeFilterConfig {
    /// Creates a probe filter without a cgroup path.
    #[must_use]
    pub fn new(filter_type: ProbeFilterType, matching: bool, allow: bool) -> Self {
        Self {
            filter_type,
            matching,
            allow,
            cgroup_path: None,
        }
    }

    /// Creates a memory-control-group probe filter.
    #[must_use]
    pub fn memory_control_group(path: impl Into<String>, matching: bool, allow: bool) -> Self {
        Self {
            filter_type: ProbeFilterType::MemoryControlGroup,
            matching,
            allow,
            cgroup_path: Some(path.into()),
        }
    }

    /// Validates this filter without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_token("probe filter type", self.filter_type.kernel_name())?;
        if matches!(self.filter_type, ProbeFilterType::MemoryControlGroup) {
            validate_required_path("probe filter cgroup path", self.cgroup_path.as_deref())?;
        } else if let Some(path) = &self.cgroup_path {
            validate_sysfs_string("probe filter cgroup path", path)?;
        }
        Ok(())
    }
}

/// Configuration for one monitoring-data probe.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ProbeConfig {
    /// Filters applied to this probe.
    pub filters: Vec<ProbeFilterConfig>,
    /// Relative probe weight when the running kernel exposes it.
    pub weight: u32,
    /// Preparations performed before sampling when supported.
    pub preparations: Vec<ProbePreparationConfig>,
}

impl ProbeConfig {
    /// Validates this probe and all of its filters without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_count("probe filter count", self.filters.len())?;
        validate_count("probe preparation count", self.preparations.len())?;
        for filter in &self.filters {
            filter.validate()?;
        }
        for preparation in &self.preparations {
            preparation.validate()?;
        }
        Ok(())
    }
}

/// Configuration for one monitoring-probe preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ProbePreparationConfig {
    /// Preparation action.
    pub action: ProbePreparationAction,
}

impl ProbePreparationConfig {
    /// Creates a preparation with the selected action.
    #[must_use]
    pub const fn new(action: ProbePreparationAction) -> Self {
        Self { action }
    }

    /// Validates this preparation without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_token("probe preparation action", self.action.kernel_name())
    }
}

/// Operation-specific monitoring controls used by newer kernels.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OperationAttributesConfig {
    /// Consume externally supplied access reports.
    pub use_reports: bool,
    /// Avoid primitive-based reads when consuming reports.
    pub write_only: bool,
    /// Kernel cpulist syntax, or `all`.
    pub cpus: String,
    /// Kernel thread-list syntax.
    pub thread_ids: String,
}

impl Default for OperationAttributesConfig {
    fn default() -> Self {
        Self {
            use_reports: false,
            write_only: false,
            cpus: "all".to_owned(),
            thread_ids: String::new(),
        }
    }
}

impl OperationAttributesConfig {
    /// Validates the strings as atomic sysfs values.
    pub fn validate(&self) -> Result<()> {
        validate_sysfs_string("operation CPU list", &self.cpus)?;
        validate_sysfs_string("operation thread list", &self.thread_ids)
    }
}

/// Configuration for one access-sample filter.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SampleFilterConfig {
    /// Filter type.
    pub filter_type: SampleFilterType,
    /// Whether the filter matches or negates its criterion.
    pub matching: bool,
    /// Whether matching samples are allowed.
    pub allow: bool,
    /// Kernel cpumask syntax for a `cpumask` filter.
    pub cpu_mask: Option<String>,
    /// Kernel thread-list syntax for a `threads` filter.
    pub thread_ids: Option<String>,
}

impl SampleFilterConfig {
    /// Creates a sample filter without type-specific data.
    #[must_use]
    pub fn new(filter_type: SampleFilterType, matching: bool, allow: bool) -> Self {
        Self {
            filter_type,
            matching,
            allow,
            cpu_mask: None,
            thread_ids: None,
        }
    }

    /// Creates a CPU-mask sample filter.
    #[must_use]
    pub fn cpu_mask(value: impl Into<String>, matching: bool, allow: bool) -> Self {
        Self {
            cpu_mask: Some(value.into()),
            ..Self::new(SampleFilterType::CpuMask, matching, allow)
        }
    }

    /// Creates a thread-list sample filter.
    #[must_use]
    pub fn threads(value: impl Into<String>, matching: bool, allow: bool) -> Self {
        Self {
            thread_ids: Some(value.into()),
            ..Self::new(SampleFilterType::Threads, matching, allow)
        }
    }

    /// Creates a write-access sample filter.
    #[must_use]
    pub fn write(matching: bool, allow: bool) -> Self {
        Self::new(SampleFilterType::Write, matching, allow)
    }

    /// Validates this sample filter without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_token("sample filter type", self.filter_type.kernel_name())?;
        match self.filter_type {
            SampleFilterType::CpuMask => {
                validate_required_path("sample filter CPU mask", self.cpu_mask.as_deref())?;
            }
            SampleFilterType::Threads => {
                validate_required_path("sample filter thread list", self.thread_ids.as_deref())?;
            }
            _ => {}
        }
        if let Some(value) = &self.cpu_mask {
            validate_sysfs_string("sample filter CPU mask", value)?;
        }
        if let Some(value) = &self.thread_ids {
            validate_sysfs_string("sample filter thread list", value)?;
        }
        Ok(())
    }
}

/// Access-sampling primitives enabled by a newer kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SamplePrimitivesConfig {
    /// Use page-table access information.
    pub page_table: bool,
    /// Use page-fault access information.
    pub page_fault: bool,
}

impl Default for SamplePrimitivesConfig {
    fn default() -> Self {
        Self {
            page_table: true,
            page_fault: false,
        }
    }
}

/// Controls which accesses are sampled on newer kernels.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct SampleControlConfig {
    /// Enabled access-detection primitives.
    pub primitives: SamplePrimitivesConfig,
    /// Filters applied to candidate samples.
    pub filters: Vec<SampleFilterConfig>,
}

impl SampleControlConfig {
    /// Validates this control and all sample filters.
    pub fn validate(&self) -> Result<()> {
        validate_count("sample filter count", self.filters.len())?;
        for filter in &self.filters {
            filter.validate()?;
        }
        Ok(())
    }
}

/// Configuration for one DAMON monitoring target.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct TargetConfig {
    /// Process ID for virtual-address operations.
    pub pid: Option<Pid>,
    /// Whether this target should be removed during an online commit.
    pub obsolete: bool,
    /// Initial monitoring regions.
    pub initial_regions: Vec<InitialRegionConfig>,
}

impl TargetConfig {
    /// Creates a target for a process address space.
    #[must_use]
    pub fn for_pid(pid: Pid) -> Self {
        Self {
            pid: Some(pid),
            obsolete: false,
            initial_regions: Vec::new(),
        }
    }

    /// Creates a target without a process identifier.
    #[must_use]
    pub const fn address_space() -> Self {
        Self {
            pid: None,
            obsolete: false,
            initial_regions: Vec::new(),
        }
    }

    /// Validates this target without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_count("initial region count", self.initial_regions.len())?;
        let mut previous_end = None;
        for region in &self.initial_regions {
            if region.start >= region.end {
                return invalid(
                    "initial region",
                    "start must be less than the exclusive end",
                );
            }
            if previous_end.is_some_and(|end| end > region.start) {
                return invalid(
                    "initial regions",
                    "regions must be sorted and must not overlap",
                );
            }
            previous_end = Some(region.end);
        }
        Ok(())
    }
}

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

    fn validate_runnable_for(&self, operation: &Operation, target_count: usize) -> Result<()> {
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

/// Configuration for one DAMON monitoring context.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ContextConfig {
    /// Monitoring operations set.
    pub operation: Operation,
    /// Core-address scale factor.
    pub address_unit: AddressUnit,
    /// Pause state.
    pub paused: bool,
    /// Operation-specific attributes.
    pub operation_attributes: OperationAttributesConfig,
    /// Sampling, aggregation, and operations-update intervals.
    pub intervals: MonitoringIntervals,
    /// Automatic sampling-interval goal.
    pub intervals_goal: IntervalsGoalConfig,
    /// Adaptive monitoring-region bounds.
    pub region_bounds: RegionBounds,
    /// Monitoring-data probes.
    pub probes: Vec<ProbeConfig>,
    /// Access-sample controls.
    pub sample_control: SampleControlConfig,
    /// Monitoring targets.
    pub targets: Vec<TargetConfig>,
    /// DAMOS schemes.
    pub schemes: Vec<SchemeConfig>,
}

impl ContextConfig {
    /// Creates a context with kernel-style default intervals and region bounds.
    #[must_use]
    pub fn new(operation: Operation) -> Self {
        Self {
            operation,
            address_unit: AddressUnit::ONE,
            paused: false,
            operation_attributes: OperationAttributesConfig::default(),
            intervals: MonitoringIntervals::default(),
            intervals_goal: IntervalsGoalConfig::default(),
            region_bounds: RegionBounds::default(),
            probes: Vec::new(),
            sample_control: SampleControlConfig::default(),
            targets: Vec::new(),
            schemes: Vec::new(),
        }
    }

    /// Validates the complete context without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_token("monitoring operation", self.operation.kernel_name())?;
        validate_count("target count", self.targets.len())?;
        validate_count("scheme count", self.schemes.len())?;
        self.intervals_goal.validate_for(self.intervals)?;
        self.operation_attributes.validate()?;
        self.sample_control.validate()?;
        validate_count("monitoring probe count", self.probes.len())?;
        for probe in &self.probes {
            probe.validate()?;
        }
        for target in &self.targets {
            target.validate()?;
        }
        match self.operation {
            Operation::VirtualAddress | Operation::FixedVirtualAddress => {
                if self.address_unit != AddressUnit::ONE {
                    return invalid(
                        "address unit",
                        "only physical-address monitoring supports non-one units",
                    );
                }
            }
            Operation::PhysicalAddress => {
                validate_address_unit_for_host(self.address_unit)?;
            }
            Operation::Unknown(_) => {}
        }
        for scheme in &self.schemes {
            scheme.validate_for(self.targets.len())?;
        }
        Ok(())
    }

    /// Validates the operation-specific invariants required before starting
    /// this context on the running kernel's current DAMON ABI.
    pub fn validate_runnable(&self) -> Result<()> {
        self.validate()?;
        if self.probes.len() > CURRENT_MAX_PROBES {
            return invalid(
                "monitoring probe count",
                "current DAMON supports at most four probes",
            );
        }
        self.validate_weighted_probes()?;
        match self.operation {
            Operation::VirtualAddress => {
                if self.targets.is_empty() {
                    return invalid("virtual-address targets", "requires at least one target");
                }
                if self.targets.iter().any(|target| target.pid.is_none()) {
                    return invalid("virtual-address target", "requires a process identifier");
                }
            }
            Operation::FixedVirtualAddress => {
                if self.targets.is_empty() {
                    return invalid(
                        "fixed virtual-address targets",
                        "requires at least one target",
                    );
                }
                if self.targets.iter().any(|target| target.pid.is_none()) {
                    return invalid(
                        "fixed virtual-address target",
                        "requires a process identifier",
                    );
                }
                if self
                    .targets
                    .iter()
                    .any(|target| target.initial_regions.is_empty())
                {
                    return invalid(
                        "fixed virtual-address target regions",
                        "requires at least one initial region per target",
                    );
                }
            }
            Operation::PhysicalAddress => {
                if self.targets.len() != 1 {
                    return invalid(
                        "physical-address targets",
                        "requires exactly one target on current DAMON kernels",
                    );
                }
                let target = &self.targets[0];
                if target.pid.is_some() {
                    return invalid(
                        "physical-address target",
                        "must not contain a process identifier",
                    );
                }
                if target.initial_regions.is_empty() {
                    return invalid(
                        "physical-address target regions",
                        "requires at least one initial region",
                    );
                }
            }
            Operation::Unknown(_) => {
                if self.targets.is_empty() {
                    return invalid("monitoring targets", "requires at least one target");
                }
            }
        }
        for scheme in &self.schemes {
            scheme.validate_runnable_for(&self.operation, self.targets.len())?;
        }
        Ok(())
    }

    fn validate_weighted_probes(&self) -> Result<()> {
        if self.probes.iter().all(|probe| probe.weight == 0) {
            return Ok(());
        }
        let sample_us = self.intervals.sample().as_micros().max(1);
        let aggregation_us = self.intervals.aggregation().as_micros();
        let maximum_hits = (aggregation_us / sample_us).clamp(1, u128::from(u32::MAX));
        if maximum_hits > u128::from(u8::MAX) {
            return invalid(
                "weighted monitoring probes",
                "samples per aggregation interval must fit an 8-bit hit count",
            );
        }
        let mut total = 0_u32;
        let maximum_hits =
            u32::try_from(maximum_hits).map_err(|_| Error::InvalidConfiguration {
                field: "weighted monitoring probes",
                reason: "samples per aggregation interval must fit u32",
            })?;
        for probe in &self.probes {
            let weighted_hits =
                probe
                    .weight
                    .checked_mul(maximum_hits)
                    .ok_or(Error::InvalidConfiguration {
                        field: "weighted monitoring probes",
                        reason: "each weight multiplied by maximum hits must fit u32",
                    })?;
            total = total
                .checked_add(weighted_hits)
                .ok_or(Error::InvalidConfiguration {
                    field: "weighted monitoring probes",
                    reason: "sum of weighted maximum hits must fit u32",
                })?;
        }
        Ok(())
    }
}

/// Complete staged configuration of the DAMON admin hierarchy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct DamonConfig {
    /// Configured kdamond instances.
    pub kdamonds: Vec<KdamondConfig>,
}

impl DamonConfig {
    /// Validates the complete hierarchy without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_count("kdamond count", self.kdamonds.len())?;
        for kdamond in &self.kdamonds {
            kdamond.validate()?;
        }
        Ok(())
    }

    /// Validates invariants required for starting the current DAMON ABI.
    ///
    /// [`Self::validate`] intentionally permits incomplete staged hierarchies
    /// and unknown future operation values. This stricter check is used by
    /// high-level sessions that will start monitoring.
    pub fn validate_runnable(&self) -> Result<()> {
        self.validate()?;
        if self.kdamonds.is_empty() {
            return invalid("kdamond count", "requires at least one kdamond");
        }
        for kdamond in &self.kdamonds {
            if kdamond.contexts.len() != 1 {
                return invalid(
                    "kdamond context count",
                    "current DAMON requires exactly one context per running kdamond",
                );
            }
            kdamond.contexts[0].validate_runnable()?;
        }
        Ok(())
    }

    pub(crate) fn mismatch_error(&self, observed: &Self) -> Option<Error> {
        if self.equivalent_after_kernel_normalization(observed) {
            return None;
        }
        Some(
            first_damon_difference(self, observed)
                .unwrap_or_else(|| configuration_mismatch("kdamonds", self, observed)),
        )
    }

    pub(crate) fn equivalent_after_kernel_normalization(&self, observed: &Self) -> bool {
        if self == observed {
            return true;
        }
        let mut canonical = self.clone();
        for (kdamond, observed_kdamond) in canonical.kdamonds.iter_mut().zip(&observed.kdamonds) {
            for (context, observed_context) in
                kdamond.contexts.iter_mut().zip(&observed_kdamond.contexts)
            {
                for (scheme, observed_scheme) in
                    context.schemes.iter_mut().zip(&observed_context.schemes)
                {
                    scheme
                        .access_pattern
                        .normalize_kernel_width(observed_scheme.access_pattern);
                    canonicalize_filter_placements(&mut scheme.filters, &observed_scheme.filters);
                }
            }
        }
        canonical == *observed
    }
}

/// Complete staged configuration for one kdamond.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct KdamondConfig {
    /// Periodic sysfs refresh interval, or zero when disabled or unavailable.
    pub refresh_interval: Duration,
    /// Monitoring contexts.
    ///
    /// Linux 7.2 permits at most one. Staging leaves that version-specific
    /// maximum to the running kernel so a future expanded ABI is not rejected
    /// in userspace.
    pub contexts: Vec<ContextConfig>,
}

impl KdamondConfig {
    /// Validates the entire object graph without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_count("context count", self.contexts.len())?;
        exact_refresh_millis(self.refresh_interval)?;
        for context in &self.contexts {
            context.validate()?;
        }
        Ok(())
    }
}

fn configuration_mismatch(
    path: impl Into<Box<str>>,
    expected: &impl fmt::Debug,
    observed: &impl fmt::Debug,
) -> Error {
    Error::ConfigurationMismatch {
        path: path.into(),
        expected: format!("{expected:?}").into(),
        observed: format!("{observed:?}").into(),
    }
}

fn first_damon_difference(expected: &DamonConfig, observed: &DamonConfig) -> Option<Error> {
    if expected.kdamonds.len() != observed.kdamonds.len() {
        return Some(configuration_mismatch(
            "kdamonds/nr_kdamonds",
            &expected.kdamonds.len(),
            &observed.kdamonds.len(),
        ));
    }
    for (index, (expected, observed)) in
        expected.kdamonds.iter().zip(&observed.kdamonds).enumerate()
    {
        let base = format!("kdamonds/{index}");
        if expected.refresh_interval != observed.refresh_interval {
            return Some(configuration_mismatch(
                format!("{base}/refresh_ms"),
                &expected.refresh_interval,
                &observed.refresh_interval,
            ));
        }
        if expected.contexts.len() != observed.contexts.len() {
            return Some(configuration_mismatch(
                format!("{base}/contexts/nr_contexts"),
                &expected.contexts.len(),
                &observed.contexts.len(),
            ));
        }
        for (context_index, (expected, observed)) in
            expected.contexts.iter().zip(&observed.contexts).enumerate()
        {
            if expected != observed {
                return Some(first_context_difference(
                    &format!("{base}/contexts/{context_index}"),
                    expected,
                    observed,
                ));
            }
        }
    }
    None
}

fn first_context_difference(
    base: &str,
    expected: &ContextConfig,
    observed: &ContextConfig,
) -> Error {
    macro_rules! field {
        ($name:literal, $field:ident) => {
            if expected.$field != observed.$field {
                return configuration_mismatch(
                    format!("{base}/{}", $name),
                    &expected.$field,
                    &observed.$field,
                );
            }
        };
    }
    field!("operations", operation);
    field!("addr_unit", address_unit);
    field!("pause", paused);
    field!("operations_attrs", operation_attributes);
    field!("monitoring_attrs/intervals", intervals);
    field!("monitoring_attrs/intervals/intervals_goal", intervals_goal);
    field!("monitoring_attrs/nr_regions", region_bounds);
    field!("monitoring_attrs/sample", sample_control);
    if expected.probes.len() != observed.probes.len() {
        return configuration_mismatch(
            format!("{base}/monitoring_attrs/probes/nr_probes"),
            &expected.probes.len(),
            &observed.probes.len(),
        );
    }
    for (index, (expected, observed)) in expected.probes.iter().zip(&observed.probes).enumerate() {
        if expected != observed {
            return configuration_mismatch(
                format!("{base}/monitoring_attrs/probes/{index}"),
                expected,
                observed,
            );
        }
    }
    if expected.targets.len() != observed.targets.len() {
        return configuration_mismatch(
            format!("{base}/targets/nr_targets"),
            &expected.targets.len(),
            &observed.targets.len(),
        );
    }
    for (index, (expected, observed)) in expected.targets.iter().zip(&observed.targets).enumerate()
    {
        if expected != observed {
            return first_target_difference(&format!("{base}/targets/{index}"), expected, observed);
        }
    }
    if expected.schemes.len() != observed.schemes.len() {
        return configuration_mismatch(
            format!("{base}/schemes/nr_schemes"),
            &expected.schemes.len(),
            &observed.schemes.len(),
        );
    }
    for (index, (expected, observed)) in expected.schemes.iter().zip(&observed.schemes).enumerate()
    {
        if expected != observed {
            return first_scheme_difference(&format!("{base}/schemes/{index}"), expected, observed);
        }
    }
    configuration_mismatch(base.to_owned(), expected, observed)
}

fn first_target_difference(base: &str, expected: &TargetConfig, observed: &TargetConfig) -> Error {
    if expected.pid != observed.pid {
        return configuration_mismatch(format!("{base}/pid_target"), &expected.pid, &observed.pid);
    }
    if expected.obsolete != observed.obsolete {
        return configuration_mismatch(
            format!("{base}/obsolete_target"),
            &expected.obsolete,
            &observed.obsolete,
        );
    }
    configuration_mismatch(
        format!("{base}/regions"),
        &expected.initial_regions,
        &observed.initial_regions,
    )
}

fn first_scheme_difference(base: &str, expected: &SchemeConfig, observed: &SchemeConfig) -> Error {
    macro_rules! field {
        ($name:literal, $field:ident) => {
            if expected.$field != observed.$field {
                return configuration_mismatch(
                    format!("{base}/{}", $name),
                    &expected.$field,
                    &observed.$field,
                );
            }
        };
    }
    field!("action", action);
    field!("access_pattern", access_pattern);
    field!("apply_interval_us", apply_interval);
    field!("target_nid", target_node);
    field!("quotas", quota);
    field!("watermarks", watermarks);
    field!("filters", filters);
    field!("dests", destinations);
    field!("stats/max_nr_snapshots", maximum_snapshots);
    configuration_mismatch(base.to_owned(), expected, observed)
}

/// Runtime counters reported by a DAMOS scheme.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SchemeStats {
    /// Number of regions for which application was attempted.
    pub regions_tried: u64,
    /// Attempted size in DAMON core address units.
    pub size_tried_units: u64,
    /// Number of successful applications.
    pub regions_applied: u64,
    /// Successfully applied size in DAMON core address units.
    pub size_applied_units: u64,
    /// Size passed by operations-layer filters in core address units, when exposed.
    pub operations_filter_passed_units: Option<u64>,
    /// Number of quota limit exceedances.
    pub quota_exceeds: u64,
    /// Number of snapshots represented by the counters, when exposed.
    pub snapshots: Option<u64>,
    /// Configured maximum number of snapshots, when exposed.
    pub maximum_snapshots: Option<u64>,
}

/// A typed handle to one staged initial region.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialRegion {
    path: PathBuf,
}

/// A typed handle to one staged DAMOS quota directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemeQuotas {
    path: PathBuf,
}

/// A typed handle to one staged DAMOS quota goal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaGoal {
    path: PathBuf,
}

/// A typed handle to one staged DAMOS watermarks directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemeWatermarks {
    path: PathBuf,
}

/// A typed handle to one staged DAMOS filter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemeFilter {
    path: PathBuf,
}

/// A typed handle to one staged weighted migration destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationDestination {
    path: PathBuf,
}

/// A typed handle to operation-specific monitoring attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationAttributes {
    path: PathBuf,
}

/// A typed handle to one monitoring-probe preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbePreparation {
    path: PathBuf,
}

/// A typed handle to access-sample controls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleControl {
    path: PathBuf,
}

/// A typed handle to one access-sample filter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleFilter {
    path: PathBuf,
}

impl InitialRegion {
    /// Returns this initial region's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the region's inclusive start address in core address units.
    pub fn start(&self) -> Result<u64> {
        read_u64(&self.path.join("start"))
    }

    /// Writes the region's inclusive start address in core address units.
    pub fn set_start(&self, start: u64) -> Result<()> {
        write_value(&self.path.join("start"), start)
    }

    /// Reads the region's exclusive end address in core address units.
    pub fn end(&self) -> Result<u64> {
        read_u64(&self.path.join("end"))
    }

    /// Writes the region's exclusive end address in core address units.
    pub fn set_end(&self, end: u64) -> Result<()> {
        write_value(&self.path.join("end"), end)
    }

    /// Reads both boundaries as an owned configuration value.
    pub fn configuration(&self) -> Result<InitialRegionConfig> {
        Ok(InitialRegionConfig {
            start: self.start()?,
            end: self.end()?,
        })
    }

    /// Writes both region boundaries.
    pub fn stage_configuration(&self, config: InitialRegionConfig) -> Result<()> {
        InitialRegionConfig::new(config.start, config.end)?;
        self.set_start(config.start)?;
        self.set_end(config.end)
    }
}

impl OperationAttributes {
    /// Returns this attributes directory's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads whether external access reports are consumed.
    pub fn use_reports(&self) -> Result<bool> {
        read_bool(&self.path.join("use_reports"))
    }

    /// Sets whether external access reports are consumed.
    pub fn set_use_reports(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("use_reports"), value)
    }

    /// Reads whether monitoring is write-only.
    pub fn write_only(&self) -> Result<bool> {
        read_bool(&self.path.join("write_only"))
    }

    /// Sets whether monitoring is write-only.
    pub fn set_write_only(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("write_only"), value)
    }

    /// Reads the kernel CPU-list string.
    pub fn cpus(&self) -> Result<String> {
        read_sysfs_string(&self.path.join("cpus"))
    }

    /// Writes the kernel CPU-list string.
    pub fn set_cpus(&self, value: &str) -> Result<()> {
        validate_sysfs_string("operation CPU list", value)?;
        write_bytes(&self.path.join("cpus"), value.as_bytes())
    }

    /// Reads the kernel thread-list string.
    pub fn thread_ids(&self) -> Result<String> {
        read_sysfs_string(&self.path.join("tids"))
    }

    /// Writes the kernel thread-list string.
    pub fn set_thread_ids(&self, value: &str) -> Result<()> {
        validate_sysfs_string("operation thread list", value)?;
        write_bytes(&self.path.join("tids"), value.as_bytes())
    }

    /// Reads all operation-specific attributes.
    pub fn configuration(&self) -> Result<OperationAttributesConfig> {
        Ok(OperationAttributesConfig {
            use_reports: self.use_reports()?,
            write_only: self.write_only()?,
            cpus: self.cpus()?,
            thread_ids: self.thread_ids()?,
        })
    }

    fn stage_configuration(&self, config: &OperationAttributesConfig) -> Result<()> {
        self.set_use_reports(config.use_reports)?;
        self.set_write_only(config.write_only)?;
        self.set_cpus(&config.cpus)?;
        self.set_thread_ids(&config.thread_ids)
    }
}

impl ProbePreparation {
    /// Returns this preparation's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the preparation action.
    pub fn action(&self) -> Result<ProbePreparationAction> {
        read_enum(
            &self.path.join("prep_action"),
            ProbePreparationAction::parse,
        )
    }

    /// Writes the preparation action.
    pub fn set_action(&self, action: &ProbePreparationAction) -> Result<()> {
        write_enum(&self.path.join("prep_action"), action)
    }

    /// Reads this preparation into owned data.
    pub fn configuration(&self) -> Result<ProbePreparationConfig> {
        Ok(ProbePreparationConfig::new(self.action()?))
    }

    fn stage_configuration(&self, config: &ProbePreparationConfig) -> Result<()> {
        self.set_action(&config.action)
    }
}

impl SampleControl {
    /// Returns this sample-control directory's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads whether page-table sampling is enabled.
    pub fn page_table_enabled(&self) -> Result<bool> {
        read_bool(&self.path.join("primitives/page_table"))
    }

    /// Enables or disables page-table sampling.
    pub fn set_page_table_enabled(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("primitives/page_table"), value)
    }

    /// Reads whether page-fault sampling is enabled.
    pub fn page_fault_enabled(&self) -> Result<bool> {
        read_bool(&self.path.join("primitives/page_fault"))
    }

    /// Enables or disables page-fault sampling.
    pub fn set_page_fault_enabled(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("primitives/page_fault"), value)
    }

    /// Reads the number of staged sample filters.
    pub fn filter_count(&self) -> Result<usize> {
        read_usize(&self.path.join("filters/nr_filters"))
    }

    /// Reconstructs the staged sample-filter directories.
    pub fn set_filter_count(&self, count: usize) -> Result<()> {
        validate_count("sample filter count", count)?;
        write_value(&self.path.join("filters/nr_filters"), count)
    }

    /// Returns a typed handle to one sample filter.
    #[must_use]
    pub fn filter(&self, index: usize) -> SampleFilter {
        SampleFilter {
            path: self.path.join("filters").join(index.to_string()),
        }
    }

    /// Reads the complete sample-control configuration.
    pub fn configuration(&self) -> Result<SampleControlConfig> {
        Ok(SampleControlConfig {
            primitives: SamplePrimitivesConfig {
                page_table: self.page_table_enabled()?,
                page_fault: self.page_fault_enabled()?,
            },
            filters: read_indexed(self.filter_count()?, |index| {
                self.filter(index).configuration()
            })?,
        })
    }

    fn stage_configuration(&self, config: &SampleControlConfig) -> Result<()> {
        self.set_page_table_enabled(config.primitives.page_table)?;
        self.set_page_fault_enabled(config.primitives.page_fault)?;
        ensure_count(&self.path.join("filters/nr_filters"), config.filters.len())?;
        for (index, filter) in config.filters.iter().enumerate() {
            self.filter(index).stage_configuration(filter)?;
        }
        Ok(())
    }
}

impl SampleFilter {
    /// Returns this filter's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the filter type.
    pub fn filter_type(&self) -> Result<SampleFilterType> {
        read_enum(&self.path.join("type"), SampleFilterType::parse)
    }

    /// Sets the filter type.
    pub fn set_filter_type(&self, value: &SampleFilterType) -> Result<()> {
        write_enum(&self.path.join("type"), value)
    }

    /// Reads whether the filter matches its criterion.
    pub fn matching(&self) -> Result<bool> {
        read_bool(&self.path.join("matching"))
    }

    /// Sets whether the filter matches its criterion.
    pub fn set_matching(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("matching"), value)
    }

    /// Reads whether matching samples are allowed.
    pub fn allowed(&self) -> Result<bool> {
        read_bool(&self.path.join("allow"))
    }

    /// Sets whether matching samples are allowed.
    pub fn set_allowed(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("allow"), value)
    }

    /// Reads the kernel cpumask string.
    pub fn cpu_mask(&self) -> Result<String> {
        read_sysfs_string(&self.path.join("cpumask"))
    }

    /// Writes the kernel cpumask string.
    pub fn set_cpu_mask(&self, value: &str) -> Result<()> {
        validate_sysfs_string("sample filter CPU mask", value)?;
        write_bytes(&self.path.join("cpumask"), value.as_bytes())
    }

    /// Reads the kernel thread-list string.
    pub fn thread_ids(&self) -> Result<String> {
        read_sysfs_string(&self.path.join("tid_arr"))
    }

    /// Writes the kernel thread-list string.
    pub fn set_thread_ids(&self, value: &str) -> Result<()> {
        validate_sysfs_string("sample filter thread list", value)?;
        write_bytes(&self.path.join("tid_arr"), value.as_bytes())
    }

    /// Reads this sample filter into owned data.
    pub fn configuration(&self) -> Result<SampleFilterConfig> {
        let filter_type = self.filter_type()?;
        let mut config =
            SampleFilterConfig::new(filter_type.clone(), self.matching()?, self.allowed()?);
        match filter_type {
            SampleFilterType::CpuMask => config.cpu_mask = Some(self.cpu_mask()?),
            SampleFilterType::Threads => config.thread_ids = Some(self.thread_ids()?),
            SampleFilterType::Unknown(_) => {
                config.cpu_mask = optional_read(&self.path.join("cpumask"), || self.cpu_mask())?;
                config.thread_ids =
                    optional_read(&self.path.join("tid_arr"), || self.thread_ids())?;
            }
            SampleFilterType::Write => {}
        }
        Ok(config)
    }

    fn stage_configuration(&self, config: &SampleFilterConfig) -> Result<()> {
        self.set_filter_type(&config.filter_type)?;
        self.set_matching(config.matching)?;
        self.set_allowed(config.allow)?;
        if let Some(value) = &config.cpu_mask {
            self.set_cpu_mask(value)?;
        }
        if let Some(value) = &config.thread_ids {
            self.set_thread_ids(value)?;
        }
        Ok(())
    }
}

impl SchemeQuotas {
    /// Returns this quota directory's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the time quota.
    pub fn time(&self) -> Result<Duration> {
        Ok(Duration::from_millis(read_u64(&self.path.join("ms"))?))
    }

    /// Sets the time quota.
    pub fn set_time(&self, value: Duration) -> Result<()> {
        write_value(&self.path.join("ms"), exact_millis("quota time", value)?)
    }

    /// Reads the size quota in DAMON core address units.
    pub fn size_units(&self) -> Result<u64> {
        read_u64(&self.path.join("bytes"))
    }

    /// Sets the size quota in DAMON core address units.
    pub fn set_size_units(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("bytes"), value)
    }

    /// Reads the quota reset interval.
    pub fn reset_interval(&self) -> Result<Duration> {
        Ok(Duration::from_millis(read_u64(
            &self.path.join("reset_interval_ms"),
        )?))
    }

    /// Sets the quota reset interval.
    pub fn set_reset_interval(&self, value: Duration) -> Result<()> {
        write_value(
            &self.path.join("reset_interval_ms"),
            exact_millis("quota reset interval", value)?,
        )
    }

    /// Reads the effective size quota in DAMON core address units.
    pub fn effective_size_units(&self) -> Result<u64> {
        read_u64(&self.path.join("effective_bytes"))
    }

    /// Reads the quota prioritization weights.
    pub fn weights(&self) -> Result<QuotaWeights> {
        let path = self.path.join("weights");
        Ok(QuotaWeights {
            size_per_thousand: read_u32(&path.join("sz_permil"))?,
            accesses_per_thousand: read_u32(&path.join("nr_accesses_permil"))?,
            age_per_thousand: read_u32(&path.join("age_permil"))?,
        })
    }

    /// Writes the quota prioritization weights.
    pub fn set_weights(&self, weights: QuotaWeights) -> Result<()> {
        let path = self.path.join("weights");
        write_value(&path.join("sz_permil"), weights.size_per_thousand)?;
        write_value(
            &path.join("nr_accesses_permil"),
            weights.accesses_per_thousand,
        )?;
        write_value(&path.join("age_permil"), weights.age_per_thousand)
    }

    /// Reads the quota-goal tuner.
    pub fn goal_tuner(&self) -> Result<QuotaGoalTuner> {
        read_enum(&self.path.join("goal_tuner"), QuotaGoalTuner::parse)
    }

    /// Selects the quota-goal tuner.
    pub fn set_goal_tuner(&self, tuner: &QuotaGoalTuner) -> Result<()> {
        write_enum(&self.path.join("goal_tuner"), tuner)
    }

    /// Reads the failed-application charge numerator.
    pub fn failure_charge_numerator(&self) -> Result<u32> {
        read_u32(&self.path.join("fail_charge_num"))
    }

    /// Sets the failed-application charge numerator.
    pub fn set_failure_charge_numerator(&self, value: u32) -> Result<()> {
        write_value(&self.path.join("fail_charge_num"), value)
    }

    /// Reads the failed-application charge denominator.
    pub fn failure_charge_denominator(&self) -> Result<u32> {
        read_u32(&self.path.join("fail_charge_denom"))
    }

    /// Sets the failed-application charge denominator.
    pub fn set_failure_charge_denominator(&self, value: u32) -> Result<()> {
        write_value(&self.path.join("fail_charge_denom"), value)
    }

    /// Reads the number of staged quota goals.
    pub fn goal_count(&self) -> Result<usize> {
        read_usize(&self.path.join("goals/nr_goals"))
    }

    /// Reconstructs the staged quota-goal directories.
    pub fn set_goal_count(&self, count: usize) -> Result<()> {
        validate_count("quota goal count", count)?;
        write_value(&self.path.join("goals/nr_goals"), count)
    }

    /// Returns a typed handle for one staged quota goal.
    #[must_use]
    pub fn goal(&self, index: usize) -> QuotaGoal {
        QuotaGoal {
            path: self.path.join("goals").join(index.to_string()),
        }
    }

    /// Reads the owned quota configuration.
    pub fn configuration(&self) -> Result<QuotaConfig> {
        let goals_path = self.path.join("goals/nr_goals");
        let goals = if path_exists(&goals_path)? {
            let count = self.goal_count()?;
            let mut values = Vec::with_capacity(count.min(MAX_EAGER_READ_CAPACITY));
            for index in 0..count {
                values.push(self.goal(index).configuration()?);
            }
            values
        } else {
            Vec::new()
        };
        Ok(QuotaConfig {
            time: self.time()?,
            size_units: self.size_units()?,
            reset_interval: self.reset_interval()?,
            weights: self.weights()?,
            goals,
            goal_tuner: optional_read(&self.path.join("goal_tuner"), || self.goal_tuner())?
                .unwrap_or_default(),
            failure_charge_numerator: optional_read(&self.path.join("fail_charge_num"), || {
                self.failure_charge_numerator()
            })?
            .unwrap_or(0),
            failure_charge_denominator: optional_read(
                &self.path.join("fail_charge_denom"),
                || self.failure_charge_denominator(),
            )?
            .unwrap_or(0),
        })
    }

    fn stage_configuration_from(
        &self,
        config: &QuotaConfig,
        observed: Option<&QuotaConfig>,
    ) -> Result<()> {
        if observed == Some(config) {
            return Ok(());
        }
        if needs_stage(observed.map(|value| &value.time), &config.time) {
            self.set_time(config.time)?;
        }
        if needs_stage(observed.map(|value| &value.size_units), &config.size_units) {
            self.set_size_units(config.size_units)?;
        }
        if needs_stage(
            observed.map(|value| &value.reset_interval),
            &config.reset_interval,
        ) {
            self.set_reset_interval(config.reset_interval)?;
        }
        if needs_stage(observed.map(|value| &value.weights), &config.weights) {
            self.set_weights(config.weights)?;
        }
        if needs_stage(observed.map(|value| &value.goals), &config.goals) {
            let goals_path = self.path.join("goals/nr_goals");
            if path_exists(&goals_path)? {
                ensure_count(&goals_path, config.goals.len())?;
                let observed_goals = observed
                    .map(|value| value.goals.as_slice())
                    .filter(|goals| goals.len() == config.goals.len());
                for (index, goal) in config.goals.iter().enumerate() {
                    if observed_goals.is_none_or(|values| &values[index] != goal) {
                        self.goal(index).stage_configuration(goal)?;
                    }
                }
            } else if !config.goals.is_empty() {
                return Err(Error::UnsupportedFeature {
                    feature: "DAMOS quota goals",
                });
            }
        }
        if needs_stage(observed.map(|value| &value.goal_tuner), &config.goal_tuner) {
            stage_optional_default(
                &self.path.join("goal_tuner"),
                &config.goal_tuner,
                &QuotaGoalTuner::default(),
                "DAMOS quota goal tuner",
                || self.set_goal_tuner(&config.goal_tuner),
            )?;
        }
        if needs_stage(
            observed.map(|value| &value.failure_charge_numerator),
            &config.failure_charge_numerator,
        ) {
            stage_optional_default(
                &self.path.join("fail_charge_num"),
                &config.failure_charge_numerator,
                &0,
                "DAMOS failure charge ratio",
                || self.set_failure_charge_numerator(config.failure_charge_numerator),
            )?;
        }
        if needs_stage(
            observed.map(|value| &value.failure_charge_denominator),
            &config.failure_charge_denominator,
        ) {
            stage_optional_default(
                &self.path.join("fail_charge_denom"),
                &config.failure_charge_denominator,
                &0,
                "DAMOS failure charge ratio",
                || self.set_failure_charge_denominator(config.failure_charge_denominator),
            )?;
        }
        Ok(())
    }
}

impl QuotaGoal {
    /// Returns this quota goal's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the target metric.
    pub fn metric(&self) -> Result<QuotaGoalMetric> {
        read_enum(&self.path.join("target_metric"), QuotaGoalMetric::parse)
    }

    /// Sets the target metric.
    pub fn set_metric(&self, metric: &QuotaGoalMetric) -> Result<()> {
        write_enum(&self.path.join("target_metric"), metric)
    }

    /// Reads the target value in the metric's kernel-defined unit.
    pub fn target_value(&self) -> Result<u64> {
        read_u64(&self.path.join("target_value"))
    }

    /// Sets the target value in the metric's kernel-defined unit.
    pub fn set_target_value(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("target_value"), value)
    }

    /// Reads the userspace-fed current value.
    pub fn current_value(&self) -> Result<u64> {
        read_u64(&self.path.join("current_value"))
    }

    /// Sets the userspace-fed current value.
    pub fn set_current_value(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("current_value"), value)
    }

    /// Reads the NUMA node identifier.
    pub fn node_id(&self) -> Result<i32> {
        read_i32(&self.path.join("nid"))
    }

    /// Sets the NUMA node identifier.
    pub fn set_node_id(&self, value: i32) -> Result<()> {
        write_value(&self.path.join("nid"), value)
    }

    /// Reads the memory-control-group path.
    pub fn cgroup_path(&self) -> Result<String> {
        read_sysfs_string(&self.path.join("path"))
    }

    /// Sets the memory-control-group path.
    pub fn set_cgroup_path(&self, value: &str) -> Result<()> {
        validate_sysfs_string("quota goal cgroup path", value)?;
        write_bytes(&self.path.join("path"), value.as_bytes())
    }

    /// Reads this quota goal as owned data.
    pub fn configuration(&self) -> Result<QuotaGoalConfig> {
        let metric = optional_read(&self.path.join("target_metric"), || self.metric())?
            .unwrap_or(QuotaGoalMetric::UserInput);
        let node_id = if metric.requires_node() || matches!(metric, QuotaGoalMetric::Unknown(_)) {
            Some(self.node_id()?)
        } else {
            None
        };
        let cgroup_path =
            if metric.requires_cgroup_path() || matches!(metric, QuotaGoalMetric::Unknown(_)) {
                Some(self.cgroup_path()?)
            } else {
                None
            };
        Ok(QuotaGoalConfig {
            metric,
            target_value: self.target_value()?,
            current_value: self.current_value()?,
            node_id,
            cgroup_path,
        })
    }

    fn stage_configuration(&self, config: &QuotaGoalConfig) -> Result<()> {
        if path_exists(&self.path.join("target_metric"))? {
            self.set_metric(&config.metric)?;
        } else if config.metric != QuotaGoalMetric::UserInput {
            return Err(Error::UnsupportedFeature {
                feature: "DAMOS quota goal metrics",
            });
        }
        self.set_target_value(config.target_value)?;
        self.set_current_value(config.current_value)?;
        if let Some(node_id) = config.node_id {
            self.set_node_id(node_id)?;
        }
        if let Some(path) = &config.cgroup_path {
            self.set_cgroup_path(path)?;
        }
        Ok(())
    }
}

impl SchemeWatermarks {
    /// Returns this watermarks directory's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the watermark metric.
    pub fn metric(&self) -> Result<WatermarkMetric> {
        read_enum(&self.path.join("metric"), WatermarkMetric::parse)
    }

    /// Selects the watermark metric.
    pub fn set_metric(&self, metric: &WatermarkMetric) -> Result<()> {
        write_enum(&self.path.join("metric"), metric)
    }

    /// Reads the watermark check interval.
    pub fn interval(&self) -> Result<Duration> {
        Ok(Duration::from_micros(read_u64(
            &self.path.join("interval_us"),
        )?))
    }

    /// Sets the watermark check interval.
    pub fn set_interval(&self, value: Duration) -> Result<()> {
        write_value(
            &self.path.join("interval_us"),
            exact_micros("watermark interval", value)?,
        )
    }

    /// Reads the high watermark.
    pub fn high(&self) -> Result<u64> {
        read_u64(&self.path.join("high"))
    }

    /// Sets the high watermark.
    pub fn set_high(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("high"), value)
    }

    /// Reads the middle watermark.
    pub fn middle(&self) -> Result<u64> {
        read_u64(&self.path.join("mid"))
    }

    /// Sets the middle watermark.
    pub fn set_middle(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("mid"), value)
    }

    /// Reads the low watermark.
    pub fn low(&self) -> Result<u64> {
        read_u64(&self.path.join("low"))
    }

    /// Sets the low watermark.
    pub fn set_low(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("low"), value)
    }

    /// Reads all watermark settings.
    pub fn configuration(&self) -> Result<WatermarksConfig> {
        Ok(WatermarksConfig {
            metric: self.metric()?,
            interval: self.interval()?,
            high: self.high()?,
            middle: self.middle()?,
            low: self.low()?,
        })
    }

    fn stage_configuration_from(
        &self,
        config: &WatermarksConfig,
        observed: Option<&WatermarksConfig>,
    ) -> Result<()> {
        if observed == Some(config) {
            return Ok(());
        }
        if needs_stage(observed.map(|value| &value.metric), &config.metric) {
            self.set_metric(&config.metric)?;
        }
        if needs_stage(observed.map(|value| &value.interval), &config.interval) {
            self.set_interval(config.interval)?;
        }
        if needs_stage(observed.map(|value| &value.high), &config.high) {
            self.set_high(config.high)?;
        }
        if needs_stage(observed.map(|value| &value.middle), &config.middle) {
            self.set_middle(config.middle)?;
        }
        if needs_stage(observed.map(|value| &value.low), &config.low) {
            self.set_low(config.low)?;
        }
        Ok(())
    }
}

impl SchemeFilter {
    /// Returns this filter's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the filter type.
    pub fn filter_type(&self) -> Result<SchemeFilterType> {
        read_enum(&self.path.join("type"), SchemeFilterType::parse)
    }

    /// Sets the filter type.
    pub fn set_filter_type(&self, value: &SchemeFilterType) -> Result<()> {
        write_enum(&self.path.join("type"), value)
    }

    /// Reads whether the filter selects matching memory.
    pub fn matching(&self) -> Result<bool> {
        read_bool(&self.path.join("matching"))
    }

    /// Selects matching or non-matching memory.
    pub fn set_matching(&self, value: bool) -> Result<()> {
        write_bool(&self.path.join("matching"), value)
    }

    /// Reads whether selected memory is allowed through the filter.
    pub fn allowed(&self) -> Result<bool> {
        read_bool(&self.allow_path()?)
    }

    /// Sets whether selected memory is allowed through the filter.
    pub fn set_allowed(&self, value: bool) -> Result<()> {
        write_bool(&self.allow_path()?, value)
    }

    /// Reads the memory-control-group path.
    pub fn cgroup_path(&self) -> Result<String> {
        read_sysfs_string(&self.path.join("memcg_path"))
    }

    /// Sets the memory-control-group path.
    pub fn set_cgroup_path(&self, value: &str) -> Result<()> {
        validate_sysfs_string("scheme filter cgroup path", value)?;
        write_bytes(&self.path.join("memcg_path"), value.as_bytes())
    }

    /// Reads the address-filter start in core address units.
    pub fn address_start(&self) -> Result<u64> {
        read_u64(&self.path.join("addr_start"))
    }

    /// Sets the address-filter start in core address units.
    pub fn set_address_start(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("addr_start"), value)
    }

    /// Reads the address-filter end in core address units.
    pub fn address_end(&self) -> Result<u64> {
        read_u64(&self.path.join("addr_end"))
    }

    /// Sets the address-filter end in core address units.
    pub fn set_address_end(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("addr_end"), value)
    }

    /// Reads the minimum huge-page size in bytes.
    pub fn minimum_size_bytes(&self) -> Result<u64> {
        read_u64(&self.path.join("min"))
    }

    /// Sets the minimum huge-page size in bytes.
    pub fn set_minimum_size_bytes(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("min"), value)
    }

    /// Reads the maximum huge-page size in bytes.
    pub fn maximum_size_bytes(&self) -> Result<u64> {
        read_u64(&self.path.join("max"))
    }

    /// Sets the maximum huge-page size in bytes.
    pub fn set_maximum_size_bytes(&self, value: u64) -> Result<()> {
        write_value(&self.path.join("max"), value)
    }

    /// Reads the filtered DAMON target index.
    pub fn target_index(&self) -> Result<usize> {
        let path = self.path.join("damon_target_idx");
        let value = read_i32(&path)?;
        usize::try_from(value).map_err(|_| {
            super::invalid_kernel_value(&path, value.to_string(), "a non-negative target index")
        })
    }

    /// Sets the filtered DAMON target index.
    pub fn set_target_index(&self, value: usize) -> Result<()> {
        validate_count("target filter index", value)?;
        write_value(&self.path.join("damon_target_idx"), value)
    }

    /// Reads this filter as owned data.
    pub fn configuration(&self) -> Result<FilterConfig> {
        let filter_type = self.filter_type()?;
        let mut config = FilterConfig::new(filter_type.clone(), self.matching()?, self.allowed()?);
        match filter_type {
            SchemeFilterType::MemoryControlGroup => {
                config.cgroup_path = Some(self.cgroup_path()?);
            }
            SchemeFilterType::Address => {
                config.address_range = Some((self.address_start()?, self.address_end()?));
            }
            SchemeFilterType::HugePageSize => {
                config.size_range = Some(ByteSizeRange::new(
                    self.minimum_size_bytes()?,
                    self.maximum_size_bytes()?,
                )?);
            }
            SchemeFilterType::Target => {
                config.target_index = Some(self.target_index()?);
            }
            SchemeFilterType::Unknown(_) => {
                config.cgroup_path =
                    optional_read(&self.path.join("memcg_path"), || self.cgroup_path())?;
                config.address_range = optional_pair(
                    &self.path.join("addr_start"),
                    &self.path.join("addr_end"),
                    || Ok((self.address_start()?, self.address_end()?)),
                )?;
                config.size_range =
                    optional_pair(&self.path.join("min"), &self.path.join("max"), || {
                        ByteSizeRange::new(self.minimum_size_bytes()?, self.maximum_size_bytes()?)
                    })?;
                config.target_index =
                    optional_read(&self.path.join("damon_target_idx"), || self.target_index())?;
            }
            _ => {}
        }
        Ok(config)
    }

    fn stage_configuration(&self, config: &FilterConfig) -> Result<()> {
        self.set_filter_type(&config.filter_type)?;
        self.set_matching(config.matching)?;
        self.set_allowed(config.allow)?;
        if let Some(path) = &config.cgroup_path {
            self.set_cgroup_path(path)?;
        }
        if let Some((start, end)) = config.address_range {
            self.set_address_start(start)?;
            self.set_address_end(end)?;
        }
        if let Some(range) = config.size_range {
            self.set_minimum_size_bytes(range.min())?;
            self.set_maximum_size_bytes(range.max())?;
        }
        if let Some(index) = config.target_index {
            self.set_target_index(index)?;
        }
        Ok(())
    }

    fn allow_path(&self) -> Result<PathBuf> {
        for name in ["allow", "pass"] {
            let path = self.path.join(name);
            if path_exists(&path)? {
                return Ok(path);
            }
        }
        Err(Error::UnsupportedFeature {
            feature: "DAMOS filter allow control",
        })
    }
}

impl MigrationDestination {
    /// Returns this migration destination's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the NUMA node identifier.
    pub fn node_id(&self) -> Result<u32> {
        read_u32(&self.path.join("id"))
    }

    /// Sets the NUMA node identifier.
    pub fn set_node_id(&self, value: u32) -> Result<()> {
        write_value(&self.path.join("id"), value)
    }

    /// Reads the relative destination weight.
    pub fn weight(&self) -> Result<u32> {
        read_u32(&self.path.join("weight"))
    }

    /// Sets the relative destination weight.
    pub fn set_weight(&self, value: u32) -> Result<()> {
        write_value(&self.path.join("weight"), value)
    }

    /// Reads both destination attributes.
    pub fn configuration(&self) -> Result<DestinationConfig> {
        Ok(DestinationConfig {
            node_id: self.node_id()?,
            weight: self.weight()?,
        })
    }

    fn stage_configuration(&self, config: DestinationConfig) -> Result<()> {
        self.set_node_id(config.node_id)?;
        self.set_weight(config.weight)
    }
}

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

fn read_indexed<T>(count: usize, mut read: impl FnMut(usize) -> Result<T>) -> Result<Vec<T>> {
    let mut values = Vec::with_capacity(count.min(MAX_EAGER_READ_CAPACITY));
    for index in 0..count {
        values.push(read(index)?);
    }
    Ok(values)
}

fn ensure_count(path: &Path, count: usize) -> Result<()> {
    validate_count("indexed child count", count)?;
    if read_usize(path)? != count {
        write_value(path, count)?;
    }
    Ok(())
}

fn needs_stage<T: PartialEq>(observed: Option<&T>, requested: &T) -> bool {
    observed != Some(requested)
}

fn semantic_filters_match(requested: &[FilterConfig], observed: &[FilterConfig]) -> bool {
    if requested == observed {
        return true;
    }
    let mut canonical = requested.to_vec();
    canonicalize_filter_placements(&mut canonical, observed);
    canonical == observed
}

fn canonicalize_filter_placements(filters: &mut [FilterConfig], observed: &[FilterConfig]) {
    let split = observed.iter().any(|filter| {
        matches!(
            filter.placement,
            FilterPlacement::Core | FilterPlacement::Operations
        )
    });
    for filter in filters.iter_mut() {
        if filter.placement == FilterPlacement::Adaptive {
            filter.placement = if split {
                if filter.filter_type.handled_by_operations() == Some(false) {
                    FilterPlacement::Core
                } else {
                    FilterPlacement::Operations
                }
            } else {
                FilterPlacement::Unified
            };
        }
    }
    if split {
        filters.sort_by_key(|filter| match filter.placement {
            FilterPlacement::Core => 0,
            FilterPlacement::Operations => 1,
            FilterPlacement::Unified => 2,
            FilterPlacement::Adaptive => 3,
        });
    }
}

fn optional_read<T>(path: &Path, read: impl FnOnce() -> Result<T>) -> Result<Option<T>> {
    if path_exists(path)? {
        read().map(Some)
    } else {
        Ok(None)
    }
}

fn stage_optional_default<T: PartialEq>(
    path: &Path,
    requested: &T,
    neutral: &T,
    feature: &'static str,
    stage: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if path_exists(path)? {
        stage()
    } else if requested == neutral {
        Ok(())
    } else {
        Err(Error::UnsupportedFeature { feature })
    }
}

fn optional_pair<T>(
    first: &Path,
    second: &Path,
    read: impl FnOnce() -> Result<T>,
) -> Result<Option<T>> {
    if path_exists(first)? && path_exists(second)? {
        read().map(Some)
    } else {
        Ok(None)
    }
}

fn read_enum<T>(path: &Path, parse: impl FnOnce(&str) -> T) -> Result<T> {
    let value = read_text(path)?;
    Ok(parse(value.trim()))
}

fn write_enum(path: &Path, value: &impl KernelName) -> Result<()> {
    validate_token("kernel enum value", value.kernel_name())?;
    write_bytes(path, value.kernel_name().as_bytes())
}

fn read_sysfs_string(path: &Path) -> Result<String> {
    let value = read_text(path)?;
    Ok(value.strip_suffix('\n').unwrap_or(&value).to_owned())
}

pub(super) fn validate_count(field: &'static str, count: usize) -> Result<()> {
    if count > KERNEL_INDEX_MAX {
        return invalid(field, "must fit the kernel's signed count type");
    }
    Ok(())
}

pub(super) fn validate_token(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty() {
        return invalid(field, "must not be empty");
    }
    if value
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return invalid(field, "must be one non-whitespace, non-NUL kernel token");
    }
    Ok(())
}

fn validate_required_path(field: &'static str, value: Option<&str>) -> Result<()> {
    let Some(value) = value else {
        return invalid(field, "is required by the selected type");
    };
    if value.is_empty() {
        return invalid(field, "must not be empty");
    }
    validate_sysfs_string(field, value)
}

pub(super) fn validate_sysfs_string(field: &'static str, value: &str) -> Result<()> {
    if value.contains(['\n', '\r', '\0']) {
        return invalid(field, "must not contain NUL or line separators");
    }
    Ok(())
}

fn exact_micros(field: &'static str, duration: Duration) -> Result<u64> {
    let micros = u64::try_from(duration.as_micros()).map_err(|_| Error::InvalidConfiguration {
        field,
        reason: "does not fit in 64-bit microseconds",
    })?;
    if Duration::from_micros(micros) != duration {
        return invalid(field, "must be exactly representable in whole microseconds");
    }
    Ok(micros)
}

fn exact_millis(field: &'static str, duration: Duration) -> Result<u64> {
    let millis = u64::try_from(duration.as_millis()).map_err(|_| Error::InvalidConfiguration {
        field,
        reason: "does not fit in 64-bit milliseconds",
    })?;
    if Duration::from_millis(millis) != duration {
        return invalid(field, "must be exactly representable in whole milliseconds");
    }
    Ok(millis)
}

fn exact_refresh_millis(duration: Duration) -> Result<u32> {
    let millis = exact_millis("refresh interval", duration)?;
    u32::try_from(millis).map_err(|_| Error::InvalidConfiguration {
        field: "refresh interval",
        reason: "does not fit the kernel unsigned-int range",
    })
}

fn validate_address_unit_for_host(unit: AddressUnit) -> Result<()> {
    #[cfg(target_os = "linux")]
    let page_size = rustix::param::page_size() as u64;
    #[cfg(not(target_os = "linux"))]
    let page_size = 4_096_u64;

    if unit.bytes() < page_size && !unit.bytes().is_power_of_two() {
        return invalid(
            "address unit",
            "units smaller than the host page size must be a power of two",
        );
    }
    Ok(())
}

const fn invalid_const<T>(field: &'static str, reason: &'static str) -> Result<T> {
    Err(Error::InvalidConfiguration { field, reason })
}

fn invalid<T>(field: &'static str, reason: &'static str) -> Result<T> {
    invalid_const(field, reason)
}
