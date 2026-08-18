//! Owned configuration values and their validation rules.

use super::{
    AccessPattern, Action, AddressUnit, ByteSizeRange, Duration, Error, MonitoringIntervals,
    Operation, Pid, ProbeFilterType, RegionBounds, Result, canonicalize_filter_placements,
    exact_micros, exact_millis, exact_refresh_millis, invalid, invalid_const, minimum_region_units,
    validate_address_unit_for_host, validate_count, validate_kernel_aligned_initial_regions,
    validate_required_path, validate_scaled_initial_regions, validate_sysfs_string, validate_token,
};
use std::fmt;

pub(super) const KERNEL_INDEX_MAX: usize = i32::MAX as usize;
pub(super) const MAX_EAGER_READ_CAPACITY: usize = 4_096;
const CURRENT_MAX_PROBES: usize = 4;

pub(super) trait KernelName {
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

            pub(super) fn parse(value: &str) -> Self {
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
    pub(super) fn handled_by_operations(&self) -> Option<bool> {
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
    pub(super) fn requires_node(&self) -> bool {
        matches!(
            self,
            Self::NodeMemoryUsedBasisPoints
                | Self::NodeMemoryFreeBasisPoints
                | Self::NodeMemoryControlGroupUsedBasisPoints
                | Self::NodeMemoryControlGroupFreeBasisPoints
                | Self::NodeEligibleMemoryBasisPoints
        )
    }

    pub(super) fn requires_cgroup_path(&self) -> bool {
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

    pub(super) const fn from_layer(layer: FilterLayer) -> Self {
        match layer {
            FilterLayer::Unified => Self::Unified,
            FilterLayer::Core => Self::Core,
            FilterLayer::Operations => Self::Operations,
        }
    }
}

impl FilterLayer {
    pub(super) const fn directory(self) -> &'static str {
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
    pub(super) fn values(self) -> Result<(u64, u64, u64, u64)> {
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

mod context;
mod hierarchy;
mod scheme;
mod target;

pub use context::*;
pub use hierarchy::*;
pub use scheme::*;
pub use target::*;
