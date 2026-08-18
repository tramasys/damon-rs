//! Typed, low-level access to DAMON's admin sysfs ABI.
//!
//! This module intentionally mirrors the kernel hierarchy. Methods perform one
//! or a small fixed number of sysfs operations and do not cache kernel state.

mod configuration;

pub use configuration::{
    ContextConfig, DamonConfig, DestinationConfig, FilterConfig, FilterLayer, FilterPlacement,
    InitialRegion, InitialRegionConfig, IntervalsGoalConfig, KdamondConfig, MigrationDestination,
    OperationAttributes, OperationAttributesConfig, ProbeConfig, ProbeFilterConfig,
    ProbePreparation, ProbePreparationAction, ProbePreparationConfig, QuotaConfig, QuotaGoal,
    QuotaGoalConfig, QuotaGoalMetric, QuotaGoalTuner, QuotaWeights, SampleControl,
    SampleControlConfig, SampleFilter, SampleFilterConfig, SampleFilterType,
    SamplePrimitivesConfig, SchemeConfig, SchemeFilter, SchemeFilterType, SchemeQuotas,
    SchemeStats, SchemeWatermarks, TargetConfig, WatermarkMetric, WatermarksConfig,
};

/// Default location of DAMON's privileged admin interface.
pub const DEFAULT_ADMIN_PATH: &str = "/sys/kernel/mm/damon/admin";

mod abi;
mod admin;
mod capabilities;
mod context;
mod ownership;
mod probe;
mod scheme;
#[path = "sysfs/io.rs"]
mod sysfs_io;
mod target;

pub use abi::*;
pub use admin::{DamonAdmin, Kdamond};
pub use capabilities::*;
pub use context::Context;
pub(crate) use ownership::{ConfigurationFingerprint, ConfigurationSnapshot};
pub use probe::{Probe, ProbeFilter};
pub use scheme::Scheme;
pub use target::Target;

#[cfg(test)]
use scheme::select_kernel_ulong_max;

#[cfg(test)]
#[allow(dead_code, missing_docs)]
pub(crate) mod test_backend;

#[cfg(test)]
mod tests;
