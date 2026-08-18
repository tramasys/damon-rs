//! Safe, typed access to the Linux Data Access Monitor (`DAMON`).
//!
//! `damon` provides two layers:
//!
//! - [`Damon`], [`ManagedHierarchy`], [`ExclusiveSession`], and [`Monitor`]
//!   manage transactional DAMON monitoring lifecycles.
//! - [`sysfs`] exposes typed building blocks for callers that need direct
//!   control over the kernel ABI.
//!
//! # Example
//!
//! ```no_run
//! use damon::{Damon, Pid};
//!
//! # fn main() -> Result<(), damon::Error> {
//! let damon = Damon::new()?;
//! let pid = Pid::new(std::process::id())?;
//! let mut monitor = damon.monitor_pid(pid).start()?;
//!
//! for region in monitor.materialize_snapshot()?.snapshot().regions() {
//!     println!(
//!         "{:#x}-{:#x}: {} accesses",
//!         region.start_bytes()?,
//!         region.end_bytes()?,
//!         region.nr_accesses()
//!     );
//! }
//! # Ok(())
//! # }
//! ```
//!
//! The high-level API uses a cooperative advisory lock, refuses to replace a
//! running kdamond, and restores preceding stopped configurations. The kernel
//! ABI cannot enforce ownership against controllers that ignore that lock.

#![forbid(unsafe_code)]

mod config;
mod error;
mod monitor;
mod region;
pub mod sysfs;

pub use config::{AddressUnit, MonitoringIntervals, Pid, RegionBounds};
pub use error::{Error, Result};
pub use monitor::{
    AttachedHierarchy, DEFAULT_SESSION_LOCK_PATH, Damon, ExclusiveSession, FvaddrSessionBuilder,
    HierarchyReadBatch, HierarchyRuntimeBatch, ManagedHierarchy, ManagedKdamond, Monitor,
    MonitorBuilder, PaddrSessionBuilder, PersistentKdamondIdentity, PersistentReceipt,
    ProcessTarget, RuntimeBatch, RuntimeReadBatch, SnapshotOutcome, SnapshotRequest, SnapshotWait,
    VaddrSessionBuilder,
};
pub use region::{
    ProbeHit, RawRegion, RawSnapshot, Region, RegionIter, ScopedSnapshot, Snapshot,
    SnapshotCompleteness, SnapshotScope, SnapshotTiming, TargetIdentity,
};
pub use sysfs::{
    AccessCountRange, AccessPattern, Action, AgeRange, ByteSizeRange, Capabilities,
    CapabilitySupport, ContextConfig, DamonConfig, DestinationConfig, FilterConfig, FilterLayer,
    FilterPlacement, InitialRegionConfig, IntervalsGoalConfig, KdamondConfig,
    ObservedConfiguration, Operation, OperationAttributesConfig, OperationCapability, ProbeConfig,
    ProbeFilterConfig, ProbeFilterType, ProbePreparationAction, ProbePreparationConfig,
    QuotaConfig, QuotaGoalConfig, QuotaGoalMetric, QuotaGoalTuner, QuotaWeights, RegionSizeRange,
    SampleControlConfig, SampleFilterConfig, SampleFilterType, SamplePrimitivesConfig,
    SchemeConfig, SchemeFilterType, SchemeStats, SysfsFeature, TargetConfig, WatermarkMetric,
    WatermarksConfig, WritableConfigurationValue,
};
