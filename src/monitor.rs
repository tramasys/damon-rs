use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::sysfs::collect_writes;
use crate::sysfs::{
    AccessCountRange, AccessPattern, Action, AgeRange, CapabilitySupport, ConfigurationFingerprint,
    ConfigurationSnapshot, ContextConfig, DamonAdmin, DamonConfig, FilterConfig,
    InitialRegionConfig, Kdamond, KdamondCommand, KdamondConfig, KdamondState,
    ObservedConfiguration, Operation, ProbeConfig, QuotaGoalConfig, RegionSizeRange, SchemeConfig,
    SchemeStats, SysfsFeature, TargetConfig, WritableConfigurationValue,
};
use crate::{
    AddressUnit, Capabilities, Error, MonitoringIntervals, Pid, RawSnapshot, RegionBounds, Result,
    ScopedSnapshot, SnapshotScope, TargetIdentity,
};

/// Conventional advisory lock used by high-level DAMON sessions.
pub const DEFAULT_SESSION_LOCK_PATH: &str = "/run/lock/damon-rs.lock";

mod hierarchy;
mod ownership;
mod persistent;
mod runtime;
mod session;
mod workflow;

pub use hierarchy::ManagedHierarchy;
pub use persistent::{AttachedHierarchy, PersistentKdamondIdentity, PersistentReceipt};
pub use runtime::{
    HierarchyReadBatch, HierarchyRuntimeBatch, ManagedKdamond, RuntimeBatch, RuntimeReadBatch,
};
pub use session::{Damon, ExclusiveSession};
pub use workflow::*;

use ownership::{
    SessionLock, StagedConfiguration, StagedOwnership, ensure_hierarchy_stopped,
    replaceable_configuration_read_error, restore_after_capability_probe, restore_configuration,
    retry_busy, running_thread_pid, stage_and_verify_configuration, stage_capability_probe,
    with_rollback,
};
use workflow::WorkflowOptions;

#[cfg(test)]
mod tests;
