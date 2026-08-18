//! High-level API tests against a filesystem fixture.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use damon::sysfs::{
    AccessCountRange, AccessPattern, Action, AgeRange, ContextConfig, DamonAdmin, DamonConfig,
    InitialRegionConfig, KdamondConfig, ProbeFilterType, RegionSizeRange,
};
use damon::{
    AddressUnit, CapabilitySupport, Damon, Error, MonitoringIntervals, Operation, Pid,
    RegionBounds, SnapshotCompleteness, SysfsFeature,
};

#[path = "high_level/low_level.rs"]
mod low_level;
#[path = "high_level/ownership.rs"]
mod ownership;
#[path = "high_level/snapshot.rs"]
mod snapshot;
#[path = "high_level/staging.rs"]
mod staging;
#[path = "high_level/support.rs"]
mod support;
#[path = "high_level/workflow.rs"]
mod workflow;

use support::Fixture;
