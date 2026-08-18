//! Owned DAMON configurations and typed nested sysfs attributes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{AddressUnit, MonitoringIntervals, Pid, RegionBounds};
use crate::{Error, Result};

use super::sysfs_io::{
    invalid_kernel_value, path_exists, read_bool, read_i32, read_text, read_u32, read_u64,
    read_usize, write_bool, write_bytes, write_value,
};
use super::{
    AccessPattern, Action, ByteSizeRange, Context, DamonAdmin, Kdamond, Operation, Probe,
    ProbeFilter, ProbeFilterType, Scheme, Target,
};

mod attributes;
mod helpers;
mod model;
mod staging;

pub use attributes::*;
pub use model::*;

use helpers::{
    canonicalize_filter_placements, ensure_count, exact_micros, exact_millis, exact_refresh_millis,
    invalid, invalid_const, minimum_region_units, needs_stage, optional_pair, optional_read,
    read_enum, read_indexed, read_sysfs_string, semantic_filters_match, stage_optional_default,
    validate_address_unit_for_host, validate_kernel_aligned_initial_regions,
    validate_required_path, validate_scaled_initial_regions, write_enum,
};
pub(super) use helpers::{validate_count, validate_sysfs_string, validate_token};
