//! Capability model and adaptive DAMON sysfs discovery.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

use super::ownership::observed_attribute_paths;
use super::sysfs_io::{
    path_exists, path_is_dir, read_text, read_usize, write_bytes, write_value,
    write_value_if_present,
};
use super::{Context, Kdamond, Operation, Scheme};

mod discovery;
mod model;

pub use model::*;

use discovery::{operation_capability, set_feature_support};
