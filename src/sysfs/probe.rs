use std::path::{Path, PathBuf};

use crate::Result;

use super::ProbeFilterType;
use super::configuration;
use super::sysfs_io::{read_bool, read_text, read_usize, write_bool, write_bytes, write_value};

/// A `monitoring_attrs/probes/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Probe {
    pub(super) path: PathBuf,
}

impl Probe {
    /// Returns this probe's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the number of staged probe filters.
    pub fn filter_count(&self) -> Result<usize> {
        read_usize(&self.path.join("filters/nr_filters"))
    }

    /// Reconstructs the staged probe-filter directories.
    pub fn set_filter_count(&self, count: usize) -> Result<()> {
        configuration::validate_count("probe filter count", count)?;
        write_value(&self.path.join("filters/nr_filters"), count)
    }

    /// Returns a typed handle for a staged probe filter.
    #[must_use]
    pub fn filter(&self, index: usize) -> ProbeFilter {
        ProbeFilter {
            path: self.path.join("filters").join(index.to_string()),
        }
    }
}

/// A `monitoring_attrs/probes/<N>/filters/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeFilter {
    pub(super) path: PathBuf,
}

impl ProbeFilter {
    /// Returns this probe filter's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the filter type.
    pub fn filter_type(&self) -> Result<ProbeFilterType> {
        let value = read_text(&self.path.join("type"))?;
        Ok(ProbeFilterType::parse(value.trim()))
    }

    /// Sets the filter type.
    pub fn set_filter_type(&self, filter_type: &ProbeFilterType) -> Result<()> {
        configuration::validate_token("probe filter type", filter_type.kernel_name())?;
        write_bytes(
            &self.path.join("type"),
            filter_type.kernel_name().as_bytes(),
        )
    }

    /// Reads whether the filter selects matching or non-matching pages.
    pub fn matching(&self) -> Result<bool> {
        read_bool(&self.path.join("matching"))
    }

    /// Selects matching or non-matching pages.
    pub fn set_matching(&self, matching: bool) -> Result<()> {
        write_bool(&self.path.join("matching"), matching)
    }

    /// Reads whether matching pages are allowed to contribute probe hits.
    pub fn allowed(&self) -> Result<bool> {
        read_bool(&self.path.join("allow"))
    }

    /// Sets whether matching pages may contribute probe hits.
    pub fn set_allowed(&self, allowed: bool) -> Result<()> {
        write_bool(&self.path.join("allow"), allowed)
    }

    /// Reads the memory-control-group path used by a `memcg` filter.
    pub fn cgroup_path(&self) -> Result<String> {
        let value = read_text(&self.path.join("path"))?;
        Ok(value.strip_suffix('\n').unwrap_or(&value).to_owned())
    }

    /// Sets the memory-control-group path used by a `memcg` filter.
    pub fn set_cgroup_path(&self, path: &str) -> Result<()> {
        configuration::validate_sysfs_string("probe filter cgroup path", path)?;
        write_bytes(&self.path.join("path"), path.as_bytes())
    }
}
