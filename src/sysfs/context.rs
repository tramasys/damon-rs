use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::Result;
use crate::config::{AddressUnit, MonitoringIntervals, RegionBounds};

use super::configuration;
use super::sysfs_io::{
    invalid_kernel_value, path_exists, read_bool, read_text, read_u64, read_usize, write_bool,
    write_bytes, write_value,
};
use super::{Operation, Probe, Scheme, Target};

/// A `contexts/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    pub(super) path: PathBuf,
}

impl Context {
    /// Returns this context's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads all monitoring operations registered by the running kernel.
    pub fn available_operations(&self) -> Result<Vec<Operation>> {
        let value = read_text(&self.path.join("avail_operations"))?;
        Ok(value
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(Operation::parse)
            .collect())
    }

    pub(super) fn available_operations_if_present(&self) -> Result<Option<Vec<Operation>>> {
        let path = self.path.join("avail_operations");
        if path_exists(&path)? {
            self.available_operations().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Reads the selected monitoring operation.
    pub fn operation(&self) -> Result<Operation> {
        let value = read_text(&self.path.join("operations"))?;
        Ok(Operation::parse(value.trim()))
    }

    /// Selects a monitoring operation.
    pub fn set_operation(&self, operation: &Operation) -> Result<()> {
        configuration::validate_token("monitoring operation", operation.kernel_name())?;
        write_bytes(
            &self.path.join("operations"),
            operation.kernel_name().as_bytes(),
        )
    }

    /// Reads the scale factor from DAMON core address units to bytes.
    pub fn address_unit(&self) -> Result<AddressUnit> {
        let path = self.path.join("addr_unit");
        let bytes = read_u64(&path)?;
        AddressUnit::new(bytes)
            .map_err(|_| invalid_kernel_value(&path, bytes.to_string(), "a non-zero address unit"))
    }

    /// Sets the scale factor from DAMON core address units to bytes.
    pub fn set_address_unit(&self, address_unit: AddressUnit) -> Result<()> {
        write_value(&self.path.join("addr_unit"), address_unit.bytes())
    }

    /// Reads whether monitoring is paused for this context.
    pub fn is_paused(&self) -> Result<bool> {
        read_bool(&self.path.join("pause"))
    }

    /// Pauses or resumes monitoring for this context.
    pub fn set_paused(&self, paused: bool) -> Result<()> {
        write_bool(&self.path.join("pause"), paused)
    }

    pub(crate) fn pause_control_available(&self) -> Result<bool> {
        path_exists(&self.path.join("pause"))
    }

    /// Reads the monitoring intervals.
    pub fn intervals(&self) -> Result<MonitoringIntervals> {
        let path = self.path.join("monitoring_attrs/intervals");
        MonitoringIntervals::new(
            Duration::from_micros(read_u64(&path.join("sample_us"))?),
            Duration::from_micros(read_u64(&path.join("aggr_us"))?),
            Duration::from_micros(read_u64(&path.join("update_us"))?),
        )
    }

    /// Writes the monitoring intervals.
    pub fn set_intervals(&self, intervals: MonitoringIntervals) -> Result<()> {
        let path = self.path.join("monitoring_attrs/intervals");
        let (sample_us, aggregation_us, update_us) = intervals.as_micros();
        write_value(&path.join("sample_us"), sample_us)?;
        write_value(&path.join("aggr_us"), aggregation_us)?;
        write_value(&path.join("update_us"), update_us)
    }

    /// Reads the adaptive monitoring-region count bounds.
    pub fn region_bounds(&self) -> Result<RegionBounds> {
        let path = self.path.join("monitoring_attrs/nr_regions");
        RegionBounds::new(read_u64(&path.join("min"))?, read_u64(&path.join("max"))?)
    }

    /// Writes the adaptive monitoring-region count bounds.
    pub fn set_region_bounds(&self, bounds: RegionBounds) -> Result<()> {
        let path = self.path.join("monitoring_attrs/nr_regions");
        write_value(&path.join("min"), bounds.min())?;
        write_value(&path.join("max"), bounds.max())
    }

    /// Reads the number of staged monitoring data probes.
    pub fn probe_count(&self) -> Result<usize> {
        read_usize(&self.path.join("monitoring_attrs/probes/nr_probes"))
    }

    /// Reconstructs the staged monitoring data-probe directories.
    ///
    /// The running kernel validates its own supported maximum. The crate does
    /// not impose a version-specific limit that could reject a future kernel,
    /// beyond the sysfs ABI's signed count representation.
    pub fn set_probe_count(&self, count: usize) -> Result<()> {
        configuration::validate_count("monitoring probe count", count)?;
        write_value(&self.path.join("monitoring_attrs/probes/nr_probes"), count)
    }

    /// Returns a typed handle for a staged monitoring data probe.
    #[must_use]
    pub fn probe(&self, index: usize) -> Probe {
        Probe {
            path: self
                .path
                .join("monitoring_attrs/probes")
                .join(index.to_string()),
        }
    }

    /// Reads the number of staged targets.
    pub fn target_count(&self) -> Result<usize> {
        read_usize(&self.path.join("targets/nr_targets"))
    }

    /// Reconstructs the staged target directories.
    pub fn set_target_count(&self, count: usize) -> Result<()> {
        configuration::validate_count("target count", count)?;
        write_value(&self.path.join("targets/nr_targets"), count)
    }

    /// Returns a typed handle for a staged target.
    #[must_use]
    pub fn target(&self, index: usize) -> Target {
        Target {
            path: self.path.join("targets").join(index.to_string()),
        }
    }

    /// Reads the number of staged DAMOS schemes.
    pub fn scheme_count(&self) -> Result<usize> {
        read_usize(&self.path.join("schemes/nr_schemes"))
    }

    /// Reconstructs the staged DAMOS scheme directories.
    pub fn set_scheme_count(&self, count: usize) -> Result<()> {
        configuration::validate_count("scheme count", count)?;
        write_value(&self.path.join("schemes/nr_schemes"), count)
    }

    /// Returns a typed handle for a staged DAMOS scheme.
    #[must_use]
    pub fn scheme(&self, index: usize) -> Scheme {
        Scheme {
            path: self.path.join("schemes").join(index.to_string()),
        }
    }
}
