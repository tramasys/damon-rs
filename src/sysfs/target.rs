use std::path::{Path, PathBuf};

use crate::Result;
use crate::config::Pid;

use super::configuration;
use super::sysfs_io::{
    invalid_kernel_value, read_bool, read_i32, read_usize, write_bool, write_value,
};

/// A `targets/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    pub(super) path: PathBuf,
}

impl Target {
    /// Returns this target's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the selected process, or `None` for an unconfigured target.
    pub fn pid(&self) -> Result<Option<Pid>> {
        let raw = read_i32(&self.path.join("pid_target"))?;
        if raw == 0 {
            return Ok(None);
        }
        if raw < 0 {
            return Err(invalid_kernel_value(
                &self.path.join("pid_target"),
                raw.to_string(),
                "a process ID or zero",
            ));
        }
        let raw = u32::try_from(raw).map_err(|_| {
            invalid_kernel_value(
                &self.path.join("pid_target"),
                raw.to_string(),
                "a process ID",
            )
        })?;
        Pid::new(raw).map(Some).map_err(|_| {
            invalid_kernel_value(
                &self.path.join("pid_target"),
                raw.to_string(),
                "a process ID",
            )
        })
    }

    /// Selects the process monitored by virtual-address operations.
    pub fn set_pid(&self, pid: Pid) -> Result<()> {
        write_value(&self.path.join("pid_target"), pid.get())
    }

    /// Clears the process selection back to the kernel's staged default.
    pub fn clear_pid(&self) -> Result<()> {
        write_value(&self.path.join("pid_target"), 0_u8)
    }

    /// Reads whether this target is staged for removal on the next commit.
    pub fn is_obsolete(&self) -> Result<bool> {
        read_bool(&self.path.join("obsolete_target"))
    }

    /// Marks or unmarks this target for removal on the next commit.
    pub fn set_obsolete(&self, obsolete: bool) -> Result<()> {
        write_bool(&self.path.join("obsolete_target"), obsolete)
    }

    /// Reads the number of staged initial monitoring regions.
    pub fn initial_region_count(&self) -> Result<usize> {
        read_usize(&self.path.join("regions/nr_regions"))
    }

    /// Reconstructs the staged initial monitoring-region directories.
    pub fn set_initial_region_count(&self, count: usize) -> Result<()> {
        configuration::validate_count("initial region count", count)?;
        write_value(&self.path.join("regions/nr_regions"), count)
    }
}
