use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::Pid;
use crate::{Error, Result};

use super::configuration;
use super::ownership::{
    ConfigurationFingerprint, ConfigurationSnapshot, ObservedConfiguration, capture_configuration,
};
use super::sysfs_io::{
    duration_millis, invalid_kernel_value, path_exists, read_i32, read_text, read_u32, read_usize,
    write_bytes, write_value, write_value_if_present,
};
use super::{Context, DEFAULT_ADMIN_PATH, KdamondCommand, KdamondState};

/// The root of the DAMON admin sysfs hierarchy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DamonAdmin {
    pub(super) root: PathBuf,
}

impl DamonAdmin {
    /// Opens and validates a DAMON admin sysfs hierarchy.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let root = path.as_ref().to_path_buf();
        let count_path = root.join("kdamonds/nr_kdamonds");
        let exists = path_exists(&count_path)?;
        if !exists {
            return Err(Error::Unavailable { path: root });
        }

        let admin = Self { root };
        admin.kdamond_count()?;
        Ok(admin)
    }

    /// Opens the conventional Linux DAMON admin path.
    pub fn open_default() -> Result<Self> {
        Self::open(DEFAULT_ADMIN_PATH)
    }

    /// Returns the admin hierarchy root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Reads the number of staged kdamond directories.
    pub fn kdamond_count(&self) -> Result<usize> {
        read_usize(&self.root.join("kdamonds/nr_kdamonds"))
    }

    /// Reconstructs the staged kdamond directories.
    ///
    /// This is a global kernel interface. Reducing the count can remove
    /// another program's configuration; callers must coordinate ownership.
    pub fn set_kdamond_count(&self, count: usize) -> Result<()> {
        configuration::validate_count("kdamond count", count)?;
        write_value(&self.root.join("kdamonds/nr_kdamonds"), count)
    }

    /// Returns a typed handle for a staged kdamond directory.
    #[must_use]
    pub fn kdamond(&self, index: usize) -> Kdamond {
        Kdamond {
            path: self.root.join("kdamonds").join(index.to_string()),
        }
    }

    pub(crate) fn configuration_snapshot(&self) -> Result<ConfigurationSnapshot> {
        ConfigurationSnapshot::capture(&self.root)
    }

    /// Reads the known typed hierarchy and every writable configuration value.
    ///
    /// The writable values include unknown future attributes and use paths
    /// relative to this admin root.
    pub fn observed_configuration(&self) -> Result<ObservedConfiguration> {
        let snapshot = self.configuration_snapshot()?;
        let configuration = self.configuration()?;
        if !snapshot.matches_complete_current_except(&[])? {
            return Err(Error::OwnershipLost {
                reason: "the DAMON hierarchy changed while it was being observed",
            });
        }
        Ok(snapshot.into_observed(configuration))
    }
}

/// A `kdamonds/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kdamond {
    pub(super) path: PathBuf,
}

impl Kdamond {
    /// Returns this kdamond's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the kernel thread's state.
    pub fn state(&self) -> Result<KdamondState> {
        let path = self.path.join("state");
        let value = read_text(&path)?;
        value.trim().parse()
    }

    /// Sends a command to this kdamond.
    pub fn command(&self, command: &KdamondCommand) -> Result<()> {
        configuration::validate_token("kdamond command", command.kernel_name())?;
        write_bytes(&self.path.join("state"), command.kernel_name().as_bytes())
    }

    /// Reads the kernel thread ID, or `None` while the thread is stopped.
    pub fn pid(&self) -> Result<Option<Pid>> {
        let raw = read_i32(&self.path.join("pid"))?;
        if raw < 0 {
            return Ok(None);
        }
        let raw = u32::try_from(raw).map_err(|_| {
            invalid_kernel_value(
                &self.path.join("pid"),
                raw.to_string(),
                "a process ID or -1",
            )
        })?;
        Pid::new(raw).map(Some).map_err(|_| {
            invalid_kernel_value(
                &self.path.join("pid"),
                raw.to_string(),
                "a process ID or -1",
            )
        })
    }

    /// Reads the periodic sysfs refresh interval.
    pub fn refresh_interval(&self) -> Result<Duration> {
        let milliseconds = read_u32(&self.path.join("refresh_ms"))?;
        Ok(Duration::from_millis(u64::from(milliseconds)))
    }

    /// Sets the periodic sysfs refresh interval.
    ///
    /// Zero disables periodic refresh. The duration must be exactly
    /// representable in milliseconds and fit the kernel's `unsigned int`.
    pub fn set_refresh_interval(&self, interval: Duration) -> Result<()> {
        let milliseconds = duration_millis(interval)?;
        write_value(&self.path.join("refresh_ms"), milliseconds)
    }

    pub(crate) fn set_default_refresh_interval_if_present(&self) -> Result<()> {
        write_value_if_present(&self.path.join("refresh_ms"), 0_u8).map(|_| ())
    }

    /// Reads the number of staged monitoring contexts.
    pub fn context_count(&self) -> Result<usize> {
        read_usize(&self.path.join("contexts/nr_contexts"))
    }

    /// Reconstructs the staged monitoring context directories.
    pub fn set_context_count(&self, count: usize) -> Result<()> {
        configuration::validate_count("context count", count)?;
        write_value(&self.path.join("contexts/nr_contexts"), count)
    }

    /// Returns a typed handle for a staged monitoring context.
    #[must_use]
    pub fn context(&self, index: usize) -> Context {
        Context {
            path: self.path.join("contexts").join(index.to_string()),
        }
    }

    pub(crate) fn configuration_fingerprint(&self) -> Result<ConfigurationFingerprint> {
        capture_configuration(&self.path)
    }
}
