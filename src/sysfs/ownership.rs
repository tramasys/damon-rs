use std::io;
use std::path::Component;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::io_error;
use crate::{Error, Result};

use super::DamonConfig;

use super::sysfs_io::{
    all_files_recursive, path_is_writable, read_configuration_value_equals, read_text, write_bytes,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConfigurationEntry {
    path: PathBuf,
    value: Box<str>,
}

/// One writable DAMON configuration value captured at a relative sysfs path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WritableConfigurationValue {
    path: PathBuf,
    value: Box<str>,
}

impl WritableConfigurationValue {
    pub(crate) fn new(path: PathBuf, value: Box<str>) -> Self {
        Self { path, value }
    }

    /// Returns the path relative to the DAMON admin root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the exact text value without the trailing sysfs newline.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// A typed hierarchy observation paired with every writable sysfs value.
///
/// [`DamonConfig`] models attributes known to this crate. `writable_values`
/// also contains unknown future attributes and can therefore identify the
/// exact observed writable hierarchy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedConfiguration {
    configuration: DamonConfig,
    writable_values: Box<[WritableConfigurationValue]>,
}

impl ObservedConfiguration {
    /// Returns the known typed configuration.
    #[must_use]
    pub const fn configuration(&self) -> &DamonConfig {
        &self.configuration
    }

    /// Returns all writable values, including unknown future attributes.
    #[must_use]
    pub const fn writable_values(&self) -> &[WritableConfigurationValue] {
        &self.writable_values
    }

    /// Splits the observation into its typed and lossless components.
    #[must_use]
    pub fn into_parts(self) -> (DamonConfig, Box<[WritableConfigurationValue]>) {
        (self.configuration, self.writable_values)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConfigurationFingerprint {
    entries: Arc<[ConfigurationEntry]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConfigurationSnapshot {
    root: PathBuf,
    fingerprint: ConfigurationFingerprint,
}

impl ConfigurationFingerprint {
    pub(crate) fn matches_current(&self) -> Result<bool> {
        self.matches_current_except(&[])
    }

    pub(crate) fn matches_current_except(&self, ignored: &[PathBuf]) -> Result<bool> {
        for entry in self.entries.iter() {
            if ignored.binary_search(&entry.path).is_ok() {
                continue;
            }
            if !read_configuration_value_equals(&entry.path, entry.value.as_bytes())? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn equals_except(&self, other: &Self, ignored: &[PathBuf]) -> bool {
        self.entries
            .iter()
            .filter(|entry| ignored.binary_search(&entry.path).is_err())
            .eq(other
                .entries
                .iter()
                .filter(|entry| ignored.binary_search(&entry.path).is_err()))
    }

    pub(crate) fn matches_current_under_except(
        &self,
        root: &Path,
        ignored: &[PathBuf],
    ) -> Result<bool> {
        let first = self
            .entries
            .partition_point(|entry| entry.path.as_path() < root);
        for entry in self.entries[first..]
            .iter()
            .take_while(|entry| entry.path.starts_with(root))
        {
            if ignored.binary_search(&entry.path).is_ok() {
                continue;
            }
            if !read_configuration_value_equals(&entry.path, entry.value.as_bytes())? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn matches_current_outside_except(
        &self,
        ignored_root: &Path,
        ignored: &[PathBuf],
    ) -> Result<bool> {
        for entry in self.entries.iter() {
            if entry.path.starts_with(ignored_root) || ignored.binary_search(&entry.path).is_ok() {
                continue;
            }
            if !read_configuration_value_equals(&entry.path, entry.value.as_bytes())? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn refreshed_paths_except(
        &self,
        paths: &[PathBuf],
        ignored: &[PathBuf],
    ) -> Result<Self> {
        let mut refreshed = self.clone();
        let entries = Arc::make_mut(&mut refreshed.entries);
        for path in paths {
            let entry = entries.iter_mut().find(|entry| &entry.path == path).ok_or(
                Error::OwnershipLost {
                    reason: "a controlled configuration path disappeared",
                },
            )?;
            entry.value = read_configuration_value(path)?;
        }
        if !refreshed.matches_current_except(ignored)? {
            return Err(Error::OwnershipLost {
                reason: "the staged writable configuration changed",
            });
        }
        Ok(refreshed)
    }
}

impl ConfigurationSnapshot {
    pub(super) fn capture(root: &Path) -> Result<Self> {
        Ok(Self {
            fingerprint: capture_configuration(root)?,
            root: root.to_path_buf(),
        })
    }

    pub(crate) fn matches_current_except(&self, ignored: &[PathBuf]) -> Result<bool> {
        self.fingerprint.matches_current_except(ignored)
    }

    pub(crate) fn matches_complete_current_except(&self, ignored: &[PathBuf]) -> Result<bool> {
        let current = capture_configuration(&self.root)?;
        Ok(self.fingerprint.equals_except(&current, ignored))
    }

    pub(crate) fn matches_current_under_except(
        &self,
        root: &Path,
        ignored: &[PathBuf],
    ) -> Result<bool> {
        self.fingerprint.matches_current_under_except(root, ignored)
    }

    pub(crate) fn matches_current_outside_except(
        &self,
        ignored_root: &Path,
        ignored: &[PathBuf],
    ) -> Result<bool> {
        self.fingerprint
            .matches_current_outside_except(ignored_root, ignored)
    }

    pub(crate) fn refreshed_paths_except(
        &self,
        paths: &[PathBuf],
        ignored: &[PathBuf],
    ) -> Result<Self> {
        Ok(Self {
            root: self.root.clone(),
            fingerprint: self.fingerprint.refreshed_paths_except(paths, ignored)?,
        })
    }

    pub(crate) fn into_observed(self, configuration: DamonConfig) -> ObservedConfiguration {
        let writable_values = self.writable_values();
        ObservedConfiguration {
            configuration,
            writable_values,
        }
    }

    pub(crate) fn writable_values(&self) -> Box<[WritableConfigurationValue]> {
        self.fingerprint
            .entries
            .iter()
            .map(|entry| WritableConfigurationValue {
                path: entry
                    .path
                    .strip_prefix(&self.root)
                    .unwrap_or(&entry.path)
                    .to_path_buf(),
                value: entry.value.clone(),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    pub(crate) fn from_writable_values(
        root: &Path,
        values: &[WritableConfigurationValue],
    ) -> Result<Self> {
        let mut entries = Vec::with_capacity(values.len().min(4_096));
        for value in values {
            if value.path.as_os_str().is_empty()
                || value.path.is_absolute()
                || value
                    .path
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(Error::InvalidReceipt {
                    reason: "contains a non-relative writable path",
                });
            }
            entries.push(ConfigurationEntry {
                path: root.join(&value.path),
                value: value.value.clone(),
            });
        }
        entries.sort_unstable_by(|left, right| left.path.cmp(&right.path));
        if entries
            .windows(2)
            .any(|entries| entries[0].path == entries[1].path)
        {
            return Err(Error::InvalidReceipt {
                reason: "contains duplicate writable paths",
            });
        }
        Ok(Self {
            root: root.to_path_buf(),
            fingerprint: ConfigurationFingerprint {
                entries: entries.into(),
            },
        })
    }

    pub(crate) fn paths_affected_by_writes(&self, writes: &[PathBuf]) -> Vec<PathBuf> {
        let mut affected = Vec::new();
        for write in writes {
            affected.push(write.clone());
            let relative = write.strip_prefix(&self.root).unwrap_or(write);
            if !is_reconstruction_count(relative) {
                continue;
            }
            let Some(parent) = write.parent() else {
                continue;
            };
            affected.extend(
                self.fingerprint
                    .entries
                    .iter()
                    .filter(|entry| entry.path.starts_with(parent))
                    .map(|entry| entry.path.clone()),
            );
        }
        affected.sort_unstable();
        affected.dedup();
        affected
    }

    pub(crate) fn matches_current(&self) -> Result<bool> {
        Ok(capture_configuration(&self.root)? == self.fingerprint)
    }

    /// Verifies captured values without rewalking the directory hierarchy.
    ///
    /// This is sufficient while the caller holds the advisory session lock
    /// and separately verifies the typed hierarchy shape.  Unknown attributes
    /// captured for rollback are still checked one by one.
    pub(crate) fn values_match_current(&self) -> Result<bool> {
        self.fingerprint.matches_current()
    }

    pub(crate) fn restore(&self) -> Result<()> {
        self.restore_except(&[])
    }

    pub(crate) fn restore_except(&self, ignored: &[PathBuf]) -> Result<()> {
        let mut entries = self.fingerprint.entries.iter().collect::<Vec<_>>();
        entries.sort_unstable_by(|left, right| {
            restoration_key(&self.root, left).cmp(&restoration_key(&self.root, right))
        });
        for entry in entries {
            if ignored.binary_search(&entry.path).is_ok() {
                continue;
            }
            if is_reconstruction_count(&entry.path)
                || !read_configuration_value_equals(&entry.path, entry.value.as_bytes())?
            {
                write_bytes(&entry.path, entry.value.as_bytes())?;
            }
        }
        if !self.matches_current_except(ignored)? {
            return Err(Error::OwnershipLost {
                reason: "the restored hierarchy does not match its captured configuration",
            });
        }
        Ok(())
    }

    pub(crate) fn restore_paths_except(
        &self,
        paths: &[PathBuf],
        ignored: &[PathBuf],
    ) -> Result<()> {
        let mut entries = self
            .fingerprint
            .entries
            .iter()
            .filter(|entry| paths.binary_search(&entry.path).is_ok())
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|left, right| {
            restoration_key(&self.root, left).cmp(&restoration_key(&self.root, right))
        });
        for entry in entries {
            if ignored.binary_search(&entry.path).is_ok() {
                continue;
            }
            if is_reconstruction_count(&entry.path)
                || !read_configuration_value_equals(&entry.path, entry.value.as_bytes())?
            {
                write_bytes(&entry.path, entry.value.as_bytes())?;
            }
        }
        for entry in self.fingerprint.entries.iter().filter(|entry| {
            paths.binary_search(&entry.path).is_ok() && ignored.binary_search(&entry.path).is_err()
        }) {
            if !read_configuration_value_equals(&entry.path, entry.value.as_bytes())? {
                return Err(Error::OwnershipLost {
                    reason: "a transaction path changed during partial rollback",
                });
            }
        }
        Ok(())
    }
}
pub(super) fn observed_attribute_paths(root: &Path) -> Result<Vec<String>> {
    let mut paths = all_files_recursive(root)?
        .into_iter()
        .filter_map(|path| {
            path.strip_prefix(root)
                .ok()
                .map(|relative| relative.to_string_lossy().into_owned())
        })
        .collect::<Vec<_>>();
    paths.sort_unstable();
    Ok(paths)
}

fn writable_configuration_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for path in all_files_recursive(root)? {
        let relative = path.strip_prefix(root).map_err(|_| {
            io_error(
                "inspect configuration path",
                &path,
                io::Error::new(io::ErrorKind::InvalidData, "path escaped kdamond root"),
            )
        })?;
        if is_runtime_attribute(relative) || !path_is_writable(&path)? {
            continue;
        }
        paths.push(path);
    }
    paths.sort_unstable();
    Ok(paths)
}

pub(super) fn capture_configuration(root: &Path) -> Result<ConfigurationFingerprint> {
    let mut entries = Vec::new();
    for path in writable_configuration_files(root)? {
        entries.push(ConfigurationEntry {
            value: read_configuration_value(&path)?,
            path,
        });
    }
    Ok(ConfigurationFingerprint {
        entries: entries.into(),
    })
}

fn read_configuration_value(path: &Path) -> Result<Box<str>> {
    let mut value = read_text(path)?;
    if value.ends_with('\n') {
        value.pop();
    }
    Ok(value.into_boxed_str())
}

fn restoration_key<'a>(root: &Path, entry: &'a ConfigurationEntry) -> (usize, bool, &'a Path) {
    let relative = entry.path.strip_prefix(root).unwrap_or(&entry.path);
    let depth = relative.components().count();
    let is_count = is_reconstruction_count(relative);
    (depth, !is_count, &entry.path)
}

fn is_reconstruction_count(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("nr_") && name != "nr_accesses_permil")
}

fn is_runtime_attribute(relative: &Path) -> bool {
    if relative
        .file_name()
        .is_some_and(|name| matches!(name.to_str(), Some("state" | "pid" | "avail_operations")))
        || relative
            .components()
            .any(|component| component.as_os_str() == "tried_regions")
        || relative.ends_with("quotas/effective_bytes")
    {
        return true;
    }

    relative
        .parent()
        .is_some_and(|parent| parent.ends_with("stats"))
        && !relative.ends_with("stats/max_nr_snapshots")
}
