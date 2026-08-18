use std::io;
use std::path::{Path, PathBuf};

use crate::error::io_error;
use crate::{Error, Result};

use super::sysfs_io::{
    all_files_recursive, path_is_writable, read_configuration_value_equals, read_text, write_bytes,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConfigurationEntry {
    path: PathBuf,
    value: Box<str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConfigurationFingerprint {
    entries: Box<[ConfigurationEntry]>,
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
        for entry in &self.entries {
            if ignored.binary_search(&entry.path).is_ok() {
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
        for path in paths {
            let entry = refreshed
                .entries
                .iter_mut()
                .find(|entry| &entry.path == path)
                .ok_or(Error::OwnershipLost {
                    reason: "a controlled configuration path disappeared",
                })?;
            let value = read_text(path)?;
            entry.value = value.strip_suffix('\n').unwrap_or(&value).into();
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

    pub(crate) fn fingerprint(&self) -> ConfigurationFingerprint {
        self.fingerprint.clone()
    }

    pub(crate) fn into_fingerprint(self) -> ConfigurationFingerprint {
        self.fingerprint
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
        let mut entries = self.fingerprint.entries.iter().collect::<Vec<_>>();
        entries.sort_unstable_by(|left, right| {
            restoration_key(&self.root, left).cmp(&restoration_key(&self.root, right))
        });
        for entry in entries {
            if is_reconstruction_count(&entry.path)
                || !read_configuration_value_equals(&entry.path, entry.value.as_bytes())?
            {
                write_bytes(&entry.path, entry.value.as_bytes())?;
            }
        }
        if !self.matches_current()? {
            return Err(Error::OwnershipLost {
                reason: "the restored hierarchy does not match its captured configuration",
            });
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
        let value = read_text(&path)?;
        entries.push(ConfigurationEntry {
            value: value.strip_suffix('\n').unwrap_or(&value).into(),
            path,
        });
    }
    Ok(ConfigurationFingerprint {
        entries: entries.into_boxed_slice(),
    })
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
