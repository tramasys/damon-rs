use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{Error, RawRegion, RawSnapshot, Result};

use super::configuration;
use super::sysfs_io::{
    duration_micros, numeric_directory_indices_into, path_exists, path_is_dir, read_text, read_u8,
    read_u32, read_u64, write_bytes, write_value,
};
use super::{AccessCountRange, AccessPattern, Action, AgeRange, RegionSizeRange};

const MAX_INITIAL_REGION_CAPACITY: usize = 4_096;

/// A `schemes/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scheme {
    pub(super) path: PathBuf,
}

impl Scheme {
    /// Returns this scheme's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the selected scheme action.
    pub fn action(&self) -> Result<Action> {
        let value = read_text(&self.path.join("action"))?;
        Ok(Action::parse(value.trim()))
    }

    /// Selects the scheme action.
    pub fn set_action(&self, action: &Action) -> Result<()> {
        configuration::validate_token("scheme action", action.kernel_name())?;
        write_bytes(&self.path.join("action"), action.kernel_name().as_bytes())
    }

    /// Reads this scheme's access pattern.
    pub fn access_pattern(&self) -> Result<AccessPattern> {
        let pattern = self.path.join("access_pattern");
        Ok(AccessPattern::new(
            read_region_size_range(&pattern.join("sz"))?,
            read_access_count_range(&pattern.join("nr_accesses"))?,
            read_age_range(&pattern.join("age"))?,
        ))
    }

    /// Sets this scheme's access pattern.
    pub fn set_access_pattern(&self, pattern: AccessPattern) -> Result<()> {
        let path = self.path.join("access_pattern");
        write_region_size_range(&path.join("sz"), pattern.size())?;
        write_access_count_range(&path.join("nr_accesses"), pattern.accesses())?;
        write_age_range(&path.join("age"), pattern.age())
    }

    pub(super) fn set_access_pattern_adaptive(&self, pattern: AccessPattern) -> Result<()> {
        let path = self.path.join("access_pattern");
        let size = path.join("sz");
        write_value(&size.join("min"), pattern.size().min())?;
        if pattern.size().max() == u64::MAX {
            write_kernel_ulong_max(&size.join("max"))?;
        } else {
            write_value(&size.join("max"), pattern.size().max())?;
        }
        write_access_count_range(&path.join("nr_accesses"), pattern.accesses())?;
        write_age_range(&path.join("age"), pattern.age())
    }

    /// Configures a pattern that matches every kernel-representable region.
    ///
    /// DAMON stores each maximum as the kernel's `unsigned long`. This method
    /// tries the 64-bit maximum and falls back to the 32-bit maximum only when
    /// the kernel rejects the wider value as out of range. It therefore works
    /// correctly for a 32-bit process controlling a 64-bit kernel.
    pub fn set_match_all(&self) -> Result<()> {
        let pattern = self.path.join("access_pattern");
        let size = pattern.join("sz");
        write_value(&size.join("min"), 0_u8)?;
        write_kernel_ulong_max(&size.join("max"))?;

        for name in ["nr_accesses", "age"] {
            let range = pattern.join(name);
            write_value(&range.join("min"), 0_u8)?;
            write_value(&range.join("max"), u32::MAX)?;
        }
        Ok(())
    }

    /// Reads the minimum interval between applications of this scheme.
    pub fn apply_interval(&self) -> Result<Duration> {
        Ok(Duration::from_micros(read_u64(
            &self.path.join("apply_interval_us"),
        )?))
    }

    /// Sets the minimum interval between applications of this scheme.
    ///
    /// Zero uses the context's aggregation interval. The duration must be
    /// exactly representable in whole microseconds.
    pub fn set_apply_interval(&self, interval: Duration) -> Result<()> {
        write_value(
            &self.path.join("apply_interval_us"),
            duration_micros(interval)?,
        )
    }

    /// Reads the last materialized tried-region results without inferring a
    /// byte scale from staged context attributes.
    ///
    /// Call [`crate::sysfs::Kdamond::command`] with
    /// [`crate::sysfs::KdamondCommand::UpdateSchemesTriedRegions`] first. `capacity_hint`
    /// only controls userspace allocation and does not limit results. The
    /// initial allocation is capped to avoid excessive eager allocation. When
    /// the kernel does not expose `total_bytes`, the total is computed from
    /// the validated materialized regions. Despite the sysfs filename, the
    /// reported total is a count of DAMON core address units. Convert the raw
    /// result with [`RawSnapshot::with_effective_address_unit`] only when the
    /// operation and address unit of the active committed context are known.
    pub fn tried_regions(&self, capacity_hint: usize) -> Result<RawSnapshot> {
        let base = self.path.join("tried_regions");
        let total_bytes_path = base.join("total_bytes");
        let reported_total_units = if path_exists(&total_bytes_path)? {
            Some(read_u64(&total_bytes_path)?)
        } else {
            None
        };
        let mut computed_total_units = 0_u64;
        let mut regions = Vec::with_capacity(capacity_hint.min(MAX_INITIAL_REGION_CAPACITY));
        let mut region_indices = Vec::new();
        numeric_directory_indices_into(&base, &mut region_indices)?;
        let mut probe_indices = Vec::with_capacity(4);
        let mut probe_hits = Vec::with_capacity(4);

        for index in region_indices {
            let mut path = base.join(index.to_string());
            path.push("start");
            let start = read_u64(&path)?;
            path.pop();
            path.push("end");
            let end = read_u64(&path)?;
            path.pop();
            path.push("nr_accesses");
            let nr_accesses = read_u32(&path)?;
            path.pop();
            path.push("age");
            let age = read_u32(&path)?;
            path.pop();
            path.push("sz_filter_passed");
            let filter_passed_units = if path_exists(&path)? {
                Some(read_u64(&path)?)
            } else {
                None
            };
            path.pop();
            let probes = path.join("probes");
            probe_hits.clear();
            if path_is_dir(&probes)? {
                numeric_directory_indices_into(&probes, &mut probe_indices)?;
                for probe_index in probe_indices.iter().copied() {
                    let hits = probes.join(probe_index.to_string()).join("hits");
                    if path_exists(&hits)? {
                        probe_hits.push((probe_index, read_u8(&hits)?));
                    }
                }
            }

            let region = RawRegion::from_kernel(
                start,
                end,
                nr_accesses,
                age,
                filter_passed_units,
                &probe_hits,
            )?;
            computed_total_units = computed_total_units
                .checked_add(region.len_units())
                .ok_or(Error::SnapshotSizeOverflow)?;
            regions.push(region);
        }

        Ok(RawSnapshot::from_kernel(
            regions,
            reported_total_units,
            computed_total_units,
        ))
    }

    /// Reads the last materialized total tried size in core address units.
    ///
    /// Call [`crate::sysfs::Kdamond::command`] with
    /// [`crate::sysfs::KdamondCommand::UpdateSchemesTriedBytes`] first.
    pub fn tried_bytes_units(&self) -> Result<u64> {
        read_u64(&self.path.join("tried_regions/total_bytes"))
    }
}

fn read_region_size_range(path: &Path) -> Result<RegionSizeRange> {
    RegionSizeRange::new(read_u64(&path.join("min"))?, read_u64(&path.join("max"))?)
}

fn write_region_size_range(path: &Path, range: RegionSizeRange) -> Result<()> {
    write_value(&path.join("min"), range.min())?;
    write_value(&path.join("max"), range.max())
}

fn read_access_count_range(path: &Path) -> Result<AccessCountRange> {
    AccessCountRange::new(read_u32(&path.join("min"))?, read_u32(&path.join("max"))?)
}

fn write_access_count_range(path: &Path, range: AccessCountRange) -> Result<()> {
    write_value(&path.join("min"), range.min())?;
    write_value(&path.join("max"), range.max())
}

fn read_age_range(path: &Path) -> Result<AgeRange> {
    AgeRange::new(read_u32(&path.join("min"))?, read_u32(&path.join("max"))?)
}

fn write_age_range(path: &Path, range: AgeRange) -> Result<()> {
    write_value(&path.join("min"), range.min())?;
    write_value(&path.join("max"), range.max())
}

fn write_kernel_ulong_max(path: &Path) -> Result<u64> {
    select_kernel_ulong_max(|value| write_value(path, value))
}

pub(super) fn select_kernel_ulong_max(mut write: impl FnMut(u64) -> Result<()>) -> Result<u64> {
    match write(u64::MAX) {
        Ok(()) => Ok(u64::MAX),
        Err(error) if is_kernel_ulong_width_error(&error) => {
            write(u64::from(u32::MAX))?;
            Ok(u64::from(u32::MAX))
        }
        Err(error) => Err(error),
    }
}

fn is_kernel_ulong_width_error(error: &Error) -> bool {
    const LINUX_EINVAL: i32 = 22;
    const LINUX_ERANGE: i32 = 34;

    matches!(
        error,
        Error::Io { source, .. }
            if matches!(source.raw_os_error(), Some(LINUX_EINVAL | LINUX_ERANGE))
    )
}
