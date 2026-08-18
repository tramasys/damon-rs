//! Shared configuration parsing and validation helpers.

use super::{
    AddressUnit, Duration, Error, FilterConfig, FilterPlacement, KERNEL_INDEX_MAX, KernelName,
    MAX_EAGER_READ_CAPACITY, Operation, Path, Result, TargetConfig, path_exists, read_text,
    read_usize, write_bytes, write_value,
};

pub(super) fn read_indexed<T>(
    count: usize,
    mut read: impl FnMut(usize) -> Result<T>,
) -> Result<Vec<T>> {
    let mut values = Vec::with_capacity(count.min(MAX_EAGER_READ_CAPACITY));
    for index in 0..count {
        values.push(read(index)?);
    }
    Ok(values)
}

pub(super) fn ensure_count(path: &Path, count: usize) -> Result<()> {
    validate_count("indexed child count", count)?;
    if read_usize(path)? != count {
        write_value(path, count)?;
    }
    Ok(())
}

pub(super) fn needs_stage<T: PartialEq>(observed: Option<&T>, requested: &T) -> bool {
    observed != Some(requested)
}

pub(super) fn semantic_filters_match(
    requested: &[FilterConfig],
    observed: &[FilterConfig],
) -> bool {
    if requested == observed {
        return true;
    }
    let mut canonical = requested.to_vec();
    canonicalize_filter_placements(&mut canonical, observed);
    canonical == observed
}

pub(super) fn canonicalize_filter_placements(
    filters: &mut [FilterConfig],
    observed: &[FilterConfig],
) {
    let split = observed.iter().any(|filter| {
        matches!(
            filter.placement,
            FilterPlacement::Core | FilterPlacement::Operations
        )
    });
    for filter in filters.iter_mut() {
        if filter.placement == FilterPlacement::Adaptive {
            filter.placement = if split {
                if filter.filter_type.handled_by_operations() == Some(false) {
                    FilterPlacement::Core
                } else {
                    FilterPlacement::Operations
                }
            } else {
                FilterPlacement::Unified
            };
        }
    }
    if split {
        filters.sort_by_key(|filter| match filter.placement {
            FilterPlacement::Core => 0,
            FilterPlacement::Operations => 1,
            FilterPlacement::Unified => 2,
            FilterPlacement::Adaptive => 3,
        });
    }
}

pub(super) fn optional_read<T>(path: &Path, read: impl FnOnce() -> Result<T>) -> Result<Option<T>> {
    if path_exists(path)? {
        read().map(Some)
    } else {
        Ok(None)
    }
}

pub(super) fn stage_optional_default<T: PartialEq>(
    path: &Path,
    requested: &T,
    neutral: &T,
    feature: &'static str,
    stage: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if path_exists(path)? {
        stage()
    } else if requested == neutral {
        Ok(())
    } else {
        Err(Error::UnsupportedFeature { feature })
    }
}

pub(super) fn optional_pair<T>(
    first: &Path,
    second: &Path,
    read: impl FnOnce() -> Result<T>,
) -> Result<Option<T>> {
    if path_exists(first)? && path_exists(second)? {
        read().map(Some)
    } else {
        Ok(None)
    }
}

pub(super) fn read_enum<T>(path: &Path, parse: impl FnOnce(&str) -> T) -> Result<T> {
    let value = read_text(path)?;
    Ok(parse(value.trim()))
}

pub(super) fn write_enum(path: &Path, value: &impl KernelName) -> Result<()> {
    validate_token("kernel enum value", value.kernel_name())?;
    write_bytes(path, value.kernel_name().as_bytes())
}

pub(super) fn read_sysfs_string(path: &Path) -> Result<String> {
    let value = read_text(path)?;
    Ok(value.strip_suffix('\n').unwrap_or(&value).to_owned())
}

pub(in crate::sysfs) fn validate_count(field: &'static str, count: usize) -> Result<()> {
    if count > KERNEL_INDEX_MAX {
        return invalid(field, "must fit the kernel's signed count type");
    }
    Ok(())
}

pub(in crate::sysfs) fn validate_token(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty() {
        return invalid(field, "must not be empty");
    }
    if value
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return invalid(field, "must be one non-whitespace, non-NUL kernel token");
    }
    Ok(())
}

pub(super) fn validate_required_path(field: &'static str, value: Option<&str>) -> Result<()> {
    let Some(value) = value else {
        return invalid(field, "is required by the selected type");
    };
    if value.is_empty() {
        return invalid(field, "must not be empty");
    }
    validate_sysfs_string(field, value)
}

pub(in crate::sysfs) fn validate_sysfs_string(field: &'static str, value: &str) -> Result<()> {
    if value.contains(['\n', '\r', '\0']) {
        return invalid(field, "must not contain NUL or line separators");
    }
    Ok(())
}

pub(super) fn exact_micros(field: &'static str, duration: Duration) -> Result<u64> {
    let micros = u64::try_from(duration.as_micros()).map_err(|_| Error::InvalidConfiguration {
        field,
        reason: "does not fit in 64-bit microseconds",
    })?;
    if Duration::from_micros(micros) != duration {
        return invalid(field, "must be exactly representable in whole microseconds");
    }
    Ok(micros)
}

pub(super) fn exact_millis(field: &'static str, duration: Duration) -> Result<u64> {
    let millis = u64::try_from(duration.as_millis()).map_err(|_| Error::InvalidConfiguration {
        field,
        reason: "does not fit in 64-bit milliseconds",
    })?;
    if Duration::from_millis(millis) != duration {
        return invalid(field, "must be exactly representable in whole milliseconds");
    }
    Ok(millis)
}

pub(super) fn exact_refresh_millis(duration: Duration) -> Result<u32> {
    let millis = exact_millis("refresh interval", duration)?;
    u32::try_from(millis).map_err(|_| Error::InvalidConfiguration {
        field: "refresh interval",
        reason: "does not fit the kernel unsigned-int range",
    })
}

pub(super) fn validate_address_unit_for_host(unit: AddressUnit) -> Result<()> {
    let page_size = host_page_size();

    if unit.bytes() < page_size && !unit.bytes().is_power_of_two() {
        return invalid(
            "address unit",
            "units smaller than the host page size must be a power of two",
        );
    }
    Ok(())
}

pub(super) fn validate_scaled_initial_regions(
    targets: &[TargetConfig],
    unit: AddressUnit,
) -> Result<()> {
    for region in targets.iter().flat_map(|target| &target.initial_regions) {
        unit.to_bytes(region.start)?;
        unit.to_bytes(region.end)?;
    }
    Ok(())
}

pub(super) fn minimum_region_units(operation: &Operation, unit: AddressUnit) -> Option<u64> {
    match operation {
        Operation::VirtualAddress | Operation::FixedVirtualAddress => Some(host_page_size()),
        Operation::PhysicalAddress => Some((host_page_size() / unit.bytes()).max(1)),
        Operation::Unknown(_) => None,
    }
}

pub(super) fn validate_kernel_aligned_initial_regions(
    targets: &[TargetConfig],
    minimum_region_units: Option<u64>,
) -> Result<()> {
    let Some(alignment) = minimum_region_units else {
        return Ok(());
    };

    for target in targets {
        let mut previous_end = None;
        for region in &target.initial_regions {
            let aligned_start = region.start - region.start % alignment;
            let remainder = region.end % alignment;
            let aligned_end = if remainder == 0 {
                region.end
            } else {
                region.end.checked_add(alignment - remainder).ok_or(
                    Error::InvalidConfiguration {
                        field: "initial region",
                        reason: "end overflows after kernel minimum-region alignment",
                    },
                )?
            };
            if previous_end.is_some_and(|end| end > aligned_start) {
                return invalid(
                    "initial regions",
                    "regions overlap after kernel minimum-region alignment",
                );
            }
            previous_end = Some(aligned_end);
        }
    }
    Ok(())
}

pub(super) fn host_page_size() -> u64 {
    #[cfg(target_os = "linux")]
    {
        rustix::param::page_size() as u64
    }
    #[cfg(not(target_os = "linux"))]
    {
        4_096_u64
    }
}

pub(super) const fn invalid_const<T>(field: &'static str, reason: &'static str) -> Result<T> {
    Err(Error::InvalidConfiguration { field, reason })
}

pub(super) fn invalid<T>(field: &'static str, reason: &'static str) -> Result<T> {
    invalid_const(field, reason)
}
