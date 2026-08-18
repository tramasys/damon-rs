//! Target, probe, and sampling configuration values.

use super::{
    AddressUnit, Pid, ProbeFilterType, ProbePreparationAction, Result, SampleFilterType, invalid,
    invalid_const, validate_count, validate_required_path, validate_sysfs_string, validate_token,
};

/// An initial target address range in DAMON core address units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InitialRegionConfig {
    /// Inclusive start address.
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
}

impl InitialRegionConfig {
    /// Creates a non-empty initial region.
    pub const fn new(start: u64, end: u64) -> Result<Self> {
        if start >= end {
            return invalid_const(
                "initial region",
                "start must be less than the exclusive end",
            );
        }
        Ok(Self { start, end })
    }

    /// Creates a region from byte boundaries that are exactly representable in `unit`.
    pub fn from_byte_range_exact(
        start_bytes: u64,
        end_bytes: u64,
        unit: AddressUnit,
    ) -> Result<Self> {
        Self::new(
            unit.units_from_bytes_exact(start_bytes)?,
            unit.units_from_bytes_exact(end_bytes)?,
        )
    }

    /// Creates the smallest core-unit region covering a non-empty byte range.
    pub fn from_byte_range_covering(
        start_bytes: u64,
        end_bytes: u64,
        unit: AddressUnit,
    ) -> Result<Self> {
        if start_bytes >= end_bytes {
            return invalid_const(
                "initial byte region",
                "start must be less than the exclusive end",
            );
        }
        Self::new(unit.floor_units(start_bytes), unit.ceil_units(end_bytes))
    }
}

/// Configuration for one monitoring-probe filter.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ProbeFilterConfig {
    /// Filter type.
    pub filter_type: ProbeFilterType,
    /// Whether the filter matches or negates its criterion.
    pub matching: bool,
    /// Whether matching pages contribute probe hits.
    pub allow: bool,
    /// Cgroup path used by a `memcg` filter.
    pub cgroup_path: Option<String>,
}

impl ProbeFilterConfig {
    /// Creates a probe filter without a cgroup path.
    #[must_use]
    pub fn new(filter_type: ProbeFilterType, matching: bool, allow: bool) -> Self {
        Self {
            filter_type,
            matching,
            allow,
            cgroup_path: None,
        }
    }

    /// Creates a memory-control-group probe filter.
    #[must_use]
    pub fn memory_control_group(path: impl Into<String>, matching: bool, allow: bool) -> Self {
        Self {
            filter_type: ProbeFilterType::MemoryControlGroup,
            matching,
            allow,
            cgroup_path: Some(path.into()),
        }
    }

    /// Validates this filter without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_token("probe filter type", self.filter_type.kernel_name())?;
        if matches!(self.filter_type, ProbeFilterType::MemoryControlGroup) {
            validate_required_path("probe filter cgroup path", self.cgroup_path.as_deref())?;
        } else if let Some(path) = &self.cgroup_path {
            validate_sysfs_string("probe filter cgroup path", path)?;
        }
        Ok(())
    }
}

/// Configuration for one monitoring-data probe.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ProbeConfig {
    /// Filters applied to this probe.
    pub filters: Vec<ProbeFilterConfig>,
    /// Relative probe weight when the running kernel exposes it.
    pub weight: u32,
    /// Preparations performed before sampling when supported.
    pub preparations: Vec<ProbePreparationConfig>,
}

impl ProbeConfig {
    /// Validates this probe and all of its filters without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_count("probe filter count", self.filters.len())?;
        validate_count("probe preparation count", self.preparations.len())?;
        for filter in &self.filters {
            filter.validate()?;
        }
        for preparation in &self.preparations {
            preparation.validate()?;
        }
        Ok(())
    }
}

/// Configuration for one monitoring-probe preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ProbePreparationConfig {
    /// Preparation action.
    pub action: ProbePreparationAction,
}

impl ProbePreparationConfig {
    /// Creates a preparation with the selected action.
    #[must_use]
    pub const fn new(action: ProbePreparationAction) -> Self {
        Self { action }
    }

    /// Validates this preparation without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_token("probe preparation action", self.action.kernel_name())
    }
}

/// Operation-specific monitoring controls used by newer kernels.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OperationAttributesConfig {
    /// Consume externally supplied access reports.
    pub use_reports: bool,
    /// Avoid primitive-based reads when consuming reports.
    pub write_only: bool,
    /// Kernel cpulist syntax, or `all`.
    pub cpus: String,
    /// Kernel thread-list syntax.
    pub thread_ids: String,
}

impl Default for OperationAttributesConfig {
    fn default() -> Self {
        Self {
            use_reports: false,
            write_only: false,
            cpus: "all".to_owned(),
            thread_ids: String::new(),
        }
    }
}

impl OperationAttributesConfig {
    /// Validates the strings as atomic sysfs values.
    pub fn validate(&self) -> Result<()> {
        validate_sysfs_string("operation CPU list", &self.cpus)?;
        validate_sysfs_string("operation thread list", &self.thread_ids)
    }
}

/// Configuration for one access-sample filter.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SampleFilterConfig {
    /// Filter type.
    pub filter_type: SampleFilterType,
    /// Whether the filter matches or negates its criterion.
    pub matching: bool,
    /// Whether matching samples are allowed.
    pub allow: bool,
    /// Kernel cpumask syntax for a `cpumask` filter.
    pub cpu_mask: Option<String>,
    /// Kernel thread-list syntax for a `threads` filter.
    pub thread_ids: Option<String>,
}

impl SampleFilterConfig {
    /// Creates a sample filter without type-specific data.
    #[must_use]
    pub fn new(filter_type: SampleFilterType, matching: bool, allow: bool) -> Self {
        Self {
            filter_type,
            matching,
            allow,
            cpu_mask: None,
            thread_ids: None,
        }
    }

    /// Creates a CPU-mask sample filter.
    #[must_use]
    pub fn cpu_mask(value: impl Into<String>, matching: bool, allow: bool) -> Self {
        Self {
            cpu_mask: Some(value.into()),
            ..Self::new(SampleFilterType::CpuMask, matching, allow)
        }
    }

    /// Creates a thread-list sample filter.
    #[must_use]
    pub fn threads(value: impl Into<String>, matching: bool, allow: bool) -> Self {
        Self {
            thread_ids: Some(value.into()),
            ..Self::new(SampleFilterType::Threads, matching, allow)
        }
    }

    /// Creates a write-access sample filter.
    #[must_use]
    pub fn write(matching: bool, allow: bool) -> Self {
        Self::new(SampleFilterType::Write, matching, allow)
    }

    /// Validates this sample filter without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_token("sample filter type", self.filter_type.kernel_name())?;
        match self.filter_type {
            SampleFilterType::CpuMask => {
                validate_required_path("sample filter CPU mask", self.cpu_mask.as_deref())?;
            }
            SampleFilterType::Threads => {
                validate_required_path("sample filter thread list", self.thread_ids.as_deref())?;
            }
            _ => {}
        }
        if let Some(value) = &self.cpu_mask {
            validate_sysfs_string("sample filter CPU mask", value)?;
        }
        if let Some(value) = &self.thread_ids {
            validate_sysfs_string("sample filter thread list", value)?;
        }
        Ok(())
    }
}

/// Access-sampling primitives enabled by a newer kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SamplePrimitivesConfig {
    /// Use page-table access information.
    pub page_table: bool,
    /// Use page-fault access information.
    pub page_fault: bool,
}

impl Default for SamplePrimitivesConfig {
    fn default() -> Self {
        Self {
            page_table: true,
            page_fault: false,
        }
    }
}

/// Controls which accesses are sampled on newer kernels.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct SampleControlConfig {
    /// Enabled access-detection primitives.
    pub primitives: SamplePrimitivesConfig,
    /// Filters applied to candidate samples.
    pub filters: Vec<SampleFilterConfig>,
}

impl SampleControlConfig {
    /// Validates the staged shape of this control and all sample filters.
    ///
    /// Operation-dependent primitive effectiveness is checked by
    /// [`crate::sysfs::ContextConfig::validate_runnable`].
    pub fn validate(&self) -> Result<()> {
        validate_count("sample filter count", self.filters.len())?;
        for filter in &self.filters {
            filter.validate()?;
        }
        Ok(())
    }
}

/// Configuration for one DAMON monitoring target.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct TargetConfig {
    /// Process ID for virtual-address operations.
    pub pid: Option<Pid>,
    /// Whether this existing target should be removed by the next online commit.
    ///
    /// High-level sessions accept this only for running updates and clear the
    /// one-shot marker by rebuilding the staged target hierarchy after commit.
    pub obsolete: bool,
    /// Initial monitoring regions.
    pub initial_regions: Vec<InitialRegionConfig>,
}

impl TargetConfig {
    /// Creates a target for a process address space.
    #[must_use]
    pub fn for_pid(pid: Pid) -> Self {
        Self {
            pid: Some(pid),
            obsolete: false,
            initial_regions: Vec::new(),
        }
    }

    /// Creates a target without a process identifier.
    #[must_use]
    pub const fn address_space() -> Self {
        Self {
            pid: None,
            obsolete: false,
            initial_regions: Vec::new(),
        }
    }

    /// Validates this target without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_count("initial region count", self.initial_regions.len())?;
        let mut previous_end = None;
        for region in &self.initial_regions {
            if region.start >= region.end {
                return invalid(
                    "initial region",
                    "start must be less than the exclusive end",
                );
            }
            if previous_end.is_some_and(|end| end > region.start) {
                return invalid(
                    "initial regions",
                    "regions must be sorted and must not overlap",
                );
            }
            previous_end = Some(region.end);
        }
        Ok(())
    }
}
