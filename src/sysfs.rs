//! Typed, low-level access to DAMON's admin sysfs ABI.
//!
//! This module intentionally mirrors the kernel hierarchy. Methods perform one
//! or a small fixed number of sysfs operations and do not cache kernel state.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{MonitoringIntervals, Pid, RegionBounds};
use crate::error::io_error;
use crate::{Error, Region, Result, Snapshot};

/// Default location of DAMON's privileged admin interface.
pub const DEFAULT_ADMIN_PATH: &str = "/sys/kernel/mm/damon/admin";

const MAX_INITIAL_REGION_CAPACITY: usize = 4_096;

/// Maximum number of monitoring data probes supported by Linux 7.2.
pub const MAX_PROBES: usize = 4;

/// A DAMON monitoring operations set.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Operation {
    /// Process virtual-address monitoring (`vaddr`).
    VirtualAddress,
    /// Fixed virtual-address-range monitoring (`fvaddr`).
    FixedVirtualAddress,
    /// Physical-address monitoring (`paddr`).
    PhysicalAddress,
    /// An operation introduced by a newer kernel.
    Unknown(Box<str>),
}

impl Operation {
    /// Returns the name used by the kernel ABI.
    #[must_use]
    pub fn kernel_name(&self) -> &str {
        match self {
            Self::VirtualAddress => "vaddr",
            Self::FixedVirtualAddress => "fvaddr",
            Self::PhysicalAddress => "paddr",
            Self::Unknown(name) => name,
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "vaddr" => Self::VirtualAddress,
            "fvaddr" => Self::FixedVirtualAddress,
            "paddr" => Self::PhysicalAddress,
            other => Self::Unknown(other.into()),
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kernel_name())
    }
}

/// A command accepted by a `kdamonds/<N>/state` file in Linux 7.2.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum KdamondCommand {
    /// Start the kernel monitoring thread.
    On,
    /// Stop the kernel monitoring thread.
    Off,
    /// Apply staged input changes to a running context.
    Commit,
    /// Apply staged DAMOS quota goals.
    CommitSchemesQuotaGoals,
    /// Refresh DAMOS statistics files.
    UpdateSchemesStats,
    /// Refresh only total tried bytes.
    UpdateSchemesTriedBytes,
    /// Materialize tried-region query results.
    UpdateSchemesTriedRegions,
    /// Remove materialized tried-region query results.
    ClearSchemesTriedRegions,
    /// Refresh effective DAMOS quotas.
    UpdateSchemesEffectiveQuotas,
    /// Refresh auto-tuned monitoring intervals.
    UpdateTunedIntervals,
}

impl KdamondCommand {
    /// Returns the command string used by the kernel ABI.
    #[must_use]
    pub const fn kernel_name(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Commit => "commit",
            Self::CommitSchemesQuotaGoals => "commit_schemes_quota_goals",
            Self::UpdateSchemesStats => "update_schemes_stats",
            Self::UpdateSchemesTriedBytes => "update_schemes_tried_bytes",
            Self::UpdateSchemesTriedRegions => "update_schemes_tried_regions",
            Self::ClearSchemesTriedRegions => "clear_schemes_tried_regions",
            Self::UpdateSchemesEffectiveQuotas => "update_schemes_effective_quotas",
            Self::UpdateTunedIntervals => "update_tuned_intervals",
        }
    }
}

/// Current state reported by a kdamond.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KdamondState {
    /// The monitoring thread is running.
    On,
    /// The monitoring thread is stopped.
    Off,
    /// A state introduced by a newer kernel.
    Unknown(Box<str>),
}

/// A DAMOS action.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Action {
    /// Mark matching memory as likely to be needed.
    WillNeed,
    /// Mark matching memory as cold.
    Cold,
    /// Reclaim matching memory.
    PageOut,
    /// Advise use of huge pages.
    HugePage,
    /// Advise against use of huge pages.
    NoHugePage,
    /// Collapse matching memory into huge pages.
    Collapse,
    /// Prioritize matching memory on the LRU.
    LruPrioritize,
    /// Deprioritize matching memory on the LRU.
    LruDeprioritize,
    /// Migrate hot memory.
    MigrateHot,
    /// Migrate cold memory.
    MigrateCold,
    /// Collect statistics without modifying memory.
    Stat,
    /// An action introduced by a newer kernel.
    Unknown(Box<str>),
}

impl Action {
    /// Returns the name used by the kernel ABI.
    #[must_use]
    pub fn kernel_name(&self) -> &str {
        match self {
            Self::WillNeed => "willneed",
            Self::Cold => "cold",
            Self::PageOut => "pageout",
            Self::HugePage => "hugepage",
            Self::NoHugePage => "nohugepage",
            Self::Collapse => "collapse",
            Self::LruPrioritize => "lru_prio",
            Self::LruDeprioritize => "lru_deprio",
            Self::MigrateHot => "migrate_hot",
            Self::MigrateCold => "migrate_cold",
            Self::Stat => "stat",
            Self::Unknown(name) => name,
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "willneed" => Self::WillNeed,
            "cold" => Self::Cold,
            "pageout" => Self::PageOut,
            "hugepage" => Self::HugePage,
            "nohugepage" => Self::NoHugePage,
            "collapse" => Self::Collapse,
            "lru_prio" => Self::LruPrioritize,
            "lru_deprio" => Self::LruDeprioritize,
            "migrate_hot" => Self::MigrateHot,
            "migrate_cold" => Self::MigrateCold,
            "stat" => Self::Stat,
            other => Self::Unknown(other.into()),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kernel_name())
    }
}

/// An optional DAMON sysfs feature detected from a concrete ABI path.
///
/// Discovery is based on populated sysfs paths rather than the running kernel
/// version. Features below an indexed child, such as a probe filter, can only
/// be discovered after that child has been staged.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SysfsFeature {
    /// `contexts/<N>/avail_operations` is present.
    AvailableOperations,
    /// `kdamonds/<N>/refresh_ms` is present.
    PeriodicRefresh,
    /// `contexts/<N>/addr_unit` is present.
    AddressUnit,
    /// `contexts/<N>/pause` is present.
    ContextPause,
    /// `monitoring_attrs/probes/nr_probes` is present.
    AttributeProbeCount,
    /// `probes/<N>/filters/nr_filters` is present.
    ProbeFilterCount,
    /// `probes/<N>/filters/<N>/type` is present.
    ProbeFilterType,
    /// `probes/<N>/filters/<N>/matching` is present.
    ProbeFilterMatching,
    /// `probes/<N>/filters/<N>/allow` is present.
    ProbeFilterAllow,
    /// `probes/<N>/filters/<N>/path` is present.
    ProbeFilterPath,
    /// `schemes/<N>/apply_interval_us` is present.
    SchemeApplyInterval,
    /// `schemes/<N>/tried_regions` is present.
    TriedRegions,
    /// `schemes/<N>/tried_regions/total_bytes` is present.
    TriedRegionsTotalBytes,
}

/// Runtime capabilities discovered from individual paths in a populated
/// DAMON hierarchy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capabilities {
    operations: Box<[Operation]>,
    features: Box<[SysfsFeature]>,
}

impl Capabilities {
    /// Returns the kernel's available monitoring operations.
    #[must_use]
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    /// Returns whether an operation is available.
    #[must_use]
    pub fn supports_operation(&self, operation: &Operation) -> bool {
        self.operations
            .iter()
            .any(|candidate| candidate == operation)
    }

    /// Returns every optional feature whose concrete path was found.
    #[must_use]
    pub fn features(&self) -> &[SysfsFeature] {
        &self.features
    }

    /// Returns whether a concrete optional sysfs feature is present.
    #[must_use]
    pub fn has(&self, feature: SysfsFeature) -> bool {
        self.features.contains(&feature)
    }
}

/// A minimum and maximum value in a DAMOS access pattern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessPatternRange {
    min: u64,
    max: u64,
}

impl AccessPatternRange {
    /// Creates a validated inclusive range.
    pub const fn new(min: u64, max: u64) -> Result<Self> {
        if min > max {
            return Err(Error::InvalidConfiguration {
                field: "access pattern range",
                reason: "minimum must not exceed maximum",
            });
        }
        Ok(Self { min, max })
    }

    /// Returns the inclusive minimum.
    #[must_use]
    pub const fn min(self) -> u64 {
        self.min
    }

    /// Returns the inclusive maximum.
    #[must_use]
    pub const fn max(self) -> u64 {
        self.max
    }
}

/// A DAMOS region access pattern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessPattern {
    size: AccessPatternRange,
    accesses: AccessPatternRange,
    age: AccessPatternRange,
}

impl AccessPattern {
    /// Creates a pattern from size, access-count, and age ranges.
    #[must_use]
    pub const fn new(
        size: AccessPatternRange,
        accesses: AccessPatternRange,
        age: AccessPatternRange,
    ) -> Self {
        Self {
            size,
            accesses,
            age,
        }
    }

    /// Returns the region-size range in bytes.
    #[must_use]
    pub const fn size(self) -> AccessPatternRange {
        self.size
    }

    /// Returns the access-count range.
    #[must_use]
    pub const fn accesses(self) -> AccessPatternRange {
        self.accesses
    }

    /// Returns the age range in aggregation intervals.
    #[must_use]
    pub const fn age(self) -> AccessPatternRange {
        self.age
    }
}

/// A monitoring data-probe filter type.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProbeFilterType {
    /// Match anonymous pages.
    Anonymous,
    /// Match pages belonging to a memory control group.
    MemoryControlGroup,
    /// A filter type introduced by a newer kernel.
    Unknown(Box<str>),
}

impl ProbeFilterType {
    /// Returns the name used by the kernel ABI.
    #[must_use]
    pub fn kernel_name(&self) -> &str {
        match self {
            Self::Anonymous => "anon",
            Self::MemoryControlGroup => "memcg",
            Self::Unknown(name) => name,
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "anon" => Self::Anonymous,
            "memcg" => Self::MemoryControlGroup,
            other => Self::Unknown(other.into()),
        }
    }
}

impl fmt::Display for ProbeFilterType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kernel_name())
    }
}

/// The root of the DAMON admin sysfs hierarchy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DamonAdmin {
    root: PathBuf,
}

impl DamonAdmin {
    /// Opens and validates a DAMON admin sysfs hierarchy.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let root = path.as_ref().to_path_buf();
        let count_path = root.join("kdamonds/nr_kdamonds");
        let exists = count_path
            .try_exists()
            .map_err(|error| io_error("inspect", &count_path, error))?;
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
        write_value(&self.root.join("kdamonds/nr_kdamonds"), count)
    }

    /// Returns a typed handle for a staged kdamond directory.
    #[must_use]
    pub fn kdamond(&self, index: usize) -> Kdamond {
        Kdamond {
            path: self.root.join("kdamonds").join(index.to_string()),
        }
    }
}

/// A `kdamonds/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kdamond {
    path: PathBuf,
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
        Ok(match value.trim() {
            "on" => KdamondState::On,
            "off" => KdamondState::Off,
            other => KdamondState::Unknown(other.into()),
        })
    }

    /// Sends a command to this kdamond.
    pub fn command(&self, command: KdamondCommand) -> Result<()> {
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

    /// Reads the number of staged monitoring contexts.
    pub fn context_count(&self) -> Result<usize> {
        read_usize(&self.path.join("contexts/nr_contexts"))
    }

    /// Reconstructs the staged monitoring context directories.
    pub fn set_context_count(&self, count: usize) -> Result<()> {
        write_value(&self.path.join("contexts/nr_contexts"), count)
    }

    /// Returns a typed handle for a staged monitoring context.
    #[must_use]
    pub fn context(&self, index: usize) -> Context {
        Context {
            path: self.path.join("contexts").join(index.to_string()),
        }
    }

    /// Discovers features from individual paths in an already populated
    /// context and scheme.
    ///
    /// This follows the official `damo` strategy of inspecting concrete ABI
    /// nodes. Paths below indexed children are reported only when the caller
    /// has staged those children.
    pub fn capabilities(&self, context_index: usize, scheme_index: usize) -> Result<Capabilities> {
        let context = self.context(context_index);
        let scheme = context.scheme(scheme_index);
        let probes = context.path.join("monitoring_attrs/probes");
        let probe_filter = probes.join("0/filters/0");
        let mut features = Vec::new();

        for (feature, path) in [
            (SysfsFeature::PeriodicRefresh, self.path.join("refresh_ms")),
            (
                SysfsFeature::AvailableOperations,
                context.path.join("avail_operations"),
            ),
            (SysfsFeature::AddressUnit, context.path.join("addr_unit")),
            (SysfsFeature::ContextPause, context.path.join("pause")),
            (SysfsFeature::AttributeProbeCount, probes.join("nr_probes")),
            (
                SysfsFeature::ProbeFilterCount,
                probes.join("0/filters/nr_filters"),
            ),
            (SysfsFeature::ProbeFilterType, probe_filter.join("type")),
            (
                SysfsFeature::ProbeFilterMatching,
                probe_filter.join("matching"),
            ),
            (SysfsFeature::ProbeFilterAllow, probe_filter.join("allow")),
            (SysfsFeature::ProbeFilterPath, probe_filter.join("path")),
            (
                SysfsFeature::SchemeApplyInterval,
                scheme.path.join("apply_interval_us"),
            ),
            (
                SysfsFeature::TriedRegionsTotalBytes,
                scheme.path.join("tried_regions/total_bytes"),
            ),
        ] {
            if path_exists(&path)? {
                features.push(feature);
            }
        }
        if path_is_dir(&scheme.path.join("tried_regions"))? {
            features.push(SysfsFeature::TriedRegions);
        }
        features.sort_unstable();

        let operations = if features.contains(&SysfsFeature::AvailableOperations) {
            context.available_operations()?
        } else {
            Vec::new()
        };
        Ok(Capabilities {
            operations: operations.into_boxed_slice(),
            features: features.into_boxed_slice(),
        })
    }
}

/// A `contexts/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    path: PathBuf,
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

    /// Reads the selected monitoring operation.
    pub fn operation(&self) -> Result<Operation> {
        let value = read_text(&self.path.join("operations"))?;
        Ok(Operation::parse(value.trim()))
    }

    /// Selects a monitoring operation.
    pub fn set_operation(&self, operation: &Operation) -> Result<()> {
        write_bytes(
            &self.path.join("operations"),
            operation.kernel_name().as_bytes(),
        )
    }

    /// Reads the address-unit size in bytes.
    pub fn address_unit(&self) -> Result<u64> {
        read_u64(&self.path.join("addr_unit"))
    }

    /// Sets the address-unit size in bytes.
    pub fn set_address_unit(&self, bytes: u64) -> Result<()> {
        if bytes == 0 {
            return Err(Error::InvalidConfiguration {
                field: "address unit",
                reason: "must be greater than zero",
            });
        }
        write_value(&self.path.join("addr_unit"), bytes)
    }

    /// Reads whether monitoring is paused for this context.
    pub fn is_paused(&self) -> Result<bool> {
        read_bool(&self.path.join("pause"))
    }

    /// Pauses or resumes monitoring for this context.
    pub fn set_paused(&self, paused: bool) -> Result<()> {
        write_bool(&self.path.join("pause"), paused)
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
        RegionBounds::new(
            read_usize(&path.join("min"))?,
            read_usize(&path.join("max"))?,
        )
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
    pub fn set_probe_count(&self, count: usize) -> Result<()> {
        if count > MAX_PROBES {
            return Err(Error::InvalidConfiguration {
                field: "probe count",
                reason: "must not exceed Linux DAMON_MAX_PROBES",
            });
        }
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

/// A `targets/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    path: PathBuf,
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
}

/// A `monitoring_attrs/probes/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Probe {
    path: PathBuf,
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
    path: PathBuf,
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
        write_bytes(&self.path.join("path"), path.as_bytes())
    }
}

/// A `schemes/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scheme {
    path: PathBuf,
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
        write_bytes(&self.path.join("action"), action.kernel_name().as_bytes())
    }

    /// Reads this scheme's access pattern.
    pub fn access_pattern(&self) -> Result<AccessPattern> {
        let pattern = self.path.join("access_pattern");
        Ok(AccessPattern::new(
            read_access_pattern_range(&pattern.join("sz"))?,
            read_access_pattern_range(&pattern.join("nr_accesses"))?,
            read_access_pattern_range(&pattern.join("age"))?,
        ))
    }

    /// Sets this scheme's access pattern.
    pub fn set_access_pattern(&self, pattern: AccessPattern) -> Result<()> {
        let path = self.path.join("access_pattern");
        write_access_pattern_range(&path.join("sz"), pattern.size())?;
        write_access_pattern_range(&path.join("nr_accesses"), pattern.accesses())?;
        write_access_pattern_range(&path.join("age"), pattern.age())
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
        let kernel_max = write_kernel_ulong_max(&size.join("max"))?;

        for name in ["nr_accesses", "age"] {
            let range = pattern.join(name);
            write_value(&range.join("min"), 0_u8)?;
            write_value(&range.join("max"), kernel_max)?;
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

    /// Reads the last materialized tried-region results.
    ///
    /// Call [`Kdamond::command`] with
    /// [`KdamondCommand::UpdateSchemesTriedRegions`] first. `capacity_hint`
    /// only controls userspace allocation and does not limit results. The
    /// initial allocation is capped to avoid excessive eager allocation. When
    /// the kernel does not expose `total_bytes`, the total is computed from
    /// the validated materialized regions.
    pub fn tried_regions(&self, capacity_hint: usize) -> Result<Snapshot> {
        let base = self.path.join("tried_regions");
        let total_bytes_path = base.join("total_bytes");
        let reported_total_bytes = if path_exists(&total_bytes_path)? {
            Some(read_u64(&total_bytes_path)?)
        } else {
            None
        };
        let mut computed_total_bytes = 0_u64;
        let mut regions = Vec::with_capacity(capacity_hint.min(MAX_INITIAL_REGION_CAPACITY));

        for index in 0_usize.. {
            let mut path = base.join(index.to_string());
            path.push("start");
            if !path_exists(&path)? {
                break;
            }
            let start = read_u64(&path)?;
            path.pop();
            path.push("end");
            let end = read_u64(&path)?;
            if end < start {
                return Err(Error::InvalidRegion { start, end });
            }
            if reported_total_bytes.is_none() {
                computed_total_bytes = computed_total_bytes
                    .checked_add(end - start)
                    .ok_or(Error::SnapshotSizeOverflow)?;
            }
            path.pop();
            path.push("nr_accesses");
            let nr_accesses = read_u64(&path)?;
            path.pop();
            path.push("age");
            let age = read_u64(&path)?;
            path.pop();
            path.push("sz_filter_passed");
            let filter_passed_bytes = if path_exists(&path)? {
                Some(read_u64(&path)?)
            } else {
                None
            };

            regions.push(Region {
                start,
                end,
                nr_accesses,
                age,
                filter_passed_bytes,
            });
        }

        Ok(Snapshot {
            regions,
            total_bytes: reported_total_bytes.unwrap_or(computed_total_bytes),
        })
    }
}

fn read_access_pattern_range(path: &Path) -> Result<AccessPatternRange> {
    AccessPatternRange::new(read_u64(&path.join("min"))?, read_u64(&path.join("max"))?)
}

fn write_access_pattern_range(path: &Path, range: AccessPatternRange) -> Result<()> {
    write_value(&path.join("min"), range.min())?;
    write_value(&path.join("max"), range.max())
}

fn write_kernel_ulong_max(path: &Path) -> Result<u64> {
    select_kernel_ulong_max(|value| write_value(path, value))
}

fn select_kernel_ulong_max(mut write: impl FnMut(u64) -> Result<()>) -> Result<u64> {
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

fn path_exists(path: &Path) -> Result<bool> {
    path.try_exists()
        .map_err(|error| io_error("inspect", path, error))
}

fn path_is_dir(path: &Path) -> Result<bool> {
    match path.metadata() {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error("inspect", path, error)),
    }
}

fn read_text(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|error| io_error("read", path, error))
}

fn read_usize(path: &Path) -> Result<usize> {
    let value = read_u64(path)?;
    usize::try_from(value).map_err(|_| invalid_kernel_value(path, value.to_string(), "usize"))
}

fn read_u32(path: &Path) -> Result<u32> {
    let value = read_u64(path)?;
    u32::try_from(value).map_err(|_| invalid_kernel_value(path, value.to_string(), "u32"))
}

fn read_i32(path: &Path) -> Result<i32> {
    let value = read_text(path)?;
    let value = value.trim();
    value
        .parse()
        .map_err(|_| invalid_kernel_value(path, value, "i32"))
}

fn read_bool(path: &Path) -> Result<bool> {
    let value = read_text(path)?;
    let value = value.trim();
    match value {
        "1" | "Y" | "y" | "yes" | "true" | "on" => Ok(true),
        "0" | "N" | "n" | "no" | "false" | "off" => Ok(false),
        _ => Err(invalid_kernel_value(path, value, "a Linux boolean")),
    }
}

fn read_u64(path: &Path) -> Result<u64> {
    let mut file = File::open(path).map_err(|error| io_error("open for reading", path, error))?;
    let mut bytes = [0_u8; 64];
    let mut used = 0;

    loop {
        if used == bytes.len() {
            return Err(invalid_kernel_value(path, "<value too long>", "u64"));
        }
        let read = file
            .read(&mut bytes[used..])
            .map_err(|error| io_error("read", path, error))?;
        if read == 0 {
            break;
        }
        used += read;
    }

    let value = std::str::from_utf8(&bytes[..used])
        .map_err(|_| invalid_kernel_value(path, "<non-UTF-8 value>", "u64"))?
        .trim();
    value
        .parse()
        .map_err(|_| invalid_kernel_value(path, value, "u64"))
}

fn invalid_kernel_value(path: &Path, value: impl Into<Box<str>>, expected: &'static str) -> Error {
    Error::InvalidKernelValue {
        path: path.to_path_buf(),
        value: value.into(),
        expected,
    }
}

fn duration_micros(duration: Duration) -> Result<u64> {
    let micros = u64::try_from(duration.as_micros()).map_err(|_| Error::InvalidConfiguration {
        field: "apply interval",
        reason: "does not fit in 64-bit microseconds",
    })?;
    if Duration::from_micros(micros) != duration {
        return Err(Error::InvalidConfiguration {
            field: "apply interval",
            reason: "must be exactly representable in whole microseconds",
        });
    }
    Ok(micros)
}

fn duration_millis(duration: Duration) -> Result<u32> {
    let milliseconds =
        u32::try_from(duration.as_millis()).map_err(|_| Error::InvalidConfiguration {
            field: "refresh interval",
            reason: "does not fit in the kernel unsigned-int range",
        })?;
    if Duration::from_millis(u64::from(milliseconds)) != duration {
        return Err(Error::InvalidConfiguration {
            field: "refresh interval",
            reason: "must be exactly representable in whole milliseconds",
        });
    }
    Ok(milliseconds)
}

fn write_value(path: &Path, value: impl fmt::Display) -> Result<()> {
    write_bytes(path, value.to_string().as_bytes())
}

fn write_bool(path: &Path, value: bool) -> Result<()> {
    write_bytes(path, if value { b"Y" } else { b"N" })
}

fn write_bytes(path: &Path, value: &[u8]) -> Result<()> {
    let mut file = open_for_write(path)?;
    write_once(&mut file, path, value)
}

fn write_once(writer: &mut impl Write, path: &Path, value: &[u8]) -> Result<()> {
    let written = loop {
        match writer.write(value) {
            Ok(written) => break written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(io_error("write", path, error)),
        }
    };
    if written != value.len() {
        return Err(io_error(
            "write complete value",
            path,
            io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "short sysfs write: wrote {written} of {} bytes",
                    value.len()
                ),
            ),
        ));
    }
    Ok(())
}

fn open_for_write(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|error| io_error("open for writing", path, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_parser_preserves_new_kernel_values() {
        assert_eq!(Operation::parse("vaddr"), Operation::VirtualAddress);
        assert_eq!(
            Operation::parse("future"),
            Operation::Unknown("future".into())
        );
    }

    #[test]
    fn action_parser_preserves_new_kernel_values() {
        assert_eq!(Action::parse("stat"), Action::Stat);
        assert_eq!(
            Action::parse("future_action"),
            Action::Unknown("future_action".into())
        );
    }

    #[test]
    fn commands_match_linux_7_2_abi() {
        assert_eq!(
            KdamondCommand::UpdateSchemesTriedRegions.kernel_name(),
            "update_schemes_tried_regions"
        );
        assert_eq!(Action::LruDeprioritize.kernel_name(), "lru_deprio");
    }

    #[test]
    fn numeric_reader_rejects_oversized_input() {
        let fixture = TempFile::new(&"9".repeat(65));
        assert!(read_u64(&fixture.path).is_err());
    }

    #[test]
    fn numeric_reader_accepts_kernel_whitespace() {
        let fixture = TempFile::new("  18446744073709551615\n");
        assert_eq!(read_u64(&fixture.path).expect("read u64::MAX"), u64::MAX);
    }

    #[test]
    fn numeric_reader_reports_malformed_values() {
        let fixture = TempFile::new("not-a-number\n");
        let error = read_u64(&fixture.path).expect_err("reject malformed value");

        assert!(matches!(
            error,
            Error::InvalidKernelValue {
                value,
                expected: "u64",
                ..
            } if &*value == "not-a-number"
        ));
    }

    #[test]
    fn bool_reader_accepts_values_emitted_and_accepted_by_linux() {
        for (value, expected) in [("Y\n", true), ("N\n", false), ("1\n", true), ("0\n", false)] {
            let fixture = TempFile::new(value);
            assert_eq!(read_bool(&fixture.path).expect("read boolean"), expected);
        }
    }

    #[test]
    fn kernel_ulong_max_falls_back_after_kernel_range_error() {
        let mut attempted = Vec::new();
        let selected = select_kernel_ulong_max(|value| {
            attempted.push(value);
            if value == u64::MAX {
                return Err(io_error("write", "max", io::Error::from_raw_os_error(34)));
            }
            Ok(())
        })
        .expect("fall back to 32-bit kernel maximum");

        assert_eq!(selected, u64::from(u32::MAX));
        assert_eq!(attempted, [u64::MAX, u64::from(u32::MAX)]);
    }

    #[test]
    fn sysfs_write_is_submitted_in_one_call() {
        let mut writer = RecordingWriter::default();
        write_once(&mut writer, Path::new("state"), b"on").expect("write complete value");

        assert_eq!(writer.calls, 1);
        assert_eq!(writer.bytes, b"on");
    }

    #[test]
    fn sysfs_write_retries_interruption_before_submitting_bytes() {
        let mut writer = InterruptedWriter::default();
        write_once(&mut writer, Path::new("state"), b"off").expect("retry interruption");

        assert_eq!(writer.calls, 2);
        assert_eq!(writer.bytes, b"off");
    }

    #[test]
    fn sysfs_write_rejects_a_short_first_write() {
        let error = write_once(&mut ShortWriter, Path::new("state"), b"commit")
            .expect_err("short sysfs write must fail");

        assert!(matches!(
            error,
            Error::Io {
                operation: "write complete value",
                source,
                ..
            } if source.kind() == io::ErrorKind::WriteZero
        ));
    }

    #[derive(Default)]
    struct RecordingWriter {
        calls: usize,
        bytes: Vec<u8>,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct InterruptedWriter {
        calls: usize,
        bytes: Vec<u8>,
    }

    impl Write for InterruptedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls == 1 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct ShortWriter;

    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len().saturating_sub(1))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(contents: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);

            let path = std::env::temp_dir().join(format!(
                "damon-rs-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, contents).expect("create temporary test file");
            Self { path }
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
