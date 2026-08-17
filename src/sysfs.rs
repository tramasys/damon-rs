//! Typed, low-level access to DAMON's admin sysfs ABI.
//!
//! This module intentionally mirrors the kernel hierarchy. Methods perform one
//! or a small fixed number of sysfs operations and do not cache kernel state.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{AddressUnit, MonitoringIntervals, Pid, RegionBounds};
use crate::error::io_error;
use crate::{Error, RawRegion, RawSnapshot, Result};

/// Default location of DAMON's privileged admin interface.
pub const DEFAULT_ADMIN_PATH: &str = "/sys/kernel/mm/damon/admin";

const MAX_INITIAL_REGION_CAPACITY: usize = 4_096;

const LINUX_7_2_AUXILIARY_CONFIG_PATHS: &[&str] = &[
    "contexts/0/monitoring_attrs/intervals/intervals_goal/access_bp",
    "contexts/0/monitoring_attrs/intervals/intervals_goal/aggrs",
    "contexts/0/monitoring_attrs/intervals/intervals_goal/min_sample_us",
    "contexts/0/monitoring_attrs/intervals/intervals_goal/max_sample_us",
    "contexts/0/schemes/0/target_nid",
    "contexts/0/schemes/0/quotas/ms",
    "contexts/0/schemes/0/quotas/bytes",
    "contexts/0/schemes/0/quotas/reset_interval_ms",
    "contexts/0/schemes/0/quotas/goal_tuner",
    "contexts/0/schemes/0/quotas/fail_charge_num",
    "contexts/0/schemes/0/quotas/fail_charge_denom",
    "contexts/0/schemes/0/quotas/weights/sz_permil",
    "contexts/0/schemes/0/quotas/weights/nr_accesses_permil",
    "contexts/0/schemes/0/quotas/weights/age_permil",
    "contexts/0/schemes/0/quotas/goals/nr_goals",
    "contexts/0/schemes/0/watermarks/metric",
    "contexts/0/schemes/0/watermarks/interval_us",
    "contexts/0/schemes/0/watermarks/high",
    "contexts/0/schemes/0/watermarks/mid",
    "contexts/0/schemes/0/watermarks/low",
    "contexts/0/schemes/0/core_filters/nr_filters",
    "contexts/0/schemes/0/ops_filters/nr_filters",
    "contexts/0/schemes/0/filters/nr_filters",
    "contexts/0/schemes/0/dests/nr_dests",
    "contexts/0/schemes/0/stats/max_nr_snapshots",
];

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
/// version. Features below an unstaged indexed child, such as a probe filter,
/// are reported through [`CapabilitySupport::RequiresStaging`].
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

/// Whether an optional sysfs feature can be observed in the current hierarchy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum CapabilitySupport {
    /// The concrete sysfs path is present.
    Supported,
    /// The concrete sysfs path is absent even though its parent is staged.
    Unsupported,
    /// An indexed parent must be staged before support can be observed.
    RequiresStaging,
}

/// The discovery result for one optional sysfs feature.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FeatureCapability {
    feature: SysfsFeature,
    support: CapabilitySupport,
}

impl FeatureCapability {
    /// Returns the optional feature being described.
    #[must_use]
    pub const fn feature(self) -> SysfsFeature {
        self.feature
    }

    /// Returns whether the feature is supported or needs more staging.
    #[must_use]
    pub const fn support(self) -> CapabilitySupport {
        self.support
    }
}

/// Runtime capabilities discovered from individual DAMON sysfs paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capabilities {
    operations: Box<[Operation]>,
    features: Box<[FeatureCapability]>,
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

    /// Returns the discovery result for every known optional feature.
    #[must_use]
    pub fn features(&self) -> &[FeatureCapability] {
        &self.features
    }

    /// Returns the discovery state of an optional sysfs feature.
    #[must_use]
    pub fn feature_support(&self, feature: SysfsFeature) -> CapabilitySupport {
        self.features
            .iter()
            .find(|capability| capability.feature == feature)
            .map_or(CapabilitySupport::Unsupported, |capability| {
                capability.support
            })
    }
}

/// A DAMOS region-size range in DAMON core address units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSizeRange {
    min: u64,
    max: u64,
}

impl RegionSizeRange {
    /// Creates a validated inclusive size range in core address units.
    pub const fn new(min: u64, max: u64) -> Result<Self> {
        if min > max {
            return Err(Error::InvalidConfiguration {
                field: "region size range",
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

    /// Converts the inclusive minimum to bytes with the context's unit.
    pub const fn min_bytes(self, address_unit: AddressUnit) -> Result<u64> {
        address_unit.to_bytes(self.min)
    }

    /// Converts the inclusive maximum to bytes with the context's unit.
    pub const fn max_bytes(self, address_unit: AddressUnit) -> Result<u64> {
        address_unit.to_bytes(self.max)
    }
}

/// A DAMOS access-count range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessCountRange {
    min: u32,
    max: u32,
}

impl AccessCountRange {
    /// Creates a validated inclusive access-count range.
    pub const fn new(min: u32, max: u32) -> Result<Self> {
        if min > max {
            return Err(Error::InvalidConfiguration {
                field: "access count range",
                reason: "minimum must not exceed maximum",
            });
        }
        Ok(Self { min, max })
    }

    /// Returns the inclusive minimum.
    #[must_use]
    pub const fn min(self) -> u32 {
        self.min
    }

    /// Returns the inclusive maximum.
    #[must_use]
    pub const fn max(self) -> u32 {
        self.max
    }
}

/// A DAMOS age range in aggregation intervals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgeRange {
    min: u32,
    max: u32,
}

impl AgeRange {
    /// Creates a validated inclusive age range.
    pub const fn new(min: u32, max: u32) -> Result<Self> {
        if min > max {
            return Err(Error::InvalidConfiguration {
                field: "age range",
                reason: "minimum must not exceed maximum",
            });
        }
        Ok(Self { min, max })
    }

    /// Returns the inclusive minimum.
    #[must_use]
    pub const fn min(self) -> u32 {
        self.min
    }

    /// Returns the inclusive maximum.
    #[must_use]
    pub const fn max(self) -> u32 {
        self.max
    }
}

/// A DAMOS region access pattern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessPattern {
    size: RegionSizeRange,
    accesses: AccessCountRange,
    age: AgeRange,
}

impl AccessPattern {
    /// Creates a pattern from size, access-count, and age ranges.
    #[must_use]
    pub const fn new(size: RegionSizeRange, accesses: AccessCountRange, age: AgeRange) -> Self {
        Self {
            size,
            accesses,
            age,
        }
    }

    /// Returns the region-size range in DAMON core address units.
    #[must_use]
    pub const fn size(self) -> RegionSizeRange {
        self.size
    }

    /// Returns the access-count range.
    #[must_use]
    pub const fn accesses(self) -> AccessCountRange {
        self.accesses
    }

    /// Returns the age range in aggregation intervals.
    #[must_use]
    pub const fn age(self) -> AgeRange {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuxiliaryConfigFingerprint(Box<[Option<Box<str>>]>);

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

    /// Discovers features from individual paths in a staged context and scheme.
    ///
    /// Paths below an unstaged probe or probe filter are reported as
    /// [`CapabilitySupport::RequiresStaging`], rather than being confused with
    /// kernel-level absence. This method never modifies the staged hierarchy.
    pub fn capabilities(&self, context_index: usize, scheme_index: usize) -> Result<Capabilities> {
        let context_count = self.context_count()?;
        if context_index >= context_count {
            return Err(Error::IndexOutOfBounds {
                kind: "context",
                index: context_index,
                count: context_count,
            });
        }
        let context = self.context(context_index);
        let scheme_count = context.scheme_count()?;
        if scheme_index >= scheme_count {
            return Err(Error::IndexOutOfBounds {
                kind: "scheme",
                index: scheme_index,
                count: scheme_count,
            });
        }
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
                SysfsFeature::SchemeApplyInterval,
                scheme.path.join("apply_interval_us"),
            ),
        ] {
            features.push(feature_capability(feature, support_for_path(&path)?));
        }

        let probe_count_support = support_for_path(&probes.join("nr_probes"))?;
        let probe_filter_count_support = match probe_count_support {
            CapabilitySupport::Unsupported => CapabilitySupport::Unsupported,
            CapabilitySupport::RequiresStaging => CapabilitySupport::RequiresStaging,
            CapabilitySupport::Supported if context.probe_count()? == 0 => {
                CapabilitySupport::RequiresStaging
            }
            CapabilitySupport::Supported => support_for_path(&probes.join("0/filters/nr_filters"))?,
        };
        features.push(feature_capability(
            SysfsFeature::ProbeFilterCount,
            probe_filter_count_support,
        ));

        let probe_filter_attribute_support = match probe_filter_count_support {
            CapabilitySupport::Unsupported => CapabilitySupport::Unsupported,
            CapabilitySupport::RequiresStaging => CapabilitySupport::RequiresStaging,
            CapabilitySupport::Supported if context.probe(0).filter_count()? == 0 => {
                CapabilitySupport::RequiresStaging
            }
            CapabilitySupport::Supported => CapabilitySupport::Supported,
        };
        for (feature, name) in [
            (SysfsFeature::ProbeFilterType, "type"),
            (SysfsFeature::ProbeFilterMatching, "matching"),
            (SysfsFeature::ProbeFilterAllow, "allow"),
            (SysfsFeature::ProbeFilterPath, "path"),
        ] {
            let support = if probe_filter_attribute_support == CapabilitySupport::Supported {
                support_for_path(&probe_filter.join(name))?
            } else {
                probe_filter_attribute_support
            };
            features.push(feature_capability(feature, support));
        }

        let tried_regions = scheme.path.join("tried_regions");
        features.push(feature_capability(
            SysfsFeature::TriedRegions,
            if path_is_dir(&tried_regions)? {
                CapabilitySupport::Supported
            } else {
                CapabilitySupport::Unsupported
            },
        ));
        features.push(feature_capability(
            SysfsFeature::TriedRegionsTotalBytes,
            support_for_path(&tried_regions.join("total_bytes"))?,
        ));

        let operations = if feature_support(&features, SysfsFeature::AvailableOperations)
            == CapabilitySupport::Supported
        {
            context.available_operations()?
        } else {
            Vec::new()
        };
        Ok(Capabilities {
            operations: operations.into_boxed_slice(),
            features: features.into_boxed_slice(),
        })
    }

    pub(crate) fn auxiliary_config_fingerprint(&self) -> Result<AuxiliaryConfigFingerprint> {
        let mut values = Vec::with_capacity(LINUX_7_2_AUXILIARY_CONFIG_PATHS.len());
        for relative in LINUX_7_2_AUXILIARY_CONFIG_PATHS {
            let path = self.path.join(relative);
            values.push(if path_exists(&path)? {
                Some(read_text(&path)?.trim().into())
            } else {
                None
            });
        }
        Ok(AuxiliaryConfigFingerprint(values.into_boxed_slice()))
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

    /// Reads whether this target is staged for removal on the next commit.
    pub fn is_obsolete(&self) -> Result<bool> {
        read_bool(&self.path.join("obsolete_target"))
    }

    /// Marks or unmarks this target for removal on the next commit.
    pub fn set_obsolete(&self, obsolete: bool) -> Result<()> {
        write_bool(&self.path.join("obsolete_target"), obsolete)
    }

    pub(crate) fn initial_region_count(&self) -> Result<usize> {
        read_usize(&self.path.join("regions/nr_regions"))
    }

    pub(crate) fn set_initial_region_count(&self, count: usize) -> Result<()> {
        write_value(&self.path.join("regions/nr_regions"), count)
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
    /// Call [`Kdamond::command`] with
    /// [`KdamondCommand::UpdateSchemesTriedRegions`] first. `capacity_hint`
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
            let mut probe_hits = [0_u8; MAX_PROBES];
            let mut probe_count = 0_u8;
            for (probe_index, hits_value) in probe_hits.iter_mut().enumerate() {
                let hits = probes.join(probe_index.to_string()).join("hits");
                if !path_exists(&hits)? {
                    break;
                }
                *hits_value = read_u8(&hits)?;
                probe_count += 1;
            }

            let region = RawRegion::from_kernel(
                start,
                end,
                nr_accesses,
                age,
                filter_passed_units,
                &probe_hits[..usize::from(probe_count)],
            )?;
            if reported_total_units.is_none() {
                computed_total_units = computed_total_units
                    .checked_add(region.len_units())
                    .ok_or(Error::SnapshotSizeOverflow)?;
            }
            regions.push(region);
        }

        Ok(RawSnapshot::from_kernel(
            regions,
            reported_total_units.unwrap_or(computed_total_units),
        ))
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
    #[cfg(test)]
    if let Some(result) = test_backend::path_exists(path) {
        return result.map_err(|error| io_error("inspect", path, error));
    }
    path.try_exists()
        .map_err(|error| io_error("inspect", path, error))
}

fn path_is_dir(path: &Path) -> Result<bool> {
    #[cfg(test)]
    if let Some(result) = test_backend::path_is_dir(path) {
        return result.map_err(|error| io_error("inspect", path, error));
    }
    match path.metadata() {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error("inspect", path, error)),
    }
}

fn support_for_path(path: &Path) -> Result<CapabilitySupport> {
    if path_exists(path)? {
        Ok(CapabilitySupport::Supported)
    } else {
        Ok(CapabilitySupport::Unsupported)
    }
}

const fn feature_capability(
    feature: SysfsFeature,
    support: CapabilitySupport,
) -> FeatureCapability {
    FeatureCapability { feature, support }
}

fn feature_support(capabilities: &[FeatureCapability], feature: SysfsFeature) -> CapabilitySupport {
    capabilities
        .iter()
        .find(|capability| capability.feature == feature)
        .map_or(CapabilitySupport::Unsupported, |capability| {
            capability.support
        })
}

fn read_text(path: &Path) -> Result<String> {
    #[cfg(test)]
    if let Some(result) = test_backend::read(path) {
        let bytes = result.map_err(|error| io_error("read", path, error))?;
        return String::from_utf8(bytes)
            .map_err(|_| invalid_kernel_value(path, "<non-UTF-8 value>", "UTF-8 text"));
    }
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

fn read_u8(path: &Path) -> Result<u8> {
    let value = read_u64(path)?;
    u8::try_from(value).map_err(|_| invalid_kernel_value(path, value.to_string(), "u8"))
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
    #[cfg(test)]
    if let Some(result) = test_backend::read(path) {
        let bytes = result.map_err(|error| io_error("read", path, error))?;
        if bytes.len() > 64 {
            return Err(invalid_kernel_value(path, "<value too long>", "u64"));
        }
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| invalid_kernel_value(path, "<non-UTF-8 value>", "u64"))?
            .trim();
        return value
            .parse()
            .map_err(|_| invalid_kernel_value(path, value, "u64"));
    }
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
    #[cfg(test)]
    if let Some(result) = test_backend::write(path, value) {
        return result.map_err(|error| io_error("write", path, error));
    }
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
#[allow(dead_code, missing_docs)]
pub(crate) mod test_backend {
    use std::collections::BTreeMap;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Node {
        Directory,
        File(Vec<u8>),
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct ModelRegion {
        pub(crate) start: u64,
        pub(crate) end: u64,
        pub(crate) nr_accesses: u32,
        pub(crate) age: u32,
        pub(crate) filter_passed_units: Option<u64>,
        pub(crate) probe_hits: Vec<u8>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) enum Mutation {
        SetFile { path: PathBuf, value: Vec<u8> },
        RemoveTree { path: PathBuf },
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum HookEvent {
        Read(PathBuf),
        Write(PathBuf, Vec<u8>),
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Hook {
        event: HookEvent,
        mutations: Vec<Mutation>,
    }

    #[derive(Debug)]
    struct State {
        nodes: BTreeMap<PathBuf, Node>,
        available_operations: Vec<u8>,
        active_files: Option<BTreeMap<PathBuf, Vec<u8>>>,
        next_kdamond_pid: u32,
        tried_regions: Vec<ModelRegion>,
        hooks: Vec<Hook>,
    }

    impl State {
        fn new(available_operations: &str) -> Self {
            let mut state = Self {
                nodes: BTreeMap::new(),
                available_operations: available_operations.as_bytes().to_vec(),
                active_files: None,
                next_kdamond_pid: 10_000,
                tried_regions: Vec::new(),
                hooks: Vec::new(),
            };
            state.directory("");
            state.directory("kdamonds");
            state.file("kdamonds/nr_kdamonds", b"0\n");
            state
        }

        fn directory(&mut self, path: impl Into<PathBuf>) {
            self.nodes.insert(path.into(), Node::Directory);
        }

        fn file(&mut self, path: impl Into<PathBuf>, value: &[u8]) {
            self.nodes.insert(path.into(), Node::File(value.to_vec()));
        }

        fn remove_tree(&mut self, path: &Path) {
            self.nodes
                .retain(|candidate, _| candidate != path && !candidate.starts_with(path));
        }

        fn remove_indexed_children(&mut self, parent: &Path) {
            self.nodes.retain(|candidate, _| {
                let Ok(relative) = candidate.strip_prefix(parent) else {
                    return true;
                };
                let Some(first) = relative.components().next() else {
                    return true;
                };
                first
                    .as_os_str()
                    .to_str()
                    .is_none_or(|component| component.parse::<usize>().is_err())
            });
        }

        fn create_kdamond(&mut self, index: usize) {
            let base = PathBuf::from(format!("kdamonds/{index}"));
            self.directory(&base);
            self.file(base.join("state"), b"off\n");
            self.file(base.join("pid"), b"-1\n");
            self.file(base.join("refresh_ms"), b"0\n");
            self.directory(base.join("contexts"));
            self.file(base.join("contexts/nr_contexts"), b"0\n");
        }

        fn create_context(&mut self, base: &Path, index: usize) {
            let base = base.join(index.to_string());
            self.directory(&base);
            let operations = self.available_operations.clone();
            self.file(base.join("avail_operations"), &operations);
            self.file(base.join("operations"), b"vaddr\n");
            self.file(base.join("addr_unit"), b"1\n");
            self.file(base.join("pause"), b"N\n");
            self.directory(base.join("monitoring_attrs"));
            self.directory(base.join("monitoring_attrs/intervals"));
            self.file(base.join("monitoring_attrs/intervals/sample_us"), b"5000\n");
            self.file(base.join("monitoring_attrs/intervals/aggr_us"), b"100000\n");
            self.file(
                base.join("monitoring_attrs/intervals/update_us"),
                b"60000000\n",
            );
            self.directory(base.join("monitoring_attrs/intervals/intervals_goal"));
            for name in ["access_bp", "aggrs", "min_sample_us", "max_sample_us"] {
                self.file(
                    base.join("monitoring_attrs/intervals/intervals_goal")
                        .join(name),
                    b"0\n",
                );
            }
            self.directory(base.join("monitoring_attrs/nr_regions"));
            self.file(base.join("monitoring_attrs/nr_regions/min"), b"10\n");
            self.file(base.join("monitoring_attrs/nr_regions/max"), b"1000\n");
            self.directory(base.join("monitoring_attrs/probes"));
            self.file(base.join("monitoring_attrs/probes/nr_probes"), b"0\n");
            self.directory(base.join("targets"));
            self.file(base.join("targets/nr_targets"), b"0\n");
            self.directory(base.join("schemes"));
            self.file(base.join("schemes/nr_schemes"), b"0\n");
        }

        fn create_target(&mut self, base: &Path, index: usize) {
            let base = base.join(index.to_string());
            self.directory(&base);
            self.file(base.join("pid_target"), b"0\n");
            self.file(base.join("obsolete_target"), b"N\n");
            self.directory(base.join("regions"));
            self.file(base.join("regions/nr_regions"), b"0\n");
        }

        fn create_target_region(&mut self, base: &Path, index: usize) {
            let base = base.join(index.to_string());
            self.directory(&base);
            self.file(base.join("start"), b"0\n");
            self.file(base.join("end"), b"0\n");
        }

        fn create_scheme(&mut self, base: &Path, index: usize) {
            let base = base.join(index.to_string());
            self.directory(&base);
            self.file(base.join("action"), b"stat\n");
            self.file(base.join("target_nid"), b"0\n");
            self.file(base.join("apply_interval_us"), b"0\n");
            self.directory(base.join("access_pattern"));
            for range in ["sz", "nr_accesses", "age"] {
                self.directory(base.join("access_pattern").join(range));
                self.file(base.join("access_pattern").join(range).join("min"), b"0\n");
                self.file(base.join("access_pattern").join(range).join("max"), b"0\n");
            }
            self.directory(base.join("quotas"));
            for name in [
                "ms",
                "bytes",
                "reset_interval_ms",
                "fail_charge_num",
                "fail_charge_denom",
            ] {
                self.file(base.join("quotas").join(name), b"0\n");
            }
            self.file(base.join("quotas/goal_tuner"), b"none\n");
            self.directory(base.join("quotas/weights"));
            for name in ["sz_permil", "nr_accesses_permil", "age_permil"] {
                self.file(base.join("quotas/weights").join(name), b"0\n");
            }
            self.directory(base.join("quotas/goals"));
            self.file(base.join("quotas/goals/nr_goals"), b"0\n");
            self.directory(base.join("watermarks"));
            self.file(base.join("watermarks/metric"), b"none\n");
            for name in ["interval_us", "high", "mid", "low"] {
                self.file(base.join("watermarks").join(name), b"0\n");
            }
            for filters in ["core_filters", "ops_filters", "filters"] {
                self.directory(base.join(filters));
                self.file(base.join(filters).join("nr_filters"), b"0\n");
            }
            self.directory(base.join("dests"));
            self.file(base.join("dests/nr_dests"), b"0\n");
            self.directory(base.join("stats"));
            self.file(base.join("stats/max_nr_snapshots"), b"0\n");
            self.directory(base.join("tried_regions"));
            self.file(base.join("tried_regions/total_bytes"), b"0\n");
        }

        fn create_probe(&mut self, base: &Path, index: usize) {
            let base = base.join(index.to_string());
            self.directory(&base);
            self.directory(base.join("filters"));
            self.file(base.join("filters/nr_filters"), b"0\n");
        }

        fn create_probe_filter(&mut self, base: &Path, index: usize) {
            let base = base.join(index.to_string());
            self.directory(&base);
            self.file(base.join("type"), b"anon\n");
            self.file(base.join("matching"), b"N\n");
            self.file(base.join("allow"), b"N\n");
            self.file(base.join("path"), b"\n");
        }

        fn parse_count(value: &[u8]) -> io::Result<usize> {
            let value = std::str::from_utf8(value)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 count"))?
                .trim()
                .parse::<usize>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid count"))?;
            if value > 128 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "test model count limit exceeded",
                ));
            }
            Ok(value)
        }

        fn reconstruct_count(&mut self, path: &Path, count: usize) -> io::Result<bool> {
            let path_text = path.to_string_lossy();
            if path_text == "kdamonds/nr_kdamonds" {
                if self.nodes.iter().any(|(candidate, node)| {
                    candidate.file_name().is_some_and(|name| name == "state")
                        && matches!(node, Node::File(value) if value == b"on\n")
                }) {
                    return Err(io::Error::from_raw_os_error(16));
                }
                let parent = Path::new("kdamonds");
                self.remove_indexed_children(parent);
                self.active_files = None;
                for index in 0..count {
                    self.create_kdamond(index);
                }
                return Ok(true);
            }
            if path_text.ends_with("/contexts/nr_contexts") {
                if count > 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Linux 7.2 supports at most one context",
                    ));
                }
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    self.create_context(parent, index);
                }
                return Ok(true);
            }
            if path_text.ends_with("/targets/nr_targets") {
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    self.create_target(parent, index);
                }
                return Ok(true);
            }
            if path_text.ends_with("/schemes/nr_schemes") {
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    self.create_scheme(parent, index);
                }
                return Ok(true);
            }
            if path_text.ends_with("/monitoring_attrs/probes/nr_probes") {
                if count > super::MAX_PROBES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "probe count exceeds DAMON_MAX_PROBES",
                    ));
                }
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    self.create_probe(parent, index);
                }
                return Ok(true);
            }
            if path_text.ends_with("/filters/nr_filters") {
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    self.create_probe_filter(parent, index);
                }
                return Ok(true);
            }
            if path_text.ends_with("/regions/nr_regions") {
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    self.create_target_region(parent, index);
                }
                return Ok(true);
            }
            Ok(false)
        }

        fn capture_active_files(&mut self) {
            self.active_files = Some(
                self.nodes
                    .iter()
                    .filter_map(|(path, node)| match node {
                        Node::File(value) => Some((path.clone(), value.clone())),
                        Node::Directory => None,
                    })
                    .collect(),
            );
        }

        fn commit_quota_goals(&mut self) {
            let staged_goals: Vec<_> = self
                .nodes
                .iter()
                .filter_map(|(path, node)| {
                    if !path.to_string_lossy().contains("/quotas/goals/") {
                        return None;
                    }
                    match node {
                        Node::File(value) => Some((path.clone(), value.clone())),
                        Node::Directory => None,
                    }
                })
                .collect();
            let active = self
                .active_files
                .as_mut()
                .expect("running model has active files");
            active.retain(|path, _| !path.to_string_lossy().contains("/quotas/goals/"));
            active.extend(staged_goals);
        }

        fn materialize_tried_regions(&mut self, kdamond: &Path) -> io::Result<()> {
            let base = kdamond.join("contexts/0/schemes/0/tried_regions");
            if !self.nodes.contains_key(&base) {
                return Err(not_found(&base));
            }
            self.remove_indexed_children(&base);
            let regions = self.tried_regions.clone();
            let total = regions.iter().try_fold(0_u64, |total, region| {
                let size = region.end.checked_sub(region.start).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid modeled region")
                })?;
                total.checked_add(size).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "modeled total overflow")
                })
            })?;
            self.file(base.join("total_bytes"), format!("{total}\n").as_bytes());
            for (index, region) in regions.iter().enumerate() {
                let region_base = base.join(index.to_string());
                self.directory(&region_base);
                self.file(
                    region_base.join("start"),
                    format!("{}\n", region.start).as_bytes(),
                );
                self.file(
                    region_base.join("end"),
                    format!("{}\n", region.end).as_bytes(),
                );
                self.file(
                    region_base.join("nr_accesses"),
                    format!("{}\n", region.nr_accesses).as_bytes(),
                );
                self.file(
                    region_base.join("age"),
                    format!("{}\n", region.age).as_bytes(),
                );
                if let Some(units) = region.filter_passed_units {
                    self.file(
                        region_base.join("sz_filter_passed"),
                        format!("{units}\n").as_bytes(),
                    );
                }
                self.directory(region_base.join("probes"));
                for (probe_index, hits) in region.probe_hits.iter().enumerate() {
                    let probe_base = region_base.join("probes").join(probe_index.to_string());
                    self.directory(&probe_base);
                    self.file(probe_base.join("hits"), format!("{hits}\n").as_bytes());
                }
            }
            Ok(())
        }

        fn write_state(&mut self, path: &Path, value: &[u8]) -> io::Result<()> {
            let command = std::str::from_utf8(value)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 command"))?
                .trim();
            let kdamond = path.parent().expect("state path has parent");
            match command {
                "on" => {
                    self.capture_active_files();
                    self.next_kdamond_pid += 1;
                    self.file(path, b"on\n");
                    self.file(
                        kdamond.join("pid"),
                        format!("{}\n", self.next_kdamond_pid).as_bytes(),
                    );
                }
                "off" => {
                    self.active_files = None;
                    self.file(path, b"off\n");
                    self.file(kdamond.join("pid"), b"-1\n");
                }
                "commit" => {
                    self.ensure_running(path)?;
                    self.capture_active_files();
                }
                "commit_schemes_quota_goals" => {
                    self.ensure_running(path)?;
                    self.commit_quota_goals();
                }
                "update_schemes_tried_regions" => {
                    self.ensure_running(path)?;
                    self.materialize_tried_regions(kdamond)?;
                }
                "update_schemes_tried_bytes" => {
                    self.ensure_running(path)?;
                    self.materialize_tried_regions(kdamond)?;
                    let base = kdamond.join("contexts/0/schemes/0/tried_regions");
                    self.remove_indexed_children(&base);
                }
                "clear_schemes_tried_regions" => {
                    self.ensure_running(path)?;
                    let base = kdamond.join("contexts/0/schemes/0/tried_regions");
                    self.remove_indexed_children(&base);
                    self.file(base.join("total_bytes"), b"0\n");
                }
                "update_schemes_stats"
                | "update_schemes_effective_quotas"
                | "update_tuned_intervals" => self.ensure_running(path)?,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unknown modeled state command",
                    ));
                }
            }
            Ok(())
        }

        fn ensure_running(&self, state_path: &Path) -> io::Result<()> {
            match self.nodes.get(state_path) {
                Some(Node::File(value)) if value == b"on\n" => Ok(()),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "modeled kdamond is not running",
                )),
            }
        }

        fn write(&mut self, path: &Path, value: &[u8]) -> io::Result<()> {
            match self.nodes.get(path) {
                Some(Node::File(_)) => {}
                Some(Node::Directory) => return Err(io::Error::from(io::ErrorKind::IsADirectory)),
                None => return Err(not_found(path)),
            }

            if path.file_name().is_some_and(|name| name == "state") {
                return self.write_state(path, value);
            }

            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("nr_"))
            {
                let count = Self::parse_count(value)?;
                if self.reconstruct_count(path, count)? {
                    self.file(path, format!("{count}\n").as_bytes());
                    return Ok(());
                }
            }

            self.file(path, value);
            Ok(())
        }

        fn apply_hooks(&mut self, event: &HookEvent) {
            let Some(index) = self.hooks.iter().position(|hook| &hook.event == event) else {
                return;
            };
            let hook = self.hooks.remove(index);
            for mutation in hook.mutations {
                match mutation {
                    Mutation::SetFile { path, value } => self.file(path, &value),
                    Mutation::RemoveTree { path } => self.remove_tree(&path),
                }
            }
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) struct Model {
        root: PathBuf,
        state: Arc<Mutex<State>>,
    }

    impl Model {
        pub(crate) fn new(available_operations: &str) -> Self {
            static NEXT_MODEL: AtomicU64 = AtomicU64::new(0);
            let root = PathBuf::from(format!(
                "/__damon_rs_model/{}-{}",
                std::process::id(),
                NEXT_MODEL.fetch_add(1, Ordering::Relaxed)
            ));
            let state = Arc::new(Mutex::new(State::new(available_operations)));
            registry()
                .lock()
                .expect("test backend registry lock poisoned")
                .push((root.clone(), Arc::downgrade(&state)));
            Self { root, state }
        }

        pub(crate) fn root(&self) -> &Path {
            &self.root
        }

        pub(crate) fn set_tried_regions(&self, regions: Vec<ModelRegion>) {
            lock(&self.state).tried_regions = regions;
        }

        pub(crate) fn active_value(&self, path: impl AsRef<Path>) -> Option<String> {
            lock(&self.state)
                .active_files
                .as_ref()?
                .get(path.as_ref())
                .map(|value| String::from_utf8_lossy(value).trim().to_owned())
        }

        pub(crate) fn after_next_read(&self, path: impl Into<PathBuf>, mutations: Vec<Mutation>) {
            lock(&self.state).hooks.push(Hook {
                event: HookEvent::Read(path.into()),
                mutations,
            });
        }

        pub(crate) fn after_next_write(
            &self,
            path: impl Into<PathBuf>,
            value: impl Into<Vec<u8>>,
            mutations: Vec<Mutation>,
        ) {
            lock(&self.state).hooks.push(Hook {
                event: HookEvent::Write(path.into(), value.into()),
                mutations,
            });
        }
    }

    type Registry = Vec<(PathBuf, Weak<Mutex<State>>)>;

    fn registry() -> &'static Mutex<Registry> {
        static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
        REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
    }

    fn lock(state: &Arc<Mutex<State>>) -> MutexGuard<'_, State> {
        state.lock().expect("test backend state lock poisoned")
    }

    fn resolve(path: &Path) -> Option<(Arc<Mutex<State>>, PathBuf)> {
        let mut registry = registry()
            .lock()
            .expect("test backend registry lock poisoned");
        registry.retain(|(_, state)| state.strong_count() > 0);
        registry
            .iter()
            .filter_map(|(root, state)| {
                let relative = path.strip_prefix(root).ok()?.to_path_buf();
                Some((root.components().count(), state.upgrade()?, relative))
            })
            .max_by_key(|(depth, _, _)| *depth)
            .map(|(_, state, relative)| (state, relative))
    }

    fn not_found(path: &Path) -> io::Error {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("modeled sysfs path {} does not exist", path.display()),
        )
    }

    pub(super) fn path_exists(path: &Path) -> Option<io::Result<bool>> {
        let (state, relative) = resolve(path)?;
        Some(Ok(lock(&state).nodes.contains_key(&relative)))
    }

    pub(super) fn path_is_dir(path: &Path) -> Option<io::Result<bool>> {
        let (state, relative) = resolve(path)?;
        Some(Ok(matches!(
            lock(&state).nodes.get(&relative),
            Some(Node::Directory)
        )))
    }

    pub(super) fn read(path: &Path) -> Option<io::Result<Vec<u8>>> {
        let (state, relative) = resolve(path)?;
        let mut state = lock(&state);
        let result = match state.nodes.get(&relative) {
            Some(Node::File(value)) => Ok(value.clone()),
            Some(Node::Directory) => Err(io::Error::from(io::ErrorKind::IsADirectory)),
            None => Err(not_found(&relative)),
        };
        if result.is_ok() {
            state.apply_hooks(&HookEvent::Read(relative));
        }
        Some(result)
    }

    pub(super) fn write(path: &Path, value: &[u8]) -> Option<io::Result<()>> {
        let (state, relative) = resolve(path)?;
        let mut state = lock(&state);
        let result = state.write(&relative, value);
        if result.is_ok() {
            state.apply_hooks(&HookEvent::Write(relative, value.to_vec()));
        }
        Some(result)
    }
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

    #[test]
    fn modeled_sysfs_reconstructs_children_and_separates_active_inputs() {
        let model = test_backend::Model::new("vaddr\nfvaddr\npaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        assert_eq!(admin.kdamond_count().expect("read initial count"), 0);

        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        kdamond.set_context_count(1).expect("stage context");
        let context = kdamond.context(0);
        context
            .set_operation(&Operation::PhysicalAddress)
            .expect("stage operation");
        context
            .set_address_unit(AddressUnit::new(4_096).expect("valid unit"))
            .expect("stage address unit");

        kdamond.command(KdamondCommand::On).expect("start model");
        let first_pid = kdamond.pid().expect("read modeled pid");
        assert!(first_pid.is_some());
        assert_eq!(
            model.active_value("kdamonds/0/contexts/0/addr_unit"),
            Some("4096".to_owned())
        );

        context
            .set_address_unit(AddressUnit::ONE)
            .expect("change only staged unit");
        assert_eq!(
            context.address_unit().expect("read staged unit"),
            AddressUnit::ONE
        );
        assert_eq!(
            model.active_value("kdamonds/0/contexts/0/addr_unit"),
            Some("4096".to_owned())
        );

        kdamond
            .command(KdamondCommand::UpdateSchemesStats)
            .expect("state command is accepted");
        assert_eq!(
            kdamond.state().expect("state remains running"),
            KdamondState::On
        );
        kdamond
            .command(KdamondCommand::Commit)
            .expect("commit staged values");
        assert_eq!(
            model.active_value("kdamonds/0/contexts/0/addr_unit"),
            Some("1".to_owned())
        );

        kdamond.command(KdamondCommand::Off).expect("stop model");
        assert_eq!(kdamond.pid().expect("read stopped pid"), None);
        kdamond.set_context_count(0).expect("remove context");
        assert!(!path_exists(context.path()).expect("inspect removed child"));
    }

    #[test]
    fn modeled_quota_goal_commit_does_not_commit_other_staged_inputs() {
        let model = test_backend::Model::new("vaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        kdamond.set_context_count(1).expect("stage context");
        let context = kdamond.context(0);
        context.set_scheme_count(1).expect("stage scheme");
        kdamond.command(KdamondCommand::On).expect("start model");

        let scheme = context.scheme(0);
        write_bytes(&scheme.path().join("quotas/ms"), b"99").expect("stage non-goal quota");
        write_bytes(&scheme.path().join("quotas/goals/nr_goals"), b"1")
            .expect("stage quota goal count");
        kdamond
            .command(KdamondCommand::CommitSchemesQuotaGoals)
            .expect("commit only quota goals");

        assert_eq!(
            model.active_value("kdamonds/0/contexts/0/schemes/0/quotas/ms"),
            Some("0".to_owned())
        );
        assert_eq!(
            model.active_value("kdamonds/0/contexts/0/schemes/0/quotas/goals/nr_goals"),
            Some("1".to_owned())
        );
    }

    #[test]
    fn modeled_kdamond_reconstruction_is_busy_while_running() {
        let model = test_backend::Model::new("vaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        kdamond.set_context_count(1).expect("stage context");
        kdamond.command(KdamondCommand::On).expect("start model");

        let error = admin
            .set_kdamond_count(0)
            .expect_err("running kdamond reconstruction must be busy");
        assert!(error.is_resource_busy());
        assert_eq!(admin.kdamond_count().expect("preserve count"), 1);

        kdamond.command(KdamondCommand::Off).expect("stop model");
        admin.set_kdamond_count(0).expect("remove stopped model");
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
