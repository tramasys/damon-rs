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

mod configuration;

pub use configuration::{
    ContextConfig, DamonConfig, DestinationConfig, FilterConfig, FilterLayer, InitialRegion,
    InitialRegionConfig, IntervalsGoalConfig, KdamondConfig, MigrationDestination,
    OperationAttributes, OperationAttributesConfig, ProbeConfig, ProbeFilterConfig,
    ProbePreparation, ProbePreparationAction, ProbePreparationConfig, QuotaConfig, QuotaGoal,
    QuotaGoalConfig, QuotaGoalMetric, QuotaGoalTuner, QuotaWeights, SampleControl,
    SampleControlConfig, SampleFilter, SampleFilterConfig, SampleFilterType,
    SamplePrimitivesConfig, SchemeConfig, SchemeFilter, SchemeFilterType, SchemeQuotas,
    SchemeStats, SchemeWatermarks, TargetConfig, WatermarkMetric, WatermarksConfig,
};

/// Default location of DAMON's privileged admin interface.
pub const DEFAULT_ADMIN_PATH: &str = "/sys/kernel/mm/damon/admin";

const MAX_INITIAL_REGION_CAPACITY: usize = 4_096;

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

/// A DAMON sysfs capability represented by the typed discovery API.
///
/// Semantic variants correspond to the official `damo` sysfs capability map.
/// Discovery uses populated paths and accepted values rather than the running
/// kernel version. Features below an unstaged indexed child are reported
/// through [`CapabilitySupport::RequiresStaging`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SysfsFeature {
    /// Process virtual-address monitoring (`sysfs/vaddr`).
    VirtualAddressOperation,
    /// Physical-address monitoring (`sysfs/paddr`).
    PhysicalAddressOperation,
    /// Fixed virtual-address monitoring (`sysfs/fvaddr`).
    FixedVirtualAddressOperation,
    /// DAMOS schemes (`sysfs/schemes`).
    Schemes,
    /// DAMOS time quotas (`sysfs/schemes_time_quota`).
    SchemeTimeQuota,
    /// DAMOS size quotas (`sysfs/schemes_size_quota`).
    SchemeSizeQuota,
    /// DAMOS quota prioritization weights (`sysfs/schemes_prioritization`).
    SchemePrioritization,
    /// DAMOS watermarks (`sysfs/schemes_wmarks`).
    SchemeWatermarks,
    /// Successful DAMOS application statistics (`sysfs/schemes_stat_succ`).
    SchemeSuccessfulStats,
    /// DAMOS quota-exceeded statistics (`sysfs/schemes_stat_qt_exceed`).
    SchemeQuotaExceededStats,
    /// `contexts/<N>/avail_operations` is present.
    AvailableOperations,
    /// Running-context parameter commits (`sysfs/online_params_commit`).
    OnlineParametersCommit,
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
    /// `targets/<N>/obsolete_target` is present.
    ObsoleteTarget,
    /// `targets/<N>/regions/nr_regions` is present.
    InitialRegions,
    /// `schemes/<N>/tried_regions` is present.
    TriedRegions,
    /// `schemes/<N>/tried_regions/total_bytes` is present.
    TriedRegionsTotalBytes,
    /// The original unified DAMOS filter directory (`sysfs/schemes_filters`).
    SchemeFilters,
    /// Anonymous-memory DAMOS filters (`sysfs/schemes_filters_anon`).
    SchemeFilterAnonymous,
    /// Memory-control-group DAMOS filters (`sysfs/schemes_filters_memcg`).
    SchemeFilterMemoryControlGroup,
    /// Address-range DAMOS filters (`sysfs/schemes_filters_addr`).
    SchemeFilterAddress,
    /// DAMON-target DAMOS filters (`sysfs/schemes_filters_target`).
    SchemeFilterTarget,
    /// Young-page DAMOS filters (`sysfs/schemes_filters_young`).
    SchemeFilterYoung,
    /// Huge-page-size DAMOS filters (`sysfs/schemes_filters_hugepage_size`).
    SchemeFilterHugePageSize,
    /// Unmapped-page DAMOS filters (`sysfs/schemes_filters_unmapped`).
    SchemeFilterUnmapped,
    /// Active-page DAMOS filters (`sysfs/schemes_filters_active`).
    SchemeFilterActive,
    /// Separate core and operations DAMOS filter directories.
    SeparateSchemeFilterDirectories,
    /// Per-filter allow controls (`sysfs/allow_filter`).
    SchemeFilterAllow,
    /// DAMOS quota goals (`sysfs/schemes_quota_goals`).
    SchemeQuotaGoals,
    /// Effective DAMOS quota reporting (`sysfs/schemes_quota_effective_bytes`).
    SchemeQuotaEffectiveBytes,
    /// DAMOS quota-goal metrics (`sysfs/schemes_quota_goal_metric`).
    SchemeQuotaGoalMetric,
    /// DAMOS quota-goal PSI metrics (`sysfs/schemes_quota_goal_some_psi`).
    SchemeQuotaGoalSomePsi,
    /// Node-memory DAMOS quota goals.
    SchemeQuotaGoalNodeMemory,
    /// Node memory-control-group DAMOS quota goals.
    SchemeQuotaGoalNodeMemoryControlGroup,
    /// Active-memory DAMOS quota goals.
    SchemeQuotaGoalActiveMemory,
    /// Node-eligible-memory DAMOS quota goals.
    SchemeQuotaGoalNodeEligibleMemory,
    /// Automatic DAMOS quota-goal tuning.
    SchemeQuotaGoalTuner,
    /// DAMOS quota failure-charge ratios.
    SchemeQuotaFailureChargeRatio,
    /// DAMOS memory migration (`sysfs/schemes_migrate`).
    SchemeMigration,
    /// Weighted DAMOS migration destinations (`sysfs/schemes_dests`).
    SchemeDestinations,
    /// Bytes passed by operations-layer filters.
    SchemeOperationsFilterPassedBytes,
    /// Number of DAMOS snapshots (`sysfs/damos_stat_nr_snapshots`).
    SchemeSnapshotCount,
    /// Configurable maximum number of DAMOS snapshots.
    SchemeMaximumSnapshotCount,
    /// DAMOS collapse action (`sysfs/damos_action_collapse`).
    CollapseAction,
    /// Auto-tuned monitoring interval goals (`sysfs/intervals_goal`).
    MonitoringIntervalsGoal,
    /// Monitoring-data probes (`sysfs/attrs_monitoring`).
    AttributeMonitoring,
    /// Anonymous-memory monitoring-probe filters (`sysfs/probe_type_anon`).
    ProbeTypeAnonymous,
    /// Memory-control-group monitoring-probe filters (`sysfs/probe_type_memcg`).
    ProbeTypeMemoryControlGroup,
    /// Monitoring-probe weights (`sysfs/probe_weights`).
    ProbeWeight,
    /// Monitoring-probe preparations (`sysfs/probe_preps`).
    ProbePreparations,
    /// Page-idle probe preparation (`sysfs/probe_prep_set_pgidle`).
    ProbePreparationSetPageIdle,
    /// Page-idle-unset monitoring probes (`sysfs/probe_type_pgidle_unset`).
    ProbeTypePageIdleUnset,
    /// DAMON sample controls (`sysfs/damon_sample_control`).
    SampleControl,
    /// Monitoring-operation attributes (`sysfs/ops_attrs`).
    OperationAttributes,
}

impl SysfsFeature {
    /// Returns the corresponding official `damo` sysfs feature name.
    ///
    /// Low-level attribute-detail variants that are finer grained than the
    /// official capability map return `None`.
    #[must_use]
    pub const fn damo_name(self) -> Option<&'static str> {
        match self {
            Self::VirtualAddressOperation => Some("sysfs/vaddr"),
            Self::PhysicalAddressOperation => Some("sysfs/paddr"),
            Self::FixedVirtualAddressOperation => Some("sysfs/fvaddr"),
            Self::Schemes => Some("sysfs/schemes"),
            Self::SchemeTimeQuota => Some("sysfs/schemes_time_quota"),
            Self::SchemeSizeQuota => Some("sysfs/schemes_size_quota"),
            Self::SchemePrioritization => Some("sysfs/schemes_prioritization"),
            Self::SchemeWatermarks => Some("sysfs/schemes_wmarks"),
            Self::SchemeSuccessfulStats => Some("sysfs/schemes_stat_succ"),
            Self::SchemeQuotaExceededStats => Some("sysfs/schemes_stat_qt_exceed"),
            Self::AvailableOperations => Some("sysfs/avail_ops"),
            Self::OnlineParametersCommit => Some("sysfs/online_params_commit"),
            Self::PeriodicRefresh => Some("sysfs/refresh_ms"),
            Self::AddressUnit => Some("sysfs/addr_unit"),
            Self::ContextPause => Some("sysfs/ctx_pause"),
            Self::AttributeMonitoring => Some("sysfs/attrs_monitoring"),
            Self::SchemeApplyInterval => Some("sysfs/schemes_apply_interval"),
            Self::ObsoleteTarget => Some("sysfs/obsolete_target"),
            Self::InitialRegions => Some("sysfs/init_regions"),
            Self::TriedRegions => Some("sysfs/schemes_tried_regions"),
            Self::TriedRegionsTotalBytes => Some("sysfs/schemes_tried_regions_sz"),
            Self::SchemeFilters => Some("sysfs/schemes_filters"),
            Self::SchemeFilterAnonymous => Some("sysfs/schemes_filters_anon"),
            Self::SchemeFilterMemoryControlGroup => Some("sysfs/schemes_filters_memcg"),
            Self::SchemeFilterAddress => Some("sysfs/schemes_filters_addr"),
            Self::SchemeFilterTarget => Some("sysfs/schemes_filters_target"),
            Self::SchemeFilterYoung => Some("sysfs/schemes_filters_young"),
            Self::SchemeFilterHugePageSize => Some("sysfs/schemes_filters_hugepage_size"),
            Self::SchemeFilterUnmapped => Some("sysfs/schemes_filters_unmapped"),
            Self::SchemeFilterActive => Some("sysfs/schemes_filters_active"),
            Self::SeparateSchemeFilterDirectories => Some("sysfs/schemes_filters_core_ops_dirs"),
            Self::SchemeFilterAllow => Some("sysfs/allow_filter"),
            Self::SchemeQuotaGoals => Some("sysfs/schemes_quota_goals"),
            Self::SchemeQuotaEffectiveBytes => Some("sysfs/schemes_quota_effective_bytes"),
            Self::SchemeQuotaGoalMetric => Some("sysfs/schemes_quota_goal_metric"),
            Self::SchemeQuotaGoalSomePsi => Some("sysfs/schemes_quota_goal_some_psi"),
            Self::SchemeQuotaGoalNodeMemory => Some("sysfs/schemes_quota_goal_node_mem_used_free"),
            Self::SchemeQuotaGoalNodeMemoryControlGroup => {
                Some("sysfs/schemes_quota_goal_node_memcg_used_free")
            }
            Self::SchemeQuotaGoalActiveMemory => Some("sysfs/damos_quota_goal_in_active_mem_bp"),
            Self::SchemeQuotaGoalNodeEligibleMemory => {
                Some("sysfs/damos_quota_goal_node_eligible_mem_bp")
            }
            Self::SchemeQuotaGoalTuner => Some("sysfs/damos_quota_goal_tuner"),
            Self::SchemeQuotaFailureChargeRatio => Some("sysfs/damos_quota_fail_charge_ratio"),
            Self::SchemeMigration => Some("sysfs/schemes_migrate"),
            Self::SchemeDestinations => Some("sysfs/schemes_dests"),
            Self::SchemeOperationsFilterPassedBytes => Some("sysfs/sz_ops_filter_passed"),
            Self::SchemeSnapshotCount => Some("sysfs/damos_stat_nr_snapshots"),
            Self::SchemeMaximumSnapshotCount => Some("sysfs/damos_max_nr_snapshots"),
            Self::CollapseAction => Some("sysfs/damos_action_collapse"),
            Self::MonitoringIntervalsGoal => Some("sysfs/intervals_goal"),
            Self::ProbeTypeAnonymous => Some("sysfs/probe_type_anon"),
            Self::ProbeTypeMemoryControlGroup => Some("sysfs/probe_type_memcg"),
            Self::ProbeWeight => Some("sysfs/probe_weights"),
            Self::ProbePreparations => Some("sysfs/probe_preps"),
            Self::ProbePreparationSetPageIdle => Some("sysfs/probe_prep_set_pgidle"),
            Self::ProbeTypePageIdleUnset => Some("sysfs/probe_type_pgidle_unset"),
            Self::SampleControl => Some("sysfs/damon_sample_control"),
            Self::OperationAttributes => Some("sysfs/ops_attrs"),
            Self::AttributeProbeCount
            | Self::ProbeFilterCount
            | Self::ProbeFilterType
            | Self::ProbeFilterMatching
            | Self::ProbeFilterAllow
            | Self::ProbeFilterPath => None,
        }
    }
}

/// Strength of the evidence observed for a DAMON sysfs capability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum CapabilitySupport {
    /// Support was established from authoritative or usable ABI evidence.
    Supported,
    /// A relevant staged path was absent or a candidate value was rejected.
    Unsupported,
    /// An indexed parent must be staged before support can be observed.
    RequiresStaging,
    /// The visible ABI or an accepted staging value suggests support, but
    /// semantic usability has not been confirmed.
    Unverified,
}

/// The discovery result for one optional sysfs feature.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FeatureCapability {
    feature: SysfsFeature,
    support: CapabilitySupport,
}

/// Discovery result for one DAMON monitoring operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OperationCapability {
    operation: Operation,
    support: CapabilitySupport,
}

impl OperationCapability {
    /// Returns the operation being described.
    #[must_use]
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    /// Returns the observed support state.
    #[must_use]
    pub const fn support(&self) -> CapabilitySupport {
        self.support
    }
}

impl FeatureCapability {
    /// Returns the optional feature being described.
    #[must_use]
    pub const fn feature(self) -> SysfsFeature {
        self.feature
    }

    /// Returns the observed support state.
    #[must_use]
    pub const fn support(self) -> CapabilitySupport {
        self.support
    }
}

/// Runtime capabilities discovered from DAMON sysfs paths and accepted values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capabilities {
    operations: Box<[OperationCapability]>,
    features: Box<[FeatureCapability]>,
    attribute_paths: Box<[String]>,
}

impl Capabilities {
    /// Returns the monitoring operations examined during discovery.
    ///
    /// A kernel-provided `avail_operations` file confirms support. On older
    /// kernels, successful staging writes are reported as
    /// [`CapabilitySupport::Unverified`] because Linux 5.18 accepts recognized
    /// operation names even when their implementations are not registered.
    #[must_use]
    pub fn operations(&self) -> &[OperationCapability] {
        &self.operations
    }

    /// Returns the observed state for an operation, if it was examined.
    #[must_use]
    pub fn operation_support(&self, operation: &Operation) -> Option<CapabilitySupport> {
        self.operations
            .iter()
            .find(|capability| capability.operation == *operation)
            .map(OperationCapability::support)
    }

    /// Returns whether operation support was confirmed.
    #[must_use]
    pub fn supports_operation(&self, operation: &Operation) -> bool {
        self.operation_support(operation) == Some(CapabilitySupport::Supported)
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

    /// Looks up support using an official `damo` sysfs feature name.
    ///
    /// Returns `None` when the name is not part of the `damo` capability map
    /// audited by this crate version.
    #[must_use]
    pub fn damo_feature_support(&self, name: &str) -> Option<CapabilitySupport> {
        self.features
            .iter()
            .find(|capability| capability.feature.damo_name() == Some(name))
            .map(|capability| capability.support())
    }

    /// Returns every concrete attribute path observed below the kdamond.
    ///
    /// Paths are relative to `kdamonds/<N>` and preserve unknown attributes
    /// introduced by newer kernels. Indexed children use the indexes that
    /// were staged when discovery ran.
    #[must_use]
    pub fn attribute_paths(&self) -> &[String] {
        &self.attribute_paths
    }

    /// Returns whether a concrete relative attribute path was observed.
    #[must_use]
    pub fn has_attribute(&self, relative_path: &str) -> bool {
        self.attribute_paths
            .binary_search_by(|path| path.as_str().cmp(relative_path))
            .is_ok()
    }

    pub(crate) fn replace_operations(&mut self, operations: Vec<OperationCapability>) {
        self.operations = operations.into_boxed_slice();
        self.sync_operation_features();
    }

    pub(crate) fn confirm_operation(&mut self, operation: &Operation) {
        if let Some(capability) = self
            .operations
            .iter_mut()
            .find(|capability| capability.operation == *operation)
        {
            capability.support = CapabilitySupport::Supported;
        } else {
            self.operations = self
                .operations
                .iter()
                .cloned()
                .chain([operation_capability(
                    operation.clone(),
                    CapabilitySupport::Supported,
                )])
                .collect::<Vec<_>>()
                .into_boxed_slice();
        }
        self.sync_operation_features();
    }

    pub(crate) fn apply_feature_capabilities(
        &mut self,
        capabilities: impl IntoIterator<Item = FeatureCapability>,
    ) {
        for capability in capabilities {
            set_feature_support(&mut self.features, capability.feature, capability.support);
        }
    }

    fn sync_operation_features(&mut self) {
        for (operation, feature) in [
            (
                Operation::VirtualAddress,
                SysfsFeature::VirtualAddressOperation,
            ),
            (
                Operation::PhysicalAddress,
                SysfsFeature::PhysicalAddressOperation,
            ),
            (
                Operation::FixedVirtualAddress,
                SysfsFeature::FixedVirtualAddressOperation,
            ),
        ] {
            let support = self
                .operation_support(&operation)
                .unwrap_or(CapabilitySupport::Unsupported);
            set_feature_support(&mut self.features, feature, support);
        }
    }
}

/// A DAMOS region-size range in DAMON core address units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSizeRange {
    min: u64,
    max: u64,
}

/// An inclusive range of byte sizes.
///
/// Unlike [`RegionSizeRange`], this range is not scaled by a context's
/// [`AddressUnit`]. Linux uses byte sizes for DAMOS `hugepage_size` filters
/// because those filters compare directly against the underlying folio size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteSizeRange {
    min: u64,
    max: u64,
}

impl ByteSizeRange {
    /// Creates a validated inclusive byte-size range.
    pub const fn new(min: u64, max: u64) -> Result<Self> {
        if min > max {
            return Err(Error::InvalidConfiguration {
                field: "byte size range",
                reason: "minimum must not exceed maximum",
            });
        }
        Ok(Self { min, max })
    }

    /// Returns the inclusive minimum in bytes.
    #[must_use]
    pub const fn min(self) -> u64 {
        self.min
    }

    /// Returns the inclusive maximum in bytes.
    #[must_use]
    pub const fn max(self) -> u64 {
        self.max
    }
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

    pub(crate) fn equivalent_after_kernel_normalization(self, observed: Self) -> bool {
        if self == observed {
            return true;
        }
        self.size.min == observed.size.min
            && self.size.max == u64::MAX
            && observed.size.max == u64::from(u32::MAX)
            && self.accesses == observed.accesses
            && self.age == observed.age
    }

    pub(crate) fn normalize_kernel_width(&mut self, observed: Self) {
        if self.equivalent_after_kernel_normalization(observed) {
            self.size = observed.size;
        }
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
    /// Match pages whose page-idle flag is unset.
    PageIdleUnset,
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
            Self::PageIdleUnset => "pgidle_unset",
            Self::Unknown(name) => name,
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "anon" => Self::Anonymous,
            "memcg" => Self::MemoryControlGroup,
            "pgidle_unset" => Self::PageIdleUnset,
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
        Ok(ConfigurationSnapshot {
            fingerprint: capture_configuration(&self.root)?,
            root: self.root.clone(),
        })
    }
}

/// A `kdamonds/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kdamond {
    path: PathBuf,
}

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

    pub(crate) fn refresh_interval_if_present(&self) -> Result<Option<Duration>> {
        let path = self.path.join("refresh_ms");
        if path_exists(&path)? {
            self.refresh_interval().map(Some)
        } else {
            Ok(None)
        }
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

    /// Discovers features passively in a staged context and scheme.
    ///
    /// Paths below an unstaged probe or probe filter are reported as
    /// [`CapabilitySupport::RequiresStaging`], rather than being confused with
    /// kernel-level absence. Semantic values that require a write probe are
    /// [`CapabilitySupport::Unverified`]. This method never modifies the staged
    /// hierarchy.
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
        let target_count = context.target_count()?;
        let probes = context.path.join("monitoring_attrs/probes");
        let probe_filter = probes.join("0/filters/0");
        let mut features = semantic_feature_capabilities(self, &context, &scheme, target_count)?;

        features.extend(probe_feature_capabilities(
            &context,
            &probes,
            &probe_filter,
        )?);

        let operations = if feature_support(&features, SysfsFeature::AvailableOperations)
            == CapabilitySupport::Supported
        {
            listed_operation_capabilities(context.available_operations()?)
        } else {
            passive_operation_capabilities(context.operation()?)
        };
        let mut capabilities = Capabilities {
            operations: operations.into_boxed_slice(),
            features: features.into_boxed_slice(),
            attribute_paths: observed_attribute_paths(&self.path)?.into_boxed_slice(),
        };
        capabilities.sync_operation_features();
        Ok(capabilities)
    }

    pub(crate) fn configuration_fingerprint(&self) -> Result<ConfigurationFingerprint> {
        capture_configuration(&self.path)
    }

    pub(crate) fn probe_operations(
        &self,
        context_index: usize,
    ) -> Result<Vec<OperationCapability>> {
        let context = self.context(context_index);
        if let Some(operations) = context.available_operations_if_present()? {
            return Ok(listed_operation_capabilities(operations));
        }

        let original = context.operation()?;
        let mut operations = Vec::with_capacity(4);
        if matches!(original, Operation::Unknown(_)) {
            operations.push(operation_capability(
                original.clone(),
                CapabilitySupport::Unverified,
            ));
        }
        let probe_result = (|| {
            for candidate in [
                Operation::VirtualAddress,
                Operation::PhysicalAddress,
                Operation::FixedVirtualAddress,
            ] {
                match context.set_operation(&candidate) {
                    Ok(()) => {
                        let support = if context.operation()? == candidate {
                            CapabilitySupport::Unverified
                        } else {
                            CapabilitySupport::Unsupported
                        };
                        operations.push(operation_capability(candidate, support));
                    }
                    Err(error) if is_unsupported_value_write(&error) => operations.push(
                        operation_capability(candidate, CapabilitySupport::Unsupported),
                    ),
                    Err(error) => return Err(error),
                }
            }
            Ok(operations)
        })();
        let restore_result = context.set_operation(&original);
        match (probe_result, restore_result) {
            (Ok(operations), Ok(())) => Ok(operations),
            (Err(operation), Ok(())) => Err(operation),
            (Ok(_), Err(restore)) => Err(restore),
            (Err(operation), Err(rollback)) => Err(Error::Rollback {
                operation: Box::new(operation),
                rollback: Box::new(rollback),
            }),
        }
    }

    pub(crate) fn stage_optional_capability_children(
        &self,
        context_index: usize,
        target_index: usize,
        scheme_index: usize,
    ) -> Result<()> {
        let context = self.context(context_index);
        let target = context.target(target_index);
        let scheme = context.scheme(scheme_index);
        for path in [
            target.path.join("regions/nr_regions"),
            scheme.path.join("quotas/goals/nr_goals"),
            scheme.path.join("core_filters/nr_filters"),
            scheme.path.join("ops_filters/nr_filters"),
            scheme.path.join("filters/nr_filters"),
            scheme.path.join("dests/nr_dests"),
        ] {
            write_value_if_present(&path, 1_u8)?;
        }
        Ok(())
    }

    pub(crate) fn probe_semantic_filter_capabilities(
        &self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<Vec<FeatureCapability>> {
        let context = self.context(context_index);
        let scheme = context.scheme(scheme_index);
        let scheme_filter_counts = [
            scheme.path.join("filters/nr_filters"),
            scheme.path.join("core_filters/nr_filters"),
            scheme.path.join("ops_filters/nr_filters"),
        ];
        let mut scheme_filter_types = Vec::new();
        for path in &scheme_filter_counts {
            if path_exists(path)? {
                scheme_filter_types.push(path.with_file_name("0").join("type"));
            }
        }
        let mut capabilities = probe_accepted_values(
            &scheme_filter_types,
            &scheme_filter_counts,
            &[
                (SysfsFeature::SchemeFilterAnonymous, "anon"),
                (SysfsFeature::SchemeFilterMemoryControlGroup, "memcg"),
                (SysfsFeature::SchemeFilterAddress, "addr"),
                (SysfsFeature::SchemeFilterTarget, "target"),
                (SysfsFeature::SchemeFilterYoung, "young"),
                (SysfsFeature::SchemeFilterHugePageSize, "hugepage_size"),
                (SysfsFeature::SchemeFilterUnmapped, "unmapped"),
                (SysfsFeature::SchemeFilterActive, "active"),
            ],
        )?;

        let probe_filter_count = context
            .path
            .join("monitoring_attrs/probes/0/filters/nr_filters");
        if path_exists(&probe_filter_count)? {
            capabilities.extend(probe_accepted_values(
                &[probe_filter_count.with_file_name("0").join("type")],
                std::slice::from_ref(&probe_filter_count),
                &[
                    (SysfsFeature::ProbeTypeAnonymous, "anon"),
                    (SysfsFeature::ProbeTypeMemoryControlGroup, "memcg"),
                    (SysfsFeature::ProbeTypePageIdleUnset, "pgidle_unset"),
                ],
            )?);
        }
        Ok(capabilities)
    }
}

fn semantic_feature_capabilities(
    kdamond: &Kdamond,
    context: &Context,
    scheme: &Scheme,
    target_count: usize,
) -> Result<Vec<FeatureCapability>> {
    let mut capabilities = context_semantic_capabilities(kdamond, context)?;
    capabilities.extend(scheme_semantic_capabilities(scheme)?);
    capabilities.extend(target_semantic_capabilities(context, target_count)?);
    capabilities.extend(scheme_filter_capabilities(scheme)?);
    capabilities.extend(quota_goal_capabilities(scheme)?);
    capabilities.extend(probe_semantic_capabilities(context)?);
    Ok(capabilities)
}

fn context_semantic_capabilities(
    kdamond: &Kdamond,
    context: &Context,
) -> Result<Vec<FeatureCapability>> {
    let probes = context.path.join("monitoring_attrs/probes/nr_probes");
    let mut capabilities = [
        SysfsFeature::VirtualAddressOperation,
        SysfsFeature::PhysicalAddressOperation,
        SysfsFeature::FixedVirtualAddressOperation,
    ]
    .into_iter()
    .map(|feature| feature_capability(feature, CapabilitySupport::Unsupported))
    .collect::<Vec<_>>();
    capabilities.extend(path_feature_capabilities([
        (
            SysfsFeature::Schemes,
            context.path.join("schemes/nr_schemes"),
        ),
        (
            SysfsFeature::AvailableOperations,
            context.path.join("avail_operations"),
        ),
        (
            SysfsFeature::OnlineParametersCommit,
            context.path.join("avail_operations"),
        ),
        (
            SysfsFeature::PeriodicRefresh,
            kdamond.path.join("refresh_ms"),
        ),
        (SysfsFeature::AddressUnit, context.path.join("addr_unit")),
        (SysfsFeature::ContextPause, context.path.join("pause")),
        (SysfsFeature::AttributeProbeCount, probes.clone()),
        (SysfsFeature::AttributeMonitoring, probes),
        (
            SysfsFeature::MonitoringIntervalsGoal,
            context
                .path
                .join("monitoring_attrs/intervals/intervals_goal/access_bp"),
        ),
        (
            SysfsFeature::SampleControl,
            context.path.join("monitoring_attrs/sample"),
        ),
        (
            SysfsFeature::OperationAttributes,
            context.path.join("operations_attrs"),
        ),
    ])?);
    Ok(capabilities)
}

fn scheme_semantic_capabilities(scheme: &Scheme) -> Result<Vec<FeatureCapability>> {
    let path = &scheme.path;
    let quotas = path.join("quotas");
    let stats = path.join("stats");
    let tried_regions = path.join("tried_regions");
    let mut capabilities = path_feature_capabilities([
        (SysfsFeature::SchemeTimeQuota, quotas.join("ms")),
        (SysfsFeature::SchemeSizeQuota, quotas.join("bytes")),
        (
            SysfsFeature::SchemePrioritization,
            quotas.join("weights/sz_permil"),
        ),
        (
            SysfsFeature::SchemeWatermarks,
            path.join("watermarks/metric"),
        ),
        (
            SysfsFeature::SchemeSuccessfulStats,
            stats.join("nr_applied"),
        ),
        (
            SysfsFeature::SchemeQuotaExceededStats,
            stats.join("qt_exceeds"),
        ),
        (
            SysfsFeature::SchemeApplyInterval,
            path.join("apply_interval_us"),
        ),
        (
            SysfsFeature::SchemeQuotaGoals,
            quotas.join("goals/nr_goals"),
        ),
        (
            SysfsFeature::SchemeQuotaEffectiveBytes,
            quotas.join("effective_bytes"),
        ),
        (SysfsFeature::SchemeMigration, path.join("target_nid")),
        (
            SysfsFeature::SchemeDestinations,
            path.join("dests/nr_dests"),
        ),
        (
            SysfsFeature::SchemeOperationsFilterPassedBytes,
            stats.join("sz_ops_filter_passed"),
        ),
        (
            SysfsFeature::SchemeSnapshotCount,
            stats.join("nr_snapshots"),
        ),
        (
            SysfsFeature::SchemeMaximumSnapshotCount,
            stats.join("max_nr_snapshots"),
        ),
        (
            SysfsFeature::SchemeQuotaGoalTuner,
            quotas.join("goal_tuner"),
        ),
        (
            SysfsFeature::SchemeQuotaFailureChargeRatio,
            quotas.join("fail_charge_denom"),
        ),
        (
            SysfsFeature::TriedRegionsTotalBytes,
            tried_regions.join("total_bytes"),
        ),
    ])?;
    for (feature, directory) in [
        (SysfsFeature::SchemeFilters, path.join("filters")),
        (
            SysfsFeature::SeparateSchemeFilterDirectories,
            path.join("core_filters"),
        ),
        (SysfsFeature::TriedRegions, tried_regions),
    ] {
        capabilities.push(feature_capability(
            feature,
            support_for_directory(&directory)?,
        ));
    }
    Ok(capabilities)
}

fn target_semantic_capabilities(
    context: &Context,
    target_count: usize,
) -> Result<Vec<FeatureCapability>> {
    let target = context.target(0);
    let support = |path: PathBuf| {
        if target_count == 0 {
            Ok(CapabilitySupport::RequiresStaging)
        } else {
            support_for_path(&path)
        }
    };
    Ok(vec![
        feature_capability(
            SysfsFeature::InitialRegions,
            support(target.path.join("regions/nr_regions"))?,
        ),
        feature_capability(
            SysfsFeature::ObsoleteTarget,
            support(target.path.join("obsolete_target"))?,
        ),
    ])
}

fn scheme_filter_capabilities(scheme: &Scheme) -> Result<Vec<FeatureCapability>> {
    let filters = scheme.path.join("filters");
    let core_filters = scheme.path.join("core_filters");
    let ops_filters = scheme.path.join("ops_filters");
    let support = filter_value_support(&[&filters, &core_filters, &ops_filters])?;
    let mut capabilities = [
        SysfsFeature::SchemeFilterAnonymous,
        SysfsFeature::SchemeFilterMemoryControlGroup,
        SysfsFeature::SchemeFilterAddress,
        SysfsFeature::SchemeFilterTarget,
        SysfsFeature::SchemeFilterYoung,
        SysfsFeature::SchemeFilterHugePageSize,
        SysfsFeature::SchemeFilterUnmapped,
        SysfsFeature::SchemeFilterActive,
    ]
    .into_iter()
    .map(|feature| feature_capability(feature, support))
    .collect::<Vec<_>>();
    capabilities.push(feature_capability(
        SysfsFeature::SchemeFilterAllow,
        indexed_attribute_support(&[
            (
                &ops_filters.join("nr_filters"),
                &ops_filters.join("0/allow"),
            ),
            (&ops_filters.join("nr_filters"), &ops_filters.join("0/pass")),
            (&filters.join("nr_filters"), &filters.join("0/allow")),
            (&filters.join("nr_filters"), &filters.join("0/pass")),
        ])?,
    ));
    Ok(capabilities)
}

fn quota_goal_capabilities(scheme: &Scheme) -> Result<Vec<FeatureCapability>> {
    let quotas = scheme.path.join("quotas");
    let goals = quotas.join("goals");
    let goal = goals.join("0");
    let goal_support = indexed_child_support(&goals.join("nr_goals"), &goal)?;
    let effective_quotas = support_for_path(&quotas.join("effective_bytes"))?;
    let max_snapshots = support_for_path(&scheme.path.join("stats/max_nr_snapshots"))?;
    let failure_charge = support_for_path(&quotas.join("fail_charge_denom"))?;
    Ok(vec![
        feature_capability(SysfsFeature::SchemeQuotaGoalMetric, effective_quotas),
        feature_capability(SysfsFeature::SchemeQuotaGoalSomePsi, effective_quotas),
        feature_capability(
            SysfsFeature::SchemeQuotaGoalNodeMemory,
            child_attribute_support(goal_support, &goal.join("nid"))?,
        ),
        feature_capability(
            SysfsFeature::SchemeQuotaGoalNodeMemoryControlGroup,
            child_attribute_support(goal_support, &goal.join("path"))?,
        ),
        feature_capability(SysfsFeature::SchemeQuotaGoalActiveMemory, max_snapshots),
        feature_capability(
            SysfsFeature::SchemeQuotaGoalNodeEligibleMemory,
            failure_charge,
        ),
        feature_capability(SysfsFeature::CollapseAction, failure_charge),
    ])
}

fn probe_semantic_capabilities(context: &Context) -> Result<Vec<FeatureCapability>> {
    let probes = context.path.join("monitoring_attrs/probes");
    let probe = probes.join("0");
    let probe_support = indexed_child_support(&probes.join("nr_probes"), &probe)?;
    let filter_support = if probe_support == CapabilitySupport::Supported {
        indexed_child_support(&probe.join("filters/nr_filters"), &probe.join("filters/0"))?
    } else {
        probe_support
    };
    let prep_support = if probe_support == CapabilitySupport::Supported {
        support_for_directory(&probe.join("preps"))?
    } else {
        probe_support
    };
    Ok(vec![
        feature_capability(SysfsFeature::ProbeTypeAnonymous, filter_support),
        feature_capability(SysfsFeature::ProbeTypeMemoryControlGroup, filter_support),
        feature_capability(
            SysfsFeature::ProbeWeight,
            child_attribute_support(probe_support, &probe.join("weight"))?,
        ),
        feature_capability(SysfsFeature::ProbePreparations, prep_support),
        feature_capability(SysfsFeature::ProbePreparationSetPageIdle, prep_support),
        feature_capability(SysfsFeature::ProbeTypePageIdleUnset, prep_support),
    ])
}

fn path_feature_capabilities(
    features: impl IntoIterator<Item = (SysfsFeature, PathBuf)>,
) -> Result<Vec<FeatureCapability>> {
    let mut capabilities = Vec::new();
    for (feature, path) in features {
        capabilities.push(feature_capability(feature, support_for_path(&path)?));
    }
    Ok(capabilities)
}

fn probe_feature_capabilities(
    context: &Context,
    probes: &Path,
    probe_filter: &Path,
) -> Result<Vec<FeatureCapability>> {
    let probe_count_support = support_for_path(&probes.join("nr_probes"))?;
    let probe_filter_count_support = match probe_count_support {
        CapabilitySupport::Unsupported => CapabilitySupport::Unsupported,
        CapabilitySupport::RequiresStaging => CapabilitySupport::RequiresStaging,
        CapabilitySupport::Unverified => CapabilitySupport::Unverified,
        CapabilitySupport::Supported if context.probe_count()? == 0 => {
            CapabilitySupport::RequiresStaging
        }
        CapabilitySupport::Supported => support_for_path(&probes.join("0/filters/nr_filters"))?,
    };
    let mut features = vec![feature_capability(
        SysfsFeature::ProbeFilterCount,
        probe_filter_count_support,
    )];

    let attribute_support = match probe_filter_count_support {
        CapabilitySupport::Unsupported => CapabilitySupport::Unsupported,
        CapabilitySupport::RequiresStaging => CapabilitySupport::RequiresStaging,
        CapabilitySupport::Unverified => CapabilitySupport::Unverified,
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
        let support = if attribute_support == CapabilitySupport::Supported {
            support_for_path(&probe_filter.join(name))?
        } else {
            attribute_support
        };
        features.push(feature_capability(feature, support));
    }
    Ok(features)
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

    pub(crate) fn available_operations_if_present(&self) -> Result<Option<Vec<Operation>>> {
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
        configuration::validate_count("probe filter count", count)?;
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
        configuration::validate_token("probe filter type", filter_type.kernel_name())?;
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
        configuration::validate_sysfs_string("probe filter cgroup path", path)?;
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

    pub(crate) fn set_access_pattern_adaptive(&self, pattern: AccessPattern) -> Result<()> {
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

        for (_index, mut path) in numeric_directories(&base)? {
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
            let mut probe_hits = Vec::new();
            if path_is_dir(&probes)? {
                for (probe_index, probe_path) in numeric_directories(&probes)? {
                    let hits = probe_path.join("hits");
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
    /// Call [`Kdamond::command`] with
    /// [`KdamondCommand::UpdateSchemesTriedBytes`] first.
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

fn is_unsupported_value_write(error: &Error) -> bool {
    const LINUX_EINVAL: i32 = 22;

    matches!(
        error,
        Error::Io { source, .. } if source.raw_os_error() == Some(LINUX_EINVAL)
    )
}

fn operation_capability(operation: Operation, support: CapabilitySupport) -> OperationCapability {
    OperationCapability { operation, support }
}

fn known_operations() -> [Operation; 3] {
    [
        Operation::VirtualAddress,
        Operation::PhysicalAddress,
        Operation::FixedVirtualAddress,
    ]
}

fn listed_operation_capabilities(available: Vec<Operation>) -> Vec<OperationCapability> {
    let mut capabilities = known_operations()
        .into_iter()
        .map(|operation| {
            let support = if available.contains(&operation) {
                CapabilitySupport::Supported
            } else {
                CapabilitySupport::Unsupported
            };
            operation_capability(operation, support)
        })
        .collect::<Vec<_>>();
    capabilities.extend(
        available
            .into_iter()
            .filter(|operation| matches!(operation, Operation::Unknown(_)))
            .map(|operation| operation_capability(operation, CapabilitySupport::Supported)),
    );
    capabilities
}

fn passive_operation_capabilities(selected: Operation) -> Vec<OperationCapability> {
    let mut capabilities = known_operations()
        .into_iter()
        .map(|operation| {
            let support = if operation == selected {
                CapabilitySupport::Unverified
            } else {
                CapabilitySupport::RequiresStaging
            };
            operation_capability(operation, support)
        })
        .collect::<Vec<_>>();
    if matches!(selected, Operation::Unknown(_)) {
        capabilities.push(operation_capability(
            selected,
            CapabilitySupport::Unverified,
        ));
    }
    capabilities
}

fn probe_accepted_values(
    value_paths: &[PathBuf],
    reset_count_paths: &[PathBuf],
    candidates: &[(SysfsFeature, &str)],
) -> Result<Vec<FeatureCapability>> {
    let probe_result = (|| {
        let mut capabilities = Vec::with_capacity(candidates.len());
        for &(feature, value) in candidates {
            let mut support = CapabilitySupport::Unsupported;
            for path in value_paths {
                if !path_exists(path)? {
                    continue;
                }
                match write_bytes(path, value.as_bytes()) {
                    Ok(()) if read_text(path)?.trim() == value => {
                        support = CapabilitySupport::Supported;
                        break;
                    }
                    Ok(()) => {}
                    Err(error) if is_unsupported_value_write(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            capabilities.push(feature_capability(feature, support));
        }
        Ok(capabilities)
    })();
    let restore_result = (|| {
        for path in reset_count_paths {
            if path_exists(path)? {
                write_value(path, 1_u8)?;
            }
        }
        Ok(())
    })();
    match (probe_result, restore_result) {
        (Ok(capabilities), Ok(())) => Ok(capabilities),
        (Err(operation), Ok(())) => Err(operation),
        (Ok(_), Err(restore)) => Err(restore),
        (Err(operation), Err(rollback)) => Err(Error::Rollback {
            operation: Box::new(operation),
            rollback: Box::new(rollback),
        }),
    }
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

fn numeric_directories(path: &Path) -> Result<Vec<(usize, PathBuf)>> {
    #[cfg(test)]
    if let Some(result) = test_backend::numeric_directories(path) {
        return result.map_err(|error| io_error("list directory", path, error));
    }

    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error("list directory", path, error)),
    };
    let mut numeric = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| io_error("read directory entry", path, error))?;
        if !entry
            .file_type()
            .map_err(|error| io_error("inspect directory entry", entry.path(), error))?
            .is_dir()
        {
            continue;
        }
        let Some(index) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<usize>().ok())
        else {
            continue;
        };
        numeric.push((index, entry.path()));
    }
    numeric.sort_unstable_by_key(|(index, _)| *index);
    Ok(numeric)
}

fn observed_attribute_paths(root: &Path) -> Result<Vec<String>> {
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

fn capture_configuration(root: &Path) -> Result<ConfigurationFingerprint> {
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

fn all_files_recursive(root: &Path) -> Result<Vec<PathBuf>> {
    #[cfg(test)]
    if let Some(result) = test_backend::all_files_recursive(root) {
        return result.map_err(|error| io_error("walk hierarchy", root, error));
    }

    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| io_error("list directory", &directory, error))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| io_error("read directory entry", &directory, error))?;
            let file_type = entry
                .file_type()
                .map_err(|error| io_error("inspect directory entry", entry.path(), error))?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                files.push(entry.path());
            }
        }
    }
    Ok(files)
}

fn path_is_writable(path: &Path) -> Result<bool> {
    #[cfg(test)]
    if let Some(result) = test_backend::path_is_writable(path) {
        return result.map_err(|error| io_error("inspect permissions", path, error));
    }
    path.metadata()
        .map(|metadata| !metadata.permissions().readonly())
        .map_err(|error| io_error("inspect permissions", path, error))
}

fn support_for_path(path: &Path) -> Result<CapabilitySupport> {
    if path_exists(path)? {
        Ok(CapabilitySupport::Supported)
    } else {
        Ok(CapabilitySupport::Unsupported)
    }
}

fn support_for_directory(path: &Path) -> Result<CapabilitySupport> {
    if path_is_dir(path)? {
        Ok(CapabilitySupport::Supported)
    } else {
        Ok(CapabilitySupport::Unsupported)
    }
}

fn indexed_attribute_support(paths: &[(&Path, &Path)]) -> Result<CapabilitySupport> {
    let mut needs_staging = false;
    for &(count_path, attribute) in paths {
        if path_exists(attribute)? {
            return Ok(CapabilitySupport::Supported);
        }
        if path_exists(count_path)? && read_usize(count_path)? == 0 {
            needs_staging = true;
        }
    }
    if needs_staging {
        return Ok(CapabilitySupport::RequiresStaging);
    }
    Ok(CapabilitySupport::Unsupported)
}

fn indexed_child_support(count_path: &Path, child: &Path) -> Result<CapabilitySupport> {
    if !path_exists(count_path)? {
        return Ok(CapabilitySupport::Unsupported);
    }
    if read_usize(count_path)? == 0 {
        return Ok(CapabilitySupport::RequiresStaging);
    }
    support_for_directory(child)
}

fn child_attribute_support(
    child_support: CapabilitySupport,
    attribute: &Path,
) -> Result<CapabilitySupport> {
    if child_support == CapabilitySupport::Supported {
        support_for_path(attribute)
    } else {
        Ok(child_support)
    }
}

fn filter_value_support(filter_directories: &[&Path]) -> Result<CapabilitySupport> {
    let mut unstaged_child = false;
    for directory in filter_directories {
        if !path_is_dir(directory)? {
            continue;
        }
        let count_path = directory.join("nr_filters");
        if !path_exists(&count_path)? {
            continue;
        }
        if read_usize(&count_path)? == 0 {
            unstaged_child = true;
        } else if path_exists(&directory.join("0/type"))? {
            return Ok(CapabilitySupport::Unverified);
        }
    }
    if unstaged_child {
        Ok(CapabilitySupport::RequiresStaging)
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

fn set_feature_support(
    capabilities: &mut [FeatureCapability],
    feature: SysfsFeature,
    support: CapabilitySupport,
) {
    if let Some(capability) = capabilities
        .iter_mut()
        .find(|capability| capability.feature == feature)
    {
        capability.support = support;
    }
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

fn read_configuration_value_equals(path: &Path, expected: &[u8]) -> Result<bool> {
    #[cfg(test)]
    if let Some(result) = test_backend::read(path) {
        return match result {
            Ok(bytes) => Ok(configuration_bytes_equal(&bytes, expected)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(io_error("read", path, error)),
        };
    }

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io_error("open for reading", path, error)),
    };
    let mut matched = 0;
    let mut newline_seen = false;
    let mut bytes = [0_u8; 256];
    loop {
        let read = file
            .read(&mut bytes)
            .map_err(|error| io_error("read", path, error))?;
        if read == 0 {
            break;
        }
        if !match_configuration_chunk(&bytes[..read], expected, &mut matched, &mut newline_seen) {
            return Ok(false);
        }
    }
    Ok(matched == expected.len())
}

#[cfg(test)]
fn configuration_bytes_equal(bytes: &[u8], expected: &[u8]) -> bool {
    let mut matched = 0;
    let mut newline_seen = false;
    match_configuration_chunk(bytes, expected, &mut matched, &mut newline_seen)
        && matched == expected.len()
}

fn match_configuration_chunk(
    bytes: &[u8],
    expected: &[u8],
    matched: &mut usize,
    newline_seen: &mut bool,
) -> bool {
    for &byte in bytes {
        if *matched < expected.len() {
            if byte != expected[*matched] {
                return false;
            }
            *matched += 1;
        } else {
            if *newline_seen || byte != b'\n' {
                return false;
            }
            *newline_seen = true;
        }
    }
    true
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

fn write_value_if_present(path: &Path, value: impl fmt::Display) -> Result<bool> {
    if !path_exists(path)? {
        return Ok(false);
    }
    write_value(path, value)?;
    Ok(true)
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

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub(crate) struct ModelSchemeStats {
        pub(crate) nr_tried: u64,
        pub(crate) sz_tried: u64,
        pub(crate) nr_applied: u64,
        pub(crate) sz_applied: u64,
        pub(crate) sz_ops_filter_passed: u64,
        pub(crate) qt_exceeds: u64,
        pub(crate) nr_snapshots: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) enum Mutation {
        SetFile { path: PathBuf, value: Vec<u8> },
        RemoveTree { path: PathBuf },
        StartKdamond { path: PathBuf },
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

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct WriteFailure {
        path: PathBuf,
        raw_os_error: i32,
    }

    #[derive(Debug)]
    struct State {
        nodes: BTreeMap<PathBuf, Node>,
        extension_files: BTreeMap<PathBuf, Vec<u8>>,
        available_operations: Vec<u8>,
        recognized_operations: Vec<u8>,
        expose_available_operations: bool,
        expose_current_damo_extensions: bool,
        supported_scheme_filter_types: Vec<u8>,
        supported_probe_filter_types: Vec<u8>,
        active_files: Option<BTreeMap<PathBuf, Vec<u8>>>,
        next_kdamond_pid: u32,
        tried_regions: Vec<ModelRegion>,
        scheme_stats: Vec<ModelSchemeStats>,
        effective_quota_bytes: Vec<u64>,
        hooks: Vec<Hook>,
        write_failures: Vec<WriteFailure>,
        write_count: usize,
    }

    impl State {
        fn new(
            available_operations: &str,
            recognized_operations: &str,
            expose_available_operations: bool,
        ) -> Self {
            let mut state = Self {
                nodes: BTreeMap::new(),
                extension_files: BTreeMap::new(),
                available_operations: available_operations.as_bytes().to_vec(),
                recognized_operations: recognized_operations.as_bytes().to_vec(),
                expose_available_operations,
                expose_current_damo_extensions: false,
                supported_scheme_filter_types:
                    b"anon\nmemcg\nyoung\naddr\ntarget\nhugepage_size\nunmapped\nactive\n".to_vec(),
                supported_probe_filter_types: b"anon\nmemcg\n".to_vec(),
                active_files: None,
                next_kdamond_pid: 10_000,
                tried_regions: Vec::new(),
                scheme_stats: Vec::new(),
                effective_quota_bytes: Vec::new(),
                hooks: Vec::new(),
                write_failures: Vec::new(),
                write_count: 0,
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

        fn restore_extension_files(&mut self) {
            let files = self.extension_files.clone();
            for (path, value) in files {
                if path
                    .parent()
                    .is_some_and(|parent| matches!(self.nodes.get(parent), Some(Node::Directory)))
                {
                    self.file(path, &value);
                }
            }
        }

        fn finish_reconstruction(&mut self) -> bool {
            self.restore_extension_files();
            true
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
            if self.expose_available_operations {
                let operations = self.available_operations.clone();
                self.file(base.join("avail_operations"), &operations);
            }
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
            if self.expose_current_damo_extensions {
                self.directory(base.join("operations_attrs"));
                self.file(base.join("operations_attrs/use_reports"), b"N\n");
                self.file(base.join("operations_attrs/write_only"), b"N\n");
                self.file(base.join("operations_attrs/cpus"), b"all\n");
                self.file(base.join("operations_attrs/tids"), b"\n");
                self.directory(base.join("monitoring_attrs/sample"));
                self.directory(base.join("monitoring_attrs/sample/primitives"));
                self.file(
                    base.join("monitoring_attrs/sample/primitives/page_table"),
                    b"Y\n",
                );
                self.file(
                    base.join("monitoring_attrs/sample/primitives/page_fault"),
                    b"N\n",
                );
                self.directory(base.join("monitoring_attrs/sample/filters"));
                self.file(
                    base.join("monitoring_attrs/sample/filters/nr_filters"),
                    b"0\n",
                );
            }
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
            self.file(base.join("target_nid"), b"-1\n");
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
            self.file(base.join("quotas/effective_bytes"), b"0\n");
            self.file(base.join("quotas/goal_tuner"), b"consist\n");
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
            for name in [
                "nr_tried",
                "sz_tried",
                "nr_applied",
                "sz_applied",
                "sz_ops_filter_passed",
                "qt_exceeds",
                "nr_snapshots",
                "max_nr_snapshots",
            ] {
                self.file(base.join("stats").join(name), b"0\n");
            }
            self.directory(base.join("tried_regions"));
            self.file(base.join("tried_regions/total_bytes"), b"0\n");
        }

        fn create_probe(&mut self, base: &Path, index: usize) {
            let base = base.join(index.to_string());
            self.directory(&base);
            self.directory(base.join("filters"));
            self.file(base.join("filters/nr_filters"), b"0\n");
            if self.expose_current_damo_extensions {
                self.file(base.join("weight"), b"0\n");
                self.directory(base.join("preps"));
                self.file(base.join("preps/nr_preps"), b"0\n");
            }
        }

        fn create_probe_preparation(&mut self, base: &Path, index: usize) {
            let base = base.join(index.to_string());
            self.directory(&base);
            self.file(base.join("prep_action"), b"set_pgidle\n");
        }

        fn create_sample_filter(&mut self, base: &Path, index: usize) {
            let base = base.join(index.to_string());
            self.directory(&base);
            self.file(base.join("type"), b"write\n");
            self.file(base.join("matching"), b"N\n");
            self.file(base.join("allow"), b"N\n");
            self.file(base.join("cpumask"), b"\n");
            self.file(base.join("tid_arr"), b"\n");
        }

        fn create_probe_filter(&mut self, base: &Path, index: usize) {
            let base = base.join(index.to_string());
            self.directory(&base);
            self.file(base.join("type"), b"anon\n");
            self.file(base.join("matching"), b"N\n");
            self.file(base.join("allow"), b"N\n");
            self.file(base.join("path"), b"\n");
        }

        fn create_scheme_filter(&mut self, base: &Path, index: usize) {
            let base = base.join(index.to_string());
            self.directory(&base);
            self.file(base.join("type"), b"anon\n");
            self.file(base.join("matching"), b"N\n");
            self.file(base.join("allow"), b"N\n");
            self.file(base.join("memcg_path"), b"\n");
            for name in ["addr_start", "addr_end", "damon_target_idx", "min", "max"] {
                self.file(base.join(name), b"0\n");
            }
        }

        fn create_quota_goal(&mut self, base: &Path, index: usize) {
            let base = base.join(index.to_string());
            self.directory(&base);
            self.file(base.join("target_metric"), b"user_input\n");
            for name in ["target_value", "current_value", "nid"] {
                self.file(base.join(name), b"0\n");
            }
            self.file(base.join("path"), b"\n");
        }

        fn create_destination(&mut self, base: &Path, index: usize) {
            let base = base.join(index.to_string());
            self.directory(&base);
            self.file(base.join("id"), b"0\n");
            self.file(base.join("weight"), b"0\n");
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

        #[allow(clippy::too_many_lines)]
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
                return Ok(self.finish_reconstruction());
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
                return Ok(self.finish_reconstruction());
            }
            if path_text.ends_with("/targets/nr_targets") {
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    self.create_target(parent, index);
                }
                return Ok(self.finish_reconstruction());
            }
            if path_text.ends_with("/schemes/nr_schemes") {
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    self.create_scheme(parent, index);
                }
                return Ok(self.finish_reconstruction());
            }
            if path_text.ends_with("/monitoring_attrs/probes/nr_probes") {
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    self.create_probe(parent, index);
                }
                return Ok(self.finish_reconstruction());
            }
            if path_text.ends_with("/preps/nr_preps") {
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    self.create_probe_preparation(parent, index);
                }
                return Ok(self.finish_reconstruction());
            }
            if path_text.ends_with("/filters/nr_filters")
                || path_text.ends_with("/core_filters/nr_filters")
                || path_text.ends_with("/ops_filters/nr_filters")
            {
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    if path_text.contains("/monitoring_attrs/sample/filters/") {
                        self.create_sample_filter(parent, index);
                    } else if path_text.contains("/monitoring_attrs/probes/") {
                        self.create_probe_filter(parent, index);
                    } else {
                        self.create_scheme_filter(parent, index);
                    }
                }
                return Ok(self.finish_reconstruction());
            }
            if path_text.ends_with("/quotas/goals/nr_goals") {
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    self.create_quota_goal(parent, index);
                }
                return Ok(self.finish_reconstruction());
            }
            if path_text.ends_with("/dests/nr_dests") {
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    self.create_destination(parent, index);
                }
                return Ok(self.finish_reconstruction());
            }
            if path_text.ends_with("/regions/nr_regions") {
                let parent = path.parent().expect("count path has parent");
                self.remove_indexed_children(parent);
                for index in 0..count {
                    self.create_target_region(parent, index);
                }
                return Ok(self.finish_reconstruction());
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

        fn materialize_scheme_stats(&mut self, kdamond: &Path) {
            let stats = self.scheme_stats.clone();
            for (index, stats) in stats.iter().enumerate() {
                let base = kdamond
                    .join("contexts/0/schemes")
                    .join(index.to_string())
                    .join("stats");
                if !self.nodes.contains_key(&base) {
                    break;
                }
                for (name, value) in [
                    ("nr_tried", stats.nr_tried),
                    ("sz_tried", stats.sz_tried),
                    ("nr_applied", stats.nr_applied),
                    ("sz_applied", stats.sz_applied),
                    ("sz_ops_filter_passed", stats.sz_ops_filter_passed),
                    ("qt_exceeds", stats.qt_exceeds),
                    ("nr_snapshots", stats.nr_snapshots),
                ] {
                    self.file(base.join(name), format!("{value}\n").as_bytes());
                }
            }
        }

        fn materialize_effective_quotas(&mut self, kdamond: &Path) {
            let quotas = self.effective_quota_bytes.clone();
            for (index, effective_bytes) in quotas.into_iter().enumerate() {
                let path = kdamond
                    .join("contexts/0/schemes")
                    .join(index.to_string())
                    .join("quotas/effective_bytes");
                if !self.nodes.contains_key(&path) {
                    break;
                }
                self.file(path, format!("{effective_bytes}\n").as_bytes());
            }
        }

        fn start_kdamond(&mut self, kdamond: &Path) -> io::Result<()> {
            let operations = kdamond.join("contexts/0/operations");
            let selected = match self.nodes.get(&operations) {
                Some(Node::File(value)) => std::str::from_utf8(value)
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?
                    .trim(),
                _ => return Err(io::Error::from_raw_os_error(22)),
            };
            if !listed_value_contains(&self.available_operations, selected) {
                return Err(io::Error::from_raw_os_error(22));
            }
            self.capture_active_files();
            self.next_kdamond_pid += 1;
            self.file(kdamond.join("state"), b"on\n");
            self.file(
                kdamond.join("pid"),
                format!("{}\n", self.next_kdamond_pid).as_bytes(),
            );
            Ok(())
        }

        fn write_state(&mut self, path: &Path, value: &[u8]) -> io::Result<()> {
            let command = std::str::from_utf8(value)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 command"))?
                .trim();
            let kdamond = path.parent().expect("state path has parent");
            match command {
                "on" => {
                    let context_count = kdamond.join("contexts/nr_contexts");
                    if !matches!(
                        self.nodes.get(&context_count),
                        Some(Node::File(value)) if value == b"1\n"
                    ) {
                        return Err(io::Error::from_raw_os_error(22));
                    }
                    if matches!(self.nodes.get(path), Some(Node::File(value)) if value == b"on\n") {
                        return Err(io::Error::from_raw_os_error(16));
                    }
                    self.start_kdamond(kdamond)?;
                }
                "off" => {
                    if self.active_files.is_none() {
                        return Err(io::Error::from_raw_os_error(22));
                    }
                    if !matches!(self.nodes.get(path), Some(Node::File(value)) if value == b"on\n")
                    {
                        return Err(io::Error::from_raw_os_error(1));
                    }
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
                "update_schemes_stats" => {
                    self.ensure_running(path)?;
                    self.materialize_scheme_stats(kdamond);
                }
                "update_schemes_effective_quotas" => {
                    self.ensure_running(path)?;
                    self.materialize_effective_quotas(kdamond);
                }
                "update_tuned_intervals" => self.ensure_running(path)?,
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
            if let Some(index) = self
                .write_failures
                .iter()
                .position(|failure| failure.path == path)
            {
                let failure = self.write_failures.remove(index);
                return Err(io::Error::from_raw_os_error(failure.raw_os_error));
            }

            match self.nodes.get(path) {
                Some(Node::File(_)) => {}
                Some(Node::Directory) => return Err(io::Error::from(io::ErrorKind::IsADirectory)),
                None => return Err(not_found(path)),
            }

            if path.file_name().is_some_and(|name| name == "state") {
                return self.write_state(path, value);
            }

            if path.file_name().is_some_and(|name| name == "operations") {
                let requested = std::str::from_utf8(value)
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?
                    .trim();
                if !listed_value_contains(&self.recognized_operations, requested) {
                    return Err(io::Error::from_raw_os_error(22));
                }
            }

            if path.file_name().is_some_and(|name| name == "type") {
                let requested = std::str::from_utf8(value)
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?
                    .trim();
                let path_text = path.to_string_lossy();
                let supported = if path_text.contains("/monitoring_attrs/probes/") {
                    listed_value_contains(&self.supported_probe_filter_types, requested)
                } else if path_text.contains("/schemes/")
                    && (path_text.contains("/filters/")
                        || path_text.contains("/core_filters/")
                        || path_text.contains("/ops_filters/"))
                {
                    listed_value_contains(&self.supported_scheme_filter_types, requested)
                } else {
                    true
                };
                if !supported {
                    return Err(io::Error::from_raw_os_error(22));
                }
            }

            let path_text = path.to_string_lossy();
            if path_text == "kdamonds/nr_kdamonds"
                || path_text.ends_with("/contexts/nr_contexts")
                || path_text.ends_with("/targets/nr_targets")
                || path_text.ends_with("/schemes/nr_schemes")
                || path_text.ends_with("/monitoring_attrs/probes/nr_probes")
                || path_text.ends_with("/preps/nr_preps")
                || path_text.ends_with("/filters/nr_filters")
                || path_text.ends_with("/core_filters/nr_filters")
                || path_text.ends_with("/ops_filters/nr_filters")
                || path_text.ends_with("/quotas/goals/nr_goals")
                || path_text.ends_with("/dests/nr_dests")
                || path_text.ends_with("/regions/nr_regions")
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
                    Mutation::StartKdamond { path } => self
                        .start_kdamond(&path)
                        .expect("modeled external kdamond start must be valid"),
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
            Self::with_operation_sets(available_operations, available_operations, true)
        }

        pub(crate) fn without_available_operations_file(available_operations: &str) -> Self {
            Self::with_operation_sets(available_operations, available_operations, false)
        }

        pub(crate) fn with_legacy_operation_sets(
            available_operations: &str,
            recognized_operations: &str,
        ) -> Self {
            Self::with_operation_sets(available_operations, recognized_operations, false)
        }

        fn with_operation_sets(
            available_operations: &str,
            recognized_operations: &str,
            expose_available_operations: bool,
        ) -> Self {
            static NEXT_MODEL: AtomicU64 = AtomicU64::new(0);
            let root = PathBuf::from(format!(
                "/__damon_rs_model/{}-{}",
                std::process::id(),
                NEXT_MODEL.fetch_add(1, Ordering::Relaxed)
            ));
            let state = Arc::new(Mutex::new(State::new(
                available_operations,
                recognized_operations,
                expose_available_operations,
            )));
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

        pub(crate) fn set_scheme_stats(&self, stats: Vec<ModelSchemeStats>) {
            lock(&self.state).scheme_stats = stats;
        }

        pub(crate) fn set_effective_quota_bytes(&self, quotas: Vec<u64>) {
            lock(&self.state).effective_quota_bytes = quotas;
        }

        pub(crate) fn set_supported_scheme_filter_types(&self, types: &str) {
            lock(&self.state).supported_scheme_filter_types = types.as_bytes().to_vec();
        }

        pub(crate) fn set_supported_probe_filter_types(&self, types: &str) {
            lock(&self.state).supported_probe_filter_types = types.as_bytes().to_vec();
        }

        pub(crate) fn enable_current_damo_extensions(&self) {
            let mut state = lock(&self.state);
            state.expose_current_damo_extensions = true;
            state.supported_probe_filter_types = b"anon\nmemcg\npgidle_unset\n".to_vec();
        }

        pub(crate) fn remove_tree(&self, path: impl AsRef<Path>) {
            lock(&self.state).remove_tree(path.as_ref());
        }

        pub(crate) fn set_file(&self, path: impl Into<PathBuf>, value: &[u8]) {
            let path = path.into();
            let mut state = lock(&self.state);
            if !state.nodes.contains_key(&path) {
                state.extension_files.insert(path.clone(), value.to_vec());
            }
            state.file(path, value);
        }

        pub(crate) fn value(&self, path: impl AsRef<Path>) -> Option<String> {
            match lock(&self.state).nodes.get(path.as_ref())? {
                Node::File(value) => Some(String::from_utf8_lossy(value).trim().to_owned()),
                Node::Directory => None,
            }
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

        pub(crate) fn fail_next_write(&self, path: impl Into<PathBuf>, raw_os_error: i32) {
            lock(&self.state).write_failures.push(WriteFailure {
                path: path.into(),
                raw_os_error,
            });
        }

        pub(crate) fn write_count(&self) -> usize {
            lock(&self.state).write_count
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

    fn listed_value_contains(values: &[u8], requested: &str) -> bool {
        std::str::from_utf8(values)
            .expect("modeled capability values are UTF-8")
            .lines()
            .map(str::trim)
            .any(|value| value == requested)
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

    pub(super) fn numeric_directories(path: &Path) -> Option<io::Result<Vec<(usize, PathBuf)>>> {
        let (state, relative) = resolve(path)?;
        let state = lock(&state);
        if !matches!(state.nodes.get(&relative), Some(Node::Directory)) {
            return Some(if state.nodes.contains_key(&relative) {
                Err(io::Error::from(io::ErrorKind::NotADirectory))
            } else {
                Ok(Vec::new())
            });
        }
        let mut numeric = state
            .nodes
            .iter()
            .filter_map(|(candidate, node)| {
                if !matches!(node, Node::Directory) || candidate.parent() != Some(&relative) {
                    return None;
                }
                let index = candidate.file_name()?.to_str()?.parse::<usize>().ok()?;
                Some((index, path.join(index.to_string())))
            })
            .collect::<Vec<_>>();
        numeric.sort_unstable_by_key(|(index, _)| *index);
        Some(Ok(numeric))
    }

    pub(super) fn all_files_recursive(path: &Path) -> Option<io::Result<Vec<PathBuf>>> {
        let (state, relative) = resolve(path)?;
        let state = lock(&state);
        if !matches!(state.nodes.get(&relative), Some(Node::Directory)) {
            return Some(Err(not_found(&relative)));
        }
        Some(Ok(state
            .nodes
            .iter()
            .filter_map(|(candidate, node)| {
                if !matches!(node, Node::File(_)) || !candidate.starts_with(&relative) {
                    return None;
                }
                Some(path.join(candidate.strip_prefix(&relative).ok()?))
            })
            .collect()))
    }

    pub(super) fn path_is_writable(path: &Path) -> Option<io::Result<bool>> {
        let (state, relative) = resolve(path)?;
        Some(match lock(&state).nodes.get(&relative) {
            Some(Node::File(_)) => Ok(true),
            Some(Node::Directory) => Err(io::Error::from(io::ErrorKind::IsADirectory)),
            None => Err(not_found(&relative)),
        })
    }

    pub(super) fn read(path: &Path) -> Option<io::Result<Vec<u8>>> {
        let (state, relative) = resolve(path)?;
        let mut state = lock(&state);
        let result = match state.nodes.get(&relative) {
            Some(Node::File(value)) => Ok(value.clone()),
            Some(Node::Directory) => Err(io::Error::from(io::ErrorKind::IsADirectory)),
            None => Err(not_found(&relative)),
        };
        state.apply_hooks(&HookEvent::Read(relative));
        Some(result)
    }

    pub(super) fn write(path: &Path, value: &[u8]) -> Option<io::Result<()>> {
        let (state, relative) = resolve(path)?;
        let mut state = lock(&state);
        let result = state.write(&relative, value);
        if result.is_ok() {
            state.write_count += 1;
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
    #[allow(clippy::too_many_lines)]
    fn semantic_features_match_the_official_damo_sysfs_map() {
        let expected = [
            (SysfsFeature::VirtualAddressOperation, "sysfs/vaddr"),
            (SysfsFeature::SchemeTimeQuota, "sysfs/schemes_time_quota"),
            (SysfsFeature::PhysicalAddressOperation, "sysfs/paddr"),
            (SysfsFeature::InitialRegions, "sysfs/init_regions"),
            (SysfsFeature::Schemes, "sysfs/schemes"),
            (
                SysfsFeature::SchemeSuccessfulStats,
                "sysfs/schemes_stat_succ",
            ),
            (SysfsFeature::SchemeSizeQuota, "sysfs/schemes_size_quota"),
            (
                SysfsFeature::SchemeQuotaExceededStats,
                "sysfs/schemes_stat_qt_exceed",
            ),
            (SysfsFeature::SchemeWatermarks, "sysfs/schemes_wmarks"),
            (
                SysfsFeature::SchemePrioritization,
                "sysfs/schemes_prioritization",
            ),
            (SysfsFeature::AvailableOperations, "sysfs/avail_ops"),
            (SysfsFeature::FixedVirtualAddressOperation, "sysfs/fvaddr"),
            (
                SysfsFeature::OnlineParametersCommit,
                "sysfs/online_params_commit",
            ),
            (SysfsFeature::TriedRegions, "sysfs/schemes_tried_regions"),
            (SysfsFeature::SchemeFilters, "sysfs/schemes_filters"),
            (
                SysfsFeature::SchemeFilterAnonymous,
                "sysfs/schemes_filters_anon",
            ),
            (
                SysfsFeature::SchemeFilterMemoryControlGroup,
                "sysfs/schemes_filters_memcg",
            ),
            (
                SysfsFeature::TriedRegionsTotalBytes,
                "sysfs/schemes_tried_regions_sz",
            ),
            (
                SysfsFeature::SchemeFilterAddress,
                "sysfs/schemes_filters_addr",
            ),
            (
                SysfsFeature::SchemeFilterTarget,
                "sysfs/schemes_filters_target",
            ),
            (
                SysfsFeature::SchemeApplyInterval,
                "sysfs/schemes_apply_interval",
            ),
            (SysfsFeature::SchemeQuotaGoals, "sysfs/schemes_quota_goals"),
            (
                SysfsFeature::SchemeQuotaEffectiveBytes,
                "sysfs/schemes_quota_effective_bytes",
            ),
            (
                SysfsFeature::SchemeQuotaGoalMetric,
                "sysfs/schemes_quota_goal_metric",
            ),
            (
                SysfsFeature::SchemeQuotaGoalSomePsi,
                "sysfs/schemes_quota_goal_some_psi",
            ),
            (
                SysfsFeature::SchemeFilterYoung,
                "sysfs/schemes_filters_young",
            ),
            (SysfsFeature::SchemeMigration, "sysfs/schemes_migrate"),
            (
                SysfsFeature::SchemeOperationsFilterPassedBytes,
                "sysfs/sz_ops_filter_passed",
            ),
            (SysfsFeature::SchemeFilterAllow, "sysfs/allow_filter"),
            (
                SysfsFeature::SchemeFilterHugePageSize,
                "sysfs/schemes_filters_hugepage_size",
            ),
            (
                SysfsFeature::SchemeFilterUnmapped,
                "sysfs/schemes_filters_unmapped",
            ),
            (
                SysfsFeature::MonitoringIntervalsGoal,
                "sysfs/intervals_goal",
            ),
            (
                SysfsFeature::SeparateSchemeFilterDirectories,
                "sysfs/schemes_filters_core_ops_dirs",
            ),
            (
                SysfsFeature::SchemeFilterActive,
                "sysfs/schemes_filters_active",
            ),
            (
                SysfsFeature::SchemeQuotaGoalNodeMemory,
                "sysfs/schemes_quota_goal_node_mem_used_free",
            ),
            (SysfsFeature::SchemeDestinations, "sysfs/schemes_dests"),
            (SysfsFeature::PeriodicRefresh, "sysfs/refresh_ms"),
            (SysfsFeature::AddressUnit, "sysfs/addr_unit"),
            (
                SysfsFeature::SchemeQuotaGoalNodeMemoryControlGroup,
                "sysfs/schemes_quota_goal_node_memcg_used_free",
            ),
            (SysfsFeature::ObsoleteTarget, "sysfs/obsolete_target"),
            (
                SysfsFeature::SchemeSnapshotCount,
                "sysfs/damos_stat_nr_snapshots",
            ),
            (
                SysfsFeature::SchemeMaximumSnapshotCount,
                "sysfs/damos_max_nr_snapshots",
            ),
            (
                SysfsFeature::SchemeQuotaGoalActiveMemory,
                "sysfs/damos_quota_goal_in_active_mem_bp",
            ),
            (
                SysfsFeature::SchemeQuotaGoalTuner,
                "sysfs/damos_quota_goal_tuner",
            ),
            (SysfsFeature::CollapseAction, "sysfs/damos_action_collapse"),
            (
                SysfsFeature::SchemeQuotaGoalNodeEligibleMemory,
                "sysfs/damos_quota_goal_node_eligible_mem_bp",
            ),
            (SysfsFeature::ContextPause, "sysfs/ctx_pause"),
            (
                SysfsFeature::SchemeQuotaFailureChargeRatio,
                "sysfs/damos_quota_fail_charge_ratio",
            ),
            (SysfsFeature::AttributeMonitoring, "sysfs/attrs_monitoring"),
            (SysfsFeature::ProbeTypeAnonymous, "sysfs/probe_type_anon"),
            (
                SysfsFeature::ProbeTypeMemoryControlGroup,
                "sysfs/probe_type_memcg",
            ),
            (SysfsFeature::ProbeWeight, "sysfs/probe_weights"),
            (SysfsFeature::ProbePreparations, "sysfs/probe_preps"),
            (
                SysfsFeature::ProbePreparationSetPageIdle,
                "sysfs/probe_prep_set_pgidle",
            ),
            (
                SysfsFeature::ProbeTypePageIdleUnset,
                "sysfs/probe_type_pgidle_unset",
            ),
            (SysfsFeature::SampleControl, "sysfs/damon_sample_control"),
            (SysfsFeature::OperationAttributes, "sysfs/ops_attrs"),
        ];

        assert_eq!(expected.len(), 57);
        let names = expected
            .iter()
            .map(|(feature, expected_name)| {
                assert_eq!(feature.damo_name(), Some(*expected_name));
                *expected_name
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names.len(), expected.len());
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
    fn fingerprint_comparison_streams_long_values_without_losing_spaces() {
        let expected = format!("  {}  ", "x".repeat(600));
        let fixture = TempFile::new(&format!("{expected}\n"));

        assert!(
            read_configuration_value_equals(&fixture.path, expected.as_bytes())
                .expect("compare long unchanged value")
        );
        assert!(
            !read_configuration_value_equals(&fixture.path, expected.trim().as_bytes())
                .expect("preserve surrounding spaces")
        );
        assert!(
            !read_configuration_value_equals(&fixture.path, b"different")
                .expect("detect changed value")
        );
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
    fn modeled_output_commands_materialize_stats_and_effective_quotas() {
        let model = test_backend::Model::new("vaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        kdamond.set_context_count(1).expect("stage context");
        let context = kdamond.context(0);
        context.set_scheme_count(2).expect("stage schemes");
        let first = context.scheme(0);
        let second = context.scheme(1);
        write_value(&first.path().join("stats/max_nr_snapshots"), 19)
            .expect("stage maximum snapshots");
        kdamond.command(KdamondCommand::On).expect("start model");

        model.set_scheme_stats(vec![
            test_backend::ModelSchemeStats {
                nr_tried: 1,
                sz_tried: 2,
                nr_applied: 3,
                sz_applied: 4,
                sz_ops_filter_passed: 5,
                qt_exceeds: 6,
                nr_snapshots: 7,
            },
            test_backend::ModelSchemeStats {
                nr_tried: 11,
                sz_tried: 12,
                nr_applied: 13,
                sz_applied: 14,
                sz_ops_filter_passed: 15,
                qt_exceeds: 16,
                nr_snapshots: 17,
            },
        ]);
        model.set_effective_quota_bytes(vec![4_096, 8_192]);

        assert_eq!(
            read_u64(&first.path().join("stats/nr_tried")).expect("read stale stats"),
            0
        );
        assert_eq!(
            read_u64(&first.path().join("quotas/effective_bytes"))
                .expect("read stale effective quota"),
            0
        );

        kdamond
            .command(KdamondCommand::UpdateSchemesStats)
            .expect("refresh modeled stats");
        for (scheme, expected) in [
            (&first, [1, 2, 3, 4, 5, 6, 7]),
            (&second, [11, 12, 13, 14, 15, 16, 17]),
        ] {
            for (name, value) in [
                "nr_tried",
                "sz_tried",
                "nr_applied",
                "sz_applied",
                "sz_ops_filter_passed",
                "qt_exceeds",
                "nr_snapshots",
            ]
            .into_iter()
            .zip(expected)
            {
                assert_eq!(
                    read_u64(&scheme.path().join("stats").join(name))
                        .expect("read refreshed stats"),
                    value
                );
            }
        }
        assert_eq!(
            read_u64(&first.path().join("stats/max_nr_snapshots"))
                .expect("read configured maximum snapshots"),
            19
        );
        assert_eq!(
            read_u64(&first.path().join("quotas/effective_bytes"))
                .expect("stats command must not update quota"),
            0
        );

        kdamond
            .command(KdamondCommand::UpdateSchemesEffectiveQuotas)
            .expect("refresh modeled effective quotas");
        assert_eq!(
            read_u64(&first.path().join("quotas/effective_bytes"))
                .expect("read first effective quota"),
            4_096
        );
        assert_eq!(
            read_u64(&second.path().join("quotas/effective_bytes"))
                .expect("read second effective quota"),
            8_192
        );
        assert_typed_scheme_output(&first, &second);
    }

    fn assert_typed_scheme_output(first: &Scheme, second: &Scheme) {
        assert_eq!(
            first.stats().expect("read typed scheme stats"),
            SchemeStats {
                regions_tried: 1,
                size_tried_units: 2,
                regions_applied: 3,
                size_applied_units: 4,
                operations_filter_passed_units: Some(5),
                quota_exceeds: 6,
                snapshots: Some(7),
                maximum_snapshots: Some(19),
            }
        );
        assert_eq!(
            second
                .quotas()
                .effective_size_units()
                .expect("read typed effective quota"),
            8_192
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

    #[test]
    fn modeled_state_transitions_match_linux_errors() {
        let model = test_backend::Model::new("vaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);

        let error = kdamond
            .command(KdamondCommand::On)
            .expect_err("starting without one context must fail");
        assert!(matches!(
            error,
            Error::Io { source, .. } if source.raw_os_error() == Some(22)
        ));

        kdamond.set_context_count(1).expect("stage context");
        kdamond.command(KdamondCommand::On).expect("start model");
        let error = kdamond
            .command(KdamondCommand::On)
            .expect_err("starting an active kdamond must be busy");
        assert!(error.is_resource_busy());

        kdamond.command(KdamondCommand::Off).expect("stop model");
        let error = kdamond
            .command(KdamondCommand::Off)
            .expect_err("stopping an inactive context must fail");
        assert!(matches!(
            error,
            Error::Io { source, .. } if source.raw_os_error() == Some(1)
        ));
    }

    #[test]
    fn modeled_indexed_children_match_linux_7_2_layout() {
        let model = test_backend::Model::new("vaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let context = admin.kdamond(0).context(0);
        admin
            .kdamond(0)
            .set_context_count(1)
            .expect("stage context");
        context.set_scheme_count(1).expect("stage scheme");
        let scheme = context.scheme(0);

        assert_eq!(
            read_text(&scheme.path().join("target_nid")).expect("read target node"),
            "-1\n"
        );

        let goals = scheme.path().join("quotas/goals");
        write_value(&goals.join("nr_goals"), 1).expect("stage quota goal");
        assert!(path_exists(&goals.join("0/target_metric")).expect("inspect quota goal"));
        assert!(path_exists(&goals.join("0/path")).expect("inspect quota goal path"));

        for name in ["filters", "core_filters", "ops_filters"] {
            let filters = scheme.path().join(name);
            write_value(&filters.join("nr_filters"), 1).expect("stage scheme filter");
            assert!(path_exists(&filters.join("0/memcg_path")).expect("inspect scheme filter"));
            assert!(!path_exists(&filters.join("0/path")).expect("distinguish probe filter"));
        }

        let dests = scheme.path().join("dests");
        write_value(&dests.join("nr_dests"), 1).expect("stage destination");
        assert!(path_exists(&dests.join("0/id")).expect("inspect destination id"));
        assert!(path_exists(&dests.join("0/weight")).expect("inspect destination weight"));

        context.set_probe_count(1).expect("stage probe");
        let probe = context.probe(0);
        probe.set_filter_count(1).expect("stage probe filter");
        assert!(path_exists(&probe.filter(0).path().join("path")).expect("inspect probe filter"));
        assert!(
            !path_exists(&probe.filter(0).path().join("memcg_path"))
                .expect("distinguish scheme filter")
        );
    }

    #[test]
    fn owned_linux_7_2_configuration_round_trips_every_input() {
        let model = test_backend::Model::new("vaddr\nfvaddr\npaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);

        let mut probe = ProbeConfig::default();
        probe.filters.push(ProbeFilterConfig::new(
            ProbeFilterType::Anonymous,
            true,
            true,
        ));
        probe.filters.push(ProbeFilterConfig::memory_control_group(
            "/workload",
            false,
            true,
        ));

        let pattern = AccessPattern::new(
            RegionSizeRange::new(4_096, 1 << 30).expect("valid size range"),
            AccessCountRange::new(1, 200).expect("valid access range"),
            AgeRange::new(2, 300).expect("valid age range"),
        );
        let mut scheme = SchemeConfig::new(Action::MigrateHot, pattern);
        scheme.apply_interval = Duration::from_millis(250);
        scheme.target_node = Some(2);
        scheme.quota = QuotaConfig {
            time: Duration::from_millis(10),
            size_units: 1 << 20,
            reset_interval: Duration::from_secs(1),
            weights: QuotaWeights {
                size_per_thousand: 100,
                accesses_per_thousand: 300,
                age_per_thousand: 600,
            },
            goals: vec![QuotaGoalConfig {
                metric: QuotaGoalMetric::NodeMemoryControlGroupFreeBasisPoints,
                target_value: 2_000,
                current_value: 1_500,
                node_id: Some(1),
                cgroup_path: Some("/workload".to_owned()),
            }],
            goal_tuner: QuotaGoalTuner::Temporal,
            failure_charge_numerator: 1,
            failure_charge_denominator: 4,
        };
        scheme.watermarks = WatermarksConfig {
            metric: WatermarkMetric::FreeMemoryRate,
            interval: Duration::from_secs(5),
            high: 800,
            middle: 500,
            low: 200,
        };
        scheme.filters = vec![
            FilterConfig::address(0, 65_536, true, true),
            FilterConfig::target(0, true, false),
            FilterConfig::huge_page_size(
                ByteSizeRange::new(2 << 20, 1 << 30).expect("valid huge-page range"),
                false,
                true,
            ),
        ];
        scheme.destinations = vec![DestinationConfig {
            node_id: 3,
            weight: 17,
        }];
        scheme.maximum_snapshots = 64;

        let mut context = ContextConfig::new(Operation::VirtualAddress);
        context.address_unit = AddressUnit::ONE;
        context.paused = false;
        context.intervals = MonitoringIntervals::new(
            Duration::from_millis(5),
            Duration::from_millis(100),
            Duration::from_secs(1),
        )
        .expect("valid intervals");
        context.intervals_goal = IntervalsGoalConfig {
            access_basis_points: 5_000,
            aggregation_intervals: 10,
            minimum_sample: Duration::from_millis(1),
            maximum_sample: Duration::from_millis(10),
        };
        context.region_bounds = RegionBounds::new(10, 10_000).expect("valid bounds");
        context.probes = vec![probe];
        context.targets.push(complete_test_target());
        context.schemes.push(scheme);

        let config = KdamondConfig {
            refresh_interval: Duration::from_millis(25),
            contexts: vec![context],
        };
        kdamond
            .stage_configuration(&config)
            .expect("stage complete configuration");
        assert_eq!(
            kdamond
                .configuration()
                .expect("read complete configuration"),
            config
        );
    }

    #[test]
    fn owned_configuration_round_trips_current_damo_probe_and_sample_controls() {
        let model = test_backend::Model::new("vaddr\n");
        model.enable_current_damo_extensions();
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);

        let mut probe = ProbeConfig {
            filters: vec![ProbeFilterConfig::new(
                ProbeFilterType::PageIdleUnset,
                true,
                true,
            )],
            weight: 7,
            preparations: vec![ProbePreparationConfig::new(
                ProbePreparationAction::SetPageIdle,
            )],
        };
        probe.filters.push(ProbeFilterConfig::memory_control_group(
            "/workload",
            false,
            true,
        ));

        let mut context = ContextConfig::new(Operation::VirtualAddress);
        context.operation_attributes = OperationAttributesConfig {
            use_reports: true,
            write_only: true,
            cpus: "0-3".to_owned(),
            thread_ids: "41 42".to_owned(),
        };
        context.probes.push(probe);
        context.sample_control = SampleControlConfig {
            primitives: SamplePrimitivesConfig {
                page_table: false,
                page_fault: true,
            },
            filters: vec![
                SampleFilterConfig::cpu_mask("0-3", true, true),
                SampleFilterConfig::threads("41 42", false, true),
                SampleFilterConfig::write(true, false),
            ],
        };
        context
            .targets
            .push(TargetConfig::for_pid(Pid::new(42).expect("valid pid")));

        let config = KdamondConfig {
            refresh_interval: Duration::ZERO,
            contexts: vec![context],
        };
        kdamond
            .stage_configuration(&config)
            .expect("stage current damo controls");

        assert_eq!(
            kdamond.configuration().expect("read current damo controls"),
            config
        );
    }

    #[test]
    fn owned_admin_configuration_round_trips_multiple_kdamonds() {
        let model = test_backend::Model::new("vaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        let config = DamonConfig {
            kdamonds: vec![
                KdamondConfig {
                    refresh_interval: Duration::from_millis(10),
                    contexts: Vec::new(),
                },
                KdamondConfig {
                    refresh_interval: Duration::from_millis(20),
                    contexts: Vec::new(),
                },
            ],
        };

        admin
            .stage_configuration(&config)
            .expect("stage complete admin hierarchy");

        assert_eq!(admin.configuration().expect("read admin hierarchy"), config);
    }

    fn complete_test_target() -> TargetConfig {
        TargetConfig {
            pid: Some(Pid::new(42).expect("valid pid")),
            obsolete: false,
            initial_regions: vec![
                InitialRegionConfig::new(0x1_0000, 0x2_0000).expect("valid region"),
                InitialRegionConfig::new(0x3_0000, 0x4_0000).expect("valid region"),
            ],
        }
    }

    #[test]
    fn owned_configuration_validation_precedes_every_write() {
        let model = test_backend::Model::new("vaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        let mut context = ContextConfig::new(Operation::VirtualAddress);
        context.targets.push(TargetConfig::address_space());
        let config = KdamondConfig {
            refresh_interval: Duration::from_millis(99),
            contexts: vec![context],
        };

        let error = kdamond
            .stage_configuration(&config)
            .expect_err("pid-less vaddr target must be rejected");
        assert!(matches!(error, Error::InvalidConfiguration { .. }));
        assert_eq!(
            kdamond.refresh_interval().expect("refresh stays unchanged"),
            Duration::ZERO
        );
        assert_eq!(
            kdamond
                .context_count()
                .expect("context count stays unchanged"),
            0
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn physical_address_staging_rejects_invalid_subpage_address_units_before_writing() {
        let model = test_backend::Model::new("paddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        let writes = model.write_count();

        let mut context = ContextConfig::new(Operation::PhysicalAddress);
        context.address_unit = AddressUnit::new(3).expect("non-zero unit");
        context.targets.push(TargetConfig::address_space());
        let config = KdamondConfig {
            refresh_interval: Duration::ZERO,
            contexts: vec![context],
        };

        let error = kdamond
            .stage_configuration(&config)
            .expect_err("subpage units must be powers of two");
        assert!(matches!(
            error,
            Error::InvalidConfiguration {
                field: "address unit",
                ..
            }
        ));
        assert_eq!(model.write_count(), writes);
    }

    #[test]
    fn indexed_counts_reject_values_wider_than_the_kernel_abi() {
        let model = test_backend::Model::new("vaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        let error = admin
            .set_kdamond_count(i32::MAX as usize + 1)
            .expect_err("kernel count overflow must be rejected");
        assert!(matches!(error, Error::InvalidConfiguration { .. }));
        assert_eq!(admin.kdamond_count().expect("count remains unchanged"), 0);
    }

    #[test]
    fn owned_configuration_preserves_absent_optional_attributes() {
        let model = test_backend::Model::new("vaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        kdamond.set_context_count(1).expect("stage context");
        let context = kdamond.context(0);
        context.set_target_count(1).expect("stage target");
        context
            .target(0)
            .set_pid(Pid::new(42).expect("valid pid"))
            .expect("stage pid");
        context.set_scheme_count(1).expect("stage scheme");

        for path in [
            "kdamonds/0/refresh_ms",
            "kdamonds/0/contexts/0/addr_unit",
            "kdamonds/0/contexts/0/pause",
            "kdamonds/0/contexts/0/monitoring_attrs/intervals/intervals_goal",
            "kdamonds/0/contexts/0/monitoring_attrs/probes",
            "kdamonds/0/contexts/0/targets/0/obsolete_target",
            "kdamonds/0/contexts/0/targets/0/regions",
            "kdamonds/0/contexts/0/schemes/0/apply_interval_us",
            "kdamonds/0/contexts/0/schemes/0/target_nid",
            "kdamonds/0/contexts/0/schemes/0/quotas/goals",
            "kdamonds/0/contexts/0/schemes/0/quotas/goal_tuner",
            "kdamonds/0/contexts/0/schemes/0/quotas/fail_charge_num",
            "kdamonds/0/contexts/0/schemes/0/quotas/fail_charge_denom",
            "kdamonds/0/contexts/0/schemes/0/filters",
            "kdamonds/0/contexts/0/schemes/0/core_filters",
            "kdamonds/0/contexts/0/schemes/0/ops_filters",
            "kdamonds/0/contexts/0/schemes/0/dests",
            "kdamonds/0/contexts/0/schemes/0/stats/sz_ops_filter_passed",
            "kdamonds/0/contexts/0/schemes/0/stats/nr_snapshots",
            "kdamonds/0/contexts/0/schemes/0/stats/max_nr_snapshots",
        ] {
            model.remove_tree(path);
        }

        let config = kdamond.configuration().expect("read legacy configuration");
        assert_eq!(config.refresh_interval, Duration::ZERO);
        let context_config = &config.contexts[0];
        assert_eq!(context_config.address_unit, AddressUnit::ONE);
        assert_eq!(
            context_config.intervals_goal,
            IntervalsGoalConfig::default()
        );
        assert!(context_config.probes.is_empty());
        assert!(context_config.targets[0].initial_regions.is_empty());
        assert!(context_config.schemes[0].destinations.is_empty());
        let stats = context.scheme(0).stats().expect("read legacy scheme stats");
        assert_eq!(stats.operations_filter_passed_units, None);
        assert_eq!(stats.snapshots, None);
        assert_eq!(stats.maximum_snapshots, None);
        kdamond
            .stage_configuration(&config)
            .expect("restage configuration without unavailable attributes");
    }

    #[test]
    fn owned_configuration_supports_damo_legacy_attribute_aliases() {
        let model = test_backend::Model::new("vaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        kdamond.set_context_count(1).expect("stage context");
        let context = kdamond.context(0);
        context.set_target_count(1).expect("stage target");
        context
            .target(0)
            .set_pid(Pid::new(42).expect("valid pid"))
            .expect("stage pid");
        context.set_scheme_count(1).expect("stage scheme");
        let scheme = context.scheme(0);
        model.remove_tree("kdamonds/0/contexts/0/schemes/0/core_filters");
        model.remove_tree("kdamonds/0/contexts/0/schemes/0/ops_filters");
        scheme
            .set_filter_count(FilterLayer::Unified, 1)
            .expect("stage filter");
        scheme.quotas().set_goal_count(1).expect("stage quota goal");

        let filter_path = "kdamonds/0/contexts/0/schemes/0/filters/0";
        model.remove_tree(format!("{filter_path}/allow"));
        model.set_file(format!("{filter_path}/pass"), b"Y\n");
        let goal_metric = "kdamonds/0/contexts/0/schemes/0/quotas/goals/0/target_metric";
        model.remove_tree(goal_metric);

        assert_eq!(
            kdamond
                .capabilities(0, 0)
                .expect("discover legacy filter control")
                .feature_support(SysfsFeature::SchemeFilterAllow),
            CapabilitySupport::Supported
        );
        let config = kdamond.configuration().expect("read legacy aliases");
        assert!(config.contexts[0].schemes[0].filters[0].allow);
        assert_eq!(
            config.contexts[0].schemes[0].quota.goals[0].metric,
            QuotaGoalMetric::UserInput
        );
        kdamond
            .stage_configuration(&config)
            .expect("restage legacy aliases");
        assert_eq!(
            model.value(format!("{filter_path}/pass")),
            Some("Y".to_owned())
        );
        assert_eq!(model.value(goal_metric), None);
    }

    #[test]
    fn owned_configuration_rejects_kernel_commit_invariants() {
        let pattern = AccessPattern::new(
            RegionSizeRange::new(0, 1).expect("valid size range"),
            AccessCountRange::new(0, 1).expect("valid access range"),
            AgeRange::new(0, 1).expect("valid age range"),
        );
        let mut context = ContextConfig::new(Operation::PhysicalAddress);
        context.targets = vec![TargetConfig::address_space(), TargetConfig::address_space()];
        assert!(context.validate().is_err());

        context.targets.truncate(1);
        context.targets[0].initial_regions = vec![
            InitialRegionConfig::new(100, 200).expect("valid region"),
            InitialRegionConfig::new(150, 250).expect("valid region"),
        ];
        assert!(context.validate().is_err());

        context.targets[0].initial_regions.clear();
        let mut scheme = SchemeConfig::new(Action::Stat, pattern);
        scheme.filters = vec![FilterConfig::new(SchemeFilterType::Anonymous, true, false)];
        context.schemes.push(scheme);
        context
            .validate()
            .expect("semantic filters are assigned to the supported ABI layer");
    }

    #[test]
    fn owned_configuration_rejects_overflow_prone_ratios_and_weights() {
        let intervals = MonitoringIntervals::default();
        let goal = IntervalsGoalConfig {
            access_basis_points: 10_001,
            aggregation_intervals: 1,
            minimum_sample: intervals.sample(),
            maximum_sample: intervals.sample(),
        };
        assert!(goal.validate_for(intervals).is_err());

        let mut quota = QuotaConfig::default();
        quota.weights.size_per_thousand = 1_001;
        assert!(quota.validate().is_err());
        quota.weights.size_per_thousand = 1_000;
        quota.time = Duration::from_millis(1);
        assert!(quota.validate().is_err());

        let pattern = AccessPattern::new(
            RegionSizeRange::new(0, 1).expect("valid size range"),
            AccessCountRange::new(0, 1).expect("valid access range"),
            AgeRange::new(0, 1).expect("valid age range"),
        );
        let mut scheme = SchemeConfig::new(Action::MigrateCold, pattern);
        scheme.destinations = vec![
            DestinationConfig::new(0, u32::MAX),
            DestinationConfig::new(1, 1),
        ];
        assert!(scheme.validate_for(1).is_err());
    }

    #[test]
    fn disabled_controls_preserve_kernel_staged_values() {
        let model = test_backend::Model::new("vaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        kdamond.set_context_count(1).expect("stage context");
        let context = kdamond.context(0);
        context
            .set_intervals_goal(IntervalsGoalConfig {
                access_basis_points: 10_001,
                aggregation_intervals: 0,
                minimum_sample: Duration::from_micros(20),
                maximum_sample: Duration::from_micros(10),
            })
            .expect("disabled interval goal ignores inactive thresholds");
        context.set_scheme_count(1).expect("stage scheme");
        let scheme = context.scheme(0);
        let watermarks = scheme.watermarks();
        watermarks
            .set_metric(&WatermarkMetric::None)
            .expect("disable watermarks");
        watermarks.set_high(1).expect("stage inactive high");
        watermarks.set_middle(3).expect("stage inactive middle");
        watermarks.set_low(2).expect("stage inactive low");
        let quotas = scheme.quotas();
        quotas.set_goal_count(1).expect("stage quota goal");
        let goal = quotas.goal(0);
        goal.set_metric(&QuotaGoalMetric::NodeMemoryControlGroupUsedBasisPoints)
            .expect("stage goal metric");
        goal.set_target_value(0).expect("disable quota goal");

        let config = kdamond.configuration().expect("read staged controls");
        config
            .validate()
            .expect("disabled controls must remain representable");
        kdamond
            .stage_configuration(&config)
            .expect("disabled controls must round-trip");
    }

    #[test]
    fn migration_without_an_explicit_node_matches_kernel_and_damo() {
        let pattern = AccessPattern::new(
            RegionSizeRange::new(0, u64::MAX).expect("valid size range"),
            AccessCountRange::new(0, u32::MAX).expect("valid access range"),
            AgeRange::new(0, u32::MAX).expect("valid age range"),
        );
        let scheme = SchemeConfig::new(Action::MigrateCold, pattern);
        scheme
            .validate_for(0)
            .expect("NUMA_NO_NODE is a kernel-representable migration target");
    }

    #[test]
    fn owned_validation_does_not_hardcode_the_kernel_context_limit() {
        let model = test_backend::Model::new("future_ops\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        let config = KdamondConfig {
            refresh_interval: Duration::ZERO,
            contexts: vec![
                ContextConfig::new(Operation::Unknown("future_ops".into())),
                ContextConfig::new(Operation::Unknown("future_ops".into())),
            ],
        };

        config
            .validate()
            .expect("future kernels may support multiple contexts");
        let error = kdamond
            .stage_configuration(&config)
            .expect_err("the Linux 7.2 model enforces its own limit");
        assert!(matches!(error, Error::Io { .. }));
        assert_eq!(kdamond.context_count().expect("read context count"), 0);
    }

    #[test]
    fn owned_configuration_round_trips_unknown_future_tokens() {
        let model = test_backend::Model::new("future_ops\n");
        model.set_supported_scheme_filter_types("future_filter\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        kdamond.set_context_count(1).expect("stage context");
        let context = kdamond.context(0);
        context
            .set_operation(&Operation::Unknown("future_ops".into()))
            .expect("select future operation");
        context.set_scheme_count(1).expect("stage scheme");
        let scheme = context.scheme(0);
        scheme
            .set_action(&Action::Unknown("future_action".into()))
            .expect("select future action");
        scheme
            .set_filter_count(FilterLayer::Unified, 1)
            .expect("stage future filter");
        scheme
            .filter(FilterLayer::Unified, 0)
            .set_filter_type(&SchemeFilterType::Unknown("future_filter".into()))
            .expect("select future filter type");
        let quotas = scheme.quotas();
        quotas.set_goal_count(1).expect("stage future quota goal");
        quotas
            .goal(0)
            .set_metric(&QuotaGoalMetric::Unknown("future_metric".into()))
            .expect("select future goal metric");
        quotas
            .set_goal_tuner(&QuotaGoalTuner::Unknown("future_tuner".into()))
            .expect("select future goal tuner");
        let watermarks = scheme.watermarks();
        watermarks
            .set_metric(&WatermarkMetric::Unknown("future_watermark".into()))
            .expect("select future watermark metric");
        watermarks.set_high(1).expect("stage future threshold");
        watermarks.set_middle(3).expect("stage future threshold");
        watermarks.set_low(2).expect("stage future threshold");

        let config = kdamond.configuration().expect("read future configuration");
        config
            .validate()
            .expect("unknown future tokens remain representable");
        kdamond
            .stage_configuration(&config)
            .expect("restage future configuration");
        assert_eq!(
            kdamond
                .configuration()
                .expect("read restaged configuration"),
            config
        );
    }

    #[test]
    fn typed_string_setters_reject_non_atomic_sysfs_values() {
        let model = test_backend::Model::new("vaddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        kdamond.set_context_count(1).expect("stage context");
        let context = kdamond.context(0);
        let error = context
            .set_operation(&Operation::Unknown("vaddr\nfuture".into()))
            .expect_err("operation must be one sysfs token");
        assert!(matches!(error, Error::InvalidConfiguration { .. }));
        assert_eq!(
            context.operation().expect("operation remains intact"),
            Operation::VirtualAddress
        );

        context.set_probe_count(1).expect("stage probe");
        let probe = context.probe(0);
        probe.set_filter_count(1).expect("stage probe filter");
        let filter = probe.filter(0);
        let error = filter
            .set_cgroup_path("/workload\0replacement")
            .expect_err("cgroup path must not contain a NUL");
        assert!(matches!(error, Error::InvalidConfiguration { .. }));
        assert_eq!(filter.cgroup_path().expect("path remains intact"), "");

        context.set_scheme_count(1).expect("stage scheme");
        let scheme = context.scheme(0);
        let error = scheme
            .set_action(&Action::Unknown("stat future".into()))
            .expect_err("action must be one sysfs token");
        assert!(matches!(error, Error::InvalidConfiguration { .. }));
        assert_eq!(
            scheme.action().expect("action remains intact"),
            Action::Stat
        );
    }

    #[test]
    fn huge_page_filter_sizes_are_bytes_independent_of_address_unit() {
        let model = test_backend::Model::new("paddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        kdamond.set_context_count(1).expect("stage context");
        let context = kdamond.context(0);
        context
            .set_operation(&Operation::PhysicalAddress)
            .expect("select paddr");
        context
            .set_address_unit(AddressUnit::new(4_096).expect("valid unit"))
            .expect("stage non-one address unit");
        context.set_scheme_count(1).expect("stage scheme");
        let scheme = context.scheme(0);
        scheme
            .set_filter_count(FilterLayer::Operations, 1)
            .expect("stage filter");
        let filter = scheme.filter(FilterLayer::Operations, 0);
        let config = FilterConfig::huge_page_size(
            ByteSizeRange::new(2 << 20, 1 << 30).expect("valid byte-size range"),
            true,
            true,
        );
        filter
            .set_filter_type(&SchemeFilterType::HugePageSize)
            .expect("select huge-page-size filter");
        filter.set_matching(true).expect("stage matching");
        filter.set_allowed(true).expect("stage allow");
        filter
            .set_minimum_size_bytes(2 << 20)
            .expect("stage minimum");
        filter
            .set_maximum_size_bytes(1 << 30)
            .expect("stage maximum");

        assert_eq!(filter.minimum_size_bytes().expect("read minimum"), 2 << 20);
        assert_eq!(filter.maximum_size_bytes().expect("read maximum"), 1 << 30);
        assert_eq!(filter.configuration().expect("read filter"), config);
    }

    #[test]
    fn nested_attribute_handles_are_symmetric() {
        let model = test_backend::Model::new("paddr\n");
        let admin = DamonAdmin::open(model.root()).expect("open modeled hierarchy");
        admin.set_kdamond_count(1).expect("stage kdamond");
        let kdamond = admin.kdamond(0);
        kdamond.set_context_count(1).expect("stage context");
        let context = kdamond.context(0);
        context.set_target_count(1).expect("stage target");
        let target = context.target(0);
        target
            .set_initial_region_count(1)
            .expect("stage initial region");
        let region = target.initial_region(0);
        region.set_start(100).expect("write start");
        region.set_end(200).expect("write end");
        assert_eq!(region.start().expect("read start"), 100);
        assert_eq!(region.end().expect("read end"), 200);

        context.set_scheme_count(1).expect("stage scheme");
        let scheme = context.scheme(0);
        scheme.set_target_node(3).expect("write target node");
        assert_eq!(scheme.target_node().expect("read target node"), 3);
        scheme
            .set_filter_count(FilterLayer::Core, 1)
            .expect("stage filter");
        let filter = scheme.filter(FilterLayer::Core, 0);
        filter
            .set_filter_type(&SchemeFilterType::Address)
            .expect("write filter type");
        filter.set_matching(true).expect("write matching");
        filter.set_allowed(false).expect("write allow");
        filter
            .set_address_start(1_000)
            .expect("write address start");
        filter.set_address_end(2_000).expect("write address end");
        assert_eq!(
            filter.filter_type().expect("read filter type"),
            SchemeFilterType::Address
        );
        assert!(filter.matching().expect("read matching"));
        assert!(!filter.allowed().expect("read allow"));
        assert_eq!(filter.address_start().expect("read address start"), 1_000);
        assert_eq!(filter.address_end().expect("read address end"), 2_000);

        let quotas = scheme.quotas();
        quotas
            .set_failure_charge_numerator(2)
            .expect("write numerator");
        quotas
            .set_failure_charge_denominator(7)
            .expect("write denominator");
        assert_eq!(
            quotas.failure_charge_numerator().expect("read numerator"),
            2
        );
        assert_eq!(
            quotas
                .failure_charge_denominator()
                .expect("read denominator"),
            7
        );
        quotas.set_goal_count(1).expect("stage quota goal");
        let goal = quotas.goal(0);
        goal.set_metric(&QuotaGoalMetric::UserInput)
            .expect("write metric");
        goal.set_target_value(12).expect("write target value");
        goal.set_current_value(9).expect("write current value");
        assert_eq!(
            goal.metric().expect("read metric"),
            QuotaGoalMetric::UserInput
        );
        assert_eq!(goal.target_value().expect("read target"), 12);
        assert_eq!(goal.current_value().expect("read current"), 9);

        scheme.set_destination_count(1).expect("stage destination");
        let destination = scheme.destination(0);
        destination.set_node_id(4).expect("write node");
        destination.set_weight(11).expect("write weight");
        assert_eq!(destination.node_id().expect("read node"), 4);
        assert_eq!(destination.weight().expect("read weight"), 11);
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
