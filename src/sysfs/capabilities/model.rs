//! Public capability values and query helpers.

use super::{Operation, operation_capability, set_feature_support};

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
    /// Huge-page-memory DAMOS quota goals.
    SchemeQuotaGoalHugePageMemory,
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
    /// DAMOS page allocation action.
    DamosAllocateAction,
    /// DAMOS page release action.
    DamosFreeAction,
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
    /// Page-idle-set monitoring probes.
    ProbeTypePageIdleSet,
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
            | Self::ProbeFilterPath
            | Self::SchemeQuotaGoalHugePageMemory
            | Self::DamosAllocateAction
            | Self::DamosFreeAction
            | Self::ProbeTypePageIdleSet => None,
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
    pub(super) feature: SysfsFeature,
    pub(super) support: CapabilitySupport,
}

/// Discovery result for one DAMON monitoring operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OperationCapability {
    pub(super) operation: Operation,
    pub(super) support: CapabilitySupport,
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
    pub(super) operations: Box<[OperationCapability]>,
    pub(super) features: Box<[FeatureCapability]>,
    pub(super) attribute_paths: Box<[String]>,
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

    pub(super) fn sync_operation_features(&mut self) {
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
