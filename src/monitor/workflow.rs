//! High-level vaddr, fvaddr, and paddr workflow builders.

use super::{
    AccessCountRange, AccessPattern, Action, AddressUnit, AgeRange, Capabilities,
    CapabilitySupport, ContextConfig, Damon, DamonConfig, Duration, Error, ExclusiveSession,
    InitialRegionConfig, KdamondConfig, MonitoringIntervals, Operation, Pid, ProbeConfig,
    RegionBounds, RegionSizeRange, Result, SchemeConfig, SchemeStats, Snapshot, SysfsFeature,
    TargetConfig, with_rollback,
};

#[derive(Clone, Debug)]
pub(super) struct WorkflowOptions<'a> {
    damon: &'a Damon,
    sample: Duration,
    aggregation: Duration,
    update: Duration,
    min_regions: u64,
    max_regions: u64,
    initial_regions: Vec<InitialRegionConfig>,
    probes: Vec<ProbeConfig>,
    schemes: Vec<SchemeConfig>,
}

impl<'a> WorkflowOptions<'a> {
    pub(super) fn new(damon: &'a Damon) -> Self {
        let intervals = MonitoringIntervals::default();
        let region_bounds = RegionBounds::default();
        Self {
            damon,
            sample: intervals.sample(),
            aggregation: intervals.aggregation(),
            update: intervals.update(),
            min_regions: region_bounds.min(),
            max_regions: region_bounds.max(),
            initial_regions: Vec::new(),
            probes: Vec::new(),
            schemes: Vec::new(),
        }
    }
}

/// Builder for a process virtual-address monitoring workflow.
#[derive(Clone, Debug)]
pub struct VaddrSessionBuilder<'a> {
    pub(super) options: WorkflowOptions<'a>,
    pub(super) pid: Option<Pid>,
}

/// Backwards-compatible name for [`VaddrSessionBuilder`].
pub type MonitorBuilder<'a> = VaddrSessionBuilder<'a>;

/// Builder for a fixed virtual-address monitoring workflow.
#[derive(Clone, Debug)]
pub struct FvaddrSessionBuilder<'a> {
    pub(super) options: WorkflowOptions<'a>,
    pub(super) pid: Option<Pid>,
}

/// Builder for a physical-address monitoring workflow.
#[derive(Clone, Debug)]
pub struct PaddrSessionBuilder<'a> {
    pub(super) options: WorkflowOptions<'a>,
    pub(super) address_unit: AddressUnit,
}

macro_rules! impl_common_workflow_builder {
    ($builder:ident) => {
        impl $builder<'_> {
            /// Replaces all monitoring intervals.
            #[must_use]
            pub const fn intervals(mut self, intervals: MonitoringIntervals) -> Self {
                self.options.sample = intervals.sample();
                self.options.aggregation = intervals.aggregation();
                self.options.update = intervals.update();
                self
            }

            /// Sets the interval between access samples.
            #[must_use]
            pub const fn sample_interval(mut self, interval: Duration) -> Self {
                self.options.sample = interval;
                self
            }

            /// Sets the interval between aggregation snapshots.
            #[must_use]
            pub const fn aggregation_interval(mut self, interval: Duration) -> Self {
                self.options.aggregation = interval;
                self
            }

            /// Sets the interval between monitoring-operations updates.
            #[must_use]
            pub const fn operations_update_interval(mut self, interval: Duration) -> Self {
                self.options.update = interval;
                self
            }

            /// Sets lower and upper bounds for the number of monitoring regions.
            #[must_use]
            pub const fn region_bounds(mut self, min: u64, max: u64) -> Self {
                self.options.min_regions = min;
                self.options.max_regions = max;
                self
            }

            /// Replaces the monitoring-data probes.
            #[must_use]
            pub fn probes(mut self, probes: impl IntoIterator<Item = ProbeConfig>) -> Self {
                self.options.probes = probes.into_iter().collect();
                self
            }

            /// Appends one monitoring-data probe.
            #[must_use]
            pub fn probe(mut self, probe: ProbeConfig) -> Self {
                self.options.probes.push(probe);
                self
            }

            /// Replaces the custom DAMOS schemes.
            ///
            /// The workflow adds a private match-all statistics scheme after
            /// these schemes so [`Monitor::snapshot`] remains independent of
            /// user policy. Address and size values use DAMON core units.
            #[must_use]
            pub fn schemes(mut self, schemes: impl IntoIterator<Item = SchemeConfig>) -> Self {
                self.options.schemes = schemes.into_iter().collect();
                self
            }

            /// Appends one custom DAMOS scheme.
            #[must_use]
            pub fn scheme(mut self, scheme: SchemeConfig) -> Self {
                self.options.schemes.push(scheme);
                self
            }
        }
    };
}

impl_common_workflow_builder!(VaddrSessionBuilder);
impl_common_workflow_builder!(FvaddrSessionBuilder);
impl_common_workflow_builder!(PaddrSessionBuilder);

impl VaddrSessionBuilder<'_> {
    /// Selects the single process monitored by this workflow.
    #[must_use]
    pub fn pid(mut self, pid: Pid) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Replaces optional initial regions expressed as byte addresses.
    #[must_use]
    pub fn regions(mut self, regions: impl IntoIterator<Item = InitialRegionConfig>) -> Self {
        self.options.initial_regions = regions.into_iter().collect();
        self
    }

    /// Appends one optional initial region expressed as byte addresses.
    #[must_use]
    pub fn region(mut self, region: InitialRegionConfig) -> Self {
        self.options.initial_regions.push(region);
        self
    }

    /// Validates, stages, and starts this virtual-address workflow.
    ///
    /// The returned monitor holds the cooperative lock and restores the
    /// preceding stopped configuration when explicitly stopped or dropped.
    pub fn start(self) -> Result<Monitor> {
        let pid = self.pid.ok_or(Error::InvalidConfiguration {
            field: "virtual-address PID",
            reason: "requires exactly one process identifier",
        })?;
        start_workflow(
            self.options,
            Operation::VirtualAddress,
            Some(pid),
            AddressUnit::ONE,
        )
    }
}

impl FvaddrSessionBuilder<'_> {
    /// Selects the single process monitored by this workflow.
    #[must_use]
    pub fn pid(mut self, pid: Pid) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Replaces required fixed regions expressed as byte addresses.
    #[must_use]
    pub fn regions(mut self, regions: impl IntoIterator<Item = InitialRegionConfig>) -> Self {
        self.options.initial_regions = regions.into_iter().collect();
        self
    }

    /// Appends one fixed region expressed as byte addresses.
    #[must_use]
    pub fn region(mut self, region: InitialRegionConfig) -> Self {
        self.options.initial_regions.push(region);
        self
    }

    /// Validates, stages, and starts this fixed virtual-address workflow.
    ///
    /// The returned monitor holds the cooperative lock and restores the
    /// preceding stopped configuration when explicitly stopped or dropped.
    pub fn start(self) -> Result<Monitor> {
        let pid = self.pid.ok_or(Error::InvalidConfiguration {
            field: "fixed virtual-address PID",
            reason: "requires exactly one process identifier",
        })?;
        start_workflow(
            self.options,
            Operation::FixedVirtualAddress,
            Some(pid),
            AddressUnit::ONE,
        )
    }
}

impl PaddrSessionBuilder<'_> {
    /// Sets the number of bytes represented by one physical-address unit.
    #[must_use]
    pub fn address_unit(mut self, address_unit: AddressUnit) -> Self {
        self.address_unit = address_unit;
        self
    }

    /// Replaces required physical regions expressed in core address units.
    #[must_use]
    pub fn regions_units(mut self, regions: impl IntoIterator<Item = InitialRegionConfig>) -> Self {
        self.options.initial_regions = regions.into_iter().collect();
        self
    }

    /// Appends one physical region expressed in core address units.
    #[must_use]
    pub fn region_units(mut self, region: InitialRegionConfig) -> Self {
        self.options.initial_regions.push(region);
        self
    }

    /// Validates, stages, and starts this physical-address workflow.
    ///
    /// The returned monitor holds the cooperative lock and restores the
    /// preceding stopped configuration when explicitly stopped or dropped.
    pub fn start(self) -> Result<Monitor> {
        start_workflow(
            self.options,
            Operation::PhysicalAddress,
            None,
            self.address_unit,
        )
    }
}

struct PreparedWorkflow {
    base_config: DamonConfig,
    capability_config: DamonConfig,
    snapshot_scheme_index: usize,
    custom_scheme_count: usize,
    capacity_hint: usize,
    sample_interval: Duration,
}

fn prepare_workflow(
    options: WorkflowOptions<'_>,
    operation: Operation,
    pid: Option<Pid>,
    address_unit: AddressUnit,
) -> Result<PreparedWorkflow> {
    let intervals = MonitoringIntervals::new(options.sample, options.aggregation, options.update)?;
    let region_bounds = RegionBounds::new(options.min_regions, options.max_regions)?;
    let mut target = pid.map_or_else(TargetConfig::address_space, TargetConfig::for_pid);
    target.initial_regions = options.initial_regions;

    let mut context = ContextConfig::new(operation);
    context.address_unit = address_unit;
    context.intervals = intervals;
    context.region_bounds = region_bounds;
    context.probes = options.probes;
    context.targets.push(target);
    context.schemes = options.schemes;
    let snapshot_scheme_index = context.schemes.len();

    let mut kdamond = KdamondConfig::default();
    kdamond.contexts.push(context);
    let mut base_config = DamonConfig::default();
    base_config.kdamonds.push(kdamond);
    base_config.validate_runnable()?;
    let mut capability_config = base_config.clone();
    capability_config.kdamonds[0].contexts[0]
        .schemes
        .push(snapshot_query_scheme(Duration::ZERO));
    capability_config.validate_runnable()?;

    Ok(PreparedWorkflow {
        base_config,
        capability_config,
        snapshot_scheme_index,
        custom_scheme_count: snapshot_scheme_index,
        capacity_hint: usize::try_from(region_bounds.max()).unwrap_or(usize::MAX),
        sample_interval: intervals.sample(),
    })
}

fn start_workflow(
    options: WorkflowOptions<'_>,
    operation: Operation,
    pid: Option<Pid>,
    address_unit: AddressUnit,
) -> Result<Monitor> {
    let damon = options.damon;
    let prepared = prepare_workflow(options, operation.clone(), pid, address_unit)?;
    let mut session = match damon.exclusive_session(&prepared.capability_config) {
        Ok(session) => session,
        Err(error) => return Err(classify_operation_staging_error(error, &operation)),
    };
    let scheme_indices = (0..=prepared.snapshot_scheme_index).collect::<Vec<_>>();
    let mut capabilities = match session.capabilities_for_schemes(0, &scheme_indices) {
        Ok(capabilities) => capabilities,
        Err(error) => return Err(with_rollback(error, session.close())),
    };
    if capabilities.operation_support(&operation) == Some(CapabilitySupport::Unsupported) {
        return Err(with_rollback(
            Error::UnsupportedOperation {
                operation: operation.clone(),
            },
            session.close(),
        ));
    }
    let snapshot_query = if capabilities.feature_support(SysfsFeature::TriedRegions)
        != CapabilitySupport::Supported
    {
        if let Err(error) = session.replace_staged_configuration(&prepared.base_config) {
            return Err(with_rollback(error, session.close()));
        }
        SnapshotQuery::Unsupported
    } else if capabilities.feature_support(SysfsFeature::OnlineParametersCommit)
        == CapabilitySupport::Supported
    {
        let mut query_config = prepared.base_config.clone();
        let apply_interval = if capabilities.feature_support(SysfsFeature::SchemeApplyInterval)
            == CapabilitySupport::Supported
        {
            prepared.sample_interval
        } else {
            Duration::ZERO
        };
        query_config.kdamonds[0].contexts[0]
            .schemes
            .push(snapshot_query_scheme(apply_interval));
        if let Err(error) = session.replace_staged_configuration(&prepared.base_config) {
            return Err(with_rollback(error, session.close()));
        }
        SnapshotQuery::OnDemand {
            base_config: Box::new(prepared.base_config),
            query_config: Box::new(query_config),
            scheme_index: prepared.snapshot_scheme_index,
            installed: false,
        }
    } else {
        SnapshotQuery::Permanent {
            scheme_index: prepared.snapshot_scheme_index,
        }
    };
    if let Err(error) = session.start() {
        let start_rollback_failed = matches!(error, Error::Rollback { .. });
        let close = session.close();
        return Err(if start_rollback_failed {
            error
        } else {
            with_rollback(error, close)
        });
    }
    capabilities.confirm_operation(&operation);

    Ok(Monitor {
        session: Some(session),
        capabilities,
        capacity_hint: prepared.capacity_hint,
        operation,
        effective_address_unit: address_unit,
        snapshot_query,
        custom_scheme_count: prepared.custom_scheme_count,
    })
}

fn classify_operation_staging_error(error: Error, operation: &Operation) -> Error {
    match error {
        Error::Io {
            ref path,
            ref source,
            ..
        } if path.file_name().is_some_and(|name| name == "operations")
            && source.raw_os_error() == Some(22) =>
        {
            Error::UnsupportedOperation {
                operation: operation.clone(),
            }
        }
        Error::Rollback {
            operation: failed,
            rollback,
        } => Error::Rollback {
            operation: Box::new(classify_operation_staging_error(*failed, operation)),
            rollback,
        },
        error => error,
    }
}

fn snapshot_query_scheme(apply_interval: Duration) -> SchemeConfig {
    let pattern = AccessPattern::new(
        RegionSizeRange::new(0, u64::MAX).expect("match-all size range is valid"),
        AccessCountRange::new(0, u32::MAX).expect("match-all access range is valid"),
        AgeRange::new(0, u32::MAX).expect("match-all age range is valid"),
    );
    let mut scheme = SchemeConfig::new(Action::Stat, pattern);
    scheme.apply_interval = apply_interval;
    scheme
}

#[derive(Debug)]
enum SnapshotQuery {
    Unsupported,
    Permanent {
        scheme_index: usize,
    },
    OnDemand {
        base_config: Box<DamonConfig>,
        query_config: Box<DamonConfig>,
        scheme_index: usize,
        installed: bool,
    },
}

/// A running high-level DAMON monitor holding a cooperative session lock.
///
/// The monitor verifies its staged configuration and kdamond thread ID before
/// destructive operations. This cannot provide absolute ownership against
/// tools that ignore the advisory lock and mutate the global sysfs hierarchy.
#[derive(Debug)]
pub struct Monitor {
    session: Option<ExclusiveSession>,
    capabilities: Capabilities,
    capacity_hint: usize,
    operation: Operation,
    effective_address_unit: AddressUnit,
    snapshot_query: SnapshotQuery,
    custom_scheme_count: usize,
}

impl Monitor {
    /// Returns the capabilities discovered when the monitor was staged.
    #[must_use]
    pub const fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// Returns the monitoring operation committed for this session.
    #[must_use]
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    /// Returns the effective address unit committed for snapshot conversion.
    ///
    /// This can differ from the context's configured address unit because
    /// Linux applies non-default units only to physical-address monitoring.
    #[must_use]
    pub const fn effective_address_unit(&self) -> AddressUnit {
        self.effective_address_unit
    }

    /// Returns the number of custom schemes supplied to the workflow builder.
    ///
    /// Any temporary private scheme used by [`Self::snapshot`] is not included.
    #[must_use]
    pub const fn scheme_count(&self) -> usize {
        self.custom_scheme_count
    }

    /// Refreshes and reads one custom scheme's runtime counters.
    ///
    /// Size fields remain in DAMON core address units. Use
    /// [`Self::effective_address_unit`] for checked conversion when needed.
    pub fn scheme_stats(&mut self, scheme_index: usize) -> Result<SchemeStats> {
        self.validate_custom_scheme_index(scheme_index)?;
        self.session
            .as_mut()
            .ok_or(Error::NotRunning)?
            .scheme_stats(0, scheme_index)
    }

    /// Reads one custom scheme's last materialized runtime counters.
    pub fn cached_scheme_stats(&self, scheme_index: usize) -> Result<SchemeStats> {
        self.validate_custom_scheme_index(scheme_index)?;
        self.session
            .as_ref()
            .ok_or(Error::NotRunning)?
            .cached_scheme_stats(0, scheme_index)
    }

    /// Refreshes once and reads every custom scheme's runtime counters.
    ///
    /// This performs one complete ownership-check pair and one kernel refresh,
    /// making it preferable to calling [`Self::scheme_stats`] in a loop.
    pub fn scheme_stats_all(&mut self) -> Result<Vec<SchemeStats>> {
        let count = self.custom_scheme_count;
        self.session
            .as_mut()
            .ok_or(Error::NotRunning)?
            .runtime_batch(|batch| {
                let mut stats = Vec::with_capacity(count);
                if count != 0 {
                    stats.push(batch.scheme_stats(0, 0)?);
                    for scheme_index in 1..count {
                        stats.push(batch.cached_scheme_stats(0, scheme_index)?);
                    }
                }
                Ok(stats)
            })
    }

    /// Reads every custom scheme's last materialized runtime counters.
    pub fn cached_scheme_stats_all(&mut self) -> Result<Vec<SchemeStats>> {
        let count = self.custom_scheme_count;
        self.session
            .as_mut()
            .ok_or(Error::NotRunning)?
            .runtime_batch(|batch| {
                let mut stats = Vec::with_capacity(count);
                for scheme_index in 0..count {
                    stats.push(batch.cached_scheme_stats(0, scheme_index)?);
                }
                Ok(stats)
            })
    }

    /// Refreshes and reads one custom scheme's effective quota in core units.
    pub fn effective_quota_units(&mut self, scheme_index: usize) -> Result<u64> {
        self.validate_custom_scheme_index(scheme_index)?;
        self.ensure_feature_supported(
            SysfsFeature::SchemeQuotaEffectiveBytes,
            "DAMOS effective quota reporting",
        )?;
        self.session
            .as_mut()
            .ok_or(Error::NotRunning)?
            .effective_quota_units(0, scheme_index)
    }

    /// Reads one custom scheme's last materialized effective quota in core units.
    pub fn cached_effective_quota_units(&self, scheme_index: usize) -> Result<u64> {
        self.validate_custom_scheme_index(scheme_index)?;
        self.ensure_feature_supported(
            SysfsFeature::SchemeQuotaEffectiveBytes,
            "DAMOS effective quota reporting",
        )?;
        self.session
            .as_ref()
            .ok_or(Error::NotRunning)?
            .cached_effective_quota_units(0, scheme_index)
    }

    /// Refreshes once and reads every custom scheme's effective quota.
    pub fn effective_quota_units_all(&mut self) -> Result<Vec<u64>> {
        self.ensure_feature_supported(
            SysfsFeature::SchemeQuotaEffectiveBytes,
            "DAMOS effective quota reporting",
        )?;
        let count = self.custom_scheme_count;
        self.session
            .as_mut()
            .ok_or(Error::NotRunning)?
            .runtime_batch(|batch| {
                let mut quotas = Vec::with_capacity(count);
                if count != 0 {
                    quotas.push(batch.effective_quota_units(0, 0)?);
                    for scheme_index in 1..count {
                        quotas.push(batch.cached_effective_quota_units(0, scheme_index)?);
                    }
                }
                Ok(quotas)
            })
    }

    /// Reads every custom scheme's last materialized effective quota.
    pub fn cached_effective_quota_units_all(&mut self) -> Result<Vec<u64>> {
        self.ensure_feature_supported(
            SysfsFeature::SchemeQuotaEffectiveBytes,
            "DAMOS effective quota reporting",
        )?;
        let count = self.custom_scheme_count;
        self.session
            .as_mut()
            .ok_or(Error::NotRunning)?
            .runtime_batch(|batch| {
                let mut quotas = Vec::with_capacity(count);
                for scheme_index in 0..count {
                    quotas.push(batch.cached_effective_quota_units(0, scheme_index)?);
                }
                Ok(quotas)
            })
    }

    /// Pauses monitoring while retaining the running workflow and ownership.
    pub fn pause(&mut self) -> Result<()> {
        self.session.as_mut().ok_or(Error::NotRunning)?.pause()
    }

    /// Resumes a workflow previously paused through [`Self::pause`].
    pub fn resume(&mut self) -> Result<()> {
        self.session.as_mut().ok_or(Error::NotRunning)?.resume()
    }

    /// Queries the current monitored regions.
    ///
    /// Every operation-specific builder creates exactly one target, so regions
    /// are returned in that target's address order. On kernels with online
    /// parameter commits, a private match-all `stat` scheme is installed only
    /// for this query. Older supported kernels retain that scheme while the
    /// monitor runs.
    ///
    /// Linux's synchronous tried-region command can wait until every configured
    /// scheme reaches its next apply interval and provides no timeout. Mutable
    /// access serializes result materialization for this monitor. Kernels before
    /// tried-region queries were introduced can still run the monitor, but this
    /// method returns [`Error::UnsupportedFeature`].
    pub fn snapshot(&mut self) -> Result<Snapshot> {
        let session = self.session.as_mut().ok_or(Error::NotRunning)?;
        let raw = match &mut self.snapshot_query {
            SnapshotQuery::Unsupported => {
                return Err(Error::UnsupportedFeature {
                    feature: "DAMOS tried-region queries",
                });
            }
            SnapshotQuery::Permanent { scheme_index } => {
                session.tried_regions(0, *scheme_index, self.capacity_hint)?
            }
            SnapshotQuery::OnDemand {
                base_config,
                query_config,
                scheme_index,
                installed,
            } => {
                if !*installed {
                    session.update_configuration(query_config)?;
                    *installed = true;
                }
                let operation = match session.tried_regions(0, *scheme_index, self.capacity_hint) {
                    Err(error @ Error::OwnershipLost { .. }) => return Err(error),
                    result => result,
                };
                let restoration = session.update_configuration(base_config);
                if restoration.is_ok() {
                    *installed = false;
                }
                match (operation, restoration) {
                    (Ok(snapshot), Ok(())) => snapshot,
                    (Err(operation), Ok(())) => return Err(operation),
                    (Ok(_), Err(restoration)) => return Err(restoration),
                    (Err(operation), Err(restoration)) => {
                        return Err(Error::Rollback {
                            operation: Box::new(operation),
                            rollback: Box::new(restoration),
                        });
                    }
                }
            }
        };
        Ok(raw.with_effective_address_unit(self.effective_address_unit))
    }

    /// Reads whether the kernel monitoring thread is running.
    pub fn is_running(&self) -> Result<bool> {
        self.session
            .as_ref()
            .map_or(Ok(false), ExclusiveSession::is_running)
    }

    /// Stops monitoring and restores the hierarchy that preceded this monitor.
    pub fn stop(mut self) -> Result<()> {
        self.session.take().ok_or(Error::NotRunning)?.close()
    }

    fn validate_custom_scheme_index(&self, scheme_index: usize) -> Result<()> {
        if scheme_index >= self.custom_scheme_count {
            return Err(Error::IndexOutOfBounds {
                kind: "custom scheme",
                index: scheme_index,
                count: self.custom_scheme_count,
            });
        }
        Ok(())
    }

    fn ensure_feature_supported(&self, feature: SysfsFeature, name: &'static str) -> Result<()> {
        if self.capabilities.feature_support(feature) == CapabilitySupport::Supported {
            Ok(())
        } else {
            Err(Error::UnsupportedFeature { feature: name })
        }
    }
}
