//! High-level vaddr, fvaddr, and paddr workflow builders.

use std::fmt;
use std::io;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::JoinHandle;
use std::time::Instant;

use super::{
    AccessCountRange, AccessPattern, Action, AddressUnit, AgeRange, Capabilities,
    CapabilitySupport, ContextConfig, Damon, DamonConfig, Duration, Error, ExclusiveSession,
    FilterConfig, InitialRegionConfig, KdamondConfig, MonitoringIntervals, Operation, Pid,
    ProbeConfig, RegionBounds, RegionSizeRange, Result, SchemeConfig, SchemeStats, ScopedSnapshot,
    SnapshotScope, SysfsFeature, TargetConfig, TargetIdentity, with_rollback,
};

#[derive(Clone, Debug)]
pub(super) struct WorkflowOptions<'a> {
    damon: &'a Damon,
    sample: Duration,
    aggregation: Duration,
    update: Duration,
    refresh: Duration,
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
            refresh: Duration::ZERO,
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
    pub(super) targets: Vec<ProcessTarget>,
}

/// Backwards-compatible name for [`VaddrSessionBuilder`].
pub type MonitorBuilder<'a> = VaddrSessionBuilder<'a>;

/// Builder for a fixed virtual-address monitoring workflow.
#[derive(Clone, Debug)]
pub struct FvaddrSessionBuilder<'a> {
    pub(super) options: WorkflowOptions<'a>,
    pub(super) targets: Vec<ProcessTarget>,
}

/// One process target for a vaddr or fvaddr workflow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessTarget {
    pid: Pid,
    initial_regions: Option<Vec<InitialRegionConfig>>,
}

impl ProcessTarget {
    /// Creates a process target with no explicit initial regions.
    #[must_use]
    pub const fn new(pid: Pid) -> Self {
        Self {
            pid,
            initial_regions: None,
        }
    }

    /// Returns the target process identifier.
    #[must_use]
    pub const fn pid(&self) -> Pid {
        self.pid
    }

    /// Returns the target-specific initial-region override.
    ///
    /// `None` inherits the builder's regions. `Some(&[])` is an explicit empty
    /// override.
    #[must_use]
    pub fn initial_regions(&self) -> Option<&[InitialRegionConfig]> {
        self.initial_regions.as_deref()
    }

    /// Replaces this target's initial regions.
    #[must_use]
    pub fn regions(mut self, regions: impl IntoIterator<Item = InitialRegionConfig>) -> Self {
        self.initial_regions = Some(regions.into_iter().collect());
        self
    }

    /// Appends one initial region for this target.
    #[must_use]
    pub fn region(mut self, region: InitialRegionConfig) -> Self {
        self.initial_regions
            .get_or_insert_with(Vec::new)
            .push(region);
        self
    }
}

impl From<Pid> for ProcessTarget {
    fn from(pid: Pid) -> Self {
        Self::new(pid)
    }
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

            /// Sets the kernel's periodic sysfs result refresh interval.
            ///
            /// Zero disables periodic refresh. Kernels without `refresh_ms`
            /// reject a non-zero value during staging.
            #[must_use]
            pub const fn result_refresh_interval(mut self, interval: Duration) -> Self {
                self.options.refresh = interval;
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
            /// these schemes so [`Monitor::materialize_snapshot`] remains independent of
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
    /// Replaces the workflow targets with one process.
    #[must_use]
    pub fn pid(mut self, pid: Pid) -> Self {
        self.targets = vec![ProcessTarget::new(pid)];
        self
    }

    /// Replaces all process targets.
    #[must_use]
    pub fn targets<T>(mut self, targets: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<ProcessTarget>,
    {
        self.targets = targets.into_iter().map(Into::into).collect();
        self
    }

    /// Appends one process target.
    #[must_use]
    pub fn target(mut self, target: impl Into<ProcessTarget>) -> Self {
        self.targets.push(target.into());
        self
    }

    /// Replaces optional common initial regions expressed as byte addresses.
    ///
    /// These regions are used by each target that has no target-specific
    /// regions.
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
        if self.targets.is_empty() {
            return Err(Error::InvalidConfiguration {
                field: "virtual-address targets",
                reason: "requires at least one process identifier",
            });
        }
        start_workflow(
            self.options,
            Operation::VirtualAddress,
            self.targets,
            AddressUnit::ONE,
        )
    }
}

impl FvaddrSessionBuilder<'_> {
    /// Replaces the workflow targets with one process.
    #[must_use]
    pub fn pid(mut self, pid: Pid) -> Self {
        self.targets = vec![ProcessTarget::new(pid)];
        self
    }

    /// Replaces all process targets.
    #[must_use]
    pub fn targets<T>(mut self, targets: impl IntoIterator<Item = T>) -> Self
    where
        T: Into<ProcessTarget>,
    {
        self.targets = targets.into_iter().map(Into::into).collect();
        self
    }

    /// Appends one process target.
    #[must_use]
    pub fn target(mut self, target: impl Into<ProcessTarget>) -> Self {
        self.targets.push(target.into());
        self
    }

    /// Replaces required common fixed regions expressed as byte addresses.
    ///
    /// These regions are used by each target that has no target-specific
    /// regions.
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
        if self.targets.is_empty() {
            return Err(Error::InvalidConfiguration {
                field: "fixed virtual-address targets",
                reason: "requires at least one process identifier",
            });
        }
        start_workflow(
            self.options,
            Operation::FixedVirtualAddress,
            self.targets,
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
            Vec::new(),
            self.address_unit,
        )
    }
}

struct PreparedWorkflow {
    base_config: DamonConfig,
    capability_config: DamonConfig,
    snapshot_scheme_index: usize,
    target_identities: Box<[TargetIdentity]>,
    custom_scheme_count: usize,
    capacity_hint: usize,
    sample_interval: Duration,
    refresh_interval: Duration,
}

fn prepare_workflow(
    options: WorkflowOptions<'_>,
    operation: Operation,
    process_targets: Vec<ProcessTarget>,
    address_unit: AddressUnit,
) -> Result<PreparedWorkflow> {
    let intervals = MonitoringIntervals::new(options.sample, options.aggregation, options.update)?;
    let region_bounds = RegionBounds::new(options.min_regions, options.max_regions)?;
    let mut context = ContextConfig::new(operation);
    context.address_unit = address_unit;
    context.intervals = intervals;
    context.region_bounds = region_bounds;
    context.probes = options.probes;
    let mut target_identities = Vec::new();
    if process_targets.is_empty() {
        let mut target = TargetConfig::address_space();
        target.initial_regions = options.initial_regions;
        context.targets.push(target);
        target_identities.push(TargetIdentity::new(0, None));
    } else {
        target_identities.reserve(process_targets.len());
        context.targets.reserve(process_targets.len());
        for (target_index, process_target) in process_targets.into_iter().enumerate() {
            let mut target = TargetConfig::for_pid(process_target.pid);
            target.initial_regions = process_target
                .initial_regions
                .unwrap_or_else(|| options.initial_regions.clone());
            context.targets.push(target);
            target_identities.push(TargetIdentity::new(target_index, Some(process_target.pid)));
        }
    }
    context.schemes = options.schemes;
    let snapshot_scheme_index = context.schemes.len();

    let mut kdamond = KdamondConfig {
        refresh_interval: options.refresh,
        ..KdamondConfig::default()
    };
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
        target_identities: target_identities.into_boxed_slice(),
        custom_scheme_count: snapshot_scheme_index,
        capacity_hint: usize::try_from(region_bounds.max()).unwrap_or(usize::MAX),
        sample_interval: intervals.sample(),
        refresh_interval: options.refresh,
    })
}

fn start_workflow(
    options: WorkflowOptions<'_>,
    operation: Operation,
    process_targets: Vec<ProcessTarget>,
    address_unit: AddressUnit,
) -> Result<Monitor> {
    let damon = options.damon;
    let prepared = prepare_workflow(options, operation.clone(), process_targets, address_unit)?;
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
    let PreparedWorkflow {
        base_config,
        target_identities,
        custom_scheme_count,
        capacity_hint,
        sample_interval,
        refresh_interval,
        ..
    } = prepared;
    let (snapshot_query, maximum_snapshot_apply_interval) = match prepare_snapshot_query(
        &mut session,
        &mut capabilities,
        base_config,
        &target_identities,
        sample_interval,
    ) {
        Ok(result) => result,
        Err(error) => return Err(with_rollback(error, session.close())),
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
        capacity_hint,
        operation,
        effective_address_unit: address_unit,
        snapshot_query,
        custom_scheme_count,
        maximum_snapshot_apply_interval,
        refresh_interval,
        cached_snapshots: Vec::new(),
    })
}

fn prepare_snapshot_query(
    session: &mut ExclusiveSession,
    capabilities: &mut Capabilities,
    base_config: DamonConfig,
    target_identities: &[TargetIdentity],
    sample_interval: Duration,
) -> Result<(SnapshotQuery, Duration)> {
    let online_commit_supported = capabilities
        .feature_support(SysfsFeature::OnlineParametersCommit)
        == CapabilitySupport::Supported;
    let apply_interval = if online_commit_supported
        && capabilities.feature_support(SysfsFeature::SchemeApplyInterval)
            == CapabilitySupport::Supported
    {
        sample_interval
    } else {
        Duration::ZERO
    };
    let tried_regions_supported =
        capabilities.feature_support(SysfsFeature::TriedRegions) == CapabilitySupport::Supported;
    let (query_config, descriptors) = if tried_regions_supported
        && target_identities.len() > 1
        && capabilities.feature_support(SysfsFeature::SchemeFilterTarget)
            != CapabilitySupport::Unsupported
    {
        let (filtered, descriptors) =
            snapshot_query_configuration(&base_config, target_identities, apply_interval, true);
        match session.replace_staged_configuration(&filtered) {
            Ok(()) => {
                let filtered_scheme_indices =
                    (0..filtered.kdamonds[0].contexts[0].schemes.len()).collect::<Vec<_>>();
                *capabilities = session.capabilities_for_schemes(0, &filtered_scheme_indices)?;
                capabilities.confirm_feature(SysfsFeature::SchemeFilterTarget);
                (filtered, descriptors)
            }
            Err(error) if target_filter_is_unsupported(&error) => {
                capabilities.reject_feature(SysfsFeature::SchemeFilterTarget);
                snapshot_query_configuration(&base_config, target_identities, apply_interval, false)
            }
            Err(error) => return Err(error),
        }
    } else {
        snapshot_query_configuration(&base_config, target_identities, apply_interval, false)
    };
    let maximum_snapshot_apply_interval = maximum_effective_apply_interval(&query_config);
    let snapshot_query = if !tried_regions_supported {
        session.replace_staged_configuration(&base_config)?;
        SnapshotQuery::Unsupported
    } else if online_commit_supported {
        session.replace_staged_configuration(&base_config)?;
        SnapshotQuery::OnDemand {
            base_config: Box::new(base_config),
            query_config: Box::new(query_config),
            descriptors,
            installed: false,
        }
    } else {
        session.replace_staged_configuration(&query_config)?;
        SnapshotQuery::Permanent { descriptors }
    };
    Ok((snapshot_query, maximum_snapshot_apply_interval))
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

#[derive(Clone, Copy, Debug)]
struct SnapshotDescriptor {
    scheme_index: usize,
    scope: SnapshotScope,
}

fn snapshot_query_configuration(
    base_config: &DamonConfig,
    target_identities: &[TargetIdentity],
    apply_interval: Duration,
    isolate_targets: bool,
) -> (DamonConfig, Box<[SnapshotDescriptor]>) {
    let mut config = base_config.clone();
    let schemes = &mut config.kdamonds[0].contexts[0].schemes;
    let first_scheme_index = schemes.len();
    if target_identities.len() == 1 {
        schemes.push(snapshot_query_scheme(apply_interval));
        return (
            config,
            vec![SnapshotDescriptor {
                scheme_index: first_scheme_index,
                scope: SnapshotScope::Target(target_identities[0]),
            }]
            .into_boxed_slice(),
        );
    }
    if isolate_targets {
        let mut descriptors = Vec::with_capacity(target_identities.len());
        for identity in target_identities.iter().copied() {
            let mut scheme = snapshot_query_scheme(apply_interval);
            scheme
                .filters
                .push(FilterConfig::target(identity.target_index(), false, false));
            let scheme_index = schemes.len();
            schemes.push(scheme);
            descriptors.push(SnapshotDescriptor {
                scheme_index,
                scope: SnapshotScope::Target(identity),
            });
        }
        return (config, descriptors.into_boxed_slice());
    }

    schemes.push(snapshot_query_scheme(apply_interval));
    (
        config,
        vec![SnapshotDescriptor {
            scheme_index: first_scheme_index,
            scope: SnapshotScope::Scheme,
        }]
        .into_boxed_slice(),
    )
}

fn maximum_effective_apply_interval(config: &DamonConfig) -> Duration {
    config
        .kdamonds
        .iter()
        .flat_map(|kdamond| &kdamond.contexts)
        .flat_map(|context| {
            context.schemes.iter().map(move |scheme| {
                if scheme.apply_interval.is_zero() {
                    context.intervals.aggregation()
                } else {
                    scheme.apply_interval
                }
            })
        })
        .max()
        .unwrap_or(Duration::ZERO)
}

fn target_filter_is_unsupported(error: &Error) -> bool {
    match error {
        Error::UnsupportedFeature { .. } => true,
        Error::Io { path, source, .. } => {
            source.raw_os_error() == Some(22)
                && path
                    .components()
                    .any(|component| component.as_os_str().to_string_lossy().contains("filter"))
        }
        _ => false,
    }
}

#[derive(Debug)]
enum SnapshotQuery {
    Unsupported,
    Permanent {
        descriptors: Box<[SnapshotDescriptor]>,
    },
    OnDemand {
        base_config: Box<DamonConfig>,
        query_config: Box<DamonConfig>,
        descriptors: Box<[SnapshotDescriptor]>,
        installed: bool,
    },
}

/// State returned by [`SnapshotRequest::wait_until`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SnapshotWait {
    /// The request completed and can be consumed with [`SnapshotRequest::finish`].
    Ready,
    /// The request is still running and retains ownership of the monitor.
    Pending,
}

/// A completed asynchronous snapshot request and its owned monitor.
#[must_use = "the outcome contains the monitor recovered from the snapshot worker"]
#[derive(Debug)]
pub struct SnapshotOutcome {
    monitor: Monitor,
    snapshots: Result<Vec<ScopedSnapshot>>,
}

impl SnapshotOutcome {
    /// Returns the monitor recovered from the request.
    #[must_use]
    pub const fn monitor(&self) -> &Monitor {
        &self.monitor
    }

    /// Returns the materialization result without consuming the outcome.
    pub fn snapshots(&self) -> std::result::Result<&[ScopedSnapshot], &Error> {
        match &self.snapshots {
            Ok(snapshots) => Ok(snapshots),
            Err(error) => Err(error),
        }
    }

    /// Splits the outcome into the recovered monitor and materialization result.
    pub fn into_parts(self) -> (Monitor, Result<Vec<ScopedSnapshot>>) {
        (self.monitor, self.snapshots)
    }
}

/// A failure to start a snapshot worker and the monitor it did not consume.
#[must_use = "the error contains the monitor that remains available to the caller"]
#[derive(Debug)]
pub struct SnapshotStartError {
    error: Error,
    monitor: Box<Monitor>,
}

impl SnapshotStartError {
    fn new(error: Error, monitor: Monitor) -> Self {
        Self {
            error,
            monitor: Box::new(monitor),
        }
    }

    /// Returns the worker-start error.
    #[must_use]
    pub const fn error(&self) -> &Error {
        &self.error
    }

    /// Returns the monitor that was not transferred to a worker.
    #[must_use]
    pub const fn monitor(&self) -> &Monitor {
        &self.monitor
    }

    /// Splits the failure into its error and recoverable monitor.
    #[must_use]
    pub fn into_parts(self) -> (Error, Monitor) {
        (self.error, *self.monitor)
    }
}

impl fmt::Display for SnapshotStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for SnapshotStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// A snapshot command running on a dedicated worker thread.
///
/// Linux exposes the command as a synchronous sysfs write with no
/// cancellation. A pending request therefore owns its [`Monitor`] until the
/// write returns. Dropping a pending request waits for the worker so no hidden
/// thread can continue mutating the session after the request disappears.
#[must_use = "dropping a pending snapshot request waits for its blocking kernel operation"]
#[derive(Debug)]
pub struct SnapshotRequest {
    receiver: Receiver<(Monitor, Result<Vec<ScopedSnapshot>>)>,
    worker: Option<JoinHandle<()>>,
    outcome: Option<SnapshotOutcome>,
}

impl SnapshotRequest {
    /// Returns whether the worker has completed without blocking.
    pub fn is_ready(&mut self) -> Result<bool> {
        if self.outcome.is_some() {
            return Ok(true);
        }
        match self.receiver.try_recv() {
            Ok((monitor, snapshots)) => {
                self.outcome = Some(SnapshotOutcome { monitor, snapshots });
                self.join_worker()?;
                Ok(true)
            }
            Err(mpsc::TryRecvError::Empty) => Ok(false),
            Err(mpsc::TryRecvError::Disconnected) => {
                self.join_worker()?;
                Err(Error::SnapshotWorkerDisconnected)
            }
        }
    }

    /// Waits until `deadline` without claiming to cancel a pending syscall.
    ///
    /// A [`SnapshotWait::Pending`] result keeps this request and its monitor in
    /// a clearly pending state. Call this method again or use [`Self::finish`].
    pub fn wait_until(&mut self, deadline: Instant) -> Result<SnapshotWait> {
        if self.outcome.is_some() {
            return Ok(SnapshotWait::Ready);
        }
        let timeout = deadline.saturating_duration_since(Instant::now());
        match self.receiver.recv_timeout(timeout) {
            Ok((monitor, snapshots)) => {
                self.outcome = Some(SnapshotOutcome { monitor, snapshots });
                self.join_worker()?;
                Ok(SnapshotWait::Ready)
            }
            Err(RecvTimeoutError::Timeout) => Ok(SnapshotWait::Pending),
            Err(RecvTimeoutError::Disconnected) => {
                self.join_worker()?;
                Err(Error::SnapshotWorkerDisconnected)
            }
        }
    }

    /// Waits for completion and returns the monitor even if materialization failed.
    pub fn finish(mut self) -> Result<SnapshotOutcome> {
        if self.outcome.is_none() {
            let (monitor, snapshots) = self
                .receiver
                .recv()
                .map_err(|_| Error::SnapshotWorkerDisconnected)?;
            self.outcome = Some(SnapshotOutcome { monitor, snapshots });
        }
        self.join_worker()?;
        self.outcome.take().ok_or(Error::SnapshotWorkerDisconnected)
    }

    fn join_worker(&mut self) -> Result<()> {
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| Error::SnapshotWorkerDisconnected)?;
        }
        Ok(())
    }
}

impl Drop for SnapshotRequest {
    fn drop(&mut self) {
        if self.outcome.is_none() {
            if let Ok((monitor, snapshots)) = self.receiver.recv() {
                self.outcome = Some(SnapshotOutcome { monitor, snapshots });
            }
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn materialize_scoped_snapshots(
    session: &mut ExclusiveSession,
    descriptors: &[SnapshotDescriptor],
    capacity_hint: usize,
    address_unit: AddressUnit,
) -> Result<Vec<ScopedSnapshot>> {
    let Some((first, remaining)) = descriptors.split_first() else {
        return Err(Error::InvalidConfiguration {
            field: "snapshot query schemes",
            reason: "requires at least one scheme",
        });
    };
    let requested_at = std::time::SystemTime::now();
    let started_at = std::time::Instant::now();
    let raw_snapshots = session.runtime_batch(|batch| {
        let mut snapshots = Vec::with_capacity(descriptors.len());
        let raw = batch.tried_regions(0, first.scheme_index, capacity_hint)?;
        snapshots.push((first, raw.with_effective_address_unit(address_unit)));
        for descriptor in remaining {
            let raw = batch.cached_tried_regions(0, descriptor.scheme_index, capacity_hint)?;
            snapshots.push((descriptor, raw.with_effective_address_unit(address_unit)));
        }
        Ok(snapshots)
    })?;
    let timing = crate::SnapshotTiming::new(
        requested_at,
        std::time::SystemTime::now(),
        started_at.elapsed(),
    );
    Ok(raw_snapshots
        .into_iter()
        .map(|(descriptor, snapshot)| {
            ScopedSnapshot::new(
                0,
                0,
                descriptor.scheme_index,
                descriptor.scope,
                timing,
                snapshot,
            )
        })
        .collect())
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
    maximum_snapshot_apply_interval: Duration,
    refresh_interval: Duration,
    cached_snapshots: Vec<ScopedSnapshot>,
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
    /// Any temporary private scheme used by [`Self::materialize_snapshot`] is not included.
    #[must_use]
    pub const fn scheme_count(&self) -> usize {
        self.custom_scheme_count
    }

    /// Returns the largest effective apply interval involved in snapshots.
    ///
    /// A scheme with a zero apply interval uses its context's aggregation
    /// interval. This value is a scheduling hint, not a timeout or hard upper
    /// bound. Linux performs tried-region materialization synchronously and
    /// provides no cancellation mechanism for the state write. `None` means
    /// tried-region queries are unsupported.
    #[must_use]
    pub fn maximum_snapshot_apply_interval(&self) -> Option<Duration> {
        match &self.snapshot_query {
            SnapshotQuery::Unsupported => None,
            SnapshotQuery::Permanent { .. } | SnapshotQuery::OnDemand { .. } => {
                Some(self.maximum_snapshot_apply_interval)
            }
        }
    }

    /// Returns the configured periodic sysfs result refresh interval.
    ///
    /// When non-zero, cached result methods can avoid explicit refresh
    /// commands when the caller accepts data from the kernel's last refresh.
    #[must_use]
    pub const fn result_refresh_interval(&self) -> Duration {
        self.refresh_interval
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
    pub fn cached_scheme_stats_all(&self) -> Result<Vec<SchemeStats>> {
        let count = self.custom_scheme_count;
        self.session
            .as_ref()
            .ok_or(Error::NotRunning)?
            .read_batch(|batch| {
                let mut stats = Vec::with_capacity(count);
                for scheme_index in 0..count {
                    stats.push(batch.scheme_stats(0, scheme_index)?);
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
    pub fn cached_effective_quota_units_all(&self) -> Result<Vec<u64>> {
        self.ensure_feature_supported(
            SysfsFeature::SchemeQuotaEffectiveBytes,
            "DAMOS effective quota reporting",
        )?;
        let count = self.custom_scheme_count;
        self.session
            .as_ref()
            .ok_or(Error::NotRunning)?
            .read_batch(|batch| {
                let mut quotas = Vec::with_capacity(count);
                for scheme_index in 0..count {
                    quotas.push(batch.effective_quota_units(0, scheme_index)?);
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

    /// Materializes one scoped snapshot.
    ///
    /// Use [`Self::materialize_snapshots`] for a multi-target query that the kernel can
    /// isolate into multiple target-scoped results. Linux's synchronous
    /// tried-region command can wait until every scheme reaches its next apply
    /// interval and provides no timeout or cancellation. See
    /// [`Self::maximum_snapshot_apply_interval`] for a scheduling hint.
    pub fn materialize_snapshot(&mut self) -> Result<&ScopedSnapshot> {
        let result_count = match &self.snapshot_query {
            SnapshotQuery::Unsupported => None,
            SnapshotQuery::Permanent { descriptors }
            | SnapshotQuery::OnDemand { descriptors, .. } => Some(descriptors.len()),
        };
        if let Some(count) = result_count.filter(|count| *count != 1) {
            return Err(Error::MultipleSnapshotResults { count });
        }
        let snapshots = self.materialize_snapshots()?;
        Ok(&snapshots[0])
    }

    /// Materializes all target-scoped or ungrouped snapshot results.
    ///
    /// One target-filtered private scheme is used per target when the kernel
    /// accepts target filters. Otherwise one [`SnapshotScope::Scheme`]
    /// result is returned. Target identity is never inferred from addresses.
    pub fn materialize_snapshots(&mut self) -> Result<&[ScopedSnapshot]> {
        let capacity_hint = self.capacity_hint;
        let address_unit = self.effective_address_unit;
        let session = self.session.as_mut().ok_or(Error::NotRunning)?;
        let snapshots = match &mut self.snapshot_query {
            SnapshotQuery::Unsupported => {
                return Err(Error::UnsupportedFeature {
                    feature: "DAMOS tried-region queries",
                });
            }
            SnapshotQuery::Permanent { descriptors } => {
                materialize_scoped_snapshots(session, descriptors, capacity_hint, address_unit)?
            }
            SnapshotQuery::OnDemand {
                base_config,
                query_config,
                descriptors,
                installed,
            } => {
                if !*installed {
                    session.update_configuration(query_config)?;
                    *installed = true;
                }
                let operation = match materialize_scoped_snapshots(
                    session,
                    descriptors,
                    capacity_hint,
                    address_unit,
                ) {
                    Err(error @ Error::OwnershipLost { .. }) => return Err(error),
                    result => result,
                };
                let restoration = session.update_configuration(base_config);
                if restoration.is_ok() {
                    *installed = false;
                }
                match (operation, restoration) {
                    (Ok(snapshots), Ok(())) => snapshots,
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
        self.cached_snapshots = snapshots;
        Ok(&self.cached_snapshots)
    }

    /// Materializes one result and transfers its allocation to the caller.
    pub fn materialize_snapshot_owned(&mut self) -> Result<ScopedSnapshot> {
        let result_count = match &self.snapshot_query {
            SnapshotQuery::Unsupported => None,
            SnapshotQuery::Permanent { descriptors }
            | SnapshotQuery::OnDemand { descriptors, .. } => Some(descriptors.len()),
        };
        if let Some(count) = result_count.filter(|count| *count != 1) {
            return Err(Error::MultipleSnapshotResults { count });
        }
        self.materialize_snapshots()?;
        self.cached_snapshots.pop().ok_or(Error::OwnershipLost {
            reason: "a successful singular snapshot request returned no result",
        })
    }

    /// Materializes all results and transfers their allocations to the caller.
    pub fn materialize_snapshots_owned(&mut self) -> Result<Vec<ScopedSnapshot>> {
        self.materialize_snapshots()?;
        Ok(std::mem::take(&mut self.cached_snapshots))
    }

    /// Starts a blocking snapshot command on a worker that owns this monitor.
    ///
    /// The request can be polled with a deadline, but the kernel write cannot
    /// be cancelled. Use [`SnapshotRequest::finish`] to recover the monitor and
    /// inspect the snapshot result.
    pub fn request_snapshot(self) -> std::result::Result<SnapshotRequest, SnapshotStartError> {
        self.request_snapshot_with(|monitor_receiver, sender| {
            std::thread::Builder::new()
                .name("damon-snapshot".into())
                .spawn(move || run_snapshot_worker(&monitor_receiver, &sender))
        })
    }

    fn request_snapshot_with(
        self,
        spawn_worker: impl FnOnce(
            Receiver<Monitor>,
            SyncSender<(Monitor, Result<Vec<ScopedSnapshot>>)>,
        ) -> io::Result<JoinHandle<()>>,
    ) -> std::result::Result<SnapshotRequest, SnapshotStartError> {
        let (monitor_sender, monitor_receiver) = mpsc::sync_channel(1);
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = match spawn_worker(monitor_receiver, sender) {
            Ok(worker) => worker,
            Err(source) => {
                return Err(SnapshotStartError::new(
                    Error::SnapshotWorkerSpawn { source },
                    self,
                ));
            }
        };
        if let Err(mpsc::SendError(monitor)) = monitor_sender.send(self) {
            let _ = worker.join();
            return Err(SnapshotStartError::new(
                Error::SnapshotWorkerDisconnected,
                monitor,
            ));
        }
        Ok(SnapshotRequest {
            receiver,
            worker: Some(worker),
            outcome: None,
        })
    }

    #[cfg(test)]
    pub(super) fn request_snapshot_with_spawn_error(
        self,
        source: io::Error,
    ) -> std::result::Result<SnapshotRequest, SnapshotStartError> {
        self.request_snapshot_with(|_, _| Err(source))
    }

    /// Returns snapshots from the last successful materialization.
    ///
    /// This performs no sysfs access. The slice is empty before the first
    /// successful snapshot request.
    #[must_use]
    pub fn cached_snapshots(&self) -> &[ScopedSnapshot] {
        &self.cached_snapshots
    }

    /// Transfers the cached result allocation to the caller without sysfs access.
    #[must_use]
    pub fn take_cached_snapshots(&mut self) -> Vec<ScopedSnapshot> {
        std::mem::take(&mut self.cached_snapshots)
    }

    /// Returns the last singular snapshot without accessing sysfs.
    pub fn cached_snapshot(&self) -> Result<Option<&ScopedSnapshot>> {
        match self.cached_snapshots.len() {
            0 => Ok(None),
            1 => Ok(self.cached_snapshots.first()),
            count => Err(Error::MultipleSnapshotResults { count }),
        }
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

fn run_snapshot_worker(
    monitor_receiver: &Receiver<Monitor>,
    sender: &SyncSender<(Monitor, Result<Vec<ScopedSnapshot>>)>,
) {
    let Ok(mut monitor) = monitor_receiver.recv() else {
        return;
    };
    let snapshots = monitor.materialize_snapshots_owned();
    let _ = sender.send((monitor, snapshots));
}
