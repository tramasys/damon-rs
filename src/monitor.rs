use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::sysfs::{
    Action, CapabilitySupport, ConfigurationFingerprint, ConfigurationSnapshot, DamonAdmin,
    DamonConfig, Kdamond, KdamondCommand, KdamondState, Operation, SysfsFeature,
};
use crate::{
    AddressUnit, Capabilities, Error, MonitoringIntervals, Pid, RegionBounds, Result, Snapshot,
};

/// Conventional advisory lock used by high-level DAMON sessions.
pub const DEFAULT_SESSION_LOCK_PATH: &str = "/run/lock/damon-rs.lock";

/// Entry point for high-level DAMON monitoring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Damon {
    admin: DamonAdmin,
    lock_path: PathBuf,
}

impl Damon {
    /// Opens the conventional `/sys/kernel/mm/damon/admin` hierarchy.
    pub fn new() -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(Error::UnsupportedPlatform);
        }
        Self::at(crate::sysfs::DEFAULT_ADMIN_PATH)
    }

    /// Opens a DAMON admin hierarchy at a custom location.
    ///
    /// This is primarily useful for mounted sysfs instances, containers, and
    /// deterministic test fixtures.
    pub fn at(path: impl AsRef<Path>) -> Result<Self> {
        Self::at_with_lock(path, DEFAULT_SESSION_LOCK_PATH)
    }

    /// Opens a DAMON hierarchy with a custom high-level session lock path.
    ///
    /// Cooperating controllers must use the same lock path. The lock is
    /// advisory because the kernel DAMON sysfs ABI has no ownership primitive.
    /// The lock file's parent directory should be trusted and non-writable by
    /// unprivileged users on a production system.
    pub fn at_with_lock(path: impl AsRef<Path>, lock_path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            admin: DamonAdmin::open(path)?,
            lock_path: lock_path.as_ref().to_path_buf(),
        })
    }

    /// Returns the advisory lock path used by high-level sessions.
    #[must_use]
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    /// Starts building a virtual-address monitor for a process.
    #[must_use]
    pub fn monitor_pid(&self, pid: Pid) -> MonitorBuilder<'_> {
        MonitorBuilder {
            damon: self,
            pid,
            sample: MonitoringIntervals::default().sample(),
            aggregation: MonitoringIntervals::default().aggregation(),
            update: MonitoringIntervals::default().update(),
            min_regions: RegionBounds::default().min(),
            max_regions: RegionBounds::default().max(),
        }
    }

    /// Transactionally stages a complete owned DAMON configuration.
    ///
    /// The complete object graph is validated before the first sysfs access.
    /// Staging then holds the advisory session lock, requires every existing
    /// kdamond to be stopped, and verifies the values read back from the
    /// kernel. If staging fails, the preceding writable hierarchy is restored,
    /// including unknown future attributes.
    ///
    /// The kernel does not provide an atomic replacement or ownership
    /// primitive. Other controllers must honor [`Self::lock_path`] for these
    /// guarantees to hold, and readers can observe intermediate sysfs writes.
    pub fn stage_configuration(&self, config: &DamonConfig) -> Result<()> {
        config.validate()?;
        let session_lock = SessionLock::acquire(&self.lock_path)?;
        self.stage_validated_configuration_locked(&session_lock, config)
    }

    /// Stages a validated configuration while the caller retains ownership of
    /// the advisory session lock.
    ///
    /// Keeping this boundary explicit lets a future running session stage,
    /// start, and record its ownership fingerprint under one uninterrupted
    /// lock acquisition.
    fn stage_validated_configuration_locked(
        &self,
        _session_lock: &SessionLock,
        config: &DamonConfig,
    ) -> Result<()> {
        retry_busy(|| ensure_hierarchy_stopped(&self.admin))?;

        let previous = retry_busy(|| self.admin.configuration_snapshot())?;
        let observed = match retry_busy(|| self.admin.configuration()) {
            Ok(observed) => Some(observed),
            Err(error) if replaceable_configuration_read_error(&error) => None,
            Err(error) => return Err(error),
        };
        if !retry_busy(|| previous.values_match_current())? {
            return Err(Error::OwnershipLost {
                reason: "the DAMON hierarchy changed while it was being captured",
            });
        }
        retry_busy(|| ensure_hierarchy_stopped(&self.admin))?;
        if observed
            .as_ref()
            .is_some_and(|observed| config.equivalent_after_kernel_normalization(observed))
        {
            return Ok(());
        }

        let operation = stage_and_verify_configuration(&self.admin, config, observed.as_ref());
        match operation {
            Ok(()) => Ok(()),
            Err(operation) => Err(with_rollback(
                operation,
                restore_configuration(&self.admin, &previous),
            )),
        }
    }

    /// Exclusively stages representative nodes and discovers this kernel's
    /// concrete and semantic DAMON sysfs capabilities.
    ///
    /// Discovery holds the same advisory lock as a monitor and requires the
    /// global DAMON hierarchy to be empty. It never starts a kdamond. The
    /// temporary hierarchy is removed before this method returns. This makes
    /// capabilities below indexed children and accepted filter values
    /// observable without replacing another controller's configuration.
    pub fn capabilities(&self) -> Result<Capabilities> {
        let _session_lock = SessionLock::acquire(&self.lock_path)?;
        let existing = self.admin.kdamond_count()?;
        if existing != 0 {
            return Err(Error::InUse { kdamonds: existing });
        }

        retry_busy(|| self.admin.set_kdamond_count(1))?;
        let kdamond = self.admin.kdamond(0);
        let result = stage_capability_probe(&kdamond);
        match result {
            Ok((capabilities, fingerprint)) => {
                cleanup_capability_probe(&self.admin, &kdamond, &fingerprint)?;
                Ok(capabilities)
            }
            Err(operation) => Err(with_rollback(
                operation,
                rollback_unstarted_slot(&self.admin, &kdamond),
            )),
        }
    }
}

fn replaceable_configuration_read_error(error: &Error) -> bool {
    matches!(
        error,
        Error::InvalidConfiguration { .. } | Error::InvalidKernelValue { .. }
    )
}

fn stage_and_verify_configuration(
    admin: &DamonAdmin,
    config: &DamonConfig,
    observed: Option<&DamonConfig>,
) -> Result<()> {
    retry_busy(|| {
        ensure_hierarchy_stopped(admin)?;
        admin.stage_validated_configuration_from(config, observed)
    })?;

    retry_busy(|| ensure_hierarchy_stopped(admin))?;
    let staged = retry_busy(|| admin.configuration_snapshot())?;
    let observed = retry_busy(|| admin.configuration())?;
    if let Some(error) = config.mismatch_error(&observed) {
        return Err(error);
    }
    if !retry_busy(|| staged.values_match_current())? {
        return Err(Error::OwnershipLost {
            reason: "the staged DAMON hierarchy changed during verification",
        });
    }
    retry_busy(|| ensure_hierarchy_stopped(admin))
}

fn restore_configuration(admin: &DamonAdmin, snapshot: &ConfigurationSnapshot) -> Result<()> {
    retry_busy(|| ensure_hierarchy_stopped(admin))?;
    retry_busy(|| {
        ensure_hierarchy_stopped(admin)?;
        snapshot.restore()
    })?;
    retry_busy(|| ensure_hierarchy_stopped(admin))?;
    if !retry_busy(|| snapshot.matches_current())? {
        return Err(Error::OwnershipLost {
            reason: "the restored DAMON hierarchy changed during verification",
        });
    }
    Ok(())
}

fn ensure_hierarchy_stopped(admin: &DamonAdmin) -> Result<()> {
    let count = admin.kdamond_count()?;
    for index in 0..count {
        match admin.kdamond(index).state()? {
            KdamondState::Off => {}
            KdamondState::On => return Err(Error::KdamondRunning { index }),
            KdamondState::Unknown(state) => return Err(Error::UnexpectedKdamondState { state }),
        }
    }
    if admin.kdamond_count()? != count {
        return Err(Error::OwnershipLost {
            reason: "the kdamond count changed while checking transaction safety",
        });
    }
    Ok(())
}

fn stage_capability_probe(kdamond: &Kdamond) -> Result<(Capabilities, ConfigurationFingerprint)> {
    kdamond.set_default_refresh_interval_if_present()?;
    retry_busy(|| kdamond.set_context_count(1))?;
    let context = kdamond.context(0);
    retry_busy(|| context.set_target_count(1))?;
    retry_busy(|| context.set_scheme_count(1))?;
    kdamond.stage_optional_capability_children(0, 0, 0)?;

    let preliminary = kdamond.capabilities(0, 0)?;
    if preliminary.feature_support(SysfsFeature::AttributeProbeCount)
        == CapabilitySupport::Supported
    {
        retry_busy(|| context.set_probe_count(1))?;
        let with_probe = kdamond.capabilities(0, 0)?;
        if with_probe.feature_support(SysfsFeature::ProbeFilterCount)
            == CapabilitySupport::Supported
        {
            retry_busy(|| context.probe(0).set_filter_count(1))?;
        }
    }

    let semantic_capabilities = retry_busy(|| kdamond.probe_semantic_filter_capabilities(0, 0))?;
    let mut capabilities = kdamond.capabilities(0, 0)?;
    capabilities.apply_feature_capabilities(semantic_capabilities);
    capabilities.replace_operations(retry_busy(|| kdamond.probe_operations(0))?);
    let fingerprint = kdamond.configuration_fingerprint()?;
    Ok((capabilities, fingerprint))
}

fn cleanup_capability_probe(
    admin: &DamonAdmin,
    kdamond: &Kdamond,
    fingerprint: &ConfigurationFingerprint,
) -> Result<()> {
    if admin.kdamond_count()? != 1 || !fingerprint.matches_current()? {
        return Err(Error::OwnershipLost {
            reason: "the staged capability-probe configuration changed",
        });
    }
    match retry_busy(|| kdamond.state())? {
        KdamondState::Off => retry_busy(|| admin.set_kdamond_count(0)),
        KdamondState::On => Err(Error::OwnershipLost {
            reason: "the capability-probe kdamond was started externally",
        }),
        KdamondState::Unknown(_) => Err(Error::OwnershipLost {
            reason: "the capability-probe kdamond state changed",
        }),
    }
}

/// Builder for a process virtual-address monitor.
#[derive(Clone, Debug)]
pub struct MonitorBuilder<'a> {
    damon: &'a Damon,
    pid: Pid,
    sample: Duration,
    aggregation: Duration,
    update: Duration,
    min_regions: u64,
    max_regions: u64,
}

impl MonitorBuilder<'_> {
    /// Replaces all monitoring intervals.
    #[must_use]
    pub fn intervals(mut self, intervals: MonitoringIntervals) -> Self {
        self.sample = intervals.sample();
        self.aggregation = intervals.aggregation();
        self.update = intervals.update();
        self
    }

    /// Sets the interval between access samples.
    #[must_use]
    pub const fn sample_interval(mut self, interval: Duration) -> Self {
        self.sample = interval;
        self
    }

    /// Sets the interval between aggregation snapshots.
    #[must_use]
    pub const fn aggregation_interval(mut self, interval: Duration) -> Self {
        self.aggregation = interval;
        self
    }

    /// Sets the interval between monitoring-operations updates.
    #[must_use]
    pub const fn operations_update_interval(mut self, interval: Duration) -> Self {
        self.update = interval;
        self
    }

    /// Sets lower and upper bounds for the number of monitoring regions.
    #[must_use]
    pub const fn region_bounds(mut self, min: u64, max: u64) -> Self {
        self.min_regions = min;
        self.max_regions = max;
        self
    }

    /// Validates, stages, and starts this monitor.
    ///
    /// The method holds an advisory file lock for the monitor's lifetime,
    /// refuses to replace a staged kdamond, and rechecks the staged
    /// configuration and kernel-thread ID. Uncooperative controllers can
    /// bypass the file lock because DAMON sysfs has no ownership primitive.
    pub fn start(self) -> Result<Monitor> {
        let intervals = MonitoringIntervals::new(self.sample, self.aggregation, self.update)?;
        let region_bounds = RegionBounds::new(self.min_regions, self.max_regions)?;
        let session_lock = SessionLock::acquire(&self.damon.lock_path)?;
        let existing = self.damon.admin.kdamond_count()?;
        if existing != 0 {
            return Err(Error::InUse { kdamonds: existing });
        }

        retry_busy(|| self.damon.admin.set_kdamond_count(1))?;
        let kdamond = self.damon.admin.kdamond(0);
        let staged_count = match self.damon.admin.kdamond_count() {
            Ok(count) => count,
            Err(operation) => {
                return Err(with_rollback(
                    operation,
                    rollback_unstarted_slot(&self.damon.admin, &kdamond),
                ));
            }
        };
        if staged_count != 1 {
            return Err(Error::OwnershipLost {
                reason: "kdamond count changed immediately after staging",
            });
        }
        let setup = configure_monitor(&kdamond, self.pid, intervals, region_bounds);
        let (mut capabilities, staged) = match setup {
            Ok(configured) => configured,
            Err(operation) => {
                return Err(with_rollback(
                    operation,
                    rollback_unstarted_slot(&self.damon.admin, &kdamond),
                ));
            }
        };
        if let Err(operation) = staged.verify(&self.damon.admin, &kdamond) {
            return Err(with_rollback(
                operation,
                rollback_unstarted_monitor(&self.damon.admin, &kdamond, &staged),
            ));
        }

        if let Err(operation) = retry_busy(|| kdamond.command(KdamondCommand::On)) {
            return Err(with_rollback(
                operation,
                rollback_unstarted_monitor(&self.damon.admin, &kdamond, &staged),
            ));
        }
        let kdamond_pid = match running_thread_pid(&kdamond) {
            Ok(pid) => pid,
            Err(operation) => {
                return Err(with_rollback(
                    operation,
                    rollback_started_without_identity(&self.damon.admin, &kdamond, &staged),
                ));
            }
        };
        let ownership = Ownership {
            staged,
            kdamond_pid,
        };
        if let Err(operation) = ownership.verify_running(&self.damon.admin, &kdamond) {
            return Err(with_rollback(
                operation,
                rollback_owned_monitor(&self.damon.admin, &kdamond, &ownership),
            ));
        }
        capabilities.confirm_operation(&Operation::VirtualAddress);

        Ok(Monitor {
            admin: self.damon.admin.clone(),
            kdamond,
            capabilities,
            capacity_hint: usize::try_from(region_bounds.max()).unwrap_or(usize::MAX),
            effective_address_unit: ownership.staged.effective_address_unit,
            ownership,
            _session_lock: session_lock,
            running: true,
            owns_slot: true,
        })
    }
}

fn configure_monitor(
    kdamond: &Kdamond,
    pid: Pid,
    intervals: MonitoringIntervals,
    region_bounds: RegionBounds,
) -> Result<(Capabilities, StagedOwnership)> {
    kdamond.set_default_refresh_interval_if_present()?;
    retry_busy(|| kdamond.set_context_count(1))?;
    let context = kdamond.context(0);
    if let Some(operations) = context.available_operations_if_present()? {
        if !operations.contains(&Operation::VirtualAddress) {
            return Err(Error::UnsupportedOperation {
                operation: Operation::VirtualAddress,
            });
        }
    }

    context.set_operation(&Operation::VirtualAddress)?;
    if context.operation()? != Operation::VirtualAddress {
        return Err(Error::UnsupportedOperation {
            operation: Operation::VirtualAddress,
        });
    }
    context.set_default_address_unit_if_present()?;
    context.set_unpaused_if_present()?;
    context.set_intervals(intervals)?;
    context.set_region_bounds(region_bounds)?;
    retry_busy(|| context.clear_probes_if_present())?;
    retry_busy(|| context.set_target_count(1))?;
    let target = context.target(0);
    target.set_pid(pid)?;
    target.retain_if_supported()?;
    retry_busy(|| target.clear_initial_regions_if_present())?;
    retry_busy(|| context.set_scheme_count(1))?;
    let scheme = context.scheme(0);
    scheme.set_action(&Action::Stat)?;
    scheme.set_match_all()?;
    scheme.set_default_apply_interval_if_present()?;

    let capabilities = kdamond.capabilities(0, 0)?;
    let staged = StagedOwnership {
        operation: Operation::VirtualAddress,
        effective_address_unit: AddressUnit::ONE,
        configuration: kdamond.configuration_fingerprint()?,
    };
    Ok((capabilities, staged))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StagedOwnership {
    operation: Operation,
    effective_address_unit: AddressUnit,
    configuration: ConfigurationFingerprint,
}

impl StagedOwnership {
    fn verify(&self, admin: &DamonAdmin, _kdamond: &Kdamond) -> Result<()> {
        if admin.kdamond_count()? != 1 {
            return Err(Error::OwnershipLost {
                reason: "the staged kdamond count changed",
            });
        }
        if !self.configuration.matches_current()? {
            return Err(Error::OwnershipLost {
                reason: "the staged writable configuration changed",
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Ownership {
    staged: StagedOwnership,
    kdamond_pid: Pid,
}

impl Ownership {
    fn verify_running(&self, admin: &DamonAdmin, kdamond: &Kdamond) -> Result<()> {
        self.staged.verify(admin, kdamond)?;
        let current = running_thread_pid(kdamond)?;
        self.verify_pid(current)
    }

    fn verify_identity(&self, admin: &DamonAdmin, kdamond: &Kdamond) -> Result<()> {
        self.staged.verify(admin, kdamond)?;
        let current = retry_busy(|| kdamond.pid())?.ok_or(Error::NotRunning)?;
        self.verify_pid(current)
    }

    fn verify_pid(&self, current: Pid) -> Result<()> {
        if current != self.kdamond_pid {
            return Err(Error::OwnershipLost {
                reason: "the kdamond kernel-thread ID changed",
            });
        }
        Ok(())
    }
}

fn running_thread_pid(kdamond: &Kdamond) -> Result<Pid> {
    match retry_busy(|| kdamond.state())? {
        KdamondState::Off => Err(Error::NotRunning),
        KdamondState::Unknown(state) => Err(Error::UnexpectedKdamondState { state }),
        KdamondState::On => retry_busy(|| kdamond.pid())?.ok_or(Error::OwnershipLost {
            reason: "a running kdamond did not expose a kernel-thread ID",
        }),
    }
}

fn with_rollback(operation: Error, rollback_result: Result<()>) -> Error {
    match rollback_result {
        Ok(()) => operation,
        Err(rollback) => Error::Rollback {
            operation: Box::new(operation),
            rollback: Box::new(rollback),
        },
    }
}

fn rollback_unstarted_slot(admin: &DamonAdmin, kdamond: &Kdamond) -> Result<()> {
    match admin.kdamond_count()? {
        0 => return Ok(()),
        1 => {}
        kdamonds => return Err(Error::InUse { kdamonds }),
    }
    match retry_busy(|| kdamond.state())? {
        KdamondState::Off => retry_busy(|| admin.set_kdamond_count(0)),
        KdamondState::On => Err(Error::OwnershipLost {
            reason: "a kdamond started during setup rollback",
        }),
        KdamondState::Unknown(_) => Err(Error::OwnershipLost {
            reason: "the kdamond state changed during setup rollback",
        }),
    }
}

fn rollback_unstarted_monitor(
    admin: &DamonAdmin,
    kdamond: &Kdamond,
    staged: &StagedOwnership,
) -> Result<()> {
    staged.verify(admin, kdamond)?;
    match retry_busy(|| kdamond.state())? {
        KdamondState::Off => retry_busy(|| admin.set_kdamond_count(0)),
        KdamondState::On => Err(Error::OwnershipLost {
            reason: "a kdamond started before setup completed",
        }),
        KdamondState::Unknown(_) => Err(Error::OwnershipLost {
            reason: "the kdamond state changed before setup completed",
        }),
    }
}

fn rollback_started_without_identity(
    admin: &DamonAdmin,
    kdamond: &Kdamond,
    staged: &StagedOwnership,
) -> Result<()> {
    staged.verify(admin, kdamond)?;
    match retry_busy(|| kdamond.state())? {
        KdamondState::Off => {
            staged.verify(admin, kdamond)?;
            retry_busy(|| admin.set_kdamond_count(0))
        }
        KdamondState::On => Err(Error::OwnershipLost {
            reason: "cannot safely stop a kdamond before its kernel-thread ID was captured",
        }),
        KdamondState::Unknown(_) => Err(Error::OwnershipLost {
            reason: "the kdamond state changed before its identity was captured",
        }),
    }
}

fn rollback_owned_monitor(
    admin: &DamonAdmin,
    kdamond: &Kdamond,
    ownership: &Ownership,
) -> Result<()> {
    ownership.verify_running(admin, kdamond)?;
    retry_busy(|| kdamond.command(KdamondCommand::Off))?;
    ownership.staged.verify(admin, kdamond)?;
    retry_busy(|| admin.set_kdamond_count(0))
}

fn retry_busy<T>(mut operation: impl FnMut() -> Result<T>) -> Result<T> {
    const MAX_RETRIES: usize = 5;
    const INITIAL_DELAY_MS: u64 = 10;
    let mut retries = 0;

    loop {
        match operation() {
            Err(error) if error.is_resource_busy() && retries < MAX_RETRIES => {
                std::thread::sleep(Duration::from_millis(INITIAL_DELAY_MS << retries));
                retries += 1;
            }
            result => return result,
        }
    }
}

#[derive(Debug)]
struct SessionLock {
    _file: File,
}

impl SessionLock {
    fn acquire(path: &Path) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;

            use rustix::fs::{FlockOperation, flock};

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(|error| crate::error::io_error("open session lock", path, error))?;
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => Ok(Self { _file: file }),
                Err(error) if error == rustix::io::Errno::WOULDBLOCK => {
                    Err(Error::SessionLockBusy {
                        path: path.to_path_buf(),
                    })
                }
                Err(error) => Err(crate::error::io_error(
                    "lock session",
                    path,
                    io::Error::from_raw_os_error(error.raw_os_error()),
                )),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            Err(Error::UnsupportedPlatform)
        }
    }
}

/// A running high-level DAMON monitor holding a cooperative session lock.
///
/// The monitor verifies its staged configuration and kdamond thread ID before
/// destructive operations. This cannot provide absolute ownership against
/// tools that ignore the advisory lock and mutate the global sysfs hierarchy.
#[derive(Debug)]
pub struct Monitor {
    admin: DamonAdmin,
    kdamond: Kdamond,
    capabilities: Capabilities,
    capacity_hint: usize,
    effective_address_unit: AddressUnit,
    ownership: Ownership,
    _session_lock: SessionLock,
    running: bool,
    owns_slot: bool,
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
        &self.ownership.staged.operation
    }

    /// Returns the effective address unit committed for snapshot conversion.
    ///
    /// This can differ from the context's configured address unit because
    /// Linux applies non-default units only to physical-address monitoring.
    #[must_use]
    pub const fn effective_address_unit(&self) -> AddressUnit {
        self.effective_address_unit
    }

    /// Queries the current monitored regions.
    ///
    /// The kernel fulfills this request through a match-all `stat` DAMOS
    /// scheme. The call may wait for the scheme's next apply interval. Mutable
    /// access serializes sysfs result materialization for this monitor. Kernels
    /// before tried-region queries were introduced can still run the monitor,
    /// but this method returns [`Error::UnsupportedFeature`].
    pub fn snapshot(&mut self) -> Result<Snapshot> {
        if !self.running {
            return Err(Error::NotRunning);
        }
        self.verify_running()?;
        if self
            .capabilities
            .feature_support(SysfsFeature::TriedRegions)
            != CapabilitySupport::Supported
        {
            return Err(Error::UnsupportedFeature {
                feature: "DAMOS tried-region queries",
            });
        }
        retry_busy(|| {
            self.kdamond
                .command(KdamondCommand::UpdateSchemesTriedRegions)
        })?;
        self.verify_identity()?;
        let raw = self
            .kdamond
            .context(0)
            .scheme(0)
            .tried_regions(self.capacity_hint)?;
        self.verify_identity()?;
        Ok(raw.with_effective_address_unit(self.effective_address_unit))
    }

    /// Reads whether the kernel monitoring thread is running.
    pub fn is_running(&self) -> Result<bool> {
        if !self.running {
            return Ok(false);
        }
        match self.ownership.verify_running(&self.admin, &self.kdamond) {
            Ok(()) => Ok(true),
            Err(Error::NotRunning) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Stops monitoring and removes the crate-owned kdamond slot.
    pub fn stop(mut self) -> Result<()> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<()> {
        if !self.owns_slot {
            return Ok(());
        }
        let count = self.admin.kdamond_count()?;
        match count {
            0 => {
                self.running = false;
                self.owns_slot = false;
                return Ok(());
            }
            1 => {}
            kdamonds => return Err(Error::InUse { kdamonds }),
        }
        match retry_busy(|| self.kdamond.state())? {
            KdamondState::On => {
                self.ownership.verify_running(&self.admin, &self.kdamond)?;
                retry_busy(|| self.kdamond.command(KdamondCommand::Off))?;
            }
            KdamondState::Off => self.ownership.staged.verify(&self.admin, &self.kdamond)?,
            KdamondState::Unknown(state) => {
                return Err(Error::UnexpectedKdamondState { state });
            }
        }
        self.running = false;
        self.ownership.staged.verify(&self.admin, &self.kdamond)?;
        retry_busy(|| self.admin.set_kdamond_count(0))?;
        self.owns_slot = false;
        Ok(())
    }

    fn verify_running(&mut self) -> Result<()> {
        match self.ownership.verify_running(&self.admin, &self.kdamond) {
            Err(Error::NotRunning) => {
                self.running = false;
                Err(Error::NotRunning)
            }
            result => result,
        }
    }

    fn verify_identity(&mut self) -> Result<()> {
        match self.ownership.verify_identity(&self.admin, &self.kdamond) {
            Err(Error::NotRunning) => {
                self.running = false;
                Err(Error::NotRunning)
            }
            result => result,
        }
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::sysfs::test_backend::{Model, ModelRegion, Mutation};
    use crate::sysfs::{
        AccessCountRange, AccessPattern, AgeRange, ContextConfig, FilterConfig, KdamondConfig,
        QuotaGoalConfig, QuotaGoalMetric, RegionSizeRange, SchemeConfig, SchemeFilterType,
        TargetConfig,
    };

    #[test]
    fn busy_operations_are_retried() {
        let mut attempts = 0;
        let value = retry_busy(|| {
            attempts += 1;
            if attempts < 3 {
                Err(os_error(16))
            } else {
                Ok(42)
            }
        })
        .expect("eventual success");

        assert_eq!(value, 42);
        assert_eq!(attempts, 3);
    }

    #[test]
    fn busy_retries_are_bounded() {
        let mut attempts = 0;
        let error = retry_busy(|| {
            attempts += 1;
            Err::<(), _>(os_error(16))
        })
        .expect_err("persistent busy error");

        assert!(error.is_resource_busy());
        assert_eq!(attempts, 6);
    }

    #[test]
    fn other_io_errors_are_not_retried() {
        let mut attempts = 0;
        let error = retry_busy(|| {
            attempts += 1;
            Err::<(), _>(os_error(13))
        })
        .expect_err("permission error");

        assert!(!error.is_resource_busy());
        assert_eq!(attempts, 1);
    }

    #[test]
    fn transactional_staging_verifies_readback_and_skips_a_matching_hierarchy() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let config = transaction_config(42, Action::Stat);

        damon
            .stage_configuration(&config)
            .expect("stage configuration transactionally");
        assert_eq!(
            damon
                .admin
                .configuration()
                .expect("read staged configuration"),
            config
        );

        let writes = model.write_count();
        damon
            .stage_configuration(&config)
            .expect("matching configuration is a no-op");
        assert_eq!(model.write_count(), writes);
    }

    #[test]
    fn transactional_staging_writes_only_changed_leaf_fields() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let original = transaction_config(42, Action::Stat);
        damon
            .stage_configuration(&original)
            .expect("stage original configuration");
        let writes = model.write_count();

        let replacement = transaction_config(77, Action::PageOut);
        damon
            .stage_configuration(&replacement)
            .expect("stage two changed leaves");

        assert_eq!(model.write_count() - writes, 2);
        assert_eq!(
            damon.admin.configuration().expect("read replacement"),
            replacement
        );
    }

    #[test]
    fn transactional_staging_accepts_split_filter_order_normalization() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut config = transaction_config(42, Action::Stat);
        config.kdamonds[0].contexts[0].schemes[0].filters = vec![
            FilterConfig::new(SchemeFilterType::Anonymous, true, true),
            FilterConfig::address(0, 4096, true, true),
        ];

        damon
            .stage_configuration(&config)
            .expect("split layout may canonicalize filter order");
        let writes = model.write_count();
        damon
            .stage_configuration(&config)
            .expect("canonicalized readback is a no-op");

        assert_eq!(model.write_count(), writes);
        let observed = damon.admin.configuration().expect("read canonical filters");
        assert_eq!(
            observed.kdamonds[0].contexts[0].schemes[0].filters[0].filter_type,
            SchemeFilterType::Address
        );
    }

    #[test]
    fn exclusive_capability_probe_observes_current_damo_controls() {
        let model = Model::new("vaddr\n");
        model.enable_current_damo_extensions();
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

        let capabilities = damon.capabilities().expect("probe current controls");

        for feature in [
            SysfsFeature::ProbeWeight,
            SysfsFeature::ProbePreparations,
            SysfsFeature::ProbePreparationSetPageIdle,
            SysfsFeature::ProbeTypePageIdleUnset,
            SysfsFeature::SampleControl,
            SysfsFeature::OperationAttributes,
        ] {
            assert_eq!(
                capabilities.feature_support(feature),
                CapabilitySupport::Supported,
                "unexpected support for {feature:?}"
            );
        }
    }

    #[test]
    fn transactional_staging_repairs_a_malformed_stopped_configuration() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let config = transaction_config(42, Action::Stat);
        damon
            .stage_configuration(&config)
            .expect("stage original configuration");
        model.set_file(
            "kdamonds/0/contexts/0/monitoring_attrs/intervals/sample_us",
            b"malformed\n",
        );

        damon
            .stage_configuration(&config)
            .expect("replace malformed staged input");

        assert_eq!(
            damon
                .admin
                .configuration()
                .expect("read repaired configuration"),
            config
        );
    }

    #[test]
    fn transactional_staging_retries_a_transient_kernel_busy_error() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let original = transaction_config(42, Action::Stat);
        damon
            .stage_configuration(&original)
            .expect("stage original configuration");
        model.fail_next_write("kdamonds/0/contexts/0/schemes/0/watermarks/low", 16);
        let replacement = transaction_config(77, Action::PageOut);

        damon
            .stage_configuration(&replacement)
            .expect("retry transient EBUSY");

        assert_eq!(
            damon
                .admin
                .configuration()
                .expect("read replacement configuration"),
            replacement
        );
    }

    #[test]
    fn transactional_staging_validates_before_locking_or_writing() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let _held_lock = SessionLock::acquire(lock.path()).expect("hold session lock");
        let mut invalid = transaction_config(42, Action::Stat);
        invalid.kdamonds[0].contexts[0].targets[0] = TargetConfig::address_space();
        let writes = model.write_count();

        let error = damon
            .stage_configuration(&invalid)
            .expect_err("validation must precede lock acquisition");

        assert!(matches!(error, Error::InvalidConfiguration { .. }));
        assert_eq!(model.write_count(), writes);
    }

    #[test]
    fn transactional_staging_uses_the_session_lock() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let _held_lock = SessionLock::acquire(lock.path()).expect("hold session lock");

        let error = damon
            .stage_configuration(&transaction_config(42, Action::Stat))
            .expect_err("cooperating transaction must honor the lock");

        assert!(matches!(error, Error::SessionLockBusy { .. }));
        assert_eq!(damon.admin.kdamond_count().expect("read count"), 0);
    }

    #[test]
    fn transactional_staging_restores_typed_and_unknown_values_after_io_failure() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let original = transaction_config(42, Action::Stat);
        damon
            .stage_configuration(&original)
            .expect("stage original configuration");
        let unknown = "kdamonds/0/contexts/0/schemes/0/future_policy";
        model.set_file(unknown, b"preserve\n");
        model.after_next_write(
            "kdamonds/0/contexts/0/schemes/0/action",
            b"pageout".to_vec(),
            vec![Mutation::SetFile {
                path: unknown.into(),
                value: b"changed\n".to_vec(),
            }],
        );
        model.fail_next_write("kdamonds/0/contexts/0/schemes/0/watermarks/low", 5);

        let mut replacement = transaction_config(77, Action::PageOut);
        replacement.kdamonds[0].contexts[0].schemes[0]
            .watermarks
            .low = 1;
        let error = damon
            .stage_configuration(&replacement)
            .expect_err("late write failure must roll back");

        assert!(
            matches!(error, Error::Io { .. }),
            "unexpected error: {error:?}"
        );
        assert_eq!(
            damon
                .admin
                .configuration()
                .expect("read restored configuration"),
            original
        );
        assert_eq!(model.value(unknown).as_deref(), Some("preserve"));
    }

    #[test]
    fn transactional_staging_restores_after_kernel_readback_mismatch() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let original = transaction_config(42, Action::Stat);
        damon
            .stage_configuration(&original)
            .expect("stage original configuration");
        model.after_next_write(
            "kdamonds/0/contexts/0/schemes/0/watermarks/low",
            b"1".to_vec(),
            vec![Mutation::SetFile {
                path: "kdamonds/0/contexts/0/schemes/0/action".into(),
                value: b"cold\n".to_vec(),
            }],
        );

        let mut replacement = transaction_config(77, Action::PageOut);
        replacement.kdamonds[0].contexts[0].schemes[0]
            .watermarks
            .low = 1;
        let error = damon
            .stage_configuration(&replacement)
            .expect_err("mismatched readback must roll back");

        match error {
            Error::ConfigurationMismatch {
                path,
                expected,
                observed,
            } => {
                assert_eq!(path.as_ref(), "kdamonds/0/contexts/0/schemes/0/action");
                assert_eq!(expected.as_ref(), "PageOut");
                assert_eq!(observed.as_ref(), "Cold");
            }
            error => panic!("unexpected error: {error:?}"),
        }
        assert_eq!(
            damon
                .admin
                .configuration()
                .expect("read restored configuration"),
            original
        );
    }

    #[test]
    fn transactional_rollback_reconstructs_the_original_indexed_hierarchy() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let original = transaction_config(42, Action::Stat);
        damon
            .stage_configuration(&original)
            .expect("stage original configuration");
        let mut replacement = transaction_config(77, Action::PageOut);
        replacement
            .kdamonds
            .push(transaction_config(88, Action::Cold).kdamonds.remove(0));
        model.fail_next_write("kdamonds/1/contexts/0/schemes/0/watermarks/low", 5);

        let error = damon
            .stage_configuration(&replacement)
            .expect_err("second kdamond failure must restore the first hierarchy");

        assert!(matches!(error, Error::Io { .. }));
        assert_eq!(damon.admin.kdamond_count().expect("read count"), 1);
        assert_eq!(
            damon
                .admin
                .configuration()
                .expect("read reconstructed configuration"),
            original
        );
    }

    #[test]
    fn transactional_rollback_restores_an_empty_sysfs_string() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut original = transaction_config(42, Action::Stat);
        original.kdamonds[0].contexts[0].schemes[0].quota.goals =
            vec![QuotaGoalConfig::new(QuotaGoalMetric::UserInput, 0)];
        damon
            .stage_configuration(&original)
            .expect("stage empty quota-goal path");

        let mut replacement = transaction_config(77, Action::PageOut);
        replacement.kdamonds[0].contexts[0].schemes[0].quota.goals = vec![QuotaGoalConfig {
            metric: QuotaGoalMetric::NodeMemoryControlGroupFreeBasisPoints,
            target_value: 0,
            current_value: 0,
            node_id: Some(1),
            cgroup_path: Some("/workload".to_owned()),
        }];
        replacement.kdamonds[0].contexts[0].schemes[0]
            .watermarks
            .low = 1;
        model.fail_next_write("kdamonds/0/contexts/0/schemes/0/watermarks/low", 5);

        let error = damon
            .stage_configuration(&replacement)
            .expect_err("late failure must restore an empty path");

        assert!(matches!(error, Error::Io { .. }));
        assert_eq!(
            model
                .value("kdamonds/0/contexts/0/schemes/0/quotas/goals/0/path")
                .as_deref(),
            Some("")
        );
        assert_eq!(
            damon
                .admin
                .configuration()
                .expect("read restored configuration"),
            original
        );
    }

    #[test]
    fn transactional_staging_never_replaces_a_running_kdamond() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let original = transaction_config(42, Action::Stat);
        damon
            .stage_configuration(&original)
            .expect("stage original configuration");
        let kdamond = damon.admin.kdamond(0);
        kdamond.command(KdamondCommand::On).expect("start kdamond");

        let error = damon
            .stage_configuration(&transaction_config(77, Action::PageOut))
            .expect_err("running hierarchy must not be replaced");

        assert!(matches!(error, Error::KdamondRunning { index: 0 }));
        assert_eq!(kdamond.state().expect("read state"), KdamondState::On);
        kdamond.command(KdamondCommand::Off).expect("stop fixture");
    }

    #[test]
    fn external_start_during_transaction_prevents_destructive_rollback() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        damon
            .stage_configuration(&transaction_config(42, Action::Stat))
            .expect("stage original configuration");
        model.after_next_write(
            "kdamonds/0/contexts/0/schemes/0/action",
            b"pageout".to_vec(),
            vec![Mutation::StartKdamond {
                path: "kdamonds/0".into(),
            }],
        );

        let error = damon
            .stage_configuration(&transaction_config(77, Action::PageOut))
            .expect_err("external start must prevent rollback");

        assert!(matches!(
            error,
            Error::Rollback {
                operation,
                rollback,
            } if matches!(*operation, Error::KdamondRunning { index: 0 })
                && matches!(*rollback, Error::KdamondRunning { index: 0 })
        ));
        let kdamond = damon.admin.kdamond(0);
        assert_eq!(kdamond.state().expect("read state"), KdamondState::On);
        kdamond.command(KdamondCommand::Off).expect("stop fixture");
    }

    #[test]
    fn staging_count_read_error_rolls_back_created_slot() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        model.after_next_write(
            "kdamonds/nr_kdamonds",
            b"1".to_vec(),
            vec![Mutation::RemoveTree {
                path: "kdamonds/nr_kdamonds".into(),
            }],
        );
        model.after_next_read("kdamonds/nr_kdamonds", Vec::new());
        model.after_next_read(
            "kdamonds/nr_kdamonds",
            vec![Mutation::SetFile {
                path: "kdamonds/nr_kdamonds".into(),
                value: b"1\n".to_vec(),
            }],
        );

        let error = damon
            .monitor_pid(Pid::new(42).expect("valid pid"))
            .start()
            .expect_err("failed verification read must fail startup");

        assert!(
            matches!(error, Error::Io { .. }),
            "unexpected error: {error:?}"
        );
        assert_eq!(
            damon.admin.kdamond_count().expect("read rolled-back count"),
            0
        );
    }

    #[test]
    fn failed_on_does_not_stop_an_external_kdamond() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        for _ in 0..2 {
            model.after_next_read("kdamonds/nr_kdamonds", Vec::new());
        }
        model.after_next_read(
            "kdamonds/nr_kdamonds",
            vec![Mutation::StartKdamond {
                path: "kdamonds/0".into(),
            }],
        );

        let error = damon
            .monitor_pid(Pid::new(42).expect("valid pid"))
            .start()
            .expect_err("external start must prevent ownership");

        assert!(matches!(
            error,
            Error::Rollback {
                operation,
                rollback,
            } if operation.is_resource_busy()
                && matches!(*rollback, Error::OwnershipLost {
                    reason: "a kdamond started before setup completed"
                })
        ));
        let kdamond = damon.admin.kdamond(0);
        assert_eq!(
            kdamond.state().expect("read external state"),
            KdamondState::On
        );
        assert!(kdamond.pid().expect("read external pid").is_some());

        kdamond.command(KdamondCommand::Off).expect("stop fixture");
        damon.admin.set_kdamond_count(0).expect("remove fixture");
    }

    #[test]
    fn pid_replacement_prevents_started_monitor_rollback() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        model.after_next_read(
            "kdamonds/0/pid",
            vec![Mutation::StartKdamond {
                path: "kdamonds/0".into(),
            }],
        );

        let error = damon
            .monitor_pid(Pid::new(42).expect("valid pid"))
            .start()
            .expect_err("replacement pid must prevent ownership");

        assert!(matches!(
            error,
            Error::Rollback {
                operation,
                rollback,
            } if matches!(*operation, Error::OwnershipLost {
                    reason: "the kdamond kernel-thread ID changed"
                })
                && matches!(*rollback, Error::OwnershipLost {
                    reason: "the kdamond kernel-thread ID changed"
                })
        ));
        let kdamond = damon.admin.kdamond(0);
        assert_eq!(
            kdamond.state().expect("read replacement state"),
            KdamondState::On
        );
        assert!(kdamond.pid().expect("read replacement pid").is_some());

        kdamond.command(KdamondCommand::Off).expect("stop fixture");
        damon.admin.set_kdamond_count(0).expect("remove fixture");
    }

    #[test]
    fn missing_startup_pid_does_not_trigger_unidentified_stop() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        model.after_next_write(
            "kdamonds/0/state",
            b"on".to_vec(),
            vec![Mutation::SetFile {
                path: "kdamonds/0/pid".into(),
                value: b"-1\n".to_vec(),
            }],
        );

        let error = damon
            .monitor_pid(Pid::new(42).expect("valid pid"))
            .start()
            .expect_err("missing kernel-thread ID must fail startup");

        assert!(matches!(
            error,
            Error::Rollback {
                operation,
                rollback,
            } if matches!(*operation, Error::OwnershipLost {
                    reason: "a running kdamond did not expose a kernel-thread ID"
                })
                && matches!(*rollback, Error::OwnershipLost {
                    reason: "cannot safely stop a kdamond before its kernel-thread ID was captured"
                })
        ));
        let kdamond = damon.admin.kdamond(0);
        assert_eq!(
            kdamond.state().expect("read running state"),
            KdamondState::On
        );

        kdamond.command(KdamondCommand::Off).expect("stop fixture");
        damon.admin.set_kdamond_count(0).expect("remove fixture");
    }

    #[test]
    fn snapshot_rechecks_ownership_after_materialization_command() {
        let model = Model::new("vaddr\nfvaddr\npaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut monitor = damon
            .monitor_pid(Pid::new(42).expect("valid pid"))
            .start()
            .expect("start modeled monitor");
        model.after_next_write(
            "kdamonds/0/state",
            b"update_schemes_tried_regions".to_vec(),
            vec![Mutation::SetFile {
                path: "kdamonds/0/contexts/0/targets/0/pid_target".into(),
                value: b"77\n".to_vec(),
            }],
        );

        let error = monitor
            .snapshot()
            .expect_err("post-command ownership change must discard results");
        assert!(matches!(
            error,
            Error::OwnershipLost {
                reason: "the staged writable configuration changed"
            }
        ));
    }

    #[test]
    fn snapshot_rechecks_ownership_after_reading_results() {
        let model = Model::new("vaddr\nfvaddr\npaddr\n");
        model.set_tried_regions(vec![ModelRegion {
            start: 4_096,
            end: 8_192,
            nr_accesses: 7,
            age: 3,
            filter_passed_units: Some(4_096),
            probe_hits: vec![2, 5],
        }]);
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut monitor = damon
            .monitor_pid(Pid::new(42).expect("valid pid"))
            .start()
            .expect("start modeled monitor");
        model.after_next_read(
            "kdamonds/0/contexts/0/schemes/0/tried_regions/0/age",
            vec![Mutation::SetFile {
                path: "kdamonds/0/contexts/0/targets/0/pid_target".into(),
                value: b"77\n".to_vec(),
            }],
        );

        let error = monitor
            .snapshot()
            .expect_err("post-read ownership change must discard results");
        assert!(matches!(
            error,
            Error::OwnershipLost {
                reason: "the staged writable configuration changed"
            }
        ));
    }

    #[test]
    fn exclusive_capability_probe_materializes_nested_attributes_and_restores_empty_state() {
        let model = Model::new("vaddr\nfvaddr\npaddr\nfuture_operation\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

        let capabilities = damon.capabilities().expect("probe modeled capabilities");

        assert_eq!(damon.admin.kdamond_count().expect("read restored count"), 0);
        assert_eq!(
            capabilities.damo_feature_support("sysfs/ctx_pause"),
            Some(CapabilitySupport::Supported)
        );
        assert_eq!(capabilities.damo_feature_support("sysfs/not_known"), None);
        assert_eq!(
            capabilities.feature_support(SysfsFeature::ProbeFilterPath),
            CapabilitySupport::Supported
        );
        assert!(capabilities.has_attribute("contexts/0/monitoring_attrs/probes/0/filters/0/path"));
        assert!(capabilities.has_attribute("contexts/0/schemes/0/quotas/goals/0/target_metric"));
        assert!(capabilities.operations().iter().any(|capability| {
            capability.operation() == &Operation::Unknown("future_operation".into())
                && capability.support() == CapabilitySupport::Supported
        }));
        assert_eq!(
            capabilities
                .features()
                .iter()
                .filter(|capability| capability.feature().damo_name().is_some())
                .count(),
            57
        );
    }

    #[test]
    fn exclusive_capability_probe_preserves_an_existing_hierarchy() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        damon
            .admin
            .set_kdamond_count(1)
            .expect("stage external hierarchy");

        let error = damon
            .capabilities()
            .expect_err("capability probing must require an empty hierarchy");

        assert!(matches!(error, Error::InUse { kdamonds: 1 }));
        assert_eq!(damon.admin.kdamond_count().expect("preserve count"), 1);
    }

    #[test]
    fn exclusive_capability_probe_tests_operations_when_listing_is_absent() {
        let model = Model::without_available_operations_file("vaddr\npaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

        let capabilities = damon.capabilities().expect("probe modeled operations");

        assert_eq!(
            capabilities.feature_support(SysfsFeature::AvailableOperations),
            CapabilitySupport::Unsupported
        );
        assert_eq!(
            capabilities.operation_support(&Operation::VirtualAddress),
            Some(CapabilitySupport::Unverified)
        );
        assert_eq!(
            capabilities.operation_support(&Operation::PhysicalAddress),
            Some(CapabilitySupport::Unverified)
        );
        assert_eq!(
            capabilities.operation_support(&Operation::FixedVirtualAddress),
            Some(CapabilitySupport::Unsupported)
        );
        assert!(!capabilities.supports_operation(&Operation::VirtualAddress));
        assert_eq!(damon.admin.kdamond_count().expect("read restored count"), 0);
    }

    #[test]
    fn legacy_operation_writes_do_not_claim_registered_support() {
        let model = Model::with_legacy_operation_sets("vaddr\n", "vaddr\npaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

        let capabilities = damon.capabilities().expect("probe legacy operations");

        assert_eq!(
            capabilities.operation_support(&Operation::PhysicalAddress),
            Some(CapabilitySupport::Unverified)
        );
        assert!(!capabilities.supports_operation(&Operation::PhysicalAddress));
    }

    #[test]
    fn recognized_but_unregistered_operation_fails_start_and_rolls_back() {
        let model = Model::with_legacy_operation_sets("paddr\n", "vaddr\npaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

        let error = damon
            .monitor_pid(Pid::new(42).expect("valid pid"))
            .start()
            .expect_err("an unregistered vaddr implementation must not start");

        assert!(matches!(error, Error::Io { .. }));
        assert_eq!(damon.admin.kdamond_count().expect("read restored count"), 0);
    }

    #[test]
    fn exclusive_capability_probe_checks_semantic_filter_values() {
        let model = Model::new("vaddr\npaddr\nfvaddr\n");
        model.set_supported_scheme_filter_types("anon\nmemcg\naddr\ntarget\n");
        model.set_supported_probe_filter_types("anon\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");

        let capabilities = damon.capabilities().expect("probe semantic values");

        assert_eq!(
            capabilities.feature_support(SysfsFeature::SchemeFilterYoung),
            CapabilitySupport::Unsupported
        );
        assert_eq!(
            capabilities.feature_support(SysfsFeature::SchemeFilterAddress),
            CapabilitySupport::Supported
        );
        assert_eq!(
            capabilities.feature_support(SysfsFeature::ProbeTypeAnonymous),
            CapabilitySupport::Supported
        );
        assert_eq!(
            capabilities.feature_support(SysfsFeature::ProbeTypeMemoryControlGroup),
            CapabilitySupport::Unsupported
        );
    }

    #[test]
    fn passive_capability_probe_does_not_claim_unchecked_filter_values() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        damon
            .admin
            .set_kdamond_count(1)
            .expect("stage modeled kdamond");
        let kdamond = damon.admin.kdamond(0);
        kdamond.set_context_count(1).expect("stage context");
        let context = kdamond.context(0);
        context.set_target_count(1).expect("stage target");
        context.set_scheme_count(1).expect("stage scheme");
        kdamond
            .stage_optional_capability_children(0, 0, 0)
            .expect("stage optional children");

        let capabilities = kdamond.capabilities(0, 0).expect("inspect paths");

        assert_eq!(
            capabilities.feature_support(SysfsFeature::SchemeFilterYoung),
            CapabilitySupport::Unverified
        );
    }

    fn transaction_config(pid: u32, action: Action) -> DamonConfig {
        let pattern = AccessPattern::new(
            RegionSizeRange::new(0, u64::MAX).expect("valid size range"),
            AccessCountRange::new(0, u32::MAX).expect("valid access range"),
            AgeRange::new(0, u32::MAX).expect("valid age range"),
        );
        let mut context = ContextConfig::new(Operation::VirtualAddress);
        context
            .targets
            .push(TargetConfig::for_pid(Pid::new(pid).expect("valid pid")));
        context.schemes.push(SchemeConfig::new(action, pattern));

        let mut kdamond = KdamondConfig::default();
        kdamond.contexts.push(context);
        let mut config = DamonConfig::default();
        config.kdamonds.push(kdamond);
        config
    }

    fn os_error(code: i32) -> Error {
        Error::Io {
            operation: "test",
            path: PathBuf::from("fixture"),
            source: io::Error::from_raw_os_error(code),
        }
    }

    struct TestLock {
        path: PathBuf,
    }

    impl TestLock {
        fn new() -> Self {
            static NEXT_LOCK: AtomicU64 = AtomicU64::new(0);
            Self {
                path: std::env::temp_dir().join(format!(
                    "damon-rs-model-lock-{}-{}",
                    std::process::id(),
                    NEXT_LOCK.fetch_add(1, Ordering::Relaxed)
                )),
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestLock {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
