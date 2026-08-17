use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::sysfs::{
    AccessPattern, Action, AuxiliaryConfigFingerprint, CapabilitySupport, DamonAdmin, Kdamond,
    KdamondCommand, KdamondState, Operation, SysfsFeature,
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
        let (capabilities, staged) = match setup {
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
    kdamond.set_refresh_interval(Duration::ZERO)?;
    retry_busy(|| kdamond.set_context_count(1))?;
    let context = kdamond.context(0);
    let operations = context.available_operations()?;
    if !operations.contains(&Operation::VirtualAddress) {
        return Err(Error::UnsupportedOperation {
            operation: Operation::VirtualAddress,
        });
    }

    context.set_operation(&Operation::VirtualAddress)?;
    context.set_address_unit(AddressUnit::ONE)?;
    context.set_paused(false)?;
    context.set_intervals(intervals)?;
    context.set_region_bounds(region_bounds)?;
    retry_busy(|| context.set_probe_count(0))?;
    retry_busy(|| context.set_target_count(1))?;
    let target = context.target(0);
    target.set_pid(pid)?;
    target.set_obsolete(false)?;
    retry_busy(|| target.set_initial_region_count(0))?;
    retry_busy(|| context.set_scheme_count(1))?;
    let scheme = context.scheme(0);
    scheme.set_action(&Action::Stat)?;
    scheme.set_match_all()?;
    scheme.set_apply_interval(Duration::ZERO)?;

    let capabilities = kdamond.capabilities(0, 0)?;
    if capabilities.feature_support(SysfsFeature::TriedRegions) != CapabilitySupport::Supported {
        return Err(Error::UnsupportedFeature {
            feature: "DAMOS tried-region queries",
        });
    }

    let staged = StagedOwnership {
        refresh_interval: Duration::ZERO,
        operation: Operation::VirtualAddress,
        configured_address_unit: AddressUnit::ONE,
        effective_address_unit: AddressUnit::ONE,
        target_pid: pid,
        intervals,
        region_bounds,
        access_pattern: scheme.access_pattern()?,
        paused: false,
        probe_count: 0,
        target_obsolete: false,
        initial_region_count: 0,
        apply_interval: Duration::ZERO,
        auxiliary_config: kdamond.auxiliary_config_fingerprint()?,
    };
    Ok((capabilities, staged))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StagedOwnership {
    refresh_interval: Duration,
    operation: Operation,
    configured_address_unit: AddressUnit,
    effective_address_unit: AddressUnit,
    target_pid: Pid,
    intervals: MonitoringIntervals,
    region_bounds: RegionBounds,
    access_pattern: AccessPattern,
    paused: bool,
    probe_count: usize,
    target_obsolete: bool,
    initial_region_count: usize,
    apply_interval: Duration,
    auxiliary_config: AuxiliaryConfigFingerprint,
}

impl StagedOwnership {
    fn verify(&self, admin: &DamonAdmin, kdamond: &Kdamond) -> Result<()> {
        if admin.kdamond_count()? != 1 {
            return Err(Error::OwnershipLost {
                reason: "the staged kdamond count changed",
            });
        }
        if kdamond.refresh_interval()? != self.refresh_interval {
            return Err(Error::OwnershipLost {
                reason: "the staged kdamond attributes changed",
            });
        }
        if kdamond.context_count()? != 1 {
            return Err(Error::OwnershipLost {
                reason: "the staged context count changed",
            });
        }
        let context = kdamond.context(0);
        if context.operation()? != self.operation
            || context.address_unit()? != self.configured_address_unit
            || context.is_paused()? != self.paused
            || context.intervals()? != self.intervals
            || context.region_bounds()? != self.region_bounds
            || context.probe_count()? != self.probe_count
        {
            return Err(Error::OwnershipLost {
                reason: "the staged monitoring attributes changed",
            });
        }
        let target = context.target(0);
        if context.target_count()? != 1
            || target.pid()? != Some(self.target_pid)
            || target.is_obsolete()? != self.target_obsolete
            || target.initial_region_count()? != self.initial_region_count
        {
            return Err(Error::OwnershipLost {
                reason: "the staged target changed",
            });
        }
        if context.scheme_count()? != 1 {
            return Err(Error::OwnershipLost {
                reason: "the staged scheme count changed",
            });
        }
        let scheme = context.scheme(0);
        if scheme.action()? != Action::Stat
            || scheme.access_pattern()? != self.access_pattern
            || scheme.apply_interval()? != self.apply_interval
        {
            return Err(Error::OwnershipLost {
                reason: "the staged scheme changed",
            });
        }
        if !self.auxiliary_config.matches_current()? {
            return Err(Error::OwnershipLost {
                reason: "the staged auxiliary configuration changed",
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
    /// access serializes sysfs result materialization for this monitor.
    pub fn snapshot(&mut self) -> Result<Snapshot> {
        if !self.running {
            return Err(Error::NotRunning);
        }
        self.verify_running()?;
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
                reason: "the staged target changed"
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
                reason: "the staged target changed"
            }
        ));
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
