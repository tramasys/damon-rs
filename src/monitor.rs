use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::sysfs::{
    AccessPattern, Action, CapabilitySupport, DamonAdmin, Kdamond, KdamondCommand, KdamondState,
    Operation, SysfsFeature,
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

    /// Returns the low-level sysfs handle.
    #[must_use]
    pub const fn admin(&self) -> &DamonAdmin {
        &self.admin
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
        if self.damon.admin.kdamond_count()? != 1 {
            return Err(Error::OwnershipLost {
                reason: "kdamond count changed immediately after staging",
            });
        }
        let kdamond = self.damon.admin.kdamond(0);
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
            return Err(rollback_started_monitor(
                operation,
                &self.damon.admin,
                &kdamond,
                &staged,
            ));
        }
        let kdamond_pid = match running_thread_pid(&kdamond) {
            Ok(pid) => pid,
            Err(operation) => {
                return Err(rollback_started_monitor(
                    operation,
                    &self.damon.admin,
                    &kdamond,
                    &staged,
                ));
            }
        };
        let ownership = Ownership {
            staged,
            kdamond_pid,
        };
        if let Err(operation) = ownership.verify_running(&self.damon.admin, &kdamond) {
            return Err(rollback_started_monitor(
                operation,
                &self.damon.admin,
                &kdamond,
                &ownership.staged,
            ));
        }

        Ok(Monitor {
            admin: self.damon.admin.clone(),
            kdamond,
            capabilities,
            capacity_hint: usize::try_from(region_bounds.max()).unwrap_or(usize::MAX),
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
    context.set_intervals(intervals)?;
    context.set_region_bounds(region_bounds)?;
    retry_busy(|| context.set_target_count(1))?;
    context.target(0).set_pid(pid)?;
    retry_busy(|| context.set_scheme_count(1))?;
    let scheme = context.scheme(0);
    scheme.set_action(&Action::Stat)?;
    scheme.set_match_all()?;

    let capabilities = kdamond.capabilities(0, 0)?;
    if capabilities.feature_support(SysfsFeature::TriedRegions) != CapabilitySupport::Supported {
        return Err(Error::UnsupportedFeature {
            feature: "DAMOS tried-region queries",
        });
    }

    let staged = StagedOwnership {
        target_pid: pid,
        intervals,
        region_bounds,
        access_pattern: scheme.access_pattern()?,
    };
    Ok((capabilities, staged))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StagedOwnership {
    target_pid: Pid,
    intervals: MonitoringIntervals,
    region_bounds: RegionBounds,
    access_pattern: AccessPattern,
}

impl StagedOwnership {
    fn verify(&self, admin: &DamonAdmin, kdamond: &Kdamond) -> Result<()> {
        if admin.kdamond_count()? != 1 {
            return Err(Error::OwnershipLost {
                reason: "the staged kdamond count changed",
            });
        }
        if kdamond.context_count()? != 1 {
            return Err(Error::OwnershipLost {
                reason: "the staged context count changed",
            });
        }
        let context = kdamond.context(0);
        if context.operation()? != Operation::VirtualAddress
            || context.address_unit()? != AddressUnit::ONE
            || context.intervals()? != self.intervals
            || context.region_bounds()? != self.region_bounds
        {
            return Err(Error::OwnershipLost {
                reason: "the staged monitoring attributes changed",
            });
        }
        if context.target_count()? != 1 || context.target(0).pid()? != Some(self.target_pid) {
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
        if scheme.action()? != Action::Stat || scheme.access_pattern()? != self.access_pattern {
            return Err(Error::OwnershipLost {
                reason: "the staged scheme changed",
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
        KdamondState::On => kdamond.pid()?.ok_or(Error::OwnershipLost {
            reason: "a running kdamond did not expose a kernel-thread ID",
        }),
    }
}

fn rollback_started_monitor(
    operation: Error,
    admin: &DamonAdmin,
    kdamond: &Kdamond,
    staged: &StagedOwnership,
) -> Error {
    with_rollback(operation, rollback_staged_monitor(admin, kdamond, staged))
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

fn rollback_staged_monitor(
    admin: &DamonAdmin,
    kdamond: &Kdamond,
    staged: &StagedOwnership,
) -> Result<()> {
    staged.verify(admin, kdamond)?;
    if kdamond_is_running(kdamond)? {
        retry_busy(|| kdamond.command(KdamondCommand::Off))?;
    }
    staged.verify(admin, kdamond)?;
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

fn kdamond_is_running(kdamond: &Kdamond) -> Result<bool> {
    match retry_busy(|| kdamond.state())? {
        KdamondState::On => Ok(true),
        KdamondState::Off => Ok(false),
        KdamondState::Unknown(state) => Err(Error::UnexpectedKdamondState { state }),
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

    /// Queries the current monitored regions.
    ///
    /// The kernel fulfills this request through a match-all `stat` DAMOS
    /// scheme. The call may wait for the scheme's next apply interval. Mutable
    /// access serializes sysfs result materialization for this monitor.
    pub fn snapshot(&mut self) -> Result<Snapshot> {
        if !self.running {
            return Err(Error::NotRunning);
        }
        match self.ownership.verify_running(&self.admin, &self.kdamond) {
            Err(Error::NotRunning) => {
                self.running = false;
                return Err(Error::NotRunning);
            }
            result => result?,
        }
        retry_busy(|| {
            self.kdamond
                .command(KdamondCommand::UpdateSchemesTriedRegions)
        })?;
        self.kdamond
            .context(0)
            .scheme(0)
            .tried_regions(self.capacity_hint)
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
}

impl Drop for Monitor {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;

    use super::*;

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

    fn os_error(code: i32) -> Error {
        Error::Io {
            operation: "test",
            path: PathBuf::from("fixture"),
            source: io::Error::from_raw_os_error(code),
        }
    }
}
