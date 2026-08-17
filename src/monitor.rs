use std::path::Path;
use std::time::Duration;

use crate::sysfs::{Action, DamonAdmin, Kdamond, KdamondCommand, KdamondState, Operation};
use crate::{Capabilities, Error, MonitoringIntervals, Pid, RegionBounds, Result, Snapshot};

/// Entry point for high-level DAMON monitoring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Damon {
    admin: DamonAdmin,
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
        Ok(Self {
            admin: DamonAdmin::open(path)?,
        })
    }

    /// Returns the low-level sysfs handle.
    #[must_use]
    pub const fn admin(&self) -> &DamonAdmin {
        &self.admin
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
    min_regions: usize,
    max_regions: usize,
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
    pub const fn region_bounds(mut self, min: usize, max: usize) -> Self {
        self.min_regions = min;
        self.max_regions = max;
        self
    }

    /// Validates, stages, and starts this monitor.
    ///
    /// To avoid destroying configurations owned by other tools, this returns
    /// [`Error::InUse`] unless `nr_kdamonds` is zero. DAMON sysfs has no
    /// transaction or ownership primitive, so system-wide coordination with
    /// other DAMON controllers remains the caller's responsibility.
    pub fn start(self) -> Result<Monitor> {
        let intervals = MonitoringIntervals::new(self.sample, self.aggregation, self.update)?;
        let region_bounds = RegionBounds::new(self.min_regions, self.max_regions)?;
        let existing = self.damon.admin.kdamond_count()?;
        if existing != 0 {
            return Err(Error::InUse { kdamonds: existing });
        }

        self.damon.admin.set_kdamond_count(1)?;
        let kdamond = self.damon.admin.kdamond(0);
        let setup = configure_monitor(&kdamond, self.pid, intervals, region_bounds);
        let capabilities = match setup {
            Ok(capabilities) => capabilities,
            Err(operation) => {
                return match self.damon.admin.set_kdamond_count(0) {
                    Ok(()) => Err(operation),
                    Err(rollback) => Err(Error::Rollback {
                        operation: Box::new(operation),
                        rollback: Box::new(rollback),
                    }),
                };
            }
        };

        Ok(Monitor {
            admin: self.damon.admin.clone(),
            kdamond,
            capabilities,
            capacity_hint: region_bounds.max(),
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
) -> Result<Capabilities> {
    kdamond.set_context_count(1)?;
    let context = kdamond.context(0);
    let operations = context.available_operations()?;
    if !operations.contains(&Operation::VirtualAddress) {
        return Err(Error::UnsupportedOperation {
            operation: Operation::VirtualAddress,
        });
    }

    context.set_operation(&Operation::VirtualAddress)?;
    context.set_intervals(intervals)?;
    context.set_region_bounds(region_bounds)?;
    context.set_target_count(1)?;
    context.target(0).set_pid(pid)?;
    context.set_scheme_count(1)?;
    let scheme = context.scheme(0);
    scheme.set_action(Action::Stat)?;
    scheme.set_match_all()?;

    let capabilities = kdamond.capabilities(0, 0)?;
    if !capabilities.has_tried_regions() {
        return Err(Error::UnsupportedFeature {
            feature: "DAMOS tried-region queries",
        });
    }

    kdamond.command(KdamondCommand::On)?;
    Ok(capabilities)
}

/// A running, exclusively owned high-level DAMON monitor.
#[derive(Debug)]
pub struct Monitor {
    admin: DamonAdmin,
    kdamond: Kdamond,
    capabilities: Capabilities,
    capacity_hint: usize,
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
        self.kdamond
            .command(KdamondCommand::UpdateSchemesTriedRegions)?;
        self.kdamond
            .context(0)
            .scheme(0)
            .tried_regions(self.capacity_hint)
    }

    /// Reads whether the kernel monitoring thread is running.
    pub fn is_running(&self) -> Result<bool> {
        Ok(matches!(self.kdamond.state()?, KdamondState::On))
    }

    /// Stops monitoring and removes the crate-owned kdamond slot.
    pub fn stop(mut self) -> Result<()> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<()> {
        if self.running {
            if !matches!(self.kdamond.state()?, KdamondState::Off) {
                self.kdamond.command(KdamondCommand::Off)?;
            }
            self.running = false;
        }
        if self.owns_slot {
            let count = self.admin.kdamond_count()?;
            match count {
                0 => self.owns_slot = false,
                1 => {
                    self.admin.set_kdamond_count(0)?;
                    self.owns_slot = false;
                }
                kdamonds => return Err(Error::InUse { kdamonds }),
            }
        }
        Ok(())
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}
