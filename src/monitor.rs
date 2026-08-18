use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::sysfs::{
    AccessCountRange, AccessPattern, Action, AgeRange, CapabilitySupport, ConfigurationFingerprint,
    ConfigurationSnapshot, ContextConfig, DamonAdmin, DamonConfig, InitialRegionConfig, Kdamond,
    KdamondCommand, KdamondConfig, KdamondState, Operation, ProbeConfig, RegionSizeRange,
    SchemeConfig, SchemeStats, SysfsFeature, TargetConfig,
};
use crate::{
    AddressUnit, Capabilities, Error, MonitoringIntervals, Pid, RawSnapshot, RegionBounds, Result,
    Snapshot,
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
        self.vaddr().pid(pid)
    }

    /// Starts building a process virtual-address monitoring workflow.
    #[must_use]
    pub fn vaddr(&self) -> VaddrSessionBuilder<'_> {
        VaddrSessionBuilder {
            options: WorkflowOptions::new(self),
            pid: None,
        }
    }

    /// Starts building a fixed virtual-address monitoring workflow.
    #[must_use]
    pub fn fvaddr(&self) -> FvaddrSessionBuilder<'_> {
        FvaddrSessionBuilder {
            options: WorkflowOptions::new(self),
            pid: None,
        }
    }

    /// Starts building a physical-address monitoring workflow.
    #[must_use]
    pub fn paddr(&self) -> PaddrSessionBuilder<'_> {
        PaddrSessionBuilder {
            options: WorkflowOptions::new(self),
            address_unit: AddressUnit::ONE,
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
            .map(drop)
    }

    /// Stages a complete configuration and retains exclusive cooperative
    /// ownership until the returned session is closed or dropped.
    ///
    /// Exactly one kdamond must be requested. Any preceding stopped hierarchy
    /// is restored by [`ExclusiveSession::close`], or on a best-effort basis
    /// when the session is dropped.
    pub fn exclusive_session(&self, config: &DamonConfig) -> Result<ExclusiveSession> {
        if config.kdamonds.len() != 1 {
            return Err(Error::InvalidConfiguration {
                field: "exclusive session kdamond count",
                reason: "must contain exactly one kdamond",
            });
        }
        config.validate_runnable()?;
        let session_lock = SessionLock::acquire(&self.lock_path)?;
        let staged_configuration =
            self.stage_validated_configuration_locked(&session_lock, config)?;
        let kdamond = self.admin.kdamond(0);
        let staged = StagedOwnership::new(
            staged_configuration.fingerprint,
            &kdamond,
            &config.kdamonds[0],
        );
        if let Err(operation) = staged.verify(&self.admin) {
            return Err(with_rollback(
                operation,
                restore_configuration(&self.admin, &staged_configuration.previous),
            ));
        }

        Ok(ExclusiveSession {
            admin: self.admin.clone(),
            kdamond,
            previous: staged_configuration.previous,
            staged,
            state: SessionState::Staged,
            _session_lock: session_lock,
            owns_hierarchy: true,
        })
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
    ) -> Result<StagedConfiguration> {
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
            return Ok(StagedConfiguration {
                fingerprint: previous.fingerprint(),
                previous,
            });
        }

        let operation = stage_and_verify_configuration(&self.admin, config, observed.as_ref());
        match operation {
            Ok(fingerprint) => Ok(StagedConfiguration {
                previous,
                fingerprint,
            }),
            Err(operation) => Err(with_rollback(
                operation,
                restore_configuration(&self.admin, &previous),
            )),
        }
    }

    /// Exclusively stages representative nodes and discovers this kernel's
    /// concrete and semantic DAMON sysfs capabilities.
    ///
    /// Discovery holds the same advisory lock as a monitor and requires all
    /// existing kdamonds to be stopped. It never starts a kdamond. The exact
    /// preceding writable hierarchy is restored before this method returns.
    /// This makes capabilities below indexed children and accepted filter
    /// values observable without discarding a stopped configuration.
    pub fn capabilities(&self) -> Result<Capabilities> {
        let _session_lock = SessionLock::acquire(&self.lock_path)?;
        retry_busy(|| ensure_hierarchy_stopped(&self.admin))?;
        let previous = retry_busy(|| self.admin.configuration_snapshot())?;
        if !retry_busy(|| previous.values_match_current())? {
            return Err(Error::OwnershipLost {
                reason: "the DAMON hierarchy changed while capability probing captured it",
            });
        }
        let kdamond = self.admin.kdamond(0);
        let result = (|| {
            retry_busy(|| ensure_hierarchy_stopped(&self.admin))?;
            retry_busy(|| self.admin.set_kdamond_count(1))?;
            stage_capability_probe(&kdamond)
        })();
        match result {
            Ok((capabilities, fingerprint)) => {
                restore_after_capability_probe(&self.admin, &kdamond, &fingerprint, &previous)?;
                Ok(capabilities)
            }
            Err(operation) => Err(with_rollback(
                operation,
                restore_configuration(&self.admin, &previous),
            )),
        }
    }
}

struct StagedConfiguration {
    previous: ConfigurationSnapshot,
    fingerprint: ConfigurationFingerprint,
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
) -> Result<ConfigurationFingerprint> {
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
    retry_busy(|| ensure_hierarchy_stopped(admin))?;
    Ok(staged.into_fingerprint())
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

fn restore_after_capability_probe(
    admin: &DamonAdmin,
    kdamond: &Kdamond,
    fingerprint: &ConfigurationFingerprint,
    previous: &ConfigurationSnapshot,
) -> Result<()> {
    if admin.kdamond_count()? != 1 || !fingerprint.matches_current()? {
        return Err(Error::OwnershipLost {
            reason: "the staged capability-probe configuration changed",
        });
    }
    match retry_busy(|| kdamond.state())? {
        KdamondState::Off => restore_configuration(admin, previous),
        KdamondState::On => Err(Error::OwnershipLost {
            reason: "the capability-probe kdamond was started externally",
        }),
        KdamondState::Unknown(_) => Err(Error::OwnershipLost {
            reason: "the capability-probe kdamond state changed",
        }),
    }
}

#[derive(Debug)]
enum SessionState {
    Staged,
    Running(Pid),
    UnidentifiedRunning,
    Closed,
}

/// A cooperatively exclusive, transactionally staged DAMON session.
///
/// The session holds the advisory lock for its entire lifetime. It verifies
/// the staged configuration and the running kdamond identity around runtime
/// commands, and restores the preceding stopped hierarchy on [`Self::close`].
/// Kernel-updated sampling and aggregation interval leaves are treated as
/// volatile while interval auto-tuning is enabled.
/// Runtime update and result-materialization methods require mutable access,
/// preventing concurrent command and read sequences within one session.
/// Controllers that ignore the advisory lock can still race this API because
/// the kernel provides no ownership primitive.
#[derive(Debug)]
pub struct ExclusiveSession {
    admin: DamonAdmin,
    kdamond: Kdamond,
    previous: ConfigurationSnapshot,
    staged: StagedOwnership,
    state: SessionState,
    _session_lock: SessionLock,
    owns_hierarchy: bool,
}

impl ExclusiveSession {
    /// Starts the staged kdamond and records its kernel-thread identity.
    pub fn start(&mut self) -> Result<()> {
        match self.state {
            SessionState::Staged => {}
            SessionState::Running(_) => return Err(Error::KdamondRunning { index: 0 }),
            SessionState::UnidentifiedRunning => {
                return Err(Error::OwnershipLost {
                    reason: "the kdamond started but its identity was not captured",
                });
            }
            SessionState::Closed => return Err(Error::NotRunning),
        }
        self.staged.verify(&self.admin)?;
        match retry_busy(|| self.kdamond.state())? {
            KdamondState::Off => {}
            KdamondState::On => {
                return Err(Error::OwnershipLost {
                    reason: "the staged kdamond was started by another controller",
                });
            }
            KdamondState::Unknown(state) => {
                return Err(Error::UnexpectedKdamondState { state });
            }
        }

        retry_busy(|| self.kdamond.command(&KdamondCommand::On))?;
        self.state = SessionState::UnidentifiedRunning;
        let pid = running_thread_pid(&self.kdamond)?;
        self.state = SessionState::Running(pid);
        self.verify_running()
    }

    /// Stops the kdamond while retaining the staged configuration and lock.
    pub fn stop(&mut self) -> Result<()> {
        self.stop_inner()
    }

    /// Stops the kdamond and restores the hierarchy that preceded the session.
    ///
    /// Unlike [`Drop`], this method reports restoration failures.
    pub fn close(mut self) -> Result<()> {
        self.close_inner()
    }

    /// Returns whether this session's identified kdamond is still running.
    pub fn is_running(&self) -> Result<bool> {
        match self.state {
            SessionState::Staged => {
                self.staged.verify(&self.admin)?;
                match retry_busy(|| self.kdamond.state())? {
                    KdamondState::Off => Ok(false),
                    KdamondState::On => Err(Error::OwnershipLost {
                        reason: "the staged kdamond was started by another controller",
                    }),
                    KdamondState::Unknown(state) => Err(Error::UnexpectedKdamondState { state }),
                }
            }
            SessionState::Running(_) => match self.verify_running() {
                Ok(()) => Ok(true),
                Err(Error::NotRunning) => Ok(false),
                Err(error) => Err(error),
            },
            SessionState::UnidentifiedRunning => Err(Error::OwnershipLost {
                reason: "the kdamond started but its identity was not captured",
            }),
            SessionState::Closed => Ok(false),
        }
    }

    /// Reads the complete staged configuration after verifying ownership.
    pub fn configuration(&self) -> Result<DamonConfig> {
        self.verify_owned_state()?;
        let configuration = retry_busy(|| self.admin.configuration())?;
        self.verify_owned_state()?;
        Ok(configuration)
    }

    /// Discovers capabilities for a staged context and scheme without mutation.
    pub fn capabilities(&self, context_index: usize, scheme_index: usize) -> Result<Capabilities> {
        self.verify_owned_state()?;
        let capabilities = retry_busy(|| self.kdamond.capabilities(context_index, scheme_index))?;
        self.verify_owned_state()?;
        Ok(capabilities)
    }

    fn capabilities_for_schemes(
        &self,
        context_index: usize,
        scheme_indices: &[usize],
    ) -> Result<Capabilities> {
        self.verify_owned_state()?;
        let capabilities = retry_busy(|| {
            self.kdamond
                .capabilities_for_schemes(context_index, scheme_indices)
        })?;
        self.verify_owned_state()?;
        Ok(capabilities)
    }

    fn replace_staged_configuration(&mut self, config: &DamonConfig) -> Result<()> {
        config.validate_runnable()?;
        if config.kdamonds.len() != 1 {
            return Err(Error::InvalidConfiguration {
                field: "exclusive session kdamond count",
                reason: "must contain exactly one kdamond",
            });
        }
        if !matches!(self.state, SessionState::Staged) {
            return Err(Error::KdamondRunning { index: 0 });
        }
        self.staged.verify(&self.admin)?;
        retry_busy(|| ensure_hierarchy_stopped(&self.admin))?;
        let previous = retry_busy(|| self.admin.configuration())?;
        self.staged.verify(&self.admin)?;

        match stage_and_verify_configuration(&self.admin, config, Some(&previous)) {
            Ok(fingerprint) => {
                self.staged = StagedOwnership::new(fingerprint, &self.kdamond, &config.kdamonds[0]);
                Ok(())
            }
            Err(operation) => match stage_and_verify_configuration(&self.admin, &previous, None) {
                Ok(fingerprint) => {
                    self.staged =
                        StagedOwnership::new(fingerprint, &self.kdamond, &previous.kdamonds[0]);
                    Err(operation)
                }
                Err(rollback) => Err(Error::Rollback {
                    operation: Box::new(operation),
                    rollback: Box::new(rollback),
                }),
            },
        }
    }

    /// Applies the currently staged inputs to the running kdamond.
    ///
    /// The session refuses untracked sysfs changes. Use
    /// [`Self::update_configuration`] to stage and commit a changed owned
    /// configuration while preserving rollback and ownership checks.
    pub fn commit(&mut self) -> Result<()> {
        self.command_with_identity_check(&KdamondCommand::Commit)?;
        self.verify_running_identity()
    }

    /// Transactionally stages and commits a changed running configuration.
    ///
    /// The requested hierarchy must still contain this session's one runnable
    /// kdamond. Obsolete targets must match the preceding target at the same
    /// index. Their one-shot markers are removed from the staged hierarchy
    /// after a successful commit, and scheme target-filter indexes refer to the
    /// retained post-commit target list. On failure, the method stages and
    /// commits the preceding owned configuration before returning the error.
    /// Controllers that ignore the advisory lock can still interfere because
    /// sysfs has no ownership or atomic-commit primitive.
    pub fn update_configuration(&mut self, config: &DamonConfig) -> Result<()> {
        config.validate_running_update()?;
        if config.kdamonds.len() != 1 {
            return Err(Error::InvalidConfiguration {
                field: "exclusive session kdamond count",
                reason: "must contain exactly one kdamond",
            });
        }
        self.verify_running()?;
        let previous = retry_busy(|| self.admin.configuration())?;
        self.verify_running()?;
        validate_obsolete_target_updates(&previous, config)?;

        match self.stage_and_commit_running(config, Some(&previous)) {
            Ok(staged) => {
                self.staged = staged;
                Ok(())
            }
            Err(operation) => match self.stage_and_commit_running(&previous, None) {
                Ok(staged) => {
                    self.staged = staged;
                    Err(operation)
                }
                Err(rollback) => Err(Error::Rollback {
                    operation: Box::new(operation),
                    rollback: Box::new(rollback),
                }),
            },
        }
    }

    /// Applies staged DAMOS quota-goal changes to the running kdamond.
    pub fn commit_scheme_quota_goals(&mut self) -> Result<()> {
        self.command_with_identity_check(&KdamondCommand::CommitSchemesQuotaGoals)?;
        self.verify_running_identity()
    }

    /// Pauses the first monitoring context and commits the request.
    pub fn pause(&mut self) -> Result<()> {
        self.pause_context(0)
    }

    /// Resumes the first monitoring context and commits the request.
    pub fn resume(&mut self) -> Result<()> {
        self.resume_context(0)
    }

    /// Pauses one monitoring context and commits the request.
    pub fn pause_context(&mut self, context_index: usize) -> Result<()> {
        self.set_context_paused(context_index, true)
    }

    /// Resumes one monitoring context and commits the request.
    pub fn resume_context(&mut self, context_index: usize) -> Result<()> {
        self.set_context_paused(context_index, false)
    }

    /// Refreshes and reads one scheme's runtime statistics.
    pub fn scheme_stats(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<SchemeStats> {
        let scheme = self.scheme(context_index, scheme_index)?;
        self.refresh_runtime_output(&KdamondCommand::UpdateSchemesStats)?;
        let stats = scheme.stats()?;
        self.verify_running_identity()?;
        Ok(stats)
    }

    /// Reads the last materialized scheme statistics without requesting a
    /// synchronous kernel refresh.
    pub fn cached_scheme_stats(
        &self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<SchemeStats> {
        self.verify_running()?;
        let stats = self.scheme(context_index, scheme_index)?.stats()?;
        self.verify_running_identity()?;
        Ok(stats)
    }

    /// Materializes and reads one scheme's tried regions in raw address units.
    pub fn tried_regions(
        &mut self,
        context_index: usize,
        scheme_index: usize,
        capacity_hint: usize,
    ) -> Result<RawSnapshot> {
        let scheme = self.scheme(context_index, scheme_index)?;
        self.command_with_identity_check(&KdamondCommand::UpdateSchemesTriedRegions)?;
        let snapshot = scheme.tried_regions(capacity_hint)?;
        self.verify_running_identity()?;
        Ok(snapshot)
    }

    /// Refreshes and reads one scheme's total tried size in core address units.
    pub fn tried_bytes_units(&mut self, context_index: usize, scheme_index: usize) -> Result<u64> {
        let scheme = self.scheme(context_index, scheme_index)?;
        self.command_with_identity_check(&KdamondCommand::UpdateSchemesTriedBytes)?;
        let units = scheme.tried_bytes_units()?;
        self.verify_running_identity()?;
        Ok(units)
    }

    /// Refreshes and reads one scheme's effective quota in core address units.
    pub fn effective_quota_units(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<u64> {
        let scheme = self.scheme(context_index, scheme_index)?;
        self.refresh_runtime_output(&KdamondCommand::UpdateSchemesEffectiveQuotas)?;
        let units = scheme.quotas().effective_size_units()?;
        self.verify_running_identity()?;
        Ok(units)
    }

    /// Reads the last materialized effective quota without requesting a
    /// synchronous kernel refresh.
    pub fn cached_effective_quota_units(
        &self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<u64> {
        self.verify_running()?;
        let units = self
            .scheme(context_index, scheme_index)?
            .quotas()
            .effective_size_units()?;
        self.verify_running_identity()?;
        Ok(units)
    }

    /// Runs multiple runtime reads or refreshes under one pair of complete
    /// ownership checks.
    ///
    /// Individual batch operations still verify the kdamond thread identity.
    /// The complete writable hierarchy is checked before and after the
    /// closure, reducing sysfs reads for polling loops without weakening the
    /// boundary checks. If both the closure and the final ownership check
    /// fail, the ownership error is returned because the closure's outputs
    /// cannot be trusted.
    pub fn runtime_batch<T>(
        &mut self,
        operation: impl FnOnce(&mut RuntimeBatch<'_>) -> Result<T>,
    ) -> Result<T> {
        self.verify_running()?;
        let result = {
            let mut batch = RuntimeBatch { session: self };
            operation(&mut batch)
        };
        let ownership = self.verify_running_identity();
        ownership?;
        result
    }

    /// Refreshes auto-tuned interval values for the running kdamond.
    pub fn update_tuned_intervals(&mut self) -> Result<()> {
        self.refresh_runtime_output(&KdamondCommand::UpdateTunedIntervals)?;
        self.verify_running_identity()
    }

    /// Clears all materialized tried-region results.
    pub fn clear_tried_regions(&mut self) -> Result<()> {
        self.command_with_identity_check(&KdamondCommand::ClearSchemesTriedRegions)?;
        self.verify_running_identity()
    }

    fn set_context_paused(&mut self, context_index: usize, paused: bool) -> Result<()> {
        self.verify_running()?;
        let context_count = self.kdamond.context_count()?;
        if context_index >= context_count {
            return Err(Error::IndexOutOfBounds {
                kind: "context",
                index: context_index,
                count: context_count,
            });
        }
        let context = self.kdamond.context(context_index);
        if !context.pause_control_available()? {
            return Err(Error::UnsupportedFeature {
                feature: "DAMON context pause",
            });
        }
        let previous = context.is_paused()?;
        if previous == paused {
            return Ok(());
        }
        let previous_fingerprint = self.staged.configuration.clone();
        let pause_path = context.path().join("pause");
        context.set_paused(paused)?;
        let operation = (|| {
            retry_busy(|| self.kdamond.command(&KdamondCommand::Commit))?;
            self.verify_running_identity_only()?;
            let observed = context.is_paused()?;
            if observed != paused {
                return Err(Error::ConfigurationMismatch {
                    path: format!("contexts/{context_index}/pause").into(),
                    expected: paused.to_string().into(),
                    observed: observed.to_string().into(),
                });
            }
            let refreshed = self.staged.configuration.refreshed_paths_except(
                std::slice::from_ref(&pause_path),
                &self.staged.volatile_paths,
            )?;
            self.verify_running_identity_only()?;
            self.staged.configuration = refreshed;
            Ok(())
        })();
        if let Err(operation) = operation {
            let rollback = (|| {
                context.set_paused(previous)?;
                retry_busy(|| self.kdamond.command(&KdamondCommand::Commit))?;
                let restored = previous_fingerprint.refreshed_paths_except(
                    std::slice::from_ref(&pause_path),
                    &self.staged.volatile_paths,
                )?;
                self.verify_running_identity_only()?;
                self.staged.configuration = restored;
                Ok(())
            })();
            return Err(with_rollback(operation, rollback));
        }
        Ok(())
    }

    fn stage_and_commit_running(
        &self,
        config: &DamonConfig,
        observed: Option<&DamonConfig>,
    ) -> Result<StagedOwnership> {
        self.verify_running_identity_only()?;
        retry_busy(|| {
            self.verify_running_identity_only()?;
            self.admin
                .stage_validated_configuration_from(config, observed)
        })?;
        self.verify_running_identity_only()?;
        let snapshot = retry_busy(|| self.admin.configuration_snapshot())?;
        let mut staged_config = retry_busy(|| self.admin.configuration())?;
        normalize_running_tuned_intervals(config, observed, &mut staged_config)?;
        if let Some(error) = config.mismatch_error(&staged_config) {
            return Err(error);
        }
        if !retry_busy(|| snapshot.values_match_current())? {
            return Err(Error::OwnershipLost {
                reason: "the running DAMON hierarchy changed during staging",
            });
        }
        self.verify_running_identity_only()?;
        retry_busy(|| self.kdamond.command(&KdamondCommand::Commit))?;
        self.verify_running_identity_only()?;

        if contains_obsolete_targets(config) {
            let cleaned = without_obsolete_targets(config);
            retry_busy(|| {
                self.verify_running_identity_only()?;
                self.admin
                    .stage_validated_configuration_from(&cleaned, Some(config))
            })?;
            self.verify_running_identity_only()?;
            let cleaned_snapshot = retry_busy(|| self.admin.configuration_snapshot())?;
            let mut cleaned_staged_config = retry_busy(|| self.admin.configuration())?;
            normalize_running_tuned_intervals(&cleaned, Some(config), &mut cleaned_staged_config)?;
            if let Some(error) = cleaned.mismatch_error(&cleaned_staged_config) {
                return Err(error);
            }
            if !retry_busy(|| cleaned_snapshot.values_match_current())? {
                return Err(Error::OwnershipLost {
                    reason: "the running DAMON hierarchy changed during obsolete-target cleanup",
                });
            }
            self.verify_running_identity_only()?;
            let staged = StagedOwnership::new(
                cleaned_snapshot.into_fingerprint(),
                &self.kdamond,
                &cleaned.kdamonds[0],
            );
            staged.verify(&self.admin)?;
            return Ok(staged);
        }

        let staged = StagedOwnership::new(
            snapshot.into_fingerprint(),
            &self.kdamond,
            &config.kdamonds[0],
        );
        staged.verify(&self.admin)?;
        Ok(staged)
    }

    fn command_with_identity_check(&self, command: &KdamondCommand) -> Result<()> {
        self.verify_running()?;
        retry_busy(|| self.kdamond.command(command))?;
        self.verify_running_identity_only()
    }

    fn refresh_runtime_output(&self, command: &KdamondCommand) -> Result<()> {
        self.verify_running()?;
        retry_busy(|| self.kdamond.command(command))?;
        self.verify_running_identity_only()
    }

    fn scheme(&self, context_index: usize, scheme_index: usize) -> Result<crate::sysfs::Scheme> {
        let context_count = self.kdamond.context_count()?;
        if context_index >= context_count {
            return Err(Error::IndexOutOfBounds {
                kind: "context",
                index: context_index,
                count: context_count,
            });
        }
        let context = self.kdamond.context(context_index);
        let scheme_count = context.scheme_count()?;
        if scheme_index >= scheme_count {
            return Err(Error::IndexOutOfBounds {
                kind: "scheme",
                index: scheme_index,
                count: scheme_count,
            });
        }
        Ok(context.scheme(scheme_index))
    }

    fn verify_owned_state(&self) -> Result<()> {
        match self.state {
            SessionState::Staged => self.staged.verify(&self.admin),
            SessionState::Running(_) => self.verify_running(),
            SessionState::UnidentifiedRunning => Err(Error::OwnershipLost {
                reason: "the kdamond started but its identity was not captured",
            }),
            SessionState::Closed => Err(Error::NotRunning),
        }
    }

    fn verify_running(&self) -> Result<()> {
        let SessionState::Running(expected) = self.state else {
            return Err(Error::NotRunning);
        };
        self.staged.verify(&self.admin)?;
        let current = running_thread_pid(&self.kdamond)?;
        if current != expected {
            return Err(Error::OwnershipLost {
                reason: "the kdamond kernel-thread ID changed",
            });
        }
        Ok(())
    }

    fn verify_running_identity(&self) -> Result<()> {
        self.staged.verify(&self.admin)?;
        self.verify_running_identity_only()
    }

    fn verify_running_identity_only(&self) -> Result<()> {
        let SessionState::Running(expected) = self.state else {
            return Err(Error::NotRunning);
        };
        if self.admin.kdamond_count()? != 1 {
            return Err(Error::OwnershipLost {
                reason: "the staged kdamond count changed",
            });
        }
        let current = retry_busy(|| self.kdamond.pid())?.ok_or(Error::NotRunning)?;
        if current != expected {
            return Err(Error::OwnershipLost {
                reason: "the kdamond kernel-thread ID changed",
            });
        }
        Ok(())
    }

    fn stop_inner(&mut self) -> Result<()> {
        match self.state {
            SessionState::Staged => {
                self.staged.verify(&self.admin)?;
                match retry_busy(|| self.kdamond.state())? {
                    KdamondState::Off => Ok(()),
                    KdamondState::On => Err(Error::OwnershipLost {
                        reason: "the staged kdamond was started by another controller",
                    }),
                    KdamondState::Unknown(state) => Err(Error::UnexpectedKdamondState { state }),
                }
            }
            SessionState::Running(_) => {
                self.staged.verify(&self.admin)?;
                match retry_busy(|| self.kdamond.state())? {
                    KdamondState::On => {
                        self.verify_running_identity_only()?;
                        retry_busy(|| self.kdamond.command(&KdamondCommand::Off))?;
                        self.staged.verify(&self.admin)?;
                        match retry_busy(|| self.kdamond.state())? {
                            KdamondState::Off => {
                                self.state = SessionState::Staged;
                                Ok(())
                            }
                            KdamondState::On => Err(Error::OwnershipLost {
                                reason: "the kdamond restarted while it was being stopped",
                            }),
                            KdamondState::Unknown(state) => {
                                Err(Error::UnexpectedKdamondState { state })
                            }
                        }
                    }
                    KdamondState::Off => {
                        self.staged.verify(&self.admin)?;
                        self.state = SessionState::Staged;
                        Ok(())
                    }
                    KdamondState::Unknown(state) => Err(Error::UnexpectedKdamondState { state }),
                }
            }
            SessionState::UnidentifiedRunning => {
                self.staged.verify(&self.admin)?;
                match retry_busy(|| self.kdamond.state())? {
                    KdamondState::Off => {
                        self.state = SessionState::Staged;
                        Ok(())
                    }
                    KdamondState::On => Err(Error::OwnershipLost {
                        reason: "cannot safely stop a kdamond before its kernel-thread ID was captured",
                    }),
                    KdamondState::Unknown(state) => Err(Error::UnexpectedKdamondState { state }),
                }
            }
            SessionState::Closed => Ok(()),
        }
    }

    fn close_inner(&mut self) -> Result<()> {
        if !self.owns_hierarchy {
            return Ok(());
        }
        self.stop_inner()?;
        self.staged.verify(&self.admin)?;
        if !retry_busy(|| self.previous.matches_current())? {
            restore_configuration(&self.admin, &self.previous)?;
        }
        self.owns_hierarchy = false;
        self.state = SessionState::Closed;
        Ok(())
    }
}

fn validate_obsolete_target_updates(previous: &DamonConfig, requested: &DamonConfig) -> Result<()> {
    for (previous_kdamond, requested_kdamond) in previous.kdamonds.iter().zip(&requested.kdamonds) {
        for (previous_context, requested_context) in previous_kdamond
            .contexts
            .iter()
            .zip(&requested_kdamond.contexts)
        {
            for (index, requested_target) in requested_context.targets.iter().enumerate() {
                if !requested_target.obsolete {
                    continue;
                }
                let Some(previous_target) = previous_context.targets.get(index) else {
                    return Err(Error::InvalidConfiguration {
                        field: "obsolete target",
                        reason: "must identify an existing target at the same index",
                    });
                };
                let mut retained_target = requested_target.clone();
                retained_target.obsolete = false;
                if previous_target.obsolete || retained_target != *previous_target {
                    return Err(Error::InvalidConfiguration {
                        field: "obsolete target",
                        reason: "must match the existing target at the same index",
                    });
                }
            }
        }
    }
    Ok(())
}

fn contains_obsolete_targets(config: &DamonConfig) -> bool {
    config.kdamonds.iter().any(|kdamond| {
        kdamond
            .contexts
            .iter()
            .any(|context| context.targets.iter().any(|target| target.obsolete))
    })
}

fn without_obsolete_targets(config: &DamonConfig) -> DamonConfig {
    let mut cleaned = config.clone();
    for kdamond in &mut cleaned.kdamonds {
        for context in &mut kdamond.contexts {
            context.targets.retain(|target| !target.obsolete);
        }
    }
    cleaned
}

fn normalize_running_tuned_intervals(
    requested: &DamonConfig,
    previous: Option<&DamonConfig>,
    observed: &mut DamonConfig,
) -> Result<()> {
    for (kdamond_index, (requested_kdamond, observed_kdamond)) in requested
        .kdamonds
        .iter()
        .zip(&mut observed.kdamonds)
        .enumerate()
    {
        for (context_index, (requested_context, observed_context)) in requested_kdamond
            .contexts
            .iter()
            .zip(&mut observed_kdamond.contexts)
            .enumerate()
        {
            let was_tuned = previous
                .and_then(|config| config.kdamonds.get(kdamond_index))
                .and_then(|kdamond| kdamond.contexts.get(context_index))
                .is_some_and(|context| context.intervals_goal.aggregation_intervals != 0);
            if requested_context.intervals_goal.aggregation_intervals == 0 && !was_tuned {
                continue;
            }
            observed_context.intervals = MonitoringIntervals::new(
                requested_context.intervals.sample(),
                requested_context.intervals.aggregation(),
                observed_context.intervals.update(),
            )?;
        }
    }
    Ok(())
}

/// Runtime operations batched between complete ownership checks.
///
/// Construct this through [`ExclusiveSession::runtime_batch`].
#[derive(Debug)]
pub struct RuntimeBatch<'a> {
    session: &'a mut ExclusiveSession,
}

impl RuntimeBatch<'_> {
    /// Synchronously refreshes and reads one scheme's statistics.
    pub fn scheme_stats(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<SchemeStats> {
        let scheme = self.session.scheme(context_index, scheme_index)?;
        self.command(&KdamondCommand::UpdateSchemesStats)?;
        let stats = scheme.stats()?;
        self.session.verify_running_identity_only()?;
        Ok(stats)
    }

    /// Reads the last materialized scheme statistics.
    pub fn cached_scheme_stats(
        &self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<SchemeStats> {
        self.session.verify_running_identity_only()?;
        let stats = self.session.scheme(context_index, scheme_index)?.stats()?;
        self.session.verify_running_identity_only()?;
        Ok(stats)
    }

    /// Materializes and reads one scheme's tried regions.
    pub fn tried_regions(
        &mut self,
        context_index: usize,
        scheme_index: usize,
        capacity_hint: usize,
    ) -> Result<RawSnapshot> {
        let scheme = self.session.scheme(context_index, scheme_index)?;
        self.command(&KdamondCommand::UpdateSchemesTriedRegions)?;
        let snapshot = scheme.tried_regions(capacity_hint)?;
        self.session.verify_running_identity_only()?;
        Ok(snapshot)
    }

    /// Synchronously refreshes and reads total tried units.
    pub fn tried_bytes_units(&mut self, context_index: usize, scheme_index: usize) -> Result<u64> {
        let scheme = self.session.scheme(context_index, scheme_index)?;
        self.command(&KdamondCommand::UpdateSchemesTriedBytes)?;
        let units = scheme.tried_bytes_units()?;
        self.session.verify_running_identity_only()?;
        Ok(units)
    }

    /// Synchronously refreshes and reads effective quota units.
    pub fn effective_quota_units(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<u64> {
        let scheme = self.session.scheme(context_index, scheme_index)?;
        self.command(&KdamondCommand::UpdateSchemesEffectiveQuotas)?;
        let units = scheme.quotas().effective_size_units()?;
        self.session.verify_running_identity_only()?;
        Ok(units)
    }

    /// Reads the last materialized effective quota units.
    pub fn cached_effective_quota_units(
        &self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<u64> {
        self.session.verify_running_identity_only()?;
        let units = self
            .session
            .scheme(context_index, scheme_index)?
            .quotas()
            .effective_size_units()?;
        self.session.verify_running_identity_only()?;
        Ok(units)
    }

    /// Synchronously refreshes auto-tuned monitoring intervals.
    pub fn update_tuned_intervals(&mut self) -> Result<()> {
        self.command(&KdamondCommand::UpdateTunedIntervals)
    }

    /// Clears materialized tried-region results.
    pub fn clear_tried_regions(&mut self) -> Result<()> {
        self.command(&KdamondCommand::ClearSchemesTriedRegions)
    }

    fn command(&self, command: &KdamondCommand) -> Result<()> {
        self.session.verify_running_identity_only()?;
        retry_busy(|| self.session.kdamond.command(command))?;
        self.session.verify_running_identity_only()
    }
}

impl Drop for ExclusiveSession {
    fn drop(&mut self) {
        let _ = self.close_inner();
    }
}

#[derive(Clone, Debug)]
struct WorkflowOptions<'a> {
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
    fn new(damon: &'a Damon) -> Self {
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
    options: WorkflowOptions<'a>,
    pid: Option<Pid>,
}

/// Backwards-compatible name for [`VaddrSessionBuilder`].
pub type MonitorBuilder<'a> = VaddrSessionBuilder<'a>;

/// Builder for a fixed virtual-address monitoring workflow.
#[derive(Clone, Debug)]
pub struct FvaddrSessionBuilder<'a> {
    options: WorkflowOptions<'a>,
    pid: Option<Pid>,
}

/// Builder for a physical-address monitoring workflow.
#[derive(Clone, Debug)]
pub struct PaddrSessionBuilder<'a> {
    options: WorkflowOptions<'a>,
    address_unit: AddressUnit,
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
        return Err(with_rollback(error, session.close()));
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct StagedOwnership {
    configuration: ConfigurationFingerprint,
    volatile_paths: Box<[PathBuf]>,
}

impl StagedOwnership {
    fn new(
        configuration: ConfigurationFingerprint,
        kdamond: &Kdamond,
        config: &KdamondConfig,
    ) -> Self {
        let mut volatile_paths = Vec::new();
        for (index, context) in config.contexts.iter().enumerate() {
            if context.intervals_goal.aggregation_intervals == 0 {
                continue;
            }
            let intervals = kdamond
                .context(index)
                .path()
                .join("monitoring_attrs/intervals");
            volatile_paths.push(intervals.join("sample_us"));
            volatile_paths.push(intervals.join("aggr_us"));
        }
        volatile_paths.sort_unstable();
        Self {
            configuration,
            volatile_paths: volatile_paths.into_boxed_slice(),
        }
    }

    fn verify(&self, admin: &DamonAdmin) -> Result<()> {
        if admin.kdamond_count()? != 1 {
            return Err(Error::OwnershipLost {
                reason: "the staged kdamond count changed",
            });
        }
        if !self
            .configuration
            .matches_current_except(&self.volatile_paths)?
        {
            return Err(Error::OwnershipLost {
                reason: "the staged writable configuration changed",
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

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::sysfs::test_backend::{Model, ModelRegion, ModelSchemeStats, Mutation};
    use crate::sysfs::{
        AccessCountRange, AccessPattern, AgeRange, ContextConfig, FilterConfig,
        IntervalsGoalConfig, KdamondConfig, QuotaGoalConfig, QuotaGoalMetric, RegionSizeRange,
        SchemeConfig, SchemeFilterType, TargetConfig,
    };

    #[test]
    fn vaddr_workflow_composes_regions_probes_schemes_and_snapshot_query() {
        let model = Model::new("vaddr\nfvaddr\npaddr\n");
        model.set_tried_regions(vec![ModelRegion {
            start: 4_096,
            end: 8_192,
            nr_accesses: 7,
            age: 3,
            filter_passed_units: Some(4_096),
            probe_hits: vec![5],
        }]);
        model.set_scheme_stats(vec![ModelSchemeStats {
            nr_tried: 11,
            sz_tried: 12,
            nr_applied: 13,
            sz_applied: 14,
            sz_ops_filter_passed: 15,
            qt_exceeds: 16,
            nr_snapshots: 17,
        }]);
        model.set_effective_quota_bytes(vec![18]);
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let initial = InitialRegionConfig::new(0x1_0000, 0x2_0000).expect("valid region");
        let mut monitor = damon
            .vaddr()
            .pid(Pid::new(42).expect("valid pid"))
            .region(initial)
            .probe(ProbeConfig::default())
            .scheme(SchemeConfig::new(Action::PageOut, match_all_pattern()))
            .start()
            .expect("start vaddr workflow");

        assert_eq!(monitor.operation(), &Operation::VirtualAddress);
        assert_eq!(monitor.effective_address_unit(), AddressUnit::ONE);
        assert_eq!(monitor.scheme_count(), 1);
        assert_eq!(
            model
                .value("kdamonds/0/contexts/0/monitoring_attrs/probes/nr_probes")
                .as_deref(),
            Some("1")
        );
        assert_eq!(
            model
                .value("kdamonds/0/contexts/0/targets/0/regions/0/start")
                .as_deref(),
            Some("65536")
        );
        assert_eq!(
            model
                .value("kdamonds/0/contexts/0/schemes/0/action")
                .as_deref(),
            Some("pageout")
        );
        assert_eq!(
            model
                .value("kdamonds/0/contexts/0/schemes/nr_schemes")
                .as_deref(),
            Some("1")
        );

        let snapshot = monitor.snapshot().expect("query private snapshot scheme");
        assert_eq!(snapshot.total_bytes().expect("byte total"), 4_096);
        assert_eq!(snapshot.region(0).expect("region").nr_accesses(), 7);
        assert_eq!(
            model
                .value("kdamonds/0/contexts/0/schemes/nr_schemes")
                .as_deref(),
            Some("1")
        );
        let stats = monitor.scheme_stats(0).expect("custom scheme stats");
        assert_eq!(stats.size_tried_units, 12);
        assert_eq!(monitor.effective_quota_units(0).expect("custom quota"), 18);
        assert!(matches!(
            monitor.scheme_stats(1),
            Err(Error::IndexOutOfBounds {
                kind: "custom scheme",
                ..
            })
        ));
        monitor.pause().expect("pause workflow");
        monitor.resume().expect("resume workflow");
        monitor.stop().expect("restore hierarchy");
    }

    #[test]
    fn fvaddr_workflow_requires_pid_and_fixed_regions_before_writing() {
        let model = Model::new("vaddr\nfvaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let writes = model.write_count();

        assert!(matches!(
            damon.fvaddr().start(),
            Err(Error::InvalidConfiguration {
                field: "fixed virtual-address PID",
                ..
            })
        ));
        assert!(matches!(
            damon.fvaddr().pid(Pid::new(42).expect("valid pid")).start(),
            Err(Error::InvalidConfiguration {
                field: "fixed virtual-address target regions",
                ..
            })
        ));
        assert_eq!(model.write_count(), writes);

        let monitor = damon
            .fvaddr()
            .pid(Pid::new(42).expect("valid pid"))
            .regions([InitialRegionConfig::new(100, 200).expect("valid region")])
            .start()
            .expect("start fvaddr workflow");
        assert_eq!(monitor.operation(), &Operation::FixedVirtualAddress);
        assert_eq!(monitor.effective_address_unit(), AddressUnit::ONE);
        assert_eq!(
            model.value("kdamonds/0/contexts/0/operations").as_deref(),
            Some("fvaddr")
        );
        monitor.stop().expect("restore hierarchy");
    }

    #[test]
    fn paddr_workflow_keeps_core_units_and_checked_byte_scale() {
        let model = Model::new("paddr\n");
        model.set_tried_regions(vec![ModelRegion {
            start: 2,
            end: 4,
            nr_accesses: 1,
            age: 1,
            filter_passed_units: Some(2),
            probe_hits: Vec::new(),
        }]);
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let writes = model.write_count();
        assert!(matches!(
            damon.paddr().start(),
            Err(Error::InvalidConfiguration {
                field: "physical-address target regions",
                ..
            })
        ));
        assert_eq!(model.write_count(), writes);

        let address_unit = AddressUnit::new(4_096).expect("valid page-size unit");
        let mut monitor = damon
            .paddr()
            .address_unit(address_unit)
            .region_units(InitialRegionConfig::new(2, 4).expect("valid raw region"))
            .start()
            .expect("start paddr workflow");
        assert_eq!(monitor.operation(), &Operation::PhysicalAddress);
        assert_eq!(monitor.effective_address_unit(), address_unit);
        assert_eq!(
            model
                .value("kdamonds/0/contexts/0/targets/0/pid_target")
                .as_deref(),
            Some("0")
        );
        let snapshot = monitor.snapshot().expect("query paddr snapshot");
        let region = snapshot.region(0).expect("physical region");
        assert_eq!(region.start_units(), 2);
        assert_eq!(region.start_bytes().expect("start bytes"), 8_192);
        assert_eq!(region.end_bytes().expect("end bytes"), 16_384);
        assert_eq!(snapshot.total_units(), 2);
        assert_eq!(snapshot.total_bytes().expect("total bytes"), 8_192);
        monitor.stop().expect("restore hierarchy");
    }

    #[test]
    fn current_kernels_install_snapshot_query_only_on_demand() {
        let model = Model::new("vaddr\n");
        model.set_tried_regions(vec![ModelRegion {
            start: 4_096,
            end: 8_192,
            nr_accesses: 1,
            age: 1,
            filter_passed_units: None,
            probe_hits: Vec::new(),
        }]);
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut monitor = damon
            .monitor_pid(Pid::new(42).expect("valid pid"))
            .start()
            .expect("start monitor");

        assert_eq!(
            model
                .value("kdamonds/0/contexts/0/schemes/nr_schemes")
                .as_deref(),
            Some("0")
        );
        assert_eq!(
            monitor
                .snapshot()
                .expect("query snapshot")
                .raw_regions()
                .len(),
            1
        );
        assert_eq!(
            model
                .value("kdamonds/0/contexts/0/schemes/nr_schemes")
                .as_deref(),
            Some("0")
        );
        monitor.stop().expect("restore hierarchy");
    }

    #[test]
    fn legacy_kernels_retain_the_snapshot_query_scheme() {
        let model = Model::without_available_operations_file("vaddr\n");
        model.set_tried_regions(vec![ModelRegion {
            start: 4_096,
            end: 8_192,
            nr_accesses: 1,
            age: 1,
            filter_passed_units: None,
            probe_hits: Vec::new(),
        }]);
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut monitor = damon
            .monitor_pid(Pid::new(42).expect("valid pid"))
            .start()
            .expect("start legacy monitor");

        assert_eq!(
            model
                .value("kdamonds/0/contexts/0/schemes/nr_schemes")
                .as_deref(),
            Some("1")
        );
        assert_eq!(
            monitor
                .snapshot()
                .expect("query legacy snapshot")
                .raw_regions()
                .len(),
            1
        );
        assert_eq!(
            model
                .value("kdamonds/0/contexts/0/schemes/nr_schemes")
                .as_deref(),
            Some("1")
        );
        monitor.stop().expect("restore hierarchy");
    }

    #[test]
    fn high_level_capabilities_include_custom_scheme_children() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut scheme = SchemeConfig::new(Action::Stat, match_all_pattern());
        scheme
            .filters
            .push(FilterConfig::new(SchemeFilterType::Anonymous, true, true));
        let monitor = damon
            .vaddr()
            .pid(Pid::new(42).expect("valid pid"))
            .scheme(scheme)
            .start()
            .expect("start monitor with filter");

        assert_eq!(
            monitor
                .capabilities()
                .feature_support(SysfsFeature::SchemeFilterAnonymous),
            CapabilitySupport::Unverified
        );
        assert_eq!(
            monitor
                .capabilities()
                .feature_support(SysfsFeature::SchemeFilterAllow),
            CapabilitySupport::Supported
        );
        monitor.stop().expect("restore hierarchy");
    }

    #[test]
    fn high_level_effective_quota_reads_are_capability_gated() {
        let model = Model::new("vaddr\n");
        model.disable_effective_quota();
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut monitor = damon
            .vaddr()
            .pid(Pid::new(42).expect("valid pid"))
            .scheme(SchemeConfig::new(Action::Stat, match_all_pattern()))
            .start()
            .expect("start monitor without effective quotas");
        let writes = model.write_count();

        assert!(matches!(
            monitor.effective_quota_units(0),
            Err(Error::UnsupportedFeature {
                feature: "DAMOS effective quota reporting"
            })
        ));
        assert!(matches!(
            monitor.cached_effective_quota_units(0),
            Err(Error::UnsupportedFeature {
                feature: "DAMOS effective quota reporting"
            })
        ));
        assert_eq!(model.write_count(), writes);
        monitor.stop().expect("restore hierarchy");
    }

    #[test]
    fn high_level_all_scheme_reads_share_refresh_and_ownership_scans() {
        let model = Model::new("vaddr\n");
        model.set_scheme_stats(vec![
            ModelSchemeStats {
                nr_tried: 1,
                ..ModelSchemeStats::default()
            },
            ModelSchemeStats {
                nr_tried: 2,
                ..ModelSchemeStats::default()
            },
            ModelSchemeStats {
                nr_tried: 3,
                ..ModelSchemeStats::default()
            },
        ]);
        model.set_effective_quota_bytes(vec![4, 5, 6]);
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut builder = damon.vaddr().pid(Pid::new(42).expect("valid pid"));
        for _ in 0..3 {
            builder = builder.scheme(SchemeConfig::new(Action::Stat, match_all_pattern()));
        }
        let mut monitor = builder.start().expect("start three-scheme monitor");

        let ordinary_start = model.read_count();
        for scheme_index in 0..3 {
            monitor
                .scheme_stats(scheme_index)
                .expect("ordinary scheme read");
        }
        let ordinary_reads = model.read_count() - ordinary_start;
        let batch_start = model.read_count();
        let stats = monitor.scheme_stats_all().expect("batched scheme reads");
        let batch_reads = model.read_count() - batch_start;

        assert_eq!(
            stats
                .iter()
                .map(|stats| stats.regions_tried)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(batch_reads < ordinary_reads);
        assert_eq!(
            monitor
                .effective_quota_units_all()
                .expect("batched effective quotas"),
            vec![4, 5, 6]
        );
        monitor.stop().expect("restore hierarchy");
    }

    #[test]
    fn workflow_operation_support_and_staging_failures_restore_state() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let region = InitialRegionConfig::new(100, 200).expect("valid region");

        let error = damon
            .fvaddr()
            .pid(Pid::new(42).expect("valid pid"))
            .region(region)
            .start()
            .expect_err("unsupported operation must be classified");
        assert!(matches!(
            error,
            Error::UnsupportedOperation {
                operation: Operation::FixedVirtualAddress
            }
        ));
        assert_eq!(model.value("kdamonds/nr_kdamonds").as_deref(), Some("0"));

        let model = Model::new("vaddr\nfvaddr\n");
        model.fail_next_write("kdamonds/0/contexts/0/targets/0/regions/0/end", 5);
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let error = damon
            .fvaddr()
            .pid(Pid::new(42).expect("valid pid"))
            .region(region)
            .start()
            .expect_err("late staging failure must roll back");
        assert!(matches!(error, Error::Io { .. }));
        assert_eq!(model.value("kdamonds/nr_kdamonds").as_deref(), Some("0"));
    }

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
        invalid.kdamonds[0].contexts[0].targets[0].initial_regions = vec![
            crate::sysfs::InitialRegionConfig::new(100, 200).expect("valid region"),
            crate::sysfs::InitialRegionConfig::new(150, 250).expect("valid region"),
        ];
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
        kdamond.command(&KdamondCommand::On).expect("start kdamond");

        let error = damon
            .stage_configuration(&transaction_config(77, Action::PageOut))
            .expect_err("running hierarchy must not be replaced");

        assert!(matches!(error, Error::KdamondRunning { index: 0 }));
        assert_eq!(kdamond.state().expect("read state"), KdamondState::On);
        kdamond.command(&KdamondCommand::Off).expect("stop fixture");
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
        kdamond.command(&KdamondCommand::Off).expect("stop fixture");
    }

    #[test]
    fn exclusive_session_setup_failure_restores_the_empty_hierarchy() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        model.fail_next_write("kdamonds/0/contexts/0/schemes/0/watermarks/low", 5);

        let error = damon
            .exclusive_session(&transaction_config(42, Action::Stat))
            .expect_err("late staging failure must fail session setup");

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
        let mut session = damon
            .exclusive_session(&transaction_config(42, Action::Stat))
            .expect("stage session");
        model.after_next_read(
            "kdamonds/0/state",
            vec![Mutation::StartKdamond {
                path: "kdamonds/0".into(),
            }],
        );

        let operation = session
            .start()
            .expect_err("external start must prevent ownership");
        let error = with_rollback(operation, session.close());

        assert!(matches!(
            error,
            Error::Rollback {
                operation,
                rollback,
            } if operation.is_resource_busy()
                && matches!(*rollback, Error::OwnershipLost {
                    reason: "the staged kdamond was started by another controller"
                })
        ));
        let kdamond = damon.admin.kdamond(0);
        assert_eq!(
            kdamond.state().expect("read external state"),
            KdamondState::On
        );
        assert!(kdamond.pid().expect("read external pid").is_some());

        kdamond.command(&KdamondCommand::Off).expect("stop fixture");
        damon.admin.set_kdamond_count(0).expect("remove fixture");
    }

    #[test]
    fn exclusive_session_restores_a_multi_kdamond_hierarchy_after_runtime_commands() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut original = transaction_config(41, Action::Stat);
        original
            .kdamonds
            .push(transaction_config(43, Action::Cold).kdamonds.remove(0));
        damon
            .stage_configuration(&original)
            .expect("stage preceding hierarchy");
        let future_attribute = "kdamonds/0/contexts/0/future_session_input";
        model.set_file(future_attribute, b"preserve\n");

        let mut replacement = transaction_config(42, Action::Stat);
        replacement.kdamonds[0].contexts[0].intervals_goal = IntervalsGoalConfig {
            access_basis_points: 100,
            aggregation_intervals: 1,
            minimum_sample: Duration::from_millis(1),
            maximum_sample: Duration::from_millis(10),
        };
        let mut session = damon
            .exclusive_session(&replacement)
            .expect("stage exclusive replacement");
        assert_eq!(damon.admin.kdamond_count().expect("read count"), 1);
        assert!(matches!(
            damon.exclusive_session(&replacement),
            Err(Error::SessionLockBusy { .. })
        ));

        configure_runtime_results(&model);
        exercise_session_runtime(&model, &mut session);
        session
            .close()
            .expect("stop and restore preceding hierarchy");

        assert_eq!(
            damon
                .admin
                .configuration()
                .expect("read restored hierarchy"),
            original
        );
        assert_eq!(model.value(future_attribute).as_deref(), Some("preserve"));
    }

    fn configure_runtime_results(model: &Model) {
        model.set_tried_regions(vec![ModelRegion {
            start: 4_096,
            end: 8_192,
            nr_accesses: 7,
            age: 3,
            filter_passed_units: Some(4_096),
            probe_hits: vec![2, 5],
        }]);
        model.set_scheme_stats(vec![ModelSchemeStats {
            nr_tried: 3,
            sz_tried: 12_288,
            nr_applied: 2,
            sz_applied: 8_192,
            sz_ops_filter_passed: 4_096,
            qt_exceeds: 1,
            nr_snapshots: 9,
        }]);
        model.set_effective_quota_bytes(vec![16_384]);
    }

    fn exercise_session_runtime(model: &Model, session: &mut ExclusiveSession) {
        session.start().expect("start session");
        assert!(session.is_running().expect("read running state"));
        let writes = model.write_count();
        assert!(matches!(
            session.scheme_stats(0, 1),
            Err(Error::IndexOutOfBounds {
                kind: "scheme",
                index: 1,
                count: 1
            })
        ));
        assert_eq!(model.write_count(), writes, "invalid index must not write");

        model.after_next_write(
            "kdamonds/0/state",
            b"update_tuned_intervals".to_vec(),
            vec![
                Mutation::SetFile {
                    path: "kdamonds/0/contexts/0/monitoring_attrs/intervals/sample_us".into(),
                    value: b"4000\n".to_vec(),
                },
                Mutation::SetFile {
                    path: "kdamonds/0/contexts/0/monitoring_attrs/intervals/aggr_us".into(),
                    value: b"80000\n".to_vec(),
                },
            ],
        );
        session
            .update_tuned_intervals()
            .expect("refresh tuned intervals");
        session.pause_context(0).expect("pause context");
        assert_eq!(
            model.active_value("kdamonds/0/contexts/0/pause").as_deref(),
            Some("Y")
        );
        session.resume().expect("resume context");
        assert_eq!(
            model.active_value("kdamonds/0/contexts/0/pause").as_deref(),
            Some("N")
        );
        session.commit().expect("commit staged inputs");
        session
            .commit_scheme_quota_goals()
            .expect("commit quota goals");

        let stats = session.scheme_stats(0, 0).expect("read scheme stats");
        assert_eq!(stats.regions_tried, 3);
        assert_eq!(stats.size_applied_units, 8_192);
        assert_eq!(stats.snapshots, Some(9));
        let snapshot = session.tried_regions(0, 0, 1).expect("read tried regions");
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot.total_units(), 4_096);
        assert_eq!(
            session.tried_bytes_units(0, 0).expect("read tried bytes"),
            4_096
        );
        assert_eq!(
            session.effective_quota_units(0, 0).expect("read quota"),
            16_384
        );
        session.clear_tried_regions().expect("clear tried regions");
        session.stop().expect("stop while retaining staged state");
        assert!(!session.is_running().expect("read stopped state"));
        session.start().expect("restart retained session");
    }

    #[test]
    fn exclusive_session_drop_best_effort_restores_the_previous_hierarchy() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let original = transaction_config(41, Action::Stat);
        damon
            .stage_configuration(&original)
            .expect("stage preceding hierarchy");

        {
            let mut session = damon
                .exclusive_session(&transaction_config(42, Action::PageOut))
                .expect("stage replacement");
            session.start().expect("start replacement");
        }

        assert_eq!(
            damon
                .admin
                .configuration()
                .expect("read restored hierarchy"),
            original
        );
    }

    #[test]
    fn synchronous_refresh_is_explicit_even_with_periodic_refresh_enabled() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut config = transaction_config(42, Action::Stat);
        config.kdamonds[0].refresh_interval = Duration::from_millis(100);
        let mut session = damon.exclusive_session(&config).expect("stage session");
        session.start().expect("start session");
        let writes = model.write_count();

        session.scheme_stats(0, 0).expect("read periodic stats");
        session
            .effective_quota_units(0, 0)
            .expect("read periodic quota");
        session
            .update_tuned_intervals()
            .expect("read periodic tuned intervals");

        assert_eq!(model.write_count(), writes + 3);
        let writes = model.write_count();
        session
            .cached_scheme_stats(0, 0)
            .expect("read cached periodic stats");
        session
            .cached_effective_quota_units(0, 0)
            .expect("read cached periodic quota");
        assert_eq!(model.write_count(), writes);
        session.close().expect("close session");
    }

    #[test]
    fn exclusive_session_transactionally_updates_a_running_configuration() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let original = transaction_config(42, Action::Stat);
        let mut session = damon.exclusive_session(&original).expect("stage session");
        session.start().expect("start session");
        let mut updated = original.clone();
        updated.kdamonds[0].contexts[0].schemes[0].action = Action::PageOut;

        session
            .update_configuration(&updated)
            .expect("commit running update");

        assert_eq!(
            model
                .active_value("kdamonds/0/contexts/0/schemes/0/action")
                .as_deref(),
            Some("pageout")
        );
        assert_eq!(
            session.configuration().expect("read updated ownership"),
            updated
        );
        session.close().expect("close updated session");
    }

    #[test]
    fn running_target_removals_are_cleaned_before_consecutive_updates() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut original = transaction_config(42, Action::Stat);
        original.kdamonds[0].contexts[0]
            .targets
            .push(TargetConfig::for_pid(Pid::new(43).expect("valid pid")));
        let mut session = damon.exclusive_session(&original).expect("stage session");
        session.start().expect("start session");

        let mut remove_first = original.clone();
        remove_first.kdamonds[0].contexts[0].targets[0].obsolete = true;
        let mut stale_filter_index = remove_first.clone();
        stale_filter_index.kdamonds[0].contexts[0].schemes[0]
            .filters
            .push(FilterConfig::target(1, true, false));
        assert!(matches!(
            session.update_configuration(&stale_filter_index),
            Err(Error::InvalidConfiguration { .. })
        ));
        session
            .update_configuration(&remove_first)
            .expect("commit target removal");

        let cleaned = session
            .configuration()
            .expect("read cleaned staged hierarchy");
        assert_eq!(cleaned.kdamonds[0].contexts[0].targets.len(), 1);
        assert_eq!(
            cleaned.kdamonds[0].contexts[0].targets[0].pid,
            Some(Pid::new(43).expect("valid pid"))
        );
        assert!(!cleaned.kdamonds[0].contexts[0].targets[0].obsolete);
        assert_eq!(
            model
                .value("kdamonds/0/contexts/0/targets/nr_targets")
                .as_deref(),
            Some("1")
        );

        let mut consecutive = cleaned.clone();
        consecutive.kdamonds[0].contexts[0].schemes[0].action = Action::PageOut;
        session
            .update_configuration(&consecutive)
            .expect("commit consecutive update from cleaned state");
        assert_eq!(
            model
                .active_value("kdamonds/0/contexts/0/targets/0/pid_target")
                .as_deref(),
            Some("43")
        );

        let error = session
            .update_configuration(&remove_first)
            .expect_err("a stale obsolete marker must not target the replacement index");
        assert!(matches!(error, Error::InvalidConfiguration { .. }));
        assert_eq!(
            model
                .active_value("kdamonds/0/contexts/0/schemes/0/action")
                .as_deref(),
            Some("pageout")
        );
        session.close().expect("close updated session");
    }

    #[test]
    fn failed_obsolete_target_cleanup_restores_the_preceding_active_targets() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut original = transaction_config(42, Action::Stat);
        original.kdamonds[0].contexts[0]
            .targets
            .push(TargetConfig::for_pid(Pid::new(43).expect("valid pid")));
        let mut session = damon.exclusive_session(&original).expect("stage session");
        session.start().expect("start session");

        let mut remove_first = original.clone();
        remove_first.kdamonds[0].contexts[0].targets[0].obsolete = true;
        model.fail_next_write("kdamonds/0/contexts/0/targets/nr_targets", 5);
        let error = session
            .update_configuration(&remove_first)
            .expect_err("failed cleanup must roll back the active removal");

        assert!(matches!(error, Error::Io { .. }));
        assert_eq!(
            session.configuration().expect("read rolled-back hierarchy"),
            original
        );
        assert_eq!(
            model
                .active_value("kdamonds/0/contexts/0/targets/0/pid_target")
                .as_deref(),
            Some("42")
        );
        session.close().expect("close rolled-back session");
    }

    #[test]
    fn running_configuration_update_rolls_back_after_commit_failure() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let original = transaction_config(42, Action::Stat);
        let mut session = damon.exclusive_session(&original).expect("stage session");
        session.start().expect("start session");
        let mut updated = original.clone();
        updated.kdamonds[0].contexts[0].schemes[0].action = Action::PageOut;
        model.fail_next_write("kdamonds/0/state", 5);

        let error = session
            .update_configuration(&updated)
            .expect_err("failed commit must roll back");

        assert!(matches!(error, Error::Io { .. }));
        assert_eq!(
            model
                .active_value("kdamonds/0/contexts/0/schemes/0/action")
                .as_deref(),
            Some("stat")
        );
        assert_eq!(
            session.configuration().expect("retain original ownership"),
            original
        );
        session.close().expect("close rolled-back session");
    }

    #[test]
    fn running_update_accepts_kernel_tuned_interval_races() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut original = transaction_config(42, Action::Stat);
        original.kdamonds[0].contexts[0].intervals_goal = IntervalsGoalConfig {
            access_basis_points: 100,
            aggregation_intervals: 1,
            minimum_sample: Duration::from_millis(1),
            maximum_sample: Duration::from_millis(10),
        };
        let mut session = damon.exclusive_session(&original).expect("stage session");
        session.start().expect("start session");
        let mut updated = original.clone();
        updated.kdamonds[0].contexts[0].schemes[0].action = Action::PageOut;
        model.after_next_write(
            "kdamonds/0/contexts/0/schemes/0/action",
            b"pageout".to_vec(),
            vec![
                Mutation::SetFile {
                    path: "kdamonds/0/contexts/0/monitoring_attrs/intervals/sample_us".into(),
                    value: b"4000\n".to_vec(),
                },
                Mutation::SetFile {
                    path: "kdamonds/0/contexts/0/monitoring_attrs/intervals/aggr_us".into(),
                    value: b"80000\n".to_vec(),
                },
            ],
        );

        session
            .update_configuration(&updated)
            .expect("accept tuned read-back values");
        assert_eq!(
            model
                .active_value("kdamonds/0/contexts/0/schemes/0/action")
                .as_deref(),
            Some("pageout")
        );
        session.close().expect("close tuned session");
    }

    #[test]
    fn runtime_batch_avoids_repeated_full_fingerprint_scans() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let config = transaction_config(42, Action::Stat);
        let mut session = damon.exclusive_session(&config).expect("stage session");
        session.start().expect("start session");

        let reads = model.read_count();
        session.scheme_stats(0, 0).expect("first ordinary read");
        session.scheme_stats(0, 0).expect("second ordinary read");
        let ordinary_reads = model.read_count() - reads;

        let reads = model.read_count();
        session
            .runtime_batch(|batch| {
                batch.scheme_stats(0, 0)?;
                batch.scheme_stats(0, 0)?;
                Ok(())
            })
            .expect("batched reads");
        let batched_reads = model.read_count() - reads;

        assert!(batched_reads < ordinary_reads);
        session.close().expect("close session");
    }

    #[test]
    fn runtime_updates_work_without_the_optional_refresh_attribute() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let config = transaction_config(42, Action::Stat);
        damon
            .stage_configuration(&config)
            .expect("stage preceding configuration");
        model.remove_tree("kdamonds/0/refresh_ms");
        let mut session = damon.exclusive_session(&config).expect("stage session");
        session.start().expect("start session");
        let writes = model.write_count();

        session.scheme_stats(0, 0).expect("refresh legacy stats");

        assert_eq!(model.write_count(), writes + 1);
        session.close().expect("close session");
    }

    #[test]
    fn exclusive_session_does_not_adopt_concurrent_changes_during_pause() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut session = damon
            .exclusive_session(&transaction_config(42, Action::Stat))
            .expect("stage session");
        session.start().expect("start session");
        model.after_next_write(
            "kdamonds/0/contexts/0/pause",
            b"Y".to_vec(),
            vec![Mutation::SetFile {
                path: "kdamonds/0/contexts/0/targets/0/pid_target".into(),
                value: b"77\n".to_vec(),
            }],
        );

        let error = session
            .pause()
            .expect_err("unrelated change must not enter the ownership fingerprint");
        assert!(matches!(
            error,
            Error::Rollback {
                operation,
                rollback,
            } if matches!(*operation, Error::OwnershipLost {
                reason: "the staged writable configuration changed"
            }) && matches!(*rollback, Error::OwnershipLost {
                reason: "the staged writable configuration changed"
            })
        ));

        model.set_file("kdamonds/0/contexts/0/targets/0/pid_target", b"42\n");
        session
            .close()
            .expect("restore after repairing external change");
    }

    #[test]
    fn exclusive_session_shape_validation_precedes_locking_and_writes() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let _held_lock = SessionLock::acquire(lock.path()).expect("hold session lock");
        let writes = model.write_count();

        let error = damon
            .exclusive_session(&DamonConfig::default())
            .expect_err("empty session configuration must fail before locking");

        assert!(matches!(
            error,
            Error::InvalidConfiguration {
                field: "exclusive session kdamond count",
                ..
            }
        ));
        assert_eq!(model.write_count(), writes);
    }

    #[test]
    fn paddr_scaling_validation_precedes_locking_and_writes() {
        let model = Model::new("paddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let _held_lock = SessionLock::acquire(lock.path()).expect("hold session lock");
        let writes = model.write_count();

        let error = damon
            .paddr()
            .address_unit(AddressUnit::new(u64::MAX).expect("nonzero unit"))
            .region_units(InitialRegionConfig::new(1, 2).expect("valid raw region"))
            .start()
            .expect_err("scaled end must overflow before locking");

        assert!(matches!(
            error,
            Error::AddressConversionOverflow {
                units: 2,
                unit_bytes: u64::MAX
            }
        ));
        assert_eq!(model.write_count(), writes);
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

        kdamond.command(&KdamondCommand::Off).expect("stop fixture");
        damon.admin.set_kdamond_count(0).expect("remove fixture");
    }

    #[test]
    fn stop_detects_an_immediate_kdamond_restart() {
        let model = Model::new("vaddr\n");
        let lock = TestLock::new();
        let damon = Damon::at_with_lock(model.root(), lock.path()).expect("open model");
        let mut session = damon
            .exclusive_session(&transaction_config(42, Action::Stat))
            .expect("stage session");
        session.start().expect("start session");
        model.after_next_write(
            "kdamonds/0/state",
            b"off".to_vec(),
            vec![Mutation::StartKdamond {
                path: "kdamonds/0".into(),
            }],
        );

        let error = session
            .stop()
            .expect_err("an immediate replacement start must be detected");

        assert!(matches!(
            error,
            Error::OwnershipLost {
                reason: "the kdamond restarted while it was being stopped"
            }
        ));
        let kdamond = damon.admin.kdamond(0);
        kdamond
            .command(&KdamondCommand::Off)
            .expect("stop replacement fixture");
        session.close().expect("restore after replacement stopped");
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

        kdamond.command(&KdamondCommand::Off).expect("stop fixture");
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
        let original = transaction_config(42, Action::Stat);
        damon
            .stage_configuration(&original)
            .expect("stage external hierarchy");
        model.set_file("kdamonds/0/contexts/0/future_input", b"preserve\n");

        damon
            .capabilities()
            .expect("probe around stopped configuration");

        assert_eq!(damon.admin.kdamond_count().expect("preserve count"), 1);
        assert_eq!(
            damon
                .admin
                .configuration()
                .expect("read restored hierarchy"),
            original
        );
        assert_eq!(
            model.value("kdamonds/0/contexts/0/future_input").as_deref(),
            Some("preserve")
        );
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

    fn match_all_pattern() -> AccessPattern {
        AccessPattern::new(
            RegionSizeRange::new(0, u64::MAX).expect("valid size range"),
            AccessCountRange::new(0, u32::MAX).expect("valid access range"),
            AgeRange::new(0, u32::MAX).expect("valid age range"),
        )
    }

    fn transaction_config(pid: u32, action: Action) -> DamonConfig {
        let mut context = ContextConfig::new(Operation::VirtualAddress);
        context
            .targets
            .push(TargetConfig::for_pid(Pid::new(pid).expect("valid pid")));
        context
            .schemes
            .push(SchemeConfig::new(action, match_all_pattern()));

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
