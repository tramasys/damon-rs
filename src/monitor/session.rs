//! Exclusive ownership, staging, rollback, and session lifecycle.

use super::{
    AddressUnit, Capabilities, ConfigurationSnapshot, DEFAULT_SESSION_LOCK_PATH, DamonAdmin,
    DamonConfig, Error, FvaddrSessionBuilder, Kdamond, KdamondCommand, KdamondState,
    MonitorBuilder, MonitoringIntervals, PaddrSessionBuilder, Path, PathBuf, Pid, RawSnapshot,
    Result, RuntimeBatch, SchemeStats, SessionLock, StagedConfiguration, StagedOwnership,
    VaddrSessionBuilder, WorkflowOptions, ensure_hierarchy_stopped,
    replaceable_configuration_read_error, restore_after_capability_probe, restore_configuration,
    retry_busy, running_thread_pid, stage_and_verify_configuration, stage_capability_probe,
    with_rollback,
};

/// Entry point for high-level DAMON monitoring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Damon {
    pub(super) admin: DamonAdmin,
    pub(super) lock_path: PathBuf,
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
    pub(super) admin: DamonAdmin,
    pub(super) kdamond: Kdamond,
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

    pub(super) fn capabilities_for_schemes(
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

    pub(super) fn replace_staged_configuration(&mut self, config: &DamonConfig) -> Result<()> {
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

    pub(super) fn scheme(
        &self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<crate::sysfs::Scheme> {
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

    pub(super) fn verify_running_identity_only(&self) -> Result<()> {
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

impl Drop for ExclusiveSession {
    fn drop(&mut self) {
        let _ = self.close_inner();
    }
}
