//! Exclusive ownership, staging, rollback, and session lifecycle.

use super::{
    AddressUnit, Capabilities, DEFAULT_SESSION_LOCK_PATH, DamonAdmin, DamonConfig, Error,
    FvaddrSessionBuilder, KdamondCommand, ManagedHierarchy, MonitorBuilder, PaddrSessionBuilder,
    Path, PathBuf, Pid, RawSnapshot, Result, RuntimeBatch, SchemeStats, SessionLock,
    StagedConfiguration, VaddrSessionBuilder, WorkflowOptions, ensure_hierarchy_stopped,
    replaceable_configuration_read_error, restore_after_capability_probe, restore_configuration,
    retry_busy, stage_and_verify_configuration, stage_capability_probe, with_rollback,
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

    /// Stages and cooperatively owns a complete runnable DAMON hierarchy.
    ///
    /// Every kdamond is initially stopped. The returned hierarchy retains the
    /// advisory lock and restores the preceding stopped configuration when
    /// explicitly closed or dropped.
    pub fn managed_hierarchy(&self, config: &DamonConfig) -> Result<ManagedHierarchy> {
        config.validate_runnable()?;
        let session_lock = SessionLock::acquire(&self.lock_path)?;
        let staged_configuration =
            self.stage_validated_configuration_locked(&session_lock, config)?;
        ManagedHierarchy::new(
            self.admin.clone(),
            staged_configuration,
            config,
            session_lock,
        )
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
        Ok(ExclusiveSession {
            managed: self.managed_hierarchy(config)?,
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
    managed: ManagedHierarchy,
}

impl ExclusiveSession {
    /// Starts the staged kdamond and records its kernel-thread identity.
    pub fn start(&mut self) -> Result<()> {
        self.managed.start_all()
    }

    /// Stops the kdamond while retaining the staged configuration and lock.
    pub fn stop(&mut self) -> Result<()> {
        self.managed.stop_all()
    }

    /// Stops the kdamond and restores the hierarchy that preceded the session.
    ///
    /// Unlike [`Drop`], this method reports restoration failures.
    pub fn close(mut self) -> Result<()> {
        self.managed.close_inner()
    }

    /// Returns whether this session's identified kdamond is still running.
    pub fn is_running(&self) -> Result<bool> {
        self.managed.is_running(0)
    }

    /// Reads the complete staged configuration after verifying ownership.
    pub fn configuration(&self) -> Result<DamonConfig> {
        self.managed.configuration()
    }

    /// Discovers capabilities for a staged context and scheme without mutation.
    pub fn capabilities(&self, context_index: usize, scheme_index: usize) -> Result<Capabilities> {
        self.verify_owned_state()?;
        let kdamond = self.managed.kdamond(0);
        let capabilities = retry_busy(|| kdamond.capabilities(context_index, scheme_index))?;
        self.verify_owned_state()?;
        Ok(capabilities)
    }

    pub(super) fn capabilities_for_schemes(
        &self,
        context_index: usize,
        scheme_indices: &[usize],
    ) -> Result<Capabilities> {
        self.verify_owned_state()?;
        let kdamond = self.managed.kdamond(0);
        let capabilities =
            retry_busy(|| kdamond.capabilities_for_schemes(context_index, scheme_indices))?;
        self.verify_owned_state()?;
        Ok(capabilities)
    }

    pub(super) fn replace_staged_configuration(&mut self, config: &DamonConfig) -> Result<()> {
        if config.kdamonds.len() != 1 {
            return Err(Error::InvalidConfiguration {
                field: "exclusive session kdamond count",
                reason: "must contain exactly one kdamond",
            });
        }
        self.managed.replace_staged_configuration(config)
    }

    /// Applies the currently staged inputs to the running kdamond.
    ///
    /// The session refuses untracked sysfs changes. Use
    /// [`Self::update_configuration`] to stage and commit a changed owned
    /// configuration while preserving rollback and ownership checks.
    pub fn commit(&mut self) -> Result<()> {
        self.command_after_ownership_check(&KdamondCommand::Commit)?;
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
        if config.kdamonds.len() != 1 {
            return Err(Error::InvalidConfiguration {
                field: "exclusive session kdamond count",
                reason: "must contain exactly one kdamond",
            });
        }
        self.managed.update_configuration(config, &[0])
    }

    /// Applies staged DAMOS quota-goal changes to the running kdamond.
    pub fn commit_scheme_quota_goals(&mut self) -> Result<()> {
        self.command_after_ownership_check(&KdamondCommand::CommitSchemesQuotaGoals)?;
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
        self.command_after_ownership_check(&KdamondCommand::UpdateSchemesStats)?;
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
        self.command_after_ownership_check(&KdamondCommand::UpdateSchemesTriedRegions)?;
        let snapshot = scheme.tried_regions(capacity_hint)?;
        self.verify_running_identity()?;
        Ok(snapshot)
    }

    /// Refreshes and reads one scheme's total tried size in core address units.
    pub fn tried_bytes_units(&mut self, context_index: usize, scheme_index: usize) -> Result<u64> {
        let scheme = self.scheme(context_index, scheme_index)?;
        self.command_after_ownership_check(&KdamondCommand::UpdateSchemesTriedBytes)?;
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
        self.command_after_ownership_check(&KdamondCommand::UpdateSchemesEffectiveQuotas)?;
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
        self.command_after_ownership_check(&KdamondCommand::UpdateTunedIntervals)?;
        self.verify_running_identity()
    }

    /// Clears all materialized tried-region results.
    pub fn clear_tried_regions(&mut self) -> Result<()> {
        self.command_after_ownership_check(&KdamondCommand::ClearSchemesTriedRegions)?;
        self.verify_running_identity()
    }

    fn set_context_paused(&mut self, context_index: usize, paused: bool) -> Result<()> {
        self.verify_running()?;
        let kdamond = self.managed.kdamond(0);
        let context_count = kdamond.context_count()?;
        if context_index >= context_count {
            return Err(Error::IndexOutOfBounds {
                kind: "context",
                index: context_index,
                count: context_count,
            });
        }
        let context = kdamond.context(context_index);
        if !context.pause_control_available()? {
            return Err(Error::UnsupportedFeature {
                feature: "DAMON context pause",
            });
        }
        let previous = context.is_paused()?;
        if previous == paused {
            return Ok(());
        }
        let previous_fingerprint = self.managed.staged.configuration.clone();
        let pause_path = context.path().join("pause");
        context.set_paused(paused)?;
        let operation = (|| {
            retry_busy(|| kdamond.command(&KdamondCommand::Commit))?;
            self.verify_running_identity_only()?;
            let observed = context.is_paused()?;
            if observed != paused {
                return Err(Error::ConfigurationMismatch {
                    path: format!("contexts/{context_index}/pause").into(),
                    expected: paused.to_string().into(),
                    observed: observed.to_string().into(),
                });
            }
            let refreshed = self.managed.staged.configuration.refreshed_paths_except(
                std::slice::from_ref(&pause_path),
                &self.managed.staged.volatile_paths,
            )?;
            self.verify_running_identity_only()?;
            self.managed.staged.configuration = refreshed;
            Ok(())
        })();
        if let Err(operation) = operation {
            let rollback = (|| {
                context.set_paused(previous)?;
                retry_busy(|| kdamond.command(&KdamondCommand::Commit))?;
                let restored = previous_fingerprint.refreshed_paths_except(
                    std::slice::from_ref(&pause_path),
                    &self.managed.staged.volatile_paths,
                )?;
                self.verify_running_identity_only()?;
                self.managed.staged.configuration = restored;
                Ok(())
            })();
            return Err(with_rollback(operation, rollback));
        }
        Ok(())
    }

    fn command_after_ownership_check(&self, command: &KdamondCommand) -> Result<()> {
        self.managed.command_after_ownership_check(0, command)
    }

    pub(super) fn scheme(
        &self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<crate::sysfs::Scheme> {
        let kdamond = self.managed.kdamond(0);
        let context_count = kdamond.context_count()?;
        if context_index >= context_count {
            return Err(Error::IndexOutOfBounds {
                kind: "context",
                index: context_index,
                count: context_count,
            });
        }
        let context = kdamond.context(context_index);
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

    pub(super) fn kdamond(&self) -> crate::sysfs::Kdamond {
        self.managed.kdamond(0)
    }

    fn verify_owned_state(&self) -> Result<()> {
        self.managed.verify_owned_state()
    }

    fn verify_running(&self) -> Result<()> {
        self.managed.verify_running(0)
    }

    fn verify_running_identity(&self) -> Result<()> {
        self.managed.verify_running_identity(0)
    }

    pub(super) fn verify_running_identity_only(&self) -> Result<()> {
        self.managed.verify_running_identity_only(0)
    }
}
