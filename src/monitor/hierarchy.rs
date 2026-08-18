//! Multi-kdamond ownership and lifecycle management.

use super::{
    Capabilities, ConfigurationSnapshot, DamonAdmin, DamonConfig, Error, HierarchyReadBatch,
    HierarchyRuntimeBatch, Kdamond, KdamondCommand, KdamondState, ManagedKdamond,
    MonitoringIntervals, ObservedConfiguration, PathBuf, Pid, QuotaGoalConfig, Result, SessionLock,
    StagedConfiguration, StagedOwnership, collect_writes, ensure_hierarchy_stopped,
    restore_configuration, retry_busy, running_thread_pid, stage_and_verify_configuration,
    with_rollback,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KdamondSessionState {
    Staged,
    Running(Pid),
    UnidentifiedRunning,
}

pub(super) struct PersistentParts {
    pub(super) configuration: ConfigurationSnapshot,
    pub(super) volatile_paths: Box<[PathBuf]>,
    pub(super) kdamond_count: usize,
    pub(super) identities: Box<[(usize, Pid)]>,
}

/// A cooperatively exclusive, transactionally staged DAMON hierarchy.
///
/// The hierarchy holds the advisory session lock for its lifetime and tracks
/// each running kdamond by its kernel-thread ID. It restores the complete
/// stopped hierarchy that preceded the session when [`Self::close`] succeeds,
/// or on a best-effort basis when dropped.
///
/// Controllers that ignore the advisory lock can still race this API because
/// DAMON sysfs provides no ownership primitive.
#[derive(Debug)]
pub struct ManagedHierarchy {
    pub(super) admin: DamonAdmin,
    previous: Option<ConfigurationSnapshot>,
    pub(super) staged: StagedOwnership,
    states: Box<[KdamondSessionState]>,
    _session_lock: SessionLock,
    owns_hierarchy: bool,
}

impl ManagedHierarchy {
    pub(super) fn new(
        admin: DamonAdmin,
        staged_configuration: StagedConfiguration,
        config: &DamonConfig,
        session_lock: SessionLock,
    ) -> Result<Self> {
        let staged = StagedOwnership::new(staged_configuration.current, &admin, config);
        if let Err(operation) = staged.verify(&admin) {
            return Err(with_rollback(
                operation,
                restore_configuration(&admin, &staged_configuration.previous),
            ));
        }
        Ok(Self {
            admin,
            previous: Some(staged_configuration.previous),
            staged,
            states: vec![KdamondSessionState::Staged; config.kdamonds.len()].into_boxed_slice(),
            _session_lock: session_lock,
            owns_hierarchy: true,
        })
    }

    /// Returns the number of managed kdamonds.
    #[must_use]
    pub const fn kdamond_count(&self) -> usize {
        self.states.len()
    }

    /// Borrows an ownership-safe runtime view of one running kdamond.
    ///
    /// Constructing the view performs no sysfs access. Each operation verifies
    /// the hierarchy and selected kernel-thread identity at its trust
    /// boundaries.
    pub fn runtime(&mut self, kdamond_index: usize) -> Result<ManagedKdamond<'_>> {
        self.expected_running_pid(kdamond_index)?;
        Ok(ManagedKdamond {
            hierarchy: self,
            index: kdamond_index,
        })
    }

    /// Runs operations across managed kdamonds under one pair of complete
    /// hierarchy ownership checks.
    ///
    /// Individual operations still verify the selected kernel-thread identity
    /// at their trust boundaries. If both the closure and final ownership check
    /// fail, the ownership error is returned because the closure's outputs
    /// cannot be trusted.
    pub fn runtime_batch<T>(
        &mut self,
        operation: impl FnOnce(&mut HierarchyRuntimeBatch<'_>) -> Result<T>,
    ) -> Result<T> {
        self.verify_owned_state()?;
        let result = {
            let mut batch = HierarchyRuntimeBatch { hierarchy: self };
            operation(&mut batch)
        };
        self.verify_owned_state()?;
        result
    }

    /// Runs cached reads across kdamonds under one pair of ownership checks.
    ///
    /// Unlike [`Self::runtime_batch`], this requires only shared access and
    /// exposes no kernel commands or configuration mutations.
    pub fn read_batch<T>(
        &self,
        operation: impl FnOnce(&mut HierarchyReadBatch<'_>) -> Result<T>,
    ) -> Result<T> {
        self.verify_owned_state()?;
        let result = {
            let mut batch = HierarchyReadBatch { hierarchy: self };
            operation(&mut batch)
        };
        self.verify_owned_state()?;
        result
    }

    /// Discovers capabilities for one staged scheme.
    ///
    /// This is available before or after starting the hierarchy. The complete
    /// owned state is verified before and after capability discovery.
    pub fn capabilities(
        &self,
        kdamond_index: usize,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<Capabilities> {
        self.validate_kdamond_index(kdamond_index)?;
        self.verify_owned_state()?;
        let capabilities = retry_busy(|| {
            self.kdamond(kdamond_index)
                .capabilities(context_index, scheme_index)
        })?;
        self.verify_owned_state()?;
        Ok(capabilities)
    }

    /// Starts every staged kdamond in index order.
    ///
    /// Each kernel-thread ID is captured immediately after its start command.
    /// If a later start fails, already identified kdamonds are stopped in
    /// reverse order. A kdamond whose start succeeded but whose identity could
    /// not be captured is never stopped without proof of ownership.
    pub fn start_all(&mut self) -> Result<()> {
        if !self.owns_hierarchy {
            return Err(Error::NotRunning);
        }
        for (index, state) in self.states.iter().enumerate() {
            match state {
                KdamondSessionState::Staged => {}
                KdamondSessionState::Running(_) => {
                    return Err(Error::KdamondRunning { index });
                }
                KdamondSessionState::UnidentifiedRunning => {
                    return Err(Error::OwnershipLost {
                        reason: "the kdamond started but its identity was not captured",
                    });
                }
            }
        }

        self.staged.verify(&self.admin)?;
        for index in 0..self.states.len() {
            match retry_busy(|| self.kdamond(index).state())? {
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
        }

        for index in 0..self.states.len() {
            let ownership = self
                .staged
                .verify_count(&self.admin)
                .and_then(|()| self.staged.verify_kdamond_configuration(&self.admin, index));
            if let Err(operation) = ownership {
                return Err(with_rollback(operation, self.rollback_started()));
            }
            if let Err(operation) = self.start_one(index) {
                return Err(with_rollback(operation, self.rollback_started()));
            }
        }
        if let Err(operation) = self.verify_owned_state() {
            return Err(with_rollback(operation, self.rollback_started()));
        }
        Ok(())
    }

    /// Stops every managed kdamond whose configuration and thread identity are
    /// still owned.
    ///
    /// Ownership loss for one kdamond does not prevent stopping other owned
    /// kdamonds. The first ownership or stop error is returned after all safe
    /// stops have been attempted.
    pub fn stop_all(&mut self) -> Result<()> {
        if !self.owns_hierarchy {
            return Ok(());
        }
        self.staged.verify_count(&self.admin)?;
        let mut first_error = None;
        for index in (0..self.states.len()).rev() {
            if let Err(error) = self.staged.verify_count(&self.admin) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
                break;
            }
            if let Err(error) = self.staged.verify_kdamond_configuration(&self.admin, index) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
                continue;
            }
            if let Err(error) = self.stop_one(index) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        if first_error.is_none() {
            first_error = self.staged.verify(&self.admin).err();
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Returns whether one identified managed kdamond is still running.
    pub fn is_running(&self, kdamond_index: usize) -> Result<bool> {
        self.validate_kdamond_index(kdamond_index)?;
        match self.states[kdamond_index] {
            KdamondSessionState::Staged => {
                self.staged.verify(&self.admin)?;
                match retry_busy(|| self.kdamond(kdamond_index).state())? {
                    KdamondState::Off => Ok(false),
                    KdamondState::On => Err(Error::OwnershipLost {
                        reason: "the staged kdamond was started by another controller",
                    }),
                    KdamondState::Unknown(state) => Err(Error::UnexpectedKdamondState { state }),
                }
            }
            KdamondSessionState::Running(_) => match self.verify_running(kdamond_index) {
                Ok(()) => Ok(true),
                Err(Error::NotRunning) => Ok(false),
                Err(error) => Err(error),
            },
            KdamondSessionState::UnidentifiedRunning => Err(Error::OwnershipLost {
                reason: "the kdamond started but its identity was not captured",
            }),
        }
    }

    /// Reads the complete staged configuration after verifying ownership.
    pub fn configuration(&self) -> Result<DamonConfig> {
        self.verify_owned_state()?;
        let configuration = retry_busy(|| self.admin.configuration())?;
        self.verify_owned_state()?;
        Ok(configuration)
    }

    /// Reads the known typed hierarchy and all writable values after verifying ownership.
    pub fn observed_configuration(&self) -> Result<ObservedConfiguration> {
        self.verify_owned_state()?;
        let observation = retry_busy(|| self.admin.observed_configuration())?;
        self.verify_owned_state()?;
        Ok(observation)
    }

    /// Transactionally updates selected running kdamonds.
    ///
    /// `config` describes the complete staged hierarchy. Unselected kdamonds
    /// must match their currently staged configurations. Selected indexes are
    /// nonempty, distinct, and committed in the supplied order after one
    /// hierarchy verification. Kernel-tuned interval leaves of unselected
    /// kdamonds are preserved. On failure, the preceding staged configuration
    /// is restored and committed to every selected kdamond.
    pub fn update_configuration(
        &mut self,
        config: &DamonConfig,
        kdamond_indices: &[usize],
    ) -> Result<()> {
        config.validate_running_update()?;
        let selected =
            validate_selected_indices(kdamond_indices, self.states.len(), config.kdamonds.len())?;
        if selected.is_empty() {
            return Err(Error::InvalidConfiguration {
                field: "selected kdamond indexes",
                reason: "must contain at least one index",
            });
        }
        for &index in &selected {
            self.expected_running_pid(index)?;
        }

        self.verify_owned_state()?;
        let previous_snapshot = retry_busy(|| self.admin.configuration_snapshot())?;
        let previous = retry_busy(|| self.admin.configuration())?;
        if !retry_busy(|| previous_snapshot.matches_current_except(&self.staged.volatile_paths))? {
            return Err(Error::OwnershipLost {
                reason: "the running DAMON hierarchy changed while its rollback state was captured",
            });
        }
        self.verify_owned_state()?;
        let mut effective = config.clone();
        let mut comparable_previous = previous.clone();
        normalize_running_tuned_intervals(config, Some(&previous), &mut comparable_previous)?;
        for index in 0..self.states.len() {
            if !selected.contains(&index) {
                if !kdamond_configurations_equivalent(
                    &config.kdamonds[index],
                    &comparable_previous.kdamonds[index],
                ) {
                    return Err(Error::InvalidConfiguration {
                        field: "unselected kdamond configuration",
                        reason: "must match the currently staged configuration",
                    });
                }
                effective.kdamonds[index] = previous.kdamonds[index].clone();
            }
        }
        validate_obsolete_target_updates(&previous, &effective)?;

        let (operation, writes) = collect_writes(|| {
            self.stage_and_commit_running(&effective, Some(&previous), &selected)
        });
        match operation {
            Ok(staged) => {
                self.staged = staged;
                Ok(())
            }
            Err(operation) => match self.restore_and_commit_running(
                &previous_snapshot,
                &previous,
                &selected,
                &writes,
            ) {
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

    pub(super) fn update_scheme_quota_goals(
        &mut self,
        kdamond_index: usize,
        context_index: usize,
        scheme_index: usize,
        goals: &[QuotaGoalConfig],
    ) -> Result<()> {
        self.validate_kdamond_index(kdamond_index)?;
        crate::sysfs::SchemeQuotas::validate_goals(goals)?;
        self.expected_running_pid(kdamond_index)?;

        self.verify_owned_state()?;
        let previous_snapshot = retry_busy(|| self.admin.configuration_snapshot())?;
        let quotas = self
            .scheme(kdamond_index, context_index, scheme_index)?
            .quotas();
        let mut quota = retry_busy(|| quotas.configuration())?;
        if !retry_busy(|| previous_snapshot.matches_current_except(&self.staged.volatile_paths))? {
            return Err(Error::OwnershipLost {
                reason: "the running DAMON hierarchy changed while its rollback state was captured",
            });
        }
        self.verify_owned_state()?;
        let previous_goals = std::mem::replace(&mut quota.goals, goals.to_vec());
        quota.validate()?;
        if quota.goals == previous_goals {
            return Ok(());
        }

        let (operation, writes) = collect_writes(|| {
            self.stage_and_commit_quota_goals(
                &quotas,
                &quota.goals,
                Some(&previous_goals),
                kdamond_index,
            )
        });
        match operation {
            Ok(staged) => {
                self.staged = staged;
                Ok(())
            }
            Err(operation) => match self.restore_and_commit_quota_goals(
                &previous_snapshot,
                kdamond_index,
                &writes,
            ) {
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

    /// Stops owned kdamonds and restores the preceding stopped hierarchy.
    ///
    /// Unlike [`Drop`], this method reports stop and restoration failures.
    pub fn close(mut self) -> Result<()> {
        self.close_inner()
    }

    pub(super) fn kdamond(&self, index: usize) -> Kdamond {
        self.admin.kdamond(index)
    }

    pub(super) fn attach_persistent(
        admin: DamonAdmin,
        staged: StagedOwnership,
        identities: &[(usize, Pid)],
        session_lock: SessionLock,
    ) -> Result<Self> {
        staged.verify_complete(&admin)?;
        let mut states = vec![KdamondSessionState::Staged; staged.kdamond_count()];
        let mut previous_index = None;
        for &(index, pid) in identities {
            if index >= states.len() {
                return Err(Error::InvalidReceipt {
                    reason: "a running kdamond identity is outside the hierarchy",
                });
            }
            if previous_index.is_some_and(|previous| previous >= index) {
                return Err(Error::InvalidReceipt {
                    reason: "running kdamond identities are not distinct and ordered",
                });
            }
            states[index] = KdamondSessionState::Running(pid);
            previous_index = Some(index);
        }
        let managed = Self {
            admin,
            previous: None,
            staged,
            states: states.into_boxed_slice(),
            _session_lock: session_lock,
            owns_hierarchy: true,
        };
        managed.verify_owned_state()?;
        Ok(managed)
    }

    pub(super) fn persistent_parts(&self) -> Result<PersistentParts> {
        self.verify_owned_state()?;
        self.staged.verify_complete(&self.admin)?;
        let identities = self
            .states
            .iter()
            .enumerate()
            .filter_map(|(index, state)| match state {
                KdamondSessionState::Running(pid) => Some(Ok((index, *pid))),
                KdamondSessionState::Staged => None,
                KdamondSessionState::UnidentifiedRunning => Some(Err(Error::OwnershipLost {
                    reason: "the kdamond started but its identity was not captured",
                })),
            })
            .collect::<Result<Vec<_>>>()?
            .into_boxed_slice();
        Ok(PersistentParts {
            configuration: self.staged.configuration.clone(),
            volatile_paths: self.staged.volatile_paths.clone(),
            kdamond_count: self.states.len(),
            identities,
        })
    }

    pub(super) fn disarm_cleanup(&mut self) {
        self.previous = None;
        self.owns_hierarchy = false;
    }

    pub(super) fn scheme(
        &self,
        kdamond_index: usize,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<crate::sysfs::Scheme> {
        self.validate_kdamond_index(kdamond_index)?;
        let kdamond = self.kdamond(kdamond_index);
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

    pub(super) fn replace_staged_configuration(&mut self, config: &DamonConfig) -> Result<()> {
        config.validate_runnable()?;
        if config.kdamonds.len() != self.states.len() {
            return Err(Error::InvalidConfiguration {
                field: "managed hierarchy kdamond count",
                reason: "cannot change while the hierarchy is owned",
            });
        }
        if let Some(index) = self
            .states
            .iter()
            .position(|state| !matches!(state, KdamondSessionState::Staged))
        {
            return Err(Error::KdamondRunning { index });
        }
        self.staged.verify(&self.admin)?;
        retry_busy(|| ensure_hierarchy_stopped(&self.admin))?;
        let previous = retry_busy(|| self.admin.configuration())?;
        self.staged.verify(&self.admin)?;

        match stage_and_verify_configuration(&self.admin, config, Some(&previous)) {
            Ok(current) => {
                self.staged = StagedOwnership::new(current, &self.admin, config);
                Ok(())
            }
            Err(operation) => match stage_and_verify_configuration(&self.admin, &previous, None) {
                Ok(current) => {
                    self.staged = StagedOwnership::new(current, &self.admin, &previous);
                    Err(operation)
                }
                Err(rollback) => Err(Error::Rollback {
                    operation: Box::new(operation),
                    rollback: Box::new(rollback),
                }),
            },
        }
    }

    pub(super) fn command_after_ownership_check(
        &self,
        kdamond_index: usize,
        command: &KdamondCommand,
    ) -> Result<()> {
        self.verify_running(kdamond_index)?;
        retry_busy(|| self.kdamond(kdamond_index).command(command))
    }

    pub(super) fn verify_owned_state(&self) -> Result<()> {
        if !self.owns_hierarchy {
            return Err(Error::NotRunning);
        }
        self.staged.verify(&self.admin)?;
        for index in 0..self.states.len() {
            match self.states[index] {
                KdamondSessionState::Staged => match retry_busy(|| self.kdamond(index).state())? {
                    KdamondState::Off => {}
                    KdamondState::On => {
                        return Err(Error::OwnershipLost {
                            reason: "the staged kdamond was started by another controller",
                        });
                    }
                    KdamondState::Unknown(state) => {
                        return Err(Error::UnexpectedKdamondState { state });
                    }
                },
                KdamondSessionState::Running(_) => {
                    self.verify_running_state_and_identity_without_count(index)?;
                }
                KdamondSessionState::UnidentifiedRunning => {
                    return Err(Error::OwnershipLost {
                        reason: "the kdamond started but its identity was not captured",
                    });
                }
            }
        }
        Ok(())
    }

    pub(super) fn verify_running(&self, kdamond_index: usize) -> Result<()> {
        self.validate_kdamond_index(kdamond_index)?;
        self.staged.verify(&self.admin)?;
        self.verify_running_state_and_identity_without_count(kdamond_index)
    }

    pub(super) fn verify_running_identity(&self, kdamond_index: usize) -> Result<()> {
        self.staged.verify(&self.admin)?;
        self.verify_running_identity_only(kdamond_index)
    }

    pub(super) fn verify_running_identity_only(&self, kdamond_index: usize) -> Result<()> {
        self.validate_kdamond_index(kdamond_index)?;
        let kdamond = self.kdamond(kdamond_index);
        self.verify_running_identity_with(kdamond_index, &kdamond)
    }

    pub(super) fn verify_running_identity_with(
        &self,
        kdamond_index: usize,
        kdamond: &Kdamond,
    ) -> Result<()> {
        if self.admin.kdamond_count()? != self.states.len() {
            return Err(Error::OwnershipLost {
                reason: "the staged kdamond count changed",
            });
        }
        let expected = self.expected_running_pid(kdamond_index)?;
        let current = retry_busy(|| kdamond.pid())?.ok_or(Error::NotRunning)?;
        if current != expected {
            return Err(Error::OwnershipLost {
                reason: "the kdamond kernel-thread ID changed",
            });
        }
        Ok(())
    }

    fn verify_running_identity_without_count(&self, kdamond_index: usize) -> Result<()> {
        let expected = self.expected_running_pid(kdamond_index)?;
        let current = retry_busy(|| self.kdamond(kdamond_index).pid())?.ok_or(Error::NotRunning)?;
        if current != expected {
            return Err(Error::OwnershipLost {
                reason: "the kdamond kernel-thread ID changed",
            });
        }
        Ok(())
    }

    fn verify_running_state_and_identity_without_count(&self, kdamond_index: usize) -> Result<()> {
        let expected = self.expected_running_pid(kdamond_index)?;
        let current = running_thread_pid(&self.kdamond(kdamond_index))?;
        if current != expected {
            return Err(Error::OwnershipLost {
                reason: "the kdamond kernel-thread ID changed",
            });
        }
        Ok(())
    }

    fn start_one(&mut self, index: usize) -> Result<()> {
        let kdamond = self.kdamond(index);
        retry_busy(|| kdamond.command(&KdamondCommand::On))?;
        self.states[index] = KdamondSessionState::UnidentifiedRunning;
        let pid = running_thread_pid(&kdamond)?;
        self.states[index] = KdamondSessionState::Running(pid);
        self.verify_running_identity_only(index)?;
        self.staged.verify_kdamond_configuration(&self.admin, index)
    }

    fn stop_one(&mut self, index: usize) -> Result<()> {
        let kdamond = self.kdamond(index);
        match self.states[index] {
            KdamondSessionState::Staged => match retry_busy(|| kdamond.state())? {
                KdamondState::Off => Ok(()),
                KdamondState::On => Err(Error::OwnershipLost {
                    reason: "the staged kdamond was started by another controller",
                }),
                KdamondState::Unknown(state) => Err(Error::UnexpectedKdamondState { state }),
            },
            KdamondSessionState::Running(expected) => match retry_busy(|| kdamond.state())? {
                KdamondState::Off => {
                    self.states[index] = KdamondSessionState::Staged;
                    Ok(())
                }
                KdamondState::On => {
                    let current = retry_busy(|| kdamond.pid())?.ok_or(Error::NotRunning)?;
                    if current != expected {
                        return Err(Error::OwnershipLost {
                            reason: "the kdamond kernel-thread ID changed",
                        });
                    }
                    retry_busy(|| kdamond.command(&KdamondCommand::Off))?;
                    match retry_busy(|| kdamond.state())? {
                        KdamondState::Off => {
                            self.states[index] = KdamondSessionState::Staged;
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
                KdamondState::Unknown(state) => Err(Error::UnexpectedKdamondState { state }),
            },
            KdamondSessionState::UnidentifiedRunning => match retry_busy(|| kdamond.state())? {
                KdamondState::Off => {
                    self.states[index] = KdamondSessionState::Staged;
                    Ok(())
                }
                KdamondState::On => Err(Error::OwnershipLost {
                    reason: "cannot safely stop a kdamond before its kernel-thread ID was captured",
                }),
                KdamondState::Unknown(state) => Err(Error::UnexpectedKdamondState { state }),
            },
        }
    }

    fn rollback_started(&mut self) -> Result<()> {
        if self
            .states
            .iter()
            .all(|state| matches!(state, KdamondSessionState::Staged))
        {
            return Ok(());
        }
        self.staged.verify_count(&self.admin)?;
        let mut first_error = None;
        for index in (0..self.states.len()).rev() {
            if matches!(self.states[index], KdamondSessionState::Staged) {
                continue;
            }
            if let Err(error) = self.staged.verify_kdamond_configuration(&self.admin, index) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
                continue;
            }
            if let Err(error) = self.stop_one(index) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn stage_and_commit_running(
        &self,
        config: &DamonConfig,
        observed: Option<&DamonConfig>,
        selected: &[usize],
    ) -> Result<StagedOwnership> {
        self.verify_owned_identities_only()?;
        retry_busy(|| {
            self.verify_owned_identities_only()?;
            self.admin
                .stage_validated_configuration_from(config, observed)
        })?;
        self.verify_owned_identities_only()?;
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
        self.verify_owned_identities_only()?;
        for &index in selected {
            self.verify_running_identity_only(index)?;
            retry_busy(|| self.kdamond(index).command(&KdamondCommand::Commit))?;
            self.verify_running_identity_only(index)?;
        }

        if contains_obsolete_targets(config, selected) {
            let cleaned = without_obsolete_targets(config, selected);
            retry_busy(|| {
                self.verify_owned_identities_only()?;
                self.admin
                    .stage_validated_configuration_from(&cleaned, Some(config))
            })?;
            self.verify_owned_identities_only()?;
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
            self.verify_owned_identities_only()?;
            let staged = StagedOwnership::new(cleaned_snapshot, &self.admin, &cleaned);
            staged.verify(&self.admin)?;
            return Ok(staged);
        }

        let staged = StagedOwnership::new(snapshot, &self.admin, config);
        staged.verify(&self.admin)?;
        Ok(staged)
    }

    fn restore_and_commit_running(
        &self,
        snapshot: &ConfigurationSnapshot,
        config: &DamonConfig,
        selected: &[usize],
        writes: &[PathBuf],
    ) -> Result<StagedOwnership> {
        self.verify_owned_identities_only()?;
        if let Err(boundary) = self.verify_rollback_boundary(snapshot, writes) {
            return Err(with_rollback(
                boundary,
                self.restore_written_and_commit_running(snapshot, writes, selected),
            ));
        }
        let affected = snapshot.paths_affected_by_writes(writes);
        retry_busy(|| snapshot.restore_paths_except(&affected, &self.staged.volatile_paths))?;
        self.verify_owned_identities_only()?;
        if !retry_busy(|| snapshot.matches_current_except(&self.staged.volatile_paths))? {
            return Err(Error::OwnershipLost {
                reason: "the running DAMON hierarchy changed during rollback",
            });
        }
        for &index in selected {
            self.verify_running_identity_only(index)?;
            retry_busy(|| self.kdamond(index).command(&KdamondCommand::Commit))?;
            self.verify_running_identity_only(index)?;
        }
        let current = retry_busy(|| self.admin.configuration_snapshot())?;
        if !retry_busy(|| snapshot.matches_current_except(&self.staged.volatile_paths))? {
            return Err(Error::OwnershipLost {
                reason: "the running DAMON hierarchy changed after rollback commit",
            });
        }
        let staged = StagedOwnership::new(current, &self.admin, config);
        staged.verify(&self.admin)?;
        Ok(staged)
    }

    fn stage_and_commit_quota_goals(
        &self,
        quotas: &crate::sysfs::SchemeQuotas,
        goals: &[QuotaGoalConfig],
        observed: Option<&[QuotaGoalConfig]>,
        kdamond_index: usize,
    ) -> Result<StagedOwnership> {
        self.verify_owned_identities_only()?;
        retry_busy(|| {
            self.verify_owned_identities_only()?;
            quotas.stage_goals_from(goals, observed)
        })?;
        self.verify_owned_identities_only()?;
        let goals_root = quotas.path().join("goals");
        let unchanged_matches = if observed.is_some_and(|values| values.len() == goals.len()) {
            let mut ignored = self.staged.volatile_paths.to_vec();
            for (index, goal) in goals.iter().enumerate() {
                if observed.is_some_and(|values| &values[index] == goal) {
                    continue;
                }
                let goal_path = quotas.goal(index).path().to_path_buf();
                ignored.push(goal_path.join("target_metric"));
                ignored.push(goal_path.join("target_value"));
                ignored.push(goal_path.join("current_value"));
                if goal.node_id.is_some() {
                    ignored.push(goal_path.join("nid"));
                }
                if goal.cgroup_path.is_some() {
                    ignored.push(goal_path.join("path"));
                }
            }
            ignored.sort_unstable();
            ignored.dedup();
            self.staged.configuration.matches_current_except(&ignored)?
        } else {
            self.staged
                .configuration
                .matches_current_outside_except(&goals_root, &self.staged.volatile_paths)?
        };
        if !unchanged_matches {
            return Err(Error::OwnershipLost {
                reason: "the running DAMON hierarchy changed during quota-goal staging",
            });
        }
        let snapshot = retry_busy(|| self.admin.configuration_snapshot())?;
        let staged_goals = retry_busy(|| quotas.goal_configurations())?;
        if staged_goals != goals {
            return Err(Error::ConfigurationMismatch {
                path: "quotas/goals".into(),
                expected: format!("{goals:?}").into(),
                observed: format!("{staged_goals:?}").into(),
            });
        }
        if !retry_busy(|| snapshot.values_match_current())? {
            return Err(Error::OwnershipLost {
                reason: "the running DAMON hierarchy changed during quota-goal staging",
            });
        }
        self.verify_owned_identities_only()?;
        self.verify_running_identity_only(kdamond_index)?;
        retry_busy(|| {
            self.kdamond(kdamond_index)
                .command(&KdamondCommand::CommitSchemesQuotaGoals)
        })?;
        self.verify_running_identity_only(kdamond_index)?;

        let staged = self.staged.with_configuration(snapshot);
        staged.verify(&self.admin)?;
        Ok(staged)
    }

    fn restore_and_commit_quota_goals(
        &self,
        snapshot: &ConfigurationSnapshot,
        kdamond_index: usize,
        writes: &[PathBuf],
    ) -> Result<StagedOwnership> {
        self.verify_owned_identities_only()?;
        if let Err(boundary) = self.verify_rollback_boundary(snapshot, writes) {
            return Err(with_rollback(
                boundary,
                self.restore_written_and_commit_quota_goals(snapshot, writes, kdamond_index),
            ));
        }
        let affected = snapshot.paths_affected_by_writes(writes);
        retry_busy(|| snapshot.restore_paths_except(&affected, &self.staged.volatile_paths))?;
        self.verify_running_identity_only(kdamond_index)?;
        retry_busy(|| {
            self.kdamond(kdamond_index)
                .command(&KdamondCommand::CommitSchemesQuotaGoals)
        })?;
        self.verify_running_identity_only(kdamond_index)?;
        if !retry_busy(|| snapshot.matches_current_except(&self.staged.volatile_paths))? {
            return Err(Error::OwnershipLost {
                reason: "the running DAMON hierarchy changed after quota-goal rollback",
            });
        }
        let current = retry_busy(|| self.admin.configuration_snapshot())?;
        let staged = self.staged.with_configuration(current);
        staged.verify(&self.admin)?;
        Ok(staged)
    }

    fn restore_written_and_commit_running(
        &self,
        snapshot: &ConfigurationSnapshot,
        writes: &[PathBuf],
        selected: &[usize],
    ) -> Result<()> {
        let affected = snapshot.paths_affected_by_writes(writes);
        retry_busy(|| snapshot.restore_paths_except(&affected, &self.staged.volatile_paths))?;
        for &index in selected {
            self.verify_running_identity_only(index)?;
            retry_busy(|| self.kdamond(index).command(&KdamondCommand::Commit))?;
            self.verify_running_identity_only(index)?;
        }
        Ok(())
    }

    fn restore_written_and_commit_quota_goals(
        &self,
        snapshot: &ConfigurationSnapshot,
        writes: &[PathBuf],
        kdamond_index: usize,
    ) -> Result<()> {
        let affected = snapshot.paths_affected_by_writes(writes);
        retry_busy(|| snapshot.restore_paths_except(&affected, &self.staged.volatile_paths))?;
        self.verify_running_identity_only(kdamond_index)?;
        retry_busy(|| {
            self.kdamond(kdamond_index)
                .command(&KdamondCommand::CommitSchemesQuotaGoals)
        })?;
        self.verify_running_identity_only(kdamond_index)
    }

    fn verify_rollback_boundary(
        &self,
        snapshot: &ConfigurationSnapshot,
        writes: &[PathBuf],
    ) -> Result<()> {
        let mut allowed = snapshot.paths_affected_by_writes(writes);
        allowed.extend(self.staged.volatile_paths.iter().cloned());
        allowed.sort_unstable();
        allowed.dedup();
        if !retry_busy(|| snapshot.matches_current_except(&allowed))? {
            return Err(Error::OwnershipLost {
                reason: "an unrelated writable value changed during the transaction",
            });
        }
        Ok(())
    }

    fn verify_owned_identities_only(&self) -> Result<()> {
        if self.admin.kdamond_count()? != self.states.len() {
            return Err(Error::OwnershipLost {
                reason: "the staged kdamond count changed",
            });
        }
        for index in 0..self.states.len() {
            match self.states[index] {
                KdamondSessionState::Staged => {
                    if !matches!(
                        retry_busy(|| self.kdamond(index).state())?,
                        KdamondState::Off
                    ) {
                        return Err(Error::OwnershipLost {
                            reason: "a staged kdamond state changed",
                        });
                    }
                }
                KdamondSessionState::Running(_) => {
                    self.verify_running_identity_without_count(index)?;
                }
                KdamondSessionState::UnidentifiedRunning => {
                    return Err(Error::OwnershipLost {
                        reason: "the kdamond started but its identity was not captured",
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_kdamond_index(&self, index: usize) -> Result<()> {
        if index >= self.states.len() {
            return Err(Error::IndexOutOfBounds {
                kind: "kdamond",
                index,
                count: self.states.len(),
            });
        }
        Ok(())
    }

    pub(super) fn expected_running_pid(&self, index: usize) -> Result<Pid> {
        self.validate_kdamond_index(index)?;
        match self.states[index] {
            KdamondSessionState::Running(pid) => Ok(pid),
            KdamondSessionState::Staged => Err(Error::NotRunning),
            KdamondSessionState::UnidentifiedRunning => Err(Error::OwnershipLost {
                reason: "the kdamond started but its identity was not captured",
            }),
        }
    }

    pub(super) fn close_inner(&mut self) -> Result<()> {
        if !self.owns_hierarchy {
            return Ok(());
        }
        self.stop_all()?;
        self.staged.verify(&self.admin)?;
        let previous = self.previous.as_ref().ok_or(Error::OwnershipLost {
            reason: "the managed hierarchy has no restoration snapshot",
        })?;
        if !retry_busy(|| previous.matches_current())? {
            restore_configuration(&self.admin, previous)?;
        }
        self.owns_hierarchy = false;
        Ok(())
    }
}

fn validate_selected_indices(
    requested: &[usize],
    managed_count: usize,
    requested_count: usize,
) -> Result<Vec<usize>> {
    if requested_count != managed_count {
        return Err(Error::InvalidConfiguration {
            field: "managed hierarchy kdamond count",
            reason: "must match the owned hierarchy",
        });
    }
    let mut seen = vec![false; managed_count];
    let mut selected = Vec::with_capacity(requested.len());
    for &index in requested {
        if index >= managed_count {
            return Err(Error::IndexOutOfBounds {
                kind: "kdamond",
                index,
                count: managed_count,
            });
        }
        if seen[index] {
            return Err(Error::InvalidConfiguration {
                field: "selected kdamond indexes",
                reason: "must not contain duplicates",
            });
        }
        seen[index] = true;
        selected.push(index);
    }
    Ok(selected)
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

fn kdamond_configurations_equivalent(
    expected: &super::KdamondConfig,
    observed: &super::KdamondConfig,
) -> bool {
    DamonConfig {
        kdamonds: vec![expected.clone()],
    }
    .equivalent_after_kernel_normalization(&DamonConfig {
        kdamonds: vec![observed.clone()],
    })
}

fn contains_obsolete_targets(config: &DamonConfig, selected: &[usize]) -> bool {
    selected.iter().any(|&index| {
        config.kdamonds[index]
            .contexts
            .iter()
            .any(|context| context.targets.iter().any(|target| target.obsolete))
    })
}

fn without_obsolete_targets(config: &DamonConfig, selected: &[usize]) -> DamonConfig {
    let mut cleaned = config.clone();
    for &index in selected {
        for context in &mut cleaned.kdamonds[index].contexts {
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

impl Drop for ManagedHierarchy {
    fn drop(&mut self) {
        if self.previous.is_some() {
            let _ = self.close_inner();
        }
    }
}
