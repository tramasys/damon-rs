//! Multi-kdamond ownership and lifecycle management.

use super::{
    ConfigurationSnapshot, DamonAdmin, DamonConfig, Error, Kdamond, KdamondCommand, KdamondState,
    MonitoringIntervals, Pid, Result, SessionLock, StagedConfiguration, StagedOwnership,
    ensure_hierarchy_stopped, restore_configuration, retry_busy, running_thread_pid,
    stage_and_verify_configuration, with_rollback,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KdamondSessionState {
    Staged,
    Running(Pid),
    UnidentifiedRunning,
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
    previous: ConfigurationSnapshot,
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
        let staged = StagedOwnership::new(staged_configuration.fingerprint, &admin, config);
        if let Err(operation) = staged.verify(&admin) {
            return Err(with_rollback(
                operation,
                restore_configuration(&admin, &staged_configuration.previous),
            ));
        }
        Ok(Self {
            admin,
            previous: staged_configuration.previous,
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
        self.staged.verify(&self.admin)?;
        match self.states[kdamond_index] {
            KdamondSessionState::Staged => {
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
            if !matches!(self.states[index], KdamondSessionState::Running(_)) {
                return Err(Error::NotRunning);
            }
        }

        self.verify_owned_state()?;
        let previous = retry_busy(|| self.admin.configuration())?;
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

        match self.stage_and_commit_running(&effective, Some(&previous), &selected) {
            Ok(staged) => {
                self.staged = staged;
                Ok(())
            }
            Err(operation) => match self.stage_and_commit_running(&previous, None, &selected) {
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
            Ok(fingerprint) => {
                self.staged = StagedOwnership::new(fingerprint, &self.admin, config);
                Ok(())
            }
            Err(operation) => match stage_and_verify_configuration(&self.admin, &previous, None) {
                Ok(fingerprint) => {
                    self.staged = StagedOwnership::new(fingerprint, &self.admin, &previous);
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
        if self.admin.kdamond_count()? != self.states.len() {
            return Err(Error::OwnershipLost {
                reason: "the staged kdamond count changed",
            });
        }
        self.verify_running_identity_without_count(kdamond_index)
    }

    fn verify_running_identity_without_count(&self, kdamond_index: usize) -> Result<()> {
        let KdamondSessionState::Running(expected) = self.states[kdamond_index] else {
            return Err(Error::NotRunning);
        };
        let current = retry_busy(|| self.kdamond(kdamond_index).pid())?.ok_or(Error::NotRunning)?;
        if current != expected {
            return Err(Error::OwnershipLost {
                reason: "the kdamond kernel-thread ID changed",
            });
        }
        Ok(())
    }

    fn verify_running_state_and_identity_without_count(&self, kdamond_index: usize) -> Result<()> {
        let KdamondSessionState::Running(expected) = self.states[kdamond_index] else {
            return Err(Error::NotRunning);
        };
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
            let staged =
                StagedOwnership::new(cleaned_snapshot.into_fingerprint(), &self.admin, &cleaned);
            staged.verify(&self.admin)?;
            return Ok(staged);
        }

        let staged = StagedOwnership::new(snapshot.into_fingerprint(), &self.admin, config);
        staged.verify(&self.admin)?;
        Ok(staged)
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

    pub(super) fn close_inner(&mut self) -> Result<()> {
        if !self.owns_hierarchy {
            return Ok(());
        }
        self.stop_all()?;
        self.staged.verify(&self.admin)?;
        if !retry_busy(|| self.previous.matches_current())? {
            restore_configuration(&self.admin, &self.previous)?;
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
        let _ = self.close_inner();
    }
}
