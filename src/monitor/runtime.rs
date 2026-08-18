//! Ownership-safe runtime access to managed kdamonds.

use super::{
    Capabilities, Error, KdamondCommand, ManagedHierarchy, QuotaGoalConfig, RawSnapshot, Result,
    SchemeStats, retry_busy, with_rollback,
};

/// A borrowed ownership-safe runtime view of one managed kdamond.
///
/// Construct this through [`ManagedHierarchy::runtime`]. Every operation
/// verifies the complete staged hierarchy and the selected kernel thread at
/// its trust boundaries.
#[derive(Debug)]
pub struct ManagedKdamond<'a> {
    pub(super) hierarchy: &'a mut ManagedHierarchy,
    pub(super) index: usize,
}

impl ManagedKdamond<'_> {
    /// Returns this kdamond's index in the managed hierarchy.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Discovers capabilities for one staged context and scheme.
    pub fn capabilities(&self, context_index: usize, scheme_index: usize) -> Result<Capabilities> {
        self.hierarchy
            .capabilities(self.index, context_index, scheme_index)
    }

    /// Returns whether the selected owned kdamond is still running.
    pub fn is_running(&self) -> Result<bool> {
        self.hierarchy.is_running(self.index)
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
        self.runtime_batch(|batch| batch.scheme_stats(context_index, scheme_index))
    }

    /// Reads one scheme's last materialized runtime statistics.
    pub fn cached_scheme_stats(
        &self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<SchemeStats> {
        self.hierarchy.verify_running(self.index)?;
        let stats = self
            .hierarchy
            .scheme(self.index, context_index, scheme_index)?
            .stats()?;
        self.hierarchy.verify_running_identity(self.index)?;
        Ok(stats)
    }

    /// Materializes and reads one scheme's tried regions in raw address units.
    ///
    /// Linux may block the materialization command until every scheme reaches
    /// its next apply interval. The returned regions are scheme scoped because
    /// ordinary sysfs tried-region output contains no target identifier.
    pub fn tried_regions(
        &mut self,
        context_index: usize,
        scheme_index: usize,
        capacity_hint: usize,
    ) -> Result<RawSnapshot> {
        self.runtime_batch(|batch| batch.tried_regions(context_index, scheme_index, capacity_hint))
    }

    /// Reads one scheme's already materialized tried regions.
    pub fn cached_tried_regions(
        &self,
        context_index: usize,
        scheme_index: usize,
        capacity_hint: usize,
    ) -> Result<RawSnapshot> {
        self.hierarchy.verify_running(self.index)?;
        let snapshot = self
            .hierarchy
            .scheme(self.index, context_index, scheme_index)?
            .tried_regions(capacity_hint)?;
        self.hierarchy.verify_running_identity(self.index)?;
        Ok(snapshot)
    }

    /// Synchronously refreshes and reads total tried units.
    pub fn tried_bytes_units(&mut self, context_index: usize, scheme_index: usize) -> Result<u64> {
        self.runtime_batch(|batch| batch.tried_bytes_units(context_index, scheme_index))
    }

    /// Reads one scheme's already materialized total tried units.
    pub fn cached_tried_bytes_units(
        &self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<u64> {
        self.hierarchy.verify_running(self.index)?;
        let units = self
            .hierarchy
            .scheme(self.index, context_index, scheme_index)?
            .tried_bytes_units()?;
        self.hierarchy.verify_running_identity(self.index)?;
        Ok(units)
    }

    /// Synchronously refreshes and reads one scheme's effective quota units.
    pub fn effective_quota_units(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<u64> {
        self.runtime_batch(|batch| batch.effective_quota_units(context_index, scheme_index))
    }

    /// Reads one scheme's last materialized effective quota units.
    pub fn cached_effective_quota_units(
        &self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<u64> {
        self.hierarchy.verify_running(self.index)?;
        let units = self
            .hierarchy
            .scheme(self.index, context_index, scheme_index)?
            .quotas()
            .effective_size_units()?;
        self.hierarchy.verify_running_identity(self.index)?;
        Ok(units)
    }

    /// Transactionally replaces one scheme's quota goals and commits only
    /// quota-goal inputs to the running kdamond.
    pub fn update_scheme_quota_goals(
        &mut self,
        context_index: usize,
        scheme_index: usize,
        goals: &[QuotaGoalConfig],
    ) -> Result<()> {
        self.hierarchy
            .update_scheme_quota_goals(self.index, context_index, scheme_index, goals)
    }

    /// Runs multiple runtime reads or refreshes under one pair of complete
    /// ownership checks.
    ///
    /// Individual batch operations still verify the selected kernel thread.
    /// If both the closure and final ownership check fail, the ownership error
    /// is returned because the closure's outputs cannot be trusted.
    pub fn runtime_batch<T>(
        &mut self,
        operation: impl FnOnce(&mut RuntimeBatch<'_>) -> Result<T>,
    ) -> Result<T> {
        self.hierarchy.verify_running(self.index)?;
        let result = {
            let kdamond = self.hierarchy.kdamond(self.index);
            let mut batch = RuntimeBatch {
                hierarchy: self.hierarchy,
                kdamond_index: self.index,
                kdamond,
                context_count: None,
                cached_context: None,
            };
            operation(&mut batch)
        };
        self.hierarchy.verify_running_identity(self.index)?;
        result
    }

    /// Runs cached reads under one pair of complete ownership checks.
    pub fn read_batch<T>(
        &self,
        operation: impl FnOnce(&mut RuntimeReadBatch<'_>) -> Result<T>,
    ) -> Result<T> {
        self.hierarchy.verify_running(self.index)?;
        let result = {
            let kdamond = self.hierarchy.kdamond(self.index);
            let mut batch = RuntimeReadBatch {
                hierarchy: self.hierarchy,
                kdamond_index: self.index,
                kdamond,
                context_count: None,
                cached_context: None,
            };
            operation(&mut batch)
        };
        self.hierarchy.verify_running_identity(self.index)?;
        result
    }

    /// Synchronously refreshes auto-tuned monitoring intervals.
    #[allow(clippy::redundant_closure_for_method_calls)]
    pub fn update_tuned_intervals(&mut self) -> Result<()> {
        self.runtime_batch(|batch| batch.update_tuned_intervals())
    }

    /// Clears materialized tried-region results.
    #[allow(clippy::redundant_closure_for_method_calls)]
    pub fn clear_tried_regions(&mut self) -> Result<()> {
        self.runtime_batch(|batch| batch.clear_tried_regions())
    }

    fn set_context_paused(&mut self, context_index: usize, paused: bool) -> Result<()> {
        self.hierarchy.verify_running(self.index)?;
        let kdamond = self.hierarchy.kdamond(self.index);
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
            self.hierarchy.verify_running_identity(self.index)?;
            return Ok(());
        }
        let previous_fingerprint = self.hierarchy.staged.configuration.clone();
        let pause_path = context.path().join("pause");
        context.set_paused(paused)?;
        let operation = (|| {
            retry_busy(|| kdamond.command(&KdamondCommand::Commit))?;
            self.hierarchy.verify_running_identity_only(self.index)?;
            let observed = context.is_paused()?;
            if observed != paused {
                return Err(Error::ConfigurationMismatch {
                    path: format!("contexts/{context_index}/pause").into(),
                    expected: paused.to_string().into(),
                    observed: observed.to_string().into(),
                });
            }
            let refreshed = self.hierarchy.staged.configuration.refreshed_paths_except(
                std::slice::from_ref(&pause_path),
                &self.hierarchy.staged.volatile_paths,
            )?;
            self.hierarchy.verify_running_identity_only(self.index)?;
            self.hierarchy.staged.configuration = refreshed;
            Ok(())
        })();
        if let Err(operation) = operation {
            let rollback = (|| {
                context.set_paused(previous)?;
                retry_busy(|| kdamond.command(&KdamondCommand::Commit))?;
                let restored = previous_fingerprint.refreshed_paths_except(
                    std::slice::from_ref(&pause_path),
                    &self.hierarchy.staged.volatile_paths,
                )?;
                self.hierarchy.verify_running_identity_only(self.index)?;
                self.hierarchy.staged.configuration = restored;
                Ok(())
            })();
            return Err(with_rollback(operation, rollback));
        }
        Ok(())
    }
}

/// Runtime operations across kdamonds batched between complete ownership checks.
///
/// Construct this through [`ManagedHierarchy::runtime_batch`]. Selecting a
/// kdamond performs no sysfs scan. Each operation on the returned
/// [`RuntimeBatch`] still verifies that kdamond's kernel-thread identity.
#[derive(Debug)]
pub struct HierarchyRuntimeBatch<'a> {
    pub(super) hierarchy: &'a mut ManagedHierarchy,
}

impl HierarchyRuntimeBatch<'_> {
    /// Borrows batched runtime access to one running kdamond.
    pub fn kdamond(&mut self, kdamond_index: usize) -> Result<RuntimeBatch<'_>> {
        self.hierarchy.expected_running_pid(kdamond_index)?;
        let kdamond = self.hierarchy.kdamond(kdamond_index);
        Ok(RuntimeBatch {
            hierarchy: self.hierarchy,
            kdamond_index,
            kdamond,
            context_count: None,
            cached_context: None,
        })
    }
}

/// Cached reads across kdamonds between complete ownership checks.
#[derive(Debug)]
pub struct HierarchyReadBatch<'a> {
    pub(super) hierarchy: &'a ManagedHierarchy,
}

impl HierarchyReadBatch<'_> {
    /// Borrows batched cached access to one running kdamond.
    pub fn kdamond(&mut self, kdamond_index: usize) -> Result<RuntimeReadBatch<'_>> {
        self.hierarchy.expected_running_pid(kdamond_index)?;
        let kdamond = self.hierarchy.kdamond(kdamond_index);
        Ok(RuntimeReadBatch {
            hierarchy: self.hierarchy,
            kdamond_index,
            kdamond,
            context_count: None,
            cached_context: None,
        })
    }
}

/// Runtime operations batched between complete ownership checks.
///
/// Construct this through [`ManagedKdamond::runtime_batch`] or
/// [`crate::ExclusiveSession::runtime_batch`].
#[derive(Debug)]
pub struct RuntimeBatch<'a> {
    pub(super) hierarchy: &'a mut ManagedHierarchy,
    pub(super) kdamond_index: usize,
    kdamond: crate::sysfs::Kdamond,
    context_count: Option<usize>,
    cached_context: Option<(usize, crate::sysfs::Context, usize)>,
}

impl RuntimeBatch<'_> {
    /// Returns the selected kdamond index.
    #[must_use]
    pub const fn kdamond_index(&self) -> usize {
        self.kdamond_index
    }

    /// Synchronously refreshes and reads one scheme's statistics.
    pub fn scheme_stats(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<SchemeStats> {
        let scheme = self.scheme(context_index, scheme_index)?;
        self.issue_command(&KdamondCommand::UpdateSchemesStats)?;
        let stats = scheme.stats()?;
        self.verify_identity()?;
        Ok(stats)
    }

    /// Reads the last materialized scheme statistics.
    pub fn cached_scheme_stats(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<SchemeStats> {
        let stats = self.scheme(context_index, scheme_index)?.stats()?;
        self.verify_identity()?;
        Ok(stats)
    }

    /// Materializes and reads one scheme's tried regions.
    pub fn tried_regions(
        &mut self,
        context_index: usize,
        scheme_index: usize,
        capacity_hint: usize,
    ) -> Result<RawSnapshot> {
        let scheme = self.scheme(context_index, scheme_index)?;
        self.issue_command(&KdamondCommand::UpdateSchemesTriedRegions)?;
        let snapshot = scheme.tried_regions(capacity_hint)?;
        self.verify_identity()?;
        Ok(snapshot)
    }

    /// Reads one scheme's already materialized tried regions.
    pub fn cached_tried_regions(
        &mut self,
        context_index: usize,
        scheme_index: usize,
        capacity_hint: usize,
    ) -> Result<RawSnapshot> {
        let snapshot = self
            .scheme(context_index, scheme_index)?
            .tried_regions(capacity_hint)?;
        self.verify_identity()?;
        Ok(snapshot)
    }

    /// Synchronously refreshes and reads total tried units.
    pub fn tried_bytes_units(&mut self, context_index: usize, scheme_index: usize) -> Result<u64> {
        let scheme = self.scheme(context_index, scheme_index)?;
        self.issue_command(&KdamondCommand::UpdateSchemesTriedBytes)?;
        let units = scheme.tried_bytes_units()?;
        self.verify_identity()?;
        Ok(units)
    }

    /// Reads one scheme's already materialized total tried units.
    pub fn cached_tried_bytes_units(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<u64> {
        let units = self
            .scheme(context_index, scheme_index)?
            .tried_bytes_units()?;
        self.verify_identity()?;
        Ok(units)
    }

    /// Synchronously refreshes and reads effective quota units.
    pub fn effective_quota_units(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<u64> {
        let scheme = self.scheme(context_index, scheme_index)?;
        self.issue_command(&KdamondCommand::UpdateSchemesEffectiveQuotas)?;
        let units = scheme.quotas().effective_size_units()?;
        self.verify_identity()?;
        Ok(units)
    }

    /// Reads the last materialized effective quota units.
    pub fn cached_effective_quota_units(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<u64> {
        let units = self
            .scheme(context_index, scheme_index)?
            .quotas()
            .effective_size_units()?;
        self.verify_identity()?;
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

    fn scheme(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<crate::sysfs::Scheme> {
        cached_scheme(
            &self.kdamond,
            context_index,
            scheme_index,
            &mut self.context_count,
            &mut self.cached_context,
        )
    }

    fn command(&self, command: &KdamondCommand) -> Result<()> {
        self.issue_command(command)?;
        self.verify_identity()
    }

    fn issue_command(&self, command: &KdamondCommand) -> Result<()> {
        self.verify_identity()?;
        retry_busy(|| self.kdamond.command(command))
    }

    fn verify_identity(&self) -> Result<()> {
        self.hierarchy
            .verify_running_identity_with(self.kdamond_index, &self.kdamond)
    }
}

/// Read-only runtime operations batched between complete ownership checks.
#[derive(Debug)]
pub struct RuntimeReadBatch<'a> {
    hierarchy: &'a ManagedHierarchy,
    kdamond_index: usize,
    kdamond: crate::sysfs::Kdamond,
    context_count: Option<usize>,
    cached_context: Option<(usize, crate::sysfs::Context, usize)>,
}

impl RuntimeReadBatch<'_> {
    /// Returns the selected kdamond index.
    #[must_use]
    pub const fn kdamond_index(&self) -> usize {
        self.kdamond_index
    }

    /// Reads one scheme's last materialized statistics.
    pub fn scheme_stats(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<SchemeStats> {
        let stats = self.scheme(context_index, scheme_index)?.stats()?;
        self.verify_identity()?;
        Ok(stats)
    }

    /// Reads one scheme's already materialized tried regions.
    pub fn tried_regions(
        &mut self,
        context_index: usize,
        scheme_index: usize,
        capacity_hint: usize,
    ) -> Result<RawSnapshot> {
        let snapshot = self
            .scheme(context_index, scheme_index)?
            .tried_regions(capacity_hint)?;
        self.verify_identity()?;
        Ok(snapshot)
    }

    /// Reads one scheme's already materialized tried total in core units.
    pub fn tried_bytes_units(&mut self, context_index: usize, scheme_index: usize) -> Result<u64> {
        let units = self
            .scheme(context_index, scheme_index)?
            .tried_bytes_units()?;
        self.verify_identity()?;
        Ok(units)
    }

    /// Reads one scheme's last materialized effective quota in core units.
    pub fn effective_quota_units(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<u64> {
        let units = self
            .scheme(context_index, scheme_index)?
            .quotas()
            .effective_size_units()?;
        self.verify_identity()?;
        Ok(units)
    }

    fn scheme(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<crate::sysfs::Scheme> {
        cached_scheme(
            &self.kdamond,
            context_index,
            scheme_index,
            &mut self.context_count,
            &mut self.cached_context,
        )
    }

    fn verify_identity(&self) -> Result<()> {
        self.hierarchy
            .verify_running_identity_with(self.kdamond_index, &self.kdamond)
    }
}

fn cached_scheme(
    kdamond: &crate::sysfs::Kdamond,
    context_index: usize,
    scheme_index: usize,
    context_count: &mut Option<usize>,
    cached_context: &mut Option<(usize, crate::sysfs::Context, usize)>,
) -> Result<crate::sysfs::Scheme> {
    let count = if let Some(count) = *context_count {
        count
    } else {
        let count = kdamond.context_count()?;
        *context_count = Some(count);
        count
    };
    if context_index >= count {
        return Err(Error::IndexOutOfBounds {
            kind: "context",
            index: context_index,
            count,
        });
    }
    if cached_context
        .as_ref()
        .is_none_or(|(cached_index, _, _)| *cached_index != context_index)
    {
        let context = kdamond.context(context_index);
        let scheme_count = context.scheme_count()?;
        *cached_context = Some((context_index, context, scheme_count));
    }
    let (_, context, scheme_count) = cached_context
        .as_ref()
        .expect("the selected context was cached");
    if scheme_index >= *scheme_count {
        return Err(Error::IndexOutOfBounds {
            kind: "scheme",
            index: scheme_index,
            count: *scheme_count,
        });
    }
    Ok(context.scheme(scheme_index))
}
