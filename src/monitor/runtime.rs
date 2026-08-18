//! Runtime commands batched between ownership checks.

use super::{ExclusiveSession, KdamondCommand, RawSnapshot, Result, SchemeStats, retry_busy};

/// Runtime operations batched between complete ownership checks.
///
/// Construct this through [`ExclusiveSession::runtime_batch`].
#[derive(Debug)]
pub struct RuntimeBatch<'a> {
    pub(super) session: &'a mut ExclusiveSession,
}

impl RuntimeBatch<'_> {
    /// Synchronously refreshes and reads one scheme's statistics.
    pub fn scheme_stats(
        &mut self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<SchemeStats> {
        let scheme = self.session.scheme(context_index, scheme_index)?;
        self.issue_command(&KdamondCommand::UpdateSchemesStats)?;
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
        self.issue_command(&KdamondCommand::UpdateSchemesTriedRegions)?;
        let snapshot = scheme.tried_regions(capacity_hint)?;
        self.session.verify_running_identity_only()?;
        Ok(snapshot)
    }

    /// Synchronously refreshes and reads total tried units.
    pub fn tried_bytes_units(&mut self, context_index: usize, scheme_index: usize) -> Result<u64> {
        let scheme = self.session.scheme(context_index, scheme_index)?;
        self.issue_command(&KdamondCommand::UpdateSchemesTriedBytes)?;
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
        self.issue_command(&KdamondCommand::UpdateSchemesEffectiveQuotas)?;
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
        self.issue_command(command)?;
        self.session.verify_running_identity_only()
    }

    fn issue_command(&self, command: &KdamondCommand) -> Result<()> {
        self.session.verify_running_identity_only()?;
        retry_busy(|| self.session.kdamond().command(command))
    }
}
