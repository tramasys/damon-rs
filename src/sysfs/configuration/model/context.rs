//! Monitoring context configuration and operation-specific validation.

use super::{
    AddressUnit, Error, IntervalsGoalConfig, MonitoringIntervals, Operation,
    OperationAttributesConfig, ProbeConfig, RegionBounds, Result, SampleControlConfig,
    SchemeConfig, TargetConfig, invalid, minimum_region_units, validate_address_unit_for_host,
    validate_count, validate_kernel_aligned_initial_regions, validate_scaled_initial_regions,
    validate_token,
};

/// Configuration for one DAMON monitoring context.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ContextConfig {
    /// Monitoring operations set.
    pub operation: Operation,
    /// Core-address scale factor.
    pub address_unit: AddressUnit,
    /// Pause state.
    pub paused: bool,
    /// Operation-specific attributes.
    pub operation_attributes: OperationAttributesConfig,
    /// Sampling, aggregation, and operations-update intervals.
    pub intervals: MonitoringIntervals,
    /// Automatic sampling-interval goal.
    pub intervals_goal: IntervalsGoalConfig,
    /// Adaptive monitoring-region bounds.
    pub region_bounds: RegionBounds,
    /// Monitoring-data probes.
    pub probes: Vec<ProbeConfig>,
    /// Access-sample controls.
    pub sample_control: SampleControlConfig,
    /// Monitoring targets.
    pub targets: Vec<TargetConfig>,
    /// DAMOS schemes.
    pub schemes: Vec<SchemeConfig>,
}

impl ContextConfig {
    /// Creates a context with kernel-style default intervals and region bounds.
    #[must_use]
    pub fn new(operation: Operation) -> Self {
        Self {
            operation,
            address_unit: AddressUnit::ONE,
            paused: false,
            operation_attributes: OperationAttributesConfig::default(),
            intervals: MonitoringIntervals::default(),
            intervals_goal: IntervalsGoalConfig::default(),
            region_bounds: RegionBounds::default(),
            probes: Vec::new(),
            sample_control: SampleControlConfig::default(),
            targets: Vec::new(),
            schemes: Vec::new(),
        }
    }

    /// Validates the complete context without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_token("monitoring operation", self.operation.kernel_name())?;
        validate_count("target count", self.targets.len())?;
        validate_count("scheme count", self.schemes.len())?;
        self.intervals_goal.validate_for(self.intervals)?;
        self.operation_attributes.validate()?;
        self.sample_control.validate()?;
        validate_count("monitoring probe count", self.probes.len())?;
        for probe in &self.probes {
            probe.validate()?;
        }
        for target in &self.targets {
            target.validate()?;
        }
        match self.operation {
            Operation::VirtualAddress | Operation::FixedVirtualAddress => {
                if self.address_unit != AddressUnit::ONE {
                    return invalid(
                        "address unit",
                        "only physical-address monitoring supports non-one units",
                    );
                }
            }
            Operation::PhysicalAddress => {
                validate_address_unit_for_host(self.address_unit)?;
                validate_scaled_initial_regions(&self.targets, self.address_unit)?;
            }
            Operation::Unknown(_) => {}
        }
        validate_kernel_aligned_initial_regions(
            &self.targets,
            minimum_region_units(&self.operation, self.address_unit),
        )?;
        for scheme in &self.schemes {
            scheme.validate_for(self.targets.len())?;
        }
        Ok(())
    }

    /// Validates the operation-specific invariants required before starting
    /// this context on the running kernel's current DAMON ABI.
    pub fn validate_runnable(&self) -> Result<()> {
        self.validate_runnable_for_lifecycle(false)
    }

    pub(super) fn validate_running_update(&self) -> Result<()> {
        self.validate_runnable_for_lifecycle(true)
    }

    pub(super) fn validate_runnable_for_lifecycle(
        &self,
        allow_obsolete_targets: bool,
    ) -> Result<()> {
        self.validate()?;
        if !allow_obsolete_targets && self.targets.iter().any(|target| target.obsolete) {
            return invalid(
                "obsolete target",
                "is valid only as a one-shot update to a running context",
            );
        }
        let retained_target_count = self
            .targets
            .iter()
            .filter(|target| !target.obsolete)
            .count();
        if retained_target_count == 0 {
            return invalid(
                "monitoring targets",
                "a running context requires at least one non-obsolete target",
            );
        }
        self.validate_weighted_probes()?;
        self.validate_runnable_sample_control()?;
        match self.operation {
            Operation::VirtualAddress => {
                if self
                    .targets
                    .iter()
                    .filter(|target| !target.obsolete)
                    .any(|target| target.pid.is_none())
                {
                    return invalid("virtual-address target", "requires a process identifier");
                }
            }
            Operation::FixedVirtualAddress => {
                if self
                    .targets
                    .iter()
                    .filter(|target| !target.obsolete)
                    .any(|target| target.pid.is_none())
                {
                    return invalid(
                        "fixed virtual-address target",
                        "requires a process identifier",
                    );
                }
                if self
                    .targets
                    .iter()
                    .filter(|target| !target.obsolete)
                    .any(|target| target.initial_regions.is_empty())
                {
                    return invalid(
                        "fixed virtual-address target regions",
                        "requires at least one initial region per target",
                    );
                }
            }
            Operation::PhysicalAddress => {
                if self.targets.len() != 1 || retained_target_count != 1 {
                    return invalid(
                        "physical-address targets",
                        "requires exactly one target on current DAMON kernels",
                    );
                }
                let target = &self.targets[0];
                if target.pid.is_some() {
                    return invalid(
                        "physical-address target",
                        "must not contain a process identifier",
                    );
                }
                if target.initial_regions.is_empty() {
                    return invalid(
                        "physical-address target regions",
                        "requires at least one initial region",
                    );
                }
            }
            Operation::Unknown(_) => {}
        }
        for scheme in &self.schemes {
            scheme.validate_runnable_for(&self.operation, retained_target_count)?;
        }
        Ok(())
    }

    fn validate_runnable_sample_control(&self) -> Result<()> {
        let primitives = self.sample_control.primitives;
        if primitives.page_table == primitives.page_fault {
            return invalid(
                "sample primitives",
                "exactly one of page-table and page-fault sampling must be enabled",
            );
        }
        if primitives.page_fault
            && matches!(
                self.operation,
                Operation::VirtualAddress | Operation::FixedVirtualAddress
            )
        {
            return invalid(
                "page-fault sampling",
                "is supported only for physical-address monitoring",
            );
        }
        if !self.sample_control.filters.is_empty() && !primitives.page_fault {
            return invalid(
                "sample filters",
                "require page-fault sampling to have an effect",
            );
        }
        Ok(())
    }

    fn validate_weighted_probes(&self) -> Result<()> {
        if self.probes.iter().all(|probe| probe.weight == 0) {
            return Ok(());
        }
        let sample_us = self.intervals.sample().as_micros().max(1);
        let aggregation_us = self.intervals.aggregation().as_micros();
        let maximum_hits = (aggregation_us / sample_us).clamp(1, u128::from(u32::MAX));
        if maximum_hits > u128::from(u8::MAX) {
            return invalid(
                "weighted monitoring probes",
                "samples per aggregation interval must fit an 8-bit hit count",
            );
        }
        let mut total = 0_u32;
        let maximum_hits =
            u32::try_from(maximum_hits).map_err(|_| Error::InvalidConfiguration {
                field: "weighted monitoring probes",
                reason: "samples per aggregation interval must fit u32",
            })?;
        for probe in &self.probes {
            let weighted_hits =
                probe
                    .weight
                    .checked_mul(maximum_hits)
                    .ok_or(Error::InvalidConfiguration {
                        field: "weighted monitoring probes",
                        reason: "each weight multiplied by maximum hits must fit u32",
                    })?;
            total = total
                .checked_add(weighted_hits)
                .ok_or(Error::InvalidConfiguration {
                    field: "weighted monitoring probes",
                    reason: "sum of weighted maximum hits must fit u32",
                })?;
        }
        Ok(())
    }
}
