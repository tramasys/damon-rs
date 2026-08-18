//! Complete admin-hierarchy configuration and mismatch diagnostics.

use super::{
    ContextConfig, Duration, Error, Result, SchemeConfig, TargetConfig,
    canonicalize_filter_placements, exact_refresh_millis, invalid, validate_count,
};
use std::fmt;

/// Complete staged configuration of the DAMON admin hierarchy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct DamonConfig {
    /// Configured kdamond instances.
    pub kdamonds: Vec<KdamondConfig>,
}

impl DamonConfig {
    /// Validates the complete hierarchy without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_count("kdamond count", self.kdamonds.len())?;
        for kdamond in &self.kdamonds {
            kdamond.validate()?;
        }
        Ok(())
    }

    /// Validates invariants required for starting the current DAMON ABI.
    ///
    /// [`Self::validate`] intentionally permits incomplete staged hierarchies
    /// and unknown future operation values. This stricter check is used by
    /// high-level sessions that will start monitoring.
    pub fn validate_runnable(&self) -> Result<()> {
        self.validate_runnable_for_lifecycle(false)
    }

    pub(crate) fn validate_running_update(&self) -> Result<()> {
        self.validate_runnable_for_lifecycle(true)
    }

    fn validate_runnable_for_lifecycle(&self, allow_obsolete_targets: bool) -> Result<()> {
        self.validate()?;
        if self.kdamonds.is_empty() {
            return invalid("kdamond count", "requires at least one kdamond");
        }
        for kdamond in &self.kdamonds {
            if kdamond.contexts.len() != 1 {
                return invalid(
                    "kdamond context count",
                    "current DAMON requires exactly one context per running kdamond",
                );
            }
            if allow_obsolete_targets {
                kdamond.contexts[0].validate_running_update()?;
            } else {
                kdamond.contexts[0].validate_runnable()?;
            }
        }
        Ok(())
    }

    pub(crate) fn mismatch_error(&self, observed: &Self) -> Option<Error> {
        if self.equivalent_after_kernel_normalization(observed) {
            return None;
        }
        Some(
            first_damon_difference(self, observed)
                .unwrap_or_else(|| configuration_mismatch("kdamonds", self, observed)),
        )
    }

    pub(crate) fn equivalent_after_kernel_normalization(&self, observed: &Self) -> bool {
        if self == observed {
            return true;
        }
        let mut canonical = self.clone();
        for (kdamond, observed_kdamond) in canonical.kdamonds.iter_mut().zip(&observed.kdamonds) {
            for (context, observed_context) in
                kdamond.contexts.iter_mut().zip(&observed_kdamond.contexts)
            {
                for (scheme, observed_scheme) in
                    context.schemes.iter_mut().zip(&observed_context.schemes)
                {
                    scheme
                        .access_pattern
                        .normalize_kernel_width(observed_scheme.access_pattern);
                    canonicalize_filter_placements(&mut scheme.filters, &observed_scheme.filters);
                }
            }
        }
        canonical == *observed
    }
}

/// Complete staged configuration for one kdamond.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct KdamondConfig {
    /// Periodic sysfs refresh interval, or zero when disabled or unavailable.
    pub refresh_interval: Duration,
    /// Monitoring contexts.
    ///
    /// Linux 7.2 permits at most one. Staging leaves that version-specific
    /// maximum to the running kernel so a future expanded ABI is not rejected
    /// in userspace.
    pub contexts: Vec<ContextConfig>,
}

impl KdamondConfig {
    /// Validates the entire object graph without touching sysfs.
    pub fn validate(&self) -> Result<()> {
        validate_count("context count", self.contexts.len())?;
        exact_refresh_millis(self.refresh_interval)?;
        for context in &self.contexts {
            context.validate()?;
        }
        Ok(())
    }
}

fn configuration_mismatch(
    path: impl Into<Box<str>>,
    expected: &impl fmt::Debug,
    observed: &impl fmt::Debug,
) -> Error {
    Error::ConfigurationMismatch {
        path: path.into(),
        expected: format!("{expected:?}").into(),
        observed: format!("{observed:?}").into(),
    }
}

fn first_damon_difference(expected: &DamonConfig, observed: &DamonConfig) -> Option<Error> {
    if expected.kdamonds.len() != observed.kdamonds.len() {
        return Some(configuration_mismatch(
            "kdamonds/nr_kdamonds",
            &expected.kdamonds.len(),
            &observed.kdamonds.len(),
        ));
    }
    for (index, (expected, observed)) in
        expected.kdamonds.iter().zip(&observed.kdamonds).enumerate()
    {
        let base = format!("kdamonds/{index}");
        if expected.refresh_interval != observed.refresh_interval {
            return Some(configuration_mismatch(
                format!("{base}/refresh_ms"),
                &expected.refresh_interval,
                &observed.refresh_interval,
            ));
        }
        if expected.contexts.len() != observed.contexts.len() {
            return Some(configuration_mismatch(
                format!("{base}/contexts/nr_contexts"),
                &expected.contexts.len(),
                &observed.contexts.len(),
            ));
        }
        for (context_index, (expected, observed)) in
            expected.contexts.iter().zip(&observed.contexts).enumerate()
        {
            if expected != observed {
                return Some(first_context_difference(
                    &format!("{base}/contexts/{context_index}"),
                    expected,
                    observed,
                ));
            }
        }
    }
    None
}

fn first_context_difference(
    base: &str,
    expected: &ContextConfig,
    observed: &ContextConfig,
) -> Error {
    macro_rules! field {
        ($name:literal, $field:ident) => {
            if expected.$field != observed.$field {
                return configuration_mismatch(
                    format!("{base}/{}", $name),
                    &expected.$field,
                    &observed.$field,
                );
            }
        };
    }
    field!("operations", operation);
    field!("addr_unit", address_unit);
    field!("pause", paused);
    field!("operations_attrs", operation_attributes);
    field!("monitoring_attrs/intervals", intervals);
    field!("monitoring_attrs/intervals/intervals_goal", intervals_goal);
    field!("monitoring_attrs/nr_regions", region_bounds);
    field!("monitoring_attrs/sample", sample_control);
    if expected.probes.len() != observed.probes.len() {
        return configuration_mismatch(
            format!("{base}/monitoring_attrs/probes/nr_probes"),
            &expected.probes.len(),
            &observed.probes.len(),
        );
    }
    for (index, (expected, observed)) in expected.probes.iter().zip(&observed.probes).enumerate() {
        if expected != observed {
            return configuration_mismatch(
                format!("{base}/monitoring_attrs/probes/{index}"),
                expected,
                observed,
            );
        }
    }
    if expected.targets.len() != observed.targets.len() {
        return configuration_mismatch(
            format!("{base}/targets/nr_targets"),
            &expected.targets.len(),
            &observed.targets.len(),
        );
    }
    for (index, (expected, observed)) in expected.targets.iter().zip(&observed.targets).enumerate()
    {
        if expected != observed {
            return first_target_difference(&format!("{base}/targets/{index}"), expected, observed);
        }
    }
    if expected.schemes.len() != observed.schemes.len() {
        return configuration_mismatch(
            format!("{base}/schemes/nr_schemes"),
            &expected.schemes.len(),
            &observed.schemes.len(),
        );
    }
    for (index, (expected, observed)) in expected.schemes.iter().zip(&observed.schemes).enumerate()
    {
        if expected != observed {
            return first_scheme_difference(&format!("{base}/schemes/{index}"), expected, observed);
        }
    }
    configuration_mismatch(base.to_owned(), expected, observed)
}

fn first_target_difference(base: &str, expected: &TargetConfig, observed: &TargetConfig) -> Error {
    if expected.pid != observed.pid {
        return configuration_mismatch(format!("{base}/pid_target"), &expected.pid, &observed.pid);
    }
    if expected.obsolete != observed.obsolete {
        return configuration_mismatch(
            format!("{base}/obsolete_target"),
            &expected.obsolete,
            &observed.obsolete,
        );
    }
    configuration_mismatch(
        format!("{base}/regions"),
        &expected.initial_regions,
        &observed.initial_regions,
    )
}

fn first_scheme_difference(base: &str, expected: &SchemeConfig, observed: &SchemeConfig) -> Error {
    macro_rules! field {
        ($name:literal, $field:ident) => {
            if expected.$field != observed.$field {
                return configuration_mismatch(
                    format!("{base}/{}", $name),
                    &expected.$field,
                    &observed.$field,
                );
            }
        };
    }
    field!("action", action);
    field!("access_pattern", access_pattern);
    field!("apply_interval_us", apply_interval);
    field!("target_nid", target_node);
    field!("quotas", quota);
    field!("watermarks", watermarks);
    field!("filters", filters);
    field!("dests", destinations);
    field!("stats/max_nr_snapshots", application_snapshot_limit);
    configuration_mismatch(base.to_owned(), expected, observed)
}
