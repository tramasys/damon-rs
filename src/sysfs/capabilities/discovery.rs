//! Passive path inspection and exclusive semantic write probes.

use super::{
    Capabilities, CapabilitySupport, Context, Error, FeatureCapability, Kdamond, Operation,
    OperationCapability, Path, PathBuf, Result, Scheme, SysfsFeature, observed_attribute_paths,
    path_exists, path_is_dir, read_text, read_usize, write_bytes, write_value,
    write_value_if_present,
};

impl Kdamond {
    /// Discovers features passively in a staged context and scheme.
    ///
    /// Paths below an unstaged probe or probe filter are reported as
    /// [`CapabilitySupport::RequiresStaging`], rather than being confused with
    /// kernel-level absence. Semantic values that require a write probe are
    /// [`CapabilitySupport::Unverified`]. This method never modifies the staged
    /// hierarchy.
    pub fn capabilities(&self, context_index: usize, scheme_index: usize) -> Result<Capabilities> {
        self.capabilities_for_schemes(context_index, &[scheme_index])
    }

    pub(crate) fn capabilities_for_schemes(
        &self,
        context_index: usize,
        scheme_indices: &[usize],
    ) -> Result<Capabilities> {
        let context_count = self.context_count()?;
        if context_index >= context_count {
            return Err(Error::IndexOutOfBounds {
                kind: "context",
                index: context_index,
                count: context_count,
            });
        }
        let context = self.context(context_index);
        let scheme_count = context.scheme_count()?;
        for &scheme_index in scheme_indices {
            if scheme_index >= scheme_count {
                return Err(Error::IndexOutOfBounds {
                    kind: "scheme",
                    index: scheme_index,
                    count: scheme_count,
                });
            }
        }
        let Some((&first_scheme_index, remaining_scheme_indices)) = scheme_indices.split_first()
        else {
            return Err(Error::InvalidConfiguration {
                field: "capability scheme indexes",
                reason: "must contain at least one scheme index",
            });
        };
        let scheme = context.scheme(first_scheme_index);
        let target_count = context.target_count()?;
        let probes = context.path.join("monitoring_attrs/probes");
        let probe_filter = probes.join("0/filters/0");
        let mut features = semantic_feature_capabilities(self, &context, &scheme, target_count)?;

        features.extend(probe_feature_capabilities(
            &context,
            &probes,
            &probe_filter,
        )?);
        for &scheme_index in remaining_scheme_indices {
            let scheme = context.scheme(scheme_index);
            merge_feature_capabilities(&mut features, scheme_semantic_capabilities(&scheme)?);
            merge_feature_capabilities(&mut features, scheme_filter_capabilities(&scheme)?);
            merge_feature_capabilities(&mut features, quota_goal_capabilities(&scheme)?);
        }

        let operations = if feature_support(&features, SysfsFeature::AvailableOperations)
            == CapabilitySupport::Supported
        {
            listed_operation_capabilities(context.available_operations()?)
        } else {
            passive_operation_capabilities(context.operation()?)
        };
        let mut capabilities = Capabilities {
            operations: operations.into_boxed_slice(),
            features: features.into_boxed_slice(),
            attribute_paths: observed_attribute_paths(&self.path)?.into_boxed_slice(),
        };
        capabilities.sync_operation_features();
        Ok(capabilities)
    }

    pub(crate) fn probe_operations(
        &self,
        context_index: usize,
    ) -> Result<Vec<OperationCapability>> {
        let context = self.context(context_index);
        if let Some(operations) = context.available_operations_if_present()? {
            return Ok(listed_operation_capabilities(operations));
        }

        let original = context.operation()?;
        let mut operations = Vec::with_capacity(4);
        if matches!(original, Operation::Unknown(_)) {
            operations.push(operation_capability(
                original.clone(),
                CapabilitySupport::Unverified,
            ));
        }
        let probe_result = (|| {
            for candidate in [
                Operation::VirtualAddress,
                Operation::PhysicalAddress,
                Operation::FixedVirtualAddress,
            ] {
                match context.set_operation(&candidate) {
                    Ok(()) => {
                        let support = if context.operation()? == candidate {
                            CapabilitySupport::Unverified
                        } else {
                            CapabilitySupport::Unsupported
                        };
                        operations.push(operation_capability(candidate, support));
                    }
                    Err(error) if is_unsupported_value_write(&error) => operations.push(
                        operation_capability(candidate, CapabilitySupport::Unsupported),
                    ),
                    Err(error) => return Err(error),
                }
            }
            Ok(operations)
        })();
        let restore_result = context.set_operation(&original);
        match (probe_result, restore_result) {
            (Ok(operations), Ok(())) => Ok(operations),
            (Err(operation), Ok(())) => Err(operation),
            (Ok(_), Err(restore)) => Err(restore),
            (Err(operation), Err(rollback)) => Err(Error::Rollback {
                operation: Box::new(operation),
                rollback: Box::new(rollback),
            }),
        }
    }

    pub(crate) fn stage_optional_capability_children(
        &self,
        context_index: usize,
        target_index: usize,
        scheme_index: usize,
    ) -> Result<()> {
        let context = self.context(context_index);
        let target = context.target(target_index);
        let scheme = context.scheme(scheme_index);
        for path in [
            target.path.join("regions/nr_regions"),
            scheme.path.join("quotas/goals/nr_goals"),
            scheme.path.join("core_filters/nr_filters"),
            scheme.path.join("ops_filters/nr_filters"),
            scheme.path.join("filters/nr_filters"),
            scheme.path.join("dests/nr_dests"),
        ] {
            write_value_if_present(&path, 1_u8)?;
        }
        Ok(())
    }

    pub(crate) fn stage_optional_probe_capability_children(
        &self,
        context_index: usize,
        probe_index: usize,
    ) -> Result<()> {
        let preparations = self
            .context(context_index)
            .probe(probe_index)
            .path()
            .join("preps/nr_preps");
        write_value_if_present(&preparations, 1_u8).map(|_| ())
    }

    pub(crate) fn probe_semantic_filter_capabilities(
        &self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<Vec<FeatureCapability>> {
        let context = self.context(context_index);
        let scheme = context.scheme(scheme_index);
        let scheme_filter_counts = [
            scheme.path.join("filters/nr_filters"),
            scheme.path.join("core_filters/nr_filters"),
            scheme.path.join("ops_filters/nr_filters"),
        ];
        let mut scheme_filter_types = Vec::new();
        for path in &scheme_filter_counts {
            if path_exists(path)? {
                scheme_filter_types.push(path.with_file_name("0").join("type"));
            }
        }
        let mut capabilities = probe_accepted_values(
            &scheme_filter_types,
            &scheme_filter_counts,
            &[
                (SysfsFeature::SchemeFilterAnonymous, "anon"),
                (SysfsFeature::SchemeFilterMemoryControlGroup, "memcg"),
                (SysfsFeature::SchemeFilterAddress, "addr"),
                (SysfsFeature::SchemeFilterTarget, "target"),
                (SysfsFeature::SchemeFilterYoung, "young"),
                (SysfsFeature::SchemeFilterHugePageSize, "hugepage_size"),
                (SysfsFeature::SchemeFilterUnmapped, "unmapped"),
                (SysfsFeature::SchemeFilterActive, "active"),
            ],
        )?;

        let probe_filter_count = context
            .path
            .join("monitoring_attrs/probes/0/filters/nr_filters");
        if path_exists(&probe_filter_count)? {
            capabilities.extend(probe_accepted_values(
                &[probe_filter_count.with_file_name("0").join("type")],
                std::slice::from_ref(&probe_filter_count),
                &[
                    (SysfsFeature::ProbeTypeAnonymous, "anon"),
                    (SysfsFeature::ProbeTypeMemoryControlGroup, "memcg"),
                    (SysfsFeature::ProbeTypePageIdleUnset, "pgidle_unset"),
                    (SysfsFeature::ProbeTypePageIdleSet, "pgidle_set"),
                ],
            )?);
        }
        Ok(capabilities)
    }

    pub(crate) fn probe_semantic_value_capabilities(
        &self,
        context_index: usize,
        scheme_index: usize,
    ) -> Result<Vec<FeatureCapability>> {
        let context = self.context(context_index);
        let scheme = context.scheme(scheme_index);
        let mut capabilities = probe_accepted_values_preserving(
            &scheme.path.join("action"),
            &[
                (SysfsFeature::CollapseAction, "collapse"),
                (SysfsFeature::DamosAllocateAction, "damos_alloc"),
                (SysfsFeature::DamosFreeAction, "damos_free"),
            ],
        )?;
        capabilities.extend(probe_accepted_values_preserving(
            &scheme.path.join("quotas/goals/0/target_metric"),
            &[
                (SysfsFeature::SchemeQuotaGoalSomePsi, "some_mem_psi_us"),
                (SysfsFeature::SchemeQuotaGoalNodeMemory, "node_mem_used_bp"),
                (
                    SysfsFeature::SchemeQuotaGoalNodeMemoryControlGroup,
                    "node_memcg_used_bp",
                ),
                (SysfsFeature::SchemeQuotaGoalActiveMemory, "active_mem_bp"),
                (
                    SysfsFeature::SchemeQuotaGoalNodeEligibleMemory,
                    "node_eligible_mem_bp",
                ),
                (
                    SysfsFeature::SchemeQuotaGoalHugePageMemory,
                    "hugepage_mem_bp",
                ),
            ],
        )?);
        capabilities.extend(probe_accepted_values_preserving(
            &context
                .path
                .join("monitoring_attrs/probes/0/preps/0/prep_action"),
            &[(SysfsFeature::ProbePreparationSetPageIdle, "set_pgidle")],
        )?);
        Ok(capabilities)
    }
}
fn semantic_feature_capabilities(
    kdamond: &Kdamond,
    context: &Context,
    scheme: &Scheme,
    target_count: usize,
) -> Result<Vec<FeatureCapability>> {
    let mut capabilities = context_semantic_capabilities(kdamond, context)?;
    capabilities.extend(scheme_semantic_capabilities(scheme)?);
    capabilities.extend(target_semantic_capabilities(context, target_count)?);
    capabilities.extend(scheme_filter_capabilities(scheme)?);
    capabilities.extend(quota_goal_capabilities(scheme)?);
    capabilities.extend(probe_semantic_capabilities(context)?);
    Ok(capabilities)
}

fn context_semantic_capabilities(
    kdamond: &Kdamond,
    context: &Context,
) -> Result<Vec<FeatureCapability>> {
    let probes = context.path.join("monitoring_attrs/probes/nr_probes");
    let mut capabilities = [
        SysfsFeature::VirtualAddressOperation,
        SysfsFeature::PhysicalAddressOperation,
        SysfsFeature::FixedVirtualAddressOperation,
    ]
    .into_iter()
    .map(|feature| feature_capability(feature, CapabilitySupport::Unsupported))
    .collect::<Vec<_>>();
    capabilities.extend(path_feature_capabilities([
        (
            SysfsFeature::Schemes,
            context.path.join("schemes/nr_schemes"),
        ),
        (
            SysfsFeature::AvailableOperations,
            context.path.join("avail_operations"),
        ),
        (
            SysfsFeature::OnlineParametersCommit,
            context.path.join("avail_operations"),
        ),
        (
            SysfsFeature::PeriodicRefresh,
            kdamond.path.join("refresh_ms"),
        ),
        (SysfsFeature::AddressUnit, context.path.join("addr_unit")),
        (SysfsFeature::ContextPause, context.path.join("pause")),
        (SysfsFeature::AttributeProbeCount, probes.clone()),
        (SysfsFeature::AttributeMonitoring, probes),
        (
            SysfsFeature::MonitoringIntervalsGoal,
            context
                .path
                .join("monitoring_attrs/intervals/intervals_goal/access_bp"),
        ),
        (
            SysfsFeature::SampleControl,
            context.path.join("monitoring_attrs/sample"),
        ),
        (
            SysfsFeature::OperationAttributes,
            context.path.join("operations_attrs"),
        ),
    ])?);
    Ok(capabilities)
}

fn scheme_semantic_capabilities(scheme: &Scheme) -> Result<Vec<FeatureCapability>> {
    let path = &scheme.path;
    let quotas = path.join("quotas");
    let stats = path.join("stats");
    let tried_regions = path.join("tried_regions");
    let mut capabilities = path_feature_capabilities([
        (SysfsFeature::SchemeTimeQuota, quotas.join("ms")),
        (SysfsFeature::SchemeSizeQuota, quotas.join("bytes")),
        (
            SysfsFeature::SchemePrioritization,
            quotas.join("weights/sz_permil"),
        ),
        (
            SysfsFeature::SchemeWatermarks,
            path.join("watermarks/metric"),
        ),
        (
            SysfsFeature::SchemeSuccessfulStats,
            stats.join("nr_applied"),
        ),
        (
            SysfsFeature::SchemeQuotaExceededStats,
            stats.join("qt_exceeds"),
        ),
        (
            SysfsFeature::SchemeApplyInterval,
            path.join("apply_interval_us"),
        ),
        (
            SysfsFeature::SchemeQuotaGoals,
            quotas.join("goals/nr_goals"),
        ),
        (
            SysfsFeature::SchemeQuotaEffectiveBytes,
            quotas.join("effective_bytes"),
        ),
        (SysfsFeature::SchemeMigration, path.join("target_nid")),
        (
            SysfsFeature::SchemeDestinations,
            path.join("dests/nr_dests"),
        ),
        (
            SysfsFeature::SchemeOperationsFilterPassedBytes,
            stats.join("sz_ops_filter_passed"),
        ),
        (
            SysfsFeature::SchemeApplicationSnapshotCount,
            stats.join("nr_snapshots"),
        ),
        (
            SysfsFeature::SchemeApplicationSnapshotLimit,
            stats.join("max_nr_snapshots"),
        ),
        (
            SysfsFeature::SchemeQuotaGoalTuner,
            quotas.join("goal_tuner"),
        ),
        (
            SysfsFeature::SchemeQuotaFailureChargeRatio,
            quotas.join("fail_charge_denom"),
        ),
        (
            SysfsFeature::TriedRegionsTotalBytes,
            tried_regions.join("total_bytes"),
        ),
    ])?;
    for (feature, directory) in [
        (SysfsFeature::SchemeFilters, path.join("filters")),
        (
            SysfsFeature::SeparateSchemeFilterDirectories,
            path.join("core_filters"),
        ),
        (SysfsFeature::TriedRegions, tried_regions),
    ] {
        capabilities.push(feature_capability(
            feature,
            support_for_directory(&directory)?,
        ));
    }
    Ok(capabilities)
}

fn target_semantic_capabilities(
    context: &Context,
    target_count: usize,
) -> Result<Vec<FeatureCapability>> {
    let target = context.target(0);
    let support = |path: PathBuf| {
        if target_count == 0 {
            Ok(CapabilitySupport::RequiresStaging)
        } else {
            support_for_path(&path)
        }
    };
    Ok(vec![
        feature_capability(
            SysfsFeature::InitialRegions,
            support(target.path.join("regions/nr_regions"))?,
        ),
        feature_capability(
            SysfsFeature::ObsoleteTarget,
            support(target.path.join("obsolete_target"))?,
        ),
    ])
}

fn scheme_filter_capabilities(scheme: &Scheme) -> Result<Vec<FeatureCapability>> {
    let filters = scheme.path.join("filters");
    let core_filters = scheme.path.join("core_filters");
    let ops_filters = scheme.path.join("ops_filters");
    let support = filter_value_support(&[&filters, &core_filters, &ops_filters])?;
    let mut capabilities = [
        SysfsFeature::SchemeFilterAnonymous,
        SysfsFeature::SchemeFilterMemoryControlGroup,
        SysfsFeature::SchemeFilterAddress,
        SysfsFeature::SchemeFilterTarget,
        SysfsFeature::SchemeFilterYoung,
        SysfsFeature::SchemeFilterHugePageSize,
        SysfsFeature::SchemeFilterUnmapped,
        SysfsFeature::SchemeFilterActive,
    ]
    .into_iter()
    .map(|feature| feature_capability(feature, support))
    .collect::<Vec<_>>();
    capabilities.push(feature_capability(
        SysfsFeature::SchemeFilterAllow,
        indexed_attribute_support(&[
            (
                &ops_filters.join("nr_filters"),
                &ops_filters.join("0/allow"),
            ),
            (&ops_filters.join("nr_filters"), &ops_filters.join("0/pass")),
            (&filters.join("nr_filters"), &filters.join("0/allow")),
            (&filters.join("nr_filters"), &filters.join("0/pass")),
        ])?,
    ));
    Ok(capabilities)
}

fn quota_goal_capabilities(scheme: &Scheme) -> Result<Vec<FeatureCapability>> {
    let quotas = scheme.path.join("quotas");
    let goals = quotas.join("goals");
    let goal = goals.join("0");
    let goal_support = indexed_child_support(&goals.join("nr_goals"), &goal)?;
    let metric_support = child_attribute_support(goal_support, &goal.join("target_metric"))?;
    let semantic_metric_support = unverified_value_support(metric_support);
    let node_support = child_attribute_support(goal_support, &goal.join("nid"))?;
    let cgroup_support = child_attribute_support(goal_support, &goal.join("path"))?;
    let action_support = unverified_value_support(support_for_path(&scheme.path.join("action"))?);
    Ok(vec![
        feature_capability(SysfsFeature::SchemeQuotaGoalMetric, metric_support),
        feature_capability(
            SysfsFeature::SchemeQuotaGoalSomePsi,
            semantic_metric_support,
        ),
        feature_capability(
            SysfsFeature::SchemeQuotaGoalNodeMemory,
            combine_support(semantic_metric_support, node_support),
        ),
        feature_capability(
            SysfsFeature::SchemeQuotaGoalNodeMemoryControlGroup,
            combine_support(semantic_metric_support, cgroup_support),
        ),
        feature_capability(
            SysfsFeature::SchemeQuotaGoalActiveMemory,
            semantic_metric_support,
        ),
        feature_capability(
            SysfsFeature::SchemeQuotaGoalNodeEligibleMemory,
            combine_support(semantic_metric_support, node_support),
        ),
        feature_capability(
            SysfsFeature::SchemeQuotaGoalHugePageMemory,
            semantic_metric_support,
        ),
        feature_capability(SysfsFeature::CollapseAction, action_support),
        feature_capability(SysfsFeature::DamosAllocateAction, action_support),
        feature_capability(SysfsFeature::DamosFreeAction, action_support),
    ])
}

fn probe_semantic_capabilities(context: &Context) -> Result<Vec<FeatureCapability>> {
    let probes = context.path.join("monitoring_attrs/probes");
    let probe = probes.join("0");
    let probe_support = indexed_child_support(&probes.join("nr_probes"), &probe)?;
    let filter_support = if probe_support == CapabilitySupport::Supported {
        indexed_child_support(&probe.join("filters/nr_filters"), &probe.join("filters/0"))?
    } else {
        probe_support
    };
    let prep_support = if probe_support == CapabilitySupport::Supported {
        support_for_directory(&probe.join("preps"))?
    } else {
        probe_support
    };
    let prep_child_support = if prep_support == CapabilitySupport::Supported {
        indexed_child_support(&probe.join("preps/nr_preps"), &probe.join("preps/0"))?
    } else {
        prep_support
    };
    let filter_value_support = unverified_value_support(filter_support);
    Ok(vec![
        feature_capability(SysfsFeature::ProbeTypeAnonymous, filter_value_support),
        feature_capability(
            SysfsFeature::ProbeTypeMemoryControlGroup,
            filter_value_support,
        ),
        feature_capability(
            SysfsFeature::ProbeWeight,
            child_attribute_support(probe_support, &probe.join("weight"))?,
        ),
        feature_capability(SysfsFeature::ProbePreparations, prep_support),
        feature_capability(
            SysfsFeature::ProbePreparationSetPageIdle,
            unverified_value_support(child_attribute_support(
                prep_child_support,
                &probe.join("preps/0/prep_action"),
            )?),
        ),
        feature_capability(SysfsFeature::ProbeTypePageIdleUnset, filter_value_support),
        feature_capability(SysfsFeature::ProbeTypePageIdleSet, filter_value_support),
    ])
}

fn path_feature_capabilities(
    features: impl IntoIterator<Item = (SysfsFeature, PathBuf)>,
) -> Result<Vec<FeatureCapability>> {
    let mut capabilities = Vec::new();
    for (feature, path) in features {
        capabilities.push(feature_capability(feature, support_for_path(&path)?));
    }
    Ok(capabilities)
}

fn probe_feature_capabilities(
    context: &Context,
    probes: &Path,
    probe_filter: &Path,
) -> Result<Vec<FeatureCapability>> {
    let probe_count_support = support_for_path(&probes.join("nr_probes"))?;
    let probe_filter_count_support = match probe_count_support {
        CapabilitySupport::Unsupported => CapabilitySupport::Unsupported,
        CapabilitySupport::RequiresStaging => CapabilitySupport::RequiresStaging,
        CapabilitySupport::Unverified => CapabilitySupport::Unverified,
        CapabilitySupport::Supported if context.probe_count()? == 0 => {
            CapabilitySupport::RequiresStaging
        }
        CapabilitySupport::Supported => support_for_path(&probes.join("0/filters/nr_filters"))?,
    };
    let mut features = vec![feature_capability(
        SysfsFeature::ProbeFilterCount,
        probe_filter_count_support,
    )];

    let attribute_support = match probe_filter_count_support {
        CapabilitySupport::Unsupported => CapabilitySupport::Unsupported,
        CapabilitySupport::RequiresStaging => CapabilitySupport::RequiresStaging,
        CapabilitySupport::Unverified => CapabilitySupport::Unverified,
        CapabilitySupport::Supported if context.probe(0).filter_count()? == 0 => {
            CapabilitySupport::RequiresStaging
        }
        CapabilitySupport::Supported => CapabilitySupport::Supported,
    };
    for (feature, name) in [
        (SysfsFeature::ProbeFilterType, "type"),
        (SysfsFeature::ProbeFilterMatching, "matching"),
        (SysfsFeature::ProbeFilterAllow, "allow"),
        (SysfsFeature::ProbeFilterPath, "path"),
    ] {
        let support = if attribute_support == CapabilitySupport::Supported {
            support_for_path(&probe_filter.join(name))?
        } else {
            attribute_support
        };
        features.push(feature_capability(feature, support));
    }
    Ok(features)
}
fn is_unsupported_value_write(error: &Error) -> bool {
    const LINUX_EINVAL: i32 = 22;

    matches!(
        error,
        Error::Io { source, .. } if source.raw_os_error() == Some(LINUX_EINVAL)
    )
}

pub(super) fn operation_capability(
    operation: Operation,
    support: CapabilitySupport,
) -> OperationCapability {
    OperationCapability { operation, support }
}

fn known_operations() -> [Operation; 3] {
    [
        Operation::VirtualAddress,
        Operation::PhysicalAddress,
        Operation::FixedVirtualAddress,
    ]
}

fn listed_operation_capabilities(available: Vec<Operation>) -> Vec<OperationCapability> {
    let mut capabilities = known_operations()
        .into_iter()
        .map(|operation| {
            let support = if available.contains(&operation) {
                CapabilitySupport::Supported
            } else {
                CapabilitySupport::Unsupported
            };
            operation_capability(operation, support)
        })
        .collect::<Vec<_>>();
    capabilities.extend(
        available
            .into_iter()
            .filter(|operation| matches!(operation, Operation::Unknown(_)))
            .map(|operation| operation_capability(operation, CapabilitySupport::Supported)),
    );
    capabilities
}

fn passive_operation_capabilities(selected: Operation) -> Vec<OperationCapability> {
    let mut capabilities = known_operations()
        .into_iter()
        .map(|operation| {
            let support = if operation == selected {
                CapabilitySupport::Unverified
            } else {
                CapabilitySupport::RequiresStaging
            };
            operation_capability(operation, support)
        })
        .collect::<Vec<_>>();
    if matches!(selected, Operation::Unknown(_)) {
        capabilities.push(operation_capability(
            selected,
            CapabilitySupport::Unverified,
        ));
    }
    capabilities
}

fn probe_accepted_values(
    value_paths: &[PathBuf],
    reset_count_paths: &[PathBuf],
    candidates: &[(SysfsFeature, &str)],
) -> Result<Vec<FeatureCapability>> {
    let probe_result = (|| {
        let mut capabilities = Vec::with_capacity(candidates.len());
        for &(feature, value) in candidates {
            let mut support = CapabilitySupport::Unsupported;
            for path in value_paths {
                if !path_exists(path)? {
                    continue;
                }
                match write_bytes(path, value.as_bytes()) {
                    Ok(()) if read_text(path)?.trim() == value => {
                        support = CapabilitySupport::Supported;
                        break;
                    }
                    Ok(()) => {}
                    Err(error) if is_unsupported_value_write(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            capabilities.push(feature_capability(feature, support));
        }
        Ok(capabilities)
    })();
    let restore_result = (|| {
        for path in reset_count_paths {
            if path_exists(path)? {
                write_value(path, 1_u8)?;
            }
        }
        Ok(())
    })();
    match (probe_result, restore_result) {
        (Ok(capabilities), Ok(())) => Ok(capabilities),
        (Err(operation), Ok(())) => Err(operation),
        (Ok(_), Err(restore)) => Err(restore),
        (Err(operation), Err(rollback)) => Err(Error::Rollback {
            operation: Box::new(operation),
            rollback: Box::new(rollback),
        }),
    }
}

fn probe_accepted_values_preserving(
    path: &Path,
    candidates: &[(SysfsFeature, &str)],
) -> Result<Vec<FeatureCapability>> {
    if !path_exists(path)? {
        return Ok(candidates
            .iter()
            .map(|(feature, _)| feature_capability(*feature, CapabilitySupport::Unsupported))
            .collect());
    }
    let original = read_text(path)?;
    let probe_result = (|| {
        let mut capabilities = Vec::with_capacity(candidates.len());
        for &(feature, value) in candidates {
            let support = match write_bytes(path, value.as_bytes()) {
                Ok(()) if read_text(path)?.trim() == value => CapabilitySupport::Supported,
                Ok(()) => CapabilitySupport::Unsupported,
                Err(error) if is_unsupported_value_write(&error) => CapabilitySupport::Unsupported,
                Err(error) => return Err(error),
            };
            capabilities.push(feature_capability(feature, support));
        }
        Ok(capabilities)
    })();
    let restore_result = write_bytes(path, original.as_bytes());
    match (probe_result, restore_result) {
        (Ok(capabilities), Ok(())) => Ok(capabilities),
        (Err(operation), Ok(())) => Err(operation),
        (Ok(_), Err(restore)) => Err(restore),
        (Err(operation), Err(rollback)) => Err(Error::Rollback {
            operation: Box::new(operation),
            rollback: Box::new(rollback),
        }),
    }
}

const fn unverified_value_support(support: CapabilitySupport) -> CapabilitySupport {
    match support {
        CapabilitySupport::Supported => CapabilitySupport::Unverified,
        other => other,
    }
}

const fn combine_support(
    semantic: CapabilitySupport,
    structural: CapabilitySupport,
) -> CapabilitySupport {
    match (semantic, structural) {
        (CapabilitySupport::Unsupported, _) | (_, CapabilitySupport::Unsupported) => {
            CapabilitySupport::Unsupported
        }
        (CapabilitySupport::RequiresStaging, _) | (_, CapabilitySupport::RequiresStaging) => {
            CapabilitySupport::RequiresStaging
        }
        (CapabilitySupport::Unverified, _) | (_, CapabilitySupport::Unverified) => {
            CapabilitySupport::Unverified
        }
        (CapabilitySupport::Supported, CapabilitySupport::Supported) => {
            CapabilitySupport::Supported
        }
    }
}

fn support_for_path(path: &Path) -> Result<CapabilitySupport> {
    if path_exists(path)? {
        Ok(CapabilitySupport::Supported)
    } else {
        Ok(CapabilitySupport::Unsupported)
    }
}

fn support_for_directory(path: &Path) -> Result<CapabilitySupport> {
    if path_is_dir(path)? {
        Ok(CapabilitySupport::Supported)
    } else {
        Ok(CapabilitySupport::Unsupported)
    }
}

fn indexed_attribute_support(paths: &[(&Path, &Path)]) -> Result<CapabilitySupport> {
    let mut needs_staging = false;
    for &(count_path, attribute) in paths {
        if path_exists(attribute)? {
            return Ok(CapabilitySupport::Supported);
        }
        if path_exists(count_path)? && read_usize(count_path)? == 0 {
            needs_staging = true;
        }
    }
    if needs_staging {
        return Ok(CapabilitySupport::RequiresStaging);
    }
    Ok(CapabilitySupport::Unsupported)
}

fn indexed_child_support(count_path: &Path, child: &Path) -> Result<CapabilitySupport> {
    if !path_exists(count_path)? {
        return Ok(CapabilitySupport::Unsupported);
    }
    if read_usize(count_path)? == 0 {
        return Ok(CapabilitySupport::RequiresStaging);
    }
    support_for_directory(child)
}

fn child_attribute_support(
    child_support: CapabilitySupport,
    attribute: &Path,
) -> Result<CapabilitySupport> {
    if child_support == CapabilitySupport::Supported {
        support_for_path(attribute)
    } else {
        Ok(child_support)
    }
}

fn filter_value_support(filter_directories: &[&Path]) -> Result<CapabilitySupport> {
    let mut unstaged_child = false;
    for directory in filter_directories {
        if !path_is_dir(directory)? {
            continue;
        }
        let count_path = directory.join("nr_filters");
        if !path_exists(&count_path)? {
            continue;
        }
        if read_usize(&count_path)? == 0 {
            unstaged_child = true;
        } else if path_exists(&directory.join("0/type"))? {
            return Ok(CapabilitySupport::Unverified);
        }
    }
    if unstaged_child {
        Ok(CapabilitySupport::RequiresStaging)
    } else {
        Ok(CapabilitySupport::Unsupported)
    }
}

const fn feature_capability(
    feature: SysfsFeature,
    support: CapabilitySupport,
) -> FeatureCapability {
    FeatureCapability { feature, support }
}

pub(super) fn feature_support(
    capabilities: &[FeatureCapability],
    feature: SysfsFeature,
) -> CapabilitySupport {
    capabilities
        .iter()
        .find(|capability| capability.feature == feature)
        .map_or(CapabilitySupport::Unsupported, |capability| {
            capability.support
        })
}

pub(super) fn set_feature_support(
    capabilities: &mut [FeatureCapability],
    feature: SysfsFeature,
    support: CapabilitySupport,
) {
    if let Some(capability) = capabilities
        .iter_mut()
        .find(|capability| capability.feature == feature)
    {
        capability.support = support;
    }
}

fn merge_feature_capabilities(
    capabilities: &mut Vec<FeatureCapability>,
    additions: impl IntoIterator<Item = FeatureCapability>,
) {
    for addition in additions {
        if let Some(existing) = capabilities
            .iter_mut()
            .find(|capability| capability.feature == addition.feature)
        {
            if capability_support_rank(addition.support) > capability_support_rank(existing.support)
            {
                existing.support = addition.support;
            }
        } else {
            capabilities.push(addition);
        }
    }
}

const fn capability_support_rank(support: CapabilitySupport) -> u8 {
    match support {
        CapabilitySupport::Unsupported => 0,
        CapabilitySupport::RequiresStaging => 1,
        CapabilitySupport::Unverified => 2,
        CapabilitySupport::Supported => 3,
    }
}
