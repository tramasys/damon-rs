//! Cooperative locking, transaction snapshots, and ownership checks.

use super::{
    Capabilities, CapabilitySupport, ConfigurationFingerprint, ConfigurationSnapshot, DamonAdmin,
    DamonConfig, Duration, Error, File, Kdamond, KdamondConfig, KdamondState, OpenOptions, Path,
    PathBuf, Pid, Result, SysfsFeature, io,
};

pub(super) struct StagedConfiguration {
    pub(super) previous: ConfigurationSnapshot,
    pub(super) fingerprint: ConfigurationFingerprint,
}

pub(super) fn replaceable_configuration_read_error(error: &Error) -> bool {
    matches!(
        error,
        Error::InvalidConfiguration { .. } | Error::InvalidKernelValue { .. }
    )
}

pub(super) fn stage_and_verify_configuration(
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

pub(super) fn restore_configuration(
    admin: &DamonAdmin,
    snapshot: &ConfigurationSnapshot,
) -> Result<()> {
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

pub(super) fn ensure_hierarchy_stopped(admin: &DamonAdmin) -> Result<()> {
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

pub(super) fn stage_capability_probe(
    kdamond: &Kdamond,
) -> Result<(Capabilities, ConfigurationFingerprint)> {
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
        retry_busy(|| kdamond.stage_optional_probe_capability_children(0, 0))?;
    }

    let mut semantic_capabilities =
        retry_busy(|| kdamond.probe_semantic_filter_capabilities(0, 0))?;
    semantic_capabilities.extend(retry_busy(|| {
        kdamond.probe_semantic_value_capabilities(0, 0)
    })?);
    let mut capabilities = kdamond.capabilities(0, 0)?;
    capabilities.apply_feature_capabilities(semantic_capabilities);
    capabilities.replace_operations(retry_busy(|| kdamond.probe_operations(0))?);
    let fingerprint = kdamond.configuration_fingerprint()?;
    Ok((capabilities, fingerprint))
}

pub(super) fn restore_after_capability_probe(
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StagedOwnership {
    pub(super) configuration: ConfigurationFingerprint,
    pub(super) volatile_paths: Box<[PathBuf]>,
}

impl StagedOwnership {
    pub(super) fn new(
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

    pub(super) fn verify(&self, admin: &DamonAdmin) -> Result<()> {
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

pub(super) fn running_thread_pid(kdamond: &Kdamond) -> Result<Pid> {
    match retry_busy(|| kdamond.state())? {
        KdamondState::Off => Err(Error::NotRunning),
        KdamondState::Unknown(state) => Err(Error::UnexpectedKdamondState { state }),
        KdamondState::On => retry_busy(|| kdamond.pid())?.ok_or(Error::OwnershipLost {
            reason: "a running kdamond did not expose a kernel-thread ID",
        }),
    }
}

pub(super) fn with_rollback(operation: Error, rollback_result: Result<()>) -> Error {
    match rollback_result {
        Ok(()) => operation,
        Err(rollback) => Error::Rollback {
            operation: Box::new(operation),
            rollback: Box::new(rollback),
        },
    }
}

pub(super) fn retry_busy<T>(mut operation: impl FnMut() -> Result<T>) -> Result<T> {
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
pub(super) struct SessionLock {
    _file: File,
}

impl SessionLock {
    pub(super) fn acquire(path: &Path) -> Result<Self> {
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
