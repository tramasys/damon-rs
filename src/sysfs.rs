//! Typed, low-level access to DAMON's admin sysfs ABI.
//!
//! This module intentionally mirrors the kernel hierarchy. Methods perform one
//! or a small fixed number of sysfs operations and do not cache kernel state.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::config::{MonitoringIntervals, Pid, RegionBounds};
use crate::error::io_error;
use crate::{Error, Region, Result, Snapshot};

/// Default location of DAMON's privileged admin interface.
pub const DEFAULT_ADMIN_PATH: &str = "/sys/kernel/mm/damon/admin";

/// A DAMON monitoring operations set.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Operation {
    /// Process virtual-address monitoring (`vaddr`).
    VirtualAddress,
    /// Fixed virtual-address-range monitoring (`fvaddr`).
    FixedVirtualAddress,
    /// Physical-address monitoring (`paddr`).
    PhysicalAddress,
    /// An operation introduced by a newer kernel.
    Unknown(Box<str>),
}

impl Operation {
    /// Returns the name used by the kernel ABI.
    #[must_use]
    pub fn kernel_name(&self) -> &str {
        match self {
            Self::VirtualAddress => "vaddr",
            Self::FixedVirtualAddress => "fvaddr",
            Self::PhysicalAddress => "paddr",
            Self::Unknown(name) => name,
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "vaddr" => Self::VirtualAddress,
            "fvaddr" => Self::FixedVirtualAddress,
            "paddr" => Self::PhysicalAddress,
            other => Self::Unknown(other.into()),
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kernel_name())
    }
}

/// A command accepted by a `kdamonds/<N>/state` file in Linux 7.2.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum KdamondCommand {
    /// Start the kernel monitoring thread.
    On,
    /// Stop the kernel monitoring thread.
    Off,
    /// Apply staged input changes to a running context.
    Commit,
    /// Apply staged DAMOS quota goals.
    CommitSchemesQuotaGoals,
    /// Refresh DAMOS statistics files.
    UpdateSchemesStats,
    /// Refresh only total tried bytes.
    UpdateSchemesTriedBytes,
    /// Materialize tried-region query results.
    UpdateSchemesTriedRegions,
    /// Remove materialized tried-region query results.
    ClearSchemesTriedRegions,
    /// Refresh effective DAMOS quotas.
    UpdateSchemesEffectiveQuotas,
    /// Refresh auto-tuned monitoring intervals.
    UpdateTunedIntervals,
}

impl KdamondCommand {
    /// Returns the command string used by the kernel ABI.
    #[must_use]
    pub const fn kernel_name(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Commit => "commit",
            Self::CommitSchemesQuotaGoals => "commit_schemes_quota_goals",
            Self::UpdateSchemesStats => "update_schemes_stats",
            Self::UpdateSchemesTriedBytes => "update_schemes_tried_bytes",
            Self::UpdateSchemesTriedRegions => "update_schemes_tried_regions",
            Self::ClearSchemesTriedRegions => "clear_schemes_tried_regions",
            Self::UpdateSchemesEffectiveQuotas => "update_schemes_effective_quotas",
            Self::UpdateTunedIntervals => "update_tuned_intervals",
        }
    }
}

/// Current state reported by a kdamond.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KdamondState {
    /// The monitoring thread is running.
    On,
    /// The monitoring thread is stopped.
    Off,
    /// A state introduced by a newer kernel.
    Unknown(Box<str>),
}

/// A DAMOS action supported by Linux 7.2.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Action {
    /// Mark matching memory as likely to be needed.
    WillNeed,
    /// Mark matching memory as cold.
    Cold,
    /// Reclaim matching memory.
    PageOut,
    /// Advise use of huge pages.
    HugePage,
    /// Advise against use of huge pages.
    NoHugePage,
    /// Collapse matching memory into huge pages.
    Collapse,
    /// Prioritize matching memory on the LRU.
    LruPrioritize,
    /// Deprioritize matching memory on the LRU.
    LruDeprioritize,
    /// Migrate hot memory.
    MigrateHot,
    /// Migrate cold memory.
    MigrateCold,
    /// Collect statistics without modifying memory.
    Stat,
}

impl Action {
    /// Returns the name used by the kernel ABI.
    #[must_use]
    pub const fn kernel_name(self) -> &'static str {
        match self {
            Self::WillNeed => "willneed",
            Self::Cold => "cold",
            Self::PageOut => "pageout",
            Self::HugePage => "hugepage",
            Self::NoHugePage => "nohugepage",
            Self::Collapse => "collapse",
            Self::LruPrioritize => "lru_prio",
            Self::LruDeprioritize => "lru_deprio",
            Self::MigrateHot => "migrate_hot",
            Self::MigrateCold => "migrate_cold",
            Self::Stat => "stat",
        }
    }
}

/// Runtime capabilities discovered from a populated DAMON context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capabilities {
    operations: Box<[Operation]>,
    refresh_ms: bool,
    pause: bool,
    address_unit: bool,
    probes: bool,
    apply_interval: bool,
    tried_regions: bool,
}

impl Capabilities {
    /// Returns the kernel's available monitoring operations.
    #[must_use]
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    /// Returns whether an operation is available.
    #[must_use]
    pub fn supports(&self, operation: &Operation) -> bool {
        self.operations
            .iter()
            .any(|candidate| candidate == operation)
    }

    /// Returns whether periodic sysfs refresh is exposed.
    #[must_use]
    pub const fn has_periodic_refresh(&self) -> bool {
        self.refresh_ms
    }

    /// Returns whether context pause control is exposed.
    #[must_use]
    pub const fn has_pause(&self) -> bool {
        self.pause
    }

    /// Returns whether configurable address units are exposed.
    #[must_use]
    pub const fn has_address_unit(&self) -> bool {
        self.address_unit
    }

    /// Returns whether data-attribute probes are exposed.
    #[must_use]
    pub const fn has_probes(&self) -> bool {
        self.probes
    }

    /// Returns whether per-scheme apply intervals are exposed.
    #[must_use]
    pub const fn has_apply_interval(&self) -> bool {
        self.apply_interval
    }

    /// Returns whether DAMOS tried-region queries are exposed.
    #[must_use]
    pub const fn has_tried_regions(&self) -> bool {
        self.tried_regions
    }
}

/// The root of the DAMON admin sysfs hierarchy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DamonAdmin {
    root: PathBuf,
}

impl DamonAdmin {
    /// Opens and validates a DAMON admin sysfs hierarchy.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let root = path.as_ref().to_path_buf();
        let count_path = root.join("kdamonds/nr_kdamonds");
        let exists = count_path
            .try_exists()
            .map_err(|error| io_error("inspect", &count_path, error))?;
        if !exists {
            return Err(Error::Unavailable { path: root });
        }

        let admin = Self { root };
        admin.kdamond_count()?;
        Ok(admin)
    }

    /// Opens the conventional Linux DAMON admin path.
    pub fn open_default() -> Result<Self> {
        Self::open(DEFAULT_ADMIN_PATH)
    }

    /// Returns the admin hierarchy root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Reads the number of staged kdamond directories.
    pub fn kdamond_count(&self) -> Result<usize> {
        read_usize(&self.root.join("kdamonds/nr_kdamonds"))
    }

    /// Reconstructs the staged kdamond directories.
    ///
    /// This is a global kernel interface. Reducing the count can remove
    /// another program's configuration; callers must coordinate ownership.
    pub fn set_kdamond_count(&self, count: usize) -> Result<()> {
        write_value(&self.root.join("kdamonds/nr_kdamonds"), count)
    }

    /// Returns a typed handle for a staged kdamond directory.
    #[must_use]
    pub fn kdamond(&self, index: usize) -> Kdamond {
        Kdamond {
            path: self.root.join("kdamonds").join(index.to_string()),
        }
    }
}

/// A `kdamonds/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kdamond {
    path: PathBuf,
}

impl Kdamond {
    /// Returns this kdamond's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the kernel thread's state.
    pub fn state(&self) -> Result<KdamondState> {
        let path = self.path.join("state");
        let value = read_text(&path)?;
        Ok(match value.trim() {
            "on" => KdamondState::On,
            "off" => KdamondState::Off,
            other => KdamondState::Unknown(other.into()),
        })
    }

    /// Sends a command to this kdamond.
    pub fn command(&self, command: KdamondCommand) -> Result<()> {
        write_bytes(&self.path.join("state"), command.kernel_name().as_bytes())
    }

    /// Reads the number of staged monitoring contexts.
    pub fn context_count(&self) -> Result<usize> {
        read_usize(&self.path.join("contexts/nr_contexts"))
    }

    /// Reconstructs the staged monitoring context directories.
    pub fn set_context_count(&self, count: usize) -> Result<()> {
        write_value(&self.path.join("contexts/nr_contexts"), count)
    }

    /// Returns a typed handle for a staged monitoring context.
    #[must_use]
    pub fn context(&self, index: usize) -> Context {
        Context {
            path: self.path.join("contexts").join(index.to_string()),
        }
    }

    /// Discovers features from an already populated context and scheme.
    pub fn capabilities(&self, context_index: usize, scheme_index: usize) -> Result<Capabilities> {
        let context = self.context(context_index);
        let scheme = context.scheme(scheme_index);
        Ok(Capabilities {
            operations: context.available_operations()?.into_boxed_slice(),
            refresh_ms: path_exists(&self.path.join("refresh_ms"))?,
            pause: path_exists(&context.path.join("pause"))?,
            address_unit: path_exists(&context.path.join("addr_unit"))?,
            probes: path_exists(&context.path.join("monitoring_attrs/probes/nr_probes"))?,
            apply_interval: path_exists(&scheme.path.join("apply_interval_us"))?,
            tried_regions: path_exists(&scheme.path.join("tried_regions/total_bytes"))?,
        })
    }
}

/// A `contexts/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    path: PathBuf,
}

impl Context {
    /// Returns this context's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads all monitoring operations registered by the running kernel.
    pub fn available_operations(&self) -> Result<Vec<Operation>> {
        let value = read_text(&self.path.join("avail_operations"))?;
        Ok(value
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(Operation::parse)
            .collect())
    }

    /// Selects a monitoring operation.
    pub fn set_operation(&self, operation: &Operation) -> Result<()> {
        write_bytes(
            &self.path.join("operations"),
            operation.kernel_name().as_bytes(),
        )
    }

    /// Writes the monitoring intervals.
    pub fn set_intervals(&self, intervals: MonitoringIntervals) -> Result<()> {
        let path = self.path.join("monitoring_attrs/intervals");
        let (sample_us, aggregation_us, update_us) = intervals.as_micros();
        write_value(&path.join("sample_us"), sample_us)?;
        write_value(&path.join("aggr_us"), aggregation_us)?;
        write_value(&path.join("update_us"), update_us)
    }

    /// Writes the adaptive monitoring-region count bounds.
    pub fn set_region_bounds(&self, bounds: RegionBounds) -> Result<()> {
        let path = self.path.join("monitoring_attrs/nr_regions");
        write_value(&path.join("min"), bounds.min())?;
        write_value(&path.join("max"), bounds.max())
    }

    /// Reads the number of staged targets.
    pub fn target_count(&self) -> Result<usize> {
        read_usize(&self.path.join("targets/nr_targets"))
    }

    /// Reconstructs the staged target directories.
    pub fn set_target_count(&self, count: usize) -> Result<()> {
        write_value(&self.path.join("targets/nr_targets"), count)
    }

    /// Returns a typed handle for a staged target.
    #[must_use]
    pub fn target(&self, index: usize) -> Target {
        Target {
            path: self.path.join("targets").join(index.to_string()),
        }
    }

    /// Reads the number of staged DAMOS schemes.
    pub fn scheme_count(&self) -> Result<usize> {
        read_usize(&self.path.join("schemes/nr_schemes"))
    }

    /// Reconstructs the staged DAMOS scheme directories.
    pub fn set_scheme_count(&self, count: usize) -> Result<()> {
        write_value(&self.path.join("schemes/nr_schemes"), count)
    }

    /// Returns a typed handle for a staged DAMOS scheme.
    #[must_use]
    pub fn scheme(&self, index: usize) -> Scheme {
        Scheme {
            path: self.path.join("schemes").join(index.to_string()),
        }
    }
}

/// A `targets/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    path: PathBuf,
}

impl Target {
    /// Returns this target's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Selects the process monitored by virtual-address operations.
    pub fn set_pid(&self, pid: Pid) -> Result<()> {
        write_value(&self.path.join("pid_target"), pid.get())
    }
}

/// A `schemes/<N>` sysfs directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scheme {
    path: PathBuf,
}

impl Scheme {
    /// Returns this scheme's sysfs path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Selects the scheme action.
    pub fn set_action(&self, action: Action) -> Result<()> {
        write_bytes(&self.path.join("action"), action.kernel_name().as_bytes())
    }

    /// Configures a pattern that matches every representable region.
    pub fn set_match_all(&self) -> Result<()> {
        let pattern = self.path.join("access_pattern");
        let native_max = usize::MAX;
        for range in ["sz", "nr_accesses", "age"] {
            let path = pattern.join(range);
            write_value(&path.join("min"), 0_u8)?;
            write_value(&path.join("max"), native_max)?;
        }
        Ok(())
    }

    /// Reads the last materialized tried-region results.
    ///
    /// Call [`Kdamond::command`] with
    /// [`KdamondCommand::UpdateSchemesTriedRegions`] first. `capacity_hint`
    /// only controls userspace allocation and does not limit results.
    pub fn tried_regions(&self, capacity_hint: usize) -> Result<Snapshot> {
        let base = self.path.join("tried_regions");
        let total_bytes = read_u64(&base.join("total_bytes"))?;
        let mut regions = Vec::with_capacity(capacity_hint);

        for index in 0_usize.. {
            let mut path = base.join(index.to_string());
            path.push("start");
            if !path_exists(&path)? {
                break;
            }
            let start = read_u64(&path)?;
            path.pop();
            path.push("end");
            let end = read_u64(&path)?;
            if end < start {
                return Err(Error::InvalidRegion { start, end });
            }
            path.pop();
            path.push("nr_accesses");
            let nr_accesses = read_u64(&path)?;
            path.pop();
            path.push("age");
            let age = read_u64(&path)?;
            path.pop();
            path.push("sz_filter_passed");
            let filter_passed_bytes = if path_exists(&path)? {
                Some(read_u64(&path)?)
            } else {
                None
            };

            regions.push(Region {
                start,
                end,
                nr_accesses,
                age,
                filter_passed_bytes,
            });
        }

        Ok(Snapshot {
            regions,
            total_bytes,
        })
    }
}

fn path_exists(path: &Path) -> Result<bool> {
    path.try_exists()
        .map_err(|error| io_error("inspect", path, error))
}

fn read_text(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|error| io_error("read", path, error))
}

fn read_usize(path: &Path) -> Result<usize> {
    let value = read_u64(path)?;
    usize::try_from(value).map_err(|_| invalid_kernel_value(path, value.to_string(), "usize"))
}

fn read_u64(path: &Path) -> Result<u64> {
    let mut file = File::open(path).map_err(|error| io_error("open for reading", path, error))?;
    let mut bytes = [0_u8; 64];
    let mut used = 0;

    loop {
        if used == bytes.len() {
            return Err(invalid_kernel_value(path, "<value too long>", "u64"));
        }
        let read = file
            .read(&mut bytes[used..])
            .map_err(|error| io_error("read", path, error))?;
        if read == 0 {
            break;
        }
        used += read;
    }

    let value = std::str::from_utf8(&bytes[..used])
        .map_err(|_| invalid_kernel_value(path, "<non-UTF-8 value>", "u64"))?
        .trim();
    value
        .parse()
        .map_err(|_| invalid_kernel_value(path, value, "u64"))
}

fn invalid_kernel_value(path: &Path, value: impl Into<Box<str>>, expected: &'static str) -> Error {
    Error::InvalidKernelValue {
        path: path.to_path_buf(),
        value: value.into(),
        expected,
    }
}

fn write_value(path: &Path, value: impl fmt::Display) -> Result<()> {
    let mut file = open_for_write(path)?;
    file.write_fmt(format_args!("{value}"))
        .map_err(|error| io_error("write", path, error))
}

fn write_bytes(path: &Path, value: &[u8]) -> Result<()> {
    let mut file = open_for_write(path)?;
    file.write_all(value)
        .map_err(|error| io_error("write", path, error))
}

fn open_for_write(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|error| io_error("open for writing", path, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_parser_preserves_new_kernel_values() {
        assert_eq!(Operation::parse("vaddr"), Operation::VirtualAddress);
        assert_eq!(
            Operation::parse("future"),
            Operation::Unknown("future".into())
        );
    }

    #[test]
    fn commands_match_linux_7_2_abi() {
        assert_eq!(
            KdamondCommand::UpdateSchemesTriedRegions.kernel_name(),
            "update_schemes_tried_regions"
        );
        assert_eq!(Action::LruDeprioritize.kernel_name(), "lru_deprio");
    }

    #[test]
    fn numeric_reader_rejects_oversized_input() {
        let fixture = TempFile::new(&"9".repeat(65));
        assert!(read_u64(&fixture.path).is_err());
    }

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(contents: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);

            let path = std::env::temp_dir().join(format!(
                "damon-rs-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, contents).expect("create temporary test file");
            Self { path }
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
