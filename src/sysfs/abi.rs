use std::fmt;

use crate::{AddressUnit, Error, Result};

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

    pub(super) fn parse(value: &str) -> Self {
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

/// A command accepted by a `kdamonds/<N>/state` file.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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
    /// A command introduced by a newer kernel.
    Unknown(Box<str>),
}

impl KdamondCommand {
    /// Returns the command string used by the kernel ABI.
    #[must_use]
    pub fn kernel_name(&self) -> &str {
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
            Self::Unknown(command) => command,
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

/// A DAMOS action.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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
    /// An action introduced by a newer kernel.
    Unknown(Box<str>),
}

impl Action {
    /// Returns the name used by the kernel ABI.
    #[must_use]
    pub fn kernel_name(&self) -> &str {
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
            Self::Unknown(name) => name,
        }
    }

    pub(super) fn parse(value: &str) -> Self {
        match value {
            "willneed" => Self::WillNeed,
            "cold" => Self::Cold,
            "pageout" => Self::PageOut,
            "hugepage" => Self::HugePage,
            "nohugepage" => Self::NoHugePage,
            "collapse" => Self::Collapse,
            "lru_prio" => Self::LruPrioritize,
            "lru_deprio" => Self::LruDeprioritize,
            "migrate_hot" => Self::MigrateHot,
            "migrate_cold" => Self::MigrateCold,
            "stat" => Self::Stat,
            other => Self::Unknown(other.into()),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kernel_name())
    }
}

/// A DAMOS region-size range in DAMON core address units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSizeRange {
    min: u64,
    max: u64,
}

/// An inclusive range of byte sizes.
///
/// Unlike [`RegionSizeRange`], this range is not scaled by a context's
/// [`AddressUnit`]. Linux uses byte sizes for DAMOS `hugepage_size` filters
/// because those filters compare directly against the underlying folio size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteSizeRange {
    min: u64,
    max: u64,
}

impl ByteSizeRange {
    /// Creates a validated inclusive byte-size range.
    pub const fn new(min: u64, max: u64) -> Result<Self> {
        if min > max {
            return Err(Error::InvalidConfiguration {
                field: "byte size range",
                reason: "minimum must not exceed maximum",
            });
        }
        Ok(Self { min, max })
    }

    /// Returns the inclusive minimum in bytes.
    #[must_use]
    pub const fn min(self) -> u64 {
        self.min
    }

    /// Returns the inclusive maximum in bytes.
    #[must_use]
    pub const fn max(self) -> u64 {
        self.max
    }
}

impl RegionSizeRange {
    /// Creates a validated inclusive size range in core address units.
    pub const fn new(min: u64, max: u64) -> Result<Self> {
        if min > max {
            return Err(Error::InvalidConfiguration {
                field: "region size range",
                reason: "minimum must not exceed maximum",
            });
        }
        Ok(Self { min, max })
    }

    /// Returns the inclusive minimum.
    #[must_use]
    pub const fn min(self) -> u64 {
        self.min
    }

    /// Returns the inclusive maximum.
    #[must_use]
    pub const fn max(self) -> u64 {
        self.max
    }

    /// Converts the inclusive minimum to bytes with the context's unit.
    pub const fn min_bytes(self, address_unit: AddressUnit) -> Result<u64> {
        address_unit.to_bytes(self.min)
    }

    /// Converts the inclusive maximum to bytes with the context's unit.
    pub const fn max_bytes(self, address_unit: AddressUnit) -> Result<u64> {
        address_unit.to_bytes(self.max)
    }
}

/// A DAMOS access-count range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessCountRange {
    min: u32,
    max: u32,
}

impl AccessCountRange {
    /// Creates a validated inclusive access-count range.
    pub const fn new(min: u32, max: u32) -> Result<Self> {
        if min > max {
            return Err(Error::InvalidConfiguration {
                field: "access count range",
                reason: "minimum must not exceed maximum",
            });
        }
        Ok(Self { min, max })
    }

    /// Returns the inclusive minimum.
    #[must_use]
    pub const fn min(self) -> u32 {
        self.min
    }

    /// Returns the inclusive maximum.
    #[must_use]
    pub const fn max(self) -> u32 {
        self.max
    }
}

/// A DAMOS age range in aggregation intervals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgeRange {
    min: u32,
    max: u32,
}

impl AgeRange {
    /// Creates a validated inclusive age range.
    pub const fn new(min: u32, max: u32) -> Result<Self> {
        if min > max {
            return Err(Error::InvalidConfiguration {
                field: "age range",
                reason: "minimum must not exceed maximum",
            });
        }
        Ok(Self { min, max })
    }

    /// Returns the inclusive minimum.
    #[must_use]
    pub const fn min(self) -> u32 {
        self.min
    }

    /// Returns the inclusive maximum.
    #[must_use]
    pub const fn max(self) -> u32 {
        self.max
    }
}

/// A DAMOS region access pattern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessPattern {
    size: RegionSizeRange,
    accesses: AccessCountRange,
    age: AgeRange,
}

impl AccessPattern {
    /// Creates a pattern from size, access-count, and age ranges.
    #[must_use]
    pub const fn new(size: RegionSizeRange, accesses: AccessCountRange, age: AgeRange) -> Self {
        Self {
            size,
            accesses,
            age,
        }
    }

    /// Returns the region-size range in DAMON core address units.
    #[must_use]
    pub const fn size(self) -> RegionSizeRange {
        self.size
    }

    /// Returns the access-count range.
    #[must_use]
    pub const fn accesses(self) -> AccessCountRange {
        self.accesses
    }

    /// Returns the age range in aggregation intervals.
    #[must_use]
    pub const fn age(self) -> AgeRange {
        self.age
    }

    pub(super) fn equivalent_after_kernel_normalization(self, observed: Self) -> bool {
        if self == observed {
            return true;
        }
        self.size.min == observed.size.min
            && self.size.max == u64::MAX
            && observed.size.max == u64::from(u32::MAX)
            && self.accesses == observed.accesses
            && self.age == observed.age
    }

    pub(super) fn normalize_kernel_width(&mut self, observed: Self) {
        if self.equivalent_after_kernel_normalization(observed) {
            self.size = observed.size;
        }
    }
}

/// A monitoring data-probe filter type.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProbeFilterType {
    /// Match anonymous pages.
    Anonymous,
    /// Match pages belonging to a memory control group.
    MemoryControlGroup,
    /// Match pages whose page-idle flag is unset.
    PageIdleUnset,
    /// A filter type introduced by a newer kernel.
    Unknown(Box<str>),
}

impl ProbeFilterType {
    /// Returns the name used by the kernel ABI.
    #[must_use]
    pub fn kernel_name(&self) -> &str {
        match self {
            Self::Anonymous => "anon",
            Self::MemoryControlGroup => "memcg",
            Self::PageIdleUnset => "pgidle_unset",
            Self::Unknown(name) => name,
        }
    }

    pub(super) fn parse(value: &str) -> Self {
        match value {
            "anon" => Self::Anonymous,
            "memcg" => Self::MemoryControlGroup,
            "pgidle_unset" => Self::PageIdleUnset,
            other => Self::Unknown(other.into()),
        }
    }
}

impl fmt::Display for ProbeFilterType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kernel_name())
    }
}
