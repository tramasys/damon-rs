use crate::sysfs::MAX_PROBES;
use crate::{AddressUnit, Result};

/// A monitored region returned by DAMON.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Region {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) nr_accesses: u32,
    pub(crate) age: u32,
    pub(crate) filter_passed_units: Option<u64>,
    pub(crate) probe_hits: [u8; MAX_PROBES],
    pub(crate) probe_count: u8,
    pub(crate) address_unit: AddressUnit,
}

impl Region {
    /// Returns the inclusive start address in DAMON core address units.
    #[must_use]
    pub const fn start_units(&self) -> u64 {
        self.start
    }

    /// Returns the inclusive start address in bytes.
    pub const fn start_bytes(&self) -> Result<u64> {
        self.address_unit.to_bytes(self.start)
    }

    /// Returns the exclusive end address in DAMON core address units.
    #[must_use]
    pub const fn end_units(&self) -> u64 {
        self.end
    }

    /// Returns the exclusive end address in bytes.
    pub const fn end_bytes(&self) -> Result<u64> {
        self.address_unit.to_bytes(self.end)
    }

    /// Returns the length in DAMON core address units.
    #[must_use]
    pub const fn len_units(&self) -> u64 {
        self.end - self.start
    }

    /// Returns the length in bytes.
    pub const fn len_bytes(&self) -> Result<u64> {
        self.address_unit.to_bytes(self.len_units())
    }

    /// Returns whether the region is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Returns the number of observed accesses in the aggregation interval.
    #[must_use]
    pub const fn nr_accesses(&self) -> u32 {
        self.nr_accesses
    }

    /// Returns the region age in aggregation intervals.
    #[must_use]
    pub const fn age(&self) -> u32 {
        self.age
    }

    /// Returns address units that passed scheme filters when exposed.
    #[must_use]
    pub const fn filter_passed_units(&self) -> Option<u64> {
        self.filter_passed_units
    }

    /// Returns bytes that passed scheme filters when exposed by the kernel.
    pub fn filter_passed_bytes(&self) -> Result<Option<u64>> {
        match self.filter_passed_units {
            Some(units) => match self.address_unit.to_bytes(units) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(error) => Err(error),
            },
            None => Ok(None),
        }
    }

    /// Returns the per-probe positive sample counters in probe-index order.
    #[must_use]
    pub fn probe_hits(&self) -> &[u8] {
        &self.probe_hits[..usize::from(self.probe_count)]
    }

    /// Returns the scale factor used for address and size fields.
    #[must_use]
    pub const fn address_unit(&self) -> AddressUnit {
        self.address_unit
    }
}

/// A point-in-time set of DAMON monitoring results.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub(crate) regions: Vec<Region>,
    pub(crate) total_units: u64,
    pub(crate) address_unit: AddressUnit,
}

impl Snapshot {
    /// Returns the monitored regions in the kernel's materialization order.
    ///
    /// Regions for one target are normally address ordered. Low-level callers
    /// can configure multiple targets, however, and the flattened sysfs result
    /// does not promise global address ordering across those targets.
    #[must_use]
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    /// Returns the matched total in DAMON core address units.
    #[must_use]
    pub const fn total_units(&self) -> u64 {
        self.total_units
    }

    /// Returns the matched total in bytes.
    pub const fn total_bytes(&self) -> Result<u64> {
        self.address_unit.to_bytes(self.total_units)
    }

    /// Returns the scale factor used for address and size fields.
    #[must_use]
    pub const fn address_unit(&self) -> AddressUnit {
        self.address_unit
    }

    /// Returns the number of regions in this snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Returns whether this snapshot contains no regions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Iterates over monitored regions.
    pub fn iter(&self) -> std::slice::Iter<'_, Region> {
        self.regions.iter()
    }
}

impl<'a> IntoIterator for &'a Snapshot {
    type Item = &'a Region;
    type IntoIter = std::slice::Iter<'a, Region>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
