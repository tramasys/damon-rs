/// A monitored virtual-memory region returned by DAMON.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Region {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) nr_accesses: u64,
    pub(crate) age: u64,
    pub(crate) filter_passed_bytes: Option<u64>,
}

impl Region {
    /// Returns the inclusive start address.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Returns the exclusive end address.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Returns the length in bytes.
    #[must_use]
    pub const fn len(self) -> u64 {
        self.end - self.start
    }

    /// Returns whether the region is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// Returns the number of observed accesses in the aggregation interval.
    #[must_use]
    pub const fn nr_accesses(self) -> u64 {
        self.nr_accesses
    }

    /// Returns the region age in aggregation intervals.
    #[must_use]
    pub const fn age(self) -> u64 {
        self.age
    }

    /// Returns bytes that passed scheme filters when exposed by the kernel.
    #[must_use]
    pub const fn filter_passed_bytes(self) -> Option<u64> {
        self.filter_passed_bytes
    }
}

/// A point-in-time set of DAMON monitoring results.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub(crate) regions: Vec<Region>,
    pub(crate) total_bytes: u64,
}

impl Snapshot {
    /// Returns the monitored regions in address order.
    #[must_use]
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    /// Returns the matched byte total reported by the kernel or, on kernels
    /// without that field, computed from the materialized regions.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
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
