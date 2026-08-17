use std::iter::FusedIterator;
use std::slice;

use crate::sysfs::MAX_PROBES;
use crate::{AddressUnit, Error, Result};

/// A monitored region returned directly by DAMON in core address units.
///
/// Linux applies a context's configured address unit only to physical-address
/// monitoring. Low-level sysfs callers can also change staged attributes
/// without committing them, so this type deliberately carries no inferred
/// byte scale. Use [`RawSnapshot::with_effective_address_unit`] only with the
/// operation and address unit that produced the results.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawRegion {
    start: u64,
    end: u64,
    nr_accesses: u32,
    age: u32,
    filter_passed_units: Option<u64>,
    probe_hits: [u8; MAX_PROBES],
    probe_count: u8,
}

impl RawRegion {
    pub(crate) fn from_kernel(
        start: u64,
        end: u64,
        nr_accesses: u32,
        age: u32,
        filter_passed_units: Option<u64>,
        probe_hits: &[u8],
    ) -> Result<Self> {
        if end < start {
            return Err(Error::InvalidRegion { start, end });
        }
        if probe_hits.len() > MAX_PROBES {
            return Err(Error::InvalidConfiguration {
                field: "snapshot probe count",
                reason: "must not exceed Linux DAMON_MAX_PROBES",
            });
        }
        let probe_count =
            u8::try_from(probe_hits.len()).map_err(|_| Error::InvalidConfiguration {
                field: "snapshot probe count",
                reason: "must fit the snapshot representation",
            })?;

        let mut stored_probe_hits = [0_u8; MAX_PROBES];
        stored_probe_hits[..probe_hits.len()].copy_from_slice(probe_hits);
        Ok(Self {
            start,
            end,
            nr_accesses,
            age,
            filter_passed_units,
            probe_hits: stored_probe_hits,
            probe_count,
        })
    }

    /// Returns the inclusive start address in DAMON core address units.
    #[must_use]
    pub const fn start_units(&self) -> u64 {
        self.start
    }

    /// Returns the exclusive end address in DAMON core address units.
    #[must_use]
    pub const fn end_units(&self) -> u64 {
        self.end
    }

    /// Returns the length in DAMON core address units.
    #[must_use]
    pub const fn len_units(&self) -> u64 {
        self.end - self.start
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

    /// Returns the per-probe positive sample counters in probe-index order.
    #[must_use]
    pub fn probe_hits(&self) -> &[u8] {
        &self.probe_hits[..usize::from(self.probe_count)]
    }
}

/// Raw point-in-time DAMON results with no inferred byte scale.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSnapshot {
    regions: Vec<RawRegion>,
    total_units: u64,
}

impl RawSnapshot {
    pub(crate) const fn from_kernel(regions: Vec<RawRegion>, total_units: u64) -> Self {
        Self {
            regions,
            total_units,
        }
    }

    /// Returns regions in the kernel's materialization order.
    ///
    /// Regions for one target are normally address ordered. Low-level callers
    /// can configure multiple targets, however, and the flattened sysfs result
    /// does not promise global address ordering across those targets.
    #[must_use]
    pub fn regions(&self) -> &[RawRegion] {
        &self.regions
    }

    /// Returns the matched total in DAMON core address units.
    #[must_use]
    pub const fn total_units(&self) -> u64 {
        self.total_units
    }

    /// Attaches the effective byte scale that produced these results.
    ///
    /// Use [`AddressUnit::ONE`] for virtual and fixed-virtual address
    /// operations. For physical-address monitoring, use the address unit from
    /// the active committed configuration, not a newer uncommitted sysfs value.
    #[must_use]
    pub const fn with_effective_address_unit(self, address_unit: AddressUnit) -> Snapshot {
        Snapshot::from_raw(self, address_unit)
    }

    /// Returns the number of regions in this raw snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Returns whether this raw snapshot contains no regions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Iterates over raw monitored regions.
    pub fn iter(&self) -> std::slice::Iter<'_, RawRegion> {
        self.regions.iter()
    }
}

impl<'a> IntoIterator for &'a RawSnapshot {
    type Item = &'a RawRegion;
    type IntoIter = std::slice::Iter<'a, RawRegion>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A borrowed monitored-region view with a known effective byte scale.
///
/// The owning [`Snapshot`] stores raw regions and its address unit only once.
/// Region views are created on demand without allocating or copying region
/// data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Region<'snapshot> {
    raw: &'snapshot RawRegion,
    address_unit: AddressUnit,
}

impl<'snapshot> Region<'snapshot> {
    const fn from_raw(raw: &'snapshot RawRegion, address_unit: AddressUnit) -> Self {
        Self { raw, address_unit }
    }

    /// Returns the inclusive start address in DAMON core address units.
    #[must_use]
    pub const fn start_units(&self) -> u64 {
        self.raw.start_units()
    }

    /// Returns the inclusive start address in bytes.
    pub const fn start_bytes(&self) -> Result<u64> {
        self.address_unit.to_bytes(self.raw.start_units())
    }

    /// Returns the exclusive end address in DAMON core address units.
    #[must_use]
    pub const fn end_units(&self) -> u64 {
        self.raw.end_units()
    }

    /// Returns the exclusive end address in bytes.
    pub const fn end_bytes(&self) -> Result<u64> {
        self.address_unit.to_bytes(self.raw.end_units())
    }

    /// Returns the length in DAMON core address units.
    #[must_use]
    pub const fn len_units(&self) -> u64 {
        self.raw.len_units()
    }

    /// Returns the length in bytes.
    pub const fn len_bytes(&self) -> Result<u64> {
        self.address_unit.to_bytes(self.raw.len_units())
    }

    /// Returns whether the region is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Returns the number of observed accesses in the aggregation interval.
    #[must_use]
    pub const fn nr_accesses(&self) -> u32 {
        self.raw.nr_accesses()
    }

    /// Returns the region age in aggregation intervals.
    #[must_use]
    pub const fn age(&self) -> u32 {
        self.raw.age()
    }

    /// Returns address units that passed scheme filters when exposed.
    #[must_use]
    pub const fn filter_passed_units(&self) -> Option<u64> {
        self.raw.filter_passed_units()
    }

    /// Returns bytes that passed scheme filters when exposed by the kernel.
    pub fn filter_passed_bytes(&self) -> Result<Option<u64>> {
        self.raw
            .filter_passed_units()
            .map(|units| self.address_unit.to_bytes(units))
            .transpose()
    }

    /// Returns the per-probe positive sample counters in probe-index order.
    #[must_use]
    pub fn probe_hits(&self) -> &[u8] {
        self.raw.probe_hits()
    }

    /// Returns the effective scale factor used for address and size fields.
    #[must_use]
    pub const fn address_unit(&self) -> AddressUnit {
        self.address_unit
    }

    /// Returns the underlying unscaled kernel result.
    #[must_use]
    pub const fn raw(&self) -> &'snapshot RawRegion {
        self.raw
    }
}

/// An allocation-free iterator over scaled region views.
#[derive(Clone, Debug)]
pub struct RegionIter<'snapshot> {
    regions: slice::Iter<'snapshot, RawRegion>,
    address_unit: AddressUnit,
}

impl<'snapshot> RegionIter<'snapshot> {
    fn new(regions: &'snapshot [RawRegion], address_unit: AddressUnit) -> Self {
        Self {
            regions: regions.iter(),
            address_unit,
        }
    }
}

impl<'snapshot> Iterator for RegionIter<'snapshot> {
    type Item = Region<'snapshot>;

    fn next(&mut self) -> Option<Self::Item> {
        self.regions
            .next()
            .map(|region| Region::from_raw(region, self.address_unit))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.regions.size_hint()
    }
}

impl DoubleEndedIterator for RegionIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.regions
            .next_back()
            .map(|region| Region::from_raw(region, self.address_unit))
    }
}

impl ExactSizeIterator for RegionIter<'_> {
    fn len(&self) -> usize {
        self.regions.len()
    }
}

impl FusedIterator for RegionIter<'_> {}

/// A point-in-time set of DAMON results with a known effective byte scale.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    raw: RawSnapshot,
    address_unit: AddressUnit,
}

impl Snapshot {
    const fn from_raw(raw: RawSnapshot, address_unit: AddressUnit) -> Self {
        Self { raw, address_unit }
    }

    /// Returns the monitored regions in the kernel's materialization order.
    ///
    /// Regions for one target are normally address ordered. Low-level callers
    /// can configure multiple targets, however, and the flattened sysfs result
    /// does not promise global address ordering across those targets.
    #[must_use]
    pub fn regions(&self) -> RegionIter<'_> {
        self.iter()
    }

    /// Returns one scaled region view by index.
    #[must_use]
    pub fn region(&self, index: usize) -> Option<Region<'_>> {
        self.raw
            .regions()
            .get(index)
            .map(|region| Region::from_raw(region, self.address_unit))
    }

    /// Returns the underlying unscaled regions as a slice.
    #[must_use]
    pub fn raw_regions(&self) -> &[RawRegion] {
        self.raw.regions()
    }

    /// Returns the underlying raw snapshot.
    #[must_use]
    pub const fn raw(&self) -> &RawSnapshot {
        &self.raw
    }

    /// Returns the matched total in DAMON core address units.
    #[must_use]
    pub const fn total_units(&self) -> u64 {
        self.raw.total_units()
    }

    /// Returns the matched total in bytes.
    pub const fn total_bytes(&self) -> Result<u64> {
        self.address_unit.to_bytes(self.total_units())
    }

    /// Returns the effective scale factor used for address and size fields.
    #[must_use]
    pub const fn address_unit(&self) -> AddressUnit {
        self.address_unit
    }

    /// Returns the number of regions in this snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Returns whether this snapshot contains no regions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Iterates over monitored regions.
    #[must_use]
    pub fn iter(&self) -> RegionIter<'_> {
        RegionIter::new(self.raw.regions(), self.address_unit)
    }
}

impl<'a> IntoIterator for &'a Snapshot {
    type Item = Region<'a>;
    type IntoIter = RegionIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_region_constructor_enforces_address_order() {
        let error =
            RawRegion::from_kernel(20, 10, 0, 0, None, &[]).expect_err("reversed region must fail");
        assert!(matches!(error, Error::InvalidRegion { start: 20, end: 10 }));
    }

    #[test]
    fn kernel_region_constructor_enforces_probe_capacity() {
        let error = RawRegion::from_kernel(10, 20, 0, 0, None, &[0; MAX_PROBES + 1])
            .expect_err("excess probe results must fail");
        assert!(matches!(
            error,
            Error::InvalidConfiguration {
                field: "snapshot probe count",
                ..
            }
        ));
    }

    #[test]
    fn raw_snapshot_requires_an_explicit_effective_unit_for_bytes() {
        let raw_region =
            RawRegion::from_kernel(1, 3, 2, 4, Some(2), &[7]).expect("valid raw region");
        let raw = RawSnapshot::from_kernel(vec![raw_region], 2);
        assert_eq!(raw.total_units(), 2);
        let raw_buffer = raw.regions().as_ptr();

        let scaled = raw.with_effective_address_unit(AddressUnit::new(4_096).expect("valid unit"));
        assert_eq!(scaled.raw_regions().as_ptr(), raw_buffer);
        assert_eq!(scaled.total_bytes().expect("convert total"), 8_192);
        assert_eq!(
            scaled
                .region(0)
                .expect("first region")
                .start_bytes()
                .expect("convert start"),
            4_096
        );
        assert_eq!(scaled.regions().len(), 1);
    }
}
