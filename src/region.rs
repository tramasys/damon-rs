use std::iter::FusedIterator;
use std::slice;

use crate::{AddressUnit, Error, Result};

const INLINE_PROBE_HITS: usize = 4;

/// One monitoring-probe result returned for a region.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProbeHit {
    index: usize,
    hits: u8,
}

impl ProbeHit {
    pub(crate) const fn from_kernel(index: usize, hits: u8) -> Self {
        Self { index, hits }
    }

    /// Returns the numeric probe directory index.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }

    /// Returns the number of positive samples for this probe.
    #[must_use]
    pub const fn hits(self) -> u8 {
        self.hits
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProbeHits {
    Inline {
        indices: [usize; INLINE_PROBE_HITS],
        hits: [u8; INLINE_PROBE_HITS],
        len: usize,
    },
    Heap {
        indices: Box<[usize]>,
        hits: Box<[u8]>,
    },
}

impl ProbeHits {
    fn from_kernel(values: &[(usize, u8)]) -> Self {
        if values.len() <= INLINE_PROBE_HITS {
            let mut indices = [0; INLINE_PROBE_HITS];
            let mut hits = [0; INLINE_PROBE_HITS];
            for (offset, (index, value)) in values.iter().copied().enumerate() {
                indices[offset] = index;
                hits[offset] = value;
            }
            return Self::Inline {
                indices,
                hits,
                len: values.len(),
            };
        }

        let (indices, hits): (Vec<_>, Vec<_>) = values.iter().copied().unzip();
        Self::Heap {
            indices: indices.into_boxed_slice(),
            hits: hits.into_boxed_slice(),
        }
    }

    const fn indices(&self) -> &[usize] {
        match self {
            Self::Inline { indices, len, .. } => {
                let (values, _) = indices.split_at(*len);
                values
            }
            Self::Heap { indices, .. } => indices,
        }
    }

    const fn hits(&self) -> &[u8] {
        match self {
            Self::Inline { hits, len, .. } => {
                let (values, _) = hits.split_at(*len);
                values
            }
            Self::Heap { hits, .. } => hits,
        }
    }
}

/// Whether every address unit counted by the kernel has a materialized region.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SnapshotCompleteness {
    /// Reported and materialized totals agree.
    Complete,
    /// The kernel reported more units than were materialized as regions.
    Partial {
        /// Total reported by the kernel in DAMON core address units.
        reported_units: u64,
        /// Sum of the materialized regions in DAMON core address units.
        materialized_units: u64,
    },
    /// Materialized regions exceed the kernel's independent reported total.
    ///
    /// This indicates an inconsistent result rather than ordinary bounded
    /// materialization.
    Inconsistent {
        /// Total reported by the kernel in DAMON core address units.
        reported_units: u64,
        /// Sum of the materialized regions in DAMON core address units.
        materialized_units: u64,
    },
    /// The kernel does not expose an independent reported total.
    Unverifiable,
}

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
    probe_hits: ProbeHits,
}

impl RawRegion {
    pub(crate) fn from_kernel(
        start: u64,
        end: u64,
        nr_accesses: u32,
        age: u32,
        filter_passed_units: Option<u64>,
        probe_hits: &[(usize, u8)],
    ) -> Result<Self> {
        if end < start {
            return Err(Error::InvalidRegion { start, end });
        }
        Ok(Self {
            start,
            end,
            nr_accesses,
            age,
            filter_passed_units,
            probe_hits: ProbeHits::from_kernel(probe_hits),
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
    ///
    /// Use [`Self::probe_indices`] or [`Self::probe_results`] when numeric
    /// directory indexes need to be preserved.
    #[must_use]
    pub fn probe_hits(&self) -> &[u8] {
        self.probe_hits.hits()
    }

    /// Returns the numeric indexes corresponding to [`Self::probe_hits`].
    #[must_use]
    pub const fn probe_indices(&self) -> &[usize] {
        self.probe_hits.indices()
    }

    /// Iterates over indexed probe results without allocating.
    #[must_use]
    pub fn probe_results(&self) -> impl ExactSizeIterator<Item = ProbeHit> + '_ {
        self.probe_indices()
            .iter()
            .copied()
            .zip(self.probe_hits().iter().copied())
            .map(|(index, hits)| ProbeHit::from_kernel(index, hits))
    }
}

/// Raw point-in-time DAMON results with no inferred byte scale.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSnapshot {
    regions: Vec<RawRegion>,
    reported_total_units: Option<u64>,
    materialized_total_units: u64,
}

impl RawSnapshot {
    pub(crate) const fn from_kernel(
        regions: Vec<RawRegion>,
        reported_total_units: Option<u64>,
        materialized_total_units: u64,
    ) -> Self {
        Self {
            regions,
            reported_total_units,
            materialized_total_units,
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
    ///
    /// This prefers the kernel's independent total when present, including
    /// when only part of the corresponding region list was materialized.
    #[must_use]
    pub const fn total_units(&self) -> u64 {
        match self.reported_total_units {
            Some(total) => total,
            None => self.materialized_total_units,
        }
    }

    /// Returns the independent total reported by the kernel when available.
    #[must_use]
    pub const fn reported_total_units(&self) -> Option<u64> {
        self.reported_total_units
    }

    /// Returns the sum of materialized region lengths.
    #[must_use]
    pub const fn materialized_total_units(&self) -> u64 {
        self.materialized_total_units
    }

    /// Reports whether the materialized regions cover the kernel's total.
    #[must_use]
    pub const fn completeness(&self) -> SnapshotCompleteness {
        match self.reported_total_units {
            Some(reported) if reported == self.materialized_total_units => {
                SnapshotCompleteness::Complete
            }
            Some(reported) if reported > self.materialized_total_units => {
                SnapshotCompleteness::Partial {
                    reported_units: reported,
                    materialized_units: self.materialized_total_units,
                }
            }
            Some(reported) => SnapshotCompleteness::Inconsistent {
                reported_units: reported,
                materialized_units: self.materialized_total_units,
            },
            None => SnapshotCompleteness::Unverifiable,
        }
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

    /// Returns the numeric indexes corresponding to [`Self::probe_hits`].
    #[must_use]
    pub const fn probe_indices(&self) -> &[usize] {
        self.raw.probe_indices()
    }

    /// Iterates over indexed probe results without allocating.
    #[must_use]
    pub fn probe_results(&self) -> impl ExactSizeIterator<Item = ProbeHit> + '_ {
        self.raw.probe_results()
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

    /// Returns the independent total reported by the kernel when available.
    #[must_use]
    pub const fn reported_total_units(&self) -> Option<u64> {
        self.raw.reported_total_units()
    }

    /// Returns the sum of materialized region lengths.
    #[must_use]
    pub const fn materialized_total_units(&self) -> u64 {
        self.raw.materialized_total_units()
    }

    /// Reports whether the materialized regions cover the kernel's total.
    #[must_use]
    pub const fn completeness(&self) -> SnapshotCompleteness {
        self.raw.completeness()
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
    fn kernel_region_constructor_keeps_future_probe_counts_and_indexes() {
        let probes = [(0, 1), (2, 3), (4, 5), (6, 7), (8, 9)];
        let region =
            RawRegion::from_kernel(10, 20, 0, 0, None, &probes).expect("valid probe results");
        assert_eq!(region.probe_indices(), &[0, 2, 4, 6, 8]);
        assert_eq!(region.probe_hits(), &[1, 3, 5, 7, 9]);
        assert_eq!(
            region.probe_results().collect::<Vec<_>>(),
            [
                ProbeHit::from_kernel(0, 1),
                ProbeHit::from_kernel(2, 3),
                ProbeHit::from_kernel(4, 5),
                ProbeHit::from_kernel(6, 7),
                ProbeHit::from_kernel(8, 9),
            ]
        );
    }

    #[test]
    fn raw_snapshot_requires_an_explicit_effective_unit_for_bytes() {
        let raw_region =
            RawRegion::from_kernel(1, 3, 2, 4, Some(2), &[(0, 7)]).expect("valid raw region");
        let raw = RawSnapshot::from_kernel(vec![raw_region], Some(2), 2);
        assert_eq!(raw.total_units(), 2);
        assert_eq!(raw.completeness(), SnapshotCompleteness::Complete);
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

    #[test]
    fn snapshot_distinguishes_partial_and_inconsistent_totals() {
        let partial = RawSnapshot::from_kernel(Vec::new(), Some(2), 1);
        assert!(matches!(
            partial.completeness(),
            SnapshotCompleteness::Partial { .. }
        ));

        let inconsistent = RawSnapshot::from_kernel(Vec::new(), Some(1), 2);
        assert!(matches!(
            inconsistent.completeness(),
            SnapshotCompleteness::Inconsistent { .. }
        ));
    }
}
