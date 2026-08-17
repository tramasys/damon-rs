use std::fmt;
use std::time::Duration;

use crate::{Error, Result};

const DEFAULT_SAMPLE_US: u64 = 5_000;
const DEFAULT_AGGREGATION_US: u64 = 100_000;
const DEFAULT_UPDATE_US: u64 = 60_000_000;

/// A Linux process identifier accepted by DAMON's virtual-address operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct Pid(u32);

impl Pid {
    /// Creates a process identifier.
    ///
    /// Linux process IDs are positive signed 32-bit values.
    pub fn new(raw: u32) -> Result<Self> {
        if raw == 0 || raw > 2_147_483_647 {
            return Err(Error::InvalidConfiguration {
                field: "pid",
                reason: "must be between 1 and i32::MAX",
            });
        }
        Ok(Self(raw))
    }

    /// Returns the numeric process identifier.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<u32> for Pid {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        Self::new(value)
    }
}

/// DAMON sampling, aggregation, and operations-update intervals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitoringIntervals {
    sample_us: u64,
    aggregation_us: u64,
    update_us: u64,
}

impl MonitoringIntervals {
    /// Creates and validates a set of monitoring intervals.
    ///
    /// Values must be exactly representable as whole microseconds, and the
    /// sampling interval must not exceed the aggregation interval. Linux
    /// accepts zero intervals.
    ///
    /// DAMON stores these values as the kernel's `unsigned long`. A 32-bit
    /// userspace process can control a 64-bit kernel, so validation cannot use
    /// userspace's `usize` width. The kernel reports an error on write when a
    /// value exceeds its native range.
    pub fn new(sample: Duration, aggregation: Duration, update: Duration) -> Result<Self> {
        let sample_us = duration_micros("sample interval", sample)?;
        let aggregation_us = duration_micros("aggregation interval", aggregation)?;
        let update_us = duration_micros("operations update interval", update)?;

        if sample_us > aggregation_us {
            return Err(Error::InvalidConfiguration {
                field: "monitoring intervals",
                reason: "sample interval must not exceed aggregation interval",
            });
        }

        Ok(Self {
            sample_us,
            aggregation_us,
            update_us,
        })
    }

    /// Returns the sampling interval.
    #[must_use]
    pub const fn sample(self) -> Duration {
        Duration::from_micros(self.sample_us)
    }

    /// Returns the aggregation interval.
    #[must_use]
    pub const fn aggregation(self) -> Duration {
        Duration::from_micros(self.aggregation_us)
    }

    /// Returns the monitoring-operations update interval.
    #[must_use]
    pub const fn update(self) -> Duration {
        Duration::from_micros(self.update_us)
    }

    pub(crate) const fn as_micros(self) -> (u64, u64, u64) {
        (self.sample_us, self.aggregation_us, self.update_us)
    }
}

impl Default for MonitoringIntervals {
    fn default() -> Self {
        Self {
            sample_us: DEFAULT_SAMPLE_US,
            aggregation_us: DEFAULT_AGGREGATION_US,
            update_us: DEFAULT_UPDATE_US,
        }
    }
}

fn duration_micros(field: &'static str, duration: Duration) -> Result<u64> {
    let micros = u64::try_from(duration.as_micros()).map_err(|_| Error::InvalidConfiguration {
        field,
        reason: "does not fit in 64-bit microseconds",
    })?;

    if Duration::from_micros(micros) != duration {
        return Err(Error::InvalidConfiguration {
            field,
            reason: "must be exactly representable in whole microseconds",
        });
    }
    Ok(micros)
}

/// Lower and upper bounds for DAMON's adaptive number of monitoring regions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionBounds {
    min: usize,
    max: usize,
}

impl RegionBounds {
    /// Creates validated region-count bounds.
    ///
    /// The kernel requires a minimum of at least three and `min <= max`.
    pub const fn new(min: usize, max: usize) -> Result<Self> {
        if min < 3 {
            return Err(Error::InvalidConfiguration {
                field: "minimum regions",
                reason: "must be at least 3",
            });
        }
        if min > max {
            return Err(Error::InvalidConfiguration {
                field: "region bounds",
                reason: "minimum must not exceed maximum",
            });
        }
        Ok(Self { min, max })
    }

    /// Returns the lower region-count bound.
    #[must_use]
    pub const fn min(self) -> usize {
        self.min
    }

    /// Returns the upper region-count bound.
    #[must_use]
    pub const fn max(self) -> usize {
        self.max
    }
}

impl Default for RegionBounds {
    fn default() -> Self {
        Self { min: 10, max: 1000 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_rejects_values_outside_linux_range() {
        assert!(Pid::new(0).is_err());
        assert!(Pid::new(2_147_483_647).is_ok());
        assert!(Pid::new(2_147_483_648).is_err());
    }

    #[test]
    fn intervals_match_kernel_invariants() {
        assert!(MonitoringIntervals::new(Duration::ZERO, Duration::ZERO, Duration::ZERO).is_ok());
        assert!(
            MonitoringIntervals::new(
                Duration::from_micros(5),
                Duration::from_micros(4),
                Duration::from_micros(10),
            )
            .is_err()
        );
        assert!(
            MonitoringIntervals::new(
                Duration::from_nanos(1),
                Duration::from_micros(1),
                Duration::from_micros(1),
            )
            .is_err()
        );
    }

    #[test]
    fn region_bounds_match_kernel_invariants() {
        assert!(RegionBounds::new(2, 100).is_err());
        assert!(RegionBounds::new(100, 99).is_err());
        assert_eq!(RegionBounds::new(3, 3).expect("valid bounds").max(), 3);
    }
}
