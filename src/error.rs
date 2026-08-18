use std::error;
use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::Operation;

/// A result returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// An error produced while validating a configuration or accessing DAMON.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// DAMON's sysfs admin interface is unavailable at the given path.
    Unavailable {
        /// The expected DAMON admin directory.
        path: PathBuf,
    },
    /// The current platform is unsupported by the default interface.
    UnsupportedPlatform,
    /// A configuration value violates a DAMON invariant.
    InvalidConfiguration {
        /// The invalid field.
        field: &'static str,
        /// A description of the invariant.
        reason: &'static str,
    },
    /// The requested monitoring operation is unavailable in this kernel.
    UnsupportedOperation {
        /// The unavailable operation.
        operation: Operation,
    },
    /// A kernel does not expose a required DAMON sysfs feature.
    UnsupportedFeature {
        /// The missing feature.
        feature: &'static str,
    },
    /// The high-level API found an existing kdamond configuration.
    InUse {
        /// The number of configured kdamonds.
        kdamonds: usize,
    },
    /// Transactional staging found a running kdamond that cannot be replaced.
    KdamondRunning {
        /// Index of the running kdamond.
        index: usize,
    },
    /// The hierarchy read back after staging did not match the request.
    ConfigurationMismatch {
        /// Logical sysfs path of the first difference.
        path: Box<str>,
        /// Requested value formatted for diagnostics.
        expected: Box<str>,
        /// Value read back from the kernel.
        observed: Box<str>,
    },
    /// An operation requires a running monitor.
    NotRunning,
    /// The kernel reported an unknown kdamond state.
    UnexpectedKdamondState {
        /// The unknown state string.
        state: Box<str>,
    },
    /// A kernel sysfs value was malformed or outside the userspace type range.
    InvalidKernelValue {
        /// The file containing the invalid value.
        path: PathBuf,
        /// The value after surrounding whitespace was removed.
        value: Box<str>,
        /// The expected representation.
        expected: &'static str,
    },
    /// A region returned by the kernel has an invalid address range.
    InvalidRegion {
        /// Inclusive start address.
        start: u64,
        /// Exclusive end address.
        end: u64,
    },
    /// Summing tried-region sizes overflowed the snapshot representation.
    SnapshotSizeOverflow,
    /// A singular snapshot was requested from a multi-result query.
    MultipleSnapshotResults {
        /// Number of scoped snapshots produced by the query.
        count: usize,
    },
    /// Converting DAMON core address units to bytes overflowed `u64`.
    AddressConversionOverflow {
        /// The raw number of DAMON address units.
        units: u64,
        /// The number of bytes per address unit.
        unit_bytes: u64,
    },
    /// A requested indexed sysfs child is not currently staged.
    IndexOutOfBounds {
        /// The kind of indexed child.
        kind: &'static str,
        /// The requested child index.
        index: usize,
        /// The number of staged children.
        count: usize,
    },
    /// Another cooperating process or thread owns the high-level session lock.
    SessionLockBusy {
        /// The advisory lock file.
        path: PathBuf,
    },
    /// The high-level session can no longer prove ownership of its sysfs slot.
    OwnershipLost {
        /// The failed ownership check.
        reason: &'static str,
    },
    /// A filesystem operation failed.
    Io {
        /// The operation being performed.
        operation: &'static str,
        /// The affected sysfs path.
        path: PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },
    /// An operation failed and restoring the preceding state also failed.
    Rollback {
        /// The primary operation error.
        operation: Box<Error>,
        /// The state-restoration error.
        rollback: Box<Error>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { path } => write!(
                formatter,
                "DAMON sysfs admin interface is unavailable at {}",
                path.display()
            ),
            Self::UnsupportedPlatform => {
                formatter.write_str("the default DAMON interface is only available on Linux")
            }
            Self::InvalidConfiguration { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::UnsupportedOperation { operation } => {
                write!(
                    formatter,
                    "kernel does not support DAMON operation {operation}"
                )
            }
            Self::UnsupportedFeature { feature } => {
                write!(
                    formatter,
                    "kernel does not expose required DAMON feature {feature}"
                )
            }
            Self::InUse { kdamonds } => write!(
                formatter,
                "DAMON is already configured with {kdamonds} kdamond(s)"
            ),
            Self::KdamondRunning { index } => {
                write!(formatter, "DAMON kdamond {index} is running")
            }
            Self::ConfigurationMismatch {
                path,
                expected,
                observed,
            } => write!(
                formatter,
                "staged DAMON value at {path} is {observed}, expected {expected}"
            ),
            Self::NotRunning => formatter.write_str("the DAMON monitor is not running"),
            Self::UnexpectedKdamondState { state } => {
                write!(formatter, "kernel returned unknown kdamond state {state:?}")
            }
            Self::InvalidKernelValue {
                path,
                value,
                expected,
            } => write!(
                formatter,
                "invalid value {value:?} in {} (expected {expected})",
                path.display()
            ),
            Self::InvalidRegion { start, end } => {
                write!(
                    formatter,
                    "kernel returned invalid region {start:#x}-{end:#x}"
                )
            }
            Self::SnapshotSizeOverflow => {
                formatter.write_str("DAMON snapshot total size exceeds u64::MAX")
            }
            Self::MultipleSnapshotResults { count } => write!(
                formatter,
                "DAMON query produced {count} scoped snapshots, use materialize_snapshots()"
            ),
            Self::AddressConversionOverflow { units, unit_bytes } => write!(
                formatter,
                "DAMON address conversion overflows u64 ({units} units at {unit_bytes} bytes each)"
            ),
            Self::IndexOutOfBounds { kind, index, count } => write!(
                formatter,
                "DAMON {kind} index {index} is out of bounds for {count} staged children"
            ),
            Self::SessionLockBusy { path } => write!(
                formatter,
                "another DAMON session holds the advisory lock {}",
                path.display()
            ),
            Self::OwnershipLost { reason } => {
                write!(formatter, "DAMON session ownership was lost: {reason}")
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} {}: {source}",
                path.display()
            ),
            Self::Rollback {
                operation,
                rollback,
            } => write!(
                formatter,
                "DAMON operation failed ({operation}); restoring the prior state also failed ({rollback})"
            ),
        }
    }
}

impl Error {
    /// Returns whether this error represents Linux `EBUSY`.
    #[must_use]
    pub fn is_resource_busy(&self) -> bool {
        const LINUX_EBUSY: i32 = 16;

        matches!(
            self,
            Self::Io { source, .. } if source.raw_os_error() == Some(LINUX_EBUSY)
        )
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Rollback { operation, .. } => Some(operation),
            _ => None,
        }
    }
}

pub(crate) fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: io::Error,
) -> Error {
    Error::Io {
        operation,
        path: path.into(),
        source,
    }
}
