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
    /// An operation requires a running monitor.
    NotRunning,
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
    /// A filesystem operation failed.
    Io {
        /// The operation being performed.
        operation: &'static str,
        /// The affected sysfs path.
        path: PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },
    /// Setup failed and restoring the previous empty state also failed.
    Rollback {
        /// The setup error.
        operation: Box<Error>,
        /// The rollback error.
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
            Self::NotRunning => formatter.write_str("the DAMON monitor is not running"),
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
                "DAMON setup failed ({operation}); rollback also failed ({rollback})"
            ),
        }
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
