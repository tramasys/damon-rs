//! Safe, typed access to the Linux Data Access Monitor (`DAMON`).
//!
//! `damon` provides two layers:
//!
//! - [`Damon`] and [`Monitor`] manage the common single-process monitoring
//!   lifecycle.
//! - [`sysfs`] exposes typed building blocks for callers that need direct
//!   control over the kernel ABI.
//!
//! # Example
//!
//! ```no_run
//! use damon::{Damon, Pid};
//!
//! # fn main() -> Result<(), damon::Error> {
//! let damon = Damon::new()?;
//! let pid = Pid::new(std::process::id())?;
//! let mut monitor = damon.monitor_pid(pid).start()?;
//!
//! for region in monitor.snapshot()?.regions() {
//!     println!("{:#x}-{:#x}: {} accesses", region.start(), region.end(), region.nr_accesses());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! The high-level API requires exclusive access to the DAMON admin sysfs tree
//! and refuses to replace an existing kdamond configuration.

#![forbid(unsafe_code)]

mod config;
mod error;
mod monitor;
mod region;
pub mod sysfs;

pub use config::{MonitoringIntervals, Pid, RegionBounds};
pub use error::{Error, Result};
pub use monitor::{Damon, Monitor, MonitorBuilder};
pub use region::{Region, Snapshot};
pub use sysfs::{Capabilities, Operation, SysfsFeature};
