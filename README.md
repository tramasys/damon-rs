# damon

`damon` is a safe, typed Rust library for the Linux DAMON admin sysfs ABI.
It provides:

- Typed low-level sysfs access and owned configuration types
- Capability-driven behavior without kernel version checks
- High-level `vaddr`, `fvaddr`, and `paddr` workflows
- Multiple process targets and managed multi-kdamond hierarchies
- Scoped and persistent lifecycle APIs
- Transactional staging, verified rollback, and ownership checks
- Runtime updates, statistics, tried-region snapshots, and probe results
- Checked address-unit conversion

The crate is sysfs-only. It does not provide the legacy debugfs backend or
continuous tracepoint recording.

## Requirements

The kernel normally needs `CONFIG_DAMON`, `CONFIG_DAMON_VADDR`, and
`CONFIG_DAMON_SYSFS`. Access to the admin interface usually requires elevated
privileges.

## Example

```rust,no_run
use std::time::Duration;

use damon::{Damon, Pid};

fn main() -> Result<(), damon::Error> {
    let damon = Damon::new()?;
    let pid = Pid::new(std::process::id())?;
    let mut monitor = damon
        .monitor_pid(pid)
        .sample_interval(Duration::from_millis(5))
        .aggregation_interval(Duration::from_millis(100))
        .start()?;

    for region in monitor.materialize_snapshot()?.snapshot().regions() {
        println!(
            "{:#x}-{:#x}: {} accesses",
            region.start_bytes()?,
            region.end_bytes()?,
            region.nr_accesses(),
        );
    }

    monitor.stop()
}
```

## API

`Damon::vaddr()`, `Damon::fvaddr()`, and `Damon::paddr()` build common
monitoring workflows. `Damon::exclusive_session()` manages one kdamond, while
`Damon::managed_hierarchy()` manages a complete multi-kdamond configuration.
`Damon::start_persistent()` returns a receipt for later verified attach,
update, and stop operations.

Scoped sessions hold a cooperative advisory lock and restore the preceding
stopped hierarchy when closed. Persistent operations reacquire the lock and
verify the receipt for each operation. The kernel has no ownership primitive,
so privileged controllers that ignore the lock cannot be excluded.

Snapshot materialization is a synchronous kernel operation and may wait for a
scheme apply interval. Cached reads avoid the materialization command.
`SnapshotRequest` supports deadline-based waiting without claiming to cancel a
blocked kernel write.

## Compatibility

The public `damon::sysfs` module exposes typed handles for direct ABI access.
Runtime support is discovered from available paths and accepted values.
Unknown future ABI values are preserved where possible. See
[the ABI notes](docs/kernel-abi.md) for the behavior that affects ownership,
snapshots, and address units.

The crate uses Rust 2024 and supports Rust 1.85 or newer. It is licensed under
MIT.
