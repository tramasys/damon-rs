# damon

`damon` is a safe, typed Rust interface to Linux DAMON (Data Access
Monitor). The repository is named `damon-rs`. The published library and crate
are named `damon`.

This initial foundation focuses on the privileged sysfs ABI and process
virtual-address monitoring. It is a library, not a replacement for the
human-facing [`damo`](https://github.com/damonitor/damo) tool.

## Current scope

- Linux DAMON admin sysfs (`/sys/kernel/mm/damon/admin`)
- Virtual-address monitoring of one PID
- Typed process IDs, intervals, region bounds, operations, actions, and errors
- Runtime operation and tri-state feature discovery
- Advisory session locking, ownership rechecks, rollback, and cleanup
- Query snapshots through a match-all `stat` DAMOS scheme
- Raw DAMON address units with checked byte conversions
- Per-probe hit counters in tried-region snapshots
- A public low-level `sysfs` module for specialized callers
- No unsafe code and one direct Linux-only syscall dependency

DAMOS policies, multiple targets/contexts, initial address ranges, physical
address monitoring, and async integration are intentionally future work.

## Requirements

The running Linux kernel needs DAMON and its sysfs interface, normally through:

```text
CONFIG_DAMON=y
CONFIG_DAMON_VADDR=y
CONFIG_DAMON_SYSFS=y
```

Access to the admin hierarchy generally requires elevated privileges. The
high-level API takes an advisory lock at `/run/lock/damon-rs.lock`, then starts
only when `nr_kdamonds` is zero. It fingerprints the staged configuration and
running kdamond thread before destructive operations. The kernel ABI is global
and has no ownership or transaction primitive, so tools that ignore the lock
can still race. Serialize `damo` and other controllers externally on the same
lock, or through another system-wide coordination mechanism.

The ABI foundation was verified against Linux 7.2. Capabilities are discovered
from sysfs instead of inferred solely from a kernel version. See
[`docs/kernel-abi.md`](docs/kernel-abi.md) for the exact source audit.

## High-level API

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
        .operations_update_interval(Duration::from_secs(60))
        .region_bounds(10, 1_000)
        .start()?;

    for region in monitor.snapshot()?.regions() {
        println!(
            "{:#x}-{:#x}: accesses={}, age={}",
            region.start_bytes()?,
            region.end_bytes()?,
            region.nr_accesses(),
            region.age(),
        );
    }

    monitor.stop()
}
```

Dropping a `Monitor` performs best-effort shutdown. Use `stop()` when shutdown
errors must be observed.

## Low-level API

```rust,no_run
use damon::sysfs::{DamonAdmin, KdamondCommand};

fn inspect() -> Result<(), damon::Error> {
    let admin = DamonAdmin::open_default()?;
    println!("configured kdamonds: {}", admin.kdamond_count()?);

    if admin.kdamond_count()? > 0 {
        println!("state: {:?}", admin.kdamond(0).state()?);
    }

    // Mutating methods are explicit and map directly to sysfs operations.
    let _stop_command = KdamondCommand::Off;
    Ok(())
}
```

## Toolchain and compatibility

Development uses the latest stable Rust toolchain. The declared MSRV is Rust
1.85, the first Rust 2024 release, and CI checks both MSRV and current stable.

## License

Licensed under the MIT License.
