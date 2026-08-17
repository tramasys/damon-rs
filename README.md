# damon

`damon` is a safe, typed Rust interface to Linux DAMON (Data Access
Monitor). The repository is named `damon-rs`; the published library and crate
are named `damon`.

This initial foundation focuses on the privileged sysfs ABI and process
virtual-address monitoring. It is a library, not a replacement for the
human-facing [`damo`](https://github.com/damonitor/damo) tool.

## Current scope

- Linux DAMON admin sysfs (`/sys/kernel/mm/damon/admin`)
- Virtual-address monitoring of one PID
- Typed process IDs, intervals, region bounds, operations, actions, and errors
- Runtime operation and feature discovery
- Lifecycle rollback and automatic best-effort cleanup
- Query snapshots through a match-all `stat` DAMOS scheme
- A public low-level `sysfs` module for specialized callers
- No runtime dependencies and no unsafe code

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
high-level API only starts when `nr_kdamonds` is zero, because the kernel ABI is
global and has no ownership or transaction primitive. Coordinate with `damo`
and other DAMON controllers at the system level.

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
            region.start(),
            region.end(),
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

## Performance policy

DAMON is designed for low-overhead monitoring, and this crate avoids hiding
unbounded background work:

- configuration is synchronous and allocation is kept off repeated numeric
  sysfs parsing paths;
- numeric snapshot fields are read into fixed stack buffers;
- snapshot storage is preallocated from the configured maximum-region hint;
- the crate has no runtime dependencies, executor, polling thread, or unsafe
  code;
- release builds use thin LTO and one codegen unit.

The kernel sysfs ABI still requires one open/read per exposed field. A future
tracepoint/perf transport should be a separate, explicitly selected data path
rather than hidden behind this API.

## Toolchain and compatibility

Development uses the latest stable Rust toolchain. The declared MSRV is Rust
1.85, the first Rust 2024 release, and CI checks both MSRV and current stable.

## License

Licensed under the MIT License.
