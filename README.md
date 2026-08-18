# damon

`damon` is a safe, typed Rust library for Linux DAMON. It targets the
privileged admin sysfs ABI and is not a replacement for the
[`damo`](https://github.com/damonitor/damo) command-line tool.

## Scope

- High-level virtual-address monitoring for one process
- Typed low-level access to DAMON admin sysfs
- Adaptive owned configuration through Linux 7.2 and current `damo` controls
- Transactional whole-hierarchy staging with verified rollback
- Generic exclusive sessions with runtime commands and exact restoration
- Runtime discovery for all 57 official `damo` sysfs capabilities
- Checked address-unit conversion and sparse tried-region parsing
- Advisory locking, ownership checks, rollback, and cleanup
- No unsafe code and one direct Linux syscall dependency

High-level physical-address sessions, multiple contexts or targets, policy
builders, and async integration are future work.

## Requirements

The kernel normally needs:

```text
CONFIG_DAMON=y
CONFIG_DAMON_VADDR=y
CONFIG_DAMON_SYSFS=y
```

Admin sysfs usually requires elevated privileges. High-level sessions use
`/run/lock/damon-rs.lock`, refuse running kdamonds, and restore preceding
stopped configurations. The lock is advisory because the kernel exposes no
ownership primitive. Other controllers must use the same lock or equivalent
system-wide coordination.

The ABI is source-audited against Linux 7.2 and live-tested on Linux 7.1.
Runtime behavior is selected from available sysfs paths and accepted values,
not the kernel version. See [the ABI notes](docs/kernel-abi.md).

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

    for region in monitor.snapshot()?.regions() {
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

`Monitor::stop()` reports shutdown errors. Dropping a monitor performs
best-effort cleanup.

`Damon::exclusive_session()` provides the same lifecycle for any validated
single-kdamond `DamonConfig`. Explicit `close()` reports restoration failures,
while `Drop` performs best-effort restoration.

## Capability discovery

`Damon::capabilities()` exclusively stages a temporary hierarchy, probes
semantic values, and restores the preceding stopped state. The passive low-level
`Kdamond::capabilities()` method does not mutate the hierarchy.

Results use four states:

- `Supported`
- `Unsupported`
- `RequiresStaging`
- `Unverified`

`Unverified` matters on early sysfs kernels that accept an operation name
without proving its implementation is registered. A successful monitor start
confirms the selected operation.

`damo` also supports the older debugfs ABI. This crate currently targets admin
sysfs only.

## Low-level access

The public `damon::sysfs` module maps typed handles directly to sysfs objects.
Low-level snapshots retain raw DAMON address units until the caller attaches a
known effective unit.

`Damon::stage_configuration()` coordinates whole-hierarchy replacement with
the session lock, rejects running kdamonds, verifies kernel read-back, and
restores the preceding writable hierarchy if staging fails. Changed
configurations write only differing leaves.

Exclusive sessions can transactionally commit owned configuration updates.
Runtime reads support explicit synchronous refreshes, cached reads, and checked
batches for lower polling overhead.

## Toolchain

The crate uses Rust 2024 and supports Rust 1.85 or newer. CI also checks current
stable Rust.

## License

MIT
