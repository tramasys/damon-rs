# DAMON kernel ABI notes

This document records the kernel contracts that shape the crate.

## Audit baseline

- Audit date: 2026-08-17
- Linux tag: `v7.2`
- Linux commit: `8d3ae59288f1e7d58d76558a6ee96d533bc5019f`
- Official `damo` commit: `590207a5e2db8d7dd0911564baff42cce114170c`

Primary sources:

- [Linux 7.2 DAMON usage](https://docs.kernel.org/7.2/admin-guide/mm/damon/usage.html)
- [Linux `sysfs.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/damon/sysfs.c?h=v7.2)
- [Linux `sysfs-schemes.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/damon/sysfs-schemes.c?h=v7.2)
- [Linux DAMON public header](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/damon.h?h=v7.2)
- [Official `damo` sysfs backend](https://github.com/damonitor/damo/blob/590207a5e2db8d7dd0911564baff42cce114170c/src/_damon_sysfs.py)

## High-level transaction

The high-level API creates one kdamond, context, target, and match-all `stat`
scheme. It selects `vaddr`, configures the process and intervals, then starts
the kdamond.

Before mutation it takes a cooperative lock and requires `nr_kdamonds` to be
zero. It fingerprints all materialized writable inputs, including unknown
future attributes, and records the kdamond thread ID. Identity is rechecked
around result materialization and cleanup. Failed setup rolls back to zero
kdamonds when ownership is still established.

These checks reduce races but cannot stop an uncooperative privileged process
from changing the global kernel interface.

## Snapshots

Snapshots use `update_schemes_tried_regions`, then numerically sort the region
and probe directories that exist. A region can expose `start`, `end`,
`nr_accesses`, `age`, `sz_filter_passed`, and probe `hits`.

When `total_bytes` is absent, the crate sums validated region sizes. When it is
present, `SnapshotCompleteness` compares the reported and materialized totals.
Kernels without tried-region queries can still run a monitor, but
`Monitor::snapshot()` returns `UnsupportedFeature`.

Results remain in kernel materialization order. Multiple low-level targets do
not imply global address ordering.

## Numeric representation

DAMON addresses and sizes use kernel `unsigned long`. The crate stores them as
`u64` and lets the kernel validate its native range. Match-all configuration
tries `u64::MAX`, then falls back to `u32::MAX` only after a kernel range error.

Physical-address results use `addr_unit`. Low-level snapshots therefore expose
raw units. Byte conversion requires an explicit effective unit and checks
overflow. High-level virtual-address sessions use an effective unit of one.

Access-pattern sizes use the kernel-width range type. Access counts and ages
use `u32`, matching the active kernel structures and preventing silent
truncation.

Validated configuration also enforces positive PIDs, ordered ranges, at least
three regions, ordered region bounds, whole-microsecond intervals, and a
sampling interval no greater than the aggregation interval. Zero intervals are
valid where the kernel accepts them.

## Capability discovery

`SysfsFeature` maps all 57 capability names in the audited official `damo`
sysfs backend. Discovery returns:

- `Supported` for authoritative or usable ABI evidence
- `Unsupported` for a confirmed absence or rejected value
- `RequiresStaging` when an indexed child is not materialized
- `Unverified` when visible ABI evidence cannot prove usability

`Damon::capabilities()` holds the advisory lock, requires an empty hierarchy,
stages representative children, probes filter values, records concrete paths,
and restores zero kdamonds. `Kdamond::capabilities()` is passive.

Without `avail_operations`, accepted operation writes remain `Unverified`.
Linux 5.18 can accept a recognized name even when its implementation is not
registered. An authoritative listing or successful monitor start confirms
support.

Unknown operation names, actions, and concrete paths are preserved for forward
compatibility.

## Compatibility boundary

Linux 7.2 is the source baseline, not a version gate. The adaptive path is also
live-tested on Linux 7.1. Wider kernel coverage still needs kernel-backed VM
tests.

Capability parity covers official `damo` admin sysfs discovery. It does not
mean every discovered feature has a high-level Rust API. The separate legacy
debugfs backend is out of scope.
