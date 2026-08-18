# DAMON kernel ABI notes

This document records the kernel contracts that shape the crate.

## Audit baseline

- Audit date: 2026-08-18
- Linux tag: `v7.2`
- Linux commit: `8d3ae59288f1e7d58d76558a6ee96d533bc5019f`
- Official `damo` commit: `80caa75bbac6b8cc6279d296ede0b112a8435d83`

Primary sources:

- [Linux 7.2 DAMON usage](https://docs.kernel.org/7.2/admin-guide/mm/damon/usage.html)
- [Linux `sysfs.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/damon/sysfs.c?h=v7.2)
- [Linux `sysfs-schemes.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/damon/sysfs-schemes.c?h=v7.2)
- [Linux DAMON public header](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/damon.h?h=v7.2)
- [Official `damo` sysfs backend](https://github.com/damonitor/damo/blob/80caa75bbac6b8cc6279d296ede0b112a8435d83/src/_damon_sysfs.py)

## High-level transaction

Each high-level builder creates one kdamond, context, and target. It selects
`vaddr`, `fvaddr`, or `paddr`, stages optional probes and custom schemes, then
adds a private match-all `stat` scheme for snapshots before starting the
kdamond.

Before mutation it takes a cooperative lock and requires all existing
kdamonds to be stopped. It captures the complete writable hierarchy,
including unknown future attributes, then records the staged fingerprint and
kdamond thread ID. Identity is rechecked around runtime commands and cleanup.
Explicit close restores the preceding hierarchy. Drop attempts the same
restoration without reporting errors.

Auto-tuned `sample_us` and `aggr_us` values are kernel-volatile while interval
tuning is enabled, so ownership checks ignore those two leaves. All other
captured writable values remain fingerprinted.

These checks reduce races but cannot stop an uncooperative privileged process
from changing the global kernel interface.

Whole-hierarchy configuration staging uses the same lock and refuses running
kdamonds. It captures every writable input, validates and stages typed values,
verifies kernel read-back, and reconstructs the captured hierarchy after a
failure. Unknown future writable attributes are included in restoration.
Changed configurations are staged as leaf-level differences.

## Snapshots

Snapshots use `update_schemes_tried_regions`, then numerically sort the region
and probe directories that exist. A region can expose `start`, `end`,
`nr_accesses`, `age`, `sz_filter_passed`, and probe `hits`.

When `total_bytes` is absent, the crate sums validated region sizes. When it is
present, `SnapshotCompleteness` compares the reported and materialized totals.
Kernels without tried-region queries can still run a monitor, but
`Monitor::snapshot()` returns `UnsupportedFeature`.

High-level workflows contain one target and return its regions in address
order. Results from multiple low-level targets remain in kernel materialization
order and do not imply global address ordering.

## Numeric representation

DAMON addresses and sizes use kernel `unsigned long`. The crate stores them as
`u64` and lets the kernel validate its native range. Match-all configuration
tries `u64::MAX`, then falls back to `u32::MAX` only after a kernel range error.

Physical-address results use `addr_unit`. Low-level snapshots therefore expose
raw units. Byte conversion requires an explicit effective unit and checks
overflow. Physical-address staging also rejects non-power-of-two units below
the runtime page size. High-level physical workflows carry the effective unit,
while virtual workflows use a unit of one.

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

`Damon::capabilities()` holds the advisory lock, requires stopped kdamonds,
stages representative children, probes filter values, records concrete paths,
and restores the preceding hierarchy. `Kdamond::capabilities()` is passive.

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

Capability parity covers official `damo` admin sysfs discovery. Probe weights
and preparations, operation attributes, and sample controls are typed when
present. The separate legacy debugfs backend is out of scope.
