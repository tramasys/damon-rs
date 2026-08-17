# DAMON kernel ABI reference

This document records the upstream evidence used for the initial `damon`
crate design. It is a compatibility reference, not a vendored copy of Linux.

## Audited upstream version

- Audit date: 2026-08-17
- Latest mainline release at audit time: Linux 7.2 (2026-08-16)
- Git tag: `v7.2`
- Commit: `8d3ae59288f1e7d58d76558a6ee96d533bc5019f`
- Latest Rust stable at audit time: 1.97.1

Primary sources:

- [Linux release metadata](https://www.kernel.org/releases.json)
- [Linux 7.2 DAMON usage documentation](https://docs.kernel.org/7.2/admin-guide/mm/damon/usage.html)
- [Linux 7.2 `mm/damon/sysfs.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/damon/sysfs.c?h=v7.2)
- [Linux 7.2 `mm/damon/sysfs-schemes.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/damon/sysfs-schemes.c?h=v7.2)
- [Linux 7.2 DAMON public header](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/damon.h?h=v7.2)
- [Official `damo` sysfs implementation](https://github.com/damonitor/damo/blob/next/src/_damon_sysfs.py)
- [Rust stable release history](https://blog.rust-lang.org/releases/)

## High-level monitor transaction

The first implementation uses one kdamond, one context, one target, and one
query scheme. Its staging sequence follows the upstream sysfs hierarchy:

```text
kdamonds/nr_kdamonds                                      <- 1
kdamonds/0/refresh_ms                                     <- 0
kdamonds/0/contexts/nr_contexts                           <- 1
kdamonds/0/contexts/0/avail_operations                    -> require vaddr
kdamonds/0/contexts/0/operations                          <- vaddr
kdamonds/0/contexts/0/addr_unit                           <- 1
kdamonds/0/contexts/0/pause                               <- N
kdamonds/0/contexts/0/monitoring_attrs/intervals/*         <- intervals
kdamonds/0/contexts/0/monitoring_attrs/nr_regions/{min,max}<- bounds
kdamonds/0/contexts/0/monitoring_attrs/probes/nr_probes    <- 0
kdamonds/0/contexts/0/targets/nr_targets                  <- 1
kdamonds/0/contexts/0/targets/0/pid_target                <- PID
kdamonds/0/contexts/0/targets/0/obsolete_target           <- N
kdamonds/0/contexts/0/targets/0/regions/nr_regions         <- 0
kdamonds/0/contexts/0/schemes/nr_schemes                  <- 1
kdamonds/0/contexts/0/schemes/0/action                    <- stat
kdamonds/0/contexts/0/schemes/0/access_pattern/*/{min,max} <- match all
kdamonds/0/contexts/0/schemes/0/apply_interval_us         <- 0
kdamonds/0/state                                           <- on
```

The kernel creates and destroys indexed directories when each `nr_*` file is
written. The high-level API takes a cooperative `flock`, refuses to begin when
any kdamond is already staged, and rolls `nr_kdamonds` back to zero if setup
fails. It also records the kdamond thread ID and fingerprints the staged
configuration before cleanup. The fingerprint covers periodic refresh, pause
state, probes, initial regions, interval goals, scheme apply interval, target
NUMA node, quotas, watermarks, scheme filter counts, destinations, and the
configured snapshot limit in addition to the primary typed settings. Snapshot
queries verify that identity before materialization, after the materialization
command, and again after reading the results. Those checks reduce races among
cooperating callers but cannot create kernel-enforced ownership or reveal an
active change that another controller commits and then hides by restoring only
the staged files.

## Snapshot semantics

The admin sysfs interface does not expose the context's live region list as a
simple file. Query-style retrieval uses DAMOS tried regions:

1. Configure a `stat` scheme whose access pattern covers the desired regions.
2. Write `update_schemes_tried_regions` to `kdamonds/0/state`.
3. Read `schemes/0/tried_regions/total_bytes` when the kernel exposes it.
4. Read consecutive indexed region directories containing `start`, `end`,
   `nr_accesses`, `age`, `sz_filter_passed`, and `probes/<N>/hits` when those
   fields are exposed.

Kernels with tried-region queries but no `total_bytes` file are supported by
summing the validated materialized region sizes in userspace. This matches the
compatibility distinction made by the official `damo` implementation.

The command can wait until the next scheme apply interval. A zero
`apply_interval_us` uses the aggregation interval. `nr_accesses` is a count per
aggregation interval and `age` is measured in aggregation intervals. Neither
is a byte-normalized density. Linux 7.2 stores each tried-region probe hit in
an `unsigned char`, which the crate preserves as `u8` in probe-index order.

## Address units

DAMON core addresses and sizes use `unsigned long`. Linux 7.2 applies a
context's `addr_unit` only to physical-address monitoring. The sysfs file is a
staging input and can differ from the active configuration until `commit`, so
reading it while materializing results cannot establish the scale that
produced those results.

The low-level Rust API therefore returns `RawSnapshot` and `RawRegion`, names
raw accessors with an `_units` suffix, and performs no implicit conversion.
Callers that know the active committed operation and unit can explicitly
attach its effective unit. Exclusive high-level sessions record the committed
operation and effective unit, using one for virtual and fixed-virtual address
monitoring and the configured unit for physical-address monitoring. Scaled
snapshots provide checked `_bytes` conversions.

A scaled `Snapshot` owns the original raw region vector and one address unit.
Its `Region` values are borrowed views created by an allocation-free iterator,
so attaching a known unit neither duplicates the vector nor stores the same
unit in every region.

## Access-pattern widths

The sysfs staging structure accepts access-pattern values as `unsigned long`,
but the active `damos_access_pattern` stores region size as `unsigned long`
and access count and age as `unsigned int`. The crate uses a kernel-width
`RegionSizeRange` and separate `u32` `AccessCountRange` and `AgeRange` types,
preventing a successful sysfs write from becoming a truncated active pattern.

## Validated invariants

The userspace types enforce kernel invariants before writing:

- PID is in `1..=i32::MAX`.
- intervals are whole microseconds represented as `u64`. Zero is valid.
- sampling interval does not exceed aggregation interval.
- minimum regions is at least three.
- minimum regions does not exceed maximum regions.
- returned region end is not below its start.
- address units are non-zero and byte conversions cannot overflow `u64`.
- access-count and age pattern limits fit `u32`.

Linux 7.2 defaults are 5,000 microseconds sampling, 100,000 microseconds
aggregation, 60,000,000 microseconds operations update, and 10 to 1,000
regions. The crate uses the same defaults.

## Compatibility policy

The ABI grows over time, so known operation and action names are typed while
unknown names are preserved. Each `SysfsFeature` is detected from its concrete
file or directory. Paths below an unstaged probe or filter are reported as
`CapabilitySupport::RequiresStaging`, distinct from `Unsupported`. This keeps
the non-mutating Rust query honest while following the same concrete-path
principle used by official `damo`, whose exhaustive probe temporarily stages
representative children and restores the saved configuration.

DAMON uses the kernel's `unsigned long` for several values. Userspace pointer
width does not reveal kernel width when a 32-bit process controls a 64-bit
kernel. The match-all helper therefore probes `u64::MAX` and falls back to
`u32::MAX` only when the kernel reports a numeric range rejection. Other `u64`
values, including monitoring-region bounds, are represented as `u64` and sent
without a userspace-`usize` restriction. The kernel validates its native
range.

Linux 7.2 is the source-verified baseline, not a hard-coded version gate. Older
kernels may work when they expose the required paths. Kernel-backed VM tests
across maintained LTS releases are planned before declaring a broad kernel
support matrix.
