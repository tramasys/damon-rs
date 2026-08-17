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
kdamonds/0/contexts/nr_contexts                           <- 1
kdamonds/0/contexts/0/avail_operations                    -> require vaddr
kdamonds/0/contexts/0/operations                          <- vaddr
kdamonds/0/contexts/0/monitoring_attrs/intervals/*         <- intervals
kdamonds/0/contexts/0/monitoring_attrs/nr_regions/{min,max}<- bounds
kdamonds/0/contexts/0/targets/nr_targets                  <- 1
kdamonds/0/contexts/0/targets/0/pid_target                <- PID
kdamonds/0/contexts/0/schemes/nr_schemes                  <- 1
kdamonds/0/contexts/0/schemes/0/action                    <- stat
kdamonds/0/contexts/0/schemes/0/access_pattern/*/{min,max} <- match all
kdamonds/0/state                                           <- on
```

The kernel creates and destroys indexed directories when each `nr_*` file is
written. The high-level API therefore refuses to begin when any kdamond is
already staged and rolls `nr_kdamonds` back to zero if setup fails.

## Snapshot semantics

The admin sysfs interface does not expose the context's live region list as a
simple file. Query-style retrieval uses DAMOS tried regions:

1. Configure a `stat` scheme whose access pattern covers the desired regions.
2. Write `update_schemes_tried_regions` to `kdamonds/0/state`.
3. Read `schemes/0/tried_regions/total_bytes` when the kernel exposes it.
4. Read consecutive indexed region directories containing `start`, `end`,
   `nr_accesses`, `age`, and, on newer kernels, `sz_filter_passed`.

Kernels with tried-region queries but no `total_bytes` file are supported by
summing the validated materialized region sizes in userspace. This matches the
compatibility distinction made by the official `damo` implementation.

The command can wait until the next scheme apply interval. A zero
`apply_interval_us` uses the aggregation interval. `nr_accesses` is a count per
aggregation interval and `age` is measured in aggregation intervals. Neither
is a byte-normalized density.

## Validated invariants

The userspace types enforce kernel invariants before writing:

- PID is in `1..=i32::MAX`.
- intervals are whole microseconds that fit `unsigned long`. Zero is valid.
- sampling interval does not exceed aggregation interval.
- minimum regions is at least three.
- minimum regions does not exceed maximum regions.
- returned region end is not below its start.

Linux 7.2 defaults are 5,000 microseconds sampling, 100,000 microseconds
aggregation, 60,000,000 microseconds operations update, and 10 to 1,000
regions. The crate uses the same defaults.

## Compatibility policy

The ABI grows over time, so known operation names are typed while unknown names
are preserved. Optional paths such as `refresh_ms`, context `pause`,
`addr_unit`, probes, scheme apply intervals, and tried-region queries are
detected from the populated hierarchy.

Linux 7.2 is the source-verified baseline, not a hard-coded version gate. Older
kernels may work when they expose the required paths. Kernel-backed VM tests
across maintained LTS releases are planned before declaring a broad kernel
support matrix.
