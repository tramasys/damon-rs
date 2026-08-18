# DAMON sysfs behavior

This document records kernel behavior that is important when using the crate.
It complements the typed API and is kept independent of a specific kernel
release.

## Ownership and transactions

DAMON admin sysfs is privileged and system-global. The kernel does not expose
an ownership primitive. Scoped and persistent operations therefore use a
cooperative advisory lock and verify the writable hierarchy and kdamond thread
IDs around mutations.

Scoped sessions capture the preceding stopped hierarchy and restore it when
closed. Managed hierarchies apply the same model to multiple kdamonds. Starts
run in index order and capture each thread ID immediately. A partial start is
rolled back in reverse order, and stop commands are sent only to identities
that still match.

Persistent operations store the complete writable hierarchy, running thread
IDs, paths, and Linux boot ID in a receipt. Each attach, update, or stop
operation reacquires the lock and verifies the receipt. A receipt is evidence
of previously observed state, not continuous ownership.

Configuration is validated before staging. The crate reads back staged values
and restores known and unknown writable attributes after a failed transaction.
Auto-tuned sampling and aggregation intervals are treated as volatile while
kernel interval tuning is enabled.

Controllers that ignore the advisory lock can still race these checks. The
crate reports ownership loss rather than stopping or restoring a hierarchy it
can no longer identify.

## Snapshots

Tried-region materialization uses the kdamond state command and is synchronous.
The write may block until configured schemes reach their next apply interval.
The sysfs ABI provides no cancellation operation. A pending `SnapshotRequest`
therefore retains its monitor, and dropping the request waits for the worker to
finish.

Cached result methods read values already materialized by the kernel and issue
no refresh command. `Monitor::maximum_snapshot_apply_interval()` returns a
scheduling hint, not a timeout.

Ordinary tried-region output does not include a target identifier. A result is
target-scoped only when one target is the sole possible source or a target
filter isolates it. Otherwise high-level results use `SnapshotScope::Scheme`.
The crate does not infer target identity from address ranges.

Region and probe directories may be sparse and are read in numeric index
order. When the kernel exposes an independent tried-size total,
`SnapshotCompleteness` compares it with the materialized regions. Without that
total, completeness is unverifiable.

## Numeric representation

DAMON addresses and sizes use kernel `unsigned long`. The crate stores them as
`u64` and checks the active kernel range when values are staged. Access counts
and ages use `u32` to match the kernel data structures.

Address and size fields use DAMON core units. A context address unit affects
physical-address monitoring, while virtual-address workflows use a unit of
one. Low-level snapshots retain raw units until the caller supplies the known
effective unit. Byte conversion checks overflow and makes exact or rounded
conversion explicit.

Initial regions are checked for ordering, overlap, kernel alignment, native
range, and scaled-address overflow before staging. Huge-page filter sizes are
always byte values and are not scaled by the context address unit.

`stats/max_nr_snapshots` is an application limit. Reaching it deactivates
further scheme application. It is not a retained-result count.

## Compatibility

The crate probes paths, files, accepted values, and staged behavior instead of
selecting behavior from a kernel version. Capability discovery distinguishes
supported, unsupported, unstaged, and unverified features. Unknown operation
names, actions, enum values, and writable configuration paths are preserved
where the ABI permits it.

The public low-level API allows partial hierarchies and direct control. Owned
configuration and high-level workflows apply stricter validation before
mutation. The crate targets admin sysfs only and does not implement the legacy
debugfs interface.
