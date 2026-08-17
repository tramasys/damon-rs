# Changelog

All notable changes will be documented here. This project follows Semantic
Versioning and the Keep a Changelog structure.

## [Unreleased]

### Added

- Initial crate infrastructure with a safe direct Linux syscall dependency.
- Typed DAMON sysfs primitives and capability discovery.
- High-level single-PID virtual-address monitoring lifecycle.
- Query snapshots backed by a match-all DAMOS `stat` scheme.
- Strict CI, MSRV checks, package verification, and dependency policy.
- Indexed probe results that preserve sparse kernel directory numbers without
  imposing the current kernel's probe-count limit on the public API.
- Independent reported and materialized snapshot totals with completeness
  reporting.
- Exclusive capability probing that temporarily stages representative indexed
  children and restores an empty hierarchy.
- A sorted concrete-attribute inventory that preserves paths unknown to this
  crate version.
- Typed coverage and exact-name lookup for all 57 official `damo` sysfs
  capability concepts.

### Changed

- Discover optional sysfs support as concrete `SysfsFeature` paths.
- Preserve unknown future DAMOS actions and expose symmetric low-level reads.
- Select match-all limits from the kernel ABI width instead of userspace
  `usize`.
- Document tried regions in kernel materialization order across targets.
- Submit every sysfs attribute value in one complete write.
- Retry transient kernel busy responses during lifecycle operations.
- Support tried-region snapshots on kernels without `total_bytes`.
- Accept zero monitoring intervals as supported by the kernel ABI.
- Bound eager snapshot allocation independently of configured region limits.
- Preserve externally changed configurations during monitor cleanup.
- Preserve raw DAMON address units and provide checked byte conversions.
- Use `u32` access-count and age ranges to match the active kernel ABI.
- Preserve tried-region probe hits in snapshot regions.
- Distinguish unsupported capabilities from paths requiring staged children.
- Serialize cooperating sessions with an advisory lock and verify staged
  configuration and kdamond identity before destructive lifecycle operations.
- Return raw low-level snapshots without inferring a byte scale from mutable
  staged context attributes.
- Track the effective committed address unit in high-level sessions and
  recheck ownership after snapshot materialization and result reads.
- Enforce region and snapshot invariants through private fields and checked
  crate-internal construction.
- Exercise lifecycle behavior with an internal sysfs state-machine backend,
  including staged and active inputs, directory reconstruction, kernel-thread
  identity transitions, and deterministic race hooks.
- Fingerprint every writable configuration attribute materialized by the
  running kernel while excluding command and result files.
- Remove the unlocked low-level handle from the high-level `Damon` entry point.
- Represent scaled regions as allocation-free borrowed views over one owned raw
  snapshot.
- Model quota-goal-only commits and running-kdamond reconstruction failures
  according to the kernel state machine.
- Run documentation tests explicitly in CI.
- Disable and verify periodic sysfs refresh for exclusively owned sessions.
- Verify captured ownership values with streaming comparisons without
  rebuilding or allocating a new fingerprint on each check.
- Match Linux state-transition errors, scheme defaults, and indexed quota,
  filter, and destination layouts in the modeled sysfs backend.
- Stage optional default-valued attributes only when the running kernel exposes
  them, including refresh, address unit, pause, probes, obsolete targets,
  initial regions, and scheme apply intervals.
- Parse tried-region and probe directories by numerically sorting the entries
  that actually exist instead of stopping at the first missing index.
- Start and manage monitors on older admin-sysfs kernels without tried-region
  queries, returning an unsupported-feature error only from snapshot requests.
- Report accepted legacy operation writes as unverified when the hierarchy does
  not expose authoritative `avail_operations`, then restore the original
  operation. A successful monitor start confirms the selected operation.
- Probe semantic DAMOS and monitoring-probe filter values in representative
  staged children instead of inferring support from a shared `type` path.
