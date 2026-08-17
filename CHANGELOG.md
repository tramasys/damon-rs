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
