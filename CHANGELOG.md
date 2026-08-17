# Changelog

All notable changes will be documented here. This project follows Semantic
Versioning and the Keep a Changelog structure.

## [Unreleased]

### Added

- Initial dependency-free crate infrastructure.
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
