# Changelog

This project follows Semantic Versioning and Keep a Changelog.

## [Unreleased]

### Added

- Safe typed access to DAMON admin sysfs
- High-level single-process virtual-address monitoring
- Match-all DAMOS snapshot queries with sparse region and probe parsing
- Raw address-unit results and checked byte-scaled views
- Four-state discovery for all 57 official `damo` sysfs capabilities
- Advisory locking, ownership fingerprints, rollback, and cleanup
- CI for formatting, linting, tests, docs, packaging, MSRV, architectures, and
  dependency policy

### Changed

- Preserve unknown kernel operations, actions, and configuration paths
- Match kernel numeric widths for sizes, access counts, and ages
- Adapt staging to attributes present on the running kernel
- Support snapshots without `total_bytes` and monitoring without tried-region
  queries
- Distinguish unstaged, unsupported, and unverified capabilities
- Confirm legacy operations only through authoritative listings or successful
  startup
- Probe semantic scheme and monitoring filter values
- Serialize cooperating sessions and recheck ownership around lifecycle and
  snapshot operations
- Model kernel reconstruction, active state, errors, and races in tests
