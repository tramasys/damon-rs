# Changelog

This project follows Semantic Versioning and Keep a Changelog.

## [Unreleased]

### Added

- Safe typed access to DAMON admin sysfs
- High-level single-process virtual-address monitoring
- Match-all DAMOS snapshot queries with sparse region and probe parsing
- Raw address-unit results and checked byte-scaled views
- Four-state discovery for all 57 official `damo` sysfs capabilities
- Validated owned Linux 7.2 configurations with read and staging support
- Typed probe weights and preparations, operation attributes, and sample controls
- Transactional whole-hierarchy staging with read-back verification and exact
  rollback of known and unknown writable attributes
- Generic exclusive sessions with runtime commands, explicit close, and
  restoration of preceding stopped configurations
- Advisory locking, ownership fingerprints, rollback, and cleanup
- CI for formatting, linting, tests, docs, packaging, MSRV, architectures, and
  dependency policy

### Changed

- Preserve unknown kernel operations, actions, and configuration paths
- Match kernel numeric widths for sizes, access counts, and ages
- Distinguish core-unit region sizes from byte-sized huge-page filters
- Adapt staging to attributes present on the running kernel
- Normalize split filter layouts and write only changed configuration leaves
- Report configuration mismatches with the path and both values
- Support snapshots without `total_bytes` and monitoring without tried-region
  queries
- Distinguish unstaged, unsupported, and unverified capabilities
- Confirm legacy operations only through authoritative listings or successful
  startup
- Probe semantic scheme and monitoring filter values
- Serialize cooperating sessions and recheck ownership around lifecycle and
  snapshot operations
- Route the single-process monitor through the generic session engine
- Model kernel reconstruction, active state, errors, and races in tests
