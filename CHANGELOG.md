# Changelog

This project follows Semantic Versioning and Keep a Changelog.

## [Unreleased]

### Added

- Safe typed access to DAMON admin sysfs
- High-level `vaddr`, `fvaddr`, and `paddr` workflow builders
- Optional initial regions, probes, and custom DAMOS schemes in high-level
  workflows
- Runtime custom-scheme statistics and effective quota reads
- Batched all-scheme statistics and effective quota reads
- Match-all DAMOS snapshot queries with sparse region and probe parsing
- Raw address-unit results and checked byte-scaled views
- Four-state discovery for all 57 official `damo` sysfs capabilities
- Validated owned Linux 7.2 configurations with read and staging support
- Typed probe weights and preparations, operation attributes, and sample controls
- Transactional whole-hierarchy staging with read-back verification and exact
  rollback of known and unknown writable attributes
- Generic exclusive sessions with runtime commands, explicit close, and
  restoration of preceding stopped configurations
- Managed multi-kdamond lifecycle with per-thread identity checks, partial-start
  rollback, selected online updates, and exact hierarchy restoration
- Persistent start, receipt serialization, verified attach, online update, and
  partial-stop recovery
- Indexed ownership-safe runtime access for managed kdamonds
- Transactional quota-goal-only updates with rollback
- Multiple-process vaddr and fvaddr workflows with target-scoped or honest
  scheme-scoped snapshots
- Lossless configuration observations that include unknown writable attributes
- Cached and owned snapshot results with completion timing
- Deadline-aware snapshot requests that preserve the monitor on worker failure
- Snapshot apply-interval inspection and periodic result refresh configuration
- Transactional online configuration updates and checked read and runtime batches
- Public string parsing for typed and future ABI values
- Exact, floor, ceiling, and covering byte-to-address-unit conversions
- Advisory locking, ownership fingerprints, rollback, and cleanup
- CI for formatting, linting, tests, docs, packaging, MSRV, architectures, and
  dependency policy

### Changed

- Preserve unknown kernel operations, actions, and configuration paths
- Match kernel numeric widths for sizes, access counts, and ages
- Model `max_nr_snapshots` as a scheme application limit rather than retained
  result storage
- Distinguish core-unit region sizes from byte-sized huge-page filters
- Adapt staging to attributes present on the running kernel
- Normalize split filter layouts and write only changed configuration leaves
- Preserve unified, core, and operation filter placement and execution order
- Separate staged-shape validation from current runnable invariants
- Restore stopped configurations around exclusive capability probing
- Report configuration mismatches with the path and both values
- Support snapshots without `total_bytes` and monitoring without tried-region
  queries
- Distinguish unstaged, unsupported, and unverified capabilities
- Confirm legacy operations only through authoritative listings or successful
  startup
- Probe semantic scheme and monitoring filter values
- Serialize cooperating sessions and recheck ownership around lifecycle and
  snapshot operations
- Route all high-level workflows through the generic session engine
- Validate scaled and kernel-aligned initial regions before staging
- Aggregate capabilities across custom schemes and gate optional runtime reads
- Install snapshot query schemes on demand when online commits are available
- Model kernel reconstruction, active state, errors, and races in tests
