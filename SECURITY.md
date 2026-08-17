# Security policy

Report vulnerabilities through GitHub private vulnerability reporting. Do not
post secrets, memory contents, or identifying process data in public issues.

DAMON admin sysfs is privileged and system-global. Do not expose low-level
mutation methods to untrusted callers.

High-level sessions use `/run/lock/damon-rs.lock`. All cooperating controllers
must share that lock or equivalent coordination. The crate also verifies
configuration and kdamond identity, but cannot stop another privileged process
from ignoring the lock.
