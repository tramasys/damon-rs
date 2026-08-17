# Security policy

The crate has not yet reached a stable release. Security fixes are applied to
the latest development version.

Please report suspected vulnerabilities privately through GitHub's private
vulnerability reporting feature once the repository is hosted. Do not include
secrets, production memory contents, or identifying process data in a public
issue.

DAMON's admin sysfs interface is privileged and system-global. Applications
must treat access to it as administrative authority, coordinate with other
DAMON controllers, and avoid exposing untrusted callers to raw low-level
mutation methods.

High-level sessions use `/run/lock/damon-rs.lock` by default. Keep the lock
file's parent directory trusted, and make every cooperating DAMON controller
use the same lock, directly or through a wrapper. A process with permission to
mutate DAMON sysfs can ignore that lock, so the crate also rechecks the staged
configuration and kdamond thread ID but cannot guarantee exclusive ownership.
