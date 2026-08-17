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

