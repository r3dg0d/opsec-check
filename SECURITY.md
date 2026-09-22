# Security Policy

## Reporting

Email or open a private advisory with reproduction steps. Do not file public issues for unfixed RCE / privilege issues.

## Scope notes

`opsec-check` is intentionally **read-only**. It may invoke sibling CLIs when present. Treat those tools’ own security policies as part of the trust boundary.

Do not run untrusted config JSON. Config is local and user-controlled.
