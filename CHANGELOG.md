# Changelog

## Unreleased

- Bound Unix audit commands to 10 seconds and 1 MiB combined captured output, using nonblocking pipes and dedicated process groups. Timeout/output/read failures kill the group and reap the child.
- Close command stdin; handle Ctrl+C through probe cleanup before returning exit 130. Preserve command exit statuses and existing text/JSON interpretation.
- Cover floods on both streams, exact combined limits, hung descendants, inherited pipes after leader exit, and real CLI interruption with isolated fake commands.

- Import passive dnscheck JSON findings with original evidence, confidence, limitations, and mapped severity; DNS warnings now affect umbrella audit exit codes.
- Report failed, malformed, oversized, or unsupported DNS reports as attention findings instead of treating diagnostic text as evidence.
- Add fake-sibling CLI regressions for severity propagation, report arguments, failure handling, complete JSON, and dry-run.

- Require explicit Mullvad connected status instead of matching incidental text or `Disconnected`.
- Add fixture coverage for official and companion status, transitional states, errors, and malformed output.

## 0.1.0 — 2026-09-22

- Initial release: built-in OPSEC checks + optional sibling tool invocation.
- Output formats: text, JSON, Markdown, HTML.
- Severity labels only (informational / attention recommended / configuration issue).
- Completions, XDG config, flake.nix, CI.
