# Changelog

## Unreleased

- Require explicit Mullvad connected status instead of matching incidental text or `Disconnected`.
- Add fixture coverage for official and companion status, transitional states, errors, and malformed output.

## 0.1.0 — 2026-09-22

- Initial release: built-in OPSEC checks + optional sibling tool invocation.
- Output formats: text, JSON, Markdown, HTML.
- Severity labels only (informational / attention recommended / configuration issue).
- Completions, XDG config, flake.nix, CI.
