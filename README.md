# opsec-check

Umbrella **privacy / OPSEC audit** CLI for Linux. It runs built-in, read-only checks and optionally shells out to sibling tools when they are on `PATH`:

`macrandom` · `mullvadctl` · `dnscheck` · `netidentity` · `metaclean` · `browserprivacy` · `fileshred`

## Honesty first

- Findings are classified only as **informational**, **attention recommended**, or **configuration issue**.
- There is **no** fake 0–100 “privacy score.”
- Every finding includes *why it matters* and, where relevant, *limitations*.
- Passing checks does **not** mean you are anonymous.

## Install

```bash
cargo install --path .
# or: nix build .#opsec-check
```

XDG paths: config `~/.config/opsec-check/config.json`, data `~/.local/share/opsec-check/`.

## Usage

```bash
opsec-check                  # default audit (text)
opsec-check --json
opsec-check --markdown
opsec-check --html
opsec-check --dry-run        # do not invoke sibling binaries
opsec-check --no-metadata-sample
opsec-check tools
opsec-check completions bash
```

Global flags: `--help` `--version` `--json` `--markdown` `--html` `--verbose` `--quiet` `--config` `--dry-run`.

Exit codes: `0` success / only informational · `2` attention recommended · `3` configuration issue · `130` interrupted.

## What it checks

| Area | Notes |
|------|--------|
| Network identity | Sibling `netidentity` when present; local iface inventory |
| VPN | Explicit Mullvad connected status / WireGuard hints |
| DNS | `/etc/resolv.conf` + sibling `dnscheck` |
| MAC | Sysfs LAA bit + sibling `macrandom` |
| Firewall | nft / ufw / firewalld best-effort |
| Listening services | `ss -tuln` heuristic |
| Browser privacy | Profile path hints + sibling `browserprivacy` |
| File metadata | Shallow sample of Pictures/Downloads/Documents |
| Hostname | Leak-style uniqueness hints |
| IPv6 / mDNS | Dual-stack & Avahi/resolved hints |
| Bluetooth | `bluetoothctl show` when available |
| Wi-Fi | sysfs wireless + nmcli/iw |
| Camera / mic | `/dev/video*`, wpctl/pactl |
| Disk / swap encryption | lsblk / cryptsetup / `/proc/swaps` |
| Removable storage | `/sys/block/*/removable`, media mounts |
| NixOS | `/etc/nixos`, flakes, `/nix/store` |

Mullvad CLI hints require an explicit connected state on the first nonempty status line. Disconnected, transitional, error, and unrecognized output do not count as connected. Interface hints remain best-effort and do not verify traffic routing or leak protection.

## Config example

`~/.config/opsec-check/config.json`:

```json
{
  "metadata_sample_dirs": ["Desktop"],
  "metadata_max_files": 24,
  "skip_sibling_tools": false
}
```

## License

MIT — see [LICENSE](LICENSE).
