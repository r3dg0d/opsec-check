//! Built-in OPSEC checks. Each returns zero or more Findings.
//! Checks are read-only and best-effort; missing tools become informational.

mod bluetooth;
mod browser;
mod camera_mic;
mod disk;
mod dns;
mod firewall;
mod hostname;
mod ipv6_mdns;
mod listening;
mod mac;
mod metadata;
mod network;
mod nixos;
mod removable;
mod vpn;
mod wifi;

use crate::config::Config;
use crate::finding::Finding;

pub struct CheckCtx<'a> {
    pub cfg: &'a Config,
    pub dry_run: bool,
    pub no_metadata_sample: bool,
}

pub fn run_all(ctx: &CheckCtx<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(hostname::check());
    out.extend(network::check(ctx));
    out.extend(vpn::check(ctx));
    out.extend(dns::check(ctx));
    out.extend(mac::check(ctx));
    out.extend(firewall::check());
    out.extend(listening::check());
    out.extend(ipv6_mdns::check());
    out.extend(wifi::check());
    out.extend(bluetooth::check());
    out.extend(camera_mic::check());
    out.extend(disk::check());
    out.extend(removable::check());
    out.extend(browser::check(ctx));
    if !ctx.no_metadata_sample {
        out.extend(metadata::check(ctx));
    }
    out.extend(nixos::check());
    out
}

pub(crate) fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub(crate) fn cmd_out(bin: &str, args: &[&str]) -> Option<String> {
    if !crate::tools::command_exists(bin) {
        return None;
    }
    let out = crate::process::output(bin, args).ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        let e = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if e.is_empty() {
            None
        } else {
            Some(e.chars().take(2000).collect())
        }
    } else {
        Some(s.chars().take(2000).collect())
    }
}
