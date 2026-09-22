use crate::finding::{Finding, Severity};
use std::path::Path;

pub fn check() -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut hits: Vec<String> = Vec::new();

    if Path::new("/etc/nixos").is_dir() {
        hits.push("/etc/nixos".into());
    }
    if Path::new("/etc/nixos/flake.nix").is_file() || Path::new("/etc/nixos/flake.lock").is_file() {
        hits.push("/etc/nixos/flake.*".into());
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = std::path::PathBuf::from(home);
        for rel in ["flake.nix", ".config/nix/flake.nix", "nixos/flake.nix"] {
            if home.join(rel).is_file() {
                hits.push(format!("$HOME/{rel}"));
            }
        }
    }
    if Path::new("/run/current-system").exists() {
        hits.push("/run/current-system".into());
    }
    if Path::new("/nix/store").is_dir() {
        hits.push("/nix/store".into());
    }

    if hits.is_empty() {
        findings.push(Finding::new(
            "nixos.absent",
            "nixos",
            Severity::Informational,
            "No NixOS/flake markers found",
            "Useful context for how configuration is managed; not a security finding.",
            "Checked /etc/nixos, flakes under HOME, /run/current-system, /nix/store.",
        ));
    } else {
        findings.push(
            Finding::new(
                "nixos.present",
                "nixos",
                Severity::Informational,
                "Nix/NixOS markers present",
                "Declarative systems make privacy hardening reproducible (firewall, resolved, MAC policies) — treat config as part of your OPSEC surface.",
                hits.join(", "),
            )
            .with_limitation(
                "Presence of Nix store does not mean the running system is NixOS.",
            )
            .with_hints([
                "Keep secrets out of world-readable nix store paths.",
                "Review networking.firewall and services.resolved in configuration.nix/flake.",
            ]),
        );
    }

    findings
}
