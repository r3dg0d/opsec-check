use crate::finding::{Finding, Severity};
use crate::tools;

pub fn check() -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut backends = Vec::new();

    if tools::command_exists("nft") {
        if let Some(out) = crate::checks::cmd_out("nft", &["list", "ruleset"]) {
            let rules = out.lines().count();
            backends.push(format!("nftables lines≈{rules}"));
            let sev = if rules < 5 {
                Severity::AttentionRecommended
            } else {
                Severity::Informational
            };
            findings.push(
                Finding::new(
                    "firewall.nft",
                    "firewall",
                    sev,
                    "nftables ruleset present",
                    "A host firewall limits unexpected inbound/outbound exposure. Empty or \
tiny rulesets often mean you rely entirely on NAT or the VPN kill-switch.",
                    format!("Approximate rule lines: {rules} (truncated)"),
                )
                .with_limitation("May need root for full ruleset; output truncated."),
            );
        } else {
            backends.push("nft present but no readable ruleset".into());
        }
    }

    if tools::command_exists("ufw") {
        if let Some(out) = crate::checks::cmd_out("ufw", &["status"]) {
            let lower = out.to_lowercase();
            let sev = if lower.contains("inactive") {
                Severity::AttentionRecommended
            } else {
                Severity::Informational
            };
            findings.push(Finding::new(
                "firewall.ufw",
                "firewall",
                sev,
                "UFW status sampled",
                "UFW is a common frontend; inactive means no UFW-enforced filtering.",
                out.chars().take(400).collect::<String>(),
            ));
            backends.push("ufw".into());
        }
    }

    if tools::command_exists("firewall-cmd") {
        if let Some(out) = crate::checks::cmd_out("firewall-cmd", &["--state"]) {
            findings.push(Finding::new(
                "firewall.firewalld",
                "firewall",
                Severity::Informational,
                "firewalld state sampled",
                "firewalld state is one signal among several possible firewall stacks.",
                out,
            ));
            backends.push("firewalld".into());
        }
    }

    if findings.is_empty() {
        findings.push(
            Finding::new(
                "firewall.unknown",
                "firewall",
                Severity::AttentionRecommended,
                "No nft/ufw/firewalld status obtained",
                "Unable to confirm host filtering. Cloud VMs and desktops often expose \
SSH or other services unintentionally.",
                "Install/use nftables, ufw, or firewalld — or confirm VPN kill-switch covers you.",
            )
            .with_limitation("Lack of detection ≠ lack of firewall (e.g. iptables-only, remote)."),
        );
    }

    let _ = backends;
    findings
}
