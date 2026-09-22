use crate::checks::CheckCtx;
use crate::finding::{Finding, Severity};
use crate::tools;

pub fn check(ctx: &CheckCtx<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Prefer netidentity sibling
    if tools::command_exists("netidentity") {
        let detail = tools::run_sibling("netidentity", &["report", "--json"], ctx.dry_run)
            .or_else(|| tools::run_sibling("netidentity", &["--help"], ctx.dry_run))
            .unwrap_or_else(|| "netidentity present".into());
        findings.push(
            Finding::new(
                "network.sibling",
                "network_identity",
                Severity::Informational,
                "netidentity available for deeper network fingerprinting",
                "External IP, DNS, and egress identity are strongest correlation signals. \
A dedicated tool gives a fuller picture than a quick umbrella check.",
                detail.chars().take(800).collect::<String>(),
            )
            .with_tool("netidentity")
            .with_limitation("opsec-check does not claim to measure anonymity."),
        );
    } else {
        findings.push(
            Finding::new(
                "network.no_sibling",
                "network_identity",
                Severity::Informational,
                "netidentity not on PATH",
                "Without a network identity helper, only coarse local interface state is shown.",
                "Install netidentity for public IP / DNS / VPN correlation snapshots.",
            )
            .with_tool("netidentity"),
        );
    }

    // Local interfaces snapshot
    let mut ifaces = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            let state = crate::checks::read_trimmed(&format!("/sys/class/net/{name}/operstate"))
                .unwrap_or_else(|| "?".into());
            ifaces.push(format!("{name}:{state}"));
        }
    }
    findings.push(
        Finding::new(
            "network.ifaces",
            "network_identity",
            Severity::Informational,
            format!("{} non-loopback interface(s)", ifaces.len()),
            "Interface names and state are local context for VPN/MAC checks.",
            if ifaces.is_empty() {
                "No interfaces found under /sys/class/net".into()
            } else {
                ifaces.join(", ")
            },
        )
        .with_limitation("Does not enumerate IPv4/IPv6 addresses by default (reduces log noise)."),
    );

    findings
}
