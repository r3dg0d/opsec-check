use crate::checks::CheckCtx;
use crate::finding::{Finding, Severity};
use crate::tools;

pub fn check(ctx: &CheckCtx<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();

    if tools::command_exists("dnscheck") {
        let detail = tools::run_sibling("dnscheck", &["report"], ctx.dry_run)
            .or_else(|| tools::run_sibling("dnscheck", &["status"], ctx.dry_run))
            .unwrap_or_else(|| "dnscheck present".into());
        findings.push(
            Finding::new(
                "dns.sibling",
                "dns",
                Severity::Informational,
                "dnscheck available — prefer it for DNS privacy analysis",
                "DNS queries reveal nearly every hostname you visit. Local stub resolvers, \
ISP forwarders, and DoH settings matter more than most users expect.",
                detail.chars().take(800).collect::<String>(),
            )
            .with_tool("dnscheck"),
        );
    }

    let resolv = crate::checks::read_trimmed("/etc/resolv.conf").unwrap_or_default();
    if resolv.is_empty() {
        findings.push(Finding::new(
            "dns.no_resolv",
            "dns",
            Severity::AttentionRecommended,
            "/etc/resolv.conf missing or empty",
            "Unusual resolver state can mean systemd-resolved, a VPN, or a break.",
            "Could not read nameserver lines from /etc/resolv.conf",
        ));
        return findings;
    }

    let mut nameservers = Vec::new();
    for line in resolv.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("nameserver") {
            nameservers.push(rest.trim().to_string());
        }
    }

    let mut severity = Severity::Informational;
    let mut notes = Vec::new();
    for ns in &nameservers {
        if ns == "127.0.0.1" || ns == "::1" || ns.starts_with("127.") {
            notes.push(format!("{ns} (local stub — inspect systemd-resolved/VPN)"));
        } else if ns.starts_with("8.8.") || ns.starts_with("1.1.1.") || ns.starts_with("9.9.9.") {
            notes.push(format!("{ns} (public resolver)"));
            severity = Severity::AttentionRecommended;
        } else {
            notes.push(ns.clone());
            // Private RFC1918 often means router/ISP CPE
            if ns.starts_with("192.168.") || ns.starts_with("10.") || ns.starts_with("172.") {
                severity = Severity::AttentionRecommended;
                notes.push("(looks like LAN/CPE — may be ISP-visible DNS)".into());
            }
        }
    }

    findings.push(
        Finding::new(
            "dns.resolv",
            "dns",
            severity,
            format!("{} nameserver(s) in resolv.conf", nameservers.len()),
            "Whoever answers your DNS sees query names. ISP CPE DNS and plaintext UDP/53 \
are common leak paths even when a VPN is 'connected'.",
            if notes.is_empty() {
                resolv.chars().take(500).collect()
            } else {
                notes.join("; ")
            },
        )
        .with_limitation(
            "Does not perform active leak probes; use dnscheck --probe when intentional.",
        )
        .with_tool("dnscheck")
        .with_hints([
            "Prefer VPN-provided DNS or a trusted encrypted resolver with leak protection.",
        ]),
    );

    findings
}
