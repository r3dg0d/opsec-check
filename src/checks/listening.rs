use crate::finding::{Finding, Severity};
use crate::tools;

pub fn check() -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut detail = String::new();

    if tools::command_exists("ss") {
        if let Some(out) = crate::checks::cmd_out("ss", &["-tuln"]) {
            detail = out;
        }
    } else if tools::command_exists("netstat") {
        if let Some(out) = crate::checks::cmd_out("netstat", &["-tuln"]) {
            detail = out;
        }
    }

    if detail.is_empty() {
        findings.push(Finding::new(
            "listening.unavailable",
            "listening",
            Severity::Informational,
            "Could not list listening sockets",
            "ss/netstat missing or unreadable; skipping exposure check.",
            "Install iproute2 (ss) for local service inventory.",
        ));
        return findings;
    }

    let mut publicish = Vec::new();
    for line in detail.lines().skip(1) {
        let lower = line.to_lowercase();
        if lower.contains("0.0.0.0:")
            || lower.contains("[::]:")
            || lower.contains("*:")
            || lower.contains(":::.")
        {
            // extract rough port token
            publicish.push(line.trim().chars().take(120).collect::<String>());
        }
    }

    if publicish.is_empty() {
        findings.push(
            Finding::new(
                "listening.local_only",
                "listening",
                Severity::Informational,
                "No obvious 0.0.0.0/[::] listeners spotted",
                "Binding only to localhost reduces remote attack surface.",
                "Parsed ss/netstat -tuln output; see limitation.",
            )
            .with_limitation("Heuristic parse; containers/namespaces may hide sockets."),
        );
    } else {
        findings.push(
            Finding::new(
                "listening.public_bind",
                "listening",
                Severity::AttentionRecommended,
                format!(
                    "{} socket(s) appear bound on all interfaces",
                    publicish.len()
                ),
                "Services listening on 0.0.0.0 or [::] are reachable from any interface \
route — including unexpected LAN or VPN peers if firewall rules are loose.",
                publicish
                    .into_iter()
                    .take(12)
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
            .with_hints([
                "Bind services to 127.0.0.1 when possible.",
                "Confirm firewall allows only intended ports.",
            ]),
        );
    }

    findings
}
