use crate::finding::{Finding, Severity};

pub fn check() -> Vec<Finding> {
    let mut findings = Vec::new();
    let host = read_hostname();
    let pretty = crate::checks::read_trimmed("/etc/hostname").unwrap_or_else(|| host.clone());

    let lower = pretty.to_lowercase();
    let looks_personal = lower.contains("vincent")
        || lower.contains("laptop")
        || pretty.contains(' ')
        || (pretty.chars().any(|c| c.is_uppercase()) && pretty.contains('-'));

    let severity = if looks_personal {
        Severity::AttentionRecommended
    } else {
        Severity::Informational
    };

    findings.push(
        Finding::new(
            "hostname.leak",
            "hostname",
            severity,
            format!("Hostname is '{pretty}'"),
            "Hostnames often appear in DHCP requests, mDNS, shell prompts, and some TLS \
client fingerprints. A personal or unique name helps correlate sessions across networks.",
            format!("Resolved hostname: {host}; /etc/hostname: {pretty}"),
        )
        .with_limitation(
            "Cannot see what remote DHCP/DNS servers logged; only local configuration.",
        )
        .with_hints([
            "Consider a generic hostname (e.g. workstation, nixbox).",
            "Disable mDNS if you do not need LAN discovery.",
        ]),
    );
    findings
}

fn read_hostname() -> String {
    if let Some(s) = crate::checks::read_trimmed("/etc/hostname") {
        return s;
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}
