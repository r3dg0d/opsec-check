use crate::checks::CheckCtx;
use crate::finding::{Finding, Severity};
use crate::tools;

pub fn check(ctx: &CheckCtx<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();

    if tools::command_exists("dnscheck") {
        findings.extend(sibling_findings(ctx.dry_run, || {
            tools::run_sibling_json("dnscheck", &["report", "--json"])
        }));
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

#[derive(serde::Deserialize)]
struct DnsReport {
    tool: String,
    detection: DnsDetection,
}

#[derive(serde::Deserialize)]
struct DnsDetection {
    findings: Vec<DnsFinding>,
    cannot_detect: Vec<String>,
}

#[derive(serde::Deserialize)]
struct DnsFinding {
    id: String,
    severity: String,
    title: String,
    detail: String,
    confidence: String,
}

fn import_report(value: serde_json::Value) -> Result<Vec<Finding>, String> {
    let report: DnsReport = serde_json::from_value(value)
        .map_err(|_| "dnscheck report has an unsupported structure".to_string())?;
    if report.tool != "dnscheck" {
        return Err("report identifies a different tool".into());
    }
    let limitation = format!(
        "Configuration heuristics do not prove actual DNS traffic egress. {}",
        report.detection.cannot_detect.join(" ")
    );
    report.detection.findings.into_iter().map(|f| {
        let severity = match f.severity.as_str() {
            "info" => Severity::Informational,
            "warning" => Severity::AttentionRecommended,
            "critical" => Severity::ConfigurationIssue,
            _ => return Err("dnscheck report has an unsupported severity".into()),
        };
        if f.id.trim().is_empty() || f.title.trim().is_empty() {
            return Err("dnscheck report has an empty finding ID or title".into());
        }
        Ok(Finding::new(
            format!("dns.dnscheck.{}", f.id), "dns", severity, f.title,
            "DNS configuration determines who can observe query names; review the sibling's evidence and confidence.",
            format!("{}\nReported confidence: {}", f.detail, f.confidence),
        ).with_tool("dnscheck").with_limitation(limitation.clone()))
    }).collect()
}

fn sibling_findings(
    dry_run: bool,
    query: impl FnOnce() -> Result<serde_json::Value, String>,
) -> Vec<Finding> {
    if dry_run {
        return vec![Finding::new(
            "dns.sibling",
            "dns",
            Severity::Informational,
            "dnscheck invocation skipped",
            "Dry-run or sibling-tool configuration prevents invoking dnscheck.",
            "Would invoke: dnscheck report --json",
        )
        .with_tool("dnscheck")];
    }
    match query().and_then(import_report) {
        Ok(mut findings) => {
            let summary = Finding::new(
                "dns.sibling",
                "dns",
                Severity::Informational,
                "dnscheck report imported",
                "Structured DNS findings contribute to the umbrella audit severity.",
                format!(
                    "Imported {} finding(s); no active probes requested.",
                    findings.len()
                ),
            )
            .with_tool("dnscheck")
            .with_limitation("An empty report does not establish leak protection.");
            findings.push(summary);
            findings
        }
        Err(error) => vec![Finding::new(
            "dns.sibling_failed",
            "dns",
            Severity::AttentionRecommended,
            "dnscheck report unavailable",
            "Missing sibling evidence leaves the deeper DNS inspection incomplete.",
            error,
        )
        .with_tool("dnscheck")
        .with_limitation("Local resolver checks still run; failure does not prove a DNS leak.")],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn report(severity: &str) -> serde_json::Value {
        json!({"tool":"dnscheck", "detection": {
            "findings":[{"id":"vpn-dns-bypass", "severity":severity,
            "title":"Non-VPN resolver", "detail":"Review the resolver route",
            "confidence":"medium"}], "cannot_detect":["Actual query egress is unobserved"]
        }})
    }

    #[test]
    fn imports_all_supported_severities_and_evidence() {
        for (source, expected) in [
            ("info", Severity::Informational),
            ("warning", Severity::AttentionRecommended),
            ("critical", Severity::ConfigurationIssue),
        ] {
            let findings = sibling_findings(false, || Ok(report(source)));
            let f = &findings[0];
            assert_eq!(f.severity, expected);
            assert_eq!(f.id, "dns.dnscheck.vpn-dns-bypass");
            assert_eq!(f.related_tool.as_deref(), Some("dnscheck"));
            assert!(f.detail.contains("Review the resolver route"));
            assert!(f.detail.contains("medium"));
            assert!(f
                .limitation
                .as_ref()
                .unwrap()
                .contains("Actual query egress"));
        }
    }

    #[test]
    fn malformed_reports_become_visible_failures() {
        for value in [
            json!({}),
            json!([]),
            json!({"tool":"dnscheck"}),
            json!({"tool":"dnscheck","detection":{"findings":null,"cannot_detect":[]}}),
        ] {
            let findings = sibling_findings(false, || Ok(value));
            assert_eq!(findings[0].id, "dns.sibling_failed");
            assert_eq!(findings[0].severity, Severity::AttentionRecommended);
        }
        let mut value = report("info");
        value["tool"] = json!("other-tool");
        assert!(import_report(value).is_err());
    }

    #[test]
    fn unknown_severity_rejects_whole_report() {
        let mut value = report("warning");
        let mut unknown = value["detection"]["findings"][0].clone();
        unknown["severity"] = json!("future-level");
        value["detection"]["findings"]
            .as_array_mut()
            .unwrap()
            .push(unknown);
        let findings = sibling_findings(false, || Ok(value));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "dns.sibling_failed");
    }

    #[test]
    fn dry_run_does_not_invoke_report_query() {
        let findings = sibling_findings(true, || panic!("must not invoke"));
        assert_eq!(findings[0].severity, Severity::Informational);
        assert!(findings[0].detail.contains("report --json"));
    }

    #[test]
    fn failed_command_is_not_an_imported_report() {
        let findings = sibling_findings(false, || Err("command failed (exit status: 2)".into()));
        assert_eq!(findings[0].id, "dns.sibling_failed");
        assert!(findings[0].detail.contains("exit status: 2"));
    }

    #[test]
    fn empty_report_is_only_a_summary() {
        let value = json!({"tool":"dnscheck","detection":{"findings":[],"cannot_detect":[]}});
        let findings = sibling_findings(false, || Ok(value));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "dns.sibling");
        assert!(findings[0]
            .limitation
            .as_ref()
            .unwrap()
            .contains("does not establish"));
    }
}
