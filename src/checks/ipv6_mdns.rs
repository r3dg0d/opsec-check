use crate::finding::{Finding, Severity};
use crate::tools;

pub fn check() -> Vec<Finding> {
    let mut findings = Vec::new();

    // IPv6: any global-looking addr on interfaces?
    let mut v6 = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc/net/if_inet6") {
        let _ = entries; // file not dir
    }
    if let Ok(text) = std::fs::read_to_string("/proc/net/if_inet6") {
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let iface = parts[5];
                if iface != "lo" {
                    v6.push(iface.to_string());
                }
            }
        }
    }
    v6.sort();
    v6.dedup();

    if v6.is_empty() {
        findings.push(Finding::new(
            "ipv6.none",
            "ipv6",
            Severity::Informational,
            "No non-loopback IPv6 addresses in /proc/net/if_inet6",
            "Disabled IPv6 can reduce dual-stack leak risk; it can also break networks that need it.",
            "IPv6 appears unused on this host (or unreadable).",
        ));
    } else {
        findings.push(
            Finding::new(
                "ipv6.present",
                "ipv6",
                Severity::AttentionRecommended,
                format!("IPv6 present on: {}", v6.join(", ")),
                "IPv6 can bypass IPv4-only VPN routes and DNS settings, leaking real egress \
or unique addresses (SLAAC) that fingerprint the device.",
                "Review VPN IPv6 support and `ip -6 route`.",
            )
            .with_limitation("Does not test whether traffic actually egresses via IPv6."),
        );
    }

    // mDNS / Avahi
    let avahi = tools::command_exists("avahi-daemon")
        || std::path::Path::new("/run/avahi-daemon").exists()
        || crate::checks::cmd_out("systemctl", &["is-active", "avahi-daemon"])
            .map(|s| s.contains("active"))
            .unwrap_or(false);

    let resolved_mdns = crate::checks::cmd_out("resolvectl", &["status"])
        .map(|s| s.to_lowercase().contains("mdns"))
        .unwrap_or(false);

    if avahi || resolved_mdns {
        findings.push(
            Finding::new(
                "mdns.active",
                "mdns",
                Severity::AttentionRecommended,
                "mDNS / Avahi hints detected",
                "mDNS publishes hostname and services on the LAN, aiding device tracking \
and reconnaissance on shared networks.",
                format!("avahi_hint={avahi}; resolved_mdns_text={resolved_mdns}"),
            )
            .with_hints([
                "Disable avahi-daemon if unused.",
                "On systemd-resolved, consider LLMNR=no and MulticastDNS=no.",
            ]),
        );
    } else {
        findings.push(Finding::new(
            "mdns.quiet",
            "mdns",
            Severity::Informational,
            "No strong mDNS/Avahi activity detected",
            "Good default for hostile LANs; verify printer/IoT discovery still works if needed.",
            "Checked avahi paths and resolvectl text.",
        ));
    }

    findings
}
