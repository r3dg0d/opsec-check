use crate::checks::CheckCtx;
use crate::finding::{Finding, Severity};
use crate::tools;

pub fn check(ctx: &CheckCtx<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut active = Vec::new();

    if tools::command_exists("mullvadctl") {
        if let Some(out) = tools::run_sibling("mullvadctl", &["status"], ctx.dry_run) {
            let lower = out.to_lowercase();
            if lower.contains("connected") {
                active.push("mullvadctl:connected".to_string());
            }
            findings.push(
                Finding::new(
                    "vpn.mullvadctl",
                    "vpn",
                    Severity::Informational,
                    "mullvadctl status sampled",
                    "VPN state changes your egress identity. Knowing whether a trusted tunnel \
is up is basic OPSEC hygiene — it is not proof of anonymity.",
                    out.chars().take(600).collect::<String>(),
                )
                .with_tool("mullvadctl"),
            );
        }
    } else if tools::command_exists("mullvad") {
        if let Some(out) = crate::checks::cmd_out("mullvad", &["status"]) {
            if out.to_lowercase().contains("connected") {
                active.push("mullvad:connected".into());
            }
            findings.push(
                Finding::new(
                    "vpn.mullvad",
                    "vpn",
                    Severity::Informational,
                    "Official mullvad CLI present",
                    "Vendor CLI reports tunnel state; still verify kill-switch / DNS separately.",
                    out.chars().take(600).collect::<String>(),
                )
                .with_hints(["Consider mullvadctl for scripted status in this toolkit."]),
            );
        }
    }

    // WireGuard interfaces
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("wg") || name.starts_with("mullvad") || name.contains("wireguard") {
                let state =
                    crate::checks::read_trimmed(&e.path().join("operstate").to_string_lossy())
                        .unwrap_or_else(|| "?".into());
                if state == "up" {
                    active.push(format!("{name}:up"));
                }
            }
        }
    }

    if tools::command_exists("wg") {
        if let Some(ifaces) = crate::checks::cmd_out("wg", &["show", "interfaces"]) {
            for iface in ifaces.split_whitespace() {
                active.push(format!("wg-tool:{iface}"));
            }
        }
    }

    if active.is_empty() {
        findings.push(
            Finding::new(
                "vpn.none_detected",
                "vpn",
                Severity::AttentionRecommended,
                "No active VPN/WireGuard hints detected",
                "Without a tunnel, your ISP (and often the destination) sees your real \
egress IP. That may be fine for your threat model — flagging absence is not a judgment.",
                "Checked mullvad(ctl), wg interfaces, and common WireGuard NIC names.",
            )
            .with_limitation(
                "OpenVPN/custom tunnels may use arbitrary interface names and be missed.",
            )
            .with_hints([
                "If you use Mullvad, install mullvadctl or ensure `mullvad status` works.",
            ]),
        );
    } else {
        findings.push(
            Finding::new(
                "vpn.active",
                "vpn",
                Severity::Informational,
                "VPN/tunnel hints present",
                "An up tunnel changes egress IP but does not hide all leaks (DNS, WebRTC, IPv6).",
                active.join(", "),
            )
            .with_limitation("Does not verify kill-switch, DNS leak protection, or multi-hop."),
        );
    }

    findings
}
