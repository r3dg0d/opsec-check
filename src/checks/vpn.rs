use crate::checks::CheckCtx;
use crate::finding::{Finding, Severity};
use crate::tools;

pub fn check(ctx: &CheckCtx<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut active = Vec::new();

    if tools::command_exists("mullvadctl") {
        if let Some(out) = tools::run_sibling("mullvadctl", &["status"], ctx.dry_run) {
            if mullvad_connected(&out) {
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
            if mullvad_connected(&out) {
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

// Both supported CLIs put the current state on their first nonempty line.
// Do not infer state from diagnostics, historical text, or substring matches.
fn mullvad_connected(output: &str) -> bool {
    let Some(line) = output.lines().map(str::trim).find(|line| !line.is_empty()) else {
        return false;
    };
    let line = line.to_ascii_lowercase();
    if let Some(state) = line.strip_prefix("state:") {
        return state.trim() == "connected";
    }
    line == "connected"
        || line
            .strip_prefix("connected to ")
            .is_some_and(|relay| !relay.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::mullvad_connected;

    #[test]
    fn official_connected_status() {
        assert!(mullvad_connected(
            "Connected to se-mma-wg-001 in Stockholm, Sweden\nRelay: se-mma-wg-001"
        ));
        assert!(mullvad_connected("\n  CONNECTED  \n"));
    }

    #[test]
    fn companion_connected_status() {
        assert!(mullvad_connected(
            "State: Connected\nRelay: se-mma-wg-001\n"
        ));
        assert!(mullvad_connected("  state: connected  \n"));
    }

    #[test]
    fn disconnected_is_not_connected() {
        for output in [
            "Disconnected",
            "State: Disconnected",
            "Disconnected\nPreviously connected to a relay",
        ] {
            assert!(!mullvad_connected(output), "{output}");
        }
    }

    #[test]
    fn transitional_and_error_states_are_not_connected() {
        for output in [
            "Connecting",
            "Disconnecting",
            "State: Connecting",
            "State: Error",
            "Blocked: unable to connect",
            "Error: not connected",
        ] {
            assert!(!mullvad_connected(output), "{output}");
        }
    }

    #[test]
    fn incidental_or_malformed_text_is_not_connected() {
        for output in [
            "not connected",
            "Connectedness",
            "State: Connectedness",
            "State: Connected (previously)",
            "Connected to ",
            "Warning: connected before\nConnected to relay",
            "[dry-run] would invoke: mullvadctl status",
            "🌐 connected",
            "",
            "  \n",
        ] {
            assert!(!mullvad_connected(output), "{output}");
        }
    }
}
