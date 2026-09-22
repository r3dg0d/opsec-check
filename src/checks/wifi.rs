use crate::finding::{Finding, Severity};
use crate::tools;

pub fn check() -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut wifi_ifaces = Vec::new();

    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let path = e.path();
            if path.join("wireless").exists() || path.join("phy80211").exists() {
                wifi_ifaces.push(name);
            }
        }
    }

    if wifi_ifaces.is_empty() {
        findings.push(Finding::new(
            "wifi.none",
            "wifi",
            Severity::Informational,
            "No sysfs wireless interfaces found",
            "Wired-only hosts avoid Wi-Fi probe-request tracking; this box may simply lack Wi-Fi.",
            "Checked /sys/class/net/*/wireless and phy80211.",
        ));
        return findings;
    }

    let mut detail = format!("ifaces: {}", wifi_ifaces.join(", "));
    if tools::command_exists("nmcli") {
        if let Some(out) = crate::checks::cmd_out(
            "nmcli",
            &[
                "-t",
                "-f",
                "NAME,TYPE,DEVICE",
                "connection",
                "show",
                "--active",
            ],
        ) {
            detail.push('\n');
            detail.push_str(&out.chars().take(400).collect::<String>());
        }
    }
    if tools::command_exists("iw") {
        if let Some(out) = crate::checks::cmd_out("iw", &["dev"]) {
            detail.push('\n');
            detail.push_str(&out.chars().take(400).collect::<String>());
        }
    }

    findings.push(
        Finding::new(
            "wifi.present",
            "wifi",
            Severity::AttentionRecommended,
            format!("Wi-Fi interface(s): {}", wifi_ifaces.join(", ")),
            "Wi-Fi stacks send probe requests and associate with stable or semi-stable MACs. \
Saved SSIDs also leak preferred networks to observers.",
            detail,
        )
        .with_tool("macrandom")
        .with_hints([
            "Randomize MAC before joining untrusted SSIDs.",
            "Forget unused saved networks in NetworkManager.",
        ]),
    );

    findings
}
