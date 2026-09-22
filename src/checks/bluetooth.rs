use crate::finding::{Finding, Severity};
use crate::tools;

pub fn check() -> Vec<Finding> {
    let mut findings = Vec::new();

    if !tools::command_exists("bluetoothctl") {
        findings.push(Finding::new(
            "bluetooth.no_ctl",
            "bluetooth",
            Severity::Informational,
            "bluetoothctl not on PATH",
            "Cannot query adapter power/discoverability without BlueZ tools.",
            "Install bluez to inspect Bluetooth OPSEC state.",
        ));
        return findings;
    }

    let show = crate::checks::cmd_out("bluetoothctl", &["show"]).unwrap_or_default();
    let powered = show.to_lowercase().contains("powered: yes");
    let discoverable = show.to_lowercase().contains("discoverable: yes");
    let pairable = show.to_lowercase().contains("pairable: yes");

    let severity = if discoverable {
        Severity::ConfigurationIssue
    } else if powered {
        Severity::AttentionRecommended
    } else {
        Severity::Informational
    };

    findings.push(
        Finding::new(
            "bluetooth.state",
            "bluetooth",
            severity,
            format!(
                "Bluetooth powered={} discoverable={} pairable={}",
                powered, discoverable, pairable
            ),
            "Bluetooth uses unique radio identifiers and can advertise device names. \
Discoverable mode is rarely needed except during pairing.",
            show.chars().take(600).collect::<String>(),
        )
        .with_hints([
            "bluetoothctl power off when unused.",
            "Keep Discoverable no except while pairing.",
        ]),
    );

    findings
}
