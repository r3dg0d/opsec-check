use crate::finding::{Finding, Severity};
use crate::tools;

pub fn check() -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut videos = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/dev") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("video") {
                videos.push(format!("/dev/{name}"));
            }
        }
    }
    videos.sort();

    if videos.is_empty() {
        findings.push(Finding::new(
            "camera.none",
            "camera_mic",
            Severity::Informational,
            "No /dev/video* nodes found",
            "Fewer capture devices means less accidental webcam exposure — or just a headless VM.",
            "Checked /dev/video*.",
        ));
    } else {
        findings.push(
            Finding::new(
                "camera.present",
                "camera_mic",
                Severity::AttentionRecommended,
                format!("{} video device node(s)", videos.len()),
                "Camera nodes can be opened by any process with device access. On desktops, \
prefer portal-mediated access and review which apps hold devices.",
                videos.join(", "),
            )
            .with_limitation(
                "Presence ≠ currently capturing; no PipeWire client graph parsed here.",
            ),
        );
    }

    // PipeWire / pulse hints
    let mut audio_notes = Vec::new();
    if tools::command_exists("wpctl") {
        if let Some(out) = crate::checks::cmd_out("wpctl", &["status"]) {
            audio_notes.push(out.chars().take(400).collect::<String>());
        }
    } else if tools::command_exists("pactl") {
        if let Some(out) = crate::checks::cmd_out("pactl", &["list", "short", "sources"]) {
            audio_notes.push(out.chars().take(400).collect::<String>());
        }
    }

    if audio_notes.is_empty() {
        findings.push(Finding::new(
            "mic.unknown",
            "camera_mic",
            Severity::Informational,
            "No wpctl/pactl audio source listing",
            "Could not inventory microphones; PipeWire/Pulse may be absent or permission-gated.",
            "Install wireplumber (wpctl) or pulseaudio-utils for source lists.",
        ));
    } else {
        findings.push(
            Finding::new(
                "mic.sources",
                "camera_mic",
                Severity::Informational,
                "Audio sources inventoried",
                "Knowing which mics exist helps you disable or unplug unused capture paths.",
                audio_notes.join("\n"),
            )
            .with_limitation("Does not show which clients currently capture."),
        );
    }

    findings
}
