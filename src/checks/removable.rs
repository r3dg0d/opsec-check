use crate::finding::{Finding, Severity};

pub fn check() -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut rem = Vec::new();

    if let Ok(entries) = std::fs::read_dir("/sys/block") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let removable =
                crate::checks::read_trimmed(&e.path().join("removable").to_string_lossy())
                    .unwrap_or_else(|| "0".into());
            if removable.trim() == "1" {
                rem.push(name);
            }
        }
    }

    // mounts under /media /run/media /mnt
    let mut mounts = Vec::new();
    if let Ok(mtab) = std::fs::read_to_string("/proc/mounts") {
        for line in mtab.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let mp = parts[1];
                if mp.starts_with("/media/")
                    || mp.starts_with("/run/media/")
                    || (mp.starts_with("/mnt/") && mp != "/mnt")
                {
                    mounts.push(format!("{} -> {}", parts[0], mp));
                }
            }
        }
    }

    if rem.is_empty() && mounts.is_empty() {
        findings.push(Finding::new(
            "removable.none",
            "removable_storage",
            Severity::Informational,
            "No removable block devices or media mounts noticed",
            "Removable media can exfiltrate data or introduce malware; empty is fine for servers.",
            "Checked /sys/block/*/removable and common media mountpoints.",
        ));
    } else {
        findings.push(
            Finding::new(
                "removable.present",
                "removable_storage",
                Severity::AttentionRecommended,
                format!(
                    "Removable devices={} media_mounts={}",
                    rem.len(),
                    mounts.len()
                ),
                "Mounted USB/SD storage is a common data-exfiltration and autorun path. \
Ensure volumes are intentionally mounted and preferably encrypted.",
                format!("devices: {}; mounts: {}", rem.join(","), mounts.join("; ")),
            )
            .with_hints(["Unmount unused volumes.", "Prefer LUKS on portable drives."]),
        );
    }

    findings
}
