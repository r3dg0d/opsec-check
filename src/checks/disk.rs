use crate::finding::{Finding, Severity};
use crate::tools;

pub fn check() -> Vec<Finding> {
    let mut findings = Vec::new();

    // lsblk FSTYPE / crypt hints
    let lsblk = if tools::command_exists("lsblk") {
        crate::checks::cmd_out("lsblk", &["-o", "NAME,TYPE,FSTYPE,MOUNTPOINT", "-n"])
    } else {
        None
    };

    let mut has_crypt = false;
    let mut has_swap = false;
    let mut root_crypt = false;
    if let Some(ref text) = lsblk {
        for line in text.lines() {
            let lower = line.to_lowercase();
            if lower.contains("crypt") || lower.contains("luks") {
                has_crypt = true;
            }
            if lower.contains("swap") {
                has_swap = true;
            }
            if (lower.contains("crypt") || lower.contains("luks"))
                && (lower.contains(" /") || lower.ends_with('/'))
            {
                root_crypt = true;
            }
        }
    }

    if tools::command_exists("cryptsetup") {
        // status of common mapper names — best effort, may need root
        for name in ["root", "cryptroot", "luks", "nixos"] {
            if let Some(out) = crate::checks::cmd_out("cryptsetup", &["status", name]) {
                if out.to_lowercase().contains("active") {
                    has_crypt = true;
                    root_crypt = true;
                }
                let _ = out;
            }
        }
    }

    if has_crypt || root_crypt {
        findings.push(
            Finding::new(
                "disk.crypt_hint",
                "disk_encryption",
                Severity::Informational,
                "Disk encryption hints detected (LUKS/crypt)",
                "Full-disk encryption protects data at rest if the device is seized while powered off.",
                lsblk.clone().unwrap_or_else(|| "cryptsetup/lsblk hints".into())
                    .chars()
                    .take(700)
                    .collect::<String>(),
            )
            .with_limitation(
                "Cannot verify key strength, TPM binding, or that *all* sensitive mounts are encrypted.",
            ),
        );
    } else {
        findings.push(
            Finding::new(
                "disk.no_crypt",
                "disk_encryption",
                Severity::AttentionRecommended,
                "No clear LUKS/crypt device detected",
                "Unencrypted disks expose files if the drive is removed or the machine is stolen cold.",
                lsblk.unwrap_or_else(|| "lsblk/cryptsetup unavailable or empty".into())
                    .chars()
                    .take(700)
                    .collect::<String>(),
            )
            .with_limitation(
                "Cloud VMs, ZFS native encryption, and some layouts may not show as 'crypt'.",
            ),
        );
    }

    // swap
    let swaps = crate::checks::read_trimmed("/proc/swaps").unwrap_or_default();
    let swap_active = swaps.lines().count() > 1;
    if swap_active || has_swap {
        // Check if swap looks like crypt
        let swap_crypt = swaps.to_lowercase().contains("crypt")
            || std::fs::read_to_string("/etc/crypttab")
                .map(|c| c.to_lowercase().contains("swap"))
                .unwrap_or(false);
        let sev = if swap_crypt {
            Severity::Informational
        } else {
            Severity::AttentionRecommended
        };
        findings.push(
            Finding::new(
                "disk.swap",
                "swap_encryption",
                sev,
                if swap_crypt {
                    "Swap appears tied to crypt/crypttab".to_string()
                } else {
                    "Swap is active — encryption unclear".to_string()
                },
                "Cleartext swap can retain passwords, keys, and document fragments across reboots.",
                swaps.chars().take(400).collect::<String>(),
            )
            .with_hints([
                "Prefer encrypted swap or zram with careful secrets handling.",
                "Consider swapoff on high-sensitivity hosts.",
            ]),
        );
    } else {
        findings.push(Finding::new(
            "disk.no_swap",
            "swap_encryption",
            Severity::Informational,
            "No active swap in /proc/swaps",
            "No swap reduces a common secrets-at-rest footgun (at the cost of memory headroom).",
            "Checked /proc/swaps.",
        ));
    }

    findings
}
