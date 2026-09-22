use crate::checks::CheckCtx;
use crate::finding::{Finding, Severity};
use crate::tools;

pub fn check(ctx: &CheckCtx<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();

    if tools::command_exists("macrandom") {
        let detail = tools::run_sibling("macrandom", &["status"], ctx.dry_run)
            .unwrap_or_else(|| "macrandom present".into());
        findings.push(
            Finding::new(
                "mac.sibling",
                "mac",
                Severity::Informational,
                "macrandom available for MAC hygiene",
                "Stable MACs link visits across Wi-Fi networks. Randomization is L2 hygiene, \
not anonymity — it does not hide your IP or accounts.",
                detail.chars().take(800).collect::<String>(),
            )
            .with_tool("macrandom"),
        );
    }

    let mut rows = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            let addr = crate::checks::read_trimmed(&e.path().join("address").to_string_lossy())
                .unwrap_or_else(|| "?".into());
            // Locally administered bit: second hex nibble's 2s bit
            let laa = is_locally_administered(&addr);
            rows.push(format!(
                "{name}={addr} ({})",
                if laa { "LAA?" } else { "UAA/vendor?" }
            ));
            if !laa && !addr.starts_with("00:00:00") {
                findings.push(
                    Finding::new(
                        format!("mac.stable.{name}"),
                        "mac",
                        Severity::AttentionRecommended,
                        format!("Interface {name} may use a vendor (stable) MAC"),
                        "A burned-in OUI helps venues and APs recognize the same device \
across time. Randomize when moving between untrusted networks.",
                        format!("address={addr}"),
                    )
                    .with_tool("macrandom")
                    .with_limitation(
                        "Sysfs address is current, not necessarily permanent (ethtool -P).",
                    )
                    .with_hints([format!("macrandom status / macrandom randomize {name}")]),
                );
            }
        }
    }

    if findings.iter().all(|f| f.id != "mac.sibling") && !rows.is_empty() {
        findings.insert(
            0,
            Finding::new(
                "mac.summary",
                "mac",
                Severity::Informational,
                "MAC addresses observed via sysfs",
                "Useful baseline when macrandom is not installed.",
                rows.join("; "),
            ),
        );
    }

    findings
}

fn is_locally_administered(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.is_empty() {
        return false;
    }
    let Ok(b) = u8::from_str_radix(parts[0], 16) else {
        return false;
    };
    b & 0x02 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn laa_bit_detection() {
        assert!(is_locally_administered("02:11:22:33:44:55"));
        assert!(!is_locally_administered("00:11:22:33:44:55"));
    }
}
