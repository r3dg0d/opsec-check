//! Sibling tool discovery (PATH only — no downloads).

use crate::finding::ToolPresence;

pub const SIBLINGS: &[&str] = &[
    "macrandom",
    "mullvadctl",
    "dnscheck",
    "netidentity",
    "metaclean",
    "browserprivacy",
    "fileshred",
];

pub fn detect_siblings() -> Vec<ToolPresence> {
    SIBLINGS
        .iter()
        .map(|name| match which::which(name) {
            Ok(p) => ToolPresence {
                name: (*name).to_string(),
                available: true,
                path: Some(p.display().to_string()),
                note: None,
            },
            Err(_) => ToolPresence {
                name: (*name).to_string(),
                available: false,
                path: None,
                note: Some("not on PATH — install sibling for deeper checks".into()),
            },
        })
        .collect()
}

/// Legacy text sample; preserve nonzero audit output, but discard runner failures.
pub fn run_sibling(name: &str, args: &[&str], dry_run: bool) -> Option<String> {
    if dry_run {
        return Some(format!("[dry-run] would invoke: {name} {}", args.join(" ")));
    }
    let bin = which::which(name).ok()?;
    let out = crate::process::output(&bin, args).ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    if text.trim().is_empty() {
        text = String::from_utf8_lossy(&out.stderr).to_string();
    }
    let trimmed: String = text.chars().take(4000).collect();
    if trimmed.trim().is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Structured reports must complete successfully and contain whole JSON.
/// Unlike legacy text sampling, diagnostics and truncated data are not evidence.
pub(crate) fn run_sibling_json(name: &str, args: &[&str]) -> Result<serde_json::Value, String> {
    let bin = which::which(name).map_err(|_| format!("{name} is no longer on PATH"))?;
    let output = crate::process::output(bin, args)?;
    decode_json_output(&output)
}

fn decode_json_output(output: &std::process::Output) -> Result<serde_json::Value, String> {
    if !output.status.success() {
        return Err(format!("command failed ({})", output.status));
    }
    serde_json::from_slice(&output.stdout).map_err(|_| "command did not return valid JSON".into())
}

pub fn command_exists(name: &str) -> bool {
    which::which(name).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn siblings_list_complete() {
        assert!(SIBLINGS.contains(&"dnscheck"));
        assert!(SIBLINGS.contains(&"macrandom"));
        assert_eq!(SIBLINGS.len(), 7);
    }

    #[test]
    fn dry_run_does_not_execute() {
        let msg = run_sibling("definitely-not-a-real-tool-xyz", &["--help"], true);
        assert!(msg.unwrap().contains("dry-run"));
    }
}
