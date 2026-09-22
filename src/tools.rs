//! Sibling tool discovery (PATH only — no downloads).

use crate::finding::ToolPresence;
use std::process::Command;

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

/// Run a sibling with args; return truncated stdout/stderr on success.
pub fn run_sibling(name: &str, args: &[&str], dry_run: bool) -> Option<String> {
    if dry_run {
        return Some(format!("[dry-run] would invoke: {name} {}", args.join(" ")));
    }
    let bin = which::which(name).ok()?;
    let out = Command::new(&bin).args(args).output().ok()?;
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
