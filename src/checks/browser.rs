use crate::checks::CheckCtx;
use crate::finding::{Finding, Severity};
use crate::tools;
use std::path::PathBuf;

pub fn check(ctx: &CheckCtx<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();

    if tools::command_exists("browserprivacy") {
        let detail = tools::run_sibling("browserprivacy", &["audit"], ctx.dry_run)
            .or_else(|| tools::run_sibling("browserprivacy", &["--help"], ctx.dry_run))
            .unwrap_or_else(|| "browserprivacy present".into());
        findings.push(
            Finding::new(
                "browser.sibling",
                "browser_privacy",
                Severity::Informational,
                "browserprivacy available for profile audits",
                "Browsers retain history, cookies, WebRTC leaks, and fingerprinting surfaces \
far beyond what a host audit can see.",
                detail.chars().take(600).collect::<String>(),
            )
            .with_tool("browserprivacy"),
        );
    }

    let home = std::env::var_os("HOME").map(PathBuf::from);
    let Some(home) = home else {
        findings.push(Finding::new(
            "browser.no_home",
            "browser_privacy",
            Severity::Informational,
            "HOME unset — skipping browser profile hints",
            "Cannot locate user browser profiles without HOME.",
            "",
        ));
        return findings;
    };

    let candidates = [
        home.join(".mozilla/firefox"),
        home.join(".config/chromium"),
        home.join(".config/google-chrome"),
        home.join(".config/BraveSoftware/Brave-Browser"),
        home.join(".librewolf"),
        home.join(".config/firefox"),
    ];

    let mut found = Vec::new();
    for p in &candidates {
        if p.exists() {
            found.push(p.display().to_string());
        }
    }

    if found.is_empty() {
        findings.push(Finding::new(
            "browser.no_profiles",
            "browser_privacy",
            Severity::Informational,
            "No common browser profile directories found",
            "Headless/server accounts often have none; flatpak paths may be missed.",
            "Checked Firefox/Chromium/Brave/LibreWolf XDG-ish locations.",
        ));
    } else {
        findings.push(
            Finding::new(
                "browser.profiles",
                "browser_privacy",
                Severity::AttentionRecommended,
                format!("{} browser profile path(s) detected", found.len()),
                "Local profiles hold cookies, history, and fingerprinting entropy. Harden \
settings (HTTPS-Only, resistFingerprinting, disable unnecessary WebRTC) and review extensions.",
                found.join("\n"),
            )
            .with_tool("browserprivacy")
            .with_limitation(
                "Does not parse prefs.js or policies; install browserprivacy for real audits.",
            )
            .with_hints([
                "Use browserprivacy audit when available.",
                "Prefer hardened browsers (LibreWolf, Mullvad Browser) for sensitive work.",
            ]),
        );
    }

    findings
}
