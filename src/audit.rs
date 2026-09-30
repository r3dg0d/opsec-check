//! Orchestrate built-in checks into an AuditReport.

use crate::checks::{self, CheckCtx};
use crate::config::Config;
use crate::finding::AuditReport;
use crate::tools;
use chrono::Utc;

pub fn run(cfg: &Config, dry_run: bool, no_metadata_sample: bool) -> AuditReport {
    let ctx = CheckCtx {
        cfg,
        dry_run,
        no_metadata_sample,
    };

    let mut findings = if cfg.skip_sibling_tools {
        // Still run built-ins; tools module just won't be invoked from checks if dry_run
        let mut c = ctx;
        c.dry_run = true;
        checks::run_all(&c)
    } else {
        checks::run_all(&ctx)
    };

    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.check.cmp(&b.check))
            .then_with(|| a.id.cmp(&b.id))
    });

    let hostname = std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            crate::process::output("hostname", &[])
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into());

    AuditReport {
        tool: "opsec-check".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        generated_at: Utc::now().to_rfc3339(),
        hostname,
        findings,
        sibling_tools: tools::detect_siblings(),
        limitations: vec![
            "Read-only local heuristics; not a penetration test or anonymity guarantee.".into(),
            "DNS sibling findings are imported from JSON; other sibling output is sampled. DNS report failures are non-fatal attention findings.".into(),
            "No fake 0–100 privacy score is computed or implied.".into(),
            "Cloud metadata, corporate MDM, and browser WebRTC leaks need separate tooling.".into(),
            "Metadata sampling is shallow by design to avoid scanning huge home trees.".into(),
        ],
    }
}
