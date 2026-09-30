#![cfg(unix)]

use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn report(severity: &str) -> Value {
    json!({"tool":"dnscheck","version":"0.1.0", "detection": {
        "findings":[{"id":"fixture-warning", "severity":severity,
        "title":"Fixture DNS issue", "detail":"Fixture evidence", "confidence":"high"}],
        "cannot_detect":["Fixture limitation"]
    }})
}

fn audit(body: &str, flags: &[&str]) -> (std::process::Output, Value, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("dnscheck");
    fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let cfg = dir.path().join("config.json");
    fs::write(&cfg, "{}").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_opsec-check"))
        .env("PATH", dir.path()) // Only the fake sibling is available.
        .env("XDG_CONFIG_HOME", dir.path())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--json",
            "--no-metadata-sample",
        ])
        .args(flags)
        .arg("audit")
        .output()
        .unwrap();
    let value = serde_json::from_slice(&output.stdout).unwrap();
    (output, value, dir)
}

fn imported(value: &Value) -> &Value {
    value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "dns.dnscheck.fixture-warning")
        .unwrap()
}

#[test]
fn warning_report_survives_real_cli_boundary() {
    let body = format!("[ \"$1\" = report ] && [ \"$2\" = --json ] && [ \"$#\" = 2 ] || exit 2\nprintf '%s\\n' '{}'", report("warning"));
    let (output, value, _) = audit(&body, &[]);
    assert_eq!(imported(&value)["severity"], "attention_recommended");
    assert!(matches!(output.status.code(), Some(2 | 3)));
}

#[test]
fn critical_report_elevates_cli_exit_status() {
    let body = format!("printf '%s\\n' '{}'", report("critical"));
    let (output, value, _) = audit(&body, &[]);
    assert_eq!(imported(&value)["severity"], "configuration_issue");
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn command_error_with_valid_json_is_not_accepted_as_evidence() {
    let body = format!("printf '%s\\n' '{}'\nexit 2", report("critical"));
    let (_, value, _) = audit(&body, &[]);
    let findings = value["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["id"] == "dns.sibling_failed"));
    assert!(!findings
        .iter()
        .any(|f| f["id"] == "dns.dnscheck.fixture-warning"));
}

#[test]
fn full_report_larger_than_old_text_sample_is_imported() {
    let mut value = report("warning");
    value["inspection"] = json!({"padding":"x".repeat(5000)});
    let body = format!("printf '%s\\n' '{}'", value);
    let (_, value, _) = audit(&body, &[]);
    assert_eq!(
        imported(&value)["detail"],
        "Fixture evidence\nReported confidence: high"
    );
}

#[test]
fn invalid_or_oversized_output_becomes_a_failure_finding() {
    for body in [
        "printf 'not json'".to_string(),
        format!("printf '%s' '{}'", "x".repeat(1024 * 1024 + 1)),
    ] {
        let (_, value, _) = audit(&body, &[]);
        assert!(value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "dns.sibling_failed"));
    }
}

#[test]
fn dry_run_never_executes_fake_sibling() {
    let (_, value, dir) = audit("printf ran > \"$0.ran\"\nexit 1", &["--dry-run"]);
    assert!(!dir.path().join("dnscheck.ran").exists());
    assert!(
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "dns.sibling"
                && f["detail"] == "Would invoke: dnscheck report --json")
    );
}
