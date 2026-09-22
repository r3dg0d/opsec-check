use std::process::Command;

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_opsec-check"));
    c.env("RUST_LOG", "error");
    c
}

#[test]
fn help_works() {
    let out = bin().arg("--help").output().expect("run");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("opsec-check"));
    assert!(s.contains("--json"));
    assert!(s.contains("--markdown"));
    assert!(s.contains("--html"));
}

#[test]
fn version_works() {
    let out = bin().arg("--version").output().expect("run");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("opsec-check"));
}

#[test]
fn tools_subcommand() {
    let out = bin().arg("tools").output().expect("run");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("macrandom"));
    assert!(s.contains("dnscheck"));
}

#[test]
fn tools_json() {
    let out = bin().args(["--json", "tools"]).output().expect("run");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(v.is_array());
}

#[test]
fn audit_json_schema_ish() {
    let out = bin()
        .args(["--json", "--dry-run", "--no-metadata-sample", "audit"])
        .output()
        .expect("run");
    // exit may be 0/2/3 depending on host
    assert!(out.status.code().unwrap_or(1) != 1 || out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["tool"], "opsec-check");
    assert!(v["findings"].is_array());
    assert!(v["sibling_tools"].is_array());
    assert!(v["limitations"].is_array());
    // Ensure we never emit a fake score field
    assert!(v.get("score").is_none());
    assert!(v.get("privacy_score").is_none());
}

#[test]
fn audit_markdown_header() {
    let out = bin()
        .args(["--markdown", "--dry-run", "audit"])
        .output()
        .expect("run");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("# opsec-check report"));
    assert!(s.contains("No numeric privacy score"));
}

#[test]
fn audit_html_doctype() {
    let out = bin()
        .args(["--html", "--dry-run", "audit"])
        .output()
        .expect("run");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("<!DOCTYPE html>"));
    assert!(s.contains("No 0–100 privacy score") || s.contains("No 0"));
}

#[test]
fn completions_bash() {
    let out = bin().args(["completions", "bash"]).output().expect("run");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("opsec-check"));
}
