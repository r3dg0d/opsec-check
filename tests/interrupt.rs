#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn sigint_stops_active_probe_and_exits_130() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("dnscheck");
    fs::write(
        &script,
        "#!/bin/sh\nprintf '%s' \"$$\" > \"$0.pid\"\nwhile :; do :; done\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let cfg = dir.path().join("config.json");
    fs::write(&cfg, "{}").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_opsec-check"))
        .env("PATH", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--json",
            "--no-metadata-sample",
            "audit",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let pid_file = dir.path().join("dnscheck.pid");
    while !pid_file.exists() && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !pid_file.exists() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("fake sibling did not start");
    }
    let probe_pid: i32 = fs::read_to_string(pid_file).unwrap().parse().unwrap();
    // SAFETY: this is the live CLI process owned by this test.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            // SAFETY: this dedicated group belongs to our fake sibling.
            unsafe {
                libc::kill(-probe_pid, libc::SIGKILL);
            }
            panic!("CLI failed to respond to SIGINT");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(130));
    assert!(
        !std::path::Path::new(&format!("/proc/{probe_pid}")).exists(),
        "probe was not reaped"
    );
}
