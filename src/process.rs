//! Bounded command capture for read-only audit probes.

use std::ffi::OsStr;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
const TIMEOUT: Duration = Duration::from_secs(10);
const OUTPUT_LIMIT: usize = 1024 * 1024;

pub fn request_interrupt() {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

pub(crate) fn output(bin: impl AsRef<OsStr>, args: &[&str]) -> Result<Output, String> {
    run(Command::new(bin).args(args), TIMEOUT, OUTPUT_LIMIT)
}

#[cfg(not(unix))]
fn run(_: &mut Command, _: Duration, _: usize) -> Result<Output, String> {
    Err("bounded audit commands require Unix".into())
}

#[cfg(unix)]
fn run(command: &mut Command, timeout: Duration, limit: usize) -> Result<Output, String> {
    use std::io::{ErrorKind, Read};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Stdio};
    use std::time::Instant;

    struct Guard(Child, bool);
    impl Drop for Guard {
        fn drop(&mut self) {
            if !self.1 {
                return;
            }
            // The unreaped group leader reserves this ID until cleanup. Signal
            // its dedicated group, including descendants that hold pipe ends.
            // SAFETY: the positive child PID came from a successful spawn.
            unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn nonblocking(pipe: &impl AsRawFd) -> Result<(), String> {
        // SAFETY: pipe owns a live FD throughout both fcntl calls.
        let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(format!(
                "could not configure command pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn read_chunk(
        pipe: &mut impl Read,
        data: &mut Vec<u8>,
        other_len: usize,
        limit: usize,
    ) -> Result<bool, String> {
        let mut buffer = [0u8; 8192];
        match pipe.read(&mut buffer) {
            Ok(0) => Ok(true),
            Ok(n) => {
                if n > limit.saturating_sub(data.len() + other_len) {
                    return Err(format!("command output exceeds {limit} byte limit"));
                }
                data.extend_from_slice(&buffer[..n]);
                Ok(false)
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                Ok(false)
            }
            Err(e) => Err(format!("could not read command output: {e}")),
        }
    }

    if interrupted() {
        return Err("audit interrupted".into());
    }
    let started = Instant::now();
    let mut child = Guard(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|e| format!("could not start command: {e}"))?,
        true,
    );
    let mut stdout = child.0.stdout.take().expect("piped stdout");
    let mut stderr = child.0.stderr.take().expect("piped stderr");
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let (mut out_eof, mut err_eof) = (false, false);
    loop {
        if interrupted() {
            return Err("audit interrupted".into());
        }
        if started.elapsed() >= timeout {
            return Err(format!("command timed out after {timeout:?}"));
        }
        // Read a bounded chunk per stream so a continuous flood cannot starve
        // the deadline, interrupt check, or the other pipe.
        if !out_eof {
            out_eof = read_chunk(&mut stdout, &mut out, err.len(), limit)?;
        }
        if !err_eof {
            err_eof = read_chunk(&mut stderr, &mut err, out.len(), limit)?;
        }
        if out_eof && err_eof {
            // Do not reap the leader while a descendant still holds a pipe:
            // its PID must remain reserved for process-group timeout cleanup.
            if let Some(status) = child
                .0
                .try_wait()
                .map_err(|e| format!("could not wait for command: {e}"))?
            {
                // Already reaped: disarm group cleanup to avoid a reused PID.
                child.1 = false;
                return Ok(Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Instant;

    fn shell(script: &str, limit: usize) -> Result<Output, String> {
        run(
            Command::new("/bin/sh").args(["-c", script]),
            Duration::from_millis(250),
            limit,
        )
    }

    #[test]
    fn captures_both_streams_and_preserves_nonzero_exit() {
        let out = shell("printf evidence; printf diagnostic >&2; exit 7", 100).unwrap();
        assert_eq!(out.stdout, b"evidence");
        assert_eq!(out.stderr, b"diagnostic");
        assert_eq!(out.status.code(), Some(7));
    }

    #[test]
    fn exact_limit_is_allowed_but_combined_overflow_is_rejected() {
        assert_eq!(shell("printf ab; printf cd >&2", 4).unwrap().stdout, b"ab");
        assert!(shell("printf ab; printf cde >&2", 4)
            .unwrap_err()
            .contains("limit"));
    }

    #[test]
    fn stdin_is_closed_instead_of_waiting_for_user_input() {
        assert_eq!(
            shell("read answer || printf eof", 100).unwrap().stdout,
            b"eof"
        );
    }

    #[test]
    fn endless_stdout_and_stderr_are_bounded() {
        for stream in ["", " >&2"] {
            let start = Instant::now();
            let result = shell(&format!("while :; do printf 12345678{stream}; done"), 64);
            assert!(result.unwrap_err().contains("limit"));
            assert!(start.elapsed() < Duration::from_secs(3));
        }
    }

    #[test]
    fn closed_pipes_do_not_hide_a_hung_process() {
        assert!(shell("exec 1>&- 2>&-; while :; do :; done", 100)
            .unwrap_err()
            .contains("timed out"));
    }

    #[test]
    fn missing_command_returns_an_error() {
        assert!(run(
            &mut Command::new("/no-such-audit-command"),
            Duration::from_millis(250),
            100
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    fn assert_stopped(pid: u32) {
        for _ in 0..100 {
            let state = std::fs::read_to_string(format!("/proc/{pid}/stat"));
            if state
                .as_ref()
                .map_or(true, |s| s.rsplit_once(") ").unwrap().1.starts_with('Z'))
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("test process {pid} still running");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn timeout_stops_child_and_descendant() {
        let sleep = which::which("sleep").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pids");
        let script = format!(
            "'{}' 30 & printf '%s %s' \"$$\" \"$!\" > '{}'; wait",
            sleep.display(),
            pid_file.display()
        );
        let start = Instant::now();
        assert!(shell(&script, 100).unwrap_err().contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(3));
        for pid in std::fs::read_to_string(pid_file)
            .unwrap()
            .split_whitespace()
        {
            assert_stopped(pid.parse().unwrap());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn exited_leader_with_inherited_pipe_does_not_hang_capture() {
        let sleep = which::which("sleep").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let script = format!(
            "'{}' 30 & printf '%s' \"$!\" > '{}'; exit 0",
            sleep.display(),
            pid_file.display()
        );
        assert!(shell(&script, 100).unwrap_err().contains("timed out"));
        assert_stopped(std::fs::read_to_string(pid_file).unwrap().parse().unwrap());
    }
}
