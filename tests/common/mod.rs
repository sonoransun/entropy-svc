//! Shared helpers for integration tests.
//!
//! Pulled in via `mod common;` at the top of each integration test file
//! that needs these helpers. Individual tests only import what they use,
//! so dead-code warnings are silenced at module level.

#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;

/// Write a temporary TOML file containing `contents`. The file is deleted
/// when the returned [`NamedTempFile`] is dropped.
pub fn tmp_toml(contents: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create tempfile");
    f.write_all(contents.as_bytes()).expect("write tempfile");
    f.flush().expect("flush tempfile");
    f
}

/// Poll `path` for existence, returning the contents (parsed as PID) once
/// present, or panicking if `timeout` elapses first.
pub fn wait_for_pid_file(path: &Path, timeout: Duration) -> i32 {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if let Ok(pid) = contents.trim().parse::<i32>() {
                return pid;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "PID file {} did not appear within {:?}",
        path.display(),
        timeout
    );
}

/// Send a signal to `pid`. Safe wrapper over `libc::kill`.
pub fn send_signal(pid: i32, signal: i32) {
    let rc = unsafe { libc::kill(pid, signal) };
    assert_eq!(
        rc,
        0,
        "kill({pid}, {signal}) failed: {}",
        std::io::Error::last_os_error()
    );
}

/// Check if a process is currently alive via `kill(pid, 0)`.
pub fn pid_alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Wait up to `timeout` for `pid` to exit. Returns true on clean exit,
/// false on timeout.
pub fn wait_for_pid_exit(pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Compute a unique temporary path for a PID file in this test run.
pub fn unique_pid_path(label: &str) -> PathBuf {
    let pid = std::process::id();
    let ns = Instant::now().elapsed().as_nanos();
    std::env::temp_dir().join(format!("mixrand_test_{label}_{pid}_{ns}.pid"))
}
