//! Integration tests for the daemon subcommand.
//!
//! Linux-only; requires write access to `/dev/random` (typically root).
//! Tests skip themselves cleanly when the environment cannot support them.
//!
//! Signal-based tests are gated behind `#[ignore]` because some container
//! test harnesses intercept or fail to deliver SIGTERM/SIGINT to subprocesses
//! spawned through `std::process::Command`. Run them explicitly with
//! `cargo test -- --ignored` on a bare-metal or VM host.

#![cfg(target_os = "linux")]

mod common;

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{pid_alive, send_signal, unique_pid_path, wait_for_pid_exit, wait_for_pid_file};

fn mixrand_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mixrand"))
}

fn can_write_dev_random() -> bool {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/random")
        .is_ok()
}

/// RAII guard: ensures a spawned daemon child is killed and reaped, and
/// any PID file is removed, even if a test panics mid-flow.
struct DaemonHandle {
    child: Option<Child>,
    pid_path: PathBuf,
    daemon_pid: Option<i32>,
}

impl DaemonHandle {
    fn spawn(extra_args: &[&str]) -> Self {
        let pid_path = unique_pid_path("daemon");
        let _ = std::fs::remove_file(&pid_path);
        let mut cmd = mixrand_bin();
        cmd.arg("daemon")
            .arg("--pid-file")
            .arg(&pid_path)
            .arg("--no-self-test")
            .arg("--interval")
            .arg("600")
            .arg("--threshold")
            .arg("1")
            .args(extra_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = cmd.spawn().expect("spawn daemon");
        Self {
            child: Some(child),
            pid_path,
            daemon_pid: None,
        }
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        if let Some(pid) = self.daemon_pid {
            if pid_alive(pid) {
                let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_file(&self.pid_path);
    }
}

#[test]
#[ignore = "signal delivery unreliable under some container test harnesses; run with --ignored on bare metal"]
fn test_daemon_starts_and_sigterm_clean_shutdown() {
    if !can_write_dev_random() {
        eprintln!("skipping: /dev/random not writable");
        return;
    }
    let mut h = DaemonHandle::spawn(&[]);
    let pid = wait_for_pid_file(&h.pid_path, Duration::from_secs(5));
    h.daemon_pid = Some(pid);
    assert!(pid_alive(pid));

    send_signal(pid, libc::SIGTERM);
    assert!(
        wait_for_pid_exit(pid, Duration::from_secs(10)),
        "daemon did not exit within 10s of SIGTERM"
    );
    let status = h
        .child
        .take()
        .expect("child present")
        .wait()
        .expect("child wait");
    assert!(status.success(), "daemon exit status: {status:?}");
}

#[test]
#[ignore = "signal delivery unreliable under some container test harnesses"]
fn test_daemon_sigint_is_equivalent_to_sigterm() {
    if !can_write_dev_random() {
        eprintln!("skipping: /dev/random not writable");
        return;
    }
    let mut h = DaemonHandle::spawn(&[]);
    let pid = wait_for_pid_file(&h.pid_path, Duration::from_secs(5));
    h.daemon_pid = Some(pid);
    send_signal(pid, libc::SIGINT);
    assert!(
        wait_for_pid_exit(pid, Duration::from_secs(10)),
        "SIGINT did not shut down daemon within 10s"
    );
    let _ = h.child.take().expect("child present").wait();
}

/// Starting a daemon while the PID file holds the PID of a living process
/// must refuse to start with a specific error message. This path does NOT
/// require signal delivery — the daemon refuses early and exits on its own.
#[test]
fn test_daemon_pid_file_collision_with_live_pid() {
    if !can_write_dev_random() {
        eprintln!("skipping: /dev/random not writable");
        return;
    }
    let pid_path = unique_pid_path("collision");
    std::fs::write(&pid_path, format!("{}\n", std::process::id())).expect("seed");

    let out = mixrand_bin()
        .arg("daemon")
        .arg("--pid-file")
        .arg(&pid_path)
        .arg("--no-self-test")
        .output()
        .expect("spawn");

    assert!(!out.status.success(), "daemon unexpectedly succeeded");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already running") || stderr.contains("another instance"),
        "stderr: {stderr}"
    );
    let _ = std::fs::remove_file(&pid_path);
}

/// Daemon rewrites a stale PID file (recorded PID is dead) and continues.
/// We verify the rewrite by polling the file until the PID differs from
/// our seeded dead PID; no signal delivery required for the assertion.
#[test]
#[ignore = "relies on signal delivery for cleanup shutdown; run with --ignored on bare metal"]
fn test_daemon_pid_file_stale_is_cleaned() {
    if !can_write_dev_random() {
        eprintln!("skipping: /dev/random not writable");
        return;
    }
    let mut dead: i32 = 2_000_000;
    while dead < 4_000_000 && unsafe { libc::kill(dead, 0) } == 0 {
        dead += 1;
    }
    let pid_path = unique_pid_path("stale");
    std::fs::write(&pid_path, format!("{dead}\n")).expect("seed stale pid file");

    let mut cmd = mixrand_bin();
    cmd.arg("daemon")
        .arg("--pid-file")
        .arg(&pid_path)
        .arg("--no-self-test")
        .arg("--interval")
        .arg("600")
        .arg("--threshold")
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut h = DaemonHandle {
        child: Some(cmd.spawn().expect("spawn daemon")),
        pid_path: pid_path.clone(),
        daemon_pid: None,
    };

    let deadline = Instant::now() + Duration::from_secs(5);
    let new_pid = loop {
        if Instant::now() > deadline {
            panic!("daemon did not rewrite stale PID file within 5s");
        }
        if let Ok(s) = std::fs::read_to_string(&pid_path) {
            if let Ok(p) = s.trim().parse::<i32>() {
                if p != dead {
                    break p;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    h.daemon_pid = Some(new_pid);
    assert!(pid_alive(new_pid));

    send_signal(new_pid, libc::SIGTERM);
    assert!(wait_for_pid_exit(new_pid, Duration::from_secs(10)));
    let _ = h.child.take().expect("child").wait();
}

/// A stale-PID rewrite without needing the daemon to exit cleanly:
/// verify that the newly-written PID differs from the seeded dead PID
/// and points at a live process. Daemon is killed via DaemonHandle::drop.
#[test]
fn test_daemon_rewrites_stale_pid_file_no_signal() {
    if !can_write_dev_random() {
        eprintln!("skipping: /dev/random not writable");
        return;
    }
    let mut dead: i32 = 2_500_000;
    while dead < 4_000_000 && unsafe { libc::kill(dead, 0) } == 0 {
        dead += 1;
    }
    let pid_path = unique_pid_path("stale_rewrite");
    std::fs::write(&pid_path, format!("{dead}\n")).expect("seed stale pid file");

    let mut cmd = mixrand_bin();
    cmd.arg("daemon")
        .arg("--pid-file")
        .arg(&pid_path)
        .arg("--no-self-test")
        .arg("--interval")
        .arg("600")
        .arg("--threshold")
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut h = DaemonHandle {
        child: Some(cmd.spawn().expect("spawn daemon")),
        pid_path: pid_path.clone(),
        daemon_pid: None,
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let new_pid = loop {
        if Instant::now() > deadline {
            panic!("daemon did not rewrite stale PID file within 5s");
        }
        if let Ok(s) = std::fs::read_to_string(&pid_path) {
            if let Ok(p) = s.trim().parse::<i32>() {
                if p != dead {
                    break p;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    h.daemon_pid = Some(new_pid);
    assert_ne!(new_pid, dead);
    assert!(pid_alive(new_pid));
    // DaemonHandle::drop will SIGKILL + reap on test end.
}

/// `--no-self-test` lets the daemon enter the loop even when some sources
/// would fail; the inverse (self-test enabled with all sources broken)
/// causes the daemon to refuse to start. We exercise only the accept path
/// here because mocking source-builder output from an integration test
/// requires the `testing` feature.
#[test]
fn test_daemon_accepts_no_self_test_flag() {
    if !can_write_dev_random() {
        eprintln!("skipping: /dev/random not writable");
        return;
    }
    let pid_path = unique_pid_path("nostest");
    let _ = std::fs::remove_file(&pid_path);
    let mut cmd = mixrand_bin();
    cmd.arg("daemon")
        .arg("--pid-file")
        .arg(&pid_path)
        .arg("--no-self-test")
        .arg("--interval")
        .arg("600")
        .arg("--threshold")
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut h = DaemonHandle {
        child: Some(cmd.spawn().expect("spawn daemon")),
        pid_path: pid_path.clone(),
        daemon_pid: None,
    };
    let pid = wait_for_pid_file(&pid_path, Duration::from_secs(5));
    h.daemon_pid = Some(pid);
    assert!(pid_alive(pid));
    // Drop guard kills the daemon.
}
