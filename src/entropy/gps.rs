//! GPS Subframe 4 / Page 17 "Special Message" field as a NIST SP 800-90A
//! **additional-input / personalization string** — NOT an entropy source.
//!
//! GPS LNAV Subframe 4, Page 17 carries 22 eight-bit ASCII characters
//! (176 bits) of "special message" text broadcast by the GPS control segment.
//! This field is **public, static, world-readable**: every receiver on Earth
//! decodes the same bytes, and an attacker with any receiver (or online almanac
//! data) knows them. It therefore contributes **~0 bits of real entropy**.
//!
//! Accordingly this type is deliberately **never** registered in
//! `build_generate_sources()` or `build_check_sources()`: it can never win the
//! selection cascade, never become the sole RNG output, and is never credited
//! as entropy. It is consumed only by `entropy::generate()`'s
//! `fold_additional_input()` step (mixed in, 0-bit credit) and shown as an
//! informational row by `list-sources` / `check`.
//!
//! ## Acquisition must never block
//!
//! A *live* page-17 acquisition can take up to ~12.5 minutes (the subframe
//! 4/5 page subcommutation period), so this code never performs a live
//! capture inline. It reads a *cached/last-known* value that an external
//! collector (gnss-sdr, u-blox UBX, a custom RTL-SDR decoder — standard
//! NMEA/gpsd does not expose raw subframes) keeps fresh in a file/FIFO, or
//! emits via a command. Every acquisition path is bounded by a hard timeout
//! and a byte cap; on timeout/short-read/length-mismatch the field is reported
//! unavailable and `generate()` proceeds with the primary source unchanged.

use std::fs::File;
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::config::GpsConfig;
use crate::error::Error;

use super::EntropySource;

/// Additional-input source for the GPS Subframe 4/Page 17 special-message field.
///
/// Acquired from a configured `command` (stdout) or `path` (file/FIFO). It is
/// never an entropy source — see the module docs.
pub struct GpsSource {
    /// Command line run via `sh -c`; its stdout is the field (takes precedence).
    command: Option<String>,
    /// File or FIFO to read the field from (used when `command` is unset).
    path: Option<String>,
    /// Hard acquisition timeout.
    timeout: Duration,
    /// Expected field length in bytes (176 bits = 22).
    expected_len: usize,
}

impl GpsSource {
    pub fn new(config: &GpsConfig) -> Self {
        Self {
            command: config.command.clone(),
            path: config.path.clone(),
            timeout: Duration::from_millis(config.timeout_ms),
            expected_len: config.expected_len,
        }
    }

    /// Upper bound on bytes read per acquisition: just past `expected_len` so an
    /// over-long producer is detected (and rejected) rather than truncated, and
    /// a hostile/looping FIFO producer cannot exhaust memory.
    fn read_cap(&self) -> usize {
        self.expected_len.saturating_add(64)
    }
}

impl EntropySource for GpsSource {
    fn name(&self) -> &str {
        "gps-sf4p17"
    }

    fn description(&self) -> &str {
        "GPS Subframe 4/Page 17 special-message field (supplemental, 0-bit credit)"
    }

    /// Never used in any cascade (this type is registered in no builder); a
    /// sentinel value well past every real source documents that intent.
    fn priority(&self) -> u32 {
        1000
    }

    fn source_type(&self) -> &str {
        "additional-input"
    }

    fn is_available(&self) -> bool {
        self.command.is_some() || self.path.is_some()
    }

    /// Acquire the field. `count` is ignored: the field is fixed-size
    /// (`expected_len`). Returns the raw field bytes, or an error (treated as
    /// "unavailable, do not fold") on timeout, short/long read, or no config.
    fn collect(&self, _count: usize) -> Result<Vec<u8>, Error> {
        let cap = self.read_cap();
        let raw = if let Some(ref cmd) = self.command {
            run_command_timeout(cmd, self.timeout, cap)?
        } else if let Some(ref path) = self.path {
            read_path_timeout(path, self.timeout, cap, self.expected_len)?
        } else {
            return Err(Error::NoEntropy(
                "gps additional-input not configured (set command or path)".into(),
            ));
        };

        if raw.len() != self.expected_len {
            return Err(Error::NoEntropy(format!(
                "gps field length {} != expected {} (misconfigured collector? \
                 emit exactly {} bytes, no trailing newline)",
                raw.len(),
                self.expected_len,
                self.expected_len,
            )));
        }

        Ok(raw)
    }
}

/// Run `cmdline` via `sh -c`, capturing up to `cap` bytes of stdout, bounded by
/// `timeout`. On timeout the child is killed and reaped; the reader thread is
/// detached (never joined on the timeout path) so a shell pipeline whose
/// grandchildren hold stdout open can never block the caller.
fn run_command_timeout(cmdline: &str, timeout: Duration, cap: usize) -> Result<Vec<u8>, Error> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmdline)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| Error::NoEntropy(format!("gps command spawn failed: {}", e)))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::NoEntropy("gps command: no stdout pipe".into()))?;

    let (tx, rx) = mpsc::channel();
    // Detached-capable reader: bounded read of stdout, result sent over channel.
    thread::spawn(move || {
        let mut buf = Vec::new();
        let res = stdout.take(cap as u64).read_to_end(&mut buf);
        let _ = tx.send(res.map(|_| buf));
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(buf)) => {
            let _ = child.wait();
            Ok(buf)
        }
        Ok(Err(e)) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(Error::NoEntropy(format!("gps command read failed: {}", e)))
        }
        Err(_) => {
            // Timeout (or sender hung up): kill + reap the shell. Do NOT join
            // the reader — a grandchild could still hold the pipe; the detached
            // thread reads at most `cap` bytes and exits when the pipe closes.
            let _ = child.kill();
            let _ = child.wait();
            Err(Error::NoEntropy("gps command timed out".into()))
        }
    }
}

/// Read up to `cap` bytes (stopping once `expected_len` are available) from a
/// regular file or FIFO at `path`, bounded by `timeout`. Opens `O_NONBLOCK` so
/// a FIFO with no writer never blocks in `open()`, and `poll(2)`s for readiness
/// so a FIFO with no data yields a timeout instead of hanging.
fn read_path_timeout(
    path: &str,
    timeout: Duration,
    cap: usize,
    expected_len: usize,
) -> Result<Vec<u8>, Error> {
    let cpath = std::ffi::CString::new(path)
        .map_err(|_| Error::NoEntropy("gps path contains interior NUL byte".into()))?;

    // SAFETY: cpath is a valid NUL-terminated C string for the duration of the
    // call; flags are valid open(2) flags.
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    if fd < 0 {
        return Err(Error::NoEntropy(format!(
            "gps path open failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // Take ownership so the fd is closed on every return path.
    // SAFETY: `fd` was just returned by a successful open(2) and is not owned
    // elsewhere.
    let _file = unsafe { File::from_raw_fd(fd) };

    let deadline = Instant::now() + timeout;
    let mut buf: Vec<u8> = Vec::with_capacity(expected_len);
    let mut chunk = [0u8; 64];

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::NoEntropy("gps path read timed out".into()));
        }
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as libc::c_int;

        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: single valid pollfd; nfds = 1.
        let pret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if pret < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::NoEntropy(format!("gps path poll failed: {}", e)));
        }
        if pret == 0 {
            return Err(Error::NoEntropy("gps path read timed out".into()));
        }

        // SAFETY: fd is valid and owned by `_file`; chunk is a valid buffer.
        let n = unsafe {
            libc::read(
                fd,
                chunk.as_mut_ptr() as *mut libc::c_void,
                chunk.len() as libc::size_t,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted || e.raw_os_error() == Some(libc::EAGAIN)
            {
                continue;
            }
            return Err(Error::NoEntropy(format!("gps path read failed: {}", e)));
        }
        if n == 0 {
            break; // EOF
        }
        buf.extend_from_slice(&chunk[..n as usize]);
        if buf.len() >= cap || buf.len() >= expected_len {
            break;
        }
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn cfg() -> GpsConfig {
        GpsConfig {
            enabled: true,
            command: None,
            path: None,
            timeout_ms: 500,
            expected_len: 22,
        }
    }

    #[test]
    fn unconfigured_is_unavailable_and_errors() {
        let src = GpsSource::new(&cfg());
        assert!(!src.is_available());
        assert!(src.collect(32).is_err());
    }

    #[test]
    fn file_mode_reads_exact_field() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("page17.bin");
        let field = b"GPS-SF4P17-TESTVALUE!!"; // exactly 22 bytes
        assert_eq!(field.len(), 22);
        File::create(&p).unwrap().write_all(field).unwrap();

        let mut c = cfg();
        c.path = Some(p.to_str().unwrap().to_string());
        let src = GpsSource::new(&c);
        assert!(src.is_available());
        assert_eq!(src.collect(32).unwrap(), field);
    }

    #[test]
    fn file_mode_length_mismatch_errors() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("short.bin");
        File::create(&p).unwrap().write_all(b"too short").unwrap();

        let mut c = cfg();
        c.path = Some(p.to_str().unwrap().to_string());
        assert!(GpsSource::new(&c).collect(32).is_err());
    }

    #[test]
    fn file_mode_too_long_errors() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("long.bin");
        File::create(&p).unwrap().write_all(&[0x41u8; 100]).unwrap();

        let mut c = cfg();
        c.path = Some(p.to_str().unwrap().to_string());
        assert!(GpsSource::new(&c).collect(32).is_err());
    }

    #[test]
    fn command_mode_reads_field() {
        let mut c = cfg();
        // printf emits exactly 22 bytes, no trailing newline.
        c.command = Some("printf 'ABCDEFGHIJKLMNOPQRSTUV'".to_string());
        let got = GpsSource::new(&c).collect(32).unwrap();
        assert_eq!(got, b"ABCDEFGHIJKLMNOPQRSTUV");
    }

    #[test]
    fn command_timeout_does_not_hang() {
        let mut c = cfg();
        c.timeout_ms = 150;
        c.command = Some("sleep 30".to_string());
        let start = Instant::now();
        assert!(GpsSource::new(&c).collect(32).is_err());
        // Must return promptly (well under the 30s sleep).
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn fifo_without_writer_times_out_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("gps.fifo");
        let cpath = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        // SAFETY: valid C string path; 0o600 perms.
        let r = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
        assert_eq!(r, 0, "mkfifo failed");

        let mut c = cfg();
        c.timeout_ms = 150;
        c.path = Some(p.to_str().unwrap().to_string());
        let start = Instant::now();
        assert!(GpsSource::new(&c).collect(32).is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
