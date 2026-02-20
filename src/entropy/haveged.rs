use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

use crate::error::Error;

/// Checks if the haveged process is running by scanning /proc/*/comm.
fn is_haveged_running() -> bool {
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return false,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Only check numeric directories (PIDs)
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = fs::read_to_string(&comm_path) {
            if comm.trim() == "haveged" {
                return true;
            }
        }
    }
    false
}

/// Checks if the kernel entropy pool has sufficient entropy (>= 1024 bits).
fn has_sufficient_entropy() -> bool {
    match fs::read_to_string("/proc/sys/kernel/random/entropy_avail") {
        Ok(s) => s.trim().parse::<u32>().unwrap_or(0) >= 1024,
        Err(_) => false,
    }
}

/// Attempts to read `count` bytes from /dev/random with non-blocking I/O
/// and a 2-second poll timeout. Requires haveged to be running and sufficient
/// kernel entropy.
pub fn read_haveged(count: usize) -> Result<Vec<u8>, Error> {
    if !is_haveged_running() {
        return Err(Error::NoEntropy("haveged process not found".into()));
    }
    if !has_sufficient_entropy() {
        return Err(Error::NoEntropy(
            "insufficient kernel entropy (< 1024 bits)".into(),
        ));
    }

    // Open /dev/random with O_NONBLOCK
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/random")
        .map_err(|e| Error::NoEntropy(format!("/dev/random not available: {}", e)))?;

    let fd = f.as_raw_fd();
    let mut buf = vec![0u8; count];
    let mut filled = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);

    while filled < count {
        let remaining_ms = deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis() as i32;
        if remaining_ms <= 0 {
            return Err(Error::NoEntropy(
                "timeout waiting for /dev/random".into(),
            ));
        }

        // Poll for readability
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
        if ret <= 0 {
            return Err(Error::NoEntropy(
                "poll on /dev/random failed or timed out".into(),
            ));
        }

        // Use the File wrapper for reading
        let n = (&f).read(&mut buf[filled..])?;
        if n == 0 {
            return Err(Error::NoEntropy(
                "/dev/random returned 0 bytes".into(),
            ));
        }
        filled += n;
    }

    Ok(buf)
}
