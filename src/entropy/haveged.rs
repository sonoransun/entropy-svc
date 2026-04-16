use crate::error::Error;

/// Attempts to read `count` bytes from `/dev/random` with non-blocking I/O
/// and a 2-second poll timeout. Requires haveged to be running and sufficient
/// kernel entropy. Linux-only.
#[cfg(target_os = "linux")]
pub fn read_haveged(count: usize) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    use std::time::Duration;

    if !is_haveged_running_in("/proc") {
        return Err(Error::NoEntropy("haveged process not found".into()));
    }
    if !has_sufficient_entropy_at("/proc/sys/kernel/random/entropy_avail", 1024) {
        return Err(Error::NoEntropy(
            "insufficient kernel entropy (< 1024 bits)".into(),
        ));
    }

    let f = std::fs::OpenOptions::new()
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
            return Err(Error::NoEntropy("timeout waiting for /dev/random".into()));
        }

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

        let n = (&f).read(&mut buf[filled..])?;
        if n == 0 {
            return Err(Error::NoEntropy("/dev/random returned 0 bytes".into()));
        }
        filled += n;
    }

    Ok(buf)
}

#[cfg(not(target_os = "linux"))]
pub fn read_haveged(_count: usize) -> Result<Vec<u8>, Error> {
    Err(Error::NoEntropy("haveged requires Linux".into()))
}

/// Walks a procfs-like directory, returning true if any `<pid>/comm` file has
/// `haveged` as its trimmed contents. Extracted from `read_haveged` so tests
/// can inject a fixture directory instead of the real `/proc`.
#[cfg(target_os = "linux")]
pub(crate) fn is_haveged_running_in<P: AsRef<std::path::Path>>(proc_root: P) -> bool {
    let entries = match std::fs::read_dir(proc_root.as_ref()) {
        Ok(e) => e,
        Err(_) => return false,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = std::fs::read_to_string(&comm_path) {
            if comm.trim() == "haveged" {
                return true;
            }
        }
    }
    false
}

/// Reads a kernel `entropy_avail`-style file and returns true when the integer
/// contents meet or exceed `threshold`. Parameterised so tests can feed a
/// fixture file.
#[cfg(target_os = "linux")]
pub(crate) fn has_sufficient_entropy_at<P: AsRef<std::path::Path>>(
    path: P,
    threshold: u32,
) -> bool {
    match std::fs::read_to_string(path.as_ref()) {
        Ok(s) => s.trim().parse::<u32>().unwrap_or(0) >= threshold,
        Err(_) => false,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn mkdirp(p: &std::path::Path) {
        fs::create_dir_all(p).expect("test setup: create_dir_all");
    }

    fn writef(path: &std::path::Path, contents: &str) {
        let mut f = fs::File::create(path).expect("test setup: File::create");
        f.write_all(contents.as_bytes())
            .expect("test setup: write_all");
    }

    #[test]
    fn test_is_haveged_running_missing_dir() {
        assert!(!is_haveged_running_in("/nonexistent/mixrand/proc"));
    }

    #[test]
    fn test_is_haveged_running_no_pid_with_haveged_comm() {
        let tmp = std::env::temp_dir().join("mixrand_test_haveged_absent");
        let _ = fs::remove_dir_all(&tmp);
        mkdirp(&tmp.join("1234"));
        writef(&tmp.join("1234/comm"), "bash\n");
        mkdirp(&tmp.join("not-a-pid"));
        writef(&tmp.join("not-a-pid/comm"), "haveged\n");

        assert!(!is_haveged_running_in(&tmp));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_is_haveged_running_detects_haveged_pid() {
        let tmp = std::env::temp_dir().join("mixrand_test_haveged_present");
        let _ = fs::remove_dir_all(&tmp);
        mkdirp(&tmp.join("77"));
        writef(&tmp.join("77/comm"), "haveged\n");

        assert!(is_haveged_running_in(&tmp));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_has_sufficient_entropy_missing_path() {
        assert!(!has_sufficient_entropy_at(
            "/nonexistent/mixrand_entropy_avail",
            1
        ));
    }

    #[test]
    fn test_has_sufficient_entropy_below_threshold() {
        let path = std::env::temp_dir().join("mixrand_entropy_low.txt");
        writef(&path, "500\n");
        assert!(!has_sufficient_entropy_at(&path, 1024));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_has_sufficient_entropy_meets_threshold() {
        let path = std::env::temp_dir().join("mixrand_entropy_ok.txt");
        writef(&path, "2048\n");
        assert!(has_sufficient_entropy_at(&path, 1024));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_has_sufficient_entropy_non_numeric() {
        let path = std::env::temp_dir().join("mixrand_entropy_junk.txt");
        writef(&path, "not-a-number\n");
        assert!(!has_sufficient_entropy_at(&path, 1));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_read_haveged_public_api() {
        // Either haveged is running with entropy (returns Ok) or it's not
        // (returns NoEntropy). Anything else is a regression.
        match read_haveged(1) {
            Ok(b) => assert_eq!(b.len(), 1),
            Err(Error::NoEntropy(_)) => {}
            Err(Error::Io(_)) => {}
            Err(e) => unreachable!("read_haveged produced an unexpected error variant: {e}"),
        }
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests_non_linux {
    use super::*;

    #[test]
    fn test_read_haveged_non_linux_errors() {
        let result = read_haveged(16);
        assert!(matches!(result, Err(Error::NoEntropy(_))));
    }
}
