//! Memory locking utilities to prevent sensitive data from being swapped to disk.
//!
//! Uses mlock(2) to lock pages in physical memory and madvise(MADV_DONTDUMP)
//! to exclude them from core dumps. Failures are logged but not fatal, since
//! the user may lack CAP_IPC_LOCK.

/// Lock a byte slice into physical memory (prevent swapping).
/// Logs a warning and returns false if mlock fails.
#[cfg(unix)]
pub fn mlock_slice(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    let ret = unsafe { libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) };
    if ret != 0 {
        log::warn!(
            "mlock failed for {} bytes: {} (missing CAP_IPC_LOCK?)",
            buf.len(),
            std::io::Error::last_os_error()
        );
        return false;
    }
    true
}

#[cfg(not(unix))]
pub fn mlock_slice(_buf: &[u8]) -> bool {
    true // no-op on non-Unix platforms
}

/// Unlock a previously mlocked byte slice.
#[cfg(unix)]
pub fn munlock_slice(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    unsafe {
        libc::munlock(buf.as_ptr() as *const libc::c_void, buf.len());
    }
}

#[cfg(not(unix))]
pub fn munlock_slice(_buf: &[u8]) {}

/// Mark a byte slice as excluded from core dumps via madvise(MADV_DONTDUMP).
/// This is Linux-specific; on other platforms it is a no-op.
pub fn dontdump_slice(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        unsafe {
            libc::madvise(
                buf.as_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MADV_DONTDUMP,
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = buf;
    }
}

/// Convenience: mlock + dontdump a byte slice.
pub fn lock_and_protect(buf: &[u8]) -> bool {
    let locked = mlock_slice(buf);
    dontdump_slice(buf);
    locked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlock_empty_slice() {
        assert!(mlock_slice(&[]));
    }

    #[test]
    fn test_munlock_empty_slice() {
        munlock_slice(&[]); // should not panic
    }

    #[test]
    fn test_dontdump_empty_slice() {
        dontdump_slice(&[]); // should not panic
    }

    #[test]
    fn test_mlock_small_buffer() {
        let buf = vec![0u8; 64];
        // mlock may fail without CAP_IPC_LOCK, but should not panic
        let _ = mlock_slice(&buf);
        munlock_slice(&buf);
    }

    #[test]
    fn test_lock_and_protect() {
        let buf = vec![0u8; 32];
        let _ = lock_and_protect(&buf);
        munlock_slice(&buf);
    }
}
