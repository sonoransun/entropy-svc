use crate::error::Error;

/// Read `count` bytes using the platform's best system call for random bytes.
///
/// - On Linux: uses `getrandom(2)` syscall (available since 3.17)
/// - On macOS: uses `getentropy(3)` in 256-byte chunks (available since 10.12)
/// - Falls back to error on unsupported platforms.
pub fn read_getrandom(count: usize) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; count];
    sys_getrandom(&mut buf)?;
    Ok(buf)
}

/// Platform-specific system call implementation.
#[cfg(target_os = "linux")]
fn sys_getrandom(buf: &mut [u8]) -> Result<(), Error> {
    let mut offset = 0;
    while offset < buf.len() {
        let ret = unsafe {
            libc::getrandom(
                buf[offset..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - offset,
                0, // flags: 0 = blocking, same as /dev/urandom
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::NoEntropy(format!("getrandom() failed: {}", err)));
        }
        let n = ret as usize;
        if n > buf.len() - offset {
            return Err(Error::NoEntropy(
                "getrandom() returned more bytes than requested".into(),
            ));
        }
        offset += n;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn sys_getrandom(buf: &mut [u8]) -> Result<(), Error> {
    // getentropy(3) is limited to 256 bytes per call on macOS
    for chunk in buf.chunks_mut(256) {
        let ret = unsafe { libc::getentropy(chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
        if ret != 0 {
            return Err(Error::NoEntropy(format!(
                "getentropy() failed: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn sys_getrandom(_buf: &mut [u8]) -> Result<(), Error> {
    Err(Error::NoEntropy(
        "getrandom/getentropy not available on this platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_getrandom_basic() {
        let result = read_getrandom(32);
        // Should succeed on Linux and macOS
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            let buf = result.unwrap();
            assert_eq!(buf.len(), 32);
            // Verify it's not all zeros (extremely unlikely for real random)
            assert!(buf.iter().any(|&b| b != 0), "getrandom returned all zeros");
        }
    }

    #[test]
    fn test_read_getrandom_large() {
        // Test > 256 bytes to exercise chunking on macOS
        let result = read_getrandom(1024);
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            let buf = result.unwrap();
            assert_eq!(buf.len(), 1024);
        }
    }

    #[test]
    fn test_read_getrandom_zero() {
        let result = read_getrandom(0);
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            let buf = result.unwrap();
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn test_read_getrandom_single_byte() {
        let result = read_getrandom(1);
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            let buf = result.unwrap();
            assert_eq!(buf.len(), 1);
        }
    }

    #[test]
    fn test_read_getrandom_uniqueness() {
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            let a = read_getrandom(32).unwrap();
            let b = read_getrandom(32).unwrap();
            assert_ne!(a, b);
        }
    }
}
