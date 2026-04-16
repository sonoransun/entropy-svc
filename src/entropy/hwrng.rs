use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::Error;

/// Attempts to read `count` bytes from `/dev/hwrng` (hardware RNG).
///
/// Returns `Err(Error::NoEntropy)` if the device is missing or unreadable, and
/// `Err(Error::Io)` if the device is present but returns fewer than `count`
/// bytes (EOF before satisfying the request).
pub fn read_hwrng(count: usize) -> Result<Vec<u8>, Error> {
    read_hwrng_from(Path::new("/dev/hwrng"), count)
}

/// Internal variant that accepts an arbitrary path, for unit testing against a
/// fixture file instead of the kernel's `/dev/hwrng` device.
pub(crate) fn read_hwrng_from(path: &Path, count: usize) -> Result<Vec<u8>, Error> {
    let mut f = File::open(path)
        .map_err(|e| Error::NoEntropy(format!("{} not available: {}", path.display(), e)))?;
    let mut buf = vec![0u8; count];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_fixture(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        let mut f = File::create(&path).expect("test setup: File::create");
        f.write_all(contents).expect("test setup: write_all");
        path
    }

    #[test]
    fn test_read_hwrng_from_fixture() {
        let path = write_fixture("mixrand_test_hwrng_fixture.bin", &[1, 2, 3, 4]);
        let result = read_hwrng_from(&path, 4).unwrap();
        assert_eq!(result, &[1, 2, 3, 4]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_hwrng_missing_path() {
        let path = std::path::Path::new("/nonexistent/mixrand_hwrng_stub");
        let result = read_hwrng_from(path, 4);
        assert!(matches!(result, Err(Error::NoEntropy(_))));
    }

    #[test]
    fn test_read_hwrng_short_fixture() {
        // Fixture has 3 bytes; request 8 — must fail on EOF.
        let path = write_fixture("mixrand_test_hwrng_short.bin", &[9, 9, 9]);
        let result = read_hwrng_from(&path, 8);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_hwrng_zero_count() {
        let path = write_fixture("mixrand_test_hwrng_zero.bin", &[1, 2]);
        let result = read_hwrng_from(&path, 0).unwrap();
        assert!(result.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_hwrng_public_api() {
        // If /dev/hwrng exists, reads should succeed; if not, NoEntropy.
        // Either outcome proves the public API is correctly plumbed.
        match read_hwrng(1) {
            Ok(b) => assert_eq!(b.len(), 1),
            Err(Error::NoEntropy(_)) => {}
            Err(e) => unreachable!("read_hwrng produced an unexpected error variant: {e}"),
        }
    }
}
