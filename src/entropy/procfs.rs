use std::fs;

/// Reads raw bytes from /proc/interrupts.
pub fn read_interrupts() -> Vec<u8> {
    fs::read("/proc/interrupts").unwrap_or_default()
}

/// Reads raw bytes from /proc/stat.
pub fn read_stat() -> Vec<u8> {
    fs::read("/proc/stat").unwrap_or_default()
}

/// Reads raw bytes from /proc/diskstats.
pub fn read_diskstats() -> Vec<u8> {
    fs::read("/proc/diskstats").unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_interrupts_graceful() {
        // On macOS /proc doesn't exist, should return empty Vec
        // On Linux, should return non-empty data
        let data = read_interrupts();
        if cfg!(target_os = "linux") {
            assert!(!data.is_empty());
        }
        // On any platform, should not panic
    }

    #[test]
    fn test_read_stat_graceful() {
        let data = read_stat();
        if cfg!(target_os = "linux") {
            assert!(!data.is_empty());
        }
    }

    #[test]
    fn test_read_diskstats_graceful() {
        let data = read_diskstats();
        // Should not panic on any platform
        let _ = data;
    }

    #[test]
    fn test_procfs_returns_bytes() {
        // All functions should return Vec<u8> without panicking
        let _ = read_interrupts();
        let _ = read_stat();
        let _ = read_diskstats();
    }
}
