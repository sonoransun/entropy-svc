/// Reads raw bytes from /proc/interrupts (Linux only).
#[cfg(target_os = "linux")]
pub fn read_interrupts() -> Vec<u8> {
    std::fs::read("/proc/interrupts").unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
pub fn read_interrupts() -> Vec<u8> {
    Vec::new()
}

/// Reads raw bytes from /proc/stat (Linux only).
#[cfg(target_os = "linux")]
pub fn read_stat() -> Vec<u8> {
    std::fs::read("/proc/stat").unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
pub fn read_stat() -> Vec<u8> {
    Vec::new()
}

/// Reads raw bytes from /proc/diskstats (Linux only).
#[cfg(target_os = "linux")]
pub fn read_diskstats() -> Vec<u8> {
    std::fs::read("/proc/diskstats").unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
pub fn read_diskstats() -> Vec<u8> {
    Vec::new()
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
