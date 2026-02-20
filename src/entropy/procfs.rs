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
