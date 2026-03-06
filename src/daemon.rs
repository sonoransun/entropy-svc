use crate::cli::DaemonArgs;
#[cfg(target_os = "linux")]
use crate::config;
use crate::config::CpuRngConfig;
use crate::error::Error;

#[cfg(not(target_os = "linux"))]
pub fn run(_args: &DaemonArgs, _cpu_config: &CpuRngConfig) -> Result<(), Error> {
    Err(Error::InvalidArgs(
        "daemon mode is only supported on Linux".into(),
    ))
}

#[cfg(target_os = "linux")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use crate::entropy;
#[cfg(target_os = "linux")]
use crate::entropy::cpurng::zeroize_vec;
#[cfg(target_os = "linux")]
use crate::health::HealthTester;
#[cfg(target_os = "linux")]
use crate::memlock;

#[cfg(target_os = "linux")]
const RNDADDENTROPY: libc::c_ulong = 0x40085203;

#[cfg(target_os = "linux")]
static SHUTDOWN: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "linux")]
static RELOAD: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
/// Build the `rand_pool_info` struct as a raw byte buffer:
/// ```text
/// struct rand_pool_info {
///     int entropy_count;  // number of bits of entropy to credit
///     int buf_size;       // number of bytes in buf
///     __u32 buf[];        // entropy data (must be u32-aligned)
/// };
/// ```
fn build_rand_pool_info(data: &[u8], entropy_bits: u32) -> Vec<u8> {
    let buf_size = data.len() as i32;
    // Pad data to 4-byte alignment
    let padded_len = (data.len() + 3) & !3;
    let total = 4 + 4 + padded_len;
    let mut buf = vec![0u8; total];
    buf[0..4].copy_from_slice(&(entropy_bits as i32).to_ne_bytes());
    buf[4..8].copy_from_slice(&buf_size.to_ne_bytes());
    buf[8..8 + data.len()].copy_from_slice(data);
    buf
}

#[cfg(target_os = "linux")]
/// Inject entropy into the kernel pool via ioctl(RNDADDENTROPY).
/// The ioctl buffer is zeroized after use regardless of success or failure.
fn inject_entropy(dev_random: &File, data: &[u8], entropy_bits: u32) -> Result<(), Error> {
    let mut buf = build_rand_pool_info(data, entropy_bits);
    memlock::lock_and_protect(&buf);
    let ret = unsafe { libc::ioctl(dev_random.as_raw_fd(), RNDADDENTROPY, buf.as_ptr()) };
    memlock::munlock_slice(&buf);
    zeroize_vec(&mut buf);
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
/// Read the current kernel entropy estimate from procfs.
fn read_entropy_avail() -> Result<u32, Error> {
    let s = fs::read_to_string("/proc/sys/kernel/random/entropy_avail")?;
    s.trim()
        .parse::<u32>()
        .map_err(|e| Error::NoEntropy(format!("failed to parse entropy_avail: {}", e)))
}

#[cfg(target_os = "linux")]
/// Validate that we can open /dev/random for writing (requires root).
fn validate_permissions() -> Result<File, Error> {
    OpenOptions::new()
        .write(true)
        .open("/dev/random")
        .map_err(|e| {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "cannot open /dev/random for writing: {} (are you root?)",
                    e
                ),
            ))
        })
}

/// Drop privileges to the specified user.
/// Calls getpwnam -> setgroups(0) -> setgid -> setuid.
/// Must be called while still root.
#[cfg(target_os = "linux")]
fn drop_privileges(username: &str) -> Result<(), Error> {
    use std::ffi::CString;

    let c_user = CString::new(username).map_err(|_| {
        Error::InvalidArgs(format!("invalid username: {}", username))
    })?;

    let pw = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if pw.is_null() {
        return Err(Error::InvalidArgs(format!("user not found: {}", username)));
    }

    let uid = unsafe { (*pw).pw_uid };
    let gid = unsafe { (*pw).pw_gid };

    // Drop supplementary groups
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    // Set GID first (must happen before setuid drops root)
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    // Set UID
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    // Verify we can't regain root
    if unsafe { libc::setuid(0) } == 0 {
        return Err(Error::InvalidArgs(
            "privilege drop failed: was able to regain uid 0".into(),
        ));
    }

    log::info!(
        target: "mixrand::daemon",
        "dropped privileges to user {} (uid={}, gid={})",
        username, uid, gid,
    );

    Ok(())
}

#[cfg(target_os = "linux")]
/// Write a PID file. Checks if an existing PID is alive via kill(pid, 0).
fn write_pid_file(path: &Path) -> Result<(), Error> {
    // Check if another instance is running
    if path.exists() {
        if let Ok(contents) = fs::read_to_string(path) {
            if let Ok(pid) = contents.trim().parse::<i32>() {
                if unsafe { libc::kill(pid, 0) } == 0 {
                    return Err(Error::InvalidArgs(format!(
                        "another instance is running (pid {})",
                        pid
                    )));
                }
            }
        }
        // Stale PID file, remove it
        let _ = fs::remove_file(path);
    }

    let pid = std::process::id();
    fs::write(path, format!("{}\n", pid)).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("failed to write PID file {}: {}", path.display(), e),
        ))
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_pid_file(path: &Path) {
    let _ = fs::remove_file(path);
}

#[cfg(target_os = "linux")]
/// Send a systemd notification if $NOTIFY_SOCKET is set.
fn sd_notify(state: &str) {
    if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
        use std::os::unix::net::UnixDatagram;
        if let Ok(sock) = UnixDatagram::unbound() {
            let _ = sock.send_to(state.as_bytes(), &socket_path);
        }
    }
}

#[cfg(target_os = "linux")]
extern "C" fn shutdown_handler(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Release);
}

#[cfg(target_os = "linux")]
extern "C" fn reload_handler(_sig: libc::c_int) {
    RELOAD.store(true, Ordering::Release);
}

#[cfg(target_os = "linux")]
fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = shutdown_handler as libc::sighandler_t;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());

        // SIGHUP triggers config reload
        let mut sa_hup: libc::sigaction = std::mem::zeroed();
        sa_hup.sa_sigaction = reload_handler as libc::sighandler_t;
        sa_hup.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa_hup.sa_mask);
        libc::sigaction(libc::SIGHUP, &sa_hup, std::ptr::null_mut());
    }
}

#[cfg(target_os = "linux")]
/// Interruptible sleep: sleeps in 250ms steps, checking SHUTDOWN between each.
fn interruptible_sleep(total: Duration) {
    let step = Duration::from_millis(250);
    let mut remaining = total;
    while remaining > Duration::ZERO && !SHUTDOWN.load(Ordering::Acquire) {
        let s = remaining.min(step);
        thread::sleep(s);
        remaining = remaining.saturating_sub(s);
    }
}

#[cfg(target_os = "linux")]
/// Compute adaptive sleep duration based on current entropy level.
/// Critical low (< threshold/2) -> 100ms, low (< threshold) -> 1s, normal -> configured interval.
fn adaptive_sleep(avail: u32, threshold: u32, normal_interval: u64) -> Duration {
    if avail < threshold / 2 {
        Duration::from_millis(100)
    } else if avail < threshold {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(normal_interval)
    }
}

#[cfg(target_os = "linux")]
fn health_check_bytes(data: &[u8], health: &mut HealthTester) -> bool {
    for chunk in data.chunks_exact(8) {
        let sample = u64::from_ne_bytes(chunk.try_into().unwrap());
        if health.feed(sample).is_err() {
            return false;
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn reload_config(config_path: Option<&Path>, cpu_config: &mut CpuRngConfig) {
    match config::load_config(config_path) {
        Ok(c) => {
            let mut new_cfg = c.cpu_rng;
            config::apply_env_overrides(&mut new_cfg);
            let warnings = new_cfg.validate();
            for w in warnings {
                log::warn!(target: "mixrand::daemon", "config: {}", w);
            }
            *cpu_config = new_cfg;
            log::info!(target: "mixrand::daemon", "config reloaded successfully");
        }
        Err(e) => {
            log::error!(target: "mixrand::daemon", "config reload failed: {}", e);
        }
    }
}

#[cfg(target_os = "linux")]
pub fn run(args: &DaemonArgs, cpu_config: &CpuRngConfig) -> Result<(), Error> {
    if args.batch_size == 0 {
        return Err(Error::InvalidArgs("batch-size must be greater than 0".into()));
    }

    let dev_random = validate_permissions()?;

    // Lock all process memory to prevent swapping entropy data to disk
    let ret = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if ret != 0 {
        log::warn!(
            target: "mixrand::daemon",
            "mlockall failed: {} (consider CAP_IPC_LOCK)",
            std::io::Error::last_os_error()
        );
    }

    install_signal_handlers();

    // Write PID file if requested
    let pid_file_path: Option<PathBuf> = args.pid_file.clone();
    if let Some(ref path) = pid_file_path {
        write_pid_file(path)?;
    }

    // Drop privileges after opening /dev/random and installing signal handlers
    if let Some(ref user) = args.user {
        drop_privileges(user)?;
    }

    let config_path: Option<PathBuf> = args.config_file.clone();
    let mut cpu_config = cpu_config.clone();

    log::info!(
        target: "mixrand::daemon",
        "started: threshold={}bits interval={}s batch={}B credit={}bits/byte",
        args.threshold, args.interval, args.batch_size, args.credit_ratio,
    );

    // Notify systemd we're ready
    sd_notify("READY=1");

    let start = Instant::now();
    let mut total_injections: u64 = 0;
    let mut total_bytes_injected: u64 = 0;
    let mut health_skips: u64 = 0;
    let mut last_heartbeat = Instant::now();
    let heartbeat_interval = Duration::from_secs(300); // 5 minutes
    let mut last_sleep;
    let mut health = HealthTester::new(4.0);

    while !SHUTDOWN.load(Ordering::Acquire) {
        // Check for config reload signal
        if RELOAD.swap(false, Ordering::Acquire) {
            log::info!(target: "mixrand::daemon", "SIGHUP received, reloading config");
            reload_config(config_path.as_deref(), &mut cpu_config);
        }

        match read_entropy_avail() {
            Ok(avail) => {
                if avail < args.threshold {
                    match entropy::generate(args.batch_size, &cpu_config) {
                        Ok(result) => {
                            let mut data = result.bytes;
                            memlock::lock_and_protect(&data);

                            // Health check before injection
                            if !health_check_bytes(&data, &mut health) {
                                log::warn!(
                                    target: "mixrand::daemon",
                                    "health check failed for {} output, skipping injection",
                                    result.source,
                                );
                                health_skips += 1;
                                memlock::munlock_slice(&data);
                                zeroize_vec(&mut data);
                                last_sleep = Duration::from_secs(1);
                                continue;
                            }

                            let credit_bits = args.batch_size as u32 * args.credit_ratio;
                            match inject_entropy(&dev_random, &data, credit_bits) {
                                Ok(()) => {
                                    total_injections += 1;
                                    total_bytes_injected += args.batch_size as u64;
                                    log::info!(
                                        target: "mixrand::daemon",
                                        "injected {}B ({}bits credit) from {}, entropy was {}bits",
                                        args.batch_size, credit_bits, result.source, avail,
                                    );
                                }
                                Err(e) => {
                                    log::error!(
                                        target: "mixrand::daemon",
                                        "ioctl failed: {}", e,
                                    );
                                }
                            }
                            memlock::munlock_slice(&data);
                            zeroize_vec(&mut data);
                        }
                        Err(e) => {
                            log::error!(
                                target: "mixrand::daemon",
                                "entropy generation failed: {}", e,
                            );
                        }
                    }

                    // Adaptive rate
                    last_sleep = adaptive_sleep(avail, args.threshold, args.interval);
                } else {
                    log::debug!(
                        target: "mixrand::daemon",
                        "entropy OK: {}bits (threshold {})",
                        avail, args.threshold,
                    );
                    last_sleep = Duration::from_secs(args.interval);
                }
            }
            Err(e) => {
                log::error!(
                    target: "mixrand::daemon",
                    "failed to read entropy_avail: {}", e,
                );
                last_sleep = Duration::from_secs(args.interval);
            }
        }

        // Heartbeat logging
        if last_heartbeat.elapsed() >= heartbeat_interval {
            let uptime = start.elapsed();
            log::info!(
                target: "mixrand::daemon",
                "heartbeat: uptime={}s injections={} total_bytes={} health_skips={} rct_failures={} apt_failures={}",
                uptime.as_secs(), total_injections, total_bytes_injected,
                health_skips, health.rct_failures(), health.apt_failures(),
            );
            last_heartbeat = Instant::now();
        }

        // Send systemd watchdog ping
        sd_notify("WATCHDOG=1");

        interruptible_sleep(last_sleep);
    }

    log::info!(
        target: "mixrand::daemon",
        "shutting down (injections={}, bytes={}, health_skips={})",
        total_injections, total_bytes_injected, health_skips,
    );

    // Clean up PID file
    if let Some(ref path) = pid_file_path {
        remove_pid_file(path);
    }

    sd_notify("STOPPING=1");

    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn test_build_rand_pool_info_basic() {
        let data = [0xAA, 0xBB, 0xCC, 0xDD];
        let buf = build_rand_pool_info(&data, 32);
        // Header: entropy_count(4) + buf_size(4) + padded data(4) = 12
        assert_eq!(buf.len(), 12);
        // entropy_count = 32
        let entropy_count = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(entropy_count, 32);
        // buf_size = 4
        let buf_size = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(buf_size, 4);
        // data bytes
        assert_eq!(&buf[8..12], &data);
    }

    #[test]
    fn test_build_rand_pool_info_padding() {
        // 5 bytes of data should be padded to 8 (next 4-byte boundary)
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let buf = build_rand_pool_info(&data, 40);
        // 4 + 4 + 8 = 16
        assert_eq!(buf.len(), 16);
        let buf_size = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(buf_size, 5);
        assert_eq!(&buf[8..13], &data);
        // Padding bytes should be zero
        assert_eq!(&buf[13..16], &[0, 0, 0]);
    }

    #[test]
    fn test_build_rand_pool_info_aligned() {
        // 8 bytes: already 4-byte aligned
        let data = [0xFF; 8];
        let buf = build_rand_pool_info(&data, 64);
        assert_eq!(buf.len(), 16); // 4 + 4 + 8
    }

    #[test]
    fn test_build_rand_pool_info_empty() {
        let buf = build_rand_pool_info(&[], 0);
        assert_eq!(buf.len(), 8); // just the two header ints
        let entropy_count = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(entropy_count, 0);
    }

    // --- adaptive_sleep ---

    #[test]
    fn test_adaptive_sleep_critical() {
        // avail < threshold/2 -> 100ms
        assert_eq!(adaptive_sleep(50, 256, 5), Duration::from_millis(100));
    }

    #[test]
    fn test_adaptive_sleep_low() {
        // avail < threshold -> 1s
        assert_eq!(adaptive_sleep(200, 256, 5), Duration::from_secs(1));
    }

    #[test]
    fn test_adaptive_sleep_normal() {
        // avail >= threshold -> normal interval
        assert_eq!(adaptive_sleep(512, 256, 5), Duration::from_secs(5));
    }

    #[test]
    fn test_adaptive_sleep_boundary() {
        // avail == threshold/2 (128 for threshold 256)
        // 128 < 256 so it's "low" -> 1s
        assert_eq!(adaptive_sleep(128, 256, 5), Duration::from_secs(1));
        // avail == threshold -> normal
        assert_eq!(adaptive_sleep(256, 256, 5), Duration::from_secs(5));
    }
}
