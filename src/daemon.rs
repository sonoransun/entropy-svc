use crate::cli::DaemonArgs;
#[cfg(target_os = "linux")]
use crate::config;
use crate::config::Config;
use crate::error::Error;

#[cfg(not(target_os = "linux"))]
pub fn run(_args: &DaemonArgs, _config: &Config) -> Result<(), Error> {
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
use crate::health::HealthTester;
#[cfg(target_os = "linux")]
use crate::memlock;
#[cfg(target_os = "linux")]
use crate::sensitive::SensitiveBytes;

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
/// The ioctl envelope is wrapped in [`SensitiveBytes`] so its contents are
/// zeroized when the function returns, regardless of success, failure, or
/// panic between the ioctl and the Drop point.
fn inject_entropy(dev_random: &File, data: &[u8], entropy_bits: u32) -> Result<(), Error> {
    let buf = SensitiveBytes::new(build_rand_pool_info(data, entropy_bits));
    memlock::lock_and_protect(&buf);
    let ret = unsafe { libc::ioctl(dev_random.as_raw_fd(), RNDADDENTROPY, buf.as_ptr()) };
    memlock::munlock_slice(&buf);
    drop(buf); // explicit zeroize before error handling
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
                format!("cannot open /dev/random for writing: {} (are you root?)", e),
            ))
        })
}

/// Drop privileges to the specified user.
/// Calls getpwnam -> setgroups(0) -> setgid -> setuid.
/// Must be called while still root.
#[cfg(target_os = "linux")]
fn drop_privileges(username: &str) -> Result<(), Error> {
    use std::ffi::CString;

    let c_user = CString::new(username)
        .map_err(|_| Error::InvalidArgs(format!("invalid username: {}", username)))?;

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
/// Write a PID file using exclusive create (O_CREAT|O_EXCL).
///
/// Sequence:
///   1. Try `create_new(path)` — fails fast with `AlreadyExists` if a PID
///      file is already present.
///   2. On `AlreadyExists`, read the recorded PID. If it is live per
///      `kill(pid, 0)`, refuse to start (another instance is running).
///      Otherwise the file is stale — remove it and retry the exclusive
///      create exactly once.
///
/// Exclusive create closes the narrow TOCTOU window between checking the
/// recorded PID and writing our own. If two daemons race the stale-cleanup
/// path, only the one whose `create_new` wins proceeds; the other sees
/// `AlreadyExists` on the retry and exits with the proper error.
fn write_pid_file(path: &Path) -> Result<(), Error> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    fn try_create(path: &Path) -> std::io::Result<fs::File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(path)
    }

    let pid_text = format!("{}\n", std::process::id());

    let mut file = match try_create(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Inspect the existing file's PID.
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
            // Stale — best-effort remove, then retry exactly once.
            let _ = fs::remove_file(path);
            try_create(path).map_err(|e| {
                Error::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to create PID file {} after stale cleanup: {}",
                        path.display(),
                        e
                    ),
                ))
            })?
        }
        Err(e) => {
            return Err(Error::Io(std::io::Error::new(
                e.kind(),
                format!("failed to create PID file {}: {}", path.display(), e),
            )));
        }
    };

    file.write_all(pid_text.as_bytes()).map_err(|e| {
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
        sa.sa_sigaction = shutdown_handler as *const () as libc::sighandler_t;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());

        // SIGHUP triggers config reload
        let mut sa_hup: libc::sigaction = std::mem::zeroed();
        sa_hup.sa_sigaction = reload_handler as *const () as libc::sighandler_t;
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
fn reload_config(config_path: Option<&Path>, full_config: &mut Config) {
    match config::load_config(config_path) {
        Ok(c) => {
            let mut new_cfg = c;
            config::apply_env_overrides(&mut new_cfg.cpu_rng);
            config::apply_hsm_env_overrides(&mut new_cfg.hsm);
            let warnings = new_cfg.cpu_rng.validate();
            for w in warnings {
                log::warn!(target: "mixrand::daemon", "config: {}", w);
            }
            let hsm_warnings = new_cfg.hsm.validate();
            for w in hsm_warnings {
                log::warn!(target: "mixrand::daemon", "config: {}", w);
            }
            *full_config = new_cfg;
            log::info!(target: "mixrand::daemon", "config reloaded successfully");
        }
        Err(e) => {
            log::error!(target: "mixrand::daemon", "config reload failed: {}", e);
        }
    }
}

/// Outcome of a single source in a startup self-test.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub enum SelfTestOutcome {
    /// Source produced bytes that passed RCT+APT health tests.
    Ok { bytes_sampled: usize },
    /// Source failed to collect (unavailable, error).
    CollectError(String),
    /// Source collected bytes but they failed RCT or APT.
    HealthFailed,
}

/// Result of `self_test`: one entry per source plus a summary flag.
#[cfg(target_os = "linux")]
pub struct SelfTestReport {
    pub per_source: Vec<(String, SelfTestOutcome)>,
    pub all_failed: bool,
    pub duration: Duration,
}

/// Probe every source in `sources`, collect `sample_size` bytes from each,
/// and run a quick NIST SP 800-90B health pass on what comes back. Intended
/// to run at daemon start so a systemd `Type=notify` service correctly
/// marks start-up failure when no entropy source is usable.
#[cfg(target_os = "linux")]
pub fn self_test(
    sources: &[Box<dyn crate::entropy::EntropySource>],
    sample_size: usize,
) -> SelfTestReport {
    let start = Instant::now();
    let mut per_source = Vec::with_capacity(sources.len());
    let mut any_ok = false;

    for source in sources {
        let outcome = match source.collect(sample_size) {
            Ok(bytes) => {
                // Wrap so the sample is zeroized on drop.
                let sample = SensitiveBytes::new(bytes);
                if health_check_bytes(
                    &sample,
                    &mut HealthTester::new(crate::health::DEFAULT_MIN_ENTROPY_BITS),
                ) {
                    any_ok = true;
                    SelfTestOutcome::Ok {
                        bytes_sampled: sample.len(),
                    }
                } else {
                    SelfTestOutcome::HealthFailed
                }
            }
            Err(e) => SelfTestOutcome::CollectError(e.to_string()),
        };
        per_source.push((source.name().to_string(), outcome));
    }

    SelfTestReport {
        per_source,
        all_failed: !any_ok,
        duration: start.elapsed(),
    }
}

#[cfg(target_os = "linux")]
pub fn run(args: &DaemonArgs, config: &Config) -> Result<(), Error> {
    if args.batch_size == 0 {
        return Err(Error::InvalidArgs(
            "batch-size must be greater than 0".into(),
        ));
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
    let mut full_config = config.clone();

    // Startup self-test: probe every source and run health tests before
    // telling systemd we're ready. Refuse to enter the main loop if every
    // source is unusable.
    if !args.no_self_test {
        let sources = entropy::build_check_sources(&full_config);
        let report = self_test(&sources, 256);
        log::info!(
            target: "mixrand::daemon",
            "self-test completed in {}ms ({} sources probed)",
            report.duration.as_millis(),
            report.per_source.len(),
        );
        for (name, outcome) in &report.per_source {
            match outcome {
                SelfTestOutcome::Ok { bytes_sampled } => log::info!(
                    target: "mixrand::daemon",
                    "self-test: {} OK ({} bytes)", name, bytes_sampled,
                ),
                SelfTestOutcome::HealthFailed => log::warn!(
                    target: "mixrand::daemon",
                    "self-test: {} health-test failed", name,
                ),
                SelfTestOutcome::CollectError(e) => log::debug!(
                    target: "mixrand::daemon",
                    "self-test: {} unavailable: {}", name, e,
                ),
            }
        }
        if report.all_failed {
            return Err(Error::NoEntropy(
                "startup self-test: all entropy sources failed".into(),
            ));
        }
    } else {
        log::warn!(
            target: "mixrand::daemon",
            "startup self-test disabled via --no-self-test",
        );
    }

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
    let mut gen_errors: u64 = 0;
    let mut last_heartbeat = Instant::now();
    let heartbeat_interval = Duration::from_secs(300); // 5 minutes
    let mut last_sleep;
    let mut health = HealthTester::new(crate::health::DEFAULT_MIN_ENTROPY_BITS);

    while !SHUTDOWN.load(Ordering::Acquire) {
        // Check for config reload signal
        if RELOAD.swap(false, Ordering::Acquire) {
            log::info!(target: "mixrand::daemon", "SIGHUP received, reloading config");
            reload_config(config_path.as_deref(), &mut full_config);
        }

        match read_entropy_avail() {
            Ok(avail) => {
                if avail < args.threshold {
                    match entropy::generate(args.batch_size, &full_config) {
                        Ok(result) => {
                            let data = SensitiveBytes::new(result.bytes);
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
                                drop(data);
                                // `continue` jumps to loop head which
                                // re-reads entropy_avail and re-assigns
                                // last_sleep before the next sleep point.
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
                            // Drop of `data` zeroizes the buffer.
                        }
                        Err(e) => {
                            log::error!(
                                target: "mixrand::daemon",
                                "entropy generation failed: {}", e,
                            );
                            gen_errors += 1;
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
                "heartbeat: uptime={}s injections={} total_bytes={} health_skips={} gen_errors={} rct_failures={} apt_failures={}",
                uptime.as_secs(), total_injections, total_bytes_injected,
                health_skips, gen_errors, health.rct_failures(), health.apt_failures(),
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

    #[test]
    fn test_build_rand_pool_info_single_byte() {
        let buf = build_rand_pool_info(&[0x42], 8);
        // 1 byte padded to 4: total = 4 + 4 + 4 = 12
        assert_eq!(buf.len(), 12);
        let buf_size = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(buf_size, 1);
        assert_eq!(buf[8], 0x42);
        // Padding bytes should be zero
        assert_eq!(buf[9], 0);
        assert_eq!(buf[10], 0);
        assert_eq!(buf[11], 0);
    }

    #[test]
    fn test_build_rand_pool_info_three_bytes() {
        let buf = build_rand_pool_info(&[1, 2, 3], 24);
        // 3 bytes padded to 4: total = 4 + 4 + 4 = 12
        assert_eq!(buf.len(), 12);
        assert_eq!(buf[8], 1);
        assert_eq!(buf[9], 2);
        assert_eq!(buf[10], 3);
        assert_eq!(buf[11], 0); // padding
    }

    #[test]
    fn test_adaptive_sleep_zero_threshold() {
        // threshold=0, threshold/2=0. avail(0) < 0 is false, so normal interval
        assert_eq!(adaptive_sleep(0, 0, 5), Duration::from_secs(5));
    }

    // --- Self-test unit tests ---

    use crate::entropy::EntropySource;
    use crate::error::Error;

    struct GoodSource;
    impl EntropySource for GoodSource {
        fn name(&self) -> &str {
            "good"
        }
        fn description(&self) -> &str {
            "test: always succeeds with high entropy"
        }
        fn priority(&self) -> u32 {
            1
        }
        fn is_available(&self) -> bool {
            true
        }
        fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
            // Pseudo-random byte sequence that passes RCT/APT: use a simple LCG.
            let mut out = Vec::with_capacity(count);
            let mut x: u64 = 0xdead_beef_cafe_f00d;
            for _ in 0..count {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                out.push((x >> 56) as u8);
            }
            Ok(out)
        }
    }

    struct FailingSource;
    impl EntropySource for FailingSource {
        fn name(&self) -> &str {
            "failing"
        }
        fn description(&self) -> &str {
            "test: always errors"
        }
        fn priority(&self) -> u32 {
            2
        }
        fn is_available(&self) -> bool {
            false
        }
        fn collect(&self, _count: usize) -> Result<Vec<u8>, Error> {
            Err(Error::NoEntropy("test source deliberately fails".into()))
        }
    }

    struct StuckSource;
    impl EntropySource for StuckSource {
        fn name(&self) -> &str {
            "stuck"
        }
        fn description(&self) -> &str {
            "test: returns all-zero (fails RCT)"
        }
        fn priority(&self) -> u32 {
            3
        }
        fn is_available(&self) -> bool {
            true
        }
        fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
            Ok(vec![0u8; count])
        }
    }

    #[test]
    fn test_self_test_all_failed_when_no_sources_healthy() {
        let sources: Vec<Box<dyn EntropySource>> =
            vec![Box::new(FailingSource), Box::new(StuckSource)];
        let report = self_test(&sources, 256);
        assert!(report.all_failed);
        assert_eq!(report.per_source.len(), 2);
        assert!(matches!(
            report.per_source[0].1,
            SelfTestOutcome::CollectError(_)
        ));
        assert!(matches!(
            report.per_source[1].1,
            SelfTestOutcome::HealthFailed
        ));
    }

    #[test]
    fn test_self_test_not_all_failed_if_any_source_ok() {
        let sources: Vec<Box<dyn EntropySource>> =
            vec![Box::new(FailingSource), Box::new(GoodSource)];
        let report = self_test(&sources, 256);
        assert!(!report.all_failed);
        // Second entry must be the Ok one; the first must be CollectError.
        assert!(matches!(
            report.per_source[0].1,
            SelfTestOutcome::CollectError(_)
        ));
        assert!(matches!(
            report.per_source[1].1,
            SelfTestOutcome::Ok { bytes_sampled: 256 }
        ));
    }

    #[test]
    fn test_self_test_empty_source_list_reports_all_failed() {
        let sources: Vec<Box<dyn EntropySource>> = vec![];
        let report = self_test(&sources, 256);
        assert!(report.all_failed);
        assert_eq!(report.per_source.len(), 0);
    }

    // --- PID file O_EXCL tests ---

    #[test]
    fn test_write_pid_file_creates_fresh() {
        let tmp = std::env::temp_dir().join("mixrand_pid_fresh.pid");
        let _ = fs::remove_file(&tmp);
        write_pid_file(&tmp).expect("fresh PID file write");
        let contents = fs::read_to_string(&tmp).expect("read");
        let pid: i32 = contents.trim().parse().expect("parse");
        assert_eq!(pid as u32, std::process::id());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_write_pid_file_refuses_live_pid() {
        let tmp = std::env::temp_dir().join("mixrand_pid_live.pid");
        let _ = fs::remove_file(&tmp);
        fs::write(&tmp, format!("{}\n", std::process::id())).expect("seed");
        let err = write_pid_file(&tmp).unwrap_err();
        match err {
            Error::InvalidArgs(m) => {
                assert!(m.contains("already running") || m.contains("another instance"))
            }
            other => panic!("expected InvalidArgs, got {:?}", other),
        }
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_write_pid_file_cleans_stale() {
        let tmp = std::env::temp_dir().join("mixrand_pid_stale.pid");
        let _ = fs::remove_file(&tmp);
        // PID 1 is always live, so use a very-high unlikely PID. Pick one that
        // definitely is not alive by first scanning.
        let mut dead_pid = 2_000_000;
        while unsafe { libc::kill(dead_pid, 0) } == 0 && dead_pid < 4_000_000 {
            dead_pid += 1;
        }
        fs::write(&tmp, format!("{}\n", dead_pid)).expect("seed");
        write_pid_file(&tmp).expect("stale cleanup");
        let contents = fs::read_to_string(&tmp).expect("read");
        let pid: i32 = contents.trim().parse().expect("parse");
        assert_eq!(pid as u32, std::process::id());
        let _ = fs::remove_file(&tmp);
    }
}
