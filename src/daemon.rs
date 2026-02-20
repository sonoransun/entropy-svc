use std::fs::{self, File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::cli::DaemonArgs;
use crate::config::CpuRngConfig;
use crate::entropy::fallback;
use crate::error::Error;

/// ioctl number for RNDADDENTROPY: _IOW('R', 0x03, int[2])
const RNDADDENTROPY: libc::c_ulong = 0x40085203;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

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

/// Inject entropy into the kernel pool via ioctl(RNDADDENTROPY).
fn inject_entropy(dev_random: &File, data: &[u8], entropy_bits: u32) -> Result<(), Error> {
    let buf = build_rand_pool_info(data, entropy_bits);
    let ret = unsafe { libc::ioctl(dev_random.as_raw_fd(), RNDADDENTROPY, buf.as_ptr()) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Read the current kernel entropy estimate from procfs.
fn read_entropy_avail() -> Result<u32, Error> {
    let s = fs::read_to_string("/proc/sys/kernel/random/entropy_avail")?;
    s.trim()
        .parse::<u32>()
        .map_err(|e| Error::NoEntropy(format!("failed to parse entropy_avail: {}", e)))
}

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

extern "C" fn signal_handler(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = signal_handler as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
}

/// Interruptible sleep: sleeps in 250ms steps, checking SHUTDOWN between each.
fn interruptible_sleep(total: Duration) {
    let step = Duration::from_millis(250);
    let mut remaining = total;
    while remaining > Duration::ZERO && !SHUTDOWN.load(Ordering::Relaxed) {
        let s = remaining.min(step);
        thread::sleep(s);
        remaining = remaining.saturating_sub(s);
    }
}

pub fn run(args: &DaemonArgs, cpu_config: &CpuRngConfig) -> Result<(), Error> {
    if args.batch_size == 0 {
        return Err(Error::InvalidArgs("batch-size must be greater than 0".into()));
    }

    let dev_random = validate_permissions()?;

    install_signal_handlers();

    log::info!(
        target: "mixrand::daemon",
        "started: threshold={}bits interval={}s batch={}B credit={}bits/byte",
        args.threshold, args.interval, args.batch_size, args.credit_ratio,
    );

    while !SHUTDOWN.load(Ordering::Relaxed) {
        match read_entropy_avail() {
            Ok(avail) => {
                if avail < args.threshold {
                    match fallback::generate_fallback(args.batch_size, cpu_config) {
                        Ok(data) => {
                            let credit_bits = args.batch_size as u32 * args.credit_ratio;
                            match inject_entropy(&dev_random, &data, credit_bits) {
                                Ok(()) => {
                                    log::info!(
                                        target: "mixrand::daemon",
                                        "injected {}B ({}bits credit), entropy was {}bits",
                                        args.batch_size, credit_bits, avail,
                                    );
                                }
                                Err(e) => {
                                    log::error!(
                                        target: "mixrand::daemon",
                                        "ioctl failed: {}", e,
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            log::error!(
                                target: "mixrand::daemon",
                                "entropy generation failed: {}", e,
                            );
                        }
                    }
                } else {
                    log::debug!(
                        target: "mixrand::daemon",
                        "entropy OK: {}bits (threshold {})",
                        avail, args.threshold,
                    );
                }
            }
            Err(e) => {
                log::error!(
                    target: "mixrand::daemon",
                    "failed to read entropy_avail: {}", e,
                );
            }
        }

        interruptible_sleep(Duration::from_secs(args.interval));
    }

    log::info!(target: "mixrand::daemon", "shutting down");
    Ok(())
}
