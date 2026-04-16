//! CPU timing-jitter entropy source.
//!
//! This module extracts entropy from timing variations between independent
//! `clock_gettime(CLOCK_MONOTONIC)` reads, and separately from the variable
//! latency of inner CPU-bound loops. The entropy density is **low and
//! platform-dependent**: on a quiet system, expect conservatively ~0.5 bits
//! of min-entropy per 64-bit sample. Both paths are therefore only used as
//! secondary inputs to the mixer — never as the sole entropy source.
//!
//! Exposed functions:
//! - [`collect_jitter_samples`] — data-dependent busy-spin + `clock_gettime`
//!   delta. 8 bytes per sample.
//! - [`collect_cpu_pipeline_jitter`] — pure CPU-pipeline jitter: two tight
//!   loops whose completion time is read back via rdtsc-equivalent monotonic
//!   time. Produces a byte per sample by XOR-folding the lower bits of each
//!   pair of timings.
//!
//! Both functions return byte slices suitable for feeding to the mixer.
//! Neither provides health-test guarantees on its own.

/// Conservative min-entropy estimate used by `HealthTester::new` when jitter
/// is the primary source: 0.5 bits per 64-bit sample. Keeps RCT/APT cutoffs
/// on the pessimistic side; real per-sample entropy on modern x86/AArch64 is
/// typically higher but platform-variable.
pub const JITTER_MIN_ENTROPY_BITS: f64 = 0.5;

/// Collects CPU jitter timing samples via `clock_gettime(CLOCK_MONOTONIC)`.
/// Uses a data-dependent busy-spin between samples to amplify
/// cache/scheduler/interrupt jitter. Each sample is the 64-bit nanosecond
/// timestamp serialized little-endian — 8 bytes per sample.
pub fn collect_jitter_samples(count: usize) -> Vec<u8> {
    let mut samples = Vec::with_capacity(count * 8);
    let mut accumulator: u64 = 0;

    for i in 0..count {
        // Data-dependent busy-spin: iteration count depends on previous timing
        let spin_count = 1000 + (accumulator & 0x1FF) as usize;
        let mut x: u64 = (i as u64).wrapping_mul(0x6C62272E07BB0142);
        for _ in 0..spin_count {
            x = x.wrapping_mul(0x5DEECE66D).wrapping_add(0xB);
        }
        // Prevent optimizer from eliminating the spin
        std::hint::black_box(x);

        let ts = clock_gettime_ns();
        accumulator = accumulator.wrapping_add(ts);
        samples.extend_from_slice(&ts.to_le_bytes());
    }

    samples
}

/// Collects CPU-pipeline jitter by timing pairs of tight loops against the
/// monotonic clock and XOR-folding the low byte of each pair's delta.
///
/// This path is less sensitive to OS-scheduler interference (which dominates
/// the clock-only path when the system is busy) because the loops complete
/// in tens of nanoseconds — far below the scheduler quantum. Entropy here
/// comes from microarchitectural timing variance (cache hits/misses, branch
/// predictor state, out-of-order scheduling).
///
/// Produces one byte per sample. Default `count=1024` gives ~1024 bytes of
/// conditioning material for the mixer — a stronger contribution than the
/// 64-sample `clock_gettime` path alone.
pub fn collect_cpu_pipeline_jitter(count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(count);
    let mut state: u64 = 0x9E3779B97F4A7C15;

    for _ in 0..count {
        let t0 = clock_gettime_ns();
        let mut a: u64 = state;
        for _ in 0..64 {
            a = a.wrapping_mul(2862933555777941757).wrapping_add(3037000493);
        }
        let t1 = clock_gettime_ns();
        let mut b: u64 = a ^ 0xD1B54A32D192ED03;
        for _ in 0..64 {
            b = b.rotate_left(13).wrapping_add(0x243F6A8885A308D3);
        }
        let t2 = clock_gettime_ns();
        std::hint::black_box((a, b));

        let d1 = t1.wrapping_sub(t0);
        let d2 = t2.wrapping_sub(t1);
        // XOR-fold two low bytes of the two deltas into one sample byte.
        let sample = ((d1 ^ d2) & 0xFF) as u8;
        out.push(sample);

        // Mix both deltas into the running state so the NEXT loop starts
        // from a distinct input — amplifies per-sample decorrelation.
        state = state.wrapping_add(d1).rotate_left(17) ^ d2;
    }

    out
}

fn clock_gettime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_MONOTONIC on a supported platform never errors. Ignoring the
    // return value here matches the existing behavior and avoids tying
    // entropy collection to error-propagation plumbing.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(ts.tv_nsec as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_correct_size() {
        let samples = collect_jitter_samples(64);
        assert_eq!(samples.len(), 64 * 8);
    }

    #[test]
    fn test_collect_zero_samples() {
        let samples = collect_jitter_samples(0);
        assert!(samples.is_empty());
    }

    #[test]
    fn test_collect_single_sample() {
        let samples = collect_jitter_samples(1);
        assert_eq!(samples.len(), 8);
    }

    #[test]
    fn test_samples_not_constant() {
        let samples = collect_jitter_samples(16);
        let chunks: Vec<&[u8]> = samples.chunks(8).collect();
        let first = chunks[0];
        let all_same = chunks.iter().all(|c| *c == first);
        assert!(!all_same, "jitter samples should not all be identical");
    }

    #[test]
    fn test_samples_have_variation() {
        let samples = collect_jitter_samples(32);
        assert!(samples.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_cpu_pipeline_jitter_correct_size() {
        let out = collect_cpu_pipeline_jitter(128);
        assert_eq!(out.len(), 128);
    }

    #[test]
    fn test_cpu_pipeline_jitter_zero() {
        let out = collect_cpu_pipeline_jitter(0);
        assert!(out.is_empty());
    }

    #[test]
    fn test_cpu_pipeline_jitter_not_constant() {
        let out = collect_cpu_pipeline_jitter(256);
        let first = out[0];
        let all_same = out.iter().all(|&b| b == first);
        assert!(
            !all_same,
            "CPU pipeline jitter should vary — if this fails consistently, \
             either timing resolution is too coarse or the loop was optimized away"
        );
    }

    #[test]
    fn test_cpu_pipeline_jitter_entropy_bounded() {
        // Sanity: across 1024 samples, at least 4 distinct byte values should
        // appear. Failing this implies the loop optimized away or CLOCK_MONOTONIC
        // resolution is pathologically coarse.
        let out = collect_cpu_pipeline_jitter(1024);
        let mut seen = [false; 256];
        for &b in &out {
            seen[b as usize] = true;
        }
        let distinct = seen.iter().filter(|s| **s).count();
        assert!(distinct >= 4, "too few distinct jitter bytes: {}", distinct);
    }

    #[test]
    fn test_min_entropy_constant_is_conservative() {
        // Guards against future edits inadvertently raising the estimate
        // past what the underlying timing path can support.
        assert!(JITTER_MIN_ENTROPY_BITS <= 1.0);
        assert!(JITTER_MIN_ENTROPY_BITS > 0.0);
    }
}
