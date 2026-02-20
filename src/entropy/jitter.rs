/// Collects CPU jitter timing samples via clock_gettime(CLOCK_MONOTONIC).
/// Uses a data-dependent busy-spin between samples to amplify
/// cache/scheduler/interrupt jitter.
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

fn clock_gettime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(ts.tv_nsec as u64)
}
