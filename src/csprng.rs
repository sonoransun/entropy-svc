use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use crate::entropy::cpurng::zeroize_bytes;
use crate::memlock;

/// Zeroize a ChaCha20Rng's internal state and forget it to prevent Drop.
fn zeroize_rng(rng: &mut ChaCha20Rng) {
    let rng_size = std::mem::size_of::<ChaCha20Rng>();
    let rng_ptr = rng as *mut ChaCha20Rng as *mut u8;
    // SAFETY: we're writing zeros over the RNG's memory.
    unsafe {
        let rng_slice = std::slice::from_raw_parts_mut(rng_ptr, rng_size);
        zeroize_bytes(rng_slice);
    }
}

/// Seeds a ChaCha20Rng with the given 32-byte seed and generates `count` random bytes.
/// Zeroizes the RNG internal state after use to prevent cold-boot / core-dump recovery.
pub fn generate(seed: [u8; 32], count: usize) -> Vec<u8> {
    memlock::lock_and_protect(&seed);

    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut buf = vec![0u8; count];
    rng.fill_bytes(&mut buf);

    // Zeroize and forget the RNG state (intentional: prevent drop from touching zeroized memory)
    zeroize_rng(&mut rng);
    #[allow(clippy::forget_non_drop)]
    std::mem::forget(rng);

    memlock::munlock_slice(&seed);

    buf
}

/// Seeds a ChaCha20Rng with the given 32-byte seed and generates `count` random bytes,
/// reseeding from `reseed_fn` every `reseed_interval` bytes.
/// All intermediate RNG and seed state is zeroized at each reseed boundary and at the end.
pub fn generate_reseeding<F>(
    mut seed: [u8; 32],
    count: usize,
    reseed_interval: usize,
    mut reseed_fn: F,
) -> Vec<u8>
where
    F: FnMut() -> [u8; 32],
{
    memlock::lock_and_protect(&seed);
    let mut buf = vec![0u8; count];
    let mut offset = 0;

    while offset < count {
        let chunk_size = (count - offset).min(reseed_interval);
        let mut rng = ChaCha20Rng::from_seed(seed);
        rng.fill_bytes(&mut buf[offset..offset + chunk_size]);

        // Zeroize old RNG state (intentional: prevent drop from touching zeroized memory)
        zeroize_rng(&mut rng);
        #[allow(clippy::forget_non_drop)]
        std::mem::forget(rng);

        offset += chunk_size;

        if offset < count {
            // Zeroize old seed and get fresh one
            memlock::munlock_slice(&seed);
            zeroize_bytes(&mut seed);
            seed = reseed_fn();
            memlock::lock_and_protect(&seed);
        }
    }

    // Zeroize final seed
    memlock::munlock_slice(&seed);
    zeroize_bytes(&mut seed);

    buf
}

/// Reseed interval: 1 MiB
pub const RESEED_INTERVAL: usize = 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_same_seed() {
        let seed = [42u8; 32];
        let a = generate(seed, 64);
        let b = generate(seed, 64);
        assert_eq!(a, b);
    }

    #[test]
    fn test_different_seeds_differ() {
        let a = generate([1u8; 32], 64);
        let b = generate([2u8; 32], 64);
        assert_ne!(a, b);
    }

    #[test]
    fn test_correct_length() {
        for &size in &[0, 1, 16, 32, 64, 128, 1024] {
            let out = generate([0u8; 32], size);
            assert_eq!(out.len(), size);
        }
    }

    #[test]
    fn test_reseeding_correct_length() {
        let seed = [42u8; 32];
        let mut counter = 0u8;
        let out = generate_reseeding(seed, 2_100_000, RESEED_INTERVAL, || {
            counter += 1;
            [counter; 32]
        });
        assert_eq!(out.len(), 2_100_000);
        // Should have reseeded at least twice (2.1MB / 1MB = 2 full chunks + partial)
        assert!(counter >= 2);
    }

    #[test]
    fn test_reseeding_small_request_no_reseed() {
        let seed = [42u8; 32];
        let mut counter = 0u8;
        let out = generate_reseeding(seed, 64, RESEED_INTERVAL, || {
            counter += 1;
            [counter; 32]
        });
        assert_eq!(out.len(), 64);
        assert_eq!(counter, 0); // No reseed needed for small request
    }

    #[test]
    fn test_generate_zero_bytes() {
        let out = generate([0u8; 32], 0);
        assert!(out.is_empty());
    }

    #[test]
    fn test_generate_reseeding_exact_boundary() {
        let seed = [42u8; 32];
        let mut counter = 0u8;
        let out = generate_reseeding(seed, RESEED_INTERVAL, RESEED_INTERVAL, || {
            counter += 1;
            [counter; 32]
        });
        assert_eq!(out.len(), RESEED_INTERVAL);
        assert_eq!(counter, 0); // Exactly one chunk, no reseed needed
    }

    #[test]
    fn test_generate_reseeding_one_over() {
        let seed = [42u8; 32];
        let mut counter = 0u8;
        let out = generate_reseeding(seed, RESEED_INTERVAL + 1, RESEED_INTERVAL, || {
            counter += 1;
            [counter; 32]
        });
        assert_eq!(out.len(), RESEED_INTERVAL + 1);
        assert_eq!(counter, 1); // Exactly one reseed
    }

    #[test]
    fn test_generate_reseeding_deterministic() {
        let seed = [99u8; 32];
        let reseed = || [77u8; 32];
        let a = generate_reseeding(seed, RESEED_INTERVAL + 100, RESEED_INTERVAL, reseed);
        let b = generate_reseeding(seed, RESEED_INTERVAL + 100, RESEED_INTERVAL, reseed);
        assert_eq!(a, b);
    }
}
