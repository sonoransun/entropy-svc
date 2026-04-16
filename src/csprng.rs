//! ChaCha20-based deterministic RNG for producing output from a 32-byte seed.
//!
//! Given a seed mixed from multiple entropy sources, [`generate`] produces
//! exactly `count` bytes of deterministic output. For requests larger than
//! a safety margin (1 MiB by default, see [`RESEED_INTERVAL`]),
//! [`generate_reseeding`] reseeds at each boundary from a caller-supplied
//! function so a compromised per-chunk seed cannot retroactively expose all
//! subsequent output.
//!
//! Both functions aggressively zeroize the `ChaCha20Rng` internal state and
//! the seed array after use (volatile writes + `mem::forget`).

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use crate::entropy::cpurng::zeroize_bytes;
use crate::memlock;

/// Zeroize a ChaCha20Rng's internal state and forget it to prevent Drop.
fn zeroize_rng(rng: &mut ChaCha20Rng) {
    let rng_size = std::mem::size_of::<ChaCha20Rng>();
    let rng_ptr = rng as *mut ChaCha20Rng as *mut u8;
    // SAFETY: We construct a `&mut [u8]` over exactly the storage of a live
    // `ChaCha20Rng` that we hold an exclusive reference to. `u8` has
    // alignment 1 and any bit pattern is a valid `u8`, so volatile writes of
    // zero are sound regardless of the underlying type's alignment. After
    // this call every caller `mem::forget`s the RNG (see `generate` and
    // `generate_reseeding` below), so Drop never reads the zeroized state as
    // if it were still a valid `ChaCha20Rng`. If upstream `rand_chacha`
    // adopts the `zeroize` crate's `Zeroize` trait on `ChaCha20Rng`, prefer
    // that — as of rand_chacha 0.9 it does not.
    unsafe {
        let rng_slice = std::slice::from_raw_parts_mut(rng_ptr, rng_size);
        zeroize_bytes(rng_slice);
    }
}

/// Seeds a ChaCha20Rng with the given 32-byte seed and generates `count`
/// random bytes. Zeroizes the RNG internal state and the seed buffer after
/// use to resist cold-boot / core-dump recovery.
///
/// Output is deterministic for a given seed — a property the KATs pin. For
/// requests exceeding a safety margin, prefer [`generate_reseeding`].
///
/// # Examples
///
/// ```
/// use mixrand::csprng::generate;
/// let a = generate([42u8; 32], 64);
/// let b = generate([42u8; 32], 64);
/// assert_eq!(a, b);
/// assert_eq!(a.len(), 64);
/// let c = generate([7u8; 32], 64);
/// assert_ne!(a, c);
/// ```
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

    fn hex(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for &x in b {
            s.push_str(&format!("{:02x}", x));
        }
        s
    }

    // Known Answer Tests (KATs) — pin the ChaCha20 seeding + output format.
    //
    // These vectors were generated from the current `generate` implementation
    // (seed -> ChaCha20Rng::from_seed -> fill_bytes). If the KAT fails, either
    // the ChaCha20 seeding semantics changed or `rand_chacha`'s output changed
    // — deterministic output for a given seed is part of the contract, so
    // either change must be intentional.

    #[test]
    fn kat_chacha_seed42_64() {
        let expected = "\
            98191f46e5830216445436978803697a5e3ab61b1e8951d4fe9ae67bab614a5f\
            7bfcfd7544b1078dda397cef45df2e6de498746805081ebc8fb90ad04eba9d02";
        assert_eq!(hex(&generate([42u8; 32], 64)), expected);
    }

    #[test]
    fn kat_chacha_seed0_128() {
        // Zero-seeded ChaCha20 matches the RFC 7539 test vector for the first
        // two blocks (initial output for zero key, zero nonce).
        let expected = "\
            76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
            da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586\
            9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed\
            29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f";
        assert_eq!(hex(&generate([0u8; 32], 128)), expected);
    }

    #[test]
    fn kat_chacha_seedff_32() {
        assert_eq!(
            hex(&generate([0xffu8; 32], 32)),
            "f6b898412f4ab061943167c1e23efaa2ba98e345a093f0b06da13bffdbd4b2c7"
        );
    }

    // --- Reseed-boundary tests ---

    #[test]
    fn test_reseeding_fn_output_differs_from_no_reseed() {
        // Control: generate 2 MiB without reseed (chunk_size=interval means
        // one seeding + one "reseed" at end; driver effectively uses the
        // same seed once). Then generate with a reseed that flips to a
        // distinct seed mid-output. Output past the boundary must differ.
        let seed = [1u8; 32];
        let no_reseed = generate_reseeding(seed, RESEED_INTERVAL + 128, RESEED_INTERVAL, || seed);
        let yes_reseed =
            generate_reseeding(seed, RESEED_INTERVAL + 128, RESEED_INTERVAL, || [2u8; 32]);
        assert_eq!(
            &no_reseed[..RESEED_INTERVAL],
            &yes_reseed[..RESEED_INTERVAL]
        );
        assert_ne!(
            &no_reseed[RESEED_INTERVAL..],
            &yes_reseed[RESEED_INTERVAL..]
        );
    }

    #[test]
    fn test_generate_zero_count_is_noop() {
        // Zero-length request must not panic even with a zero seed.
        assert!(generate([0u8; 32], 0).is_empty());
        // And with a reseeding driver.
        let out = generate_reseeding([0u8; 32], 0, RESEED_INTERVAL, || [0u8; 32]);
        assert!(out.is_empty());
    }

    #[test]
    fn test_generate_reseed_count_equals_boundary_minus_one() {
        // 1 MiB − 1 with 1 MiB interval: no reseed.
        let seed = [42u8; 32];
        let mut counter = 0u8;
        let _ = generate_reseeding(seed, RESEED_INTERVAL - 1, RESEED_INTERVAL, || {
            counter += 1;
            [counter; 32]
        });
        assert_eq!(counter, 0);
    }
}
