use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// Seeds a ChaCha20Rng with the given 32-byte seed and generates `count` random bytes.
pub fn generate(seed: [u8; 32], count: usize) -> Vec<u8> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut buf = vec![0u8; count];
    rng.fill_bytes(&mut buf);
    buf
}

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
}
