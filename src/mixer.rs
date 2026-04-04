use blake2::{
    digest::{consts::U32, Digest},
    Blake2b,
};

use crate::entropy::cpurng::zeroize_bytes;

type Blake2b256 = Blake2b<U32>;

/// Mixes multiple entropy inputs through BLAKE2b-256 with domain separation
/// and length-prefixed feeding to produce a 32-byte seed.
/// The intermediate hash result is zeroized before returning.
pub fn mix_entropy(inputs: &[(&str, &[u8])]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();

    // Domain separation tag
    hasher.update(b"mixrand-entropy-v1");

    for (label, data) in inputs {
        // Length-prefixed label
        let label_bytes = label.as_bytes();
        hasher.update((label_bytes.len() as u64).to_le_bytes());
        hasher.update(label_bytes);

        // Length-prefixed data
        hasher.update((data.len() as u64).to_le_bytes());
        hasher.update(data);
    }

    let mut result = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&result);
    zeroize_bytes(result.as_mut_slice());

    seed
}

/// Two-stage HKDF-style extract-then-expand mixer for defense-in-depth
/// with low-entropy-density inputs.
///
/// Extract: Two-pass BLAKE2b (first pass domain-tagged input hash,
///          second pass re-hashes with counter)
/// Expand:  HKDF-Expand using BLAKE2b with counter bytes, producing
///          arbitrary-length output.
pub fn mix_entropy_hkdf(inputs: &[(&str, &[u8])], output_len: usize) -> Vec<u8> {
    // === Extract phase ===
    // First pass: domain-tagged hash of all inputs
    let mut extract1 = Blake2b256::new();
    extract1.update(b"mixrand-hkdf-extract-v1");
    for (label, data) in inputs {
        let label_bytes = label.as_bytes();
        extract1.update((label_bytes.len() as u64).to_le_bytes());
        extract1.update(label_bytes);
        extract1.update((data.len() as u64).to_le_bytes());
        extract1.update(data);
    }
    let mut pass1 = extract1.finalize();

    // Second pass: re-hash with counter for additional extraction
    let mut extract2 = Blake2b256::new();
    extract2.update(b"mixrand-hkdf-extract2-v1");
    extract2.update(pass1.as_slice());
    extract2.update([0x01]); // counter byte
    zeroize_bytes(pass1.as_mut_slice());
    let mut prk = [0u8; 32];
    let mut prk_result = extract2.finalize();
    prk.copy_from_slice(&prk_result);
    zeroize_bytes(prk_result.as_mut_slice());

    // === Expand phase ===
    let mut output = Vec::with_capacity(output_len);
    let mut prev_block = [0u8; 32];
    let mut counter: u8 = 1;

    while output.len() < output_len {
        let mut expand = Blake2b256::new();
        expand.update(b"mixrand-hkdf-expand-v1");
        expand.update(prk);
        if counter > 1 {
            expand.update(prev_block);
        }
        expand.update([counter]);

        let mut block = expand.finalize();
        let remaining = output_len - output.len();
        let to_copy = remaining.min(32);
        output.extend_from_slice(&block[..to_copy]);

        prev_block.copy_from_slice(&block);
        zeroize_bytes(block.as_mut_slice());
        counter = counter.wrapping_add(1);
    }

    // Zeroize intermediates
    zeroize_bytes(&mut prk);
    zeroize_bytes(&mut prev_block);

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        let a = mix_entropy(&[("label", b"data")]);
        let b = mix_entropy(&[("label", b"data")]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_different_inputs_differ() {
        let a = mix_entropy(&[("label", b"data1")]);
        let b = mix_entropy(&[("label", b"data2")]);
        assert_ne!(a, b);
    }

    #[test]
    fn test_domain_separation() {
        let a = mix_entropy(&[("label-a", b"same")]);
        let b = mix_entropy(&[("label-b", b"same")]);
        assert_ne!(a, b);
    }

    #[test]
    fn test_empty_inputs() {
        let result = mix_entropy(&[]);
        assert_eq!(result.len(), 32);
        // Should not panic and should produce a valid hash
    }

    #[test]
    fn test_input_order_matters() {
        let a = mix_entropy(&[("x", b"1"), ("y", b"2")]);
        let b = mix_entropy(&[("y", b"2"), ("x", b"1")]);
        assert_ne!(a, b);
    }

    // --- HKDF mixer tests ---

    #[test]
    fn test_hkdf_deterministic() {
        let a = mix_entropy_hkdf(&[("label", b"data")], 32);
        let b = mix_entropy_hkdf(&[("label", b"data")], 32);
        assert_eq!(a, b);
    }

    #[test]
    fn test_hkdf_different_inputs_differ() {
        let a = mix_entropy_hkdf(&[("label", b"data1")], 32);
        let b = mix_entropy_hkdf(&[("label", b"data2")], 32);
        assert_ne!(a, b);
    }

    #[test]
    fn test_hkdf_variable_output_length() {
        for &len in &[16, 32, 48, 64, 128] {
            let out = mix_entropy_hkdf(&[("test", b"data")], len);
            assert_eq!(out.len(), len);
        }
    }

    #[test]
    fn test_hkdf_differs_from_blake2b() {
        let blake = mix_entropy(&[("label", b"data")]);
        let hkdf = mix_entropy_hkdf(&[("label", b"data")], 32);
        assert_ne!(&blake[..], &hkdf[..]);
    }

    #[test]
    fn test_hkdf_empty_inputs() {
        let result = mix_entropy_hkdf(&[], 32);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hkdf_zero_output_length() {
        let result = mix_entropy_hkdf(&[("test", b"data")], 0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_hkdf_large_output() {
        // 8192 bytes = 256 blocks, forces u8 counter to wrap
        let out = mix_entropy_hkdf(&[("test", b"data")], 8192);
        assert_eq!(out.len(), 8192);
    }

    #[test]
    fn test_hkdf_prefix_consistency() {
        let inputs: &[(&str, &[u8])] = &[("test", b"data")];
        let short = mix_entropy_hkdf(inputs, 32);
        let long = mix_entropy_hkdf(inputs, 64);
        // First 32 bytes of 64-byte output should match the 32-byte output
        assert_eq!(&short[..], &long[..32]);
    }

    #[test]
    fn test_mix_entropy_many_inputs() {
        let inputs: Vec<(&str, &[u8])> = (0..100)
            .map(|_| ("label", b"data" as &[u8]))
            .collect();
        let result = mix_entropy(&inputs);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_mix_entropy_always_32_bytes() {
        assert_eq!(mix_entropy(&[]).len(), 32);
        assert_eq!(mix_entropy(&[("a", b"")]).len(), 32);
        assert_eq!(mix_entropy(&[("a", &[0u8; 1024])]).len(), 32);
        assert_eq!(mix_entropy(&[("a", b"x"), ("b", b"y"), ("c", b"z")]).len(), 32);
    }
}
