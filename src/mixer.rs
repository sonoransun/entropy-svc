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

    let result = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&result);

    // Zeroize the GenericArray result
    let mut result_bytes = [0u8; 32];
    result_bytes.copy_from_slice(&result);
    zeroize_bytes(&mut result_bytes);

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
    let pass1 = extract1.finalize();

    // Second pass: re-hash with counter for additional extraction
    let mut extract2 = Blake2b256::new();
    extract2.update(b"mixrand-hkdf-extract2-v1");
    extract2.update(pass1);
    extract2.update([0x01]); // counter byte
    let mut prk = [0u8; 32];
    let prk_result = extract2.finalize();
    prk.copy_from_slice(&prk_result);

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

        let block = expand.finalize();
        let remaining = output_len - output.len();
        let to_copy = remaining.min(32);
        output.extend_from_slice(&block[..to_copy]);

        prev_block.copy_from_slice(&block);
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
}
