use blake2::{
    digest::{consts::U32, Digest},
    Blake2b,
};

type Blake2b256 = Blake2b<U32>;

/// Mixes multiple entropy inputs through BLAKE2b-256 with domain separation
/// and length-prefixed feeding to produce a 32-byte seed.
pub fn mix_entropy(inputs: &[(&str, &[u8])]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();

    // Domain separation tag
    hasher.update(b"mixrand-entropy-v1");

    for (label, data) in inputs {
        // Length-prefixed label
        let label_bytes = label.as_bytes();
        hasher.update(&(label_bytes.len() as u64).to_le_bytes());
        hasher.update(label_bytes);

        // Length-prefixed data
        hasher.update(&(data.len() as u64).to_le_bytes());
        hasher.update(data);
    }

    let result = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&result);
    seed
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
}
