//! Entropy mixing via BLAKE2b and HKDF with domain separation.
//!
//! Two mixer functions share the same framing convention — u64 little-endian
//! length prefixes on both the label and the data payload, plus a
//! domain-separation tag as the very first BLAKE2b input. Pinning these
//! details prevents silent wire-format drift across releases; KATs in the
//! test module lock current outputs byte-for-byte.
//!
//! - [`mix_entropy`] — BLAKE2b-256 single pass. Produces exactly 32 bytes.
//!   Use when the caller already accumulated high-entropy inputs from
//!   independent sources.
//! - [`mix_entropy_hkdf`] — Two-stage extract-then-expand when defense in
//!   depth is desired against low-entropy-density inputs. Produces an
//!   arbitrary-length byte string.
//!
//! Intermediate digest buffers are volatile-zeroized before return.

use blake2::{
    digest::{consts::U32, Digest},
    Blake2b,
};

use crate::entropy::cpurng::zeroize_bytes;

type Blake2b256 = Blake2b<U32>;

/// Mixes multiple entropy inputs through BLAKE2b-256 with domain separation
/// and length-prefixed feeding to produce a 32-byte seed.
///
/// The intermediate hash result is zeroized before returning.
///
/// # Framing
///
/// - Domain tag: `b"mixrand-entropy-v1"` (prepended, no length prefix)
/// - For each input: `u64_le(len(label)) || label || u64_le(len(data)) || data`
/// - Input order matters (it changes the hash input stream)
///
/// # Examples
///
/// ```
/// use mixrand::mixer::mix_entropy;
/// let seed = mix_entropy(&[
///     ("hwrng", &[0x42u8; 32]),
///     ("cpurng", &[0x19u8; 32]),
/// ]);
/// assert_eq!(seed.len(), 32);
/// // Same inputs always produce the same seed:
/// assert_eq!(
///     mix_entropy(&[("a", b"1")]),
///     mix_entropy(&[("a", b"1")]),
/// );
/// // Different labels change the output:
/// assert_ne!(
///     mix_entropy(&[("a", b"1")]),
///     mix_entropy(&[("b", b"1")]),
/// );
/// ```
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

/// Two-stage HKDF-style extract-then-expand mixer for defense in depth with
/// low-entropy-density inputs. Produces `output_len` bytes.
///
/// Extract: two-pass BLAKE2b. First pass hashes `mixrand-hkdf-extract-v1ǁ
/// inputs`. Second pass re-hashes `mixrand-hkdf-extract2-v1ǁpass1ǁ0x01` —
/// the extra counter byte guarantees the PRK cannot equal any direct
/// application of `mix_entropy` even on identical inputs.
///
/// Expand: counter-mode BLAKE2b. Each block:
/// `BLAKE2b(mixrand-hkdf-expand-v2ǁPRKǁ(prev_block if counter>1)ǁcounter_le32)`
/// then truncated to `output_len`. The counter is 4 LE bytes of a `u32`; the
/// v1 form used a single byte and silently wrapped at block 256, producing
/// duplicate output blocks past 8160 bytes. Domain tag bumped to v2 so KATs
/// over v1 output do not falsely match.
///
/// The output is `prefix-consistent`:
/// `mix_entropy_hkdf(x, n)[..m] == mix_entropy_hkdf(x, m)` for `m <= n`,
/// within block-aligned prefixes.
///
/// # Examples
///
/// ```
/// use mixrand::mixer::mix_entropy_hkdf;
/// let out = mix_entropy_hkdf(&[("hwrng", &[0xab; 32])], 128);
/// assert_eq!(out.len(), 128);
/// // Prefix consistency across sibling calls (within a block multiple):
/// let a = mix_entropy_hkdf(&[("src", b"data")], 32);
/// let b = mix_entropy_hkdf(&[("src", b"data")], 64);
/// assert_eq!(a, b[..32]);
/// ```
pub fn mix_entropy_hkdf(inputs: &[(&str, &[u8])], output_len: usize) -> Vec<u8> {
    // Zeroize-on-drop guard so an unwinding panic between finalize() and the
    // existing explicit zeroize doesn't leave a digest in memory.
    struct ZeroOnDrop<'a>(&'a mut [u8]);
    impl Drop for ZeroOnDrop<'_> {
        fn drop(&mut self) {
            zeroize_bytes(self.0);
        }
    }

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
    let pass1_guard = ZeroOnDrop(pass1.as_mut_slice());

    // Second pass: re-hash with counter for additional extraction
    let mut extract2 = Blake2b256::new();
    extract2.update(b"mixrand-hkdf-extract2-v1");
    extract2.update(&*pass1_guard.0);
    extract2.update([0x01]); // counter byte
    drop(pass1_guard);
    let mut prk = [0u8; 32];
    let mut prk_result = extract2.finalize();
    let prk_result_guard = ZeroOnDrop(prk_result.as_mut_slice());
    prk.copy_from_slice(&*prk_result_guard.0);
    drop(prk_result_guard);

    // === Expand phase ===
    let mut output = Vec::with_capacity(output_len);
    let mut prev_block = [0u8; 32];
    // 32 bytes/block * 2^32 ~= 137 GiB; well above the 100 MiB CLI cap. v1
    // used u8 and wrapped at 256 blocks (8160 bytes); see domain tag note.
    let mut counter: u32 = 1;

    while output.len() < output_len {
        let mut expand = Blake2b256::new();
        expand.update(b"mixrand-hkdf-expand-v2");
        expand.update(prk);
        if counter > 1 {
            expand.update(prev_block);
        }
        expand.update(counter.to_le_bytes());

        let mut block = expand.finalize();
        let remaining = output_len - output.len();
        let to_copy = remaining.min(32);
        output.extend_from_slice(&block[..to_copy]);

        prev_block.copy_from_slice(&block);
        zeroize_bytes(block.as_mut_slice());
        counter += 1;
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
        // 8192 bytes = 256 blocks; pre-fix u8 counter would have wrapped here.
        let out = mix_entropy_hkdf(&[("test", b"data")], 8192);
        assert_eq!(out.len(), 8192);
    }

    #[test]
    fn test_hkdf_output_beyond_u8_counter_wrap_unique_blocks() {
        // Regression for the v1 counter-wrap bug: at block 257 the u8 counter
        // would re-read 1 with `if counter > 1` false, so prev_block wasn't
        // mixed in, producing output identical to block 1. Request enough
        // output to span that boundary and assert every 32-byte block is
        // distinct.
        let out = mix_entropy_hkdf(&[("src", b"data")], 32 * 300);
        let mut seen = std::collections::HashSet::new();
        for chunk in out.chunks_exact(32) {
            assert!(
                seen.insert(chunk.to_vec()),
                "duplicate 32-byte block at offset {}",
                seen.len() * 32
            );
        }
        assert_eq!(seen.len(), 300);
    }

    #[test]
    fn test_hkdf_block_257_not_equal_to_block_1() {
        // Tighter variant of the wrap regression: precisely the v1-broken pair.
        let out = mix_entropy_hkdf(&[("src", b"data")], 32 * 260);
        let block_1 = &out[..32];
        let block_257 = &out[32 * 256..32 * 257];
        assert_ne!(block_1, block_257);
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
        let inputs: Vec<(&str, &[u8])> = (0..100).map(|_| ("label", b"data" as &[u8])).collect();
        let result = mix_entropy(&inputs);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_mix_entropy_always_32_bytes() {
        assert_eq!(mix_entropy(&[]).len(), 32);
        assert_eq!(mix_entropy(&[("a", b"")]).len(), 32);
        assert_eq!(mix_entropy(&[("a", &[0u8; 1024])]).len(), 32);
        assert_eq!(
            mix_entropy(&[("a", b"x"), ("b", b"y"), ("c", b"z")]).len(),
            32
        );
    }

    fn hex(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for &x in b {
            s.push_str(&format!("{:02x}", x));
        }
        s
    }

    // Known Answer Tests (KATs) — pin current framing and domain tags.
    //
    // If any KAT fails, the wire format changed and mixed entropy produced by
    // future code will not match bytes produced by older code with the same
    // inputs. Cross-version compatibility is not promised, but a silent change
    // is a bug: bump domain tags to a new version suffix and update KATs.
    //
    // Domain tags pinned:
    //   mix_entropy       -> "mixrand-entropy-v1"
    //   mix_entropy_hkdf  -> "mixrand-hkdf-extract-v1" + "mixrand-hkdf-extract2-v1"
    //                        + "mixrand-hkdf-expand-v2"
    // Framing pinned:
    //   u64 little-endian length prefixes on both label and data;
    //   0x01 counter byte after pass1 in HKDF extract stage 2;
    //   per-block counter:u32 LE + prev_block feedback (when counter > 1) in expand.
    //   v1 used counter:u8 and wrapped at block 256; see
    //   test_hkdf_output_beyond_u8_counter_wrap_unique_blocks.

    #[test]
    fn kat_mix_entropy_empty() {
        assert_eq!(
            hex(&mix_entropy(&[])),
            "5a752d85077e90f6a086e9be7a41fbedf64e7fbbabc5c7e0a51438af38c7de3a"
        );
    }

    #[test]
    fn kat_mix_entropy_single() {
        assert_eq!(
            hex(&mix_entropy(&[("src", b"data")])),
            "3fc4f387b67eb24d6d5fa349ea055c207f97ab8357e97e38c9bc9eb9824c7a22"
        );
    }

    #[test]
    fn kat_mix_entropy_two_inputs() {
        assert_eq!(
            hex(&mix_entropy(&[("a", b"1"), ("b", b"22")])),
            "c8775643ba58ac16de05f4c30332a446f243a4853806db3f07cbbe15870981d2"
        );
    }

    #[test]
    fn kat_mix_entropy_zero_length_label() {
        // Pins the length-prefix framing: zero-length label still emits its u64 length.
        assert_eq!(
            hex(&mix_entropy(&[("", b"x")])),
            "45b5e4051d3d40a4c62e6cec4d290c82ae3eee388df910d8c62748d46caf096d"
        );
    }

    #[test]
    fn kat_hkdf_32() {
        assert_eq!(
            hex(&mix_entropy_hkdf(&[("src", b"data")], 32)),
            "919d52fefbd56b4c65f845e1f08bd3dfdc889835bf5aa903f9f0a70ef3a402ce"
        );
    }

    #[test]
    fn kat_hkdf_64_exercises_counter_and_feedback() {
        // Cross-block: second 32B derives from prev_block + counter=2.
        let expected = "\
            919d52fefbd56b4c65f845e1f08bd3dfdc889835bf5aa903f9f0a70ef3a402ce\
            1d9873884be206ef8c00ba00094f9ed221e8248207f7e2ef2b0e4edf321b1de3";
        assert_eq!(hex(&mix_entropy_hkdf(&[("src", b"data")], 64)), expected);
    }

    #[test]
    fn kat_hkdf_empty_inputs_short_output() {
        assert_eq!(
            hex(&mix_entropy_hkdf(&[], 16)),
            "9e56db60d7b60d04cedc86b7132b6a9c"
        );
    }

    #[test]
    fn kat_hkdf_non_block_aligned_length() {
        // 100 bytes = 3 full blocks + 4 bytes, exercising partial-block truncation.
        let expected = "\
            919d52fefbd56b4c65f845e1f08bd3dfdc889835bf5aa903f9f0a70ef3a402ce\
            1d9873884be206ef8c00ba00094f9ed221e8248207f7e2ef2b0e4edf321b1de3\
            699978287d54e8a1e3e70315e2f454d739c40e73e4431d075a5ef5315681a9ce\
            a60f9015";
        assert_eq!(hex(&mix_entropy_hkdf(&[("src", b"data")], 100)), expected);
    }

    #[test]
    fn kat_hkdf_past_u8_wrap_boundary() {
        // Pin the last 32 bytes of the 257th block (one block past the v1
        // bug). Any regression to u8 counter or domain tag v2 will trip this.
        let out = mix_entropy_hkdf(&[("src", b"data")], 32 * 257);
        let last_block_hex = hex(&out[32 * 256..]);
        assert_eq!(
            last_block_hex,
            "2507c9b02edfa4ee6787c8ebe56e9d4c0c4c5c95940e9dd7390914e5091d25bc"
        );
    }
}
