//! Property-based tests for mixrand crypto + formatter surfaces.
//!
//! These run as a standalone integration test binary (since the crate has no
//! library target, we can't pull `mix_entropy`/`generate` into the existing
//! binary's test tree via `use`). Instead, each property test spawns the
//! `mixrand` CLI and asserts structural invariants of its output.
//!
//! Invariants covered:
//! - Hex output has length `2 * bytes + 1` (byte + newline)
//! - Hex output round-trips back to bytes for any requested length 1..=256
//! - Base64 and base64url outputs decode to exactly `bytes` bytes
//! - Raw output is exactly `bytes` bytes (no encoding, no newline)
//! - Count N produces N independent outputs (non-empty, separated)
//! - Output determinism: successive invocations produce different bytes
//!   (i.e. actual randomness, not a constant)

use assert_cmd::Command;
use proptest::prelude::*;

fn decode_hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len() % 2 == 0, "hex string has odd length: {}", s.len());
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, .. ProptestConfig::default() })]

    #[test]
    fn hex_length_invariant(n in 1usize..=256) {
        let out = Command::cargo_bin("mixrand")
            .unwrap()
            .args(["-n", &n.to_string(), "-f", "hex"])
            .output()
            .expect("failed to run mixrand");
        prop_assert!(out.status.success());
        let s = String::from_utf8(out.stdout).unwrap();
        prop_assert_eq!(s.len(), 2 * n + 1, "expected 2N hex + newline");
    }

    #[test]
    fn hex_roundtrips_to_bytes(n in 1usize..=256) {
        let out = Command::cargo_bin("mixrand")
            .unwrap()
            .args(["-n", &n.to_string(), "-f", "hex"])
            .output()
            .unwrap();
        prop_assert!(out.status.success());
        let decoded = decode_hex(&String::from_utf8(out.stdout).unwrap());
        prop_assert_eq!(decoded.len(), n);
    }

    #[test]
    fn base64_decodes_to_exactly_n_bytes(n in 1usize..=256) {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        let out = Command::cargo_bin("mixrand")
            .unwrap()
            .args(["-n", &n.to_string(), "-f", "base64"])
            .output()
            .unwrap();
        prop_assert!(out.status.success());
        let s = String::from_utf8(out.stdout).unwrap();
        let decoded = STANDARD.decode(s.trim()).expect("valid base64");
        prop_assert_eq!(decoded.len(), n);
    }

    #[test]
    fn base64url_decodes_to_exactly_n_bytes(n in 1usize..=256) {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let out = Command::cargo_bin("mixrand")
            .unwrap()
            .args(["-n", &n.to_string(), "-f", "base64url"])
            .output()
            .unwrap();
        prop_assert!(out.status.success());
        let s = String::from_utf8(out.stdout).unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(s.trim()).expect("valid base64url");
        prop_assert_eq!(decoded.len(), n);
    }

    #[test]
    fn raw_is_exactly_n_bytes(n in 1usize..=256) {
        let out = Command::cargo_bin("mixrand")
            .unwrap()
            .args(["-n", &n.to_string(), "-f", "raw"])
            .output()
            .unwrap();
        prop_assert!(out.status.success());
        prop_assert_eq!(out.stdout.len(), n);
    }

    #[test]
    fn count_produces_n_outputs(n in 2usize..=5) {
        let out = Command::cargo_bin("mixrand")
            .unwrap()
            .args(["-n", "8", "-f", "hex", "--count", &n.to_string()])
            .output()
            .unwrap();
        prop_assert!(out.status.success());
        let lines: Vec<&str> = std::str::from_utf8(&out.stdout)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .collect();
        prop_assert_eq!(lines.len(), n);
        for line in &lines {
            prop_assert_eq!(line.len(), 16);
        }
    }

    #[test]
    fn successive_outputs_differ(n in 32usize..=64) {
        let out_a = Command::cargo_bin("mixrand")
            .unwrap()
            .args(["-n", &n.to_string(), "-f", "hex"])
            .output()
            .unwrap();
        let out_b = Command::cargo_bin("mixrand")
            .unwrap()
            .args(["-n", &n.to_string(), "-f", "hex"])
            .output()
            .unwrap();
        prop_assert!(out_a.status.success() && out_b.status.success());
        // Two independent 32+-byte random outputs should virtually never match.
        prop_assert_ne!(out_a.stdout, out_b.stdout);
    }
}
