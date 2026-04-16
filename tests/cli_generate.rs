//! End-to-end tests for `mixrand` generate-mode output formats and options.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn generate_default_hex_32_bytes() {
    Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "32"])
        .assert()
        .success()
        .stdout(predicate::function(|s: &[u8]| s.len() == 65)); // 64 hex + \n
}

#[test]
fn generate_hex_upper_is_uppercase() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "16", "-f", "hex-upper"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let trimmed = s.trim();
    assert_eq!(trimmed.len(), 32);
    assert!(trimmed
        .chars()
        .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase()));
}

#[test]
fn generate_raw_has_exact_length_and_no_newline() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "64", "-f", "raw"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout.len(), 64);
}

#[test]
fn generate_base64_decodes_correctly() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "48", "-f", "base64"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let decoded = STANDARD.decode(s.trim()).unwrap();
    assert_eq!(decoded.len(), 48);
}

#[test]
fn generate_base64url_has_no_padding() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "10", "-f", "base64url"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(!s.contains('='));
    assert!(!s.contains('+'));
    assert!(!s.contains('/'));
}

#[test]
fn generate_text_produces_printable_ascii() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "32", "-f", "text"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let line = s.trim_end_matches('\n');
    assert_eq!(line.chars().count(), 32);
    for c in line.chars() {
        assert!(
            matches!(c as u32, 33..=126),
            "non-printable char in text output: {:?}",
            c
        );
    }
}

#[test]
fn generate_octal_format() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "4", "-f", "octal"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let parts: Vec<&str> = s.trim().split_whitespace().collect();
    assert_eq!(parts.len(), 4);
    for p in &parts {
        assert_eq!(p.len(), 3);
        assert!(p.chars().all(|c| ('0'..='7').contains(&c)));
        let v = u16::from_str_radix(p, 8).unwrap();
        assert!(v <= 255);
    }
}

#[test]
fn generate_binary_format() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "3", "-f", "binary"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let parts: Vec<&str> = s.trim().split_whitespace().collect();
    assert_eq!(parts.len(), 3);
    for p in &parts {
        assert_eq!(p.len(), 8);
        assert!(p.chars().all(|c| c == '0' || c == '1'));
    }
}

#[test]
fn generate_uuencode_has_wrapper_frame() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "16", "-f", "uuencode"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.starts_with("begin 644 data\n"));
    assert!(s.trim_end().ends_with("end"));
}

#[test]
fn generate_count_n_produces_n_lines() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["--count", "4", "-n", "8", "-f", "hex"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let lines: Vec<&str> = std::str::from_utf8(&out.stdout)
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(lines.len(), 4);
    for line in &lines {
        assert_eq!(line.len(), 16);
        assert!(line.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[test]
fn generate_to_output_file_writes_bytes() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "24", "-f", "raw", "-o", tmp.path().to_str().unwrap()])
        .assert()
        .success();
    let contents = std::fs::read(tmp.path()).unwrap();
    assert_eq!(contents.len(), 24);
}

#[test]
fn generate_rejects_zero_bytes() {
    Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "0"])
        .assert()
        .failure();
}

#[test]
fn generate_rejects_byte_count_over_max() {
    Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "2147483647"]) // > 100 MiB
        .assert()
        .failure();
}

#[test]
fn generate_outputs_differ_across_invocations() {
    let a = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "32", "-f", "hex"])
        .output()
        .unwrap();
    let b = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "32", "-f", "hex"])
        .output()
        .unwrap();
    assert_ne!(a.stdout, b.stdout);
}

#[test]
fn show_config_prints_toml() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["--show-config"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    // TOML output should contain known field names.
    assert!(s.contains("oversample"));
    assert!(s.contains("mixer_mode"));
}

// --- CLI input-validation edge cases ---

#[test]
fn generate_exceeds_max_byte_count_is_rejected() {
    // MAX_BYTES is 100 MiB in main.rs; request 101 MiB.
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "105906176", "-f", "hex"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("exceeds maximum") || err.contains("100 MiB"),
        "stderr: {err}"
    );
}

#[test]
fn generate_invalid_format_fails_with_helpful_error() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "4", "-f", "xyzzy"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    // Clap produces a "invalid value 'xyzzy' for '--format <FORMAT>'" message
    // and lists possible values.
    assert!(
        err.contains("invalid value") || err.contains("possible values"),
        "stderr: {err}"
    );
}

#[test]
fn generate_zero_bytes_is_rejected() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["-n", "0", "-f", "raw"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "zero-byte request unexpectedly accepted"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("greater than 0") || err.contains("must be"),
        "stderr: {err}"
    );
}
