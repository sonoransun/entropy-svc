//! End-to-end test: 4-layer config merge (defaults -> TOML file -> env var -> CLI flag).
//!
//! Uses `--show-config` to read back the effective config and asserts that the
//! expected layer wins at each stage.

use assert_cmd::Command;
use std::io::Write;

fn extract_field(toml: &str, field: &str) -> String {
    for line in toml.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(field) {
            if let Some(value) = rest.strip_prefix(" = ") {
                return value.trim().trim_matches('"').to_string();
            }
            if let Some(value) = rest.strip_prefix("=") {
                return value.trim().trim_matches('"').to_string();
            }
        }
    }
    panic!("field `{}` not found in config output:\n{}", field, toml);
}

#[test]
fn default_layer_wins_when_nothing_set() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["--show-config"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(extract_field(&s, "oversample"), "2");
    assert_eq!(extract_field(&s, "rdrand_retries"), "10");
}

#[test]
fn toml_file_overrides_default() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        tmp.as_file(),
        "[cpu_rng]\noversample = 7\nrdrand_retries = 42\n"
    )
    .unwrap();
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .env_remove("MIXRAND_OVERSAMPLE")
        .env_remove("MIXRAND_RDRAND_RETRIES")
        .args(["--config", tmp.path().to_str().unwrap(), "--show-config"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(extract_field(&s, "oversample"), "7");
    assert_eq!(extract_field(&s, "rdrand_retries"), "42");
}

#[test]
fn env_overrides_toml() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp.as_file(), "[cpu_rng]\noversample = 7\n").unwrap();
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .env("MIXRAND_OVERSAMPLE", "5")
        .args(["--config", tmp.path().to_str().unwrap(), "--show-config"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(extract_field(&s, "oversample"), "5");
}

#[test]
fn cli_overrides_env_and_toml() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp.as_file(), "[cpu_rng]\noversample = 7\n").unwrap();
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .env("MIXRAND_OVERSAMPLE", "5")
        .args([
            "--config",
            tmp.path().to_str().unwrap(),
            "--oversample",
            "3",
            "--show-config",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(extract_field(&s, "oversample"), "3");
}

#[test]
fn cli_validation_clamps_out_of_range() {
    // oversample max is 16; CLI passes 100 and validation should clamp.
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .env_remove("MIXRAND_OVERSAMPLE")
        .args(["--oversample", "100", "--show-config"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(extract_field(&s, "oversample"), "16");
}
