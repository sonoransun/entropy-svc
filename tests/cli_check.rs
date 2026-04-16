//! End-to-end tests for `mixrand check` subcommand.
//!
//! Uses short durations (2s) with sample_size 2500 (FIPS minimum) against the
//! `fallback` source, which is always available on every platform.

use assert_cmd::Command;

#[test]
fn check_runs_text_output() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args([
            "check",
            "--duration",
            "2s",
            "--sample-size",
            "2500",
            "--sources",
            "fallback",
            "--quiet",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8(out.stdout).unwrap();
    // Text output: look for the per-source table heading or source name.
    assert!(
        s.contains("fallback"),
        "expected 'fallback' in output: {}",
        s
    );
}

#[test]
fn check_runs_json_output_parses() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args([
            "check",
            "--duration",
            "2s",
            "--sample-size",
            "2500",
            "--sources",
            "fallback",
            "--quiet",
            "--output-format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&s).unwrap_or_else(|e| panic!("invalid JSON: {}\n---\n{}", e, s));
    // Expect a top-level structure with sources.
    assert!(v.is_object() || v.is_array());
}

#[test]
fn check_runs_csv_output_has_header() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args([
            "check",
            "--duration",
            "2s",
            "--sample-size",
            "2500",
            "--sources",
            "fallback",
            "--quiet",
            "--output-format",
            "csv",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8(out.stdout).unwrap();
    let first = s.lines().next().unwrap_or("");
    // CSV header row should list column names.
    assert!(first.contains(','), "expected CSV header: {:?}", first);
}

#[test]
fn check_rejects_invalid_duration() {
    Command::cargo_bin("mixrand")
        .unwrap()
        .args(["check", "--duration", "not-a-duration"])
        .assert()
        .failure();
}
