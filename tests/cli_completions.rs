//! End-to-end tests for `mixrand completions <shell>`.
//!
//! Verifies each supported shell emits non-empty completion script. Shell-
//! specific parse checks (e.g. `bash -n`) aren't run here since those tools
//! may not be installed in every test environment.

use assert_cmd::Command;

#[test]
fn bash_completions_emit_non_empty() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["completions", "bash"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.len() > 100);
    assert!(s.contains("mixrand"));
    assert!(s.contains("_mixrand") || s.contains("complete"));
}

#[test]
fn zsh_completions_emit_non_empty() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["completions", "zsh"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.len() > 100);
    assert!(s.starts_with("#compdef"));
}

#[test]
fn fish_completions_emit_non_empty() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["completions", "fish"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.len() > 100);
    assert!(s.contains("mixrand"));
}

#[test]
fn powershell_completions_emit_non_empty() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["completions", "powershell"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.len() > 100);
    assert!(s.contains("mixrand"));
}
