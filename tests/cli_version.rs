//! Integration tests for the `--version --verbose` build-info output.

use assert_cmd::Command;
use predicates::prelude::*;

fn run(args: &[&str]) -> assert_cmd::assert::Assert {
    Command::cargo_bin("mixrand")
        .expect("mixrand binary")
        .args(args)
        .assert()
}

#[test]
fn plain_version_unchanged() {
    // `--version` alone should still match clap's one-line format.
    run(&["--version"])
        .success()
        .stdout(predicate::str::starts_with("mixrand "))
        .stdout(predicate::str::contains("git:").not());
}

#[test]
fn version_verbose_prints_build_info_block() {
    let assert = run(&["--version", "--verbose"]).success();
    let out = assert.get_output();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("mixrand "), "stdout: {stdout}");
    // Every labeled field from version_info::print_verbose.
    for needle in ["git:", "built:", "rustc:", "target:", "features:"] {
        assert!(
            stdout.contains(needle),
            "expected `{needle}` in stdout, got: {stdout}"
        );
    }
}

#[test]
fn version_verbose_accepts_short_flags() {
    // `-V -v` should also trigger the verbose block.
    run(&["-V", "-v"])
        .success()
        .stdout(predicate::str::contains("built:"));
}

#[test]
fn version_verbose_flags_in_reverse_order() {
    run(&["--verbose", "--version"])
        .success()
        .stdout(predicate::str::contains("built:"));
}

#[test]
fn verbose_without_version_does_not_trigger() {
    // `--verbose` on its own is owned by the log-args flatten and should
    // NOT print the version block; clap may error depending on subcommand
    // presence. Either way, stdout must not be the verbose block.
    let out = Command::cargo_bin("mixrand")
        .expect("mixrand binary")
        .args(["--verbose"])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("built:"),
        "bare --verbose should not emit build info: {stdout}"
    );
}
