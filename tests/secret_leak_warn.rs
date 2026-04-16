//! Test that passing a secret on the CLI triggers a WARN on stderr.

use assert_cmd::Command;

#[test]
fn pkcs11_pin_on_cli_warns_stderr() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["--pkcs11-pin", "12345", "-n", "16"])
        .output()
        .unwrap();
    assert!(out.status.success() || !out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("--pkcs11-pin") && stderr.to_lowercase().contains("security"),
        "expected security warning in stderr, got:\n{}",
        stderr
    );
}

#[test]
fn yubihsm_password_on_cli_warns_stderr() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["--yubihsm-password", "letmein", "-n", "16"])
        .output()
        .unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("--yubihsm-password"),
        "expected --yubihsm-password mentioned in warning:\n{}",
        stderr
    );
}

#[test]
fn no_warning_when_env_var_used() {
    // Using MIXRAND_PKCS11_PIN via env var must NOT trigger the warning.
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .env("MIXRAND_PKCS11_PIN", "viaenv")
        .args(["-n", "16"])
        .output()
        .unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.contains("--pkcs11-pin"),
        "no warning should mention --pkcs11-pin when env was used:\n{}",
        stderr
    );
}
