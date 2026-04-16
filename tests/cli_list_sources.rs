//! End-to-end tests for `mixrand list-sources`.

use assert_cmd::Command;

#[test]
fn list_sources_shows_core_sources() {
    // list-sources uses `build_check_sources`, which lists granular CPU
    // instruction sources rather than a single `cpurng` entry.
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["list-sources"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    for name in [
        "hwrng",
        "rdseed",
        "rdrand",
        "haveged",
        "getrandom",
        "urandom",
        "fallback",
    ] {
        assert!(
            s.contains(name),
            "expected {} in list-sources output:\n{}",
            name,
            s
        );
    }
}

#[test]
fn list_sources_has_header_columns() {
    let out = Command::cargo_bin("mixrand")
        .unwrap()
        .args(["list-sources"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    // First non-separator line should contain the column headers.
    let first = s.lines().next().unwrap_or("");
    assert!(first.contains("Name"));
    assert!(first.contains("Status"));
    assert!(first.contains("Type"));
}
