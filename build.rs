//! Build script for mixrand.
//!
//! Emits `cargo:rustc-env=MIXRAND_*` variables capturing build provenance
//! (git commit, build timestamp, rustc version, target triple). These are
//! read by `src/version_info.rs` to produce the `--version --verbose`
//! output. All values fall back to `"unknown"` if the corresponding tool
//! is unavailable, so non-git source trees and offline builds still work.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn run_git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn git_hash() -> String {
    run_git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_string())
}

fn git_dirty_suffix() -> &'static str {
    match Command::new("git").args(["status", "--porcelain"]).output() {
        Ok(o) if o.status.success() => {
            if o.stdout.is_empty() {
                ""
            } else {
                "-dirty"
            }
        }
        _ => "",
    }
}

fn rustc_version() -> String {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    match Command::new(&rustc).arg("--version").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    }
}

/// Minimal RFC3339-shaped timestamp in UTC (YYYY-MM-DDTHH:MM:SSZ). Avoids
/// adding a chrono/time dep; the value is informational only.
fn build_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Decompose using the classic algorithm (Howard Hinnant "date"-style,
    // but truncated for RFC3339 UTC only). No deps.
    let (year, month, day, hour, minute, second) = ts_to_ymd_hms(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

/// Unix seconds → (year, month[1..12], day[1..31], h, m, s).
fn ts_to_ymd_hms(ts: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = ts.div_euclid(86_400);
    let secs_of_day = ts.rem_euclid(86_400) as u32;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day / 60) % 60;
    let second = secs_of_day % 60;
    // Civil from days since 1970-01-01 (Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 {
        (mp + 3) as u32
    } else {
        (mp - 9) as u32
    };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, minute, second)
}

fn main() {
    let hash = git_hash();
    let dirty = git_dirty_suffix();
    println!("cargo:rustc-env=MIXRAND_GIT_HASH={hash}{dirty}");
    println!(
        "cargo:rustc-env=MIXRAND_BUILD_TIMESTAMP={}",
        build_timestamp()
    );
    println!("cargo:rustc-env=MIXRAND_RUSTC_VERSION={}", rustc_version());
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=MIXRAND_TARGET={target}");

    // Rebuild if HEAD moves or a refs/heads commit lands.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");
}
