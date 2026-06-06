//! Build provenance + feature enumeration for `--version --verbose`.
//!
//! The env vars here are emitted by `build.rs` at compile time, so
//! accessing them via `env!(...)` is infallible. The feature list is
//! computed by checking `cfg!(feature = ...)` for every known optional
//! feature; the order is stable and matches `Cargo.toml`.

/// Short git commit of the build (`unknown` if not built from a git tree).
pub const GIT_HASH: &str = env!("MIXRAND_GIT_HASH");

/// UTC RFC3339 timestamp of the build.
pub const BUILD_TIMESTAMP: &str = env!("MIXRAND_BUILD_TIMESTAMP");

/// Full `rustc --version` string used to compile this binary.
pub const RUSTC_VERSION: &str = env!("MIXRAND_RUSTC_VERSION");

/// Target triple (e.g. `x86_64-unknown-linux-gnu`).
pub const TARGET: &str = env!("MIXRAND_TARGET");

/// Version string from `Cargo.toml`.
pub const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Enabled optional features as a `&'static str` slice in declaration
/// order. Returns an empty slice for a stock build (no `hsm`/`sgx` etc).
pub fn enabled_features() -> &'static [&'static str] {
    const fn collect() -> &'static [&'static str] {
        // const-ish collection via a fixed-size builder is awkward in
        // stable Rust; use a runtime-sized array inside a match tree for
        // readability. The compiler inlines this into a constant list.
        &[
            #[cfg(feature = "pkcs11")]
            "pkcs11",
            #[cfg(feature = "tpm2")]
            "tpm2",
            #[cfg(feature = "pcsc")]
            "pcsc",
            #[cfg(feature = "yubikey")]
            "yubikey",
            #[cfg(feature = "yubihsm-native")]
            "yubihsm-native",
            #[cfg(feature = "gnupg")]
            "gnupg",
            #[cfg(feature = "sgx")]
            "sgx",
            #[cfg(feature = "gps")]
            "gps",
            #[cfg(feature = "testing")]
            "testing",
        ]
    }
    collect()
}

/// Print the verbose version block to stdout. Used when the CLI sees
/// both `--version`/`-V` and `--verbose`/`-v` in the same invocation.
pub fn print_verbose() {
    let features = enabled_features();
    let features_str = if features.is_empty() {
        "default".to_string()
    } else {
        features.join(", ")
    };
    println!("mixrand {PKG_VERSION}");
    println!("  git:       {GIT_HASH}");
    println!("  built:     {BUILD_TIMESTAMP}");
    println!("  rustc:     {RUSTC_VERSION}");
    println!("  target:    {TARGET}");
    println!("  features:  {features_str}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_non_empty() {
        // At minimum the Cargo version is guaranteed to be present.
        assert!(!PKG_VERSION.is_empty());
        // build.rs falls back to "unknown" but never an empty string.
        assert!(!GIT_HASH.is_empty());
        assert!(!BUILD_TIMESTAMP.is_empty());
        assert!(!RUSTC_VERSION.is_empty());
        assert!(!TARGET.is_empty());
    }

    #[test]
    fn timestamp_looks_rfc3339_utc() {
        // Shape: YYYY-MM-DDTHH:MM:SSZ (length 20).
        let ts = BUILD_TIMESTAMP;
        if ts != "unknown" {
            assert_eq!(ts.len(), 20, "unexpected timestamp: {ts}");
            assert!(ts.ends_with('Z'));
            assert_eq!(ts.as_bytes()[4], b'-');
            assert_eq!(ts.as_bytes()[7], b'-');
            assert_eq!(ts.as_bytes()[10], b'T');
        }
    }

    #[test]
    fn enabled_features_stable_reference() {
        // Stock build has no optional features enabled.
        let f = enabled_features();
        // Whatever subset is on, every entry must be one of the known
        // feature names.
        let known = [
            "pkcs11",
            "tpm2",
            "pcsc",
            "yubikey",
            "yubihsm-native",
            "gnupg",
            "sgx",
            "gps",
            "testing",
        ];
        for name in f {
            assert!(known.contains(name), "unexpected feature: {name}");
        }
    }
}
