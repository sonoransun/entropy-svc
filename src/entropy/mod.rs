pub mod cpurng;
pub mod fallback;
pub mod getrandom;
#[cfg(feature = "gnupg")]
pub mod gnupg;
#[cfg(feature = "gps")]
pub mod gps;
pub mod haveged;
pub mod hwrng;
pub mod jitter;
#[cfg(any(test, feature = "testing"))]
pub mod mock;
#[cfg(feature = "pcsc")]
pub mod pcsc;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;
pub mod procfs;
#[cfg(feature = "sgx")]
pub mod sgx;
#[cfg(feature = "tpm2")]
pub mod tpm2;
#[cfg(feature = "yubihsm-native")]
pub mod yubihsm;
#[cfg(feature = "yubikey")]
pub mod yubikey;

use std::path::Path;

use crate::config::Config;
use crate::config::CpuRngConfig;
use crate::error::Error;
use crate::health::HealthTester;

/// Result of entropy generation, including the bytes and which source was used.
pub struct EntropyResult {
    pub bytes: Vec<u8>,
    pub source: String,
}

/// Trait for pluggable entropy sources with priority-ordered fallback.
#[allow(dead_code)]
pub trait EntropySource: Send + Sync {
    /// Short machine-friendly name (e.g., "hwrng", "rdseed").
    fn name(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str;

    /// Priority (lower = tried first in generate cascade).
    fn priority(&self) -> u32;

    /// Quick availability check. Returns true if the source is likely to work.
    fn is_available(&self) -> bool;

    /// Source classification: "hardware", "system", or "software".
    fn source_type(&self) -> &str {
        "software"
    }

    /// Collect `count` bytes of entropy.
    fn collect(&self, count: usize) -> Result<Vec<u8>, Error>;
}

// ---------------------------------------------------------------------------
// Source implementations
// ---------------------------------------------------------------------------

pub struct HwrngSource;

impl EntropySource for HwrngSource {
    fn name(&self) -> &str {
        "hwrng"
    }
    fn description(&self) -> &str {
        "Hardware RNG (/dev/hwrng)"
    }
    fn priority(&self) -> u32 {
        10
    }
    fn source_type(&self) -> &str {
        "hardware"
    }
    fn is_available(&self) -> bool {
        Path::new("/dev/hwrng").exists()
    }
    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        hwrng::read_hwrng(count)
    }
}

/// CPU hardware RNG using the best available instruction (with oversampling).
/// This is the source used in `generate()` — it wraps the full cpurng cascade.
pub struct CpuRngStandaloneSource {
    config: CpuRngConfig,
}

impl CpuRngStandaloneSource {
    pub fn new(config: &CpuRngConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

impl EntropySource for CpuRngStandaloneSource {
    fn name(&self) -> &str {
        "cpurng"
    }
    fn description(&self) -> &str {
        "CPU hardware RNG (standalone)"
    }
    fn priority(&self) -> u32 {
        20
    }
    fn source_type(&self) -> &str {
        "hardware"
    }
    fn is_available(&self) -> bool {
        cpurng::collect_cpu_entropy(1, &self.config).is_ok()
    }
    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        cpurng::collect_cpu_entropy_standalone(count, &self.config).map(|r| r.bytes)
    }
}

/// Individual CPU instruction sources (for granular check-mode testing)
pub struct RdseedSource {
    retries: u32,
}

impl RdseedSource {
    pub fn new(config: &CpuRngConfig) -> Self {
        Self {
            retries: config.rdseed_retries,
        }
    }
}

impl EntropySource for RdseedSource {
    fn name(&self) -> &str {
        "rdseed"
    }
    fn description(&self) -> &str {
        "CPU RDSEED instruction"
    }
    fn priority(&self) -> u32 {
        21
    }
    fn source_type(&self) -> &str {
        "hardware"
    }
    fn is_available(&self) -> bool {
        cpurng::collect_rdseed(1, self.retries).is_ok()
    }
    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        cpurng::collect_rdseed(count, self.retries)
    }
}

pub struct RdrandSource {
    retries: u32,
}

impl RdrandSource {
    pub fn new(config: &CpuRngConfig) -> Self {
        Self {
            retries: config.rdrand_retries,
        }
    }
}

impl EntropySource for RdrandSource {
    fn name(&self) -> &str {
        "rdrand"
    }
    fn description(&self) -> &str {
        "CPU RDRAND instruction"
    }
    fn priority(&self) -> u32 {
        22
    }
    fn source_type(&self) -> &str {
        "hardware"
    }
    fn is_available(&self) -> bool {
        cpurng::collect_rdrand(1, self.retries).is_ok()
    }
    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        cpurng::collect_rdrand(count, self.retries)
    }
}

pub struct XstoreSource {
    quality: u32,
}

impl XstoreSource {
    pub fn new(config: &CpuRngConfig) -> Self {
        Self {
            quality: config.xstore_quality,
        }
    }
}

impl EntropySource for XstoreSource {
    fn name(&self) -> &str {
        "xstore"
    }
    fn description(&self) -> &str {
        "VIA PadLock XSTORE instruction"
    }
    fn priority(&self) -> u32 {
        23
    }
    fn source_type(&self) -> &str {
        "hardware"
    }
    fn is_available(&self) -> bool {
        cpurng::collect_xstore(1, self.quality).is_ok()
    }
    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        cpurng::collect_xstore(count, self.quality)
    }
}

pub struct RndrSource {
    retries: u32,
}

impl RndrSource {
    pub fn new(config: &CpuRngConfig) -> Self {
        Self {
            retries: config.rndr_retries,
        }
    }
}

impl EntropySource for RndrSource {
    fn name(&self) -> &str {
        "rndr"
    }
    fn description(&self) -> &str {
        "AArch64 RNDR instruction"
    }
    fn priority(&self) -> u32 {
        24
    }
    fn source_type(&self) -> &str {
        "hardware"
    }
    fn is_available(&self) -> bool {
        cpurng::collect_rndr(1, self.retries).is_ok()
    }
    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        cpurng::collect_rndr(count, self.retries)
    }
}

pub struct RndrrsSource {
    retries: u32,
}

impl RndrrsSource {
    pub fn new(config: &CpuRngConfig) -> Self {
        Self {
            retries: config.rndrrs_retries,
        }
    }
}

impl EntropySource for RndrrsSource {
    fn name(&self) -> &str {
        "rndrrs"
    }
    fn description(&self) -> &str {
        "AArch64 RNDRRS instruction (reseeded)"
    }
    fn priority(&self) -> u32 {
        25
    }
    fn source_type(&self) -> &str {
        "hardware"
    }
    fn is_available(&self) -> bool {
        cpurng::collect_rndrrs(1, self.retries).is_ok()
    }
    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        cpurng::collect_rndrrs(count, self.retries)
    }
}

pub struct HavegedSource;

impl EntropySource for HavegedSource {
    fn name(&self) -> &str {
        "haveged"
    }
    fn description(&self) -> &str {
        "haveged (/dev/random)"
    }
    fn priority(&self) -> u32 {
        30
    }
    fn source_type(&self) -> &str {
        "system"
    }
    fn is_available(&self) -> bool {
        haveged::read_haveged(1).is_ok()
    }
    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        haveged::read_haveged(count)
    }
}

pub struct GetrandomSource;

impl EntropySource for GetrandomSource {
    fn name(&self) -> &str {
        "getrandom"
    }
    fn description(&self) -> &str {
        "getrandom(2)/getentropy(3) syscall"
    }
    fn priority(&self) -> u32 {
        35
    }
    fn source_type(&self) -> &str {
        "system"
    }
    fn is_available(&self) -> bool {
        getrandom::read_getrandom(1).is_ok()
    }
    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        getrandom::read_getrandom(count)
    }
}

pub struct UrandomSource;

impl EntropySource for UrandomSource {
    fn name(&self) -> &str {
        "urandom"
    }
    fn description(&self) -> &str {
        "/dev/urandom"
    }
    fn priority(&self) -> u32 {
        36
    }
    fn source_type(&self) -> &str {
        "system"
    }
    fn is_available(&self) -> bool {
        Path::new("/dev/urandom").exists()
    }
    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        use std::fs::File;
        use std::io::Read;
        let mut f = File::open("/dev/urandom")
            .map_err(|e| Error::NoEntropy(format!("/dev/urandom not available: {}", e)))?;
        let mut buf = vec![0u8; count];
        f.read_exact(&mut buf)?;
        Ok(buf)
    }
}

pub struct FallbackSource {
    config: CpuRngConfig,
}

impl FallbackSource {
    pub fn new(config: &CpuRngConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

impl EntropySource for FallbackSource {
    fn name(&self) -> &str {
        "fallback"
    }
    fn description(&self) -> &str {
        "Fallback (getrandom/urandom + procfs + jitter + cpu-rng -> BLAKE2b -> ChaCha20)"
    }
    fn priority(&self) -> u32 {
        40
    }
    fn is_available(&self) -> bool {
        true
    }
    fn collect(&self, count: usize) -> Result<Vec<u8>, Error> {
        fallback::generate_fallback(count, &self.config)
    }
}

// ---------------------------------------------------------------------------
// Source builders
// ---------------------------------------------------------------------------

/// Add HSM/secure-element sources based on feature flags and configuration.
#[allow(unused_variables)]
fn add_hsm_sources(sources: &mut Vec<Box<dyn EntropySource>>, config: &Config) {
    #[cfg(feature = "sgx")]
    if config.hsm.sgx.enabled {
        sources.push(Box::new(sgx::SgxSource::new(&config.hsm.sgx)));
    }

    #[cfg(feature = "tpm2")]
    if config.hsm.tpm2.enabled {
        sources.push(Box::new(tpm2::Tpm2Source::new(&config.hsm.tpm2)));
    }

    #[cfg(feature = "pkcs11")]
    if config.hsm.pkcs11.enabled && config.hsm.pkcs11.library_path.is_some() {
        sources.push(Box::new(pkcs11::Pkcs11Source::new(&config.hsm.pkcs11)));
    }

    #[cfg(feature = "yubihsm-native")]
    if config.hsm.yubihsm.enabled {
        sources.push(Box::new(yubihsm::YubiHsmSource::new(&config.hsm.yubihsm)));
    }

    #[cfg(feature = "yubikey")]
    if config.hsm.yubikey.enabled {
        sources.push(Box::new(yubikey::YubiKeySource::new(&config.hsm.yubikey)));
    }

    #[cfg(feature = "pcsc")]
    if config.hsm.pcsc.enabled {
        sources.push(Box::new(pcsc::PcscSource::new(&config.hsm.pcsc)));
    }

    #[cfg(feature = "gnupg")]
    if config.hsm.gnupg.enabled {
        sources.push(Box::new(gnupg::GnuPGSource::new(&config.hsm.gnupg)));
    }

    // Suppress unused variable warning when no HSM features are enabled
    let _ = config;
}

/// Build the sources used by `generate()` (main entropy cascade).
///
/// Priority order (lower = tried first): SGX (4), TPM2 (5), PKCS#11/YubiHSM
/// (6), YubiKey/PC/SC (7), GnuPG (8), hwrng (10), cpurng (20), haveged (30),
/// getrandom (35), urandom (36), fallback (40). When a source fails its
/// health check, the cascade falls through to the next available source —
/// `fallback` is always last and always available.
pub fn build_generate_sources(config: &Config) -> Vec<Box<dyn EntropySource>> {
    let mut sources: Vec<Box<dyn EntropySource>> = vec![Box::new(HwrngSource)];

    add_hsm_sources(&mut sources, config);

    sources.push(Box::new(CpuRngStandaloneSource::new(&config.cpu_rng)));
    sources.push(Box::new(HavegedSource));
    sources.push(Box::new(GetrandomSource));
    sources.push(Box::new(UrandomSource));
    sources.push(Box::new(FallbackSource::new(&config.cpu_rng)));

    sources.sort_by_key(|s| s.priority());
    sources
}

/// Build all granular sources for statistical testing in `check` mode.
pub fn build_check_sources(config: &Config) -> Vec<Box<dyn EntropySource>> {
    let mut sources: Vec<Box<dyn EntropySource>> = vec![
        Box::new(HwrngSource),
        Box::new(RndrrsSource::new(&config.cpu_rng)),
        Box::new(RndrSource::new(&config.cpu_rng)),
        Box::new(RdseedSource::new(&config.cpu_rng)),
        Box::new(RdrandSource::new(&config.cpu_rng)),
        Box::new(XstoreSource::new(&config.cpu_rng)),
        Box::new(HavegedSource),
        Box::new(GetrandomSource),
        Box::new(UrandomSource),
    ];

    add_hsm_sources(&mut sources, config);

    sources.push(Box::new(FallbackSource::new(&config.cpu_rng)));

    sources.sort_by_key(|s| s.priority());
    sources
}

/// Run a quick health check on entropy bytes using NIST SP 800-90B tests.
/// Returns `true` if the bytes pass, `false` if a health failure is detected.
fn health_check(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return true; // too few bytes for meaningful health check
    }
    let mut ht = HealthTester::new(crate::health::DEFAULT_MIN_ENTROPY_BITS);
    for chunk in bytes.chunks_exact(8) {
        let sample = u64::from_ne_bytes(chunk.try_into().unwrap());
        if ht.feed(sample).is_err() {
            return false;
        }
    }
    true
}

/// Gather optional **public** "additional inputs" (NIST SP 800-90A
/// personalization) to fold into generated output. These contribute **0
/// credited entropy** and are never selectable entropy sources. Currently the
/// only one is the GPS Subframe 4/Page 17 special-message field.
///
/// Acquisition is best-effort and bounded by a timeout inside the source; any
/// failure is logged at debug and skipped. The entropy path never blocks on,
/// nor fails because of, an additional input.
#[allow(unused_variables)]
fn gather_additional_inputs(config: &Config) -> Vec<(&'static str, Vec<u8>)> {
    // `mut` is used only when an additional-input feature (e.g. `gps`) is built.
    #[allow(unused_mut)]
    let mut addins: Vec<(&'static str, Vec<u8>)> = Vec::new();

    #[cfg(feature = "gps")]
    if config.hsm.gps.enabled {
        let src = gps::GpsSource::new(&config.hsm.gps);
        if src.is_available() {
            match src.collect(0) {
                Ok(field) => addins.push(("gps-sf4p17", field)),
                Err(e) => log::debug!("gps additional-input unavailable: {}", e),
            }
        }
    }

    addins
}

/// Fold public additional inputs into a strong primary by XOR-ing a public,
/// deterministic keystream derived from those inputs (NIST SP 800-90A
/// "additional input" treatment).
///
/// This is **entropy-neutral**: the mask is a function of public data only, so
/// XOR-ing it into the primary cannot raise or lower the primary's entropy —
/// the output is information-theoretically equivalent to the primary
/// (recoverable as `output XOR mask`). It can therefore never let a public
/// value masquerade as entropy, never weakens the primary below its own
/// strength, and needs no reseeding (the mask is public, of any length).
///
/// Returns `primary` unchanged when there are no addins — so behavior is
/// identical to the pre-existing path whenever GPS is disabled/unavailable.
fn fold_additional_input(mut primary: Vec<u8>, addins: &[(&str, &[u8])]) -> Vec<u8> {
    if addins.is_empty() || primary.is_empty() {
        return primary;
    }
    // 32-byte key from the PUBLIC addins, expanded to a primary-length PUBLIC
    // ChaCha20 keystream. mix_entropy zeroizes its digest; csprng::generate
    // zeroizes the seed and RNG state.
    let key = crate::mixer::mix_entropy(addins);
    let mut mask = crate::csprng::generate(key, primary.len());
    for (p, m) in primary.iter_mut().zip(mask.iter()) {
        *p ^= *m;
    }
    cpurng::zeroize_vec(&mut mask);
    primary
}

/// Attempts entropy sources in priority order, running a health check on each.
/// Sources that fail collection or health testing are skipped.
///
/// After a strong source wins and passes the health check, any configured
/// public additional inputs (e.g. the GPS Subframe 4/Page 17 field) are folded
/// in via [`fold_additional_input`] — mixed but credited 0 entropy bits. The
/// health check gates the *primary* (the real entropy); the fold is
/// entropy-neutral.
pub fn generate(count: usize, config: &Config) -> Result<EntropyResult, Error> {
    let sources = build_generate_sources(config);

    let mut tried = Vec::new();
    for source in &sources {
        match source.collect(count) {
            Ok(bytes) => {
                if !health_check(&bytes) {
                    log::warn!("{} failed health check, trying next source", source.name());
                    tried.push(format!("{}: health check failed", source.name()));
                    continue;
                }

                // Fold in public additional inputs (0-bit credit). Skipped for
                // zero-length requests and whenever none are available.
                let addins = if count > 0 {
                    gather_additional_inputs(config)
                } else {
                    Vec::new()
                };
                if addins.is_empty() {
                    return Ok(EntropyResult {
                        bytes,
                        source: source.description().into(),
                    });
                }
                let refs: Vec<(&str, &[u8])> =
                    addins.iter().map(|(l, d)| (*l, d.as_slice())).collect();
                let labels: Vec<&str> = addins.iter().map(|(l, _)| *l).collect();
                let folded = fold_additional_input(bytes, &refs);
                return Ok(EntropyResult {
                    bytes: folded,
                    source: format!(
                        "{} + {} (0-bit addin)",
                        source.description(),
                        labels.join("+")
                    ),
                });
            }
            Err(e) => {
                log::debug!("{} unavailable: {}", source.name(), e);
                tried.push(format!("{}: {}", source.name(), e));
            }
        }
    }

    if tried.is_empty() {
        Err(Error::NoEntropy("no entropy sources configured".into()))
    } else {
        Err(Error::NoEntropy(format!(
            "all entropy sources failed: {}",
            tried.join("; ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_produces_bytes() {
        let config = Config::default();
        let result = generate(32, &config).unwrap();
        assert_eq!(result.bytes.len(), 32);
        assert!(!result.source.is_empty());
    }

    // --- GPS additional-input invariants ---

    #[test]
    fn gps_additional_input_never_a_selectable_source() {
        // Even with GPS enabled, it must never appear in either source builder
        // (so it can never win the cascade or be graded in check / daemon
        // self-test).
        let mut config = Config::default();
        config.hsm.gps.enabled = true;
        config.hsm.gps.path = Some("/nonexistent/page17".into());
        for s in build_generate_sources(&config) {
            assert_ne!(
                s.name(),
                "gps-sf4p17",
                "GPS must never be in the generate cascade"
            );
        }
        for s in build_check_sources(&config) {
            assert_ne!(
                s.name(),
                "gps-sf4p17",
                "GPS must never be in the check builder"
            );
        }
    }

    #[test]
    fn fold_empty_addins_is_identity() {
        let primary = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(fold_additional_input(primary.clone(), &[]), primary);
    }

    #[test]
    fn fold_is_entropy_neutral_and_recoverable() {
        let primary = vec![0xAAu8; 64];
        let addin: &[u8] = b"public-gps-field-value"; // 22 bytes
        let out = fold_additional_input(primary.clone(), &[("gps-sf4p17", addin)]);
        assert_ne!(out, primary, "fold must change the bytes");
        assert_eq!(out.len(), primary.len());

        // Recompute the public mask and confirm output XOR mask == primary,
        // proving the fold preserves (and cannot manufacture) entropy.
        let key = crate::mixer::mix_entropy(&[("gps-sf4p17", addin)]);
        let mask = crate::csprng::generate(key, primary.len());
        let recovered: Vec<u8> = out.iter().zip(mask.iter()).map(|(o, m)| o ^ m).collect();
        assert_eq!(
            recovered, primary,
            "output XOR public mask must recover primary"
        );
    }

    #[test]
    fn fold_differs_by_addin() {
        let primary = vec![0x11u8; 48];
        let a = fold_additional_input(
            primary.clone(),
            &[("gps-sf4p17", &b"AAAAAAAAAAAAAAAAAAAAAA"[..])],
        );
        let b = fold_additional_input(
            primary.clone(),
            &[("gps-sf4p17", &b"BBBBBBBBBBBBBBBBBBBBBB"[..])],
        );
        assert_ne!(a, b, "different addin must yield different output");
    }

    #[test]
    fn gather_additional_inputs_empty_when_gps_disabled() {
        let config = Config::default(); // gps.enabled == false by default
        assert!(gather_additional_inputs(&config).is_empty());
    }

    #[test]
    fn gather_additional_inputs_empty_when_enabled_but_unconfigured() {
        let mut config = Config::default();
        config.hsm.gps.enabled = true; // but no command/path => unavailable
        assert!(gather_additional_inputs(&config).is_empty());
    }

    #[cfg(feature = "gps")]
    #[test]
    fn gather_skips_gps_when_collect_fails() {
        // Enabled with a configured-but-broken path: is_available() is true,
        // collect() fails, gather must degrade gracefully to empty.
        let mut config = Config::default();
        config.hsm.gps.enabled = true;
        config.hsm.gps.path = Some("/nonexistent/page17".into());
        config.hsm.gps.timeout_ms = 100;
        assert!(gather_additional_inputs(&config).is_empty());
    }

    #[test]
    fn test_generate_different_sizes() {
        let config = Config::default();
        for &size in &[1, 16, 64, 256] {
            let result = generate(size, &config).unwrap();
            assert_eq!(result.bytes.len(), size);
        }
    }

    #[test]
    fn test_build_generate_sources_has_core() {
        let config = Config::default();
        let sources = build_generate_sources(&config);
        // At minimum: hwrng, cpurng, haveged, getrandom, urandom, fallback
        assert!(sources.len() >= 6);
        let names: Vec<&str> = sources.iter().map(|s| s.name()).collect();
        assert!(names.contains(&"hwrng"));
        assert!(names.contains(&"cpurng"));
        assert!(names.contains(&"haveged"));
        assert!(names.contains(&"getrandom"));
        assert!(names.contains(&"urandom"));
        assert!(names.contains(&"fallback"));
    }

    #[test]
    fn test_build_generate_sources_priority_ordering() {
        // urandom (36) must appear before fallback (40), after haveged (30).
        let config = Config::default();
        let sources = build_generate_sources(&config);
        let pos_of =
            |name: &str| -> Option<usize> { sources.iter().position(|s| s.name() == name) };
        let (haveged, urandom, fallback) = (
            pos_of("haveged").unwrap(),
            pos_of("urandom").unwrap(),
            pos_of("fallback").unwrap(),
        );
        assert!(haveged < urandom);
        assert!(urandom < fallback);
    }

    #[test]
    fn test_build_check_sources() {
        let config = Config::default();
        let sources = build_check_sources(&config);
        // At minimum: 10 core sources
        assert!(sources.len() >= 10);
        let names: Vec<&str> = sources.iter().map(|s| s.name()).collect();
        assert!(names.contains(&"hwrng"));
        assert!(names.contains(&"fallback"));
        assert!(names.contains(&"getrandom"));
    }

    #[test]
    fn test_source_priorities_ascending() {
        let config = Config::default();
        let sources = build_generate_sources(&config);
        for i in 1..sources.len() {
            assert!(
                sources[i].priority() >= sources[i - 1].priority(),
                "{} has lower priority than {}",
                sources[i].name(),
                sources[i - 1].name()
            );
        }
    }

    #[test]
    fn test_fallback_always_available() {
        let config = CpuRngConfig::default();
        let source = FallbackSource::new(&config);
        assert!(source.is_available());
    }

    #[test]
    fn test_fallback_collect() {
        let config = CpuRngConfig::default();
        let source = FallbackSource::new(&config);
        let data = source.collect(64).unwrap();
        assert_eq!(data.len(), 64);
    }

    #[test]
    fn test_getrandom_source() {
        let source = GetrandomSource;
        if source.is_available() {
            let data = source.collect(32).unwrap();
            assert_eq!(data.len(), 32);
        }
    }

    #[test]
    fn test_health_check_all_zeros_fails() {
        assert!(!health_check(&[0u8; 256]));
    }

    #[test]
    fn test_health_check_random_passes() {
        use rand_chacha::ChaCha20Rng;
        use rand_core::{RngCore, SeedableRng};
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let mut data = vec![0u8; 256];
        rng.fill_bytes(&mut data);
        assert!(health_check(&data));
    }

    #[test]
    fn test_health_check_small_data_passes() {
        assert!(health_check(&[1, 2, 3]));
    }

    #[test]
    fn test_generate_large_request() {
        let config = Config::default();
        let result = generate(4096, &config).unwrap();
        assert_eq!(result.bytes.len(), 4096);
    }
}
