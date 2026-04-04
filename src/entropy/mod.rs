pub mod cpurng;
pub mod fallback;
pub mod getrandom;
pub mod haveged;
pub mod hwrng;
pub mod jitter;
pub mod procfs;

use std::path::Path;

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

/// Build the sources used by `generate()` (main entropy cascade).
pub fn build_generate_sources(config: &CpuRngConfig) -> Vec<Box<dyn EntropySource>> {
    vec![
        Box::new(HwrngSource),
        Box::new(CpuRngStandaloneSource::new(config)),
        Box::new(HavegedSource),
        Box::new(FallbackSource::new(config)),
    ]
}

/// Build all granular sources for statistical testing in `check` mode.
pub fn build_check_sources(config: &CpuRngConfig) -> Vec<Box<dyn EntropySource>> {
    vec![
        Box::new(HwrngSource),
        Box::new(RndrrsSource::new(config)),
        Box::new(RndrSource::new(config)),
        Box::new(RdseedSource::new(config)),
        Box::new(RdrandSource::new(config)),
        Box::new(XstoreSource::new(config)),
        Box::new(HavegedSource),
        Box::new(GetrandomSource),
        Box::new(UrandomSource),
        Box::new(FallbackSource::new(config)),
    ]
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

/// Attempts entropy sources in priority order, running a health check on each.
/// Sources that fail collection or health testing are skipped.
pub fn generate(count: usize, config: &CpuRngConfig) -> Result<EntropyResult, Error> {
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
                return Ok(EntropyResult {
                    bytes,
                    source: source.description().into(),
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
        let config = CpuRngConfig::default();
        let result = generate(32, &config).unwrap();
        assert_eq!(result.bytes.len(), 32);
        assert!(!result.source.is_empty());
    }

    #[test]
    fn test_generate_different_sizes() {
        let config = CpuRngConfig::default();
        for &size in &[1, 16, 64, 256] {
            let result = generate(size, &config).unwrap();
            assert_eq!(result.bytes.len(), size);
        }
    }

    #[test]
    fn test_build_generate_sources_order() {
        let config = CpuRngConfig::default();
        let sources = build_generate_sources(&config);
        assert_eq!(sources.len(), 4);
        assert_eq!(sources[0].name(), "hwrng");
        assert_eq!(sources[1].name(), "cpurng");
        assert_eq!(sources[2].name(), "haveged");
        assert_eq!(sources[3].name(), "fallback");
    }

    #[test]
    fn test_build_check_sources() {
        let config = CpuRngConfig::default();
        let sources = build_check_sources(&config);
        assert_eq!(sources.len(), 10);
        // Verify names match expected
        let names: Vec<&str> = sources.iter().map(|s| s.name()).collect();
        assert!(names.contains(&"hwrng"));
        assert!(names.contains(&"fallback"));
        assert!(names.contains(&"getrandom"));
    }

    #[test]
    fn test_source_priorities_ascending() {
        let config = CpuRngConfig::default();
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
        let config = CpuRngConfig::default();
        let result = generate(4096, &config).unwrap();
        assert_eq!(result.bytes.len(), 4096);
    }
}
