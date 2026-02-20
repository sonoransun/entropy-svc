pub mod cpurng;
pub mod fallback;
pub mod haveged;
pub mod hwrng;
pub mod jitter;
pub mod procfs;

use crate::config::CpuRngConfig;
use crate::error::Error;

/// Result of entropy generation, including the bytes and which source was used.
pub struct EntropyResult {
    pub bytes: Vec<u8>,
    pub source: String,
}

/// Attempts entropy sources in priority order:
/// 1. Hardware RNG (/dev/hwrng)
/// 2. CPU hardware RNG (RDSEED/RDRAND/XSTORE) with standalone oversampling
/// 3. Haveged (/dev/random with haveged)
/// 4. Fallback (urandom + procfs + jitter mixed through BLAKE2b → ChaCha20)
pub fn generate(count: usize, config: &CpuRngConfig) -> Result<EntropyResult, Error> {
    // Try hardware RNG first
    match hwrng::read_hwrng(count) {
        Ok(bytes) => {
            return Ok(EntropyResult {
                bytes,
                source: "hardware RNG (/dev/hwrng)".into(),
            });
        }
        Err(e) => {
            log::debug!("hwrng unavailable: {}", e);
        }
    }

    // Try CPU hardware RNG (RDSEED/RDRAND/XSTORE) with standalone oversampling
    match cpurng::collect_cpu_entropy_standalone(count, config) {
        Ok(result) => {
            let source = if config.oversample > 1 {
                format!(
                    "CPU hardware RNG ({}, {}x oversample)",
                    result.source_label, config.oversample
                )
            } else {
                format!("CPU hardware RNG ({})", result.source_label)
            };
            return Ok(EntropyResult {
                bytes: result.bytes,
                source,
            });
        }
        Err(e) => {
            log::debug!("cpurng unavailable: {}", e);
        }
    }

    // Try haveged
    match haveged::read_haveged(count) {
        Ok(bytes) => {
            return Ok(EntropyResult {
                bytes,
                source: "haveged (/dev/random)".into(),
            });
        }
        Err(e) => {
            log::debug!("haveged unavailable: {}", e);
        }
    }

    // Fallback
    let bytes = fallback::generate_fallback(count, config)?;
    Ok(EntropyResult {
        bytes,
        source: "fallback (urandom + procfs + jitter + cpu-rng → BLAKE2b → ChaCha20)".into(),
    })
}
