use std::fs::File;
use std::io::Read;

use crate::config::{CpuRngConfig, MixerMode};
use crate::csprng;
use crate::error::Error;
use crate::memlock;
use crate::mixer;

use super::cpurng;
use super::getrandom;
use super::jitter;
use super::procfs;

/// Read 32 bytes from the best available system random source.
/// Prefers getrandom(2)/getentropy(3), falls back to /dev/urandom.
fn read_system_random(buf: &mut [u8; 32]) -> Result<(), Error> {
    match getrandom::read_getrandom(32) {
        Ok(data) => {
            buf.copy_from_slice(&data);
            Ok(())
        }
        Err(_) => {
            // Fall back to /dev/urandom
            File::open("/dev/urandom")?.read_exact(buf)?;
            Ok(())
        }
    }
}

/// Collect a fresh 32-byte seed from system random + procfs + jitter + cpu-rng mixed through BLAKE2b.
fn collect_fresh_seed(config: &CpuRngConfig) -> [u8; 32] {
    let mut urandom_seed = [0u8; 32];
    let _ = read_system_random(&mut urandom_seed);

    let mut interrupts = procfs::read_interrupts();
    let mut stat = procfs::read_stat();
    let mut diskstats = procfs::read_diskstats();
    let mut jitter_data = jitter::collect_jitter_samples(64);
    let mut cpu_entropy =
        cpurng::collect_cpu_entropy_best_effort(config.fallback_mix_bytes, config);

    let seed = mixer::mix_entropy(&[
        ("urandom-reseed", &urandom_seed),
        ("interrupts", &interrupts),
        ("stat", &stat),
        ("diskstats", &diskstats),
        ("jitter", &jitter_data),
        ("cpu-rng", &cpu_entropy),
    ]);

    cpurng::zeroize_bytes(&mut urandom_seed);
    cpurng::zeroize_vec(&mut interrupts);
    cpurng::zeroize_vec(&mut stat);
    cpurng::zeroize_vec(&mut diskstats);
    cpurng::zeroize_vec(&mut jitter_data);
    cpurng::zeroize_vec(&mut cpu_entropy);

    seed
}

/// Fallback entropy source: mixes getrandom/urandom, procfs data, CPU jitter, and
/// CPU hardware RNG through BLAKE2b-256 to seed a ChaCha20Rng.
/// All intermediate buffers are zeroized after use.
/// For requests > 1 MiB, the CSPRNG is reseeded with fresh entropy at each 1 MiB boundary.
pub fn generate_fallback(count: usize, config: &CpuRngConfig) -> Result<Vec<u8>, Error> {
    // Seed 32 bytes from getrandom/urandom
    let mut urandom_seed = [0u8; 32];
    read_system_random(&mut urandom_seed)?;
    memlock::lock_and_protect(&urandom_seed);

    // Read procfs entropy sources (raw bytes, no parsing)
    let mut interrupts = procfs::read_interrupts();
    let mut stat = procfs::read_stat();
    let mut diskstats = procfs::read_diskstats();

    // Collect 64 CPU jitter timing samples
    let mut jitter_data = jitter::collect_jitter_samples(64);

    // Collect CPU hardware entropy (best-effort, empty Vec if unavailable)
    let mut cpu_entropy =
        cpurng::collect_cpu_entropy_best_effort(config.fallback_mix_bytes, config);

    // Mix all inputs through BLAKE2b-256 with domain separation
    let inputs: &[(&str, &[u8])] = &[
        ("urandom", &urandom_seed),
        ("interrupts", &interrupts),
        ("stat", &stat),
        ("diskstats", &diskstats),
        ("jitter", &jitter_data),
        ("cpu-rng", &cpu_entropy),
    ];
    let mut seed = match config.mixer_mode {
        MixerMode::Hkdf => {
            let hkdf_out = mixer::mix_entropy_hkdf(inputs, 32);
            let mut s = [0u8; 32];
            s.copy_from_slice(&hkdf_out);
            s
        }
        MixerMode::Blake2b => mixer::mix_entropy(inputs),
    };
    memlock::lock_and_protect(&seed);

    // Use reseeding CSPRNG for large requests (reseed every 1 MiB)
    let output = if count > csprng::RESEED_INTERVAL {
        let cfg = config.clone();
        csprng::generate_reseeding(seed, count, csprng::RESEED_INTERVAL, || {
            collect_fresh_seed(&cfg)
        })
    } else {
        csprng::generate(seed, count)
    };

    // Zeroize all intermediate buffers
    memlock::munlock_slice(&urandom_seed);
    cpurng::zeroize_bytes(&mut urandom_seed);
    cpurng::zeroize_vec(&mut interrupts);
    cpurng::zeroize_vec(&mut stat);
    cpurng::zeroize_vec(&mut diskstats);
    cpurng::zeroize_vec(&mut jitter_data);
    cpurng::zeroize_vec(&mut cpu_entropy);
    memlock::munlock_slice(&seed);
    cpurng::zeroize_bytes(&mut seed);

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_fallback_basic() {
        let config = CpuRngConfig::default();
        let result = generate_fallback(32, &config).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_generate_fallback_various_sizes() {
        let config = CpuRngConfig::default();
        for &size in &[1, 16, 64, 256, 1024] {
            let result = generate_fallback(size, &config).unwrap();
            assert_eq!(result.len(), size);
        }
    }

    #[test]
    fn test_generate_fallback_not_constant() {
        let config = CpuRngConfig::default();
        let a = generate_fallback(32, &config).unwrap();
        let b = generate_fallback(32, &config).unwrap();
        // Extremely unlikely to be the same
        assert_ne!(a, b);
    }

    #[test]
    fn test_generate_fallback_hkdf_mode() {
        let config = CpuRngConfig {
            mixer_mode: MixerMode::Hkdf,
            ..Default::default()
        };
        let result = generate_fallback(64, &config).unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_generate_fallback_zero_bytes() {
        let config = CpuRngConfig::default();
        let result = generate_fallback(0, &config).unwrap();
        assert!(result.is_empty());
    }
}
