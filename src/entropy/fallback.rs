use std::fs::File;
use std::io::Read;

use crate::config::CpuRngConfig;
use crate::csprng;
use crate::error::Error;
use crate::mixer;

use super::cpurng;
use super::jitter;
use super::procfs;

/// Fallback entropy source: mixes /dev/urandom, procfs data, CPU jitter, and
/// CPU hardware RNG through BLAKE2b-256 to seed a ChaCha20Rng.
/// All intermediate buffers are zeroized after use.
pub fn generate_fallback(count: usize, config: &CpuRngConfig) -> Result<Vec<u8>, Error> {
    // Seed 32 bytes from /dev/urandom
    let mut urandom_seed = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut urandom_seed)?;

    // Read procfs entropy sources (raw bytes, no parsing)
    let mut interrupts = procfs::read_interrupts();
    let mut stat = procfs::read_stat();
    let mut diskstats = procfs::read_diskstats();

    // Collect 64 CPU jitter timing samples
    let mut jitter = jitter::collect_jitter_samples(64);

    // Collect CPU hardware entropy (best-effort, empty Vec if unavailable)
    let mut cpu_entropy =
        cpurng::collect_cpu_entropy_best_effort(config.fallback_mix_bytes, config);

    // Mix all inputs through BLAKE2b-256 with domain separation
    let mut seed = mixer::mix_entropy(&[
        ("urandom", &urandom_seed),
        ("interrupts", &interrupts),
        ("stat", &stat),
        ("diskstats", &diskstats),
        ("jitter", &jitter),
        ("cpu-rng", &cpu_entropy),
    ]);

    // Seed ChaCha20Rng and generate output bytes
    let output = csprng::generate(seed, count);

    // Zeroize all intermediate buffers
    cpurng::zeroize_bytes(&mut urandom_seed);
    cpurng::zeroize_vec(&mut interrupts);
    cpurng::zeroize_vec(&mut stat);
    cpurng::zeroize_vec(&mut diskstats);
    cpurng::zeroize_vec(&mut jitter);
    cpurng::zeroize_vec(&mut cpu_entropy);
    cpurng::zeroize_bytes(&mut seed);

    Ok(output)
}
