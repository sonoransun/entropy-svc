//! End-to-end entropy-generation pipeline benchmark.
//!
//! Drives the full mix+CSPRNG path via a deterministic `MockEntropySource`
//! (gated behind the `testing` feature). The mock bypasses real hardware
//! sources so wall-clock numbers capture mixer + csprng overhead only.
//!
//! Build with: `cargo bench --features testing --bench full_pipeline`.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use mixrand::csprng::generate;
use mixrand::mixer::{mix_entropy, mix_entropy_hkdf};

fn bench_mix_then_csprng(c: &mut Criterion) {
    // Simulate: caller gathers entropy from 3 sources, feeds to mix_entropy,
    // then generates N output bytes via ChaCha20.
    let inputs: Vec<(&str, Vec<u8>)> = vec![
        ("hwrng", vec![0xA5u8; 32]),
        ("cpurng", vec![0x19u8; 32]),
        ("jitter", vec![0x77u8; 32]),
    ];
    let refs: Vec<(&str, &[u8])> = inputs.iter().map(|(s, v)| (*s, v.as_slice())).collect();

    let mut group = c.benchmark_group("full_pipeline_blake2b_to_csprng");
    for &count in &[32usize, 1024, 65_536, 1_048_576] {
        group.throughput(Throughput::Bytes(count as u64));
        group.bench_function(format!("{}B", count), |b| {
            b.iter(|| {
                let seed = mix_entropy(black_box(&refs));
                let out = generate(seed, count);
                black_box(out);
            });
        });
    }
    group.finish();
}

fn bench_hkdf_to_csprng(c: &mut Criterion) {
    let inputs: Vec<(&str, Vec<u8>)> =
        vec![("hwrng", vec![0xA5u8; 64]), ("cpurng", vec![0x19u8; 64])];
    let refs: Vec<(&str, &[u8])> = inputs.iter().map(|(s, v)| (*s, v.as_slice())).collect();

    let mut group = c.benchmark_group("full_pipeline_hkdf_to_csprng");
    for &count in &[32usize, 1024, 65_536] {
        group.throughput(Throughput::Bytes(count as u64));
        group.bench_function(format!("{}B", count), |b| {
            b.iter(|| {
                let prk = mix_entropy_hkdf(black_box(&refs), 32);
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&prk);
                let out = generate(seed, count);
                black_box(out);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_mix_then_csprng, bench_hkdf_to_csprng);
criterion_main!(benches);
