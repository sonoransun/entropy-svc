//! Criterion microbenchmarks for the ChaCha20 CSPRNG: with and without
//! reseeding, across small and large output sizes.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use mixrand::csprng::{generate, generate_reseeding, RESEED_INTERVAL};

fn bench_generate_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("csprng_generate");
    for &size in &[32usize, 1024, 65_536, 1_048_576] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{}B", size), |b| {
            let seed = [0xA5u8; 32];
            b.iter(|| {
                let out = generate(black_box(seed), black_box(size));
                black_box(out);
            });
        });
    }
    group.finish();
}

fn bench_generate_reseeding(c: &mut Criterion) {
    let mut group = c.benchmark_group("csprng_generate_reseeding");
    for &size in &[RESEED_INTERVAL, RESEED_INTERVAL + 100, RESEED_INTERVAL * 2] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{}B", size), |b| {
            let seed = [0xC3u8; 32];
            b.iter(|| {
                let out =
                    generate_reseeding(black_box(seed), black_box(size), RESEED_INTERVAL, || {
                        [0x5Au8; 32]
                    });
                black_box(out);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_generate_sizes, bench_generate_reseeding);
criterion_main!(benches);
