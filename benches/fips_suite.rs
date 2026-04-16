//! Regression benches for the FIPS 140-2 statistical test suite.
//!
//! Tracks throughput of each individual test and the full suite over a
//! 2500-byte (20000-bit) sample — the fixed input size spec'd by FIPS
//! 140-2 for these tests. A perf regression here usually points at an
//! inefficiency in bit-iteration or counter logic within `src/stats.rs`.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use mixrand::stats::{fips_long_runs, fips_monobit, fips_poker, fips_runs, fips_suite};

fn sample_bytes() -> [u8; 2500] {
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let mut data = [0u8; 2500];
    rng.fill_bytes(&mut data);
    data
}

fn bench_fips_individual(c: &mut Criterion) {
    let data = sample_bytes();
    let mut group = c.benchmark_group("fips_140_2");
    group.throughput(Throughput::Bytes(2500));
    group.bench_function("monobit", |b| {
        b.iter(|| {
            let r = fips_monobit(black_box(&data));
            black_box(r);
        });
    });
    group.bench_function("poker", |b| {
        b.iter(|| {
            let r = fips_poker(black_box(&data));
            black_box(r);
        });
    });
    group.bench_function("runs", |b| {
        b.iter(|| {
            let r = fips_runs(black_box(&data));
            black_box(r);
        });
    });
    group.bench_function("long_runs", |b| {
        b.iter(|| {
            let r = fips_long_runs(black_box(&data));
            black_box(r);
        });
    });
    group.finish();
}

fn bench_fips_full_suite(c: &mut Criterion) {
    let data = sample_bytes();
    let mut group = c.benchmark_group("fips_140_2_suite");
    group.throughput(Throughput::Bytes(2500));
    group.bench_function("full_suite", |b| {
        b.iter(|| {
            let r = fips_suite(black_box(&data));
            black_box(r);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_fips_individual, bench_fips_full_suite);
criterion_main!(benches);
