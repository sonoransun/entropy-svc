//! Criterion microbenchmarks for the mixer: BLAKE2b single-pass vs HKDF
//! extract-then-expand across small, medium, and large input sizes.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use mixrand::mixer::{mix_entropy, mix_entropy_hkdf};

fn bench_blake2b_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("mix_entropy_blake2b");
    for &size in &[32usize, 256, 1024, 65_536, 1_048_576] {
        let data = vec![0xA5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{}B", size), |b| {
            b.iter(|| {
                let out = mix_entropy(black_box(&[("src", &data)]));
                black_box(out);
            });
        });
    }
    group.finish();
}

fn bench_hkdf_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("mix_entropy_hkdf");
    let input = vec![0xA5u8; 1024];
    for &out_len in &[32usize, 64, 256, 1024, 8192] {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_function(format!("out_{}B", out_len), |b| {
            b.iter(|| {
                let out = mix_entropy_hkdf(black_box(&[("src", &input)]), out_len);
                black_box(out);
            });
        });
    }
    group.finish();
}

fn bench_mix_entropy_many_inputs(c: &mut Criterion) {
    let mut group = c.benchmark_group("mix_entropy_many_inputs");
    for &n in &[1usize, 4, 16, 64] {
        let inputs: Vec<(&str, Vec<u8>)> = (0..n)
            .map(|i| {
                let label = if i == 0 { "hwrng" } else { "source" };
                (label, vec![0x42u8; 64])
            })
            .collect();
        let refs: Vec<(&str, &[u8])> = inputs.iter().map(|(s, v)| (*s, v.as_slice())).collect();
        group.bench_function(format!("{}_inputs", n), |b| {
            b.iter(|| {
                let out = mix_entropy(black_box(&refs));
                black_box(out);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_blake2b_sizes,
    bench_hkdf_sizes,
    bench_mix_entropy_many_inputs
);
criterion_main!(benches);
