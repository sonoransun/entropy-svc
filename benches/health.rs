//! Criterion microbenchmark for the SP 800-90B health tester (RCT + APT)
//! per 64-bit sample.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use mixrand::health::HealthTester;

fn bench_feed_rct_apt(c: &mut Criterion) {
    let mut group = c.benchmark_group("health_tester_feed");
    group.throughput(Throughput::Elements(1));

    group.bench_function("new_sample_each", |b| {
        let mut ht = HealthTester::new(4.0);
        let mut x: u64 = 0;
        b.iter(|| {
            x = x.wrapping_add(1);
            let _ = ht.feed(black_box(x));
        });
    });

    group.bench_function("repeating_sample", |b| {
        let mut ht = HealthTester::new(4.0);
        b.iter(|| {
            let _ = ht.feed(black_box(0));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_feed_rct_apt);
criterion_main!(benches);
