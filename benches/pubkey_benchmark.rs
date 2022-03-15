use criterion::{criterion_group, criterion_main, Criterion};
use elgamal_capsule::elgamal::generate_pub_key;
use rug::rand::RandState;
use rug::Integer;
use std::time::Duration;

fn pubkey_gen_benchmark(bit_length: u32) {
    let mut rand = RandState::new_mersenne_twister();
    for i in 1..10 {
        let seed = Integer::from(i as i32);
        rand.seed(&seed);
        generate_pub_key(&mut rand, bit_length);
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sample-size-example");
    group
        .significance_level(0.1)
        .measurement_time(Duration::from_secs(20));
    group.bench_function("pubkey gen small x10", |b| {
        b.iter(|| pubkey_gen_benchmark(64))
    });
    group.bench_function("pubkey gen middle x10", |b| {
        b.iter(|| pubkey_gen_benchmark(128))
    });
    group.bench_function("pubkey gen big x10", |b| {
        b.iter(|| pubkey_gen_benchmark(196))
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
