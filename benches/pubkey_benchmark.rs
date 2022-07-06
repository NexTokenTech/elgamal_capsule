use criterion::{criterion_group, criterion_main, Criterion};
use elgamal_trex::{
    elgamal::{generate_pub_key,RawPublicKey,RawKey,PublicKey},
    KeyGenerator
};
use rug::rand::RandState;
use rug::Integer;
use std::time::Duration;
use sp_core::U256;

fn pubkey_gen_2_196_benchmark(rand:&mut RandState) {
    let raw_key = RawPublicKey {
        p: U256::from(1i32),
        g: U256::from(1i32),
        h: U256::from(1i32),
        bit_length: 1u32,
    };
    for i in 2..196{
        raw_key.yield_pubkey(rand,i);
    }
}

fn pubkey_gen_benchmark(bit_length: u32) {
    let mut rand = RandState::new_mersenne_twister();
    for i in 1..10 {
        let seed = Integer::from(i as i32);
        generate_pub_key(&mut rand, bit_length,seed);
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sample-size-example");
    group
        .significance_level(0.1)
        .measurement_time(Duration::from_secs(110));
    group.bench_function("pubkey gen small x10", |b| {
        b.iter(|| pubkey_gen_benchmark(64))
    });
    group.bench_function("pubkey gen middle x10", |b| {
        b.iter(|| pubkey_gen_benchmark(128))
    });
    group.bench_function("pubkey gen big x10", |b| {
        b.iter(|| pubkey_gen_benchmark(196))
    });
    group.bench_function("pubkey gen 2-196", |b| {
        let mut rand = RandState::new_mersenne_twister();
        b.iter(move || pubkey_gen_2_196_benchmark(&mut rand))
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
