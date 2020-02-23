use criterion::{criterion_group, criterion_main, Criterion};
use rust_simulator::aes_soft;
use rust_simulator::codec::Codec;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut aes_256_open_cl = Codec::new().unwrap();

    let key = vec![
        210, 51, 245, 243, 109, 154, 58, 127, 99, 229, 195, 34, 103, 170, 183, 16, 61, 83, 196,
        156, 124, 20, 16, 161, 3, 25, 180, 170, 26, 19, 163, 12,
    ];
    let mut keys = [0u32; 60];
    aes_soft::setkey_enc_k256(&key, &mut keys);
    let block = vec![
        206, 213, 196, 136, 255, 138, 90, 170, 236, 76, 241, 48, 122, 18, 42, 189,
    ];

    let mut group = c.benchmark_group("GPU benchmark");
    group.sample_size(10);

    group.bench_function("encode-single", |b| {
        b.iter(|| {
            aes_256_open_cl
                .aes_256_enc_iterations(&block, &keys, 1)
                .unwrap();
        })
    });

    group.bench_function("encode-66k", |b| {
        b.iter(|| {
            aes_256_open_cl
                .aes_256_enc_iterations(&block, &keys, 66000)
                .unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
