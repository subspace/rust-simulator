use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use rust_simulator::aes_soft;
use rust_simulator::codec::Codec;
use rust_simulator::crypto;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut codec = Codec::new().unwrap();

    let id = crypto::random_bytes_32();
    let mut keys = [0u32; 44];
    aes_soft::setkey_enc_k128(&id, &mut keys);
    let piece = crypto::random_bytes_4096();
    let iv = vec![13u128];

    let iv = crypto::random_bytes_16();
    c.bench_function("PoR-128-encode-single", |b| {
        b.iter(|| {
            codec.por_128_enc(&piece, &iv, &keys).unwrap();
        })
    });

    group.bench_function("PoR-128-encode-single", |b| {
        b.iter(|| {
            codec.por_128_enc(&pieces, &ivs, &keys).unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
