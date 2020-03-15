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

    let mut group = c.benchmark_group("GPU benchmark");
    group.sample_size(10);

    group.bench_function("PoR-128-encode-single", |b| {
        b.iter(|| {
            codec.por_128_enc(&piece, &iv, &keys).unwrap();
        })
    });

    let pieces: Vec<u8> = (0..100).flat_map(|_| piece.to_vec()).collect();
    let ivs = vec![13u128; 100];

    group.bench_function("PoR-128-encode-100", |b| {
        b.iter(|| {
            codec.por_128_enc(&pieces, &ivs, &keys).unwrap();
        })
    });

    let mut keys = [0u32; 44];
    aes_soft::setkey_dec_k128(&id, &mut keys);
    let encoding = crypto::por_encode_single_block_software(&piece, &id, iv[0] as usize).to_vec();

    group.bench_function("PoR-128-decode-single", |b| {
        b.iter(|| {
            codec.por_128_dec(&encoding, &iv, &keys).unwrap();
        })
    });

    let encodings: Vec<u8> = (0..100).flat_map(|_| encoding.to_vec()).collect();

    group.bench_function("PoR-128-decode-100", |b| {
        b.iter(|| {
            codec.por_128_dec(&encodings, &ivs, &keys).unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
