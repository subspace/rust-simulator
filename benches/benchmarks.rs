use criterion::black_box;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use rust_simulator::aes_soft;
use rust_simulator::codec::Codec;
use rust_simulator::crypto;

pub fn criterion_benchmark(c: &mut Criterion) {
    {
        let mut codec = Codec::new().unwrap();

        let id = crypto::random_bytes_32();
        let mut keys = [0u32; 44];
        aes_soft::setkey_enc_k128(&id, &mut keys);
        let piece = crypto::random_bytes_4096();
        let iv = vec![13u128];

        let mut group = c.benchmark_group("GPU");
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
        let encoding =
            crypto::por_encode_single_block_software(&piece, &id, iv[0] as usize).to_vec();

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
    {
        let id = crypto::random_bytes_16();
        let keys = crypto::expand_keys_aes_128_enc(&id);
        let piece = crypto::random_bytes_4096();
        let iv = crypto::random_bytes_16();

        let mut group = c.benchmark_group("CPU");
        group.sample_size(100);

        let aes_iterations = 256;
        let breadth_iterations = 16;

        group.bench_function("PoR-128-encode-simple-internal", |b| {
            b.iter(|| {
                let mut piece = piece;
                black_box(crypto::por_encode_simple_internal(
                    &mut piece,
                    &keys,
                    &iv,
                    aes_iterations,
                ))
            })
        });

        group.bench_function("PoR-128-encode-pipelined-internal", |b| {
            let mut pieces = [piece; 4];
            let ivs = [&iv; 4];
            b.iter(|| {
                black_box(crypto::por_encode_pipelined_internal(
                    &mut pieces,
                    &keys,
                    ivs,
                    aes_iterations,
                ))
            })
        });

        // Here we use incorrect key, but performance should be identical
        group.bench_function("PoR-128-decode-pipelined-internal", |b| {
            let mut piece = piece;
            b.iter(|| {
                black_box(crypto::por_decode_pipelined_internal(
                    &mut piece,
                    &keys,
                    &iv,
                    aes_iterations,
                ))
            })
        });

        group.bench_function("PoR-128-encode-simple", |b| {
            b.iter(|| {
                let mut piece = piece;
                black_box(crypto::por_encode_simple(
                    &mut piece,
                    &keys,
                    &iv,
                    aes_iterations,
                    breadth_iterations,
                ))
            })
        });

        group.bench_function("PoR-128-encode-pipelined", |b| {
            let mut pieces = [piece; 4];
            let ivs = [&iv; 4];
            b.iter(|| {
                black_box(crypto::por_encode_pipelined(
                    &mut pieces,
                    &keys,
                    ivs,
                    aes_iterations,
                    breadth_iterations,
                ))
            })
        });

        // Here we use incorrect key, but performance should be identical
        group.bench_function("PoR-128-decode-pipelined", |b| {
            let mut piece = piece;
            b.iter(|| {
                black_box(crypto::por_decode_pipelined(
                    &mut piece,
                    &keys,
                    &iv,
                    aes_iterations,
                    breadth_iterations,
                ))
            })
        });

        group.finish();
    }
    {
        use crypto::memory_bound;
        use rust_simulator::Piece;

        let piece = crypto::random_bytes_4096();
        let iv = [1, 2, 3];
        let sbox = memory_bound::SBoxDirect::new();
        let sbox_inverse = memory_bound::SBoxInverse::new();

        {
            let mut group = c.benchmark_group("Memory-bound");
            group.sample_size(100);

            for &iterations in &[1_usize, 100, 3000] {
                group.bench_function(format!("Prove-{}-iterations", iterations), |b| {
                    b.iter(|| {
                        let mut piece = piece;
                        black_box(memory_bound::por_encode_simple(
                            &mut piece, iv, iterations, &sbox,
                        ))
                    })
                });

                group.bench_function(format!("Verify-{}-iterations", iterations), |b| {
                    b.iter(|| {
                        let mut piece = piece;
                        black_box(memory_bound::por_decode_simple(
                            &mut piece,
                            iv,
                            iterations,
                            &sbox_inverse,
                        ))
                    })
                });
            }

            group.finish();
        }

        {
            let pieces: Vec<Piece> = (0..2560_usize).map(|_| piece).collect();
            let mut group = c.benchmark_group("Memory-bound-parallel");
            group.sample_size(10);

            for &iterations in &[1_usize /*, 100, 3000*/] {
                for &concurrency in &[8, 16, 32, 64] {
                    group.bench_function(
                        format!(
                            "Prove-{}-iterations-{}-concurrency",
                            iterations, concurrency
                        ),
                        |b| {
                            b.iter(|| {
                                let mut pieces = pieces.clone();
                                black_box(memory_bound::por_encode_simple_parallel(
                                    &mut pieces,
                                    iv,
                                    iterations,
                                    &sbox,
                                    concurrency,
                                ))
                            })
                        },
                    );

                    group.bench_function(
                        format!(
                            "Verify-{}-iterations-{}-concurrency",
                            iterations, concurrency
                        ),
                        |b| {
                            b.iter(|| {
                                let mut pieces = pieces.clone();
                                black_box(memory_bound::por_decode_simple_parallel(
                                    &mut pieces,
                                    iv,
                                    iterations,
                                    &sbox_inverse,
                                    concurrency,
                                ))
                            })
                        },
                    );
                }
            }

            group.finish();
        }
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
