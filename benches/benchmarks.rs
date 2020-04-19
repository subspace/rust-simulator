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
        let seed = crypto::random_bytes_16();
        let id = crypto::random_bytes_16();
        let base_aes_iterations = 3_000_000;
        let prove_keys = crypto::expand_keys_aes_128_enc(&id);

        let mut group = c.benchmark_group("Proof-of-time");
        group.sample_size(10);

        let benchmark_parameters = [1usize, 10, 100]
            .iter()
            .map(|&n| n * base_aes_iterations)
            .flat_map(|aes_iterations| {
                [4, 16, 64]
                    .iter()
                    .map(move |&verifier_parallelism| (aes_iterations, verifier_parallelism))
            });
        for (aes_iterations, verifier_parallelism) in benchmark_parameters {
            group.bench_function(
                format!(
                    "Prove-{}-iterations-{}-parallelism",
                    aes_iterations, verifier_parallelism
                ),
                |b| {
                    b.iter(|| {
                        black_box(crypto::prove(
                            &seed,
                            &prove_keys,
                            aes_iterations,
                            verifier_parallelism,
                        ))
                    })
                },
            );

            let proof = crypto::prove(&seed, &prove_keys, aes_iterations, verifier_parallelism);
            let verify_keys = crypto::expand_keys_aes_128_dec(&id);

            group.bench_function(
                format!(
                    "Verify-pipelined-{}-iterations-{}-parallelism",
                    aes_iterations, verifier_parallelism
                ),
                |b| {
                    b.iter(|| {
                        black_box(crypto::verify_pipelined(
                            &proof,
                            &seed,
                            &verify_keys,
                            aes_iterations,
                        ))
                    })
                },
            );

            group.bench_function(
                format!(
                    "Verify-pipelined-parallel-{}-iterations-{}-parallelism",
                    aes_iterations, verifier_parallelism
                ),
                |b| {
                    b.iter(|| {
                        black_box(crypto::verify_pipelined_parallel(
                            &proof,
                            &seed,
                            &verify_keys,
                            aes_iterations,
                        ))
                    })
                },
            );
        }

        group.finish();
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
