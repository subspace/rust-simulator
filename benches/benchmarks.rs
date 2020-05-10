use criterion::black_box;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use rust_simulator::crypto;

pub fn criterion_benchmark(c: &mut Criterion) {
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
