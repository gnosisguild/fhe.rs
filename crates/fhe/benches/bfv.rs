// Expect indexing in benchmarks for convenience
#![expect(missing_docs, reason = "examples/benches/tests omit docs by design")]
#![expect(
    clippy::indexing_slicing,
    reason = "performance or example code relies on validated indices"
)]

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use fhe::bfv::{
    BfvParameters, Ciphertext, Encoding, EvaluationKeyBuilder, Multiplicator, Plaintext, PublicKey,
    RelinearizationKey, SecretKey,
};
use fhe_math::rns::{RnsContext, ScalingFactor};
use fhe_math::zq::primes::generate_prime;
use fhe_traits::{FheEncoder, FheEncrypter};
use itertools::Itertools;
use num_bigint::BigUint;
use rand::rng;
use std::hint::black_box;
use std::time::Duration;

pub fn bfv_benchmark(c: &mut Criterion) {
    let mut rng = rng();
    let mut group = c.benchmark_group("bfv");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(600));
    group.measurement_time(Duration::from_millis(1000));

    for params in BfvParameters::default_parameters_128(20).unwrap() {
        let sk = SecretKey::random(&params, &mut rng);
        let ek = if params.moduli().len() > 1 {
            Some(
                EvaluationKeyBuilder::new(&sk)
                    .unwrap()
                    .enable_inner_sum()
                    .unwrap()
                    .enable_column_rotation(1)
                    .unwrap()
                    .enable_expansion(params.degree().ilog2() as usize)
                    .unwrap()
                    .build(&mut rng)
                    .unwrap(),
            )
        } else {
            None
        };

        let rk = if params.moduli().len() > 1 {
            Some(RelinearizationKey::new(&sk, &mut rng).unwrap())
        } else {
            None
        };

        let pt1 =
            Plaintext::try_encode(&(1..16u64).collect_vec(), Encoding::simd(), &params).unwrap();
        let pt2 =
            Plaintext::try_encode(&(3..39u64).collect_vec(), Encoding::simd(), &params).unwrap();
        let c1: Ciphertext = sk.try_encrypt(&pt1, &mut rng).unwrap();
        let c2: Ciphertext = sk.try_encrypt(&pt2, &mut rng).unwrap();

        let q = params.moduli_sizes().iter().sum::<usize>();

        group.bench_function(
            BenchmarkId::new("keygen_sk", format!("n={}/log(q)={}", params.degree(), q)),
            |b| {
                b.iter(|| SecretKey::random(&params, &mut rng));
            },
        );

        group.bench_function(
            BenchmarkId::new("keygen_pk", format!("n={}/log(q)={}", params.degree(), q)),
            |b| {
                b.iter(|| PublicKey::new(&sk, &mut rng));
            },
        );

        group.bench_function(
            BenchmarkId::new("keygen_rk", format!("n={}/log(q)={}", params.degree(), q)),
            |b| {
                b.iter(|| RelinearizationKey::new(&sk, &mut rng));
            },
        );

        group.bench_function(
            BenchmarkId::new("encode_poly", format!("n={}/log(q)={}", params.degree(), q)),
            |b| {
                b.iter(|| {
                    Plaintext::try_encode(&(1..16u64).collect_vec(), Encoding::poly(), &params)
                });
            },
        );

        group.bench_function(
            BenchmarkId::new("encode_simd", format!("n={}/log(q)={}", params.degree(), q)),
            |b| {
                b.iter(|| {
                    Plaintext::try_encode(&(1..16u64).collect_vec(), Encoding::simd(), &params)
                });
            },
        );

        group.bench_function(
            BenchmarkId::new("encrypt_sk", format!("n={}/log(q)={}", params.degree(), q)),
            |b| {
                b.iter(|| {
                    let ciphertext: Ciphertext = sk.try_encrypt(&pt1, &mut rng).unwrap();
                    black_box(ciphertext)
                });
            },
        );

        group.bench_function(
            BenchmarkId::new("add_ct", format!("n={}/log(q)={}", params.degree(), q)),
            |b| {
                b.iter(|| black_box(&c1 + &c2));
            },
        );

        group.bench_function(
            BenchmarkId::new(
                "add_assign_ct",
                format!("n={}/log(q)={}", params.degree(), q),
            ),
            |b| {
                b.iter_batched(
                    || c1.clone(),
                    |mut left| {
                        left += &c2;
                        black_box(left)
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_function(
            BenchmarkId::new("add_pt", format!("n={}/log(q)={}", params.degree(), q)),
            |b| {
                b.iter(|| black_box(&c1 + &pt2));
            },
        );

        group.bench_function(
            BenchmarkId::new(
                "add_assign_pt",
                format!("n={}/log(q)={}", params.degree(), q),
            ),
            |b| {
                b.iter_batched(
                    || c1.clone(),
                    |mut left| {
                        left += &pt2;
                        black_box(left)
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_function(
            BenchmarkId::new("sub_ct", format!("n={}/log(q)={}", params.degree(), q)),
            |b| {
                b.iter(|| black_box(&c1 - &c2));
            },
        );

        group.bench_function(
            BenchmarkId::new(
                "sub_assign_ct",
                format!("n={}/log(q)={}", params.degree(), q),
            ),
            |b| {
                b.iter_batched(
                    || c1.clone(),
                    |mut left| {
                        left -= &c2;
                        black_box(left)
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_function(
            BenchmarkId::new("sub_pt", format!("n={}/log(q)={}", params.degree(), q)),
            |b| {
                b.iter(|| black_box(&c1 - &pt2));
            },
        );

        group.bench_function(
            BenchmarkId::new(
                "sub_assign_pt",
                format!("n={}/log(q)={}", params.degree(), q),
            ),
            |b| {
                b.iter_batched(
                    || c1.clone(),
                    |mut left| {
                        left -= &pt2;
                        black_box(left)
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_function(
            BenchmarkId::new("neg", format!("n={}/log(q)={}", params.degree(), q)),
            |b| {
                b.iter(|| black_box(-&c2));
            },
        );

        let c3 = &c1 * &c1;
        if let Some(rk) = rk.as_ref() {
            group.bench_function(
                BenchmarkId::new("relinearize", format!("n={}/log(q)={}", params.degree(), q)),
                |b| {
                    b.iter_batched(
                        || c3.clone(),
                        |mut product| {
                            rk.relinearizes(&mut product).unwrap();
                            black_box(product)
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }

        if let Some(ek) = ek {
            group.bench_function(
                BenchmarkId::new("rotate_rows", format!("n={}/log(q)={}", params.degree(), q)),
                |b| {
                    b.iter(|| black_box(ek.rotates_rows(&c1).unwrap()));
                },
            );

            group.bench_function(
                BenchmarkId::new(
                    "rotate_columns",
                    format!("n={}/log(q)={}", params.degree(), q),
                ),
                |b| {
                    b.iter(|| black_box(ek.rotates_columns_by(&c1, 1).unwrap()));
                },
            );

            group.bench_function(
                BenchmarkId::new("inner_sum", format!("n={}/log(q)={}", params.degree(), q)),
                |b| {
                    b.iter(|| black_box(ek.computes_inner_sum(&c1).unwrap()));
                },
            );

            for i in 1..=params.degree().ilog2() {
                if params.degree() > 2048 && i > 4 {
                    continue; // Skip slow benchmarks
                }
                group.bench_function(
                    BenchmarkId::new(
                        format!("expand_{i}"),
                        format!("n={}/log(q)={}", params.degree(), q),
                    ),
                    |b| {
                        b.iter(|| black_box(ek.expands(&c1, 1 << i).unwrap()));
                    },
                );
            }
        }

        group.bench_function(
            BenchmarkId::new("mul", format!("n={}/log(q)={}", params.degree(), q)),
            |b| {
                b.iter(|| black_box(&c1 * &c2));
            },
        );

        group.bench_function(
            BenchmarkId::new("square", format!("n={}/log(q)={}", params.degree(), q)),
            |b| {
                b.iter(|| black_box(&c1 * &c1));
            },
        );

        if let Some(rk) = rk.as_ref() {
            group.bench_function(
                BenchmarkId::new(
                    "mul_then_relinearize",
                    format!("n={}/log(q)={}", params.degree(), q),
                ),
                |b| {
                    b.iter(|| {
                        let mut product = &c1 * &c2;
                        rk.relinearizes(&mut product).unwrap();
                        black_box(product)
                    });
                },
            );

            // Default multiplication method
            let multiplicator = Multiplicator::default(rk).unwrap();

            group.bench_function(
                BenchmarkId::new(
                    "mul_and_relin",
                    format!("n={}/log(q)={}", params.degree(), q),
                ),
                |b| {
                    b.iter(|| black_box(multiplicator.multiply(&c1, &c2).unwrap()));
                },
            );

            // Second multiplication option.
            let nmoduli = q.div_ceil(62);
            let mut extended_basis = params.moduli().to_vec();
            let mut upper_bound = u64::MAX >> 2;
            while extended_basis.len() != nmoduli + params.moduli().len() {
                upper_bound = generate_prime(62, 2 * params.degree() as u64, upper_bound).unwrap();
                if !extended_basis.contains(&upper_bound) {
                    extended_basis.push(upper_bound)
                }
            }
            let rns_q = RnsContext::new(&extended_basis[..params.moduli().len()]).unwrap();
            let rns_p = RnsContext::new(&extended_basis[params.moduli().len()..]).unwrap();
            let mut multiplicator = Multiplicator::new(
                ScalingFactor::one(),
                ScalingFactor::new(rns_p.modulus(), rns_q.modulus()).unwrap(),
                &extended_basis,
                ScalingFactor::new(&BigUint::from(params.plaintext()), rns_p.modulus()).unwrap(),
                &params,
            )
            .unwrap();
            assert!(multiplicator.enable_relinearization(rk).is_ok());
            group.bench_function(
                BenchmarkId::new(
                    "mul_and_relin_2",
                    format!("n={}/log(q)={}", params.degree(), q),
                ),
                |b| {
                    b.iter(|| black_box(multiplicator.multiply(&c1, &c2).unwrap()));
                },
            );
        }
    }

    group.finish();
}

criterion_group!(bfv, bfv_benchmark);
criterion_main!(bfv);
