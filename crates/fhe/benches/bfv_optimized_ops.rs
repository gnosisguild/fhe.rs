// Expect indexing in benchmarks for convenience
#![expect(missing_docs, reason = "examples/benches/tests omit docs by design")]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, SecretKey, dot_product_scalar};
use fhe_traits::{FheEncoder, FheEncrypter};
use itertools::{Itertools, izip};
use rand::rng;
use std::hint::black_box;
use std::time::Duration;

pub fn bfv_benchmark(c: &mut Criterion) {
    let mut rng = rng();
    let mut group = c.benchmark_group("bfv_optimized_ops");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(1));

    // Keep CI and local smoke runs from allocating the full largest benchmark
    // matrix while retaining the complete suite for normal benchmark runs.
    let smoke = std::env::var_os("FHE_BENCH_SMOKE").is_some();
    let sizes: &[usize] = if smoke { &[10] } else { &[10, 128, 1000] };

    for params in BfvParameters::default_parameters_128(20)
        .unwrap()
        .take(if smoke { 1 } else { usize::MAX })
    {
        for &size in sizes {
            let sk = SecretKey::random(&params, &mut rng);
            let ct_vec = (0..size)
                .map(|i| {
                    let pt = Plaintext::try_encode(
                        &(0..16).map(|j| ((i + j) % 100) as u64).collect_vec(),
                        Encoding::poly(),
                        &params,
                    )
                    .unwrap();
                    sk.try_encrypt(&pt, &mut rng).unwrap()
                })
                .collect_vec();
            let pt_vec = (0..size)
                .map(|i| {
                    Plaintext::try_encode(
                        &(0..36).map(|j| ((i + 3 * j) % 100) as u64).collect_vec(),
                        Encoding::poly(),
                        &params,
                    )
                    .unwrap()
                })
                .collect_vec();

            // Both benchmarks compute the same dot product over the same
            // nonempty plaintext vectors. The old naive case accumulated in
            // a ciphertext shared across iterations (and even benchmark
            // registrations), so its timed workload drifted on every run.
            let naive = || {
                let mut sum = Ciphertext::zero(&params);
                for (ct, pt) in izip!(&ct_vec, &pt_vec) {
                    sum += &(ct * pt);
                }
                sum
            };
            assert_eq!(
                naive(),
                dot_product_scalar(ct_vec.iter(), pt_vec.iter()).unwrap(),
                "naive and optimized benchmark workloads must agree"
            );

            group.bench_function(
                BenchmarkId::new(
                    "dot_product/naive",
                    format!(
                        "size={}/degree={}/logq={}",
                        size,
                        params.degree(),
                        params.moduli_sizes().iter().sum::<usize>()
                    ),
                ),
                |b| {
                    b.iter(|| black_box(naive()));
                },
            );

            group.bench_function(
                BenchmarkId::new(
                    "dot_product/opt",
                    format!(
                        "size={}/degree={}/logq={}",
                        size,
                        params.degree(),
                        params.moduli_sizes().iter().sum::<usize>()
                    ),
                ),
                |b| {
                    b.iter(|| black_box(dot_product_scalar(ct_vec.iter(), pt_vec.iter()).unwrap()));
                },
            );
        }
    }

    group.finish();
}

criterion_group!(bfv, bfv_benchmark);
criterion_main!(bfv);
