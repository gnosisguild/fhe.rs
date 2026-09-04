// Expect indexing in benchmarks for convenience
#![expect(missing_docs, reason = "examples/benches/tests omit docs by design")]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, SecretKey, dot_product_scalar};
use fhe_traits::{FheEncoder, FheEncrypter};
use itertools::{Itertools, izip};
use rand::rng;
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
            let pt1 = Plaintext::try_encode(&(1..16u64).collect_vec(), Encoding::poly(), &params)
                .unwrap();
            let mut c1: Ciphertext = sk.try_encrypt(&pt1, &mut rng).unwrap();

            let ct_vec = (0..size)
                .map(|i| {
                    let pt = Plaintext::try_encode(
                        &((i as u64)..16u64).collect_vec(),
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
                        &((i as u64)..39u64).collect_vec(),
                        Encoding::poly(),
                        &params,
                    )
                    .unwrap()
                })
                .collect_vec();

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
                    b.iter(|| izip!(&ct_vec, &pt_vec).for_each(|(cti, pti)| c1 += &(cti * pti)));
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
                    b.iter(|| dot_product_scalar(ct_vec.iter(), pt_vec.iter()));
                },
            );
        }
    }

    group.finish();
}

criterion_group!(bfv, bfv_benchmark);
criterion_main!(bfv);
