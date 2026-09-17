//! Benchmarks for direct-RNS smudging noise sampling and dealing.

#![expect(
    clippy::expect_used,
    reason = "benchmark setup uses fixed validated parameters and dimensions"
)]

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fhe::trbfv::{Lambda, ShareManager, TRBFV};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[path = "../support/mod.rs"]
mod support;

fn bench_smudging_sampling(criterion: &mut Criterion) {
    for preset_name in ["insecure", "secure8192"] {
        let preset = match preset_name {
            "insecure" => support::insecure().expect("benchmark parameters must be valid"),
            _ => support::secure8192().expect("benchmark parameters must be valid"),
        };
        let params = preset.parameters;
        let trbfv = TRBFV::new(preset.num_parties, preset.threshold, params.clone())
            .expect("benchmark committee must validate");
        let lambda = if preset.lambda >= fhe::trbfv::MIN_SECURE_LAMBDA {
            Lambda::secure(preset.lambda).expect("secure lambda must validate")
        } else {
            Lambda::insecure(preset.lambda)
        };
        let degree = params.degree();

        let mut group = criterion.benchmark_group(format!("trbfv_smudging/{preset_name}"));
        group.throughput(Throughput::Elements(degree as u64));

        group.bench_function(BenchmarkId::new("sample", degree), |bencher| {
            let mut rng = ChaCha8Rng::seed_from_u64(1);
            bencher.iter(|| {
                black_box(
                    trbfv
                        .generate_smudging_error(
                            black_box(preset.max_ciphertexts),
                            0,
                            lambda,
                            &mut rng,
                        )
                        .expect("smudging sampling must succeed"),
                )
            });
        });

        group.bench_function(BenchmarkId::new("deal", degree), |bencher| {
            let mut manager =
                ShareManager::new(preset.num_parties, preset.threshold, params.clone())
                    .expect("share manager must validate");
            // Owners are one-time values, so each measured dealing iteration
            // consumes a freshly sampled owner prepared untimed in setup.
            bencher.iter_batched(
                || {
                    let mut rng = ChaCha8Rng::seed_from_u64(100);
                    trbfv
                        .generate_smudging_error(preset.max_ciphertexts, 0, lambda, &mut rng)
                        .expect("pool sampling must succeed")
                },
                |noise| {
                    let mut rng = ChaCha8Rng::seed_from_u64(2);
                    black_box(
                        manager
                            .generate_secret_shares_from_smudging_noise(black_box(noise), &mut rng)
                            .expect("smudging dealing must succeed"),
                    )
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.finish();
    }
}

criterion_group!(benches, bench_smudging_sampling);
criterion_main!(benches);
