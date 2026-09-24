//! Benchmarks for direct RNS Shamir operations through the public ShareManager API.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "benchmark setup uses fixed validated parameters and dimensions"
)]

use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::{
    SecretKeyShare, ShareManager, SmudgingConfig, SmudgingNoiseGenerator, SmudgingShare,
};
use fhe_traits::{FheEncoder, FheEncrypter};
use ndarray::Array2;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[path = "../support/mod.rs"]
mod support;

fn bench_rns_shamir(criterion: &mut Criterion) {
    let preset = support::presets::insecure().expect("benchmark parameters must be valid");
    let params = preset.parameters;
    let degree = params.degree();
    let modulus_count = params.moduli().len();

    for (party_count, threshold) in [(3usize, 1usize), (5, 2), (20, 9)] {
        let manager =
            ShareManager::new(party_count, threshold, params.clone()).expect("valid committee");
        let mut setup_rng = ChaCha8Rng::seed_from_u64(1);
        let secret_key = SecretKey::random(&params, &mut setup_rng);
        let secret_key_poly = manager
            .coeffs_to_poly_level0(secret_key.coeffs.as_ref())
            .expect("secret-key conversion must succeed");

        let dealer_shares: Vec<_> = (0..party_count)
            .map(|_| {
                manager
                    .generate_secret_key_shares(secret_key_poly.clone(), &mut setup_rng)
                    .expect("benchmark share generation must succeed")
                    .into_transport()
            })
            .collect();
        let aggregated_shares: Vec<_> = (0..party_count)
            .map(|party_index| {
                let collected: Vec<_> = dealer_shares
                    .iter()
                    .map(|modulus_shares| {
                        Array2::from_shape_fn(
                            (modulus_count, degree),
                            |(modulus_index, coefficient)| {
                                modulus_shares[modulus_index][[party_index, coefficient]]
                            },
                        )
                    })
                    .collect();
                manager
                    .aggregate_secret_key_shares(
                        collected
                            .into_iter()
                            .map(SecretKeyShare::from_transport)
                            .collect(),
                    )
                    .expect("multi-dealer share aggregation must succeed")
            })
            .collect();

        let smudging_config = SmudgingConfig::new(params.clone(), party_count, 1, 0)
            .expect("zero-security smudging configuration must be valid");
        let smudging_noise = SmudgingNoiseGenerator::new(smudging_config)
            .expect("smudging generator must be valid")
            .generate(&mut setup_rng)
            .expect("smudging noise generation must succeed");
        let smudging_shares = manager
            .generate_smudging_shares(smudging_noise, &mut setup_rng)
            .expect("smudging share generation must succeed")
            .into_transport();
        let smudging_aggregates: Vec<_> = (0..party_count)
            .map(|party_index| {
                let share = Array2::from_shape_fn(
                    (modulus_count, degree),
                    |(modulus_index, coefficient)| {
                        smudging_shares[modulus_index][[party_index, coefficient]]
                    },
                );
                manager
                    .aggregate_smudging_shares(vec![SmudgingShare::from_transport(share)])
                    .expect("smudging share aggregation must succeed")
            })
            .collect();

        let public_key = PublicKey::new(&secret_key, &mut setup_rng);
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &params)
            .expect("plaintext encoding must succeed");
        let ciphertext: Arc<Ciphertext> = Arc::new(
            public_key
                .try_encrypt(&plaintext, &mut setup_rng)
                .expect("encryption must succeed"),
        );
        let party_ids: Vec<_> = (1..=threshold + 1).collect();
        let decryption_shares: Vec<_> = party_ids
            .iter()
            .copied()
            .zip(smudging_aggregates)
            .map(|(party_id, smudging_share)| {
                manager
                    .decryption_share(
                        &ciphertext,
                        &aggregated_shares[party_id - 1],
                        smudging_share,
                    )
                    .expect("decryption-share generation must succeed")
            })
            .collect();

        let mut group = criterion.benchmark_group(format!("trbfv_shamir/n={party_count}"));
        group.throughput(Throughput::Elements((modulus_count * degree) as u64));

        group.bench_function(BenchmarkId::new("share_generation", degree), |bencher| {
            let mut rng = ChaCha8Rng::seed_from_u64(2);
            bencher.iter(|| {
                black_box(
                    manager
                        .generate_secret_key_shares(black_box(secret_key_poly.clone()), &mut rng)
                        .expect("share generation must succeed")
                        .into_transport(),
                )
            });
        });

        group.bench_function(
            BenchmarkId::new("reconstruction_decrypt", threshold + 1),
            |bencher| {
                bencher.iter(|| {
                    black_box(
                        manager
                            .decrypt_from_shares(
                                black_box(&decryption_shares),
                                black_box(&party_ids),
                                &ciphertext,
                            )
                            .expect("reconstruction must succeed"),
                    )
                });
            },
        );

        group.finish();
    }
}

criterion_group!(benches, bench_rns_shamir);
criterion_main!(benches);
