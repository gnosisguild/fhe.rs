//! Benchmarks for direct RNS Shamir operations through the public TRBFV API.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "benchmark setup uses fixed validated parameters and dimensions"
)]

use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::ShareManager;
use fhe_traits::{FheEncoder, FheEncrypter};
use ndarray::Array2;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[path = "../support/mod.rs"]
mod support;

fn bench_rns_shamir(criterion: &mut Criterion) {
    let preset = support::insecure().expect("benchmark parameters must be valid");
    let params = preset.parameters;
    let degree = params.degree();
    let modulus_count = params.moduli().len();

    for (party_count, threshold) in [(3usize, 1usize), (5, 2), (20, 9)] {
        let mut manager =
            ShareManager::new(party_count, threshold, params.clone()).expect("valid committee");
        let mut setup_rng = ChaCha8Rng::seed_from_u64(1);
        let secret_key = SecretKey::random(&params, &mut setup_rng);
        let secret_poly = manager
            .coeffs_to_poly_level0(secret_key.coeffs.as_ref())
            .expect("secret-key conversion must succeed");

        let modulus_shares = manager
            .generate_secret_shares_from_poly(secret_poly.clone(), &mut setup_rng)
            .expect("benchmark share generation must succeed");
        let aggregated_shares: Vec<_> = (0..party_count)
            .map(|party_index| {
                let share = Array2::from_shape_fn(
                    (modulus_count, degree),
                    |(modulus_index, coefficient)| {
                        modulus_shares[modulus_index][[party_index, coefficient]]
                    },
                );
                manager
                    .aggregate_collected_shares(std::slice::from_ref(&share))
                    .expect("share aggregation must succeed")
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
        // Zero-noise aggregates (one per reconstructing party): exercise
        // decryption through the dedicated dealing/aggregation pipeline.
        let zero_generator = fhe::trbfv::smudging::SmudgingNoiseGenerator::new(
            params.clone(),
            num_bigint::BigUint::from(0u32),
        );
        let zero_noise = zero_generator
            .generate_smudging_error(&mut setup_rng)
            .expect("zero-noise generation must succeed");
        let mut inboxes: Vec<Vec<fhe::trbfv::SmudgingShare>> =
            (0..party_count).map(|_| Vec::new()).collect();
        for (recipient, share) in manager
            .deal_smudging_noise(zero_noise, &mut setup_rng)
            .expect("zero-noise dealing must succeed")
            .into_iter()
            .enumerate()
        {
            inboxes[recipient].push(share);
        }
        let decryption_shares: Vec<_> = party_ids
            .iter()
            .map(|&party_id| {
                let inbox = std::mem::take(&mut inboxes[party_id - 1]);
                let noise = manager
                    .aggregate_smudging_shares(inbox)
                    .expect("zero-noise aggregation must succeed");
                manager
                    .decryption_share(
                        ciphertext.clone(),
                        aggregated_shares[party_id - 1].clone().into_ntt(),
                        noise,
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
                        .generate_secret_shares_from_poly(black_box(secret_poly.clone()), &mut rng)
                        .expect("share generation must succeed"),
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
                                black_box(decryption_shares.clone()),
                                black_box(party_ids.clone()),
                                ciphertext.clone(),
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
