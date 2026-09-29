//! Dedicated benchmark for [`fhe::trbfv::ShareManager::decrypt_from_shares`].
//!
//! This target exists for the audit issue #257 before/after comparison of the
//! reconstruction hot path and is intentionally independent of the
//! `trbfv_shamir` criterion suite: it measures only the final
//! reconstruct-scale-convert step of threshold decryption.
//!
//! # Methodology
//!
//! * Fixed moderate parameters: polynomial degree `8192`, the five ~41-bit
//!   moduli from the degree-8192 row of the library's
//!   `BfvParameters::default_parameters_128` table, plaintext modulus `2^20`,
//!   `n = 5` parties, threshold `T = 2` (three reconstructing shares).
//!   `2t <= q_0` holds, so decryption runs the exact machine-word fast path.
//! * Deterministic setup: one dealer secret key (`ChaCha8Rng`,
//!   `seed_from_u64(1)`) is Shamir-dealt to all five parties and aggregated
//!   per party. Every party uses a zero smudging aggregate, so the measured
//!   time is independent of sampled noise.
//! * The timed operation is `decrypt_from_shares` alone: RNS Shamir
//!   reconstruction over the five-modulus chain, the `t/Q` scaling (with
//!   per-call context setup before #265 or the cached bridge after #265),
//!   and the final conversion into the plaintext polynomial. Setup,
//!   encryption, and share computation happen
//!   once outside the timed closure; `black_box` keeps every input and the
//!   result observable.
//! * A one-shot correctness check runs before timing so a broken parameter
//!   or share setup fails fast instead of benchmarking garbage.
//!
//! # Before/after comparison
//!
//! The file only uses APIs that already exist at dev snapshot `2ae8203`,
//! so the identical benchmark can run on that snapshot. For a closer
//! before/after comparison, use `b8260a2` (the first-parent tree just before
//! #265) and `5f4cc44` (the #265 merge), or the current audit stack as the
//! after tree. Copy this file to `crates/fhe/benches/` in the older worktree
//! and register it in `crates/fhe/Cargo.toml` with
//!
//! ```toml
//! [[bench]]
//! name = "trbfv_decrypt_from_shares"
//! harness = false
//! ```
//!
//! and run the same command as below. Do not interpret any difference before
//! both numbers are measured on the same machine.
//!
//! # Run
//!
//! ```text
//! cargo bench -p fhe --bench trbfv_decrypt_from_shares
//! ```

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "benchmark setup uses fixed validated parameters and dimensions"
)]

use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fhe::bfv::{BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::{SecretKeyShare, ShareManager, SmudgingShare};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::Array2;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

/// Degree-8192 row of `BfvParameters::default_parameters_128`: five ~41-bit
/// NTT-friendly moduli (copied verbatim from the parameter table).
const MODULI: &[u64] = &[
    0x1ffffff0001,
    0x1fffffb0001,
    0x1fffff24001,
    0x1ffffed8001,
    0x1ffffed0001,
];

const DEGREE: usize = 8192;
const PLAINTEXT_MODULUS: u64 = 1 << 20;
const PARTY_COUNT: usize = 5;
const THRESHOLD: usize = 2;

fn bench_decrypt_from_shares(criterion: &mut Criterion) {
    let params: Arc<_> = BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_plaintext_modulus(PLAINTEXT_MODULUS)
        .set_moduli(MODULI)
        .set_variance(10)
        .build_arc()
        .expect("benchmark parameters must be valid");
    let modulus_count = params.moduli().len();

    let manager = ShareManager::new(PARTY_COUNT, THRESHOLD, params.clone())
        .expect("honest-majority committee must be valid");
    let mut setup_rng = ChaCha8Rng::seed_from_u64(1);

    let secret_key = SecretKey::random(&params, &mut setup_rng);
    let secret_key_poly = manager
        .coeffs_to_poly_level0(secret_key.coeffs.as_ref())
        .expect("secret-key conversion must succeed");
    let dealt = manager
        .generate_secret_key_shares(secret_key_poly, &mut setup_rng)
        .expect("share dealing must succeed")
        .into_transport();

    let aggregated_shares: Vec<_> = (0..PARTY_COUNT)
        .map(|party| {
            let collected =
                Array2::from_shape_fn((modulus_count, DEGREE), |(modulus_index, coefficient)| {
                    dealt[modulus_index][[party, coefficient]]
                });
            manager
                .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(collected)])
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

    let party_ids: Vec<usize> = (1..=THRESHOLD + 1).collect();
    let decryption_shares: Vec<_> = party_ids
        .iter()
        .map(|&party| {
            let zero_smudging = manager
                .aggregate_smudging_shares(vec![SmudgingShare::from_transport(Array2::zeros((
                    modulus_count,
                    DEGREE,
                )))])
                .expect("zero smudging aggregate must succeed");
            manager
                .decryption_share(&ciphertext, &aggregated_shares[party - 1], zero_smudging)
                .expect("decryption-share generation must succeed")
        })
        .collect();

    // Fail fast instead of benchmarking a broken setup: one decryption must
    // return the encoded value.
    let sanity = manager
        .decrypt_from_shares(&decryption_shares, &party_ids, &ciphertext)
        .expect("sanity decryption must succeed");
    let decoded =
        Vec::<u64>::try_decode(&sanity, Encoding::poly()).expect("sanity decoding must succeed");
    assert_eq!(decoded[0], 42, "sanity decryption must recover the value");
    assert!(
        decoded.iter().skip(1).all(|&value| value == 0),
        "sanity decryption must recover the padded encoding"
    );

    let mut group = criterion.benchmark_group(format!("trbfv_decrypt_from_shares/n={PARTY_COUNT}"));
    group.throughput(Throughput::Elements((modulus_count * DEGREE) as u64));

    group.bench_function(BenchmarkId::new("decrypt_from_shares", DEGREE), |bencher| {
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
    });

    group.finish();
}

criterion_group!(benches, bench_decrypt_from_shares);
criterion_main!(benches);
