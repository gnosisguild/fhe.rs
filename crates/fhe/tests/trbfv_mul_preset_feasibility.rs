//! Preset-level smudging feasibility and depth-3 end-to-end coverage for the
//! multiplicative trBFV examples.
//!
//! Regression guard for issue #113: the multiplication examples
//! (`crates/fhe/examples/trbfv_mul_bfv_share.rs` and
//! `trbfv_mul_bfv_share_binding.rs`) previously declared smudging-infeasible
//! parameter sets and panicked inside Rayon worker closures at runtime. The
//! constants below MUST match the presets declared in those two example files;
//! when an example preset is retuned, update this file in the same change.

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use fhe::bfv::{self, BfvParameters, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe::mbfv::AggregateIter;
use fhe::trbfv::{
    ContributionBinding, DecryptionShare, KeyShareContribution, Lambda, NoiseShareContribution,
    NoiseShareMatrix, ParticipantSet, SecretShareMatrix, SessionId, ShareManager,
    SmudgingBoundCalculator, SmudgingBoundCalculatorConfig, SmudgingCoefficients, TRBFV,
};
use fhe::trlbfv::{
    AggregatedPublicKey, PublicKeyShare, RelinKeyShare, aggregate_relinearization_key,
};
use fhe_math::rq::PowerBasis;
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::Array;
use num_bigint::BigUint;
use rand::{Rng, SeedableRng, rng};
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;

// ── trBFV preset of the multiplication examples ────────────────────────────
const DEGREE: usize = 16384;
const NUM_PARTIES: usize = 19; // odd n = 2t + 1, paper-conforming
const THRESHOLD: usize = 9; // (n - 1) / 2, maximal corruption tolerance
const LAMBDA: usize = 38;
const M: usize = 1; // single ciphertext, as in the examples
const MULT_DEPTH: u32 = 3; // three chained multiplications
const PLAINTEXT_MODULUS_TRBFV: u64 = 1_000;
const TRBFV_MODULI: &[u64] = &[
    0x003fffffffef8001, // 18014398508400641 (largest)
    0x003fffffffeb8001, // 18014398508138497
    0x003fffffffe38001, // 18014398507614209
    0x003fffffffdd8001, // 18014398507220993
    0x003fffffffd78001, // 18014398506827777
];
const TRBFV_ERROR1_VARIANCE: &str = "4326914048779023023775413607683413333";

// ── Share-encryption preset of the multiplication examples ─────────────────
// Plaintext modulus = largest trBFV modulus, so every Shamir residue
// (in [0, q_i) for each trBFV modulus q_i) encodes directly as a BFV plaintext.
const PLAINTEXT_MODULUS_SHARE_ENC: u64 = TRBFV_MODULI[0];
const SHARE_ENC_MODULI: &[u64] = &[0x3fffffffffd78001, 0x3fffffffffe80001];

fn trbfv_params() -> Arc<BfvParameters> {
    bfv::BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_plaintext_modulus(PLAINTEXT_MODULUS_TRBFV)
        .set_moduli(TRBFV_MODULI)
        .set_variance(10)
        .unwrap()
        .set_error1_variance_str(TRBFV_ERROR1_VARIANCE)
        .unwrap()
        .build_arc()
        .unwrap()
}

/// The exact preset of the two multiplicative examples must yield a feasible
/// smudging bound (issue #113). An infeasible preset used to panic inside the
/// Rayon worker closures of the examples instead of reporting the
/// `SmudgingBoundInfeasible` error.
#[test]
fn mul_bfv_share_examples_preset_smudging_feasible() {
    let params = trbfv_params();
    let config = SmudgingBoundCalculatorConfig::new_multiplicative(
        params,
        NUM_PARTIES,
        M,
        MULT_DEPTH,
        Lambda::secure(LAMBDA).unwrap(),
    )
    .unwrap();
    let bound = SmudgingBoundCalculator::new(config)
        .with_accepted_participant_count(NUM_PARTIES)
        .calculate_sm_bound()
        .expect("the multiplication-example preset must be smudging-feasible");
    assert!(
        bound > BigUint::from(0_u64),
        "a feasible preset must produce a strictly positive smudging bound"
    );
}

/// The share-encryption plaintext modulus is the largest trBFV modulus, so
/// every Shamir share value (a residue of one of the trBFV moduli) fits into a
/// share-encryption plaintext.
#[test]
fn share_enc_plaintext_modulus_covers_trbfv_moduli() {
    let max_trbfv_modulus = *TRBFV_MODULI.iter().max().unwrap();
    assert_eq!(
        PLAINTEXT_MODULUS_SHARE_ENC, max_trbfv_modulus,
        "share-encryption plaintext modulus must equal the largest trBFV modulus"
    );
    // What this verifies: every Shamir share value is a residue of one of the
    // trBFV moduli, and the largest trBFV modulus equals the share-encryption
    // plaintext modulus — so every share value fits the share-encryption
    // plaintext space. Decryption correctness (noise budget) is not verified
    // here; see the example-file comments.
    assert!(
        SHARE_ENC_MODULI
            .iter()
            .all(|&q| q > PLAINTEXT_MODULUS_SHARE_ENC),
        "every share-encryption modulus must exceed the plaintext modulus"
    );
}

/// The preset threshold is the maximal corruption tolerance of the honest
/// majority: t = (n - 1) / 2 (paper-conforming odd n = 2t + 1).
#[test]
fn preset_threshold_is_maximal_corruption_tolerance() {
    assert_eq!(THRESHOLD, (NUM_PARTIES - 1) / 2);
    assert_eq!(NUM_PARTIES, 2 * THRESHOLD + 1);
}

/// Full cryptographic-core depth-3 test of the exact multiplication-example
/// preset, as a CI test (issue #113): distributed l-BFV PK/RLK, Shamir
/// sharing of keys and smudging noise, three chained multiplications with
/// relinearization, and threshold decryption with `threshold + 1` shares.
/// Unlike the examples, it does not exercise the encrypted share transport
/// or the binding example's MBFV public-key aggregation path.
#[test]
fn mul_examples_preset_depth3_e2e() {
    let params = trbfv_params();
    let trbfv =
        TRBFV::new(NUM_PARTIES, THRESHOLD, params.clone()).expect("n=19, t=9 must validate");

    let mut rng = rng();
    let crs_seed = {
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);
        seed
    };
    let urs_seed = {
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);
        seed
    };

    let participant_set = ParticipantSet::new([42u8; 32], (1..=NUM_PARTIES as u32).collect())
        .expect("sorted unique participant IDs");

    // ── Distributed l-BFV public key and relinearization key ────────────
    let sk_shares: Vec<SecretKey> = (0..NUM_PARTIES)
        .map(|_| SecretKey::random(&params, &mut rng))
        .collect();

    let contributions: Vec<(PublicKeyShare, RelinKeyShare)> = sk_shares
        .par_iter()
        .enumerate()
        .map(|(i, sk_i)| {
            let mut local_rng = rand::rng();
            let binding = ContributionBinding::new(participant_set.clone(), (i + 1) as u32)
                .expect("valid contribution binding");
            let pk_share = PublicKeyShare::new_with_seed_and_binding(
                sk_i,
                crs_seed,
                binding.clone(),
                &mut local_rng,
            )
            .expect("PK contribution generation");
            let rlk_share = RelinKeyShare::contribution_with_binding(
                sk_i,
                urs_seed,
                crs_seed,
                binding,
                0, // ciphertext_level
                0, // key_level
                &mut local_rng,
            )
            .expect("RLK share generation");
            (pk_share, rlk_share)
        })
        .collect();

    let pk_shares: Vec<PublicKeyShare> = contributions.iter().map(|(pk, _)| pk.clone()).collect();
    let rlk_shares: Vec<RelinKeyShare> = contributions.iter().map(|(_, rlk)| rlk.clone()).collect();
    let aggregated_pk = pk_shares
        .into_iter()
        .aggregate::<AggregatedPublicKey>()
        .expect("PK aggregation");
    let pk = aggregated_pk.operational();
    let rlk = aggregate_relinearization_key(&rlk_shares, &aggregated_pk).expect("RLK aggregation");

    // ── Smudging noise (one-time pre-shared material) at the preset ──────
    let mut smudging_noises: Vec<Option<SmudgingCoefficients>> = (0..NUM_PARTIES)
        .map(|_| {
            trbfv
                .generate_smudging_error_with_participant_count(
                    1,
                    MULT_DEPTH,
                    NUM_PARTIES, // all n parties contribute to the RLK
                    Lambda::secure(LAMBDA).expect("secure lambda"),
                    &mut rng,
                )
                .expect("smudging noise generation at the preset must be feasible")
        })
        .map(Some)
        .collect();

    // ── Shamir share deal / collect / aggregate (SK + noise) ─────────────
    struct Party {
        sk_sss: Vec<SecretShareMatrix>,
        esi_sss: Vec<NoiseShareMatrix>,
        sk_sss_collected: Vec<SecretShareMatrix>,
        es_sss_collected: Vec<NoiseShareMatrix>,
        sk_poly_sum: Option<fhe::trbfv::AggregatedKeyShare<PowerBasis>>,
        es_poly_sum: Option<fhe::trbfv::OneTimeNoiseShare>,
    }

    let mut parties: Vec<Party> = (0..NUM_PARTIES)
        .map(|i| {
            let mut share_manager =
                ShareManager::new(NUM_PARTIES, THRESHOLD, params.clone()).expect("share manager");

            // Shamir-share this party's secret key.
            let sk_poly = share_manager
                .coeffs_to_poly_level0(sk_shares[i].coeffs.clone().as_ref())
                .expect("sk to poly");
            let sk_sss = share_manager
                .generate_secret_shares_from_poly(sk_poly, &mut rng)
                .expect("sk share generation");

            // Shamir-share this party's smudging noise.
            let esi_poly = share_manager
                .bigints_to_poly(smudging_noises[i].take().unwrap())
                .expect("esi to poly");
            let esi_sss = share_manager
                .generate_noise_shares_from_poly(esi_poly, &mut rng)
                .expect("esi share generation");

            Party {
                sk_sss,
                esi_sss,
                sk_sss_collected: Vec::with_capacity(NUM_PARTIES),
                es_sss_collected: Vec::with_capacity(NUM_PARTIES),
                sk_poly_sum: None,
                es_poly_sum: None,
            }
        })
        .collect();

    // Each party collects the row addressed to it from every other party's
    // share matrix (simulated as local access, as in the e2e test suite).
    for receiver_idx in 0..NUM_PARTIES {
        let mut sk_rows: Vec<SecretShareMatrix> = Vec::with_capacity(NUM_PARTIES);
        let mut es_rows: Vec<NoiseShareMatrix> = Vec::with_capacity(NUM_PARTIES);
        for sender in parties.iter() {
            let collect_secret_row = |sss: &[SecretShareMatrix]| -> SecretShareMatrix {
                let mut rows = Array::zeros((0, params.degree()));
                for share_matrix in sss {
                    let row = share_matrix.row(receiver_idx).expect("valid share row");
                    rows.push_row(row).expect("append share row");
                }
                SecretShareMatrix::new(rows)
            };
            let collect_noise_row = |sss: &[NoiseShareMatrix]| -> NoiseShareMatrix {
                let mut rows = Array::zeros((0, params.degree()));
                for share_matrix in sss {
                    let row = share_matrix.row(receiver_idx).expect("valid share row");
                    rows.push_row(row).expect("append share row");
                }
                NoiseShareMatrix::new(rows)
            };
            sk_rows.push(collect_secret_row(&sender.sk_sss));
            es_rows.push(collect_noise_row(&sender.esi_sss));
        }
        parties[receiver_idx].sk_sss_collected = sk_rows;
        parties[receiver_idx].es_sss_collected = es_rows;
    }

    // Aggregate collected SK and noise shares into per-party polynomials.
    let participant_set = ParticipantSet::new(
        SessionId::new(rand::random()),
        (1..=NUM_PARTIES as u32).collect(),
    )
    .expect("participant set");
    let use_session = SessionId::new(rand::random());
    for party in parties.iter_mut() {
        let key_contributions = party
            .sk_sss_collected
            .iter()
            .enumerate()
            .map(|(index, matrix)| {
                KeyShareContribution::new(
                    ContributionBinding::new(participant_set.clone(), (index + 1) as u32)
                        .expect("binding"),
                    matrix.clone(),
                )
            })
            .collect::<Vec<_>>();
        party.sk_poly_sum = Some(
            trbfv
                .aggregate_collected_shares(&participant_set, &key_contributions)
                .expect("aggregate sk shares"),
        );
        let noise_contributions = std::mem::take(&mut party.es_sss_collected)
            .into_iter()
            .enumerate()
            .map(|(index, matrix)| {
                NoiseShareContribution::new(
                    ContributionBinding::new(participant_set.clone(), (index + 1) as u32)
                        .expect("binding"),
                    matrix,
                )
            })
            .collect();
        party.es_poly_sum = Some(
            trbfv
                .aggregate_noise_shares(&participant_set, use_session, noise_contributions)
                .expect("aggregate es shares"),
        );
    }

    // ── Encrypt, chain three multiplications with relinearization ────────
    let mut encrypt = |value: u64| -> Ciphertext {
        let pt = Plaintext::try_encode(&[value], Encoding::poly(), &params).expect("encode");
        pk.try_encrypt(&pt, &mut rng).expect("encryption")
    };

    let a = 3u64;
    let b = 5u64;
    let c = 2u64;
    let d = 4u64;
    let ct_a = encrypt(a);
    let ct_b = encrypt(b);
    let ct_c = encrypt(c);
    let ct_d = encrypt(d);

    let mut ct_ab = &ct_a * &ct_b;
    assert_eq!(ct_ab.len(), 3, "multiplication must yield 3 components");
    rlk.relinearizes(&mut ct_ab).expect("relinearization 1");
    assert_eq!(ct_ab.len(), 2, "relinearization must yield 2 components");

    let mut ct_abc = &ct_ab * &ct_c;
    rlk.relinearizes(&mut ct_abc).expect("relinearization 2");

    let mut ct_abcd = &ct_abc * &ct_d;
    rlk.relinearizes(&mut ct_abcd).expect("relinearization 3");
    assert_eq!(ct_abcd.len(), 2);

    let tally = Arc::new(ct_abcd);

    // ── Threshold decryption with exactly threshold + 1 shares ───────────
    let reconstructing: Vec<usize> = (1..=THRESHOLD + 1).collect();
    assert_eq!(reconstructing.len(), THRESHOLD + 1);

    let d_share_polys: Vec<DecryptionShare> = reconstructing
        .iter()
        .map(|&party_id| {
            let party = &mut parties[party_id - 1];
            trbfv
                .decryption_share(
                    tally.clone(),
                    party_id as u32,
                    party.sk_poly_sum.take().unwrap().into_ntt().unwrap(),
                    use_session,
                    party.es_poly_sum.take().unwrap(),
                )
                .expect("decryption share")
        })
        .collect();

    // A single share must be insufficient.
    let one_share_result = trbfv.decrypt(vec![d_share_polys[0].clone()], tally.clone());
    assert!(
        one_share_result.is_err(),
        "single share must not decrypt (threshold requires {} shares)",
        THRESHOLD + 1
    );

    // Exactly threshold + 1 shares must decrypt to the correct product.
    let decrypted = trbfv
        .decrypt(d_share_polys, tally)
        .expect("threshold decryption with t+1 shares");
    let result_vec = Vec::<u64>::try_decode(&decrypted, Encoding::poly()).expect("decode result");
    let expected = a * b * c * d;
    assert_eq!(
        result_vec[0], expected,
        "threshold decryption must recover {a} * {b} * {c} * {d} = {expected}, got {}",
        result_vec[0]
    );
}
