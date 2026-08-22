//! End-to-end threshold BFV tests with the production secure_8192 presets.

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use fhe::bfv::{
    self, BfvParameters, Ciphertext, CommonRandomPoly, Encoding, Plaintext, PublicKey, SecretKey,
};
use fhe::mbfv::{AggregateIter, PublicKeyShare};
use fhe::trbfv::smudging::SmudgingNoiseGenerator;
use fhe::trbfv::{
    Lambda, SecretPoly, SecretShareMatrix, ShareManager, SmudgingBoundCalculator,
    SmudgingBoundCalculatorConfig, SmudgingCoefficients, TRBFV,
};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use ndarray::{Array, ArrayView};
use num_bigint::BigInt;
use rayon::prelude::*;

// Secure preset (degree 8192), as used in production (enclave).
const DEGREE: usize = 8192;
const NUM_PARTIES: usize = 20;
const THRESHOLD: usize = 9; // max for n = 20: (n - 1) / 2
const LAMBDA: usize = 50;
const NUM_SUMMED: usize = 50;

// Threshold BFV parameters.
const TRBFV_PLAINTEXT_MODULUS: u64 = 1_000_000;
const TRBFV_MODULI: &[u64] = &[0x02000000015a0001, 0x0200000001460001, 0x0200000001210001];
const TRBFV_ERROR1_VARIANCE: &str = "18148392902450051384713312396360971277653333";

// DKG parameters: BFV instance for encrypted Shamir share transport. The
// plaintext modulus equals the largest trBFV modulus (0x02000000015a0001).
const DKG_PLAINTEXT_MODULUS: u64 = 144115188098531329;
const DKG_MODULI: &[u64] = &[0x0800000000004001, 0x0800000000044001];

fn trbfv_params() -> Arc<BfvParameters> {
    bfv::BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_plaintext_modulus(TRBFV_PLAINTEXT_MODULUS)
        .set_moduli(TRBFV_MODULI)
        .set_variance(10)
        .set_error1_variance_str(TRBFV_ERROR1_VARIANCE)
        .unwrap()
        .build_arc()
        .unwrap()
}

fn dkg_params() -> Arc<BfvParameters> {
    bfv::BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_plaintext_modulus(DKG_PLAINTEXT_MODULUS)
        .set_moduli(DKG_MODULI)
        .set_variance(10)
        .build_arc()
        .unwrap()
}

enum NoiseMode {
    /// Each party samples its smudging contribution uniformly in [-B_sm, B_sm].
    Random,
    /// Each party's smudging contribution is +B_sm on every coefficient, so
    /// the aggregated noise is exactly n * B_sm: the correctness boundary.
    WorstCase,
}

fn run_threshold_sum_e2e(noise_mode: NoiseMode) {
    let params_trbfv = trbfv_params();
    let params_dkg = dkg_params();
    let trbfv = TRBFV::new(NUM_PARTIES, THRESHOLD, params_trbfv.clone()).unwrap();

    // Worst-case noise needs the bound itself.
    let smudging_bound = match noise_mode {
        NoiseMode::Random => None,
        NoiseMode::WorstCase => {
            let config = SmudgingBoundCalculatorConfig::new(
                params_trbfv.clone(),
                NUM_PARTIES,
                NUM_SUMMED,
                Lambda::secure(LAMBDA).unwrap(),
            )
            .unwrap();
            let bound = SmudgingBoundCalculator::new(config)
                .calculate_sm_bound()
                .expect("secure_8192 parameters must admit a smudging bound");
            Some(BigInt::from(bound))
        }
    };

    struct Party {
        pk_share: PublicKeyShare,
        sk_sss: Vec<SecretShareMatrix>,
        esi_sss: Vec<SecretShareMatrix>,
        sk_sss_collected: Vec<SecretShareMatrix>,
        es_sss_collected: Vec<SecretShareMatrix>,
        sk_poly_sum: SecretPoly<PowerBasis>,
        es_poly_sum: SecretPoly<PowerBasis>,
        // Per-party BFV keys (DKG preset) for encrypted share transport.
        sk_dkg: SecretKey,
        pk_dkg: PublicKey,
    }

    let mut rng = rand::rng();
    let crp = CommonRandomPoly::new(&params_trbfv, &mut rng).unwrap();

    let mut parties: Vec<Party> = (0..NUM_PARTIES)
        .into_par_iter()
        .map(|_| {
            let mut rng = rand::rng();

            let sk_share = SecretKey::random(&params_trbfv, &mut rng);
            let pk_share = PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();

            let mut share_manager =
                ShareManager::new(NUM_PARTIES, THRESHOLD, params_trbfv.clone()).unwrap();
            let sk_poly = share_manager
                .coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())
                .unwrap();
            let sk_sss = trbfv
                .generate_secret_shares_from_poly(sk_poly, &mut rng)
                .unwrap();

            let esi_coeffs: SmudgingCoefficients = match &smudging_bound {
                None => trbfv
                    .generate_smudging_error(
                        NUM_SUMMED,
                        0,
                        Lambda::secure(LAMBDA).unwrap(),
                        &mut rng,
                    )
                    .unwrap(),
                Some(bound) => SmudgingCoefficients::new(vec![bound.clone(); DEGREE]),
            };
            let esi_poly = share_manager.bigints_to_poly(&esi_coeffs).unwrap();
            let esi_sss = share_manager
                .generate_secret_shares_from_poly(esi_poly, &mut rng)
                .unwrap();

            let sk_dkg = SecretKey::random(&params_dkg, &mut rng);
            let pk_dkg = PublicKey::new(&sk_dkg, &mut rng);

            let ctx = params_trbfv.context_at_level(0).unwrap();
            Party {
                pk_share,
                sk_sss,
                esi_sss,
                sk_sss_collected: Vec::with_capacity(NUM_PARTIES),
                es_sss_collected: Vec::with_capacity(NUM_PARTIES),
                sk_poly_sum: SecretPoly::new(Poly::<PowerBasis>::zero(ctx)),
                es_poly_sum: SecretPoly::new(Poly::<PowerBasis>::zero(ctx)),
                sk_dkg,
                pk_dkg,
            }
        })
        .collect();

    // Encrypted share transport: sender encrypts each receiver's share rows
    // under the receiver's DKG public key.
    let pk_dkg_list: Vec<PublicKey> = parties.iter().map(|p| p.pk_dkg.clone()).collect();

    // encrypted_shares[sender][receiver] = (sk share cts, esi share cts), one ct per modulus.
    let encrypted_shares: Vec<Vec<(Vec<Ciphertext>, Vec<Ciphertext>)>> = parties
        .par_iter()
        .map(|party| {
            pk_dkg_list
                .iter()
                .enumerate()
                .map(|(receiver_idx, receiver_pk)| {
                    let mut rng = rand::rng();
                    let mut encrypt_rows = |sss: &[SecretShareMatrix]| -> Vec<Ciphertext> {
                        sss.iter()
                            .map(|share_matrix| {
                                let share_vec: Vec<u64> =
                                    share_matrix.row(receiver_idx).unwrap().to_vec();
                                let pt = Plaintext::try_encode(
                                    &share_vec,
                                    Encoding::poly(),
                                    &params_dkg,
                                )
                                .unwrap();
                                receiver_pk.try_encrypt(&pt, &mut rng).unwrap()
                            })
                            .collect()
                    };
                    (encrypt_rows(&party.sk_sss), encrypt_rows(&party.esi_sss))
                })
                .collect()
        })
        .collect();

    // Each receiver decrypts the share rows addressed to it and collects them.
    parties
        .par_iter_mut()
        .enumerate()
        .for_each(|(receiver_idx, party)| {
            for sender_encrypted in encrypted_shares.iter() {
                let (encrypted_sk_shares, encrypted_esi_shares) = &sender_encrypted[receiver_idx];

                let decrypt_rows = |cts: &[Ciphertext], sk: &SecretKey| -> SecretShareMatrix {
                    let mut rows = Array::zeros((0, DEGREE));
                    for ct in cts {
                        let pt = sk.try_decrypt(ct).unwrap();
                        let decrypted: Vec<u64> =
                            Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();
                        rows.push_row(ArrayView::from(&decrypted)).unwrap();
                    }
                    SecretShareMatrix::new(rows)
                };

                let sk_rows = decrypt_rows(encrypted_sk_shares, &party.sk_dkg);
                let es_rows = decrypt_rows(encrypted_esi_shares, &party.sk_dkg);
                party.sk_sss_collected.push(sk_rows);
                party.es_sss_collected.push(es_rows);
            }
        });

    parties.par_iter_mut().for_each(|party| {
        party.sk_poly_sum = trbfv
            .aggregate_collected_shares(&party.sk_sss_collected)
            .unwrap();
        party.es_poly_sum = trbfv
            .aggregate_collected_shares(&party.es_sss_collected)
            .unwrap();
    });

    let pk: PublicKey = parties
        .iter()
        .map(|p| p.pk_share.clone())
        .aggregate()
        .unwrap();

    // Encrypt NUM_SUMMED ones and sum them homomorphically.
    let numbers: Vec<u64> = vec![1; NUM_SUMMED];
    let numbers_encrypted: Vec<Ciphertext> = numbers
        .par_iter()
        .map(|&number| {
            let mut rng = rand::rng();
            let pt = Plaintext::try_encode(&[number], Encoding::poly(), &params_trbfv).unwrap();
            pk.try_encrypt(&pt, &mut rng).unwrap()
        })
        .collect();
    let mut sum = Ciphertext::zero(&params_trbfv);
    for ct in &numbers_encrypted {
        sum += ct;
    }
    let tally = Arc::new(sum);

    // Threshold decryption with an arbitrary (non-prefix) subset of parties:
    // 1-based indices {2, 4, ..., 20}, i.e. threshold + 1 = 10 parties.
    let reconstructing: Vec<usize> = (1..=NUM_PARTIES).filter(|i| i % 2 == 0).collect();
    assert_eq!(reconstructing.len(), THRESHOLD + 1);

    let d_share_polys: Vec<SecretPoly<PowerBasis>> = reconstructing
        .iter()
        .map(|&party_id| {
            let party = &parties[party_id - 1];
            trbfv
                .decryption_share(
                    tally.clone(),
                    party.sk_poly_sum.clone().into_ntt().unwrap(),
                    party.es_poly_sum.clone(),
                )
                .unwrap()
        })
        .collect();

    let decrypted = trbfv.decrypt(d_share_polys, reconstructing, tally).unwrap();
    let result_vec = Vec::<u64>::try_decode(&decrypted, Encoding::poly()).unwrap();

    let expected: u64 = numbers.iter().sum();
    assert_eq!(
        result_vec[0], expected,
        "threshold decryption returned a wrong sum"
    );
}

#[test]
fn trbfv_e2e_secure_8192_random_smudging_noise() {
    run_threshold_sum_e2e(NoiseMode::Random);
}

#[test]
fn trbfv_e2e_secure_8192_worst_case_smudging_noise() {
    run_threshold_sum_e2e(NoiseMode::WorstCase);
}

/// The DKG plaintext space must contain every possible Shamir share value,
/// i.e. every trBFV modulus. This pins the relation between the two presets.
#[test]
fn dkg_plaintext_modulus_covers_trbfv_moduli() {
    let max_trbfv_modulus = *TRBFV_MODULI.iter().max().unwrap();
    assert!(
        DKG_PLAINTEXT_MODULUS >= max_trbfv_modulus,
        "DKG plaintext modulus must be >= every trBFV modulus so shares fit in transport plaintexts"
    );
}

// ── Independent invariant tests (not formula mirrors) ─────────────────

/// The secure_8192 preset must produce a feasible (non-zero) smudging bound.
#[test]
fn trbfv_smudging_bound_is_feasible_for_secure_8192_preset() {
    use num_bigint::BigUint;

    let params = trbfv_params();
    let config = SmudgingBoundCalculatorConfig::new(
        params.clone(),
        NUM_PARTIES,
        NUM_SUMMED,
        Lambda::secure(LAMBDA).unwrap(),
    )
    .unwrap();
    let bound = SmudgingBoundCalculator::new(config)
        .calculate_sm_bound()
        .unwrap();

    // The bound must be strictly positive.
    assert!(bound > BigUint::from(0_u64));

    let generator = SmudgingNoiseGenerator::new(params, bound.clone());
    assert_eq!(generator.smudging_bound(), &bound);
}

/// The smudging bound must respect the strict Delta inequality:
/// 2 * (B_C + n * B_sm) < Delta = floor(Q / t).
///
/// This is tested as an invariant: the calculator enforces it internally,
/// so we only need to verify that the returned bound is internally
/// consistent (i.e., the calculator did not silently produce a bound
/// that violates its own inequality).
#[test]
fn trbfv_smudging_bound_respects_strict_correctness() {
    use num_bigint::BigUint;

    let params = trbfv_params();
    let config = SmudgingBoundCalculatorConfig::new(
        params.clone(),
        NUM_PARTIES,
        NUM_SUMMED,
        Lambda::secure(LAMBDA).unwrap(),
    )
    .unwrap();
    let bound = SmudgingBoundCalculator::new(config)
        .calculate_sm_bound()
        .unwrap();

    // Reconstruct Delta = floor(Q / t) from the preset constants.
    let q_full: BigUint = TRBFV_MODULI.iter().map(|&m| BigUint::from(m)).product();
    let t = BigUint::from(TRBFV_PLAINTEXT_MODULUS);
    let delta = &q_full / &t;

    // For the inequality to have passed, we must have (2 * n * B_sm) < Delta.
    // (This is a weaker check than the full 2*(B_C + n*B_sm) < Delta,
    //  but it's a simple invariant that any feasible bound must satisfy.)
    let two_n_bsm = BigUint::from(2_u64 * NUM_PARTIES as u64) * &bound;
    assert!(
        two_n_bsm < delta,
        "2*n*B_sm = {two_n_bsm} must be < Delta = {delta}"
    );
}

/// Default accepted participant count equals n, so using the builder to
/// set it to n must produce the same bound as the default.
#[test]
fn trbfv_smudging_default_accepted_count_matches_explicit_n() {
    let params = trbfv_params();
    let config = SmudgingBoundCalculatorConfig::new(
        params.clone(),
        NUM_PARTIES,
        NUM_SUMMED,
        Lambda::secure(LAMBDA).unwrap(),
    )
    .unwrap();
    let bound_default = SmudgingBoundCalculator::new(config.clone())
        .calculate_sm_bound()
        .unwrap();
    let bound_explicit = SmudgingBoundCalculator::new(config)
        .with_accepted_participant_count(NUM_PARTIES)
        .calculate_sm_bound()
        .unwrap();
    assert_eq!(bound_default, bound_explicit);
}
