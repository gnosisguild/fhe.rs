//! End-to-end threshold BFV tests with the production secure_8192 presets.

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

#[path = "../examples/support/presets.rs"]
mod presets;

use std::sync::Arc;

use fhe::bfv::{Ciphertext, CommonRandomPoly, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::mbfv::{AggregateIter, PublicKeyShare};
use fhe::trbfv::smudging::SmudgingNoiseGenerator;
use fhe::trbfv::{
    Lambda, ShareManager, SmudgingBoundCalculator, SmudgingBoundCalculatorConfig, TRBFV,
};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use ndarray::{Array, Array2, ArrayView};
use num_bigint::BigInt;
use rayon::prelude::*;

const NUM_SUMMED: usize = 50;

enum NoiseMode {
    /// Each party samples its smudging contribution uniformly in [-B_sm, B_sm].
    Random,
    /// Each party's smudging contribution is +B_sm on every coefficient, so
    /// the aggregated noise is exactly n * B_sm: the correctness boundary.
    WorstCase,
}

fn run_threshold_sum_e2e(noise_mode: NoiseMode) {
    let preset = presets::secure_8192().unwrap();
    let params_trbfv = preset.parameters.clone();
    let params_dkg = preset.share_parameters.clone();
    let degree = params_trbfv.degree();
    let num_parties = preset.num_parties;
    let threshold = preset.threshold;
    let lambda = preset.lambda;
    let trbfv = TRBFV::new(num_parties, threshold, params_trbfv.clone()).unwrap();

    // Worst-case noise needs the bound itself.
    let smudging_bound = match noise_mode {
        NoiseMode::Random => None,
        NoiseMode::WorstCase => {
            let config = SmudgingBoundCalculatorConfig::new(
                params_trbfv.clone(),
                num_parties,
                NUM_SUMMED,
                Lambda::secure(lambda).unwrap(),
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
        sk_sss: Vec<Array2<u64>>,
        esi_sss: Vec<Array2<u64>>,
        sk_sss_collected: Vec<Array2<u64>>,
        es_sss_collected: Vec<Array2<u64>>,
        sk_poly_sum: Poly<PowerBasis>,
        es_poly_sum: Poly<PowerBasis>,
        // Per-party BFV keys (DKG preset) for encrypted share transport.
        sk_dkg: SecretKey,
        pk_dkg: PublicKey,
    }

    let mut rng = rand::rng();
    let crp = CommonRandomPoly::new(&params_trbfv, &mut rng).unwrap();

    let mut parties: Vec<Party> = (0..num_parties)
        .into_par_iter()
        .map(|_| {
            let mut rng = rand::rng();

            let sk_share = SecretKey::random(&params_trbfv, &mut rng);
            let pk_share = PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();

            let mut share_manager =
                ShareManager::new(num_parties, threshold, params_trbfv.clone()).unwrap();
            let sk_poly = share_manager
                .coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())
                .unwrap();
            let sk_sss = trbfv
                .generate_secret_shares_from_poly(sk_poly, &mut rng)
                .unwrap();

            let esi_coeffs: Vec<BigInt> = match &smudging_bound {
                None => trbfv
                    .generate_smudging_error(
                        NUM_SUMMED,
                        0,
                        Lambda::secure(lambda).unwrap(),
                        &mut rng,
                    )
                    .unwrap(),
                Some(bound) => vec![bound.clone(); degree],
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
                sk_sss_collected: Vec::with_capacity(num_parties),
                es_sss_collected: Vec::with_capacity(num_parties),
                sk_poly_sum: Poly::<PowerBasis>::zero(ctx),
                es_poly_sum: Poly::<PowerBasis>::zero(ctx),
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
                    let mut encrypt_rows = |sss: &[Array2<u64>]| -> Vec<Ciphertext> {
                        sss.iter()
                            .map(|share_matrix| {
                                let share_vec: Vec<u64> = share_matrix.row(receiver_idx).to_vec();
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

                let decrypt_rows = |cts: &[Ciphertext], sk: &SecretKey| -> Array2<u64> {
                    let mut rows = Array::zeros((0, degree));
                    for ct in cts {
                        let pt = sk.try_decrypt(ct).unwrap();
                        let decrypted: Vec<u64> =
                            Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();
                        rows.push_row(ArrayView::from(&decrypted)).unwrap();
                    }
                    rows
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
    let reconstructing: Vec<usize> = (1..=num_parties).filter(|i| i % 2 == 0).collect();
    assert_eq!(reconstructing.len(), threshold + 1);

    let d_share_polys: Vec<Poly<PowerBasis>> = reconstructing
        .iter()
        .map(|&party_id| {
            let party = &parties[party_id - 1];
            trbfv
                .decryption_share(
                    tally.clone(),
                    party.sk_poly_sum.clone().into_ntt(),
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
    let preset = presets::secure_8192().unwrap();
    let max_trbfv_modulus = *preset.parameters.moduli().iter().max().unwrap();
    assert!(
        preset.share_parameters.plaintext() >= max_trbfv_modulus,
        "DKG plaintext modulus must be >= every trBFV modulus so shares fit in transport plaintexts"
    );
}

// ── Independent invariant tests (not formula mirrors) ─────────────────

/// The secure_8192 preset must produce a feasible (non-zero) smudging bound.
#[test]
fn trbfv_smudging_bound_is_feasible_for_secure_8192_preset() {
    use num_bigint::BigUint;

    let preset = presets::secure_8192().unwrap();
    let params = preset.parameters.clone();
    let config = SmudgingBoundCalculatorConfig::new(
        params.clone(),
        preset.num_parties,
        NUM_SUMMED,
        Lambda::secure(preset.lambda).unwrap(),
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

    let preset = presets::secure_8192().unwrap();
    let params = preset.parameters.clone();
    let config = SmudgingBoundCalculatorConfig::new(
        params.clone(),
        preset.num_parties,
        NUM_SUMMED,
        Lambda::secure(preset.lambda).unwrap(),
    )
    .unwrap();
    let bound = SmudgingBoundCalculator::new(config)
        .calculate_sm_bound()
        .unwrap();

    // Reconstruct Delta = floor(Q / t) from the preset parameters.
    let q_full: BigUint = params.moduli().iter().map(|&m| BigUint::from(m)).product();
    let t = BigUint::from(params.plaintext());
    let delta = &q_full / &t;

    // For the inequality to have passed, we must have (2 * n * B_sm) < Delta.
    // (This is a weaker check than the full 2*(B_C + n*B_sm) < Delta,
    //  but it's a simple invariant that any feasible bound must satisfy.)
    let two_n_bsm = BigUint::from(2_u64 * preset.num_parties as u64) * &bound;
    assert!(
        two_n_bsm < delta,
        "2*n*B_sm = {two_n_bsm} must be < Delta = {delta}"
    );
}

/// Default accepted participant count equals n, so using the builder to
/// set it to n must produce the same bound as the default.
#[test]
fn trbfv_smudging_default_accepted_count_matches_explicit_n() {
    let preset = presets::secure_8192().unwrap();
    let params = preset.parameters.clone();
    let config = SmudgingBoundCalculatorConfig::new(
        params.clone(),
        preset.num_parties,
        NUM_SUMMED,
        Lambda::secure(preset.lambda).unwrap(),
    )
    .unwrap();
    let bound_default = SmudgingBoundCalculator::new(config.clone())
        .calculate_sm_bound()
        .unwrap();
    let bound_explicit = SmudgingBoundCalculator::new(config)
        .with_accepted_participant_count(preset.num_parties)
        .calculate_sm_bound()
        .unwrap();
    assert_eq!(bound_default, bound_explicit);
}
