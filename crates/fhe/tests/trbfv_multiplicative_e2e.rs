//! End-to-end threshold BFV multiplicative-depth test.
//!
//! Verifies that a depth-1 homomorphic multiplication under distributed
//! l-BFV public/relin keys, Shamir secret sharing, accepted-participant
//! smudging, and threshold decryption:
//!
//! * exactly `threshold + 1` shares decrypt the product correctly,
//! * a single share is insufficient.

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe::lbfv::{
    LBFVContributionBinding, LBFVParticipantSet, LBFVPublicKey, LBFVRelinKeyShare,
    LBFVRelinearizationKey,
};
use fhe::trbfv::{Lambda, ShareManager, TRBFV};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::{Array, Array2};
use num_bigint::BigInt;
use rand::{Rng, SeedableRng, rng};
use rand_chacha::ChaCha8Rng;

/// Small parameters for fast depth-1 multiplicative e2e testing.
///
/// The relinearization error bound contains the largest modulus `b_g` as a
/// factor, which makes large moduli infeasible for depth > 0.  We use modest
/// 40-bit moduli (still large enough for NTT with degree 64) and a few of
/// them to provide Q budget, keeping `b_g` small enough for the
/// multiplicative recurrence to produce a feasible smudging bound.
fn mul_params() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(64)
        .set_plaintext_modulus(1153)
        .set_moduli_sizes(&[40; 4])
        .set_variance(1)
        .build_arc()
        .unwrap()
}

/// Paper-conforming trBFV config: n = 2t + 1 = 3, threshold t = 1.
const N: usize = 3;
const THRESHOLD: usize = 1; // (n - 1) / 2
const MULT_DEPTH: u32 = 1;
const LAMBDA_VALUE: usize = 35; // MIN_SECURE_LAMBDA

/// Distributed l-BFV PK + RLK contributions, Shamir-shared key/noise, depth-1
/// multiplication, threshold decryption.
#[test]
fn depth1_mul_distributed_lbfv_trbfv_decrypt() {
    let params = mul_params();
    let trbfv = TRBFV::new(N, THRESHOLD, params.clone()).expect("n=3, t=1 must validate");

    // ── Common CRS / URS seeds ╌───────────────────────────────────────
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

    // ── Participant set (1‑based IDs) ╌─────────────────────────────────
    let participant_set = LBFVParticipantSet::new([42u8; 32], (1..=N as u32).collect())
        .expect("sorted unique participant IDs");

    // ── Per-party secret-key contributions ╌───────────────────────────
    let sk_shares: Vec<SecretKey> = (0..N)
        .map(|_| SecretKey::random(&params, &mut rng))
        .collect();

    // ── Distributed l-BFV public key ╌─────────────────────────────────
    let pk_contributions: Vec<LBFVPublicKey> = sk_shares
        .iter()
        .enumerate()
        .map(|(i, sk_i)| {
            let binding = LBFVContributionBinding::new(participant_set.clone(), (i + 1) as u32)
                .expect("valid contribution binding");
            LBFVPublicKey::new_with_seed_and_binding(sk_i, crs_seed, binding, &mut rng)
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("PK contribution generation");
    let aggregated_pk = LBFVPublicKey::aggregate(&pk_contributions).expect("PK aggregation");

    // ── Distributed l-BFV relinearization key ╌────────────────────────
    let rlk_shares: Vec<LBFVRelinKeyShare> = sk_shares
        .iter()
        .enumerate()
        .map(|(i, sk_i)| {
            let binding = LBFVContributionBinding::new(participant_set.clone(), (i + 1) as u32)
                .expect("valid contribution binding");
            LBFVRelinKeyShare::contribution_with_binding(
                sk_i, urs_seed, crs_seed, binding, 0, // ciphertext_level
                0, // key_level
                &mut rng,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("RLK share generation");
    let aggregated_rlk =
        LBFVRelinearizationKey::aggregate(&rlk_shares, &aggregated_pk).expect("RLK aggregation");

    // ── Smudging noise (pre-shared, one‑time per party) ╌─────────────
    let smudging_noises: Vec<Vec<BigInt>> = (0..N)
        .map(|_| {
            trbfv
                .generate_smudging_error_with_participant_count(
                    1,
                    MULT_DEPTH,
                    N, // all n parties contribute to the RLK
                    Lambda::secure(LAMBDA_VALUE).expect("secure lambda"),
                    &mut rng,
                )
                .expect("smudging noise generation")
        })
        .collect();

    // ── Shamir share deal / collect / aggregate (SK + noise) ╌─────────
    struct Party {
        sk_sss: Vec<Array2<u64>>,
        esi_sss: Vec<Array2<u64>>,
        sk_sss_collected: Vec<Array2<u64>>,
        es_sss_collected: Vec<Array2<u64>>,
        sk_poly_sum: Poly<PowerBasis>,
        es_poly_sum: Poly<PowerBasis>,
    }

    let ctx_level0 = params.context_at_level(0).expect("level-0 context");
    let mut parties: Vec<Party> = (0..N)
        .map(|i| {
            let mut share_manager =
                ShareManager::new(N, THRESHOLD, params.clone()).expect("share manager");

            // Shamir‑share this party's secret key
            let sk_poly = share_manager
                .coeffs_to_poly_level0(sk_shares[i].coeffs.clone().as_ref())
                .expect("sk to poly");
            let sk_sss = share_manager
                .generate_secret_shares_from_poly(sk_poly, &mut rng)
                .expect("sk share generation");

            // Shamir‑share this party's smudging noise
            let esi_poly = share_manager
                .bigints_to_poly(&smudging_noises[i])
                .expect("esi to poly");
            let esi_sss = share_manager
                .generate_secret_shares_from_poly(esi_poly, &mut rng)
                .expect("esi share generation");

            Party {
                sk_sss,
                esi_sss,
                sk_sss_collected: Vec::with_capacity(N),
                es_sss_collected: Vec::with_capacity(N),
                sk_poly_sum: Poly::<PowerBasis>::zero(ctx_level0),
                es_poly_sum: Poly::<PowerBasis>::zero(ctx_level0),
            }
        })
        .collect();

    // Each party collects the row addressed to it from every other party's
    // share matrix (simulated as local access — no encrypted transport).
    // Collect all rows before pushing to avoid double borrows.
    for receiver_idx in 0..N {
        let mut sk_rows: Vec<Array2<u64>> = Vec::with_capacity(N);
        let mut es_rows: Vec<Array2<u64>> = Vec::with_capacity(N);
        for sender in parties.iter() {
            let collect_row = |sss: &[Array2<u64>]| -> Array2<u64> {
                let mut rows = Array::zeros((0, params.degree()));
                for share_matrix in sss {
                    let row = share_matrix.row(receiver_idx);
                    rows.push_row(row).expect("append share row");
                }
                rows
            };
            sk_rows.push(collect_row(&sender.sk_sss));
            es_rows.push(collect_row(&sender.esi_sss));
        }
        parties[receiver_idx].sk_sss_collected = sk_rows;
        parties[receiver_idx].es_sss_collected = es_rows;
    }

    // Aggregate collected SK and noise shares into per-party polynomials.
    for party in parties.iter_mut() {
        party.sk_poly_sum = trbfv
            .aggregate_collected_shares(&party.sk_sss_collected)
            .expect("aggregate sk shares");
        party.es_poly_sum = trbfv
            .aggregate_collected_shares(&party.es_sss_collected)
            .expect("aggregate es shares");
    }

    // ── Encrypt, multiply, relinearize ╌───────────────────────────────
    let mut encrypt = |value: u64| -> Ciphertext {
        let pt =
            Plaintext::try_encode(&[value], Encoding::poly(), &params).expect("plaintext encode");
        aggregated_pk
            .try_encrypt(&pt, &mut rng)
            .expect("encryption")
    };

    let ct_a = encrypt(2);
    let ct_b = encrypt(3);

    // Ciphertext multiplication produces a 3-component ciphertext.
    let mut ct_prod = &ct_a * &ct_b;
    assert_eq!(ct_prod.len(), 3, "multiplication must yield 3 components");
    assert_eq!(ct_prod.level, ct_a.level);

    aggregated_rlk
        .relinearizes(&mut ct_prod)
        .expect("relinearization");
    assert_eq!(ct_prod.len(), 2, "relinearization must yield 2 components");

    let tally = Arc::new(ct_prod);

    // ── Threshold decryption ╌─────────────────────────────────────────
    let reconstructing: Vec<usize> = vec![1, 2]; // threshold + 1 = 2
    assert_eq!(reconstructing.len(), THRESHOLD + 1);

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
                .expect("decryption share")
        })
        .collect();

    // A single share must be insufficient.
    let one_share_result = trbfv.decrypt(
        vec![d_share_polys[0].clone()],
        vec![reconstructing[0]],
        tally.clone(),
    );
    assert!(
        one_share_result.is_err(),
        "single share must not decrypt (threshold requires {} shares)",
        THRESHOLD + 1
    );

    // Exactly threshold + 1 shares must decrypt to the correct product.
    let decrypted = trbfv
        .decrypt(d_share_polys, reconstructing, tally)
        .expect("threshold decryption with t+1 shares");
    let result_vec =
        Vec::<u64>::try_decode(&decrypted, Encoding::poly()).expect("decode decryption result");
    assert_eq!(
        result_vec[0], 6,
        "threshold decryption must recover 2 * 3 = 6, got {}",
        result_vec[0]
    );
}
