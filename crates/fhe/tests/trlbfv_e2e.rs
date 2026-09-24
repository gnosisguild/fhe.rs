//! End-to-end threshold l-BFV multiplication test.
//!
//! Verifies that a depth-1 homomorphic multiplication under distributed
//! l-BFV public/relin keys, Shamir secret sharing, contributor-count-aware
//! smudging, and threshold decryption:
//!
//! * exactly `threshold + 1` shares decrypt the product correctly,
//! * a single share is insufficient.

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use fhe::aggregate::AggregateIter;
use fhe::bfv::{Ciphertext, Encoding, Plaintext, SecretKey};
use fhe::trbfv::{
    AggregatedSecretKeyShare, AggregatedSmudgingShare, SecretKeyShare, ShareManager,
    SmudgingConfig, SmudgingNoiseGenerator, SmudgingShare,
};
use fhe::trlbfv::{LBFVPublicKey, PublicKeyShare, RelinKeyShare, aggregate_relinearization_key};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::{Array, Array2};

#[path = "../support/mod.rs"]
mod support;

/// Small paper-conforming committee: n = 2t + 1 = 3, threshold t = 1.
const N: usize = 3;
const THRESHOLD: usize = 1; // (n - 1) / 2
const MULT_DEPTH: u32 = 1;
const LAMBDA_VALUE: usize = 31;

/// Distributed l-BFV PK + RLK contributions, Shamir-shared key/noise, depth-1
/// multiplication, threshold decryption.
#[test]
fn depth1_mul_distributed_lbfv_trlbfv_decrypt() {
    let preset = support::presets::secure16384().expect("secure16384 profile must be valid");
    let params = preset.parameters;
    let share_params = preset.share_parameters.unwrap();
    assert_eq!(share_params.degree(), params.degree());
    assert_eq!(share_params.moduli().len(), 2);
    let manager = ShareManager::new(N, THRESHOLD, params.clone()).expect("n=3, t=1 must validate");

    // ── Common CRS / URS seeds ╌───────────────────────────────────────
    let mut rng = support::presets::rng(81);
    let crs_seed = support::presets::seed(82);
    let urs_seed = support::presets::seed(83);

    // ── Per-party secret-key contributions ╌───────────────────────────
    let sk_shares: Vec<SecretKey> = (0..N)
        .map(|_| SecretKey::random(&params, &mut rng))
        .collect();

    // ── Distributed l-BFV public key ╌─────────────────────────────────
    let pk_contributions: Vec<PublicKeyShare> = sk_shares
        .iter()
        .map(|sk_i| PublicKeyShare::new_with_seed(sk_i, crs_seed, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("PK contribution generation");
    let pk = pk_contributions
        .into_iter()
        .aggregate::<LBFVPublicKey>()
        .expect("PK aggregation");

    // ── Distributed l-BFV relinearization key ╌────────────────────────
    let rlk_shares: Vec<RelinKeyShare> = sk_shares
        .iter()
        .map(|sk_i| {
            RelinKeyShare::contribution(
                sk_i, urs_seed, crs_seed, 0, // ciphertext_level
                0, // key_level
                &mut rng,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("RLK share generation");
    let aggregated_rlk = aggregate_relinearization_key(&rlk_shares, &pk).expect("RLK aggregation");

    // ── Smudging noise (pre-shared, one‑time per party) ╌─────────────
    // Each party samples one noise owner; dealing below consumes it
    // straight into Shamir shares without exposing the polynomial.
    let mut smudging_noises = (0..N)
        .map(|_| {
            let config = SmudgingConfig::new(params.clone(), N, 1, LAMBDA_VALUE)
                .expect("smudging config")
                .with_mult_depth(MULT_DEPTH);
            // Use n as the conservative aggregate RLK contribution count.
            SmudgingNoiseGenerator::new(config)
                .expect("smudging generator")
                .generate(&mut rng)
                .expect("smudging noise generation")
        })
        .collect::<Vec<_>>()
        .into_iter();

    // ── Shamir share deal / collect / aggregate (SK + noise) ╌─────────
    struct Party {
        // Explicit transport buffers; recipients rehydrate typed owners after receipt.
        secret_key_shares_transport: Vec<Array2<u64>>,
        smudging_shares_transport: Vec<Array2<u64>>,
        secret_key_shares_collected: Vec<SecretKeyShare>,
        smudging_shares_collected: Vec<SmudgingShare>,
        secret_key_aggregate: Option<AggregatedSecretKeyShare>,
        smudging_aggregate: Option<AggregatedSmudgingShare>,
    }

    let mut parties: Vec<Party> = (0..N)
        .map(|i| {
            let share_manager =
                ShareManager::new(N, THRESHOLD, params.clone()).expect("share manager");

            // Shamir‑share this party's secret key
            let secret_key_poly = share_manager
                .coeffs_to_poly_level0(sk_shares[i].coeffs.clone().as_ref())
                .expect("sk to poly");
            let secret_key_shares_transport = share_manager
                .generate_secret_key_shares(secret_key_poly, &mut rng)
                .expect("sk share generation")
                .into_transport();

            // Shamir‑share this party's smudging noise, consuming its
            // one-time owner.
            let smudging_shares_transport = share_manager
                .generate_smudging_shares(
                    smudging_noises.next().expect("one noise owner per party"),
                    &mut rng,
                )
                .expect("esi share generation")
                .into_transport();

            Party {
                secret_key_shares_transport,
                smudging_shares_transport,
                secret_key_shares_collected: Vec::with_capacity(N),
                smudging_shares_collected: Vec::with_capacity(N),
                secret_key_aggregate: None,
                smudging_aggregate: None,
            }
        })
        .collect();

    // Each party collects the row addressed to it from every other party's
    // share matrix (simulated as local access — no encrypted transport).
    // Collect all rows before pushing to avoid double borrows.
    for receiver_idx in 0..N {
        let mut secret_key_rows: Vec<Array2<u64>> = Vec::with_capacity(N);
        let mut smudging_rows: Vec<Array2<u64>> = Vec::with_capacity(N);
        for sender in parties.iter() {
            let collect_row = |sss: &[Array2<u64>]| -> Array2<u64> {
                let mut rows = Array::zeros((0, params.degree()));
                for share_matrix in sss {
                    let row = share_matrix.row(receiver_idx);
                    rows.push_row(row).expect("append share row");
                }
                rows
            };
            secret_key_rows.push(collect_row(&sender.secret_key_shares_transport));
            smudging_rows.push(collect_row(&sender.smudging_shares_transport));
        }
        parties[receiver_idx].secret_key_shares_collected = secret_key_rows
            .into_iter()
            .map(SecretKeyShare::from_transport)
            .collect();
        parties[receiver_idx].smudging_shares_collected = smudging_rows
            .into_iter()
            .map(SmudgingShare::from_transport)
            .collect();
    }

    // Aggregate collected secret-key and smudging shares into per-party owners.
    for party in parties.iter_mut() {
        party.secret_key_aggregate = Some(
            manager
                .aggregate_secret_key_shares(
                    std::mem::take(&mut party.secret_key_shares_collected)
                        .into_iter()
                        .collect(),
                )
                .expect("aggregate sk shares"),
        );
        party.smudging_aggregate = Some(
            manager
                .aggregate_smudging_shares(
                    std::mem::take(&mut party.smudging_shares_collected)
                        .into_iter()
                        .collect(),
                )
                .expect("aggregate es shares"),
        );
    }

    // ── Encrypt, multiply, relinearize ╌───────────────────────────────
    let mut encrypt = |value: u64| -> Ciphertext {
        let pt =
            Plaintext::try_encode(&[value], Encoding::poly(), &params).expect("plaintext encode");
        pk.try_encrypt(&pt, &mut rng).expect("encryption")
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

    let decryption_shares: Vec<Poly<PowerBasis>> = reconstructing
        .iter()
        .map(|&party_id| {
            let party = &mut parties[party_id - 1];
            manager
                .decryption_share(
                    tally.clone(),
                    party
                        .secret_key_aggregate
                        .as_ref()
                        .expect("one key owner per party"),
                    party
                        .smudging_aggregate
                        .take()
                        .expect("one noise owner per party"),
                )
                .expect("decryption share")
        })
        .collect();

    // A single share must be insufficient.
    let one_share_result = manager.decrypt_from_shares(
        vec![decryption_shares[0].clone()],
        vec![reconstructing[0]],
        tally.clone(),
    );
    assert!(
        one_share_result.is_err(),
        "single share must not decrypt (threshold requires {} shares)",
        THRESHOLD + 1
    );

    // Exactly threshold + 1 shares must decrypt to the correct product.
    let decrypted = manager
        .decrypt_from_shares(decryption_shares, reconstructing, tally)
        .expect("threshold decryption with t+1 shares");
    let result_vec =
        Vec::<u64>::try_decode(&decrypted, Encoding::poly()).expect("decode decryption result");
    assert_eq!(
        result_vec[0], 6,
        "threshold decryption must recover 2 * 3 = 6, got {}",
        result_vec[0]
    );
}
