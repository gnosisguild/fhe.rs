//! End-to-end threshold l-BFV multiplication test.
//!
//! Verifies that a depth-1 homomorphic multiplication under distributed
//! l-BFV public/relin keys, Shamir secret sharing, local smudging, PRF
//! masking, and threshold decryption:
//!
//! * exactly `threshold + 1` shares decrypt the product correctly,
//! * a single share is insufficient.

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use fhe::aggregate::AggregateIter;
use fhe::bfv::{Ciphertext, Encoding, Plaintext, SecretKey};
use fhe::trbfv::{SecretKeyShare, ShareManager, SmudgingConfig, SmudgingNoiseGenerator};
use fhe::trlbfv::{LBFVPublicKey, PublicKeyShare, RelinKeyShare, aggregate_relinearization_key};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::{Array, Array2};

#[path = "../support/mod.rs"]
mod support;

/// Small paper-conforming committee: n = 2t + 1 = 3, threshold t = 1.
const N: usize = 3;
const THRESHOLD: usize = 1; // (n - 1) / 2
const MULT_DEPTH: u32 = 1;
const LAMBDA_VALUE: usize = 31;

/// Distributed l-BFV PK + RLK contributions, Shamir-shared key, depth-1
/// multiplication, threshold decryption with local smudging.
#[test]
fn depth1_mul_distributed_lbfv_trlbfv_decrypt() {
    let preset = support::presets::secure16384().expect("secure16384 profile must be valid");
    let params = preset.parameters;
    let share_params = preset.share_parameters.unwrap();
    assert_eq!(share_params.degree(), params.degree());
    assert_eq!(share_params.moduli().len(), 2);
    let manager = ShareManager::new(N, THRESHOLD, params.clone()).expect("n=3, t=1 must validate");

    let mut rng = support::presets::rng(81);
    let crs_seed = support::presets::seed(82);
    let urs_seed = support::presets::seed(83);

    let sk_shares: Vec<SecretKey> = (0..N)
        .map(|_| SecretKey::random(&params, &mut rng))
        .collect();

    let pk_contributions: Vec<PublicKeyShare> = sk_shares
        .iter()
        .map(|sk_i| PublicKeyShare::contribute_with_seed(sk_i, crs_seed, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .expect("PK contribution generation");
    let pk = pk_contributions
        .into_iter()
        .aggregate::<LBFVPublicKey>()
        .expect("PK aggregation");

    let rlk_shares: Vec<RelinKeyShare> = sk_shares
        .iter()
        .map(|sk_i| {
            RelinKeyShare::contribute_with_seed(
                sk_i, urs_seed, crs_seed, 0, // ciphertext_level
                0, // key_level
                &mut rng,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("RLK share generation");
    let aggregated_rlk = aggregate_relinearization_key(&rlk_shares, &pk).expect("RLK aggregation");

    struct Party {
        secret_key_shares_transport: Vec<Array2<u64>>,
        secret_key_shares_collected: Vec<SecretKeyShare>,
        secret_key_aggregate: Option<fhe::trbfv::AggregatedSecretKeyShare>,
    }

    let mut parties: Vec<Party> = (0..N)
        .map(|i| {
            let share_manager =
                ShareManager::new(N, THRESHOLD, params.clone()).expect("share manager");
            let secret_key_poly = share_manager
                .coeffs_to_poly_level0(sk_shares[i].coeffs.clone().as_ref())
                .expect("sk to poly");
            let secret_key_shares_transport = share_manager
                .generate_secret_key_shares(secret_key_poly, &mut rng)
                .expect("sk share generation")
                .into_transport();

            Party {
                secret_key_shares_transport,
                secret_key_shares_collected: Vec::with_capacity(N),
                secret_key_aggregate: None,
            }
        })
        .collect();

    let transports: Vec<Vec<Array2<u64>>> = parties
        .iter()
        .map(|party| party.secret_key_shares_transport.clone())
        .collect();
    for (receiver_idx, party) in parties.iter_mut().enumerate() {
        party.secret_key_shares_collected = transports
            .iter()
            .map(|secret_key_shares_transport| {
                let mut rows = Array::zeros((0, params.degree()));
                for share_matrix in secret_key_shares_transport {
                    rows.push_row(share_matrix.row(receiver_idx))
                        .expect("append share row");
                }
                SecretKeyShare::from_transport(rows)
            })
            .collect();
    }

    for party in parties.iter_mut() {
        party.secret_key_aggregate = Some(
            manager
                .aggregate_secret_key_shares(std::mem::take(&mut party.secret_key_shares_collected))
                .expect("aggregate sk shares"),
        );
    }

    let prf_keys = support::examples::simulated_committee_prf_keys(N, &mut rng);
    let config = SmudgingConfig::new(params.clone(), N, 1, LAMBDA_VALUE)
        .expect("smudging config")
        .with_mult_depth(MULT_DEPTH);
    let generator = SmudgingNoiseGenerator::new(config).expect("smudging generator");

    let mut encrypt = |value: u64| -> Ciphertext {
        let pt =
            Plaintext::try_encode(&[value], Encoding::poly(), &params).expect("plaintext encode");
        pk.try_encrypt(&pt, &mut rng).expect("encryption")
    };

    let ct_a = encrypt(2);
    let ct_b = encrypt(3);

    let mut ct_prod = &ct_a * &ct_b;
    assert_eq!(ct_prod.len(), 3, "multiplication must yield 3 components");
    assert_eq!(ct_prod.level, ct_a.level);

    aggregated_rlk
        .relinearizes(&mut ct_prod)
        .expect("relinearization");
    assert_eq!(ct_prod.len(), 2, "relinearization must yield 2 components");

    let tally = Arc::new(ct_prod);

    let reconstructing: Vec<usize> = vec![1, 2];
    assert_eq!(reconstructing.len(), THRESHOLD + 1);

    let decryption_shares: Vec<_> = reconstructing
        .iter()
        .map(|&party_id| {
            let party = &parties[party_id - 1];
            manager
                .decryption_share(
                    &tally,
                    party
                        .secret_key_aggregate
                        .as_ref()
                        .expect("one key owner per party"),
                    party_id,
                    &reconstructing,
                    generator.generate(&mut rng).expect("local smudging"),
                    &prf_keys[party_id - 1],
                )
                .expect("decryption share")
        })
        .collect();

    let one_share_result =
        manager.decrypt_from_shares(std::slice::from_ref(&decryption_shares[0]), &tally);
    assert!(
        one_share_result.is_err(),
        "single share must not decrypt (threshold requires {} shares)",
        THRESHOLD + 1
    );

    let decrypted = manager
        .decrypt_from_shares(&decryption_shares, &tally)
        .expect("threshold decryption with t+1 shares");
    let result_vec =
        Vec::<u64>::try_decode(&decrypted, Encoding::poly()).expect("decode decryption result");
    assert_eq!(
        result_vec[0], 6,
        "threshold decryption must recover 2 * 3 = 6, got {}",
        result_vec[0]
    );
}
