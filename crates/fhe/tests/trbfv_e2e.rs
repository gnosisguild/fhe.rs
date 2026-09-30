//! End-to-end threshold BFV addition test.
//!
//! Verifies standard BFV encryption, Shamir secret sharing, local smudging,
//! PRF masking, and threshold decryption without the distributed l-BFV key
//! or relinearization layer.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

use std::sync::Arc;

use fhe::bfv::{Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::{
    FreshNoiseModel, SecretKeyShare, ShareManager, SmudgingConfig, SmudgingNoiseGenerator,
};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::Array2;

#[path = "../support/mod.rs"]
mod support;

/// Small paper-conforming committee: n = 2t + 1 = 3, threshold t = 1.
const N: usize = 3;
const THRESHOLD: usize = 1;
const LAMBDA_VALUE: usize = 31;

#[test]
fn threshold_bfv_addition_decrypts_with_t_plus_one_shares() {
    let preset = support::presets::secure8192().expect("secure8192 profile must be valid");
    let params = preset.parameters;
    let mut rng = support::presets::rng(91);

    let manager = ShareManager::new(N, THRESHOLD, params.clone()).expect("share manager");

    let secret_key = SecretKey::random(&params, &mut rng);
    let secret_key_poly = manager
        .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
        .expect("secret key to polynomial");
    let secret_key_shares_transport = manager
        .generate_secret_key_shares(secret_key_poly, &mut rng)
        .expect("secret key share generation")
        .into_transport();
    let prf_keys = support::examples::simulated_committee_prf_keys(N, &mut rng);

    let secret_key_shares_collected: Vec<Vec<SecretKeyShare>> = (0..N)
        .map(|receiver_idx| {
            let mut secret_key_rows = Array2::zeros((0, params.degree()));
            for shares_for_modulus in secret_key_shares_transport
                .iter()
                .take(params.moduli().len())
            {
                secret_key_rows
                    .push_row(ndarray::ArrayView::from(
                        shares_for_modulus.row(receiver_idx),
                    ))
                    .expect("append secret key share row");
            }
            vec![SecretKeyShare::from_transport(secret_key_rows)]
        })
        .collect();

    let secret_key_aggregates: Vec<_> = secret_key_shares_collected
        .into_iter()
        .map(|collected| {
            manager
                .aggregate_secret_key_shares(collected)
                .expect("aggregate secret key shares")
        })
        .collect();

    let pk = PublicKey::new(&secret_key, &mut rng).unwrap();
    let mut encrypt = |value: u64| {
        let plaintext =
            Plaintext::try_encode(&[value], Encoding::poly(), &params).expect("plaintext encoding");
        pk.try_encrypt(&plaintext, &mut rng)
            .expect("BFV encryption")
    };
    let ct_a = encrypt(2);
    let ct_b = encrypt(3);
    let ciphertext = Arc::new(&ct_a + &ct_b);

    let config = SmudgingConfig::new(
        params.clone(),
        N,
        2,
        LAMBDA_VALUE,
        FreshNoiseModel::BfvPublicKey,
    )
    .expect("smudging config");
    let generator = SmudgingNoiseGenerator::new(config).expect("smudging generator");

    let reconstructing = vec![1, 2];
    let decryption_shares: Vec<_> = reconstructing
        .iter()
        .map(|&party_id| {
            let index = party_id - 1;
            manager
                .decryption_share(
                    &ciphertext,
                    &secret_key_aggregates[index],
                    party_id,
                    &reconstructing,
                    generator.generate(&mut rng).expect("local smudging"),
                    &prf_keys[index],
                )
                .expect("decryption share")
        })
        .collect();

    assert!(
        manager
            .decrypt_from_shares(std::slice::from_ref(&decryption_shares[0]), &ciphertext)
            .is_err(),
        "one share must not decrypt"
    );

    let plaintext = manager
        .decrypt_from_shares(&decryption_shares, &ciphertext)
        .expect("threshold decryption with t+1 shares");
    let decoded = Vec::<u64>::try_decode(&plaintext, Encoding::poly()).expect("decode plaintext");
    assert_eq!(decoded[0], 5);
}
