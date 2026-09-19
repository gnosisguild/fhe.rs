//! End-to-end threshold BFV addition test.
//!
//! Verifies standard BFV encryption, Shamir secret sharing, smudging, and
//! threshold decryption without the distributed l-BFV key or relinearization
//! layer.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

use std::sync::Arc;

use fhe::bfv::{Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::{ShareManager, SmudgingConfig, SmudgingNoiseGenerator};
use fhe_math::rq::{Poly, PowerBasis};
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
    let preset = support::secure8192().expect("secure8192 profile must be valid");
    let params = preset.parameters;
    let mut rng = support::rng(91);

    let mut manager = ShareManager::new(N, THRESHOLD, params.clone()).expect("share manager");

    let secret_key = SecretKey::random(&params, &mut rng);
    let sk_poly = manager
        .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
        .expect("secret key to polynomial");
    let sk_sss = manager
        .generate_secret_shares_from_poly(sk_poly, &mut rng)
        .expect("secret key share generation");

    let es_sss: Vec<Vec<Array2<u64>>> = (0..N)
        .map(|_| {
            // The evaluated ciphertext below is the sum of two fresh encryptions.
            let config =
                SmudgingConfig::new(params.clone(), N, 2, LAMBDA_VALUE).expect("smudging config");
            let generator = SmudgingNoiseGenerator::new(config).expect("smudging generator");
            let noise = generator
                .generate(&mut rng)
                .expect("smudging noise generation");
            manager
                .generate_secret_shares_from_smudging_noise(noise, &mut rng)
                .expect("smudging noise share generation")
        })
        .collect();

    let mut sk_sss_collected: Vec<Vec<Array2<u64>>> = (0..N).map(|_| Vec::new()).collect();
    let mut es_sss_collected: Vec<Vec<Array2<u64>>> = (0..N).map(|_| Vec::new()).collect();
    for receiver_idx in 0..N {
        let mut sk_rows = Array2::zeros((0, params.degree()));
        for shares_for_modulus in sk_sss.iter().take(params.moduli().len()) {
            sk_rows
                .push_row(ndarray::ArrayView::from(
                    shares_for_modulus.row(receiver_idx),
                ))
                .expect("append secret key share row");
        }
        sk_sss_collected[receiver_idx].push(sk_rows);

        for noise_shares in &es_sss {
            let mut es_rows = Array2::zeros((0, params.degree()));
            for shares_for_modulus in noise_shares.iter().take(params.moduli().len()) {
                es_rows
                    .push_row(ndarray::ArrayView::from(
                        shares_for_modulus.row(receiver_idx),
                    ))
                    .expect("append smudging share row");
            }
            es_sss_collected[receiver_idx].push(es_rows);
        }
    }

    let sk_poly_sums: Vec<Poly<PowerBasis>> = sk_sss_collected
        .iter()
        .map(|collected| {
            manager
                .aggregate_collected_shares(collected)
                .expect("aggregate secret key shares")
        })
        .collect();
    let es_poly_sums: Vec<Poly<PowerBasis>> = es_sss_collected
        .iter()
        .map(|collected| {
            manager
                .aggregate_collected_shares(collected)
                .expect("aggregate smudging shares")
        })
        .collect();

    let pk = PublicKey::new(&secret_key, &mut rng);
    let mut encrypt = |value: u64| {
        let plaintext =
            Plaintext::try_encode(&[value], Encoding::poly(), &params).expect("plaintext encoding");
        pk.try_encrypt(&plaintext, &mut rng)
            .expect("BFV encryption")
    };
    let ct_a = encrypt(2);
    let ct_b = encrypt(3);
    let ciphertext = Arc::new(&ct_a + &ct_b);

    let reconstructing = vec![1, 2];
    let decryption_shares: Vec<Poly<PowerBasis>> = reconstructing
        .iter()
        .map(|&party_id| {
            let index = party_id - 1;
            manager
                .decryption_share(
                    ciphertext.clone(),
                    sk_poly_sums[index].clone().into_ntt(),
                    es_poly_sums[index].clone(),
                )
                .expect("decryption share")
        })
        .collect();

    assert!(
        manager
            .decrypt_from_shares(
                vec![decryption_shares[0].clone()],
                vec![reconstructing[0]],
                ciphertext.clone(),
            )
            .is_err(),
        "one share must not decrypt"
    );

    let plaintext = manager
        .decrypt_from_shares(decryption_shares, reconstructing, ciphertext)
        .expect("threshold decryption with t+1 shares");
    let decoded = Vec::<u64>::try_decode(&plaintext, Encoding::poly()).expect("decode plaintext");
    assert_eq!(decoded[0], 5);
}
