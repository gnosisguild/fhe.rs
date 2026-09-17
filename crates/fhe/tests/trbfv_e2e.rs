//! End-to-end threshold BFV addition test.
//!
//! Verifies standard BFV encryption, Shamir secret sharing, smudging, and
//! threshold decryption without the distributed l-BFV key or relinearization
//! layer.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

use std::sync::Arc;

use fhe::bfv::{Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::{Lambda, ShareManager, SmudgingShare, TRBFV};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::Array2;
use rand_chacha::ChaCha8Rng;

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
    let trbfv = TRBFV::new(N, THRESHOLD, params.clone()).expect("n=3, t=1 must validate");
    let mut rng = support::rng(91);

    let mut managers: Vec<ShareManager> = (0..N)
        .map(|_| ShareManager::new(N, THRESHOLD, params.clone()).expect("share manager"))
        .collect();

    let secret_key = SecretKey::random(&params, &mut rng);
    let sk_poly = managers[0]
        .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
        .expect("secret key to polynomial");
    let sk_sss = managers[0]
        .generate_secret_shares_from_poly(sk_poly, &mut rng)
        .expect("secret key share generation");

    let mut sk_sss_collected: Vec<Vec<Array2<u64>>> = (0..N).map(|_| Vec::new()).collect();
    for (receiver_idx, collected) in sk_sss_collected.iter_mut().enumerate().take(N) {
        let mut sk_rows = Array2::zeros((0, params.degree()));
        for shares_for_modulus in sk_sss.iter().take(params.moduli().len()) {
            sk_rows
                .push_row(ndarray::ArrayView::from(
                    shares_for_modulus.row(receiver_idx),
                ))
                .expect("append secret key share row");
        }
        collected.push(sk_rows);
    }

    let sk_poly_sums: Vec<Poly<PowerBasis>> = managers
        .iter()
        .enumerate()
        .map(|(i, manager)| {
            manager
                .aggregate_collected_shares(&sk_sss_collected[i])
                .expect("aggregate secret key shares")
        })
        .collect();

    let pk = PublicKey::new(&secret_key, &mut rng);
    let encrypt = |value: u64, rng: &mut ChaCha8Rng| {
        let plaintext =
            Plaintext::try_encode(&[value], Encoding::poly(), &params).expect("plaintext encoding");
        pk.try_encrypt(&plaintext, rng).expect("BFV encryption")
    };

    // Two independent decryptions, each with freshly sampled, dealt, and
    // aggregated noise: reusing one aggregate across transcripts is rejected
    // by construction (owners move), so the test performs the full pipeline
    // twice with distinct ciphertexts.
    for (left, right, expected) in [(2u64, 3u64, 5u64), (7, 8, 15)] {
        let ciphertext = Arc::new(&encrypt(left, &mut rng) + &encrypt(right, &mut rng));

        let mut inboxes: Vec<Vec<SmudgingShare>> = (0..N).map(|_| Vec::new()).collect();
        for _ in 0..N {
            let noise = trbfv
                .generate_smudging_error(2, 0, Lambda::secure(LAMBDA_VALUE).unwrap(), &mut rng)
                .expect("smudging noise generation");
            for (receiver, share) in managers[0]
                .deal_smudging_noise(noise, &mut rng)
                .expect("smudging noise dealing")
                .into_iter()
                .enumerate()
            {
                inboxes[receiver].push(share);
            }
        }

        let reconstructing = vec![1, 2];
        let mut decryption_shares = Vec::new();
        for &party_id in &reconstructing {
            let index = party_id - 1;
            // Each decrypting party aggregates its own inbox and consumes the
            // resulting aggregate in exactly one decryption-share call.
            let inbox = std::mem::take(&mut inboxes[index]);
            let es_i = managers[index]
                .aggregate_smudging_shares(inbox)
                .expect("aggregate smudging shares");
            decryption_shares.push(
                trbfv
                    .decryption_share(
                        ciphertext.clone(),
                        sk_poly_sums[index].clone().into_ntt(),
                        es_i,
                    )
                    .expect("decryption share"),
            );
        }

        if expected == 5 {
            assert!(
                trbfv
                    .decrypt(
                        vec![decryption_shares[0].clone()],
                        vec![reconstructing[0]],
                        ciphertext.clone(),
                    )
                    .is_err(),
                "one share must not decrypt"
            );
        }

        let plaintext = trbfv
            .decrypt(decryption_shares, reconstructing, ciphertext)
            .expect("threshold decryption with t+1 shares");
        let decoded =
            Vec::<u64>::try_decode(&plaintext, Encoding::poly()).expect("decode plaintext");
        assert_eq!(decoded[0], expected);
    }
}
