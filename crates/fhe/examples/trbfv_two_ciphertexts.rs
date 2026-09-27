//! Threshold decryption of two independent ciphertexts.
//!
//! Committee PRF keys are sampled once. Each ciphertext is decrypted on its
//! own: fresh local smudging, a digest `H(S, ct)`, and a mask `r_i^{S,ct}`
//! from that digest. The two masks differ because the digest includes `ct`.
//!
//! ```text
//! cargo run --release --example trbfv_two_ciphertexts
//! ```
//!
//! Uses the insecure degree-128 profile so the Poseidon2 PRF finishes quickly.
//! Not for production.

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

#[path = "../support/mod.rs"]
mod support;

use std::{error::Error, sync::Arc};

use fhe::{
    bfv::{Encoding, Plaintext, PublicKey, SecretKey},
    trbfv::{PartyPrfKeys, ShareManager, SmudgingConfig, SmudgingNoiseGenerator},
};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::{Array2, ArrayView};
use rand::CryptoRng;

fn encrypt_u64<R: CryptoRng>(value: u64, pk: &PublicKey, rng: &mut R) -> Arc<fhe::bfv::Ciphertext> {
    let pt = Plaintext::try_encode(&[value], Encoding::poly(), &pk.params).unwrap();
    Arc::new(pk.try_encrypt(&pt, rng).unwrap())
}

fn decrypt_one(
    manager: &ShareManager,
    ciphertext: Arc<fhe::bfv::Ciphertext>,
    sk_poly_sums: &[Poly<PowerBasis>],
    reconstructing: &[usize],
    prf_keys: &[PartyPrfKeys],
    generator: &SmudgingNoiseGenerator,
    rng: &mut impl CryptoRng,
) -> u64 {
    let mut shares = Vec::new();
    for &party_id in reconstructing {
        let party_index = party_id - 1;
        shares.push(
            manager
                .decryption_share(
                    ciphertext.clone(),
                    sk_poly_sums[party_index].clone().into_ntt(),
                    party_id,
                    reconstructing,
                    generator.generate(rng).unwrap(),
                    &prf_keys[party_index],
                )
                .unwrap(),
        );
    }
    let plaintext = manager
        .decrypt_from_shares(shares, reconstructing.to_vec(), ciphertext)
        .unwrap();
    Vec::<u64>::try_decode(&plaintext, Encoding::poly()).unwrap()[0]
}

fn main() -> Result<(), Box<dyn Error>> {
    let preset = support::insecure()?;
    let params = preset.parameters.clone();
    let n = 3;
    let threshold = 1;
    let num_ciphertexts = 2;
    let mut rng = rand::rng();

    println!("# Two independent threshold decryptions");
    println!("\tn = {n}, threshold = {threshold}, m = {num_ciphertexts}");
    println!("\tPRF keys sampled once; each ciphertext gets its own H(S, ct) mask");

    let manager = ShareManager::new(n, threshold, params.clone())?;
    let secret_key = SecretKey::random(&params, &mut rng);
    let public_key = PublicKey::new(&secret_key, &mut rng);
    let sk_poly = manager.coeffs_to_poly_level0(secret_key.coeffs.as_ref())?;
    let sk_shares = manager.generate_secret_shares_from_poly(sk_poly, &mut rng)?;

    let degree = params.degree();
    let mut sk_poly_sums = Vec::with_capacity(n);
    for party_index in 0..n {
        let mut node_share = Array2::zeros((0, degree));
        for share in sk_shares.iter().take(params.moduli().len()) {
            node_share.push_row(ArrayView::from(share.row(party_index)))?;
        }
        sk_poly_sums.push(manager.aggregate_collected_shares(std::slice::from_ref(&node_share))?);
    }

    // Same committee keys for every ciphertext.
    let prf_keys = manager.generate_prf_keys(&mut rng)?;
    let reconstructing = vec![1usize, 2];
    let config = SmudgingConfig::new(params.clone(), n, num_ciphertexts, preset.lambda)?;
    let generator = SmudgingNoiseGenerator::new(config)?;

    let ct_left = encrypt_u64(7, &public_key, &mut rng);
    let ct_right = encrypt_u64(11, &public_key, &mut rng);

    // Masks are F_k(H(S, ct)). Different ciphertexts ⇒ different digests.
    let mask_left = prf_keys[0].mask(&reconstructing, ct_left.as_ref())?;
    let mask_right = prf_keys[0].mask(&reconstructing, ct_right.as_ref())?;
    assert_ne!(
        mask_left.coefficients(),
        mask_right.coefficients(),
        "party 1 must get a different mask for each ciphertext"
    );
    println!("Party 1 PRF masks for the two ciphertexts differ.");

    let left = decrypt_one(
        &manager,
        ct_left,
        &sk_poly_sums,
        &reconstructing,
        &prf_keys,
        &generator,
        &mut rng,
    );
    let right = decrypt_one(
        &manager,
        ct_right,
        &sk_poly_sums,
        &reconstructing,
        &prf_keys,
        &generator,
        &mut rng,
    );

    println!("Decrypted: {left} and {right}");
    assert_eq!(left, 7);
    assert_eq!(right, 11);
    println!("Both ciphertexts decrypted with independent PartDec / FinDec.");

    Ok(())
}
