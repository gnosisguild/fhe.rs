//! Two independent threshold decryptions with a ten-party committee.
//!
//! Committee PRF keys are sampled once for this local simulation/trusted setup.
//! A distributed deployment must establish matching keys and securely
//! distribute each party's bundle externally. Each ciphertext is decrypted on
//! its own: fresh local smudging, a digest `H(S, ct)`, and a mask `r_i^{S,ct}`
//! from that digest. The two masks differ because the digest includes `ct`.
//! Five of the ten parties participate, which is the minimum for threshold 4.
//!
//! ```text
//! cargo run --release --example trbfv_ten_parties
//! ```
//!
//! Uses the insecure degree-128 profile so the Poseidon2 PRF finishes quickly.
//! The even-sized committee is also outside the current threshold theorem.
//! This is a mechanics demo, not for production.

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

#[path = "../support/mod.rs"]
mod support;

use std::error::Error;

use fhe::{
    bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    trbfv::{
        AggregatedSecretKeyShare, PartyPrfKeys, SecretKeyShare, ShareManager, SmudgingConfig,
        SmudgingNoiseGenerator,
    },
};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::{Array2, ArrayView};
use rand::CryptoRng;

const N_PARTIES: usize = 10;
const THRESHOLD: usize = 4;
const RECONSTRUCTING_PARTIES: usize = THRESHOLD + 1;

fn encrypt_u64<R: CryptoRng>(value: u64, pk: &PublicKey, rng: &mut R) -> Ciphertext {
    let pt = Plaintext::try_encode(&[value], Encoding::poly(), &pk.params).unwrap();
    pk.try_encrypt(&pt, rng).unwrap()
}

fn decrypt_one(
    manager: &ShareManager,
    ciphertext: &Ciphertext,
    sk_aggregates: &[AggregatedSecretKeyShare],
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
                    ciphertext,
                    &sk_aggregates[party_index],
                    party_id,
                    reconstructing,
                    generator.generate(rng).unwrap(),
                    &prf_keys[party_index],
                )
                .unwrap(),
        );
    }
    let plaintext = manager.decrypt_from_shares(&shares, ciphertext).unwrap();
    Vec::<u64>::try_decode(&plaintext, Encoding::poly()).unwrap()[0]
}

fn main() -> Result<(), Box<dyn Error>> {
    let preset = support::presets::insecure()?;
    let params = preset.parameters.clone();
    let num_ciphertexts = 2;
    let mut rng = rand::rng();

    println!("# Two independent threshold decryptions with ten parties");
    println!(
        "\tn = {N_PARTIES}, threshold = {THRESHOLD}, decryptors = {RECONSTRUCTING_PARTIES}, m = {num_ciphertexts}"
    );
    println!("\tPRF keys sampled once; each ciphertext gets its own H(S, ct) mask");

    let manager = ShareManager::new(N_PARTIES, THRESHOLD, params.clone())?;
    let secret_key = SecretKey::random(&params, &mut rng);
    let public_key = PublicKey::new(&secret_key, &mut rng);
    let sk_poly = manager.coeffs_to_poly_level0(secret_key.coeffs.as_ref())?;
    let sk_shares = manager
        .generate_secret_key_shares(sk_poly, &mut rng)?
        .into_transport();

    let degree = params.degree();
    let mut sk_aggregates = Vec::with_capacity(N_PARTIES);
    for party_index in 0..N_PARTIES {
        let mut node_share = Array2::zeros((0, degree));
        for share in sk_shares.iter().take(params.moduli().len()) {
            node_share.push_row(ArrayView::from(share.row(party_index)))?;
        }
        sk_aggregates.push(
            manager
                .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(node_share)])?,
        );
    }

    // The first threshold + 1 parties reconstruct from the ten-party committee.
    let reconstructing: Vec<usize> = (1..=RECONSTRUCTING_PARTIES).collect();
    let prf_keys = PartyPrfKeys::generate_committee(N_PARTIES, &mut rng)?;
    let config = SmudgingConfig::new(params.clone(), N_PARTIES, num_ciphertexts, preset.lambda)?;
    let generator = SmudgingNoiseGenerator::new(config)?;

    let ct_left = encrypt_u64(7, &public_key, &mut rng);
    let ct_right = encrypt_u64(11, &public_key, &mut rng);

    // Masks are F_k(H(S, ct)). Different ciphertexts ⇒ different digests.
    let mask_left = prf_keys[0].mask(&reconstructing, &ct_left)?;
    let mask_right = prf_keys[0].mask(&reconstructing, &ct_right)?;
    assert_ne!(
        mask_left.coefficients(),
        mask_right.coefficients(),
        "party 1 must get a different mask for each ciphertext"
    );
    println!("Party 1 PRF masks for the two ciphertexts differ.");

    let left = decrypt_one(
        &manager,
        &ct_left,
        &sk_aggregates,
        &reconstructing,
        &prf_keys,
        &generator,
        &mut rng,
    );
    let right = decrypt_one(
        &manager,
        &ct_right,
        &sk_aggregates,
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
