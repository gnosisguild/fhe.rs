//! Smoke coverage for a repository-selected BFV 128-bit profile.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

#[path = "support/testkit.rs"]
mod testkit;

use fhe::bfv::{BfvParameters, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};

#[test]
fn default_128_profile_supports_bfv_addition() {
    let params = BfvParameters::default_parameters_128(20)
        .unwrap()
        .nth(2)
        .expect("the selected standard-128 profile must exist");
    let mut rng = testkit::rng(71);
    let sk = SecretKey::random(&params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);
    let left = Plaintext::try_encode(&[17_u64], Encoding::poly(), &params).unwrap();
    let right = Plaintext::try_encode(&[25_u64], Encoding::poly(), &params).unwrap();
    let sum =
        &pk.try_encrypt(&left, &mut rng).unwrap() + &pk.try_encrypt(&right, &mut rng).unwrap();
    let decoded = Vec::<u64>::try_decode(&sk.try_decrypt(&sum).unwrap(), Encoding::poly()).unwrap();

    assert_eq!(decoded[0], 42, "standard-128 seed=71 BFV addition failed");
}
