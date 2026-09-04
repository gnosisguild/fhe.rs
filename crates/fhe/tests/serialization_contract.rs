//! Dedicated serialization round-trip and malformed-input coverage.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

#[path = "support/insecure.rs"]
mod insecure;
#[path = "support/testkit.rs"]
mod testkit;

use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, CommonRandomPoly, CommonRandomPolyVec,
    Encoding, Plaintext, PublicKey, SecretKey,
};
use fhe::lbfv::{LBFVPublicKey, LBFVRelinearizationKey};
use fhe::trlbfv::{ContributionBinding, ParticipantSet, PublicKeyShare, RelinKeyShare};
use fhe_traits::{Deserialize, DeserializeParametrized, FheEncoder, FheEncrypter, Serialize};

#[test]
fn representative_objects_round_trip_through_protobuf() {
    let params = insecure::parameters();
    let mut rng = testkit::rng(61);
    let parameter_bytes = params.to_bytes();
    assert_eq!(
        BfvParameters::try_deserialize(&parameter_bytes).unwrap(),
        *params
    );

    let sk = SecretKey::random(&params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);
    let plaintext = Plaintext::try_encode(&[9_u64], Encoding::poly(), &params).unwrap();
    let ciphertext = pk.try_encrypt(&plaintext, &mut rng).unwrap();
    let ciphertext_bytes = ciphertext.to_bytes();
    assert_eq!(
        Ciphertext::from_bytes(&ciphertext_bytes, &params).unwrap(),
        ciphertext
    );
    assert_eq!(PublicKey::from_bytes(&pk.to_bytes(), &params).unwrap(), pk);

    let crp = CommonRandomPoly::new_deterministic(&params, testkit::seed(62)).unwrap();
    assert_eq!(
        CommonRandomPoly::deserialize(&crp.to_bytes(), &params).unwrap(),
        crp
    );
}

#[test]
fn lbfv_keys_round_trip_and_reject_malformed_or_mismatched_inputs() {
    let params = insecure::parameters();
    let other_params = BfvParametersBuilder::new()
        .set_degree(64)
        .set_plaintext_modulus(1153)
        .set_moduli_sizes(&[40, 40])
        .build_arc()
        .unwrap();
    let mut rng = testkit::rng(63);
    let sk = SecretKey::random(&params, &mut rng);
    let crp_a = CommonRandomPolyVec::from_seed(&params, testkit::seed(64)).unwrap();
    let crp_d1 = CommonRandomPolyVec::from_seed(&params, testkit::seed(65)).unwrap();
    let pk = LBFVPublicKey::new_with_crp(&sk, &crp_a, &mut rng).unwrap();
    let rlk = LBFVRelinearizationKey::new_with_crp(&sk, &pk, &crp_d1, &mut rng).unwrap();

    assert_eq!(
        LBFVPublicKey::from_bytes(&pk.to_bytes(), &params).unwrap(),
        pk
    );
    assert_eq!(
        LBFVRelinearizationKey::from_bytes(&rlk.to_bytes(), &params).unwrap(),
        rlk
    );

    let participant_set = ParticipantSet::new(testkit::seed(67), vec![1]).unwrap();
    let binding = ContributionBinding::new(participant_set, 1).unwrap();
    let public_key_share =
        PublicKeyShare::contribute_with_crp_and_binding(&sk, &crp_a, binding.clone(), &mut rng)
            .unwrap();
    let relin_key_share = RelinKeyShare::contribution_with_crp_and_binding(
        &sk, &crp_d1, &crp_a, binding, 0, 0, &mut rng,
    )
    .unwrap();
    assert_eq!(
        PublicKeyShare::from_bytes(&public_key_share.to_bytes(), &params).unwrap(),
        public_key_share
    );
    assert_eq!(
        RelinKeyShare::from_bytes(&relin_key_share.to_bytes(), &params).unwrap(),
        relin_key_share
    );
    assert!(LBFVPublicKey::from_bytes(&pk.to_bytes(), &other_params).is_err());
    assert!(LBFVRelinearizationKey::from_bytes(&rlk.to_bytes(), &other_params).is_err());

    let public_key_bytes = pk.to_bytes();
    let truncated_public_key = &public_key_bytes[..public_key_bytes.len() / 2];
    assert!(LBFVPublicKey::from_bytes(truncated_public_key, &params).is_err());
    assert!(LBFVRelinearizationKey::from_bytes(&[0xff], &params).is_err());
}

#[test]
fn ciphertext_deserialization_rejects_truncation_and_parameter_mismatch() {
    let params = insecure::parameters();
    let other_params = BfvParametersBuilder::new()
        .set_degree(64)
        .set_plaintext_modulus(1153)
        .set_moduli_sizes(&[40, 40])
        .build_arc()
        .unwrap();
    let mut rng = testkit::rng(66);
    let sk = SecretKey::random(&params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);
    let plaintext = Plaintext::try_encode(&[13_u64], Encoding::poly(), &params).unwrap();
    let ciphertext = pk.try_encrypt(&plaintext, &mut rng).unwrap();
    let bytes = ciphertext.to_bytes();

    assert!(Ciphertext::from_bytes(&bytes, &other_params).is_err());
    let truncated_ciphertext = &bytes[..bytes.len() / 2];
    assert!(Ciphertext::from_bytes(truncated_ciphertext, &params).is_err());
    assert!(Ciphertext::from_bytes(&[0xff], &params).is_err());
}
