//! Serialization round-trip and malformed-input coverage.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

#[path = "../support/mod.rs"]
mod support;

use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, CommonRandomPoly, CommonRandomPolyVec,
    Encoding, Plaintext, PublicKey, SecretKey,
};
use fhe::lbfv::{LBFVPublicKey, LBFVRelinearizationKey};
use fhe::trlbfv::{PublicKeyShare, RelinKeyShare};
use fhe_traits::{
    Deserialize, DeserializeParametrized, FheEncoder, FheEncrypter, MAX_SERIALIZED_BYTES, Serialize,
};

#[test]
fn representative_objects_round_trip_through_protobuf() {
    let params = support::presets::insecure().unwrap().parameters;
    let mut rng = support::presets::rng(61);
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

    let crp = CommonRandomPoly::new_deterministic(&params, support::presets::seed(62)).unwrap();
    assert_eq!(
        CommonRandomPoly::deserialize(&crp.to_bytes(), &params).unwrap(),
        crp
    );
}

#[test]
fn secure_profiles_preserve_error1_variance_through_protobuf() {
    for profile in support::presets::profiles().unwrap().into_iter().skip(1) {
        let expected_error1_variance = profile.parameters.get_error1_variance().clone();
        let decoded = BfvParameters::try_deserialize(&profile.parameters.to_bytes()).unwrap();

        assert_eq!(
            decoded, *profile.parameters,
            "profile {} must preserve all serialized parameters",
            profile.name
        );
        assert_eq!(
            decoded.get_error1_variance(),
            &expected_error1_variance,
            "profile {} must preserve its custom error1 variance",
            profile.name
        );
    }
}

#[test]
fn lbfv_keys_round_trip_and_reject_malformed_or_mismatched_inputs() {
    let params = support::presets::insecure().unwrap().parameters;
    let other_params = BfvParametersBuilder::new()
        .set_degree(64)
        .set_plaintext_modulus(1153)
        .set_moduli_sizes(&[40, 40])
        .build_arc()
        .unwrap();
    let mut rng = support::presets::rng(63);
    let sk = SecretKey::random(&params, &mut rng);
    let crp_a = CommonRandomPolyVec::from_seed(&params, support::presets::seed(64)).unwrap();
    let crp_d1 = CommonRandomPolyVec::from_seed(&params, support::presets::seed(65)).unwrap();
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
    let reconstructed_pk = rlk.reconstruct_public_key().unwrap();
    assert_eq!(reconstructed_pk.parameters(), pk.parameters());
    assert_eq!(reconstructed_pk.row_count(), pk.row_count());
    assert!(
        pk.rows()
            .iter()
            .zip(reconstructed_pk.rows())
            .all(|(left, right)| left.level == right.level && left.iter().eq(right.iter()))
    );
    // With verified seed metadata preserved, the reconstruction is fully
    // equal to the input key — concrete rows and seed metadata alike.
    assert_eq!(reconstructed_pk, pk);

    let public_key_share = PublicKeyShare::contribute_with_crp(&sk, &crp_a, &mut rng).unwrap();
    let relin_key_share =
        RelinKeyShare::contribute_with_crp(&sk, &crp_d1, &crp_a, 0, 0, &mut rng).unwrap();
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

/// Verified seed metadata must shrink the wire format at level 0: the seeded
/// CRP-built operational relinearization key omits the concrete URS/CRS rows
/// the explicit equivalent must carry, for identical polynomial material.
#[test]
fn seeded_crp_keys_serialize_smaller_than_explicit_equivalents() {
    let params = support::presets::insecure().unwrap().parameters;
    let mut rng = support::presets::rng(67);
    let sk = SecretKey::random(&params, &mut rng);

    let crp_a = CommonRandomPolyVec::from_seed(&params, support::presets::seed(68)).unwrap();
    let crp_d1 = CommonRandomPolyVec::from_seed(&params, support::presets::seed(69)).unwrap();
    // Same concrete rows without seed metadata.
    let crp_d1_seedless =
        CommonRandomPolyVec::from_polys(&params, crp_d1.to_polys(), None).unwrap();

    let pk = LBFVPublicKey::new_with_crp(&sk, &crp_a, &mut rng).unwrap();
    let pk_seedless = LBFVPublicKey::from_parts(
        pk.rows().iter().map(|row| row[0].clone()).collect(),
        pk.rows().iter().map(|row| row[1].clone()).collect(),
        params.clone(),
        None,
    )
    .unwrap();

    // Identical rng streams: any difference between the two keys is then
    // attributable to the representation, not the randomness.
    let seeded_key = LBFVRelinearizationKey::new_leveled_with_crp(
        &sk,
        &pk,
        &crp_d1,
        0,
        0,
        &mut support::presets::rng(70),
    )
    .unwrap();
    let explicit_key = LBFVRelinearizationKey::new_leveled_with_crp(
        &sk,
        &pk_seedless,
        &crp_d1_seedless,
        0,
        0,
        &mut support::presets::rng(70),
    )
    .unwrap();

    // Same polynomial material, different representation.
    assert_eq!(seeded_key.d0_components(), explicit_key.d0_components());
    assert_eq!(seeded_key.d1_components(), explicit_key.d1_components());
    assert_eq!(seeded_key.a_components(), explicit_key.a_components());
    assert_eq!(seeded_key.b_components(), explicit_key.b_components());
    assert_eq!(seeded_key.reconstruct_public_key().unwrap(), pk);

    let seeded_size = seeded_key.to_bytes().len();
    let explicit_size = explicit_key.to_bytes().len();
    assert!(
        seeded_size < explicit_size,
        "seeded operational RLK ({seeded_size} bytes) must serialize smaller than the explicit equivalent ({explicit_size} bytes)"
    );

    // Both representations round-trip.
    assert_eq!(
        LBFVRelinearizationKey::from_bytes(&seeded_key.to_bytes(), &params).unwrap(),
        seeded_key
    );
    assert_eq!(
        LBFVRelinearizationKey::from_bytes(&explicit_key.to_bytes(), &params).unwrap(),
        explicit_key
    );
}

#[test]
fn ciphertext_deserialization_rejects_truncation_and_parameter_mismatch() {
    let params = support::presets::insecure().unwrap().parameters;
    let other_params = BfvParametersBuilder::new()
        .set_degree(64)
        .set_plaintext_modulus(1153)
        .set_moduli_sizes(&[40, 40])
        .build_arc()
        .unwrap();
    let mut rng = support::presets::rng(66);
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

#[test]
fn evaluation_keys_roundtrip_through_the_default_and_bounded_routes() {
    use fhe::bfv::{EvaluationKey, EvaluationKeyBuilder};

    let params = support::presets::insecure().unwrap().parameters;
    let mut rng = support::presets::rng(71);
    let sk = SecretKey::random(&params, &mut rng);
    let evaluation_key = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)
        .unwrap()
        .enable_inner_sum()
        .unwrap()
        .build(&mut rng)
        .unwrap();
    let bytes = evaluation_key.to_bytes();

    assert_eq!(
        EvaluationKey::from_bytes(&bytes, &params).unwrap(),
        evaluation_key
    );
    assert_eq!(
        EvaluationKey::from_bytes_with_limit(&bytes, &params, usize::MAX).unwrap(),
        evaluation_key
    );
    assert_eq!(
        EvaluationKey::from_bytes_with_limit(&bytes, &params, bytes.len()).unwrap(),
        evaluation_key
    );

    // The caller-supplied bound applies before any decoding work.
    let error = EvaluationKey::from_bytes_with_limit(&bytes, &params, bytes.len() - 1).unwrap_err();
    assert!(matches!(
        error,
        fhe::Error::SerializationError(fhe::SerializationError::PayloadTooLarge { .. })
    ));
    assert!(matches!(
        EvaluationKey::from_bytes_with_limit(&bytes, &params, 0).unwrap_err(),
        fhe::Error::SerializationError(fhe::SerializationError::PayloadTooLarge { .. })
    ));
}

/// The default deserialize route must keep the global 256 MiB cap, while the
/// bounded opt-in route admits the same length under its hard ceiling. The
/// oversized buffer is lazily backed by zero pages, so this check verifies
/// the size policy without committing that memory; the end-to-end roundtrip
/// of the real ~309 MB key is an ignored unit test on
/// `EvaluationKey` (`oversized_evaluation_key_roundtrips_through_the_opt_in_route`).
#[test]
fn default_cap_rejects_large_evaluation_keys_and_the_opt_in_ceiling_admits_the_length() {
    use fhe::bfv::EvaluationKey;

    let params = support::presets::insecure().unwrap().parameters;
    let oversized = vec![0u8; MAX_SERIALIZED_BYTES + 1];

    let error = EvaluationKey::from_bytes(&oversized, &params).unwrap_err();
    assert!(matches!(
        error,
        fhe::Error::SerializationError(fhe::SerializationError::PayloadTooLarge { .. })
    ));

    let error = EvaluationKey::from_bytes_with_limit(&oversized, &params, usize::MAX).unwrap_err();
    assert!(!matches!(
        error,
        fhe::Error::SerializationError(fhe::SerializationError::PayloadTooLarge { .. })
    ));
}
