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
use fhe_traits::{Deserialize, DeserializeParametrized, FheEncoder, FheEncrypter, Serialize};

#[test]
fn representative_objects_round_trip_through_protobuf() {
    let params = support::insecure().unwrap().parameters;
    let mut rng = support::rng(61);
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

    let crp = CommonRandomPoly::new_deterministic(&params, support::seed(62)).unwrap();
    assert_eq!(
        CommonRandomPoly::deserialize(&crp.to_bytes(), &params).unwrap(),
        crp
    );
}

#[test]
fn secure_profiles_preserve_error1_variance_through_protobuf() {
    for profile in support::profiles().unwrap().into_iter().skip(1) {
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
    let params = support::insecure().unwrap().parameters;
    let other_params = BfvParametersBuilder::new()
        .set_degree(64)
        .set_plaintext_modulus(1153)
        .set_moduli_sizes(&[40, 40])
        .build_arc()
        .unwrap();
    let mut rng = support::rng(63);
    let sk = SecretKey::random(&params, &mut rng);
    let crp_a = CommonRandomPolyVec::from_seed(&params, support::seed(64)).unwrap();
    let crp_d1 = CommonRandomPolyVec::from_seed(&params, support::seed(65)).unwrap();
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

    let public_key_share = PublicKeyShare::contribute_with_crp(&sk, &crp_a, &mut rng).unwrap();
    let relin_key_share =
        RelinKeyShare::contribution_with_crp(&sk, &crp_d1, &crp_a, 0, 0, &mut rng).unwrap();
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
    let params = support::insecure().unwrap().parameters;
    let other_params = BfvParametersBuilder::new()
        .set_degree(64)
        .set_plaintext_modulus(1153)
        .set_moduli_sizes(&[40, 40])
        .build_arc()
        .unwrap();
    let mut rng = support::rng(66);
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
fn smudging_owners_round_trip_through_transport_boundary() {
    use fhe::trbfv::{
        AggregatedSmudgingShare, Lambda, MIN_SECURE_LAMBDA, ShareManager, SmudgingShare, TRBFV,
    };

    for profile in support::profiles().unwrap() {
        let trbfv = TRBFV::new(
            profile.num_parties,
            profile.threshold,
            profile.parameters.clone(),
        )
        .unwrap();
        let lambda = if profile.lambda < MIN_SECURE_LAMBDA {
            Lambda::insecure(profile.lambda)
        } else {
            Lambda::secure(profile.lambda).unwrap()
        };
        let mult_depth = profile.multiplicative_depth.unwrap_or(0);
        let mut rng = support::rng(71);
        let mut manager = ShareManager::new(
            profile.num_parties,
            profile.threshold,
            profile.parameters.clone(),
        )
        .unwrap();

        let noise = trbfv
            .generate_smudging_error(profile.max_ciphertexts, mult_depth, lambda, &mut rng)
            .unwrap();
        let shares = manager.deal_smudging_noise(noise, &mut rng).unwrap();
        assert_eq!(shares.len(), profile.num_parties);

        // Share round-trip: re-exporting the imported share must reproduce
        // the exact payload bytes.
        let mut shares = shares.into_iter();
        let first = shares.next().unwrap();
        let share_bytes = first.export(&profile.parameters).unwrap();
        let imported = SmudgingShare::from_bytes(&share_bytes, &profile.parameters).unwrap();
        assert_eq!(
            imported.export(&profile.parameters).unwrap(),
            share_bytes,
            "profile {} share round-trip must preserve bytes",
            profile.name
        );

        // Aggregate round-trip over the remaining shares.
        let aggregate = manager.aggregate_smudging_shares(shares.collect()).unwrap();
        let aggregate_bytes = aggregate.export();
        let imported_aggregate =
            AggregatedSmudgingShare::from_bytes(&aggregate_bytes, &profile.parameters).unwrap();
        assert_eq!(
            imported_aggregate.export(),
            aggregate_bytes,
            "profile {} aggregate round-trip must preserve bytes",
            profile.name
        );
    }
}

#[test]
fn smudging_transport_rejects_truncation_and_parameter_mismatch() {
    use fhe::trbfv::{Lambda, ShareManager, SmudgingShare, TRBFV};

    let profile = support::insecure().unwrap();
    let other_params = support::secure8192().unwrap().parameters;
    let trbfv = TRBFV::new(
        profile.num_parties,
        profile.threshold,
        profile.parameters.clone(),
    )
    .unwrap();
    let mut rng = support::rng(72);
    let mut manager = ShareManager::new(
        profile.num_parties,
        profile.threshold,
        profile.parameters.clone(),
    )
    .unwrap();
    let noise = trbfv
        .generate_smudging_error(
            profile.max_ciphertexts,
            0,
            Lambda::insecure(profile.lambda),
            &mut rng,
        )
        .unwrap();
    let share = manager
        .deal_smudging_noise(noise, &mut rng)
        .unwrap()
        .remove(0);
    let bytes = share.export(&profile.parameters).unwrap();

    assert!(SmudgingShare::from_bytes(&bytes, &other_params).is_err());
    let truncated = &bytes[..bytes.len() / 2];
    assert!(SmudgingShare::from_bytes(truncated, &profile.parameters).is_err());
    assert!(SmudgingShare::from_bytes(&[0xff], &profile.parameters).is_err());
}
