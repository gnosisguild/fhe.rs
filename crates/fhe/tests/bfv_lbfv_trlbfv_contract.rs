//! Shared profile coverage for BFV, LBFV, and threshold LBFV.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

#[path = "support/insecure.rs"]
mod insecure;
#[path = "support/secure8192.rs"]
mod secure8192;
#[path = "support/secure_16384.rs"]
mod secure_16384;
#[path = "support/testkit.rs"]
mod testkit;

use std::sync::Arc;

use fhe::aggregate::AggregateIter;
use fhe::bfv::{BfvParameters, CommonRandomPolyVec, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::lbfv::{LBFVPublicKey, LBFVRelinearizationKey};
use fhe::trlbfv::{AggregatedPublicKey, ContributionBinding, ParticipantSet, PublicKeyShare};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};

struct Profile {
    name: &'static str,
    params: Arc<BfvParameters>,
    share_params: Option<Arc<BfvParameters>>,
    simd: bool,
    seed: u8,
}

fn profiles() -> [Profile; 3] {
    [
        Profile {
            name: "insecure",
            params: insecure::parameters(),
            share_params: None,
            simd: true,
            seed: 11,
        },
        Profile {
            name: "secure8192",
            params: secure8192::parameters(),
            share_params: Some(secure8192::share_encryption_parameters()),
            simd: false,
            seed: 22,
        },
        Profile {
            name: "secure_16384",
            params: secure_16384::parameters(),
            share_params: Some(secure_16384::share_encryption_parameters()),
            simd: false,
            seed: 33,
        },
    ]
}

#[test]
fn named_profiles_expose_complete_context_metadata() {
    for profile in profiles() {
        assert!(
            profile.params.degree().is_power_of_two(),
            "{} seed={} has a non-power-of-two degree",
            profile.name,
            profile.seed
        );
        assert_eq!(
            profile.params.context_levels().len(),
            profile.params.moduli().len(),
            "{} seed={} has an incomplete context chain",
            profile.name,
            profile.seed
        );
        assert_eq!(
            profile.params.max_level() + 1,
            profile.params.moduli().len(),
            "{} seed={} has an invalid maximum level",
            profile.name,
            profile.seed
        );
        assert!(
            profile.params.plaintext_big()
                < &profile
                    .params
                    .moduli()
                    .iter()
                    .fold(num_bigint::BigUint::from(1_u64), |product, modulus| product
                        * *modulus),
            "{} seed={} has plaintext modulus outside Q",
            profile.name,
            profile.seed
        );
        if let Some(share_params) = profile.share_params {
            assert_eq!(
                share_params.degree(),
                profile.params.degree(),
                "{} seed={} share profile has a different ring degree",
                profile.name,
                profile.seed
            );
            let largest_modulus = *profile.params.moduli().iter().max().unwrap();
            assert!(
                share_params.plaintext() >= largest_modulus,
                "{} seed={} share plaintext does not cover the operational modulus",
                profile.name,
                profile.seed
            );
        }
    }
}

#[test]
fn bfv_addition_and_simd_round_trip_use_deterministic_profile() {
    for profile in profiles().into_iter().take(2) {
        let mut rng = testkit::rng(profile.seed);
        let sk = SecretKey::random(&profile.params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let left = Plaintext::try_encode(&[2_u64], Encoding::poly(), &profile.params).unwrap();
        let right = Plaintext::try_encode(&[3_u64], Encoding::poly(), &profile.params).unwrap();
        let sum =
            &pk.try_encrypt(&left, &mut rng).unwrap() + &pk.try_encrypt(&right, &mut rng).unwrap();
        let decoded =
            Vec::<u64>::try_decode(&sk.try_decrypt(&sum).unwrap(), Encoding::poly()).unwrap();
        assert_eq!(
            decoded[0], 5,
            "{} seed={} BFV polynomial addition failed",
            profile.name, profile.seed
        );

        if profile.simd {
            let values = [1_u64, 2, 3, 4];
            let plaintext =
                Plaintext::try_encode(&values, Encoding::simd(), &profile.params).unwrap();
            let ciphertext = pk.try_encrypt(&plaintext, &mut rng).unwrap();
            let decoded =
                Vec::<u64>::try_decode(&sk.try_decrypt(&ciphertext).unwrap(), Encoding::simd())
                    .unwrap();
            assert_eq!(
                &decoded[..values.len()],
                values,
                "{} seed={} BFV SIMD round trip failed",
                profile.name,
                profile.seed
            );
        }
    }
}

#[test]
fn lbfv_multiplication_and_relinearization_round_trip() {
    let profile = profiles().into_iter().next().unwrap();
    let mut rng = testkit::rng(profile.seed);
    let sk = SecretKey::random(&profile.params, &mut rng);
    let crp_a = CommonRandomPolyVec::from_seed(&profile.params, testkit::seed(41)).unwrap();
    let crp_d1 = CommonRandomPolyVec::from_seed(&profile.params, testkit::seed(42)).unwrap();
    let pk = LBFVPublicKey::new_with_crp(&sk, &crp_a, &mut rng).unwrap();
    let rlk = LBFVRelinearizationKey::new_with_crp(&sk, &pk, &crp_d1, &mut rng).unwrap();

    let left = Plaintext::try_encode(&[2_u64], Encoding::poly(), &profile.params).unwrap();
    let right = Plaintext::try_encode(&[3_u64], Encoding::poly(), &profile.params).unwrap();
    let left = pk.try_encrypt(&left, &mut rng).unwrap();
    let right = pk.try_encrypt(&right, &mut rng).unwrap();
    let mut product = &left * &right;
    assert_eq!(product.len(), 3);
    rlk.relinearizes(&mut product).unwrap();
    assert_eq!(product.len(), 2);
    let decoded =
        Vec::<u64>::try_decode(&sk.try_decrypt(&product).unwrap(), Encoding::poly()).unwrap();
    assert_eq!(
        decoded[0], 6,
        "insecure seed={} LBFV multiplication failed",
        profile.seed
    );
}

#[test]
fn trlbfv_bound_aggregation_requires_an_exact_participant_set() {
    let profile = profiles().into_iter().next().unwrap();
    let mut rng = testkit::rng(profile.seed);
    let participant_set = ParticipantSet::new(testkit::seed(51), vec![3, 1, 2]).unwrap();
    let crp = CommonRandomPolyVec::from_seed(&profile.params, testkit::seed(52)).unwrap();
    let secret_keys: Vec<_> = (0..3)
        .map(|_| SecretKey::random(&profile.params, &mut rng))
        .collect();
    let shares: Vec<PublicKeyShare> = secret_keys
        .iter()
        .enumerate()
        .map(|(index, secret_key)| {
            let binding =
                ContributionBinding::new(participant_set.clone(), (index + 1) as u32).unwrap();
            PublicKeyShare::contribute_with_crp_and_binding(secret_key, &crp, binding, &mut rng)
                .unwrap()
        })
        .collect();
    let aggregated: AggregatedPublicKey = shares.clone().into_iter().aggregate().unwrap();
    let reordered: AggregatedPublicKey = shares.clone().into_iter().rev().aggregate().unwrap();
    assert_eq!(reordered.participant_set(), aggregated.participant_set());

    let joint_coeffs: Vec<i64> = (0..profile.params.degree())
        .map(|index| secret_keys.iter().map(|key| key.coeffs[index]).sum())
        .collect();
    let joint_sk = SecretKey::new(joint_coeffs, &profile.params);
    let plaintext = Plaintext::try_encode(&[7_u64], Encoding::poly(), &profile.params).unwrap();
    let ciphertext = aggregated
        .operational()
        .try_encrypt(&plaintext, &mut rng)
        .unwrap();
    assert_eq!(joint_sk.try_decrypt(&ciphertext).unwrap(), plaintext);

    let bad_set = ParticipantSet::new(testkit::seed(53), vec![1, 2, 3]).unwrap();
    let bad_binding = ContributionBinding::new(bad_set, 3).unwrap();
    let bad_share = PublicKeyShare::contribute_with_crp_and_binding(
        &secret_keys[2],
        &crp,
        bad_binding,
        &mut rng,
    )
    .unwrap();
    let inconsistent = vec![shares[0].clone(), shares[1].clone(), bad_share]
        .into_iter()
        .aggregate::<AggregatedPublicKey>();
    assert!(
        inconsistent.is_err(),
        "insecure seed={} accepted mismatched participant sets",
        profile.seed
    );

    let incomplete = shares
        .into_iter()
        .take(2)
        .aggregate::<AggregatedPublicKey>();
    assert!(
        incomplete.is_err(),
        "insecure seed={} accepted an incomplete participant set",
        profile.seed
    );
}

#[test]
fn invalid_profile_configurations_fail_explicitly() {
    assert!(
        fhe::bfv::BfvParametersBuilder::new()
            .set_degree(15)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[40, 40])
            .build()
            .is_err()
    );
    assert!(
        fhe::bfv::BfvParametersBuilder::new()
            .set_degree(64)
            .set_plaintext_modulus(1153)
            .set_moduli(&[41, 41])
            .build()
            .is_err()
    );
}
