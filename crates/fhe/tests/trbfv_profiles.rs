//! Threshold BFV (trBFV) profile and input-validation tests.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../support/mod.rs"]
mod support;

use fhe::bfv::Ciphertext;
use fhe::trbfv::{FreshNoiseModel, ShareManager, SmudgingConfig, SmudgingNoiseGenerator};
use fhe::{Error, ThresholdError};
use num_traits::Zero;
use std::sync::Arc;
use support::presets::Preset;

fn profiles() -> [Preset; 3] {
    support::presets::profiles().unwrap()
}

#[test]
fn profiles_match_threshold_configuration() {
    for profile in profiles() {
        assert_eq!(
            profile.threshold,
            (profile.num_parties - 1) / 2,
            "profile {} must use the documented honest-majority threshold",
            profile.name
        );
        assert!(
            profile.parameters.moduli().len() >= 2,
            "profile {} must have an RNS modulus chain",
            profile.name
        );

        let manager = ShareManager::new(
            profile.num_parties,
            profile.threshold,
            profile.parameters.clone(),
        )
        .unwrap();
        assert_eq!(manager.n(), profile.num_parties);
        assert_eq!(manager.threshold(), profile.threshold);

        if let Some(share_parameters) = profile.share_parameters {
            assert_eq!(
                share_parameters.degree(),
                profile.parameters.degree(),
                "profile {} share transport must use the same ring degree",
                profile.name
            );
        }
    }
}

#[test]
fn named_profiles_have_feasible_smudging_bounds() {
    for profile in profiles() {
        // Lambda is caller-chosen policy; the library only rejects values
        // above fhe::trbfv::smudging::MAX_LAMBDA. The BFV public-key model is
        // the profile check's baseline encryption path; the l-BFV model is
        // covered by the secure16384 profile check in profiles.rs.
        let lambda = profile.lambda;
        let model = FreshNoiseModel::BfvPublicKey;
        let config = match profile.multiplicative_depth {
            Some(depth) => SmudgingConfig::new(
                profile.parameters.clone(),
                profile.num_parties,
                profile.max_ciphertexts,
                lambda,
                model,
            )
            .unwrap()
            .with_mult_depth(depth),
            None => SmudgingConfig::new(
                profile.parameters.clone(),
                profile.num_parties,
                profile.max_ciphertexts,
                lambda,
                model,
            )
            .unwrap(),
        };

        let generator = SmudgingNoiseGenerator::new(config).unwrap();
        let bound = generator.smudging_bound();
        assert!(
            !bound.is_zero(),
            "profile {} must produce a non-zero smudging bound",
            profile.name
        );
    }
}

#[test]
fn reconstruction_rejects_invalid_public_inputs() {
    let profile = profiles()[0].clone();
    let manager = ShareManager::new(
        profile.num_parties,
        profile.threshold,
        profile.parameters.clone(),
    )
    .unwrap();
    let ciphertext = Arc::new(Ciphertext::zero(&profile.parameters));

    let too_few = manager.decrypt_from_shares(&[], &ciphertext).unwrap_err();
    assert!(matches!(
        too_few,
        Error::Threshold(ThresholdError::ShareCountMismatch {
            actual: 0,
            expected
        }) if expected == profile.threshold + 1
    ));
}
