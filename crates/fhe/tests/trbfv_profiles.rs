//! Threshold BFV (trBFV) profile and input-validation tests.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../support/mod.rs"]
mod support;

use fhe::bfv::Ciphertext;
use fhe::trbfv::{ShareManager, SmudgingConfig, SmudgingNoiseGenerator};
use fhe::{Error, ThresholdError};
use fhe_math::rq::{Poly, PowerBasis};
use num_traits::Zero;
use std::sync::Arc;
use support::Preset;

fn profiles() -> [Preset; 3] {
    support::profiles().unwrap()
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
        // above fhe::trbfv::smudging::MAX_LAMBDA.
        let lambda = profile.lambda;
        let config = match profile.multiplicative_depth {
            Some(depth) => {
                let mut config = SmudgingConfig::new(
                    profile.parameters.clone(),
                    profile.num_parties,
                    profile.max_ciphertexts,
                    lambda,
                )
                .unwrap();
                config.mult_depth = depth;
                config
            }
            None => SmudgingConfig::new(
                profile.parameters.clone(),
                profile.num_parties,
                profile.max_ciphertexts,
                lambda,
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
    let ctx = profile.parameters.context_at_level(0).unwrap();
    let share = || Poly::<PowerBasis>::zero(ctx);
    let ciphertext = Arc::new(Ciphertext::zero(&profile.parameters));

    let too_few = manager
        .decrypt_from_shares(vec![share()], vec![1], ciphertext.clone())
        .unwrap_err();
    assert!(matches!(
        too_few,
        Error::Threshold(ThresholdError::ShareCountMismatch {
            actual: 1,
            expected
        }) if expected == profile.threshold + 1
    ));

    let duplicate = manager
        .decrypt_from_shares(
            vec![share(), share(), share()],
            vec![1, 1, 2],
            ciphertext.clone(),
        )
        .unwrap_err();
    assert!(matches!(
        duplicate,
        Error::Threshold(ThresholdError::DuplicatePartyId { party_id: 1 })
    ));

    let zero_id =
        manager.decrypt_from_shares(vec![share(), share(), share()], vec![0, 2, 3], ciphertext);
    assert!(matches!(
        zero_id.unwrap_err(),
        Error::Threshold(ThresholdError::InvalidPartyId { party_id: 0, n })
            if n == profile.num_parties
    ));
}
