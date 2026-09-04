//! Public TRBFV contract tests across named parameter profiles.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/standard_8192.rs"]
mod standard_8192;
#[path = "support/toy.rs"]
mod toy;

use std::sync::Arc;

use fhe::bfv::Ciphertext;
use fhe::trbfv::{Lambda, SmudgingBoundCalculator, SmudgingBoundCalculatorConfig, TRBFV};
use fhe::{Error, ThresholdError};
use fhe_math::rq::{Poly, PowerBasis};
use num_traits::Zero;
#[derive(Clone)]
struct TrbfvProfile {
    name: &'static str,
    parameters: Arc<fhe::bfv::BfvParameters>,
    num_parties: usize,
    threshold: usize,
    lambda: usize,
    max_ciphertexts: usize,
    multiplicative_depth: Option<u32>,
}

fn profiles() -> [TrbfvProfile; 2] {
    [
        TrbfvProfile {
            name: "toy",
            parameters: toy::parameters(),
            num_parties: 3,
            threshold: 1,
            lambda: 35,
            max_ciphertexts: 1,
            multiplicative_depth: Some(1),
        },
        TrbfvProfile {
            name: "standard-8192",
            parameters: standard_8192::parameters(),
            num_parties: 20,
            threshold: 9,
            lambda: 50,
            max_ciphertexts: 50,
            multiplicative_depth: None,
        },
    ]
}

#[test]
fn named_profiles_match_threshold_contract() {
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

        let trbfv = TRBFV::new(
            profile.num_parties,
            profile.threshold,
            profile.parameters.clone(),
        )
        .unwrap();
        assert_eq!(trbfv.n, profile.num_parties);
        assert_eq!(trbfv.threshold, profile.threshold);
    }
}

#[test]
fn named_profiles_have_feasible_smudging_bounds() {
    for profile in profiles() {
        let lambda = Lambda::secure(profile.lambda).unwrap();
        let config = match profile.multiplicative_depth {
            Some(depth) => SmudgingBoundCalculatorConfig::new_multiplicative(
                profile.parameters.clone(),
                profile.num_parties,
                profile.max_ciphertexts,
                depth,
                lambda,
            )
            .unwrap(),
            None => SmudgingBoundCalculatorConfig::new(
                profile.parameters.clone(),
                profile.num_parties,
                profile.max_ciphertexts,
                lambda,
            )
            .unwrap(),
        };

        let bound = SmudgingBoundCalculator::new(config)
            .calculate_sm_bound()
            .unwrap();
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
    let trbfv = TRBFV::new(
        profile.num_parties,
        profile.threshold,
        profile.parameters.clone(),
    )
    .unwrap();
    let ctx = profile.parameters.context_at_level(0).unwrap();
    let share = || Poly::<PowerBasis>::zero(ctx);
    let ciphertext = Arc::new(Ciphertext::zero(&profile.parameters));

    let too_few = trbfv
        .decrypt(vec![share()], vec![1], ciphertext.clone())
        .unwrap_err();
    assert!(matches!(
        too_few,
        Error::Threshold(ThresholdError::ShareCountMismatch {
            actual: 1,
            expected: 2
        })
    ));

    let duplicate = trbfv
        .decrypt(vec![share(), share()], vec![1, 1], ciphertext.clone())
        .unwrap_err();
    assert!(matches!(
        duplicate,
        Error::Threshold(ThresholdError::DuplicatePartyId { party_id: 1 })
    ));

    let zero_id = trbfv
        .decrypt(vec![share(), share()], vec![0, 2], ciphertext)
        .unwrap_err();
    assert!(matches!(
        zero_id,
        Error::Threshold(ThresholdError::InvalidPartyId { party_id: 0, n: 3 })
    ));
}
