//! Regression tests for the shared parameter profiles.

#[path = "../support/mod.rs"]
mod support;

use fhe::trbfv::{FreshNoiseModel, SmudgingConfig, SmudgingNoiseGenerator};
use num_bigint::BigUint;

#[test]
fn insecure_profile_matches_supplied_128_parameters() {
    let preset = support::presets::insecure().unwrap();
    assert_eq!(preset.parameters.degree(), 128);
    assert_eq!(preset.parameters.plaintext(), 100);
    assert_eq!(
        preset.parameters.moduli(),
        &[
            0x00ff_ffff_ffff_c601,
            0x00ff_ffff_ffff_c301,
            0x00ff_ffff_ffff_a501,
        ]
    );
    assert_eq!(preset.parameters.variance(), 10);
    assert_eq!(
        preset.parameters.get_error1_variance().to_string(),
        "50471587840"
    );
    assert_eq!(preset.num_parties, 19);
    assert_eq!(preset.threshold, 9);
    assert_eq!(preset.lambda, 2);
    assert_eq!(preset.multiplicative_depth, Some(3));

    let share_parameters = preset.share_parameters.as_ref().unwrap();
    assert_eq!(share_parameters.degree(), 128);
    assert_eq!(share_parameters.plaintext(), 72_057_594_037_913_089);
    assert_eq!(
        share_parameters.moduli(),
        &[0x01ff_ffff_ffff_9001, 0x01ff_ffff_ffff_9501]
    );
    assert_eq!(share_parameters.variance(), 10);
}

#[test]
fn secure8192_profile_is_feasible_and_covers_share_moduli() {
    let preset = support::presets::secure8192().unwrap();
    assert_eq!(preset.parameters.degree(), 8192);
    assert_eq!(preset.parameters.plaintext(), 1_000_000);
    assert_eq!(
        preset.parameters.moduli(),
        &[0x0400000000c00001, 0x0400000000a40001, 0x0400000000990001]
    );
    assert_eq!(
        preset.parameters.get_error1_variance().to_string(),
        "17723039943798878305460955570711717478400"
    );
    assert_eq!(preset.num_parties, 20);
    assert_eq!(preset.threshold, 9);
    assert_eq!(preset.lambda, 45);
    assert_eq!(preset.multiplicative_depth, None);

    // The profile check pins the exact bound of the BFV public-key model,
    // the library path the threshold profile's ciphertexts use.
    let config = SmudgingConfig::new(
        preset.parameters.clone(),
        preset.num_parties,
        preset.max_ciphertexts,
        preset.lambda,
        FreshNoiseModel::BfvPublicKey,
    )
    .unwrap();
    let bound = SmudgingNoiseGenerator::new(config)
        .unwrap()
        .smudging_bound()
        .clone();
    assert_eq!(
        bound,
        BigUint::parse_bytes(b"132922799578495921427264261134328266752000000", 10).unwrap()
    );

    // The l-BFV public-key model widens the encryption-randomness support to
    // 2 * variance, which is still feasible for this profile and
    // pins the model-dependent arithmetic exactly.
    let lbfv_bound = SmudgingNoiseGenerator::new(
        SmudgingConfig::new(
            preset.parameters.clone(),
            preset.num_parties,
            preset.max_ciphertexts,
            preset.lambda,
            FreshNoiseModel::LbfvPublicKey,
        )
        .unwrap(),
    )
    .unwrap()
    .smudging_bound()
    .clone();
    assert_eq!(
        lbfv_bound,
        BigUint::parse_bytes(b"132922799578531811412534070437952356352000000", 10).unwrap()
    );
    assert!(
        lbfv_bound > bound,
        "l-BFV model must widen the smudging bound"
    );

    assert!(
        preset
            .parameters
            .moduli()
            .iter()
            .all(|&modulus| { modulus <= preset.share_parameters.as_ref().unwrap().plaintext() })
    );
}

#[test]
fn secure16384_profile_is_feasible_and_covers_share_moduli() {
    let preset = support::presets::secure16384().unwrap();
    assert_eq!(preset.parameters.degree(), 16384);
    assert_eq!(preset.parameters.plaintext(), 1_000);
    assert_eq!(
        preset.parameters.moduli(),
        &[
            0x00040000009f0001,
            0x00040000008a0001,
            0x0004000000800001,
            0x00040000007e0001,
            0x0004000000750001,
        ]
    );
    assert_eq!(
        preset.parameters.get_error1_variance().to_string(),
        "264093875047547791978479834453333"
    );
    assert_eq!(preset.num_parties, 20);
    assert_eq!(preset.threshold, 9);
    assert_eq!(preset.lambda, 31);
    assert_eq!(preset.multiplicative_depth, Some(3));

    // This profile backs both multiplication examples: depth-1+ circuits
    // encrypted with the MBFV-aggregated BFV public key and with the
    // distributed l-BFV public key. Both fresh-noise models must stay
    // feasible at the profile's depth.
    for model in [
        FreshNoiseModel::BfvPublicKey,
        FreshNoiseModel::LbfvPublicKey,
    ] {
        let config = SmudgingConfig::new(
            preset.parameters.clone(),
            preset.num_parties,
            preset.max_ciphertexts,
            preset.lambda,
            model,
        )
        .unwrap()
        .with_mult_depth(preset.multiplicative_depth.unwrap());
        let bound = SmudgingNoiseGenerator::new(config)
            .unwrap()
            .smudging_bound()
            .clone();
        assert!(bound > BigUint::from(0_u64));
    }

    assert!(
        preset
            .parameters
            .moduli()
            .iter()
            .all(|&modulus| { modulus <= preset.share_parameters.as_ref().unwrap().plaintext() })
    );
}
