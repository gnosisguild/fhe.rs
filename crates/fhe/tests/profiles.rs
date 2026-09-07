//! Regression tests for the shared parameter profiles.

#[path = "../support/mod.rs"]
mod support;

use fhe::trbfv::{Lambda, SmudgingBoundCalculator, SmudgingBoundCalculatorConfig};
use num_bigint::BigUint;

#[test]
fn insecure_profile_matches_supplied_512_parameters() {
    let preset = support::insecure().unwrap();
    assert_eq!(preset.parameters.degree(), 512);
    assert_eq!(preset.parameters.plaintext(), 100);
    assert_eq!(preset.parameters.moduli(), &[0xffffee001, 0xffffc4001]);
    assert_eq!(preset.parameters.variance(), 10);
    assert_eq!(preset.parameters.get_error1_variance().to_string(), "3");
    assert_eq!(preset.num_parties, 5);
    assert_eq!(preset.threshold, 2);
    assert_eq!(preset.lambda, 2);
    assert_eq!(preset.multiplicative_depth, Some(0));

    let dkg_parameters = preset.share_parameters.as_ref().unwrap();
    assert_eq!(dkg_parameters.degree(), 512);
    assert_eq!(dkg_parameters.plaintext(), 0xffffee001);
    assert_eq!(dkg_parameters.moduli(), &[0x7fffffffe0001]);
    assert_eq!(dkg_parameters.variance(), 3);
    assert_eq!(dkg_parameters.get_error1_variance().to_string(), "10");
}

#[test]
fn secure8192_profile_is_feasible_and_covers_share_moduli() {
    let preset = support::secure8192().unwrap();
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

    let config = SmudgingBoundCalculatorConfig::new(
        preset.parameters.clone(),
        preset.num_parties,
        preset.max_ciphertexts,
        Lambda::secure(preset.lambda).unwrap(),
    )
    .unwrap();
    let bound = SmudgingBoundCalculator::new(config)
        .calculate_sm_bound()
        .unwrap();
    assert_eq!(
        bound,
        BigUint::parse_bytes(b"132922799578495921427264261134328266752000000", 10).unwrap()
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
    let preset = support::secure16384().unwrap();
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

    let config = SmudgingBoundCalculatorConfig::new_multiplicative(
        preset.parameters.clone(),
        preset.num_parties,
        preset.max_ciphertexts,
        preset.multiplicative_depth.unwrap(),
        Lambda::secure(preset.lambda).unwrap(),
    )
    .unwrap();
    let bound = SmudgingBoundCalculator::new(config)
        .with_accepted_participant_count(preset.num_parties)
        .calculate_sm_bound()
        .unwrap();
    assert!(bound > BigUint::from(0_u64));

    assert!(
        preset
            .parameters
            .moduli()
            .iter()
            .all(|&modulus| { modulus <= preset.share_parameters.as_ref().unwrap().plaintext() })
    );
}
