//! Regression tests for the parameter sets used by the examples and benches.

use fhe::trbfv::presets;
use fhe::trbfv::{Lambda, SmudgingBoundCalculator, SmudgingBoundCalculatorConfig};
use num_bigint::BigUint;

#[test]
fn secure_8192_matches_the_published_preset() {
    let params = presets::secure_8192_trbfv_parameters().unwrap();
    assert_eq!(params.degree(), 8192);
    assert_eq!(params.plaintext(), 1_000_000);
    assert_eq!(params.moduli(), presets::SECURE_8192_TRBFV_MODULI);
    assert_eq!(
        params.get_error1_variance().to_string(),
        presets::SECURE_8192_ERROR1_VARIANCE
    );

    let config = SmudgingBoundCalculatorConfig::new(
        params,
        presets::SECURE_8192_NUM_PARTIES,
        presets::SECURE_8192_MAX_CIPHERTEXTS,
        Lambda::secure(presets::SECURE_8192_LAMBDA).unwrap(),
    )
    .unwrap();
    let bound = SmudgingBoundCalculator::new(config)
        .calculate_sm_bound()
        .unwrap();
    assert_eq!(
        bound,
        BigUint::parse_bytes(b"132922799578495921427264261134328266752000000", 10).unwrap()
    );
}

#[test]
fn secure_8192_share_parameters_cover_computation_moduli() {
    let params = presets::secure_8192_share_parameters().unwrap();
    assert_eq!(params.degree(), presets::SECURE_8192_DEGREE);
    assert_eq!(
        params.plaintext(),
        presets::SECURE_8192_SHARE_PLAINTEXT_MODULUS
    );
    assert!(
        presets::SECURE_8192_TRBFV_MODULI
            .iter()
            .all(|&modulus| modulus <= params.plaintext())
    );
}

#[test]
fn secure_16384_matches_the_published_preset() {
    let params = presets::secure_16384_lbfv_parameters().unwrap();
    assert_eq!(params.degree(), presets::SECURE_16384_DEGREE);
    assert_eq!(
        params.plaintext(),
        presets::SECURE_16384_LBFV_PLAINTEXT_MODULUS
    );
    assert_eq!(params.moduli(), presets::SECURE_16384_LBFV_MODULI);
    assert_eq!(
        params.get_error1_variance().to_string(),
        presets::SECURE_16384_ERROR1_VARIANCE
    );

    let config = SmudgingBoundCalculatorConfig::new_multiplicative(
        params,
        presets::SECURE_16384_NUM_PARTIES,
        3,
        presets::SECURE_16384_MULT_DEPTH,
        Lambda::secure(presets::SECURE_16384_LAMBDA).unwrap(),
    )
    .unwrap();
    let bound = SmudgingBoundCalculator::new(config)
        .with_accepted_participant_count(presets::SECURE_16384_NUM_PARTIES)
        .calculate_sm_bound()
        .unwrap();
    assert!(bound > BigUint::from(0_u64));
}

#[test]
fn secure_16384_share_parameters_cover_computation_moduli() {
    let params = presets::secure_16384_share_parameters().unwrap();
    assert_eq!(params.degree(), presets::SECURE_16384_DEGREE);
    assert_eq!(
        params.plaintext(),
        presets::SECURE_16384_SHARE_PLAINTEXT_MODULUS
    );
    assert!(
        presets::SECURE_16384_LBFV_MODULI
            .iter()
            .all(|&modulus| modulus <= params.plaintext())
    );
}
