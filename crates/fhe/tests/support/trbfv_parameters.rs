//! Common degree-8192 regression preset for both threshold-decryption protocols.
//!
//! The preset meets the lambda policy and the calculator's correctness check,
//! not an independent security certification. Its 20-party case is outside the
//! Urban–Rambaud odd-party theorem. These are regression parameters, not
//! recommended deployment parameters.

use fhe::bfv::{BfvParameters, BfvParametersBuilder};
use fhe::trbfv::{Lambda, SmudgingBoundCalculatorConfig};
use num_bigint::BigUint;
use std::sync::Arc;

pub(super) const DEGREE: usize = 8192;
pub(super) const NUM_PARTIES: usize = 20;
pub(super) const THRESHOLD: usize = 9;
pub(super) const LAMBDA: usize = 50;
pub(super) const NUM_SUMMED: usize = 50;

const TRBFV_PLAINTEXT_MODULUS: u64 = 1_000_000;
const TRBFV_MODULI: &[u64] = &[0x02000000015a0001, 0x0200000001460001, 0x0200000001210001];
const TRBFV_ERROR1_VARIANCE: &str = "18148392902450051384713312396360971277653333";

// Each transported Shamir residue is in [0, q_i), so equality with max(q_i) suffices.
const TRANSPORT_PLAINTEXT_MODULUS: u64 = 144115188098531329;
const TRANSPORT_MODULI: &[u64] = &[0x0800000000004001, 0x0800000000044001];

pub(super) fn trbfv_params() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_plaintext_modulus(TRBFV_PLAINTEXT_MODULUS)
        .set_moduli(TRBFV_MODULI)
        .set_variance(10)
        .set_error1_variance_str(TRBFV_ERROR1_VARIANCE)
        .unwrap()
        .build_arc()
        .unwrap()
}

pub(super) fn transport_params() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_plaintext_modulus(TRANSPORT_PLAINTEXT_MODULUS)
        .set_moduli(TRANSPORT_MODULI)
        .set_variance(10)
        .build_arc()
        .unwrap()
}

pub(super) fn bound_config(params: Arc<BfvParameters>) -> SmudgingBoundCalculatorConfig {
    SmudgingBoundCalculatorConfig::new(
        params,
        NUM_PARTIES,
        NUM_SUMMED,
        Lambda::secure(LAMBDA).unwrap(),
    )
    .unwrap()
}

pub(super) fn assert_correctness_budget(bound: &BigUint) {
    let b_enc = BigUint::parse_bytes(b"7378697629483820646400", 10).unwrap();
    assert_eq!(bound_config(trbfv_params()).b_enc, b_enc);

    // Independently checked calculator B_C for this preset and 50-input sum.
    // Pin it so neither protocol can silently drift to a different preset/budget.
    let b_c = BigUint::parse_bytes(b"368934881474191380924850", 10).unwrap();
    let expected = (BigUint::from(1u32) << (LAMBDA + 1)) * DEGREE * &b_c;
    assert_eq!(bound, &expected);

    let q: BigUint = TRBFV_MODULI.iter().copied().map(BigUint::from).product();
    let delta = q / TRBFV_PLAINTEXT_MODULUS;
    assert!(BigUint::from(2u32) * (&b_c + BigUint::from(NUM_PARTIES) * bound) < delta);
}

pub(super) fn assert_transport_range() {
    let params = trbfv_params();
    let transport = transport_params();
    assert_eq!(transport.degree(), params.degree());
    assert!(params.moduli().iter().all(|&q| q <= transport.plaintext()));
}
