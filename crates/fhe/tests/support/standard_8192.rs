//! Production-like TRBFV parameters for secure integration tests.

use std::sync::Arc;

use fhe::bfv::{BfvParameters, BfvParametersBuilder};

pub fn parameters() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus(1_000_000)
        .set_moduli(&[0x02000000015a0001, 0x0200000001460001, 0x0200000001210001])
        .set_variance(10)
        .set_error1_variance_str("18148392902450051384713312396360971277653333")
        .expect("standard TRBFV error variance must be valid")
        .build_arc()
        .expect("standard TRBFV parameters must be valid")
}
