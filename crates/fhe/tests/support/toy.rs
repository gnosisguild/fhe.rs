//! Small TRBFV parameters for fast integration tests.

use std::sync::Arc;

use fhe::bfv::{BfvParameters, BfvParametersBuilder};

pub fn parameters() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(64)
        .set_plaintext_modulus(1153)
        .set_moduli_sizes(&[40; 4])
        .set_variance(1)
        .build_arc()
        .expect("toy TRBFV parameters must be valid")
}
