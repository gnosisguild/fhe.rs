//! Intentionally insecure parameters for fast integration and negative tests.

use std::sync::Arc;

use fhe::bfv::{BfvParameters, BfvParametersBuilder};

/// Build a small profile for breadth and failure-path coverage.
///
/// This profile must never be used as evidence for a security claim.
pub fn parameters() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(64)
        .set_plaintext_modulus(1153)
        .set_moduli_sizes(&[40; 4])
        .set_variance(1)
        .build_arc()
        .expect("insecure test parameters must be valid")
}
