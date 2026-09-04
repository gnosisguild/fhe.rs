//! Degree-16384 parameters for LBFV multiplication and relinearization.

use std::sync::Arc;

use fhe::bfv::{BfvParameters, BfvParametersBuilder};

/// Build the production-like degree-16384 multiplication profile.
pub fn parameters() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(16384)
        .set_plaintext_modulus(1_000)
        .set_moduli(&[
            0x00040000009f0001,
            0x00040000008a0001,
            0x0004000000800001,
            0x00040000007e0001,
            0x0004000000750001,
        ])
        .set_variance(10)
        .set_error1_variance_str("264093875047547791978479834453333")
        .expect("secure_16384 error variance must be valid")
        .build_arc()
        .expect("secure_16384 parameters must be valid")
}

/// Build the degree-16384 BFV profile used for encrypted share transport.
pub fn share_encryption_parameters() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(16384)
        .set_plaintext_modulus(1_125_899_917_262_849)
        .set_moduli(&[0x0010000000060001, 0x00100000000f0001])
        .set_variance(10)
        .build_arc()
        .expect("secure_16384 share-encryption parameters must be valid")
}
