//! Representative degree-8192 parameters for production-like smoke tests.

use std::sync::Arc;

use fhe::bfv::{BfvParameters, BfvParametersBuilder};

pub fn parameters() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus(1_000_000)
        .set_moduli(&[0x0400000000c00001, 0x0400000000a40001, 0x0400000000990001])
        .set_variance(10)
        .set_error1_variance_str("17723039943798878305460955570711717478400")
        .expect("secure8192 error variance must be valid")
        .build_arc()
        .expect("secure8192 parameters must be valid")
}

/// Build the degree-8192 BFV profile used for encrypted share transport.
pub fn share_encryption_parameters() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus(288_230_376_164_294_657)
        .set_moduli(&[0x1000000000024001, 0x1000000000054001])
        .set_variance(10)
        .build_arc()
        .expect("secure8192 share-encryption parameters must be valid")
}
