//! Parameter sets used by the threshold BFV and l-BFV examples.

use std::sync::Arc;

use crate::Result;
use crate::bfv::{BfvParameters, BfvParametersBuilder};

/// Secure-8192 ring dimension.
pub const SECURE_8192_DEGREE: usize = 8192;
/// Secure-8192 plaintext modulus for threshold BFV computation.
pub const SECURE_8192_TRBFV_PLAINTEXT_MODULUS: u64 = 1_000_000;
/// Secure-8192 maximum supported number of summed ciphertexts.
pub const SECURE_8192_MAX_CIPHERTEXTS: usize = 1_000_000;
/// Secure-8192 party count.
pub const SECURE_8192_NUM_PARTIES: usize = 20;
/// Secure-8192 maximal corruption threshold.
pub const SECURE_8192_THRESHOLD: usize = 9;
/// Secure-8192 statistical security level.
pub const SECURE_8192_LAMBDA: usize = 45;
/// Secure-8192 computation ciphertext moduli.
pub const SECURE_8192_TRBFV_MODULI: &[u64] =
    &[0x0400000000c00001, 0x0400000000a40001, 0x0400000000990001];
/// Secure-8192 configured error-1 variance.
pub const SECURE_8192_ERROR1_VARIANCE: &str = "17723039943798878305460955570711717478400";
/// Secure-8192 plaintext modulus for encrypted share transport.
pub const SECURE_8192_SHARE_PLAINTEXT_MODULUS: u64 = 288230376164294657;
/// Secure-8192 encrypted share-transport ciphertext moduli.
pub const SECURE_8192_SHARE_MODULI: &[u64] = &[0x1000000000024001, 0x1000000000054001];

/// Secure-16384 ring dimension.
pub const SECURE_16384_DEGREE: usize = 16384;
/// Secure-16384 plaintext modulus for l-BFV computation.
pub const SECURE_16384_LBFV_PLAINTEXT_MODULUS: u64 = 1_000;
/// Secure-16384 party count used by the threshold examples.
pub const SECURE_16384_NUM_PARTIES: usize = 20;
/// Secure-16384 maximal corruption threshold.
pub const SECURE_16384_THRESHOLD: usize = 9;
/// Secure-16384 multiplicative depth.
pub const SECURE_16384_MULT_DEPTH: u32 = 3;
/// Secure-16384 statistical security level.
pub const SECURE_16384_LAMBDA: usize = 31;
/// Secure-16384 l-BFV computation ciphertext moduli.
pub const SECURE_16384_LBFV_MODULI: &[u64] = &[
    0x00040000009f0001,
    0x00040000008a0001,
    0x0004000000800001,
    0x00040000007e0001,
    0x0004000000750001,
];
/// Secure-16384 configured error-1 variance.
pub const SECURE_16384_ERROR1_VARIANCE: &str = "264093875047547791978479834453333";
/// Secure-16384 plaintext modulus for encrypted share transport.
pub const SECURE_16384_SHARE_PLAINTEXT_MODULUS: u64 = 1_125_899_917_262_849;
/// Secure-16384 encrypted share-transport ciphertext moduli.
pub const SECURE_16384_SHARE_MODULI: &[u64] = &[0x0010000000060001, 0x00100000000f0001];

/// Build the Secure-8192 threshold BFV computation parameters.
pub fn secure_8192_trbfv_parameters() -> Result<Arc<BfvParameters>> {
    BfvParametersBuilder::new()
        .set_degree(SECURE_8192_DEGREE)
        .set_plaintext_modulus(SECURE_8192_TRBFV_PLAINTEXT_MODULUS)
        .set_moduli(SECURE_8192_TRBFV_MODULI)
        .set_variance(10)
        .set_error1_variance_str(SECURE_8192_ERROR1_VARIANCE)?
        .build_arc()
}

/// Build the Secure-8192 BFV parameters used to transport shares.
pub fn secure_8192_share_parameters() -> Result<Arc<BfvParameters>> {
    BfvParametersBuilder::new()
        .set_degree(SECURE_8192_DEGREE)
        .set_plaintext_modulus(SECURE_8192_SHARE_PLAINTEXT_MODULUS)
        .set_moduli(SECURE_8192_SHARE_MODULI)
        .set_variance(10)
        .build_arc()
}

/// Build the Secure-16384 l-BFV computation parameters.
pub fn secure_16384_lbfv_parameters() -> Result<Arc<BfvParameters>> {
    BfvParametersBuilder::new()
        .set_degree(SECURE_16384_DEGREE)
        .set_plaintext_modulus(SECURE_16384_LBFV_PLAINTEXT_MODULUS)
        .set_moduli(SECURE_16384_LBFV_MODULI)
        .set_variance(10)
        .set_error1_variance_str(SECURE_16384_ERROR1_VARIANCE)?
        .build_arc()
}

/// Build the Secure-16384 BFV parameters used to transport shares.
pub fn secure_16384_share_parameters() -> Result<Arc<BfvParameters>> {
    BfvParametersBuilder::new()
        .set_degree(SECURE_16384_DEGREE)
        .set_plaintext_modulus(SECURE_16384_SHARE_PLAINTEXT_MODULUS)
        .set_moduli(SECURE_16384_SHARE_MODULI)
        .set_variance(10)
        .build_arc()
}
