#![allow(dead_code)]

//! Parameter presets shared by the threshold examples and their regression tests.

use std::sync::Arc;

use fhe::Result;
use fhe::bfv::{BfvParameters, BfvParametersBuilder};

/// A computation preset and its share-encryption parameters.
#[derive(Clone)]
pub struct Preset {
    /// Parameters used for the homomorphic computation.
    pub parameters: Arc<BfvParameters>,
    /// Parameters used to encrypt distributed shares.
    pub share_parameters: Arc<BfvParameters>,
    /// Maximum number of summed ciphertexts supported by the preset.
    pub max_ciphertexts: usize,
    /// Default number of parties.
    pub num_parties: usize,
    /// Default corruption threshold.
    pub threshold: usize,
    /// Default statistical security level.
    pub lambda: usize,
    /// Multiplicative depth supported by the preset, when applicable.
    pub multiplicative_depth: Option<u32>,
}

/// Build the Secure-8192 threshold BFV preset.
pub fn secure8192() -> Result<Preset> {
    let parameters = BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus(1_000_000)
        .set_moduli(&[0x0400000000c00001, 0x0400000000a40001, 0x0400000000990001])
        .set_variance(10)
        .set_error1_variance_str("17723039943798878305460955570711717478400")?
        .build_arc()?;
    let share_parameters = BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus(288230376164294657)
        .set_moduli(&[0x1000000000024001, 0x1000000000054001])
        .set_variance(10)
        .build_arc()?;

    Ok(Preset {
        parameters,
        share_parameters,
        max_ciphertexts: 1_000_000,
        num_parties: 20,
        threshold: 9,
        lambda: 45,
        multiplicative_depth: None,
    })
}

/// Build the Secure-16384 l-BFV preset.
pub fn secure_16384() -> Result<Preset> {
    let parameters = BfvParametersBuilder::new()
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
        .set_error1_variance_str("264093875047547791978479834453333")?
        .build_arc()?;
    let share_parameters = BfvParametersBuilder::new()
        .set_degree(16384)
        .set_plaintext_modulus(1_125_899_917_262_849)
        .set_moduli(&[0x0010000000060001, 0x00100000000f0001])
        .set_variance(10)
        .build_arc()?;

    Ok(Preset {
        parameters,
        share_parameters,
        max_ciphertexts: 3,
        num_parties: 20,
        threshold: 9,
        lambda: 31,
        multiplicative_depth: Some(3),
    })
}
