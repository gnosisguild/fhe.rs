#![allow(dead_code)]

//! Shared parameter presets and deterministic helpers for tests, examples, and benches.

use std::sync::Arc;

use fhe::Result;
use fhe::bfv::{BfvParameters, BfvParametersBuilder};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

/// Degree-128 depth-3 parameters for correctness testing. Not secure.
///
/// `n = 19` (`t = 9`), `z = 3`, `k = 100`, `lambda = 2`. Its smudging bound
/// is configured for the default accepted participant count `|S| = n`.
pub mod insecure_128 {
    /// Polynomial ring degree.
    pub const DEGREE: usize = 128;
    /// Number of parties (ciphernodes).
    pub const NUM_PARTIES: usize = 19;
    /// Multiplicative depth supported by the design point.
    pub const MULT_DEPTH: u32 = 3;
    /// Number of initial noise terms folded into `B_C`.
    pub const MAX_CIPHERTEXTS: usize = 3;
    /// Statistical security parameter of the design point.
    pub const LAMBDA: usize = 2;

    /// Threshold BFV computation parameters.
    pub mod threshold {
        /// Plaintext modulus.
        pub const PLAINTEXT_MODULUS: u64 = 100;
        /// Ciphertext moduli (3 x 56 bits).
        pub const MODULI: &[u64] = &[
            0x00ff_ffff_ffff_c601,
            0x00ff_ffff_ffff_c301,
            0x00ff_ffff_ffff_a501,
        ];
        /// Error-1 variance for the supplied smudging bound.
        pub const ERROR1_VARIANCE: &str = "50471587840";
        /// Secret/error variance.
        pub const VARIANCE: usize = 10;
    }

    /// BFV parameters used to encrypt Shamir shares.
    pub mod share_enc {
        /// Plaintext modulus.
        pub const PLAINTEXT_MODULUS: u64 = 72_057_594_037_913_089;
        /// Ciphertext moduli (2 x 57 bits).
        pub const MODULI: &[u64] = &[0x01ff_ffff_ffff_9001, 0x01ff_ffff_ffff_9501];
        /// Secret/error variance.
        pub const VARIANCE: usize = 10;
    }
}

/// A computation profile and its optional encrypted-share transport profile.
#[derive(Clone)]
pub struct Preset {
    /// Stable profile name used in diagnostics and test output.
    pub name: &'static str,
    /// Parameters used for homomorphic computation.
    pub parameters: Arc<BfvParameters>,
    /// Parameters used to encrypt distributed shares, when available.
    pub share_parameters: Option<Arc<BfvParameters>>,
    /// Whether the profile is intended for SIMD coverage.
    pub simd: bool,
    /// Maximum number of summed ciphertexts supported by the profile.
    pub max_ciphertexts: usize,
    /// Default number of parties.
    pub num_parties: usize,
    /// Default corruption threshold.
    pub threshold: usize,
    /// Default statistical security level.
    pub lambda: usize,
    /// Multiplicative depth supported by the profile, when applicable.
    pub multiplicative_depth: Option<u32>,
}

impl Preset {
    /// Return the transport profile required by encrypted-share workflows.
    pub fn encrypted_share_parameters(&self) -> Result<Arc<BfvParameters>> {
        self.share_parameters.clone().ok_or_else(|| {
            fhe::Error::DefaultError(format!(
                "profile {} has no encrypted-share parameters",
                self.name
            ))
        })
    }
}

/// Build the supplied degree-128 profile used for fast correctness tests.
///
/// This profile must never be used as evidence for a security claim.
pub fn insecure() -> Result<Preset> {
    let parameters = BfvParametersBuilder::new()
        .set_degree(insecure_128::DEGREE)
        .set_plaintext_modulus(insecure_128::threshold::PLAINTEXT_MODULUS)
        .set_moduli(insecure_128::threshold::MODULI)
        .set_variance(insecure_128::threshold::VARIANCE)
        .set_error1_variance_str(insecure_128::threshold::ERROR1_VARIANCE)?
        .build_arc()?;
    let share_parameters = BfvParametersBuilder::new()
        .set_degree(insecure_128::DEGREE)
        .set_plaintext_modulus(insecure_128::share_enc::PLAINTEXT_MODULUS)
        .set_moduli(insecure_128::share_enc::MODULI)
        .set_variance(insecure_128::share_enc::VARIANCE)
        .build_arc()?;

    Ok(Preset {
        name: "insecure",
        parameters,
        share_parameters: Some(share_parameters),
        simd: false,
        max_ciphertexts: insecure_128::MAX_CIPHERTEXTS,
        num_parties: insecure_128::NUM_PARTIES,
        threshold: (insecure_128::NUM_PARTIES - 1) / 2,
        lambda: insecure_128::LAMBDA,
        multiplicative_depth: Some(insecure_128::MULT_DEPTH),
    })
}

/// Build the degree-8192 threshold BFV profile.
pub fn secure8192() -> Result<Preset> {
    let parameters = BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus(1_000_000)
        .set_moduli(&[0x0400000000c00001, 0x0400000000a40001, 0x0400000000990001])
        .set_variance(10)
        .set_error1_variance_str("17723039943798878305460955570711717478400")?
        .build_arc()?;
    // Share transport uses standard BFV; the large threshold-BFV e1 variance
    // belongs only to the computation parameters above.
    let share_parameters = BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus(288_230_376_164_294_657)
        .set_moduli(&[0x1000000000024001, 0x1000000000054001])
        .set_variance(10)
        .build_arc()?;

    Ok(Preset {
        name: "secure8192",
        parameters,
        share_parameters: Some(share_parameters),
        simd: false,
        max_ciphertexts: 1_000_000,
        num_parties: 20,
        threshold: 9,
        lambda: 45,
        multiplicative_depth: None,
    })
}

/// Build the degree-16384 l-BFV multiplication profile.
pub fn secure16384() -> Result<Preset> {
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
    // Share transport uses standard BFV; the large threshold-BFV e1 variance
    // belongs only to the computation parameters above.
    let share_parameters = BfvParametersBuilder::new()
        .set_degree(16384)
        .set_plaintext_modulus(1_125_899_917_262_849)
        .set_moduli(&[0x0010000000060001, 0x00100000000f0001])
        .set_variance(10)
        .build_arc()?;

    Ok(Preset {
        name: "secure16384",
        parameters,
        share_parameters: Some(share_parameters),
        simd: false,
        max_ciphertexts: 3,
        num_parties: 20,
        threshold: 9,
        lambda: 31,
        multiplicative_depth: Some(3),
    })
}

/// Build every named profile used by the integration test suite.
pub fn profiles() -> Result<[Preset; 3]> {
    Ok([insecure()?, secure8192()?, secure16384()?])
}

/// Expand a short test seed into the ChaCha8 seed used by the library.
#[must_use]
pub fn seed(value: u8) -> [u8; 32] {
    [value; 32]
}

/// Create a deterministic cryptographic RNG for a test case.
#[must_use]
pub fn rng(value: u8) -> ChaCha8Rng {
    ChaCha8Rng::from_seed(seed(value))
}
