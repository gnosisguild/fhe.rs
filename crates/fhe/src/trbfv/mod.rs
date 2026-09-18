//! The Threshold BFV scheme, as described by Antoine Urban and Matthieu Rambaud.
//! in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).

/// Configuration and validation for threshold BFV
pub mod config;
/// Error types for threshold operations
pub mod errors;
/// Share collection and management
pub mod shares;
/// Smudging abstractions and implementations
pub mod smudging;

// Re-export main types for convenience
pub use shares::ShareManager;
pub use smudging::{
    GeneratedSmudgingNoise, Lambda, MIN_SECURE_LAMBDA, SmudgingBoundCalculator,
    SmudgingBoundCalculatorConfig, SmudgingNoiseGenerator,
};
