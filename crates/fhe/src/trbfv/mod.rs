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
/// Main threshold BFV orchestrator
pub mod threshold;
pub use crate::identity::{ContributionBinding, ParticipantSet, SessionId};

// Re-export main types for convenience
pub use shares::{
    AggregatedKeyShare, DecryptionShare, KeyShareContribution, NoisePoly, NoiseShareContribution,
    NoiseShareMatrix, OneTimeNoiseShare, SecretPoly, SecretShareMatrix, ShareManager,
};
pub use smudging::{
    Lambda, MIN_SECURE_LAMBDA, SmudgingBoundCalculator, SmudgingBoundCalculatorConfig,
    SmudgingCoefficients,
};
pub use threshold::TRBFV;
