//! The Threshold BFV scheme, as described by Antoine Urban and Matthieu Rambaud.
//! in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).

/// Configuration and validation for threshold BFV
pub mod config;
/// Error types for threshold operations
pub mod errors;
/// Secret sharing abstractions and implementations
pub mod secret_sharing;
/// Share collection and management
pub mod shares;
/// Smudging abstractions and implementations
pub mod smudging;
/// Main threshold BFV orchestrator
pub mod threshold;

// Re-export main types for convenience
pub use secret_sharing::{SecretSharer, ShamirSecretSharing};
pub use shares::ShareManager;
pub use smudging::{VarianceCalculator, VarianceCalculatorConfig};
pub use threshold::TRBFV;
