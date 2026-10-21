//! Threshold BFV with Shamir key sharing and synchronized decryption.
//!
//! Decryption uses a designated set, fresh local noise, and pairwise PRF masks from
//! [Colin de Verdière–Passelègue–Stehlé 2026](https://eprint.iacr.org/2026/031).
//! The `threshold-decryption` feature is enabled by default; disabling it
//! retains core BFV and key sharing without the optional PRF dependencies.

#[cfg(feature = "threshold-decryption")]
mod arithmetic;
#[cfg(feature = "threshold-decryption")]
mod decryption;
#[cfg(feature = "threshold-decryption")]
mod prf;

/// Configuration and validation for threshold BFV
pub mod config;
/// Error types for threshold operations
pub mod errors;
/// Shamir Secret Sharing implementation
pub mod shamir;
/// Share collection and management
pub mod shares;
/// Smudging bounds, statistical-security policy, and fresh local noise
pub mod smudging;

// Re-export main types for convenience
#[cfg(feature = "threshold-decryption")]
pub use decryption::{DecryptionShare, SynchronizedDecryptor};
#[cfg(feature = "threshold-decryption")]
pub use errors::SynchronizedDecryptionError;
#[cfg(feature = "threshold-decryption")]
pub use prf::{PRF_KEY_LEN, PartyPrfKeyTransport, PartyPrfKeys, PrfKey};
pub use shamir::ShamirSecretSharing;
pub use shares::ShareManager;
pub use smudging::{
    Lambda, MIN_SECURE_LAMBDA, SmudgingBoundCalculator, SmudgingBoundCalculatorConfig,
};
#[cfg(feature = "threshold-decryption")]
pub use smudging::{SmudgingNoise, SmudgingNoiseGenerator};
