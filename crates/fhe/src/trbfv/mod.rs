//! The Threshold BFV scheme.
//!
//! Shamir sharing follows Urban–Rambaud 2024
//! ([Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf)).
//! Partial decryption follows Colin de Verdière–Passelègue–Stehlé 2026
//! ([On Threshold Fully Homomorphic Encryption with Synchronized Decryptors](https://eprint.iacr.org/2026/031.pdf)):
//! designated parties apply Lagrange coefficients locally, add fresh smudging
//! noise, and mask with committee PRF keys.

/// Internal configuration and validation for threshold BFV.
mod config;
/// Error types for threshold operations
pub mod errors;
/// Committee PRF keys and partial-decryption masks
pub mod prf;
/// Share collection and management
pub mod shares;
/// Smudging abstractions and implementations
pub mod smudging;

// Re-export main types for convenience
pub use prf::{PartyPrfKeys, PrfKey};
pub use shares::ShareManager;
pub use smudging::{SmudgingConfig, SmudgingNoise, SmudgingNoiseGenerator};
