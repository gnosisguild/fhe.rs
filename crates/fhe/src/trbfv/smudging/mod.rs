//! Smudging abstractions and implementations.
//!
//! This module provides abstractions for smudging operations used in threshold BFV.
//!
//! Smudging is a cryptographic technique used in threshold schemes to hide intermediate
//! values during the decryption process. Each party adds carefully chosen noise (smudging error)
//! to their decryption share, which prevents adversaries from learning information about
//! individual secret key shares.
//!
//! # Why is Smudging Necessary?
//!
//! In threshold BFV decryption:
//! 1. Each party computes a decryption share using their secret key share
//! 2. Without smudging, these shares could leak information about the secret keys
//! 3. Smudging noise masks the intermediate values while preserving correctness
//! 4. The noise cancels out during final reconstruction, revealing the correct plaintext

/// Configuration for smudging operations.
pub mod config;
/// Noise generation for smudging.
pub mod noise;

pub use config::SmudgingConfig;
pub use noise::{SmudgingGenerator, StandardSmudgingGenerator};
