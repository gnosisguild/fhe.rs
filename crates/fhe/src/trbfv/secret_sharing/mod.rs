//! Secret sharing abstractions and implementations.
//!
//! This module provides abstractions for secret sharing schemes used in threshold BFV.

/// Shamir Secret Sharing implementation for threshold BFV.
pub mod shamir;
/// Traits for secret sharing operations.
pub mod traits;

pub use shamir::ShamirSecretSharing;
pub use traits::SecretSharer;
