//! Public-key and relinearization primitives for l-BFV, based on
//! [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
//!
//! This module provides the local key and ciphertext operations, not distributed
//! key establishment, authenticated communication rounds, or a complete robust
//! threshold protocol. Single-round arithmetic alone does not establish robustness.

pub mod keys;

pub use keys::LBFVPublicKey;
pub use keys::LBFVRelinearizationKey;
