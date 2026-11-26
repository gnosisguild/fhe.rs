//! Public-key and relinearization primitives for l-BFV, based on
//! [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
//!
//! [`crate::trlbfv`] constructs these same operational keys from distributed
//! contributions. [`crate::trbfv`] opens level-zero ciphertexts using Shamir shares.

pub mod keys;

pub use keys::LBFVPublicKey;
pub use keys::LBFVRelinearizationKey;
