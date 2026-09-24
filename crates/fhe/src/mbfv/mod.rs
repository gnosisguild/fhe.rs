// Expect indexing in multiparty BFV cryptographic operations for performance
#![expect(
    clippy::indexing_slicing,
    reason = "performance or example code relies on validated indices"
)]

//! Experimental implementation of the Multiparty BFV scheme, as described by
//! Christian Mouchet et. al. in [Multiparty Homomorphic Encryption from
//! Ring-Learning-with-Errors](https://eprint.iacr.org/2020/304.pdf).
//!
//! # Security warning
//!
//! This module is incomplete and has not been independently audited. In
//! particular, common-reference-string generation and the noise flooding
//! required by the key-switching protocols are not fully implemented. It must
//! not be used in production or to protect sensitive data.
//!
//! The module is available only with the `experimental-mbfv` Cargo feature.
//! Aggregation checks shared parameters, reference polynomials, row shapes,
//! and public-input binding. Share bytes do not authenticate their original
//! ciphertext or CRP; the surrounding protocol must authenticate contributors
//! and associate received shares with their public inputs.
//!
//! # Ownership conventions
//!
//! [`PublicKeyShare::new`] consumes its CRP because the share retains it for
//! aggregation. [`RelinKeyGenerator::new`] borrows a reusable CRP vector for
//! the generator's lifetime; round-one shares retain their own concrete copy
//! to validate that all contributions used the same CRP. Key-switch shares
//! retain their input ciphertext for aggregation, so
//! [`SecretKeySwitchShare::new`] takes an `Arc<Ciphertext>`;
//! [`DecryptionShare::new`] borrows an `Arc` and clones it into that owner.
//! [`PublicKeySwitchShare::new`] borrows its input ciphertext and output key,
//! retaining only the public components required for aggregation checks.

mod public_key_gen;
mod public_key_switch;
mod relin_key_gen;
pub mod round;
mod secret_key_switch;
mod validate;

pub use crate::aggregate::{Aggregate, AggregateIter};
pub use crate::bfv::CommonRandomPoly;
pub use public_key_gen::{PublicKeyShare, PublicKeyShareIntermediates};
pub use public_key_switch::PublicKeySwitchShare;
pub use relin_key_gen::{RelinKeyGenerator, RelinKeyShare};
pub use secret_key_switch::{DecryptionShare, SecretKeySwitchShare};
