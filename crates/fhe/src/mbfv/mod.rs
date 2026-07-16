// Expect indexing in multiparty BFV cryptographic operations for performance
#![expect(
    clippy::indexing_slicing,
    reason = "performance or example code relies on validated indices"
)]

//! The Multiparty BFV scheme, as described by Christian Mouchet et. al.
//! in [Multiparty Homomorphic Encryption from Ring-Learning-with-Errors](https://eprint.iacr.org/2020/304.pdf).
//!
//! # Security limitations
//!
//! This module is experimental and implements an N-out-of-N protocol for
//! semi-honest parties. It is not a threshold or robust protocol.
//!
//! In particular, [`DecryptionShare`], [`SecretKeySwitchShare`], and
//! [`PublicKeySwitchShare`] use the ordinary BFV error distribution instead of
//! noise flooding derived from the current ciphertext noise. These operations
//! provide the protocol's functional algebra, but do not implement the
//! transcript-privacy requirement from the cited construction. Their shares
//! contain secret-dependent noisy relations, and repeated or adversarially
//! chosen requests may reveal secret-key-share information. Do not use these
//! operations where their transcripts must remain private from another party
//! or an aggregator.
//!
//! This limitation is specific to these MBFV interactive operations. It does
//! not apply to the separate BFV, LBFV, or TRBFV implementations.

mod aggregate;
mod crp;
mod public_key_gen;
mod public_key_switch;
mod relin_key_gen;
pub mod round;
mod secret_key_switch;

pub use aggregate::{Aggregate, AggregateIter};
pub use crp::CommonRandomPoly;
pub use public_key_gen::PublicKeyShare;
pub use public_key_switch::PublicKeySwitchShare;
pub use relin_key_gen::{RelinKeyGenerator, RelinKeyShare};
pub use secret_key_switch::{DecryptionShare, SecretKeySwitchShare};
