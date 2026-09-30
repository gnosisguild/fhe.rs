//! Threshold l-BFV key generation with [`PublicKeyShare`] and [`RelinKeyShare`].
//!
//! Shares are additive secret-key contributions, not Shamir decryption shares.
//! Aggregation produces operational [`crate::lbfv`] keys:
//! - [`Aggregate`] combines public-key shares.
//! - [`aggregate_relinearization_key`] combines RLK shares with a public key.
//! - [`aggregate_key_pair`] combines both halves of one selected contributor set.
//!
//! Contribution envelopes and operational-key encodings are distinct wire types.
//!
//! # Security boundary
//!
//! Aggregation validates parameters, levels, contexts, reference strings, and
//! arithmetic structure. It does not authenticate contributors, reject duplicate
//! submissions, or prove that PK/RLK halves use the same secret summand.
//! [`RelinKeyWitness`] is not a proof; this crate provides no consistency-proof
//! verifier. Pairing avoids accidental one-sided omissions, not malicious
//! mispairing or caller-side `zip` truncation. See [`aggregate_key_pair`].
//!
//! CRS and URS generation must be independent. Checks reject identical seeds,
//! repeated rows, and shared rows, but cannot detect unequal correlated randomness.
//! DKG, FLSS/GURS, output delivery, authentication, admission, session binding,
//! and replay prevention remain protocol responsibilities. Threshold decryption
//! is provided separately by [`crate::trbfv`].

mod aggregate;
mod public_key_share;
mod relin_key_share;

pub use crate::aggregate::{Aggregate, AggregateIter};
pub use crate::lbfv::{LBFVPublicKey, LBFVRelinearizationKey};
pub use aggregate::{aggregate_key_pair, aggregate_relinearization_key};
pub use public_key_share::PublicKeyShare;
pub use relin_key_share::{RelinKeyShare, RelinKeyWitness};
