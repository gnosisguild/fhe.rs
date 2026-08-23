//! The Multiparty BFV scheme, as described by Christian Mouchet et. al.
//! in [Multiparty Homomorphic Encryption from Ring-Learning-with-Errors](https://eprint.iacr.org/2020/304.pdf).
//!
//! # Sessions, participants, and bindings
//!
//! MBFV reuses the crate-level [`crate::SessionId`], [`crate::ParticipantSet`],
//! and [`crate::ContributionBinding`] vocabulary. Every supported share
//! carries a required binding: the caller supplies a fresh, operation-specific
//! [`crate::SessionId`] per protocol execution (public-key generation,
//! secret-key switching/decryption, public-key switching, and each
//! relinearization execution have distinct sessions unless deliberately defined as
//! one execution), and an exact N-out-of-N [`crate::ParticipantSet`] of 1-based
//! participant IDs. Every aggregation entry point validates exact,
//! one-contribution-per-member coverage before any polynomial arithmetic and
//! rejects duplicates, missing IDs, unknown IDs, and shares whose
//! session/set metadata differs. Aggregators additionally compare concrete
//! public inputs (parameters, CRPs, ciphertexts, target keys) by structural
//! value equality, so a shared session label cannot combine structurally
//! different inputs; CRP generation, distribution, and reuse policy remain
//! external to this module (see also issue #105 for planned CRP-freshness
//! documentation).
//!
//! Bindings and these checks establish *consistency only*: the library does
//! not authenticate contributors or prove that a share was formed correctly.
//! MBFV remains a semi-honest N-out-of-N protocol surface without DKG
//! orchestration, broadcast authentication, ZK proofs, robust threshold
//! semantics, or noise flooding; transport/orchestration is responsible for
//! authenticating who supplied each share.

mod aggregate;
mod consistency;
mod public_key_gen;
mod public_key_switch;
mod relin_key_gen;
pub mod round;
mod secret_key_switch;
#[cfg(feature = "protobuf")]
mod wire;

pub use aggregate::{Aggregate, AggregateIter};
pub use public_key_gen::PublicKeyShare;
pub use public_key_switch::PublicKeySwitchShare;
pub use relin_key_gen::{RelinKeyGenerator, RelinKeyShare};
pub use secret_key_switch::{DecryptionShare, SecretKeySwitchShare};
