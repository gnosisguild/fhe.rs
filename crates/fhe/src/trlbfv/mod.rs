//! Threshold l-BFV key generation with [`PublicKeyShare`] and [`RelinKeyShare`].
//!
//! This is the threshold/multiparty boundary for l-BFV, analogous to
//! [`crate::mbfv`]. Parties create [`PublicKeyShare`] and [`RelinKeyShare`]
//! values here, and aggregation produces the operational key types from
//! [`crate::lbfv`]. The shares are additive contributions from secret-key
//! summands; they are not Shamir shares used for threshold decryption.
//! The operational key types are re-exported here for convenience; their
//! canonical definitions are in [`crate::lbfv`]. Public-key shares use the
//! shared [`Aggregate`] trait, while relinearization-key aggregation takes a
//! public key as additional input through [`aggregate_relinearization_key`].
//!
//! The implementation covers the additive public-key and linear
//! relinearization-key construction described by Urban--Rambaud, §5. DKG
//! orchestration, authentication, ZK proofs, FLSS/GURS, guaranteed output
//! delivery, noise-budget policy, and threshold decryption remain caller or
//! protocol responsibilities. In particular, callers must select and
//! authenticate contributions and prevent duplicate inclusion.
//!
//! # Independence of the reference strings
//!
//! Threshold key generation consumes two shared reference strings: the CRS
//! `a` shared by the public-key contributions and the URS `d1` shared by the
//! relinearization-key contributions. The two strings **must be generated
//! independently** (distinct seeds or separately sampled polynomials). Share
//! constructors, deserialization, and aggregation reject identical seeds,
//! rows repeated within one string, and rows shared between the two strings,
//! so no share or aggregated key built from observably reused randomness is
//! produced. These equality checks cannot certify independence against
//! deliberately correlated but unequal randomness; obtaining the reference
//! strings from an independently sampled, honestly generated source remains a
//! protocol responsibility.

mod aggregate;
mod public_key_share;
mod relin_key_share;

pub use crate::aggregate::{Aggregate, AggregateIter};
pub use crate::lbfv::{LBFVPublicKey, LBFVRelinearizationKey};
pub use aggregate::aggregate_relinearization_key;
pub use public_key_share::PublicKeyShare;
pub use relin_key_share::{RelinKeyShare, RelinKeyWitness};
