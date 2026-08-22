//! Threshold l-BFV key-generation: [`PublicKeyShare`], [`RelinKeyShare`], and
//! [`AggregatedPublicKey`].
//!
//! This is the threshold/multiparty boundary for l-BFV, analogous to
//! [`crate::mbfv`]. Parties create [`PublicKeyShare`] and [`RelinKeyShare`]
//! values here, and aggregation produces the operational key types from
//! [`crate::lbfv`]. The shares are additive contributions from secret-key
//! summands; they are not Shamir shares used for threshold decryption.
//!
//! Participant/session bindings ([`ContributionBinding`], [`ParticipantSet`])
//! are consistency metadata only — they are not authentication.
//!
//! The implementation covers the additive public-key and linear
//! relinearization-key construction described by Urban--Rambaud, §5. DKG
//! orchestration, authentication, ZK proofs, FLSS/GURS, guaranteed output
//! delivery, noise-budget policy, and threshold decryption remain caller or
//! protocol responsibilities. Participant/session bindings provide
//! consistency checks only; they are not authentication.
//!
//! # Two aggregation paths
//!
//! - **Bound** — aggregate into [`AggregatedPublicKey`] for participant-set
//!   enforcement. Use [`aggregate_relinearization_key`] with the
//!   [`AggregatedPublicKey`] argument.
//!
//! - **Unbound** — aggregate directly into [`LBFVPublicKey`] (CRS-only
//!   validation). Use
//!   [`aggregate_relinearization_key_unbound`] with the
//!   [`LBFVPublicKey`] argument. This path is appropriate when ZK proofs
//!   handle authentication and contribution validity externally.

mod aggregate;
pub mod binding;
mod public_key_share;
mod relin_key_share;

pub use crate::lbfv::{LBFVPublicKey, LBFVRelinearizationKey};
pub use crate::mbfv::{Aggregate, AggregateIter};
pub use aggregate::{
    AggregatedPublicKey, aggregate_relinearization_key, aggregate_relinearization_key_unbound,
};
pub use binding::{ContributionBinding, ParticipantSet, SessionId};
pub use public_key_share::PublicKeyShare;
pub use relin_key_share::{RelinKeyShare, RlkWitness};
