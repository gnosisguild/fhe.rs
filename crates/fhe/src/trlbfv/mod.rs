//! Threshold l-BFV key generation with [`PublicKeyShare`] and [`RelinKeyShare`].
//!
//! This is the threshold/multiparty boundary for l-BFV, analogous to
//! [`crate::mbfv`]. Parties create [`PublicKeyShare`] and [`RelinKeyShare`]
//! values here, and aggregation produces the operational key types from
//! [`crate::lbfv`]. The shares are additive contributions from secret-key
//! summands; they are not Shamir shares used for threshold decryption.
//!
//! The implementation covers the additive public-key and linear
//! relinearization-key construction described by Urban--Rambaud, §5. DKG
//! orchestration, authentication, ZK proofs, FLSS/GURS, guaranteed output
//! delivery, noise-budget policy, and threshold decryption remain caller or
//! protocol responsibilities. In particular, callers must select and
//! authenticate contributions and prevent duplicate inclusion.

mod aggregate;
mod public_key_share;
mod relin_key_share;

pub use crate::aggregate::{Aggregate, AggregateIter};
pub use crate::lbfv::{LBFVPublicKey, LBFVRelinearizationKey};
pub use aggregate::aggregate_relinearization_key;
pub use public_key_share::PublicKeyShare;
pub use relin_key_share::{RelinKeyShare, RlkWitness};
