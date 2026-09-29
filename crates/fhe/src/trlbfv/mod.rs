//! Threshold l-BFV key generation with [`PublicKeyShare`] and [`RelinKeyShare`].
//!
//! This is the threshold/multiparty boundary for l-BFV, analogous to
//! [`crate::mbfv`]. Parties create [`PublicKeyShare`] and [`RelinKeyShare`]
//! values here, and aggregation produces the operational key types from
//! [`crate::lbfv`]. The shares are additive contributions from secret-key
//! summands; they are not Shamir shares used for threshold decryption.
//! The operational key types are re-exported here for convenience; their
//! canonical definitions are in [`crate::lbfv`]. Public-key shares use the
//! shared [`Aggregate`] trait. Relinearization-key aggregation takes a public
//! key as additional input through [`aggregate_relinearization_key`], and
//! [`aggregate_key_pair`] aggregates paired
//! `(PublicKeyShare, RelinKeyShare)` contributions from one selected
//! contributor set as a single submission.
//!
//! # Aggregation validates only observable properties
//!
//! Aggregation validates parameters, levels, contexts, shared
//! reference-string rows, and arithmetic structure. It **cannot** establish
//! that a public key and a relinearization key were built from the same
//! contributor set, and it does **not** cryptographically verify that
//! contributions are consistent with the aggregate secret (the sum of the
//! contributors' secret summands): a mismatched or malicious contribution
//! can pass this validation, yielding a key that may appear to operate
//! normally yet decrypt incorrectly. [`aggregate_key_pair`] makes
//! one-selected-set pairing explicit and prevents a one-sided omission from
//! being passed directly, but pairing is a caller discipline, not a
//! cryptographic guarantee: incorrectly constructed pairs (including a
//! truncating zip of separate lists) and dishonest contributions are not
//! detected.
//!
//! Two distinct limitations must not be conflated:
//!
//! * *Same-secret consistency* is a cryptographic property that belongs in
//!   this library, but `trlbfv` currently ships no proof system or verifier
//!   for it, so nothing here proves consistency for arbitrary externally
//!   supplied pairs. [`RelinKeyWitness`] is generation-side witness
//!   material, not itself a proof or complete proof material; once a proof
//!   system covering the relevant PK/RLK relations is defined, in-library
//!   cryptographic proof verification could establish this property as a
//!   future library capability.
//! * *Contributor authentication and admission* — who may contribute,
//!   binding each pair's halves to an identity, and duplicate policing — are
//!   external protocol responsibilities of the integrating application.
//!
//! The implementation covers the additive public-key and linear
//! relinearization-key construction described by Urban--Rambaud, §5. DKG
//! orchestration, FLSS/GURS, guaranteed output delivery, noise-budget
//! policy, and threshold decryption remain caller or protocol
//! responsibilities.
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
pub use aggregate::{aggregate_key_pair, aggregate_relinearization_key};
pub use public_key_share::PublicKeyShare;
pub use relin_key_share::{RelinKeyShare, RelinKeyWitness};
