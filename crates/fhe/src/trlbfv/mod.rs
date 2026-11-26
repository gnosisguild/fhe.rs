//! Distributed l-BFV public and relinearization key generation (Urban–Rambaud §5).
//!
//! Each party uses its own secret summand and the same two independently
//! generated reference strings: `a` (CRS) and `d1` (URS). Exchange the two
//! typed contribution messages and call [`aggregate_key_pair`] on the accepted
//! pairs. The resulting keys use the ordinary [`crate::lbfv`] wire formats.
//! Generate only one [`RelinKeyShare`] per secret and URS, use fresh `d1`
//! rows per level, and resend the saved bytes on retry.
//!
//! Shamir-share those same secret summands with [`crate::trbfv::ShareManager`]
//! for threshold decryption. For ciphertexts encrypted with the resulting
//! public key select [`crate::trbfv::FreshNoiseModel::LbfvPublicKey`].
//! Against malicious dealers, key confidentiality also requires protection
//! from adaptive (rogue-key) contributions. See [`aggregate_key_pair`] for
//! the admission requirements.

mod aggregate;
mod public_key_share;
mod relin_key_share;

pub use crate::aggregate::{Aggregate, AggregateIter};
pub use crate::lbfv::{LBFVPublicKey, LBFVRelinearizationKey};
pub use aggregate::{aggregate_key_pair, aggregate_relinearization_key};
pub use public_key_share::PublicKeyShare;
pub use relin_key_share::{RelinKeyShare, RelinKeyWitness};
