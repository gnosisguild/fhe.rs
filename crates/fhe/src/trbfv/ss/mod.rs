//! Decryption with SS (secret-sharing) smudging noise.
//!
//! Noise is sampled, Shamir-dealt, and aggregated before partial decryption.
//! Reconstruction uses Shamir interpolation, without PRF keys or designated-set hashes.

mod decryption;
mod shares;
mod smudging;

pub use decryption::{SsSmudgingDecryptionShare, SsSmudgingDecryptor};
pub use shares::{AggregatedSmudgingShare, DealtSmudgingShares, RecipientSmudgingShare};
pub use smudging::{DealerSmudgingNoise, SsSmudgingNoiseGenerator};
