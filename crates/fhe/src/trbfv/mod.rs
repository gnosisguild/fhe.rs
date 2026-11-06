//! Threshold BFV with Shamir key sharing and two distinct decryption protocols.
//!
//! Default synchronized decryption uses a designated set, fresh local noise, and pairwise PRF masks from
//! [Colin de Verdière–Passelègue–Stehlé 2026](https://eprint.iacr.org/2026/031).
//! The `synchronized-decryption` feature is enabled by default; disabling it
//! retains BFV, key sharing, and SS decryption without the optional PRF dependencies.
//! SS decryption is always available and uses sampled-and-dealt noise with
//! separate noise and partial-share types. Defaults expose both protocols.

mod buffers;
mod ss;
#[cfg(feature = "synchronized-decryption")]
mod synchronized;

/// Configuration and validation for threshold BFV
pub mod config;
/// Error types for threshold operations
pub mod errors;
/// Shamir Secret Sharing implementation
pub mod shamir;
/// Share collection and management
pub mod shares;
/// Smudging bounds, statistical-security policy, and fresh local noise
pub mod smudging;

// Re-export main types for convenience
pub use config::SsSmudgingDecryptionConfig;
#[cfg(feature = "synchronized-decryption")]
pub use config::SynchronizedDecryptionConfig;
#[cfg(feature = "synchronized-decryption")]
pub use errors::SynchronizedDecryptionError;
pub use shamir::ShamirSecretSharing;
pub use shares::ShareManager;
pub use smudging::{
    Lambda, MIN_SECURE_LAMBDA, SmudgingBoundCalculator, SmudgingBoundCalculatorConfig,
};
pub use ss::{
    AggregatedSmudgingShare, DealerSmudgingNoise, DealtSmudgingShares, RecipientSmudgingShare,
    SsSmudgingDecryptionShare, SsSmudgingDecryptor, SsSmudgingNoiseGenerator,
};
#[cfg(feature = "synchronized-decryption")]
pub use synchronized::{
    DecryptionShare, PRF_KEY_LEN, PartyPrfKeyTransport, PartyPrfKeys, PrfKey, SmudgingNoise,
    SmudgingNoiseGenerator, SynchronizedDecryptor,
};
