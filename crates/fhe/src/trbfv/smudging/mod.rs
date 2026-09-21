//! Threshold BFV smudging configuration and noise generation.
//!
//! The implementation is split between bound arithmetic and one-time noise
//! sampling while this module remains the public API surface.

mod bound;
mod noise;
mod owners;

pub use bound::{MAX_LAMBDA, SmudgingConfig};
pub use noise::{SmudgingNoise, SmudgingNoiseGenerator};
pub use owners::{AggregatedSmudgingShare, SmudgingShare};
