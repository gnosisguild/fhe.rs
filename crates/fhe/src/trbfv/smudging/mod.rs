//! Smudging bounds, fresh local-noise generation, and one-use noise ownership.
//!
//! [`SmudgingBoundCalculator`] determines the required coefficient bound.
//! With `threshold-decryption` enabled, `SmudgingNoiseGenerator` samples
//! or wraps coefficients for one partial-decryption call.

mod bounds;
#[cfg(feature = "threshold-decryption")]
mod noise;

pub use bounds::{
    Lambda, MIN_SECURE_LAMBDA, SmudgingBoundCalculator, SmudgingBoundCalculatorConfig,
};
#[cfg(feature = "threshold-decryption")]
pub use noise::{SmudgingNoise, SmudgingNoiseGenerator};
