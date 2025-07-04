//! Smudging abstractions and implementations.
//!
//! This module provides abstractions for smudging operations used in threshold BFV.

/// Configuration for smudging operations.
pub mod config;
/// Noise generation for smudging.
pub mod noise;

pub use config::SmudgingConfig;
pub use noise::{SmudgingGenerator, StandardSmudgingGenerator}; 