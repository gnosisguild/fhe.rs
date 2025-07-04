/// Smudging noise generation for threshold BFV.
///
/// This module provides the traits and implementations for generating smudging noise
/// in the threshold BFV scheme.

use crate::Error;
use fhe_util::sample_vec_normal;
use rand::{CryptoRng, RngCore};

/// Trait for generating smudging noise.
pub trait SmudgingGenerator {
    /// Generate smudging error coefficients for noise.
    fn generate_smudging_error<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<Vec<i64>, Error>;
}

/// Standard smudging noise generator.
#[derive(Debug)]
pub struct StandardSmudgingGenerator {
    /// Degree of the polynomial (number of coefficients)
    pub degree: usize,
    /// Variance for noise generation
    pub variance: usize,
}

impl StandardSmudgingGenerator {
    /// Create a new standard smudging generator.
    pub fn new(degree: usize, variance: usize) -> Self {
        Self { degree, variance }
    }
}

impl SmudgingGenerator for StandardSmudgingGenerator {
    /// Generate smudging error coefficients for noise.
    fn generate_smudging_error<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<i64>, Error> {
        // For each party, generate local smudging noise, coeffs of of degree N − 1 with coefficients
        // in [−Bsm, Bsm]
        let s_coefficients = sample_vec_normal(self.degree, self.variance, rng)
            .map_err(|e| Error::smudging(format!("Failed to generate smudging noise: {}", e)))?;
        Ok(s_coefficients)
    }
} 