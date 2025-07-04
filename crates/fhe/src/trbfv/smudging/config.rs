/// Smudging configuration for threshold BFV.
///
/// This module provides configuration and validation for smudging operations.

use crate::Error;

/// Configuration for smudging operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmudgingConfig {
    /// Variance for smudging noise generation
    pub variance: usize,
    /// Degree of the polynomial (number of coefficients)
    pub degree: usize,
}

impl SmudgingConfig {
    /// Create a new smudging configuration.
    pub fn new(variance: usize, degree: usize) -> Result<Self, Error> {
        if variance == 0 {
            return Err(Error::UnspecifiedInput(
                "Smudging variance must be greater than 0".to_string(),
            ));
        }
        if degree == 0 {
            return Err(Error::UnspecifiedInput(
                "Degree must be greater than 0".to_string(),
            ));
        }
        Ok(Self { variance, degree })
    }

    /// Get the variance.
    pub fn variance(&self) -> usize {
        self.variance
    }

    /// Get the degree.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), Error> {
        if self.variance == 0 {
            return Err(Error::UnspecifiedInput(
                "Smudging variance must be greater than 0".to_string(),
            ));
        }
        if self.degree == 0 {
            return Err(Error::UnspecifiedInput(
                "Degree must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
} 