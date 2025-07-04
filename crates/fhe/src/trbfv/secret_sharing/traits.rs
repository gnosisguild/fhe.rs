/// Traits for secret sharing operations.
///
/// This module defines the core traits for threshold secret sharing operations.

use crate::Error;
use ndarray::Array2;

/// Trait for generating secret shares from polynomial coefficients.
pub trait SecretSharer {
    /// Generate Shamir Secret Shares for polynomial coefficients.
    fn generate_secret_shares(&mut self, coeffs: Box<[i64]>) -> Result<Vec<Array2<u64>>, Error>;
} 