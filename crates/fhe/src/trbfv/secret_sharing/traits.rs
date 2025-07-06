/// Traits for secret sharing operations.
///
/// This module defines the core traits for threshold secret sharing operations.
use crate::Error;
use ndarray::Array2;
use num_bigint_old::BigInt;

/// Trait for generating secret shares from polynomial coefficients.
pub trait SecretSharer {
    /// Generate secret shares for polynomial coefficients.
    fn generate_secret_shares(&mut self, coeffs: Box<[i64]>) -> Result<Vec<Array2<u64>>, Error>;

    /// Reconstruct a secret coefficient from shares.
    fn reconstruct_coefficient(
        &self,
        shares: &[(usize, BigInt)],
        modulus: u64,
    ) -> Result<BigInt, Error>;
}
