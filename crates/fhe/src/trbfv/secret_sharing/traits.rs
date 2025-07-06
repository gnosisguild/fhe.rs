/// Traits for secret sharing operations.
///
/// This module defines the core traits for threshold secret sharing operations.
/// The SecretSharer trait provides a unified interface for different secret sharing
/// schemes, allowing easy extensibility and pluggable implementations.
use crate::Error;
use ndarray::Array2;
use num_bigint_old::BigInt;

/// Trait for secret sharing operations in threshold cryptography.
///
/// This trait provides a unified interface for secret sharing schemes used in threshold BFV.
/// It supports both share generation and reconstruction operations needed for the threshold protocol.
pub trait SecretSharer {
    /// Generate secret shares for polynomial coefficients.
    ///
    /// Takes polynomial coefficients and creates secret shares that can be distributed
    /// to different parties in the threshold scheme.
    ///
    /// # Arguments
    /// - `coeffs`: Polynomial coefficients to be shared
    ///
    /// # Returns
    /// Vector of share arrays, one per modulus in the BFV parameter set.
    /// Each Array2<u64> has dimensions [n_parties, degree] where:
    /// - Rows represent different parties
    /// - Columns represent polynomial coefficients
    fn generate_secret_shares(&mut self, coeffs: Box<[i64]>) -> Result<Vec<Array2<u64>>, Error>;

    /// Reconstruct a secret coefficient from shares.
    ///
    /// Takes shares from different parties and reconstructs the original secret coefficient.
    /// This is used during the decryption process to combine partial results.
    ///
    /// # Arguments
    /// - `shares`: Vector of (party_id, share_value) pairs
    /// - `modulus`: The modulus under which reconstruction is performed
    ///
    /// # Returns
    /// The reconstructed secret coefficient
    fn reconstruct_coefficient(
        &self,
        shares: &[(usize, BigInt)],
        modulus: u64,
    ) -> Result<BigInt, Error>;
}
