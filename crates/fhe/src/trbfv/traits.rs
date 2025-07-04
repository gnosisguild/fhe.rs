/// Traits for threshold secret sharing operations.
///
/// This module defines the core traits for threshold BFV operations including
/// secret sharing and smudging noise generation.

use crate::Error;
use ndarray::Array2;
use rand::{CryptoRng, RngCore};

/// Trait for generating secret shares from polynomial coefficients.
pub trait SecretSharer {
    /// Generate Shamir Secret Shares for polynomial coefficients.
    fn generate_secret_shares(&mut self, coeffs: Box<[i64]>) -> Result<Vec<Array2<u64>>, Error>;
}

/// Trait for generating smudging noise.
pub trait SmudgingGenerator {
    /// Generate smudging error coefficients for noise.
    fn generate_smudging_error<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<Vec<i64>, Error>;
}

#[cfg(test)]
mod tests {

    use crate::bfv::{BfvParametersBuilder, SecretKey};
    use crate::trbfv::TRBFV;
    use rand::thread_rng;

    #[test]
    fn test_secret_sharer_trait() {
        let mut rng = thread_rng();
        let degree = 2048;
        let plaintext_modulus = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];
        let params = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        let mut trbfv = TRBFV::new(5, 3, 160, params.clone()).unwrap();
        let sk = SecretKey::random(&params, &mut rng);
        let coeffs = sk.coeffs.clone();

        let shares = trbfv.generate_secret_shares(coeffs);
        assert!(shares.is_ok());
        let shares = shares.unwrap();
        assert_eq!(shares.len(), moduli.len());
        assert_eq!(shares[0].nrows(), 5); // n parties
        assert_eq!(shares[0].ncols(), degree); // degree coefficients
    }

    #[test]
    fn test_smudging_generator_trait() {
        let mut rng = thread_rng();
        let degree = 2048;
        let plaintext_modulus = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];
        let params = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        let mut trbfv = TRBFV::new(5, 3, 160, params.clone()).unwrap();
        let smudging_error = trbfv.generate_smudging_error(&mut rng);
        assert!(smudging_error.is_ok());
        let smudging_error = smudging_error.unwrap();
        assert_eq!(smudging_error.len(), degree);
    }
} 