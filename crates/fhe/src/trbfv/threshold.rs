/// Main threshold BFV orchestrator.
///
/// This module provides the main TRBFV struct that coordinates between secret sharing,
/// smudging, and share management operations to implement the threshold BFV protocol.
///
/// # Threshold BFV Overview
///
/// Threshold BFV enables distributed decryption where:
/// - Secret keys are shared among n parties using secret sharing
/// - Only t parties (threshold) are needed to decrypt
/// - Up to t-1 parties can be compromised without breaking security
/// - Smudging noise protects intermediate values during decryption
///
/// # Protocol Flow
///
/// 1. **Setup**: Generate BFV parameters and TRBFV configuration
/// 2. **Key Generation**: Each party generates secret key shares
/// 3. **Share Distribution**: Parties exchange shares via secure channels
/// 4. **Encryption**: Standard BFV encryption (no changes needed)
/// 5. **Threshold Decryption**:
///    - Each party computes decryption share with smudging
///    - Combine threshold shares to recover plaintext
use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::trbfv::config::validate_threshold_config;
use crate::trbfv::secret_sharing::{SecretSharer, ShamirSecretSharing};
use crate::trbfv::shares::ShareManager;
use crate::trbfv::smudging::{SmudgingGenerator, StandardSmudgingGenerator};
use crate::Error;
use fhe_math::rq::Poly;
use fhe_traits::FheParametrized;
use ndarray::Array2;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

/// Threshold BFV configuration and operations.
/// This struct serves as the main coordinator for threshold BFV operations, managing
/// the interaction between secret sharing, smudging, and share management components.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TRBFV {
    /// Number of parties in the threshold scheme
    pub n: usize,
    /// Threshold for reconstruction (must be < n and > 0)
    pub threshold: usize,
    /// Variance for smudging noise generation
    pub smudging_variance: usize,
    /// BFV parameters (contains degree, plaintext_modulus, moduli, etc.)
    pub params: Arc<BfvParameters>,
}

impl TRBFV {
    /// Creates a new threshold BFV configuration.
    ///
    /// # Arguments
    /// * `n` - Number of parties (must be > 0)
    /// * `threshold` - Threshold for reconstruction (must be < n and > 0)
    /// * `smudging_variance` - Variance for smudging noise generation
    /// * `params` - BFV parameters
    pub fn new(
        n: usize,
        threshold: usize,
        smudging_variance: usize,
        params: Arc<BfvParameters>,
    ) -> Result<Self, Error> {
        // Validate all parameters
        validate_threshold_config(n, threshold)?;

        Ok(Self {
            n,
            threshold,
            smudging_variance,
            params,
        })
    }

    /// Generate Shamir Secret Shares for polynomial coefficients.
    ///
    /// This method creates secret shares that can be distributed to different parties.
    /// Each party will receive one share for each polynomial coefficient.
    ///
    /// # Arguments
    /// * `coeffs` - Polynomial coefficients to be shared (typically secret key coefficients)
    ///
    /// # Returns
    /// Vector of share matrices, one per BFV modulus. Each matrix has dimensions [n, degree].
    pub fn generate_secret_shares(
        &mut self,
        coeffs: Box<[i64]>,
    ) -> Result<Vec<Array2<u64>>, Error> {
        let mut shamir_ss = ShamirSecretSharing::new(self.n, self.threshold, self.params.clone());
        shamir_ss.generate_secret_shares(coeffs)
    }

    /// Aggregate collected secret sharing shares to compute SK_i polynomial sum.
    ///
    /// This method combines shares collected from other parties to reconstruct the
    /// secret key material needed for decryption.
    ///
    /// # Arguments
    /// * `sk_sss_collected` - Shares collected from other parties
    ///
    /// # Returns
    /// Aggregated polynomial representing the combined secret key material
    pub fn aggregate_collected_shares(
        &mut self,
        sk_sss_collected: &[Array2<u64>], // collected sk sss shares from other parties
    ) -> Result<Poly, Error> {
        let mut share_manager = ShareManager::new(self.n, self.threshold, self.params.clone());
        share_manager.aggregate_collected_shares(sk_sss_collected)
    }

    /// Generate smudging error coefficients for noise.
    ///
    /// Creates noise that will be added to decryption shares to protect privacy.
    /// The noise is sampled from a normal distribution with the configured variance.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// Vector of smudging error coefficients
    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<i64>, Error> {
        let mut smudging_gen =
            StandardSmudgingGenerator::new(self.params.degree(), self.smudging_variance);
        smudging_gen.generate_smudging_error(rng)
    }

    /// Compute decryption share from ciphertext and secret/smudging polynomials.
    ///
    /// Each party calls this method to compute their contribution to the threshold decryption.
    /// The result should be sent to the party coordinating the decryption.
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext to decrypt
    /// * `sk_i` - This party's secret key polynomial
    /// * `es_i` - This party's smudging error polynomial
    ///
    /// # Returns
    /// Decryption share polynomial
    pub fn decryption_share(
        &mut self,
        ciphertext: Arc<Ciphertext>,
        sk_i: Poly,
        es_i: Poly,
    ) -> Result<Poly, Error> {
        let mut share_manager = ShareManager::new(self.n, self.threshold, self.params.clone());
        share_manager.decryption_share(ciphertext, sk_i, es_i)
    }

    /// Decrypt ciphertext from collected decryption shares (threshold number required).
    ///
    /// This method performs the final step of threshold decryption by combining
    /// decryption shares from at least `threshold` parties.
    ///
    /// # Arguments
    /// * `d_share_polys` - Decryption shares from different parties
    /// * `ciphertext` - The original ciphertext being decrypted
    ///
    /// # Returns
    /// The decrypted plaintext
    pub fn decrypt(
        &mut self,
        d_share_polys: Vec<Poly>,
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext, Error> {
        let mut share_manager = ShareManager::new(self.n, self.threshold, self.params.clone());
        share_manager.decrypt_from_shares(d_share_polys, ciphertext)
    }
}

impl FheParametrized for TRBFV {
    type Parameters = BfvParameters;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfv::{BfvParametersBuilder, SecretKey};
    use rand::thread_rng;

    #[test]
    fn test_trbfv_new() {
        let n: usize = 16;
        let threshold = 9;
        let degree = 2048;
        let plaintext_modulus = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];
        let params = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        let trbfv = TRBFV::new(n, threshold, 160, params.clone()).unwrap();
        assert_eq!(trbfv.n, n);
        assert_eq!(trbfv.threshold, threshold);
        assert_eq!(trbfv.smudging_variance, 160);
        assert_eq!(trbfv.params, params);
    }

    #[test]
    fn test_validation_errors() {
        let degree = 2048;
        let plaintext_modulus = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];
        let params = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        // Test invalid n = 0
        assert!(TRBFV::new(0, 3, 160, params.clone()).is_err());

        // Test invalid threshold >= n
        assert!(TRBFV::new(5, 5, 160, params.clone()).is_err());

        // Test invalid threshold = 0
        assert!(TRBFV::new(5, 0, 160, params.clone()).is_err());
    }

    #[test]
    fn test_secret_sharing_integration() {
        let n: usize = 16;
        let threshold = 9;
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

        let mut trbfv = TRBFV::new(n, threshold, 160, params.clone()).unwrap();
        let sk = SecretKey::random(&params, &mut rng);
        let coeffs = sk.coeffs.clone();

        let shares = trbfv.generate_secret_shares(coeffs);
        assert!(shares.is_ok());
        let shares = shares.unwrap();
        assert_eq!(shares.len(), moduli.len());
        assert_eq!(shares[0].nrows(), n); // n parties
        assert_eq!(shares[0].ncols(), degree); // degree coefficients
    }

    #[test]
    fn test_smudging_integration() {
        let n: usize = 16;
        let threshold = 9;
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

        let mut trbfv = TRBFV::new(n, threshold, 160, params.clone()).unwrap();
        let smudging_error = trbfv.generate_smudging_error(&mut rng);
        assert!(smudging_error.is_ok());
        let smudging_error = smudging_error.unwrap();
        assert_eq!(smudging_error.len(), degree);
    }
}
