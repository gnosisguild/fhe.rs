use std::sync::Arc;

/// Main threshold BFV orchestrator.
///
/// This module provides the main TRBFV struct that coordinates between secret sharing,
/// smudging, and share management operations to implement the threshold BFV protocol.
///
/// # Threshold BFV Overview
///
/// Threshold BFV enables distributed decryption where:
/// - Secret keys are shared among n parties using secret sharing
/// - Only t+1 parties (threshold) are needed to decrypt
/// - Up to t parties can be compromised without breaking security
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
use crate::trbfv::shares::ShareManager;
use crate::trbfv::smudging::{
    SmudgingBoundCalculator, SmudgingBoundCalculatorConfig, SmudgingNoiseGenerator,
};
use crate::Error;
use fhe_math::rq::Poly;
use fhe_traits::FheParametrized;
use ndarray::Array2;
use num_bigint::BigInt;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Threshold BFV configuration and operations.
/// This struct serves as the main coordinator for threshold BFV operations, managing
/// the interaction between secret sharing, smudging, and share management components.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TRBFV {
    /// Number of parties in the threshold scheme
    pub n: usize,
    /// Threshold for reconstruction (must be <= (n-1)/2)
    pub threshold: usize,
    /// BFV parameters (contains degree, plaintext_modulus, moduli, etc.)
    pub params: Arc<BfvParameters>,
}

impl TRBFV {
    /// Creates a new threshold BFV configuration.
    ///
    /// # Arguments
    /// * `n` - Number of parties (must be > 0)
    /// * `threshold` - Threshold for reconstruction (must be <= (n-1)/2)
    /// * `params` - BFV parameters
    pub fn new(n: usize, threshold: usize, params: Arc<BfvParameters>) -> Result<Self, Error> {
        // Validate all parameters
        validate_threshold_config(n, threshold)?;

        Ok(Self {
            n,
            threshold,
            params,
        })
    }

    /// Generate Shamir Secret Shares for polynomial coefficients.
    ///
    /// This method creates secret shares that can be distributed to different parties.
    /// Each party will receive one share for each polynomial coefficient.
    ///
    /// # Arguments
    /// * `poly` - Polynomial to be shared (typically secret key polynomial)
    ///
    /// # Returns
    /// Vector of share matrices, one per BFV modulus. Each matrix has dimensions [n, degree].
    pub fn generate_secret_shares_from_poly(
        &mut self,
        poly: Zeroizing<Poly>,
    ) -> Result<Vec<Array2<u64>>, Error> {
        let mut share_manager = ShareManager::new(self.n, self.threshold, self.params.clone());
        share_manager.generate_secret_shares_from_poly(poly)
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
    /// Creates noise that will be added to decryption shares.
    /// Uses optimal variance calculation based on security parameters and number of ciphertexts.
    ///
    /// # Arguments
    /// * `num_ciphertexts` - Number of ciphertexts being processed (e.g., votes to count, numbers to sum)
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// Vector of smudging error coefficients
    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &self,
        num_ciphertexts: usize,
        _rng: &mut R,
    ) -> Result<Vec<BigInt>, Error> {
        let config =
            SmudgingBoundCalculatorConfig::new(self.params.clone(), self.n, num_ciphertexts);
        let calculator = SmudgingBoundCalculator::new(config);
        let generator = SmudgingNoiseGenerator::from_bound_calculator(calculator)?;

        generator.generate_smudging_error()
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
    use crate::bfv::{BfvParametersBuilder, Encoding, Plaintext, PublicKey, SecretKey};
    use fhe_math::rq::{Poly, Representation};
    use fhe_traits::{FheEncoder, FheEncrypter};
    use rand::{rngs::OsRng, thread_rng};

    fn test_params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(8192)
            .set_plaintext_modulus(16384)
            .set_moduli(&[0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001])
            .build_arc()
            .unwrap()
    }

    #[test]
    #[allow(unused_mut)]
    fn test_trbfv_new() {
        let n: usize = 16;
        let threshold = 7;
        let params = test_params();

        let mut trbfv = TRBFV::new(n, threshold, params.clone()).unwrap();
        assert_eq!(trbfv.n, n);
        assert_eq!(trbfv.threshold, threshold);
        assert_eq!(trbfv.params, params);
    }

    #[test]
    fn test_validation_errors() {
        let params = test_params();

        // Test invalid n = 0
        assert!(TRBFV::new(0, 3, params.clone()).is_err());

        // Test invalid threshold > (n-1)/2
        assert!(TRBFV::new(3, 2, params.clone()).is_err());
        assert!(TRBFV::new(3, 3, params.clone()).is_err());
        assert!(TRBFV::new(3, 4, params.clone()).is_err());
    }

    #[test]
    #[allow(unused_mut)]
    fn test_secret_sharing_integration() {
        let mut rng = thread_rng();
        let n: usize = 5;
        let threshold = 2;
        let params = test_params();

        let mut trbfv = TRBFV::new(n, threshold, params.clone()).unwrap();

        // Generate a secret key for testing
        let sk = SecretKey::random(&params, &mut rng);
        let share_manager = ShareManager::new(n, threshold, params.clone());
        let sk_poly = share_manager
            .coeffs_to_poly_level0(sk.coeffs.clone().as_ref())
            .unwrap();
        let shares = trbfv.generate_secret_shares_from_poly(sk_poly).unwrap();

        // Check that we got the right number of shares
        assert_eq!(shares.len(), params.moduli().len());
        for share_matrix in shares {
            assert_eq!(share_matrix.nrows(), n);
            assert_eq!(share_matrix.ncols(), params.degree());
        }
    }

    #[test]
    fn test_smudging_error_generation() {
        let params = test_params();
        let n = 3;
        let threshold = 1;
        let trbfv = TRBFV::new(n, threshold, params.clone()).unwrap();

        let result = trbfv.generate_smudging_error(1, &mut OsRng);
        assert_eq!(result.unwrap().len(), params.degree());
    }

    #[test]
    fn test_smudging_error_multiple_ciphertexts() {
        let params = test_params();
        let n = 3;
        let threshold = 1;
        let trbfv = TRBFV::new(n, threshold, params.clone()).unwrap();

        // Test with multiple ciphertexts (this should increase the bound requirements)
        let result = trbfv.generate_smudging_error(10, &mut OsRng);
        assert_eq!(result.unwrap().len(), params.degree());
    }

    #[test]
    fn test_decryption_share_generation() {
        let mut rng = thread_rng();
        let params = test_params();
        let n = 3;
        let threshold = 1;
        let mut trbfv = TRBFV::new(n, threshold, params.clone()).unwrap();

        // Create a test ciphertext
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let plaintext_data = vec![42u64];
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Generate polynomials for decryption share
        let share_manager = ShareManager::new(n, threshold, params.clone());
        let sk_poly = share_manager
            .coeffs_to_poly_level0(sk.coeffs.as_ref())
            .unwrap();
        let ctx = params.ctx_at_level(0).unwrap();
        let es_poly = Poly::zero(ctx, Representation::PowerBasis);

        let decryption_share = trbfv
            .decryption_share(ct, (*sk_poly).clone(), es_poly)
            .unwrap();

        assert_eq!(decryption_share.coefficients().ncols(), params.degree());
    }

    #[test]
    fn test_full_threshold_decrypt_workflow() {
        let mut rng = OsRng;
        let params = test_params();
        let n = 3;
        let threshold = 1;

        // Create multiple TRBFV instances (simulating parties)
        let mut trbfv_instances: Vec<TRBFV> = (0..n)
            .map(|_| TRBFV::new(n, threshold, params.clone()).unwrap())
            .collect();

        // Each party has their own secret key
        let secret_keys: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        // Create a test ciphertext (using first party's key for simplicity)
        let pk = PublicKey::new(&secret_keys[0], &mut rng);
        let plaintext_data = vec![123u64];
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Each party generates decryption shares
        let mut decryption_shares = Vec::new();
        for i in 0..(threshold+1) {
            let share_manager = ShareManager::new(n, threshold, params.clone());
            let sk_poly = share_manager
                .coeffs_to_poly_level0(secret_keys[i].coeffs.as_ref())
                .unwrap();
            let ctx = params.ctx_at_level(0).unwrap();
            let es_poly = Poly::zero(ctx, Representation::PowerBasis);

            let share = trbfv_instances[i]
                .decryption_share(ct.clone(), (*sk_poly).clone(), es_poly)
                .unwrap();
            decryption_shares.push(share);
        }

        // Test the decrypt method
        let result = trbfv_instances[0].decrypt(decryption_shares, ct);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fhe_parametrized_trait() {
        let params = test_params();
        let trbfv = TRBFV::new(3, 1, params.clone()).unwrap();

        // Test basic struct properties instead
        assert_eq!(trbfv.params, params);
    }

    #[test]
    fn test_clone_and_debug() {
        let params = test_params();
        let trbfv1 = TRBFV::new(5, 2, params.clone()).unwrap();

        // Test Clone
        let trbfv2 = trbfv1.clone();
        assert_eq!(trbfv1.n, trbfv2.n);
        assert_eq!(trbfv1.threshold, trbfv2.threshold);

        // Test Debug (should not panic)
        let debug_str = format!("{trbfv1:?}");
        assert!(debug_str.contains("TRBFV"));

        // Test PartialEq
        assert_eq!(trbfv1, trbfv2);
    }

    #[test]
    fn test_edge_case_minimal_threshold() {
        let params = test_params();

        // Minimal valid configuration: 3 parties, threshold 1
        let mut trbfv = TRBFV::new(3, 1, params.clone()).unwrap();
        assert_eq!(trbfv.n, 3);
        assert_eq!(trbfv.threshold, 1);

        // Test that basic operations work
        let mut rng = thread_rng();
        let sk = SecretKey::random(&params, &mut rng);
        let share_manager = ShareManager::new(3, 1, params.clone());
        let sk_poly = share_manager
            .coeffs_to_poly_level0(sk.coeffs.as_ref())
            .unwrap();

        let shares = trbfv.generate_secret_shares_from_poly(sk_poly);
        assert!(shares.is_ok());
    }
}
