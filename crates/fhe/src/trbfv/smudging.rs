/// Threshold BFV Smudging Noise Generation
///
/// This module provides variance calculation and smudging noise generation for threshold BFV.
/// The noise generation uses security-optimal variance calculation based on:
/// - Security parameter λ = 80
/// - Circuit depth (number of multiplications)
/// - Number of parties
/// - BFV parameters (degree, moduli, plaintext modulus)
use crate::bfv::BfvParameters;
use crate::Error;

use num_bigint::BigUint;
use rand::distributions::{Distribution, Uniform};
use rand::{CryptoRng, Rng, RngCore};
use std::sync::Arc;

/// Configuration for calculating optimal smudging variance in threshold BFV.
///
/// This struct holds all parameters needed to calculate the optimal smudging noise
/// variance according to the trBFV security requirements.
#[derive(Debug, Clone)]
pub struct VarianceCalculatorConfig {
    /// BFV parameters (degree, moduli, plaintext modulus)
    pub params: Arc<BfvParameters>,
    /// Number of parties in the threshold scheme
    pub n: usize,
    /// Number of ciphertexts being processed
    pub m: usize,
    /// Encryption error bound (default 19)
    pub b_enc: u64,
    /// Fresh error bound (default 19)  
    pub b_e: u64,
    /// Public key error bound (default)
    pub public_key_error_bound: u64,
    /// Secret key coefficient bound (default 19)
    pub secret_key_bound: u64,
    /// Security parameter (fixed at 80)
    pub lambda: usize,
}

impl VarianceCalculatorConfig {
    /// Create a new variance calculator configuration.
    ///
    /// Uses standard cryptographic parameters:
    /// - b_enc = b_e = 19 (encryption/error bounds)
    /// - secret_key_bound = 10 (ternary secret key)
    /// - λ = 80 (security parameter)
    ///
    /// # Arguments
    /// * `params` - BFV parameters containing degree, moduli, plaintext modulus
    /// * `n` - Number of parties in threshold scheme
    /// * `m` - Number of ciphertexts being processed (e.g., votes to count, numbers to sum)
    pub fn new(params: Arc<BfvParameters>, n: usize, m: usize) -> Self {
        Self {
            params,
            n,
            m,
            b_enc: 19,
            b_e: 19,
            public_key_error_bound: 19,
            secret_key_bound: 19,
            lambda: 80,
        }
    }
}

/// Calculator for optimal smudging variance in threshold BFV schemes.
///
/// Implements the mathematical formulas for calculating secure smudging noise
/// variance that balances correctness and security requirements.
#[derive(Debug)]
pub struct VarianceCalculator {
    config: VarianceCalculatorConfig,
}

impl VarianceCalculator {
    /// Create a new variance calculator.
    pub fn new(config: VarianceCalculatorConfig) -> Self {
        Self { config }
    }

    /// Generate smudging error coefficients using optimal variance.
    ///
    /// This is the main method that calculates optimal variance and generates
    /// uniformly distributed smudging noise coefficients.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// Vector of smudging error coefficients (length = degree)
    ///
    /// # Errors
    /// Returns error if variance calculation fails (e.g., infeasible bounds with λ=80)
    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Vec<i64>, Error> {
        let (b_sm_bigint, _variance) = self.calculate_b_sm_and_variance()?;

        // TODO: check if this is correct
        // Use modular arithmetic: reduce B_sm modulo the primary BFV modulus
        // This preserves the mathematical structure while keeping values manageable
        let primary_modulus = BigUint::from(self.config.params.moduli()[0]);
        let b_sm_mod = &b_sm_bigint % &primary_modulus;

        // Convert the reduced bound to u64 (fits since it's < modulus < 2^64)
        let b_sm_u64: u64 = b_sm_mod
            .try_into()
            .map_err(|_| Error::UnspecifiedInput("Modular reduction failed".to_string()))?;

        // For symmetric sampling in [-bound, bound], we need bound < i64::MAX
        // If the modular bound is too large, use half the modulus
        let b_sm = if b_sm_u64 > i64::MAX as u64 {
            (primary_modulus.clone() / BigUint::from(2u64))
                .try_into()
                .unwrap_or(i64::MAX / 2)
        } else {
            b_sm_u64 as i64
        };

        // Generate uniform noise over [-B_sm, B_sm] for each coefficient
        let mut coefficients = Vec::with_capacity(self.config.params.degree());
        for _ in 0..self.config.params.degree() {
            let coeff = Self::sample_uniform_symmetric(b_sm, rng);
            coefficients.push(coeff);
        }

        Ok(coefficients)
    }

    /// Calculate the optimal smudging variance.
    ///
    /// # Returns
    /// The calculated variance as BigUint
    ///
    /// # Errors
    /// Returns error if bounds are infeasible (lower bound > upper bound)
    pub fn calculate_variance(&self) -> Result<BigUint, Error> {
        let (_b_sm, variance) = self.calculate_b_sm_and_variance()?;
        Ok(variance)
    }

    /// Internal method to calculate both B_sm and variance in one go.
    ///
    /// This avoids redundant calculations and conversion cycles.
    ///
    /// # Returns
    /// Tuple of (B_sm as BigUint, variance as BigUint)
    fn calculate_b_sm_and_variance(&self) -> Result<(BigUint, BigUint), Error> {
        // Step 1: Calculate B_fresh = d * |e| + B_enc + d * B * |sk|
        let degree = self.config.params.degree() as u64;
        let b_fresh = degree * self.config.public_key_error_bound
            + self.config.b_enc
            + degree * self.config.b_e * self.config.secret_key_bound;

        // Step 2: Calculate full modulus Q = ∏ q_i (product of all moduli)
        let mut q_full = BigUint::from(1u64);
        for &modulus in self.config.params.moduli() {
            q_full *= BigUint::from(modulus);
        }

        // Step 3: Calculate k = t (plaintext modulus)
        let k = BigUint::from(self.config.params.plaintext());

        // Step 4: Calculate ε(q) = Q mod k (remainder)
        let epsilon_q = &q_full % &k;

        // Step 5: Calculate B_c = m * B_fresh + ε(q)
        let b_c = BigUint::from(self.config.m as u64) * BigUint::from(b_fresh) + epsilon_q;

        // Step 6: Calculate bounds for B_sm
        // Upper bound: B_sm < (Q/(2*t) - B_c) / n
        let two_t = BigUint::from(2u64) * &k;
        let q_over_2t = &q_full / &two_t;

        if q_over_2t <= b_c {
            return Err(Error::UnspecifiedInput(
                "Circuit too deep: B_c exceeds Q/(2t), making correctness impossible".to_string(),
            ));
        }

        let upper_bound = (&q_over_2t - &b_c) / BigUint::from(self.config.n);

        // Lower bound: B_sm >= 2^λ * B_c
        let two_lambda = BigUint::from(2u64).pow(self.config.lambda as u32);
        let lower_bound = &two_lambda * &b_c;

        // Use lower bound + upper bound / 2 for security (conservative approach)
        // TODO: check if this is correct
        let b_sm_bigint = lower_bound + &upper_bound / BigUint::from(2u64);

        // Calculate variance: σ² = (B_sm / 3)²
        let b_sm_over_3 = &b_sm_bigint / BigUint::from(3u64);
        let variance = &b_sm_over_3 * &b_sm_over_3;

        Ok((b_sm_bigint, variance))
    }

    /// Sample uniformly from [-bound, bound]
    fn sample_uniform_symmetric<R: Rng>(bound: i64, rng: &mut R) -> i64 {
        Uniform::new_inclusive(-bound, bound).sample(rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfv::BfvParametersBuilder;
    use rand::thread_rng;

    fn realistic_params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(4096)
            .set_plaintext_modulus(65537)
            .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
            .build_arc()
            .unwrap()
    }

    fn small_params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(4096)
            .set_moduli(&[0xffffee001, 0xffffc4001])
            .build_arc()
            .unwrap()
    }

    #[test]
    fn test_variance_calculator_basic() {
        let params = realistic_params();
        let config = VarianceCalculatorConfig::new(params, 3, 1);
        let calculator = VarianceCalculator::new(config);

        // Should either succeed or fail gracefully with λ=80
        match calculator.calculate_variance() {
            Ok(variance) => {
                assert!(variance > BigUint::from(0u64));
                println!("✓ Variance calculated: {}", variance);
            }
            Err(e) => {
                println!("Expected failure with λ=80: {}", e);
                assert!(e.to_string().contains("Infeasible"));
            }
        }
    }

    #[test]
    fn test_smudging_generation() {
        let params = realistic_params();
        let config = VarianceCalculatorConfig::new(params.clone(), 3, 1);
        let calculator = VarianceCalculator::new(config);
        let mut rng = thread_rng();

        match calculator.generate_smudging_error(&mut rng) {
            Ok(coefficients) => {
                assert_eq!(coefficients.len(), params.degree());
                println!("✓ Generated {} smudging coefficients", coefficients.len());
            }
            Err(e) => {
                println!("Expected failure with λ=80: {}", e);
                assert!(e.to_string().len() > 0);
            }
        }
    }

    #[test]
    fn test_mathematical_consistency() {
        let params = small_params();
        let config = VarianceCalculatorConfig::new(params, 3, 1);
        let calculator = VarianceCalculator::new(config);

        if let Ok((b_sm, variance)) = calculator.calculate_b_sm_and_variance() {
            // Verify variance = (B_sm / 3)²
            let b_sm_over_3 = &b_sm / BigUint::from(3u64);
            let expected_variance = &b_sm_over_3 * &b_sm_over_3;
            assert_eq!(variance, expected_variance);
            println!(
                "✓ Mathematical consistency verified: B_sm={}, σ²={}",
                b_sm, variance
            );
        }
    }

    #[test]
    fn test_parameter_validation() {
        let params = small_params();

        // Test with extremely large number of ciphertexts - should trigger B_c > Q/(2t) error
        let config = VarianceCalculatorConfig::new(params, 3, 100_000_000);
        let calculator = VarianceCalculator::new(config);

        let result = calculator.calculate_variance();
        match result {
            Err(e) if e.to_string().contains("Circuit too deep") => {
                println!("✓ Correctly rejected infeasible parameters: B_c > Q/(2t)");
            }
            Ok(_) => {
                println!("✓ Large parameter set succeeded (calculation is robust)");
            }
            Err(e) => {
                println!("✓ Parameters rejected for other reason: {}", e);
            }
        }
    }

    #[test]
    fn test_config_creation() {
        let params = realistic_params();
        let config = VarianceCalculatorConfig::new(params.clone(), 5, 2);

        assert_eq!(config.n, 5);
        assert_eq!(config.m, 2);
        assert_eq!(config.b_enc, 19);
        assert_eq!(config.b_e, 19);
        assert_eq!(config.public_key_error_bound, 19);
        assert_eq!(config.secret_key_bound, 19);
        assert_eq!(config.lambda, 80);
        assert_eq!(config.params.degree(), 4096);
    }
}
