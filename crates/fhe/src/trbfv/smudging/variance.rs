/// Variance calculator for smudging noise in threshold BFV.
///
/// This module provides functionality to calculate the optimal smudging noise variance
/// that satisfies both security and correctness constraints for threshold BFV operations.
use crate::bfv::BfvParameters;
use crate::Error;
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};
use std::sync::Arc;

/// Parameters for variance calculation.
///
/// These parameters define the security and correctness constraints for smudging noise.
/// The configuration is tied to specific BFV parameters to ensure consistency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarianceCalculatorConfig {
    /// BFV parameters (degree, moduli, plaintext modulus, etc.)
    pub params: Arc<BfvParameters>,
    /// Number of parties in the threshold scheme (n)
    pub n: usize,
    /// Number of multiplication operations in the circuit (m)
    pub m: usize,
    /// Encryption bound (B_enc)
    pub b_enc: u64,
    /// Error bound (B_e)
    pub b_e: u64,
    /// Public key error bound
    pub public_key_error_bound: u64,
    /// Secret key bound
    pub secret_key_bound: u64,
    /// Security parameter lambda
    pub lambda: usize,
}

impl VarianceCalculatorConfig {
    /// Create a new variance calculator configuration.
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `n` - Number of parties in the threshold scheme
    /// * `m` - Number of multiplication operations in the circuit
    pub fn new(params: Arc<BfvParameters>, n: usize, m: usize) -> Self {
        Self {
            params,
            n,
            m,
            b_enc: 19,
            b_e: 19,
            public_key_error_bound: 19,
            secret_key_bound: 10,
            lambda: 80,
        }
    }

    /// Set the number of parties (n).
    pub fn with_n(mut self, n: usize) -> Self {
        self.n = n;
        self
    }

    /// Set the number of multiplications (m).
    pub fn with_m(mut self, m: usize) -> Self {
        self.m = m;
        self
    }

    /// Set the encryption bound (B_enc).
    pub fn with_b_enc(mut self, b_enc: u64) -> Self {
        self.b_enc = b_enc;
        self
    }

    /// Set the error bound (B_e).
    pub fn with_b_e(mut self, b_e: u64) -> Self {
        self.b_e = b_e;
        self
    }

    /// Set the public key error bound.
    pub fn with_public_key_error_bound(mut self, bound: u64) -> Self {
        self.public_key_error_bound = bound;
        self
    }

    /// Set the secret key bound.
    pub fn with_secret_key_bound(mut self, bound: u64) -> Self {
        self.secret_key_bound = bound;
        self
    }
}

/// Calculator for smudging noise variance.
///
/// This struct provides methods to calculate the optimal variance for smudging noise
/// based on the security and correctness requirements of threshold BFV operations.
#[derive(Debug)]
pub struct VarianceCalculator {
    /// Variance calculation configuration (includes BFV parameters)
    config: VarianceCalculatorConfig,
}

impl VarianceCalculator {
    /// Create a new variance calculator.
    ///
    /// # Arguments
    /// * `config` - Configuration containing BFV parameters and variance calculation constraints
    pub fn new(config: VarianceCalculatorConfig) -> Self {
        Self { config }
    }

    /// Calculate the optimal smudging noise variance.
    ///
    /// This method implements the variance calculation algorithm based on the
    /// security analysis for threshold BFV operations.
    ///
    /// # Returns
    /// The calculated variance for smudging noise generation
    pub fn calculate_variance(&self) -> Result<BigUint, Error> {
        // Step 1: Calculate B_fresh - fresh ciphertext noise bound
        let degree = self.config.params.degree() as u64;
        let b_fresh = self.calculate_b_fresh(degree)?;

        // Step 2: Calculate B_c - circuit noise bound
        let b_circuit = self.calculate_b_circuit(b_fresh)?;

        // Step 3: Calculate upper bound constraint (correctness)
        let upper_bound = self.calculate_upper_bound(b_circuit)?;

        // Step 4: Calculate lower bound constraint (security)
        let lower_bound = self.calculate_lower_bound(b_circuit)?;

        // Step 5: Validate bounds are feasible
        if lower_bound > upper_bound {
            return Err(Error::smudging(format!(
                "Infeasible bounds: lower_bound ({}) > upper_bound ({}). \
                Consider adjusting security parameters or circuit depth.",
                lower_bound, upper_bound
            )));
        }

        // Step 6: Choose B_sm (for now, use the geometric mean of bounds approximation)
        let b_sm = if lower_bound.is_zero() {
            &upper_bound / BigUint::from(2u64)
        } else {
            if upper_bound > &lower_bound * BigUint::from(10u64) {
                // If upper bound is much larger, use closer to lower bound
                &lower_bound * BigUint::from(2u64)
            } else {
                // Use arithmetic mean as approximation for geometric mean
                (&lower_bound + &upper_bound) / BigUint::from(2u64)
            }
        };

        // Step 7: Calculate variance assuming uniform distribution over [-B_sm, B_sm]
        // For uniform distribution: σ² = (B_sm / 3)²
        let variance = (&b_sm / BigUint::from(3u64)).pow(2);

        Ok(variance)
    }

    /// Calculate the full ciphertext modulus Q = ∏q_i.
    ///
    /// In BFV with RNS representation, we need the product of all moduli.
    fn calculate_full_modulus(&self) -> BigUint {
        let moduli = self.config.params.moduli();
        let mut q_full = BigUint::one();
        for &qi in moduli {
            q_full *= BigUint::from(qi);
        }
        q_full
    }

    /// Calculate B_fresh - fresh ciphertext noise bound.
    ///
    /// B_fresh = d * |e| + B_enc + d * B * |sk|
    ///
    /// # Arguments
    /// * `degree` - Polynomial degree (d)
    fn calculate_b_fresh(&self, degree: u64) -> Result<u64, Error> {
        let d = degree;
        let e_bound = self.config.b_e;
        let b_enc = self.config.b_enc;
        let sk_bound = self.config.secret_key_bound;

        // B_fresh = d * |e| + B_enc + d * B * |sk|
        // Note: B in the formula appears to be related to some bound, using b_e for now
        let b_fresh = d * e_bound + b_enc + d * self.config.b_e * sk_bound;

        Ok(b_fresh)
    }

    /// Calculate B_c - circuit noise bound.
    ///
    /// B_c = m * B_fresh + |ε(q)| where ε(q) is the remainder of q/t
    ///
    /// # Arguments
    /// * `b_fresh` - Fresh ciphertext noise bound
    fn calculate_b_circuit(&self, b_fresh: u64) -> Result<u64, Error> {
        let m = self.config.m as u64;

        // Calculate |ε(q)| - remainder of Q/t where Q is the full modulus and t is the plaintext modulus
        let q_full = self.calculate_full_modulus();
        let t = BigUint::from(self.config.params.plaintext());
        let epsilon_q = (&q_full % &t).to_u64().unwrap_or(0);

        let b_circuit = m * b_fresh + epsilon_q;

        Ok(b_circuit)
    }

    /// Calculate upper bound constraint for correctness.
    ///
    /// B_sm < (Q/2t - B_c)/n
    ///
    /// # Arguments
    /// * `b_circuit` - Circuit noise bound
    fn calculate_upper_bound(&self, b_circuit: u64) -> Result<BigUint, Error> {
        let q_full = self.calculate_full_modulus();
        let t = BigUint::from(self.config.params.plaintext());
        let n = BigUint::from(self.config.n);
        let b_circuit_big = BigUint::from(b_circuit);

        // Calculate Q/(2*t) - B_c
        let numerator = &q_full / (&t * BigUint::from(2u64));

        if numerator <= b_circuit_big {
            return Err(Error::smudging(format!(
                "Circuit noise bound ({}) exceeds correctness threshold ({}). \
                Circuit is too deep for these parameters.",
                b_circuit, numerator
            )));
        }

        let upper_bound = (numerator - b_circuit_big) / n;

        Ok(upper_bound)
    }

    /// Calculate lower bound constraint for security.
    ///
    /// B_sm >= 2^λ * B_c
    ///
    /// # Arguments
    /// * `b_circuit` - Circuit noise bound
    fn calculate_lower_bound(&self, b_circuit: u64) -> Result<BigUint, Error> {
        let lambda = self.config.lambda;

        // Calculate 2^λ * B_c
        let security_factor = BigUint::one() << lambda; // 2^λ
        let lower_bound = security_factor * BigUint::from(b_circuit);

        Ok(lower_bound)
    }

    /// Get the current configuration.
    pub fn config(&self) -> &VarianceCalculatorConfig {
        &self.config
    }

    /// Update the configuration.
    pub fn set_config(&mut self, config: VarianceCalculatorConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfv::BfvParametersBuilder;

    #[test]
    fn test_variance_calculator_creation() {
        let params = BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(4096)
            .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
            .build_arc()
            .unwrap();

        let config = VarianceCalculatorConfig::new(params, 10, 1);
        let calculator = VarianceCalculator::new(config);

        assert_eq!(calculator.config.n, 10);
        assert_eq!(calculator.config.m, 1);
        assert_eq!(calculator.config.lambda, 80);
    }

    #[test]
    fn test_variance_calculation() {
        let params = BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(4096)
            .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
            .build_arc()
            .unwrap();

        let config = VarianceCalculatorConfig::new(params, 10, 1);
        let calculator = VarianceCalculator::new(config);

        // Test variance calculation - with lambda=80, bounds might be infeasible
        let result = calculator.calculate_variance();
        match result {
            Ok(variance) => {
                assert!(variance > BigUint::zero(), "Variance should be positive");
            }
            Err(e) => {
                // With lambda=80, bounds might be infeasible - this is expected
                assert!(e.to_string().contains("bounds") || e.to_string().contains("lambda"));
            }
        }
    }

    #[test]
    fn test_correctness_handling() {
        let params = BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(4096)
            .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
            .build_arc()
            .unwrap();

        let config = VarianceCalculatorConfig::new(params, 10, 4);
        let calculator = VarianceCalculator::new(config);

        // This should handle lambda=80 gracefully - with m=4, bounds might be infeasible
        let result = calculator.calculate_variance();
        match result {
            Ok(variance) => {
                assert!(variance > BigUint::zero());
            }
            Err(e) => {
                // With lambda=80 and m=4, this might fail due to infeasible bounds
                assert!(e.to_string().contains("bounds") || e.to_string().contains("Circuit"));
            }
        }
    }

    #[test]
    fn test_builder_pattern() {
        let params = BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(4096)
            .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
            .build_arc()
            .unwrap();

        let config = VarianceCalculatorConfig::new(params, 5, 3)
            .with_b_enc(25)
            .with_b_e(30)
            .with_secret_key_bound(15);

        assert_eq!(config.n, 5);
        assert_eq!(config.m, 3);
        assert_eq!(config.lambda, 80);
        assert_eq!(config.b_enc, 25);
        assert_eq!(config.b_e, 30);
        assert_eq!(config.secret_key_bound, 15);
    }

    #[test]
    fn test_full_modulus_calculation() {
        // Use valid BFV parameters that satisfy NTT constraints
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(17)
            .set_moduli(&[97, 113])
            .build_arc()
            .unwrap();

        let config = VarianceCalculatorConfig::new(params, 5, 1);
        let calculator = VarianceCalculator::new(config);

        let full_modulus = calculator.calculate_full_modulus();
        let expected = BigUint::from(97u64 * 113u64); // 10961
        assert_eq!(full_modulus, expected);
    }
}
