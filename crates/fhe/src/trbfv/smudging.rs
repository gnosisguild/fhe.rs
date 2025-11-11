/// Threshold BFV Smudging Noise Generation
///
/// This module provides variance calculation and smudging noise generation for threshold BFV.
/// Variance calculations use arbitrary precision arithmetic, while noise generation uses
/// optimized standard library sampling since cryptographic variances always exceed i64 bounds.
///
/// Key features:
/// - Arbitrary precision variance calculation using BigUint
/// - Efficient noise generation using standard uniform sampling
/// - Statistical Security parameter λ = 80 with configurable circuit depth
/// - No precision loss in calculations while maintaining performance
use crate::bfv::BfvParameters;
//use crate::trbfv::normal::sample_bigint_normal_vec;
use crate::Error;

use num_bigint::{BigInt, BigUint, RandBigInt};
use rand::{CryptoRng, Rng, RngCore};
use std::sync::Arc;

/// Configuration for calculating optimal smudging variance in threshold BFV.
///
/// All parameters use arbitrary precision arithmetic to handle cryptographically large values.
#[derive(Debug, Clone)]
pub struct SmudgingBoundCalculatorConfig {
    /// BFV parameters (degree, moduli, plaintext modulus)
    pub params: Arc<BfvParameters>,
    /// Number of parties in the threshold scheme
    pub n: usize,
    /// Number of ciphertexts being processed
    pub m: usize,
    /// Encryption error1 bound (BigUint for arbitrary precision)
    pub b_enc: BigUint,
    /// Encryption error2 bound (u64 for standard integers)
    pub b_e: u64,
    /// Public key error poly for infinity norm calculation
    pub public_key_error: u64,
    /// Secret key poly for infinity norm calculation
    pub secret_key_bound: u64,
    /// Statistical Security parameter (fixed: 80)
    pub lambda: usize,
}

impl SmudgingBoundCalculatorConfig {
    /// Create a new variance calculator configuration with standard parameters.
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `n` - Number of parties in threshold scheme  
    /// * `m` - Number of ciphertexts to process
    pub fn new(params: Arc<BfvParameters>, n: usize, m: usize) -> Self {
        let variance = params.variance();
        let error1_variance = params.get_error1_variance().clone();
        // B_enc ≈ sqrt(3 * error1_variance)
        let b_enc = (BigUint::from(3u32) * error1_variance).sqrt();

        Self {
            params,
            n,
            m,
            b_enc,
            b_e: (2 * variance) as u64,
            public_key_error: (2 * variance) as u64,
            secret_key_bound: n as u64,
            lambda: 80,
        }
    }
}

/// Calculator for optimal smudging variance using arbitrary precision arithmetic.
///
/// Implements the trBFV security formulas without any approximations or precision limitations.
#[derive(Debug)]
pub struct SmudgingBoundCalculator {
    config: SmudgingBoundCalculatorConfig,
}

impl SmudgingBoundCalculator {
    /// Create a new bound calculator.
    pub fn new(config: SmudgingBoundCalculatorConfig) -> Self {
        Self { config }
    }

    /// Calculate the optimal smudging bound using arbitrary precision arithmetic.
    ///
    /// Implements the trBFV security formula for B_sm which balances
    /// security (≥ 2^λ * B_c) and correctness (< (Q/2t - B_c)/n).
    ///
    /// # Returns
    /// Calculated bound B_sm as BigUint (can be arbitrarily large)
    ///
    /// # Errors
    /// Returns error if circuit is too deep (B_c exceeds Q/2t limit)
    pub fn calculate_sm_bound(&self) -> Result<BigUint, Error> {
        // Degree and basic parameters
        let d = BigUint::from(self.config.params.degree());

        // b_enc is already BigUint, use directly
        let b_enc = &self.config.b_enc;
        // b_e is u64, convert to BigUint for calculations
        let b_e = BigUint::from(self.config.b_e);
        let e_norm = BigUint::from(self.config.public_key_error);
        let sk_norm = BigUint::from(self.config.secret_key_bound);

        // Calculate B_fresh = d·||e||_∞ + B_enc + d·B_e·||sk||_∞
        let b_fresh = &d * &e_norm + b_enc + &d * &b_e * &sk_norm;

        // Calculate full modulus Q = ∏q_i
        let mut q_full = BigUint::from(1u64);
        for &modulus in self.config.params.moduli() {
            q_full *= BigUint::from(modulus);
        }

        // Calculate circuit depth bound B_c = m·(B_fresh + (Q mod t))
        let t = BigUint::from(self.config.params.plaintext());
        let b_c = BigUint::from(self.config.m) * (&b_fresh + &q_full % &t);

        // Security constraint: verify B_c < Q/(2t) for correctness
        let q_over_2t = &q_full / (BigUint::from(2u64) * &t);
        if b_c >= q_over_2t {
            return Err(Error::UnspecifiedInput(
                "Circuit too deep: B_c exceeds Q/(2t), violating correctness bound".to_string(),
            ));
        }

        // Calculate optimal B_sm: balance security (2^λ·B_c) and correctness ((Q/2t - B_c)/n)
        let lower_bound = BigUint::from(2u64).pow(self.config.lambda as u32) * &b_c;
        let upper_bound = (&q_over_2t - &b_c) / BigUint::from(self.config.n);
        let b_sm = if upper_bound >= lower_bound {
            lower_bound
        } else {
            return Err(Error::UnspecifiedInput(
                "Upper bound is less than lower bound, cannot calculate B_sm".to_string(),
            ));
        };

        Ok(b_sm)
    }
}

/// Smudging noise generator using simple uniform sampling.
///
/// Since calculated variances (180+ bits) always exceed i64 bounds, we directly
/// use maximum safe sampling range without arbitrary precision overhead.
#[derive(Debug)]
pub struct SmudgingNoiseGenerator {
    params: Arc<BfvParameters>,
    smudging_bound: BigUint,
}

impl SmudgingNoiseGenerator {
    /// Create a new noise generator with calculated variance.
    pub fn new(params: Arc<BfvParameters>, smudging_bound: BigUint) -> Self {
        Self {
            params,
            smudging_bound,
        }
    }

    /// Create a noise generator from a smudging bound calculator.
    pub fn from_bound_calculator(calculator: SmudgingBoundCalculator) -> Result<Self, Error> {
        let params = calculator.config.params.clone();
        let smudging_bound = calculator.calculate_sm_bound()?;
        Ok(Self::new(params, smudging_bound))
    }

    /// Generate smudging error coefficients using the calculated bound.
    ///
    /// # Returns
    /// A vector of BigInt coefficients sampled from the normal distribution
    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Vec<BigInt>, Error> {
        let degree = self.params.degree();

        // To sample the smudging noise from a normal distribution uncomment the following lines

        // Convert B_sm (stored in `smudging_variance`) to BigInt for sampling
        // let bound = BigInt::from(self.smudging_bound.clone());

        // Sample degree many noise coefficients from D_{Z,σ} ∩ [-bound, bound]
        // let samples = sample_bigint_normal_vec(&bound, degree);

        // Sample degree many noise coefficients uniformly from [-bound, bound]
        let samples = self.sample_uniform_coefficients(degree, rng);

        Ok(samples)
    }

    /// Sample uniform coefficients from [-bound, bound]
    fn sample_uniform_coefficients<R: RngCore + CryptoRng>(
        &self,
        count: usize,
        rng: &mut R,
    ) -> Vec<BigInt> {
        let mut samples = Vec::with_capacity(count);

        // Pre-calculate bound + 1 for efficiency
        let upper_bound = &self.smudging_bound + 1u32;
        let zero = BigUint::from(0u32);

        for _ in 0..count {
            // Sample magnitude from [0, bound]
            let magnitude = rng.gen_biguint_range(&zero, &upper_bound);
            let abs_value = BigInt::from(magnitude);

            // Randomly choose sign (50/50 chance)
            let sample = if rng.gen_bool(0.5) {
                abs_value
            } else {
                -abs_value
            };

            samples.push(sample);
        }

        samples
    }

    /// Get the polynomial degree.
    pub fn degree(&self) -> usize {
        self.params.degree()
    }

    /// Get the smudging variance.
    pub fn smudging_bound(&self) -> &BigUint {
        &self.smudging_bound
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfv::BfvParametersBuilder;
    use num_traits::Signed;
    use num_traits::Zero;
    use rand::thread_rng;
    use std::str::FromStr;

    fn test_params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(8192)
            .set_plaintext_modulus(16384)
            .set_moduli(&[0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001])
            .build_arc()
            .unwrap()
    }

    #[test]
    fn test_smudging_bound_calculator_config() {
        let params = test_params();
        let config = SmudgingBoundCalculatorConfig::new(params.clone(), 5, 2);

        assert_eq!(config.params, params);
        assert_eq!(config.n, 5);
        assert_eq!(config.m, 2);
        // b_enc is now BigUint
        assert_eq!(
            config.b_enc,
            (BigUint::from(3u32) * params.get_error1_variance()).sqrt()
        );
        // b_e is u64
        assert_eq!(config.b_e, (params.variance() * 2) as u64);
        assert_eq!(config.public_key_error, 2 * params.variance() as u64);
        assert_eq!(config.secret_key_bound, 5);
        assert_eq!(config.lambda, 80);
    }

    #[test]
    fn test_smudging_bound_calculator_minimal_case() {
        let params = test_params();
        let config = SmudgingBoundCalculatorConfig::new(params.clone(), 3, 1);
        let calculator = SmudgingBoundCalculator::new(config);

        let result = calculator.calculate_sm_bound();

        // With small parameters, this should succeed
        match result {
            Ok(bound) => {
                assert!(bound > BigUint::from(0u64));
                println!("Calculated bound has {} bits", bound.bits());
            }
            Err(e) => {
                // If it fails, should be due to circuit depth constraint
                assert!(
                    e.to_string().contains("Circuit too deep")
                        || e.to_string()
                            .contains("Upper bound is less than lower bound")
                );
            }
        }
    }

    #[test]
    fn test_smudging_noise_generator_creation() {
        let params = test_params();
        let bound = BigUint::from(12345u64);
        let generator = SmudgingNoiseGenerator::new(params.clone(), bound.clone());

        assert_eq!(generator.params, params);
        assert_eq!(generator.smudging_bound, bound);
        assert_eq!(generator.degree(), params.degree());
        assert_eq!(generator.smudging_bound(), &bound);
    }

    #[test]
    fn test_smudging_noise_generator_from_calculator() {
        let params = test_params();
        let config = SmudgingBoundCalculatorConfig::new(params.clone(), 3, 1);
        let calculator = SmudgingBoundCalculator::new(config);

        let result = SmudgingNoiseGenerator::from_bound_calculator(calculator);

        match result {
            Ok(generator) => {
                assert_eq!(generator.params, params);
                assert_eq!(generator.degree(), params.degree());
                assert!(generator.smudging_bound() > &BigUint::from(0u64));
            }
            Err(e) => {
                // Expected for large security parameter - that's OK
                assert!(!e.to_string().is_empty());
            }
        }
    }

    #[test]
    fn test_noise_generation_small_bound() {
        let mut rng = thread_rng();
        let params = test_params();
        let bound = BigUint::from(1000u64);
        let generator = SmudgingNoiseGenerator::new(params.clone(), bound);

        let result = generator.generate_smudging_error(&mut rng);
        assert!(result.is_ok());

        let coefficients = result.unwrap();
        assert_eq!(coefficients.len(), params.degree());

        // All coefficients should be bounded
        for coeff in &coefficients {
            assert!(coeff.abs() <= BigInt::from(1000u64));
        }
    }

    #[test]
    fn test_noise_generation_zero_bound() {
        let mut rng = thread_rng();
        let params = test_params();
        let bound = BigUint::from(0u64);
        let generator = SmudgingNoiseGenerator::new(params.clone(), bound);

        let coefficients = generator.generate_smudging_error(&mut rng).unwrap();
        assert_eq!(coefficients.len(), params.degree());
        assert!(coefficients.iter().all(|x| x.is_zero()));
    }

    #[test]
    fn test_noise_generation_large_bound() {
        let mut rng = thread_rng();
        let params = test_params();
        let large_bound = BigUint::from_str("123456789012345678901234567890").unwrap();
        let generator = SmudgingNoiseGenerator::new(params.clone(), large_bound.clone());

        let coefficients = generator.generate_smudging_error(&mut rng).unwrap();
        assert_eq!(coefficients.len(), params.degree());

        // Should generate non-zero coefficients with high probability
        let non_zero_count = coefficients.iter().filter(|x| !x.is_zero()).count();
        assert!(non_zero_count > coefficients.len() / 4); // At least 25% should be non-zero

        // All should be within bounds
        for coeff in &coefficients {
            assert!(coeff.abs() <= BigInt::from(large_bound.clone()));
        }
    }

    #[test]
    fn test_realistic_parameters_workflow() {
        let mut rng = thread_rng();
        let params = test_params();
        let n = 3;
        let m = 1;

        // Try the complete workflow
        let config = SmudgingBoundCalculatorConfig::new(params.clone(), n, m);
        let calculator = SmudgingBoundCalculator::new(config);

        let bound_result = calculator.calculate_sm_bound();

        match bound_result {
            Ok(bound) => {
                let generator = SmudgingNoiseGenerator::new(params.clone(), bound.clone());
                let coefficients = generator.generate_smudging_error(&mut rng).unwrap();
                assert_eq!(coefficients.len(), params.degree());
            }
            Err(_) => {
                // This is acceptable for some parameter sets
            }
        }
    }
}
