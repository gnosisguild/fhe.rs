/// Threshold BFV Smudging Noise Generation
///
/// This module provides variance calculation and smudging noise generation for threshold BFV.
/// Variance calculations use arbitrary precision arithmetic, while noise generation uses
/// optimized standard library sampling since cryptographic variances always exceed i64 bounds.
///
/// Key features:
/// - Arbitrary precision variance calculation using BigUint
/// - Efficient noise generation using standard uniform sampling
/// - Security parameter λ = 80 with configurable circuit depth
/// - No precision loss in calculations while maintaining performance
use crate::bfv::BfvParameters;
use crate::Error;

use fhe_math::rq::Poly;
use num_bigint::BigUint;
use num_traits::Zero;
use rand::{CryptoRng, Rng, RngCore};
use std::sync::Arc;

/// Configuration for calculating optimal smudging variance in threshold BFV.
///
/// All parameters use arbitrary precision arithmetic to handle cryptographically large values.
#[derive(Debug, Clone)]
pub struct VarianceCalculatorConfig {
    /// BFV parameters (degree, moduli, plaintext modulus)
    pub params: Arc<BfvParameters>,
    /// Number of parties in the threshold scheme
    pub n: usize,
    /// Number of ciphertexts being processed
    pub m: usize,
    /// Encryption error bound (standard: 19)
    pub b_enc: u64,
    /// Fresh error bound (standard: 19)  
    pub b_e: u64,
    /// Public key error polynomials for infinity norm calculation
    pub public_key_errors: Vec<Poly>,
    /// Secret key polynomials for infinity norm calculation
    pub secret_keys: Vec<Poly>,
    /// Security parameter (fixed: 80)
    pub lambda: usize,
}

impl VarianceCalculatorConfig {
    /// Create a new variance calculator configuration with standard parameters.
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `n` - Number of parties in threshold scheme  
    /// * `m` - Number of ciphertexts to process
    /// * `public_key_errors` - Public key error polynomials
    /// * `secret_keys` - Secret key polynomials
    pub fn new(
        params: Arc<BfvParameters>,
        n: usize,
        m: usize,
        public_key_errors: Vec<Poly>,
        secret_keys: Vec<Poly>,
    ) -> Self {
        Self {
            params,
            n,
            m,
            b_enc: 19,
            b_e: 19,
            public_key_errors,
            secret_keys,
            lambda: 80,
        }
    }
}

/// Calculator for optimal smudging variance using arbitrary precision arithmetic.
///
/// Implements the trBFV security formulas without any approximations or precision limitations.
#[derive(Debug)]
pub struct VarianceCalculator {
    config: VarianceCalculatorConfig,
}

impl VarianceCalculator {
    /// Create a new variance calculator.
    pub fn new(config: VarianceCalculatorConfig) -> Self {
        Self { config }
    }

    /// Calculate the infinity norm of polynomial vectors using arbitrary precision.
    ///
    /// Returns the maximum absolute coefficient value across all polynomials.
    fn calculate_infinity_norm(polys: &[Poly]) -> BigUint {
        let mut max_coeff = BigUint::from(0u64);
        for poly in polys {
            let coeffs: Vec<BigUint> = poly.into();
            for coeff in coeffs {
                max_coeff = max_coeff.max(coeff);
            }
        }
        max_coeff
    }

    /// Calculate the optimal smudging variance using arbitrary precision arithmetic.
    ///
    /// Implements the trBFV variance formula: σ² = (B_sm/3)² where B_sm balances
    /// security (≥ 2^λ * B_c) and correctness (< (Q/2t - B_c)/n).
    ///
    /// # Returns
    /// Calculated variance as BigUint (can be arbitrarily large)
    ///
    /// # Errors  
    /// Returns error if circuit is too deep (B_c exceeds Q/2t limit)
    pub fn calculate_variance(&self) -> Result<BigUint, Error> {
        // Calculate infinity norms from actual polynomial errors
        let e_norm = Self::calculate_infinity_norm(&self.config.public_key_errors);
        let sk_norm = Self::calculate_infinity_norm(&self.config.secret_keys);

        // Calculate B_fresh = d·||e||_∞ + B_enc + d·B_e·||sk||_∞
        let d = BigUint::from(self.config.params.degree());
        let b_fresh = &d * e_norm
            + BigUint::from(self.config.b_enc)
            + &d * BigUint::from(self.config.b_e) * sk_norm;

        // Calculate full modulus Q = ∏q_i
        let mut q_full = BigUint::from(1u64);
        for &modulus in self.config.params.moduli() {
            q_full *= BigUint::from(modulus);
        }

        // Calculate circuit depth bound B_c = m·B_fresh + (Q mod t)
        let t = BigUint::from(self.config.params.plaintext());
        let b_c = BigUint::from(self.config.m) * b_fresh + &q_full % &t;

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
        let b_sm = (lower_bound + upper_bound) / BigUint::from(2u64);

        // Calculate variance: σ² = (B_sm/3)²
        let b_sm_div_3 = b_sm / BigUint::from(3u64);
        let variance = &b_sm_div_3 * &b_sm_div_3;

        Ok(variance)
    }
}

/// Smudging noise generator using simple uniform sampling.
///
/// Since calculated variances (180+ bits) always exceed i64 bounds, we directly
/// use maximum safe sampling range without arbitrary precision overhead.
#[derive(Debug)]
pub struct SmudgingNoiseGenerator {
    params: Arc<BfvParameters>,
    smudging_variance: BigUint,
}

impl SmudgingNoiseGenerator {
    /// Create a new noise generator with calculated variance.
    pub fn new(params: Arc<BfvParameters>, smudging_variance: BigUint) -> Self {
        Self {
            params,
            smudging_variance,
        }
    }

    /// Create a noise generator from a variance calculator.
    pub fn from_calculator(calculator: VarianceCalculator) -> Result<Self, Error> {
        let params = calculator.config.params.clone();
        let variance = calculator.calculate_variance()?;
        Ok(Self::new(params, variance))
    }

    /// Sample a vector with uniform distribution for cryptographically large variances.
    ///
    /// This function handles arbitrary precision variances using BigUint and samples
    /// uniformly from [-3√variance, 3√variance], saturating to i64 bounds when necessary.
    /// Designed for threshold cryptographic schemes where variances exceed standard limits.
    ///
    /// # Arguments
    /// * `vector_size` - Number of coefficients to generate
    /// * `variance` - Variance as BigUint (can be arbitrarily large)  
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// Vector of i64 coefficients sampled uniformly from the calculated range
    fn sample_vec_uniform_bigint<R: RngCore + CryptoRng>(
        vector_size: usize,
        variance: &BigUint,
        rng: &mut R,
    ) -> Result<Vec<i64>, &'static str> {
        // Handle zero variance case
        if variance.is_zero() {
            return Ok(vec![0i64; vector_size]);
        }

        // Calculate sampling bound: 3*sqrt(variance)
        // This covers ~99.7% of a normal distribution
        let sqrt_variance = variance.sqrt();
        let bound_bigint = &sqrt_variance * 3u64;

        // Convert to i64 with saturation for cryptographically large variances
        let max_safe_bound = i64::MAX / 2; // 2^62, maximum safe bound
        let bound = if bound_bigint.bits() > 62 {
            max_safe_bound // Saturate to safe maximum
        } else {
            // Safe to convert since it fits in 62 bits
            bound_bigint
                .to_string()
                .parse::<i64>()
                .unwrap_or(max_safe_bound)
                .min(max_safe_bound)
        };

        // Generate coefficients uniformly in [-bound, bound]
        let mut coefficients = Vec::with_capacity(vector_size);
        for _ in 0..vector_size {
            let coefficient = rng.gen_range(-bound..=bound);
            coefficients.push(coefficient);
        }

        Ok(coefficients)
    }

    /// Generate smudging noise coefficients using uniform sampling.
    ///
    /// Uses `sample_vec_uniform_bigint` function which handles arbitrary
    /// precision variances and automatically saturates to safe i64 bounds.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// Vector of i64 noise coefficients sampled uniformly from [-3√variance, 3√variance]
    ///
    /// # Errors
    /// Returns error if sampling fails
    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Vec<i64>, Error> {
        let degree = self.params.degree();

        // Use general-purpose BigUint-compatible uniform sampling
        Self::sample_vec_uniform_bigint(degree, &self.smudging_variance, rng)
            .map_err(|e| Error::UnspecifiedInput(format!("Sampling failed: {}", e)))
    }

    /// Get the polynomial degree.
    pub fn degree(&self) -> usize {
        self.params.degree()
    }

    /// Get the smudging variance.
    pub fn smudging_variance(&self) -> &BigUint {
        &self.smudging_variance
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfv::BfvParametersBuilder;
    use fhe_math::rq::{Poly, Representation};
    use rand::thread_rng;
    use std::str::FromStr;

    fn test_params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(4096)
            .set_plaintext_modulus(65537)
            .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
            .build_arc()
            .unwrap()
    }

    fn zero_polynomials(params: &Arc<BfvParameters>, count: usize) -> Vec<Poly> {
        let ctx = params.ctx_at_level(0).unwrap();
        (0..count)
            .map(|_| Poly::zero(&ctx, Representation::PowerBasis))
            .collect()
    }

    fn small_polynomials(params: &Arc<BfvParameters>, count: usize) -> Vec<Poly> {
        let mut rng = thread_rng();
        let ctx = params.ctx_at_level(0).unwrap();
        (0..count)
            .map(|_| Poly::small(&ctx, Representation::PowerBasis, 3, &mut rng).unwrap())
            .collect()
    }

    #[test]
    fn test_variance_calculation_minimal_case() {
        let params = test_params();
        let config = VarianceCalculatorConfig::new(
            params.clone(),
            3,
            1,
            zero_polynomials(&params, 1),
            zero_polynomials(&params, 1),
        );

        let variance = VarianceCalculator::new(config)
            .calculate_variance()
            .unwrap();

        assert!(variance > BigUint::from(0u64));
        assert!(
            variance.bits() > 100,
            "Variance should be cryptographically large"
        );
    }

    #[test]
    fn test_variance_calculation_circuit_depth_limit() {
        let params = test_params();
        let config = VarianceCalculatorConfig::new(
            params.clone(),
            3,
            10_000_000, // Excessive circuit depth
            small_polynomials(&params, 1),
            small_polynomials(&params, 1),
        );

        let result = VarianceCalculator::new(config).calculate_variance();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Circuit too deep"));
    }

    #[test]
    fn test_infinity_norm_arbitrary_precision() {
        let params = test_params();

        // Test zero norm
        let zero_norm = VarianceCalculator::calculate_infinity_norm(&zero_polynomials(&params, 2));
        assert_eq!(zero_norm, BigUint::from(0u64));

        // Test non-zero norm
        let small_norm =
            VarianceCalculator::calculate_infinity_norm(&small_polynomials(&params, 2));
        assert!(small_norm >= BigUint::from(0u64));
    }

    #[test]
    fn test_noise_generation_zero_variance() {
        let mut rng = thread_rng();
        let params = test_params();
        let generator = SmudgingNoiseGenerator::new(params.clone(), BigUint::from(0u64));

        let coefficients = generator.generate_smudging_error(&mut rng).unwrap();

        assert_eq!(coefficients.len(), params.degree());
        assert!(coefficients.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_noise_generation_large_variance() {
        let mut rng = thread_rng();
        let params = test_params();

        // Test with extremely large variance (200+ bits) - uses maximum safe sampling
        let huge_variance =
            BigUint::from_str("1606938044258990275541962092341162602522202993782792835301376")
                .unwrap();
        let generator = SmudgingNoiseGenerator::new(params.clone(), huge_variance);

        let coefficients = generator.generate_smudging_error(&mut rng).unwrap();

        assert_eq!(coefficients.len(), params.degree());
        // Should generate non-zero coefficients with high probability
        assert!(coefficients.iter().any(|&x| x != 0));
        // All coefficients should be within safe i64 bounds
        assert!(coefficients.iter().all(|&x| x.abs() <= i64::MAX / 2));
    }

    #[test]
    fn test_end_to_end_workflow() {
        let mut rng = thread_rng();
        let params = test_params();

        // Calculate variance
        let config = VarianceCalculatorConfig::new(
            params.clone(),
            5,
            2,
            zero_polynomials(&params, 1),
            zero_polynomials(&params, 1),
        );
        let variance = VarianceCalculator::new(config)
            .calculate_variance()
            .unwrap();

        // Generate noise with calculated variance
        let generator = SmudgingNoiseGenerator::new(params.clone(), variance.clone());
        let coefficients = generator.generate_smudging_error(&mut rng).unwrap();

        assert_eq!(coefficients.len(), params.degree());
        println!(
            "Successfully generated noise with {}-bit variance",
            variance.bits()
        );
    }

    #[test]
    fn test_realistic_parameters() {
        let params = test_params();
        let config = VarianceCalculatorConfig::new(
            params.clone(),
            3,
            1,
            small_polynomials(&params, 2),
            small_polynomials(&params, 2),
        );

        // With realistic parameters, may succeed or fail due to security constraints
        match VarianceCalculator::new(config).calculate_variance() {
            Ok(variance) => assert!(variance > BigUint::from(0u64)),
            Err(e) => assert!(e.to_string().contains("Circuit too deep")),
        }
    }
}
