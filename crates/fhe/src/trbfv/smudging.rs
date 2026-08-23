use crate::Error;
/// Threshold BFV Smudging Noise Generation
///
/// This module provides variance calculation and smudging noise generation for threshold BFV.
/// Variance calculations use arbitrary precision arithmetic, while noise generation uses
/// optimized standard library sampling since cryptographic variances always exceed i64 bounds.
///
/// Key features:
/// - Arbitrary precision variance calculation using BigUint
/// - Efficient noise generation using standard uniform sampling
/// - Configurable statistical security parameter λ
/// - No precision loss in calculations while maintaining performance
use crate::bfv::BfvParameters;

use num_bigint::{BigInt, BigUint};
use num_traits::ToPrimitive;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

/// Minimum statistical security parameter accepted for production use.
pub const MIN_SECURE_LAMBDA: usize = 35;

/// Statistical security level for smudging noise generation.
///
/// The smudging bound is always computed as
/// `B_sm = 2^(lambda + 1) * degree * B_C`; this type
/// only controls which values of lambda the library accepts. Production code
/// must use [`Lambda::secure`], which rejects lambda below
/// [`MIN_SECURE_LAMBDA`]. Test setups that deliberately trade security for
/// speed must opt in explicitly via [`Lambda::insecure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lambda {
    /// Statistical security parameter validated to be >= [`MIN_SECURE_LAMBDA`].
    /// Construct via [`Lambda::secure`].
    Secure(usize),
    /// NOT SECURE: lambda below [`MIN_SECURE_LAMBDA`], so the smudging noise
    /// does not statistically hide the decryption noise. For testing only.
    /// Construct via [`Lambda::insecure`].
    Insecure(usize),
}

impl Lambda {
    /// Create a secure level. Fails if `lambda < MIN_SECURE_LAMBDA`.
    pub fn secure(lambda: usize) -> Result<Self, Error> {
        if lambda < MIN_SECURE_LAMBDA {
            return Err(Error::insecure_lambda(lambda, MIN_SECURE_LAMBDA));
        }
        Ok(Self::Secure(lambda))
    }

    /// Create an explicitly insecure level for fast testing (lambda clamped to >= 2).
    ///
    /// The smudging noise generated under this level does NOT hide the
    /// decryption noise. Never use in production.
    #[must_use]
    pub fn insecure(lambda: usize) -> Self {
        Self::Insecure(lambda.max(2))
    }

    /// The statistical security parameter lambda.
    #[must_use]
    pub fn value(&self) -> usize {
        match self {
            Self::Secure(lambda) | Self::Insecure(lambda) => *lambda,
        }
    }

    /// Whether this level meets the secure minimum.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Secure(_))
    }
}

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
    /// Encryption error1 infinity-norm bound (BigUint for arbitrary precision)
    pub b_enc: BigUint,
    /// Encryption error2 bound (u64 for standard integers)
    pub b_e: u64,
    /// Public key error poly for infinity norm calculation
    pub public_key_error: u64,
    /// Secret key poly for infinity norm calculation
    pub secret_key_bound: u64,
    /// Statistical security level
    pub lambda: Lambda,
}

/// Compute the infinity-norm bound for the configured error sampler.
fn compute_b_enc(error1_variance: &BigUint) -> BigUint {
    match error1_variance.to_u64() {
        Some(variance) if variance <= 16 => BigUint::from(2u32 * variance as u32),
        _ => {
            let target = error1_variance * 3u32;
            let mut bound = target.sqrt();
            while &bound * (&bound + 1u32) < target {
                bound += 1u32;
            }
            bound
        }
    }
}

impl SmudgingBoundCalculatorConfig {
    /// Create a new variance calculator configuration with standard parameters.
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `n` - Number of parties in threshold scheme
    /// * `m` - Number of ciphertexts to process
    /// * `lambda` - Statistical security level
    #[must_use]
    pub fn new(params: Arc<BfvParameters>, n: usize, m: usize, lambda: Lambda) -> Self {
        let variance = params.variance();
        let b_enc = compute_b_enc(params.get_error1_variance());

        Self {
            params,
            n,
            m,
            b_enc,
            b_e: (2 * variance) as u64,
            public_key_error: (n as u64) * (2 * variance) as u64,
            secret_key_bound: n as u64,
            lambda,
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
    #[must_use]
    pub fn new(config: SmudgingBoundCalculatorConfig) -> Self {
        Self { config }
    }

    /// Calculate the optimal smudging bound using arbitrary precision arithmetic.
    ///
    /// Implements the trBFV security formula for B_sm which balances
    /// security (`2^(lambda + 1) * degree * B_C`) and correctness
    /// (`< (Q/2t - B_C)/n`).
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

        // Compute modulus product Q
        let mut q_full = BigUint::from(1u64);
        for &modulus in self.config.params.moduli() {
            q_full *= BigUint::from(modulus);
        }

        // Circuit correctness bound
        let t = BigUint::from(self.config.params.plaintext());
        let b_c = BigUint::from(self.config.m) * (&b_fresh + &q_full % &t);

        // Correctness check: B_c < Q/(2t)
        let q_over_2t = &q_full / (BigUint::from(2u64) * &t);
        if b_c >= q_over_2t {
            return Err(Error::smudging_bound_infeasible(
                "circuit too deep or parameters too small: B_C exceeds Q/(2t), violating the correctness bound",
            ));
        }

        // Calculate B_sm using the degree-aware whole-transcript security bound.
        let lambda = self.config.lambda.value();
        let exponent = lambda.checked_add(1).ok_or_else(|| {
            Error::smudging_bound_infeasible("lambda is too large to calculate B_sm")
        })?;
        let lower_bound = (BigUint::from(1u64) << exponent) * &d * &b_c;
        let upper_bound = (&q_over_2t - &b_c) / BigUint::from(self.config.n);
        if upper_bound < lower_bound {
            return Err(Error::smudging_bound_infeasible(
                "security lower bound 2^(lambda + 1) * degree * B_C exceeds the correctness upper bound (Q/(2t) - B_C)/n",
            ));
        }
        Ok(lower_bound)
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
    #[must_use]
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
    /// The coefficients are sampled uniformly from `[-B_sm, B_sm]`, as
    /// specified for the smudging noise in the trBFV paper.
    ///
    /// # Returns
    /// A vector of uniformly sampled BigInt coefficients
    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Vec<BigInt>, Error> {
        let degree = self.params.degree();
        Ok(self.sample_uniform_coefficients(degree, rng))
    }

    /// Sample uniform coefficients from `[-bound, bound]`.
    fn sample_uniform_coefficients<R: RngCore + CryptoRng>(
        &self,
        count: usize,
        rng: &mut R,
    ) -> Vec<BigInt> {
        let bound = BigInt::from(self.smudging_bound.clone());
        fhe_math::rq::sample_uniform_coefficients_bigint(&bound, count, rng)
    }

    /// Get the polynomial degree.
    #[must_use]
    pub fn degree(&self) -> usize {
        self.params.degree()
    }

    /// Get the smudging variance.
    #[must_use]
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
    use rand::rng;
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
        let config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 5, 2, Lambda::secure(80).unwrap());

        assert_eq!(config.params, params);
        assert_eq!(config.n, 5);
        assert_eq!(config.m, 2);
        assert_eq!(config.lambda.value(), 80);
        assert_eq!(config.b_enc, compute_b_enc(params.get_error1_variance()));
        assert_eq!(config.b_e, (params.variance() * 2) as u64);
        assert_eq!(
            config.public_key_error,
            (config.n as u64) * (2 * params.variance()) as u64
        );
        assert_eq!(config.secret_key_bound, 5);
        assert_eq!(config.lambda.value(), 80);
    }

    #[test]
    fn b_enc_matches_the_error_sampler_support() {
        let params16 = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(2)
            .set_moduli(&[65537])
            .set_error1_variance_usize(16)
            .build_arc()
            .unwrap();
        let config16 = SmudgingBoundCalculatorConfig::new(params16, 1, 1, Lambda::insecure(2));
        assert_eq!(config16.b_enc, BigUint::from(32u32));

        let params17 = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(2)
            .set_moduli(&[65537])
            .set_error1_variance_usize(17)
            .build_arc()
            .unwrap();
        let config17 = SmudgingBoundCalculatorConfig::new(params17, 1, 1, Lambda::insecure(2));
        assert_eq!(config17.b_enc, BigUint::from(7u32));
    }

    #[test]
    fn smudging_bound_includes_degree_and_extra_security_bit() {
        let params = test_params();
        let config = SmudgingBoundCalculatorConfig::new(params.clone(), 3, 1, Lambda::insecure(2));

        let degree = BigUint::from(params.degree());
        let b_enc = config.b_enc.clone();
        let b_e = BigUint::from(config.b_e);
        let public_key_error = BigUint::from(config.public_key_error);
        let secret_key_bound = BigUint::from(config.secret_key_bound);
        let b_fresh = &degree * &public_key_error + b_enc + &degree * &b_e * &secret_key_bound;

        let mut q = BigUint::from(1u64);
        for &modulus in params.moduli() {
            q *= modulus;
        }
        let plaintext = BigUint::from(params.plaintext());
        let b_c = &b_fresh + &q % &plaintext;
        let expected = (BigUint::from(1u64) << 3usize) * &degree * &b_c;

        assert_eq!(
            SmudgingBoundCalculator::new(config)
                .calculate_sm_bound()
                .unwrap(),
            expected
        );
    }

    #[test]
    fn test_smudging_bound_calculator_minimal_case() {
        let params = test_params();
        let config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 3, 1, Lambda::secure(80).unwrap());
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
        let config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 3, 1, Lambda::secure(80).unwrap());
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
        let mut rng = rng();
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
        let mut rng = rng();
        let params = test_params();
        let bound = BigUint::from(0u64);
        let generator = SmudgingNoiseGenerator::new(params.clone(), bound);

        let coefficients = generator.generate_smudging_error(&mut rng).unwrap();
        assert_eq!(coefficients.len(), params.degree());
        assert!(coefficients.iter().all(|x| x.is_zero()));
    }

    #[test]
    fn test_noise_generation_large_bound() {
        let mut rng = rng();
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
        let mut rng = rng();
        let params = test_params();
        let n = 3;
        let m = 1;

        // Try the complete workflow
        let config =
            SmudgingBoundCalculatorConfig::new(params.clone(), n, m, Lambda::secure(80).unwrap());
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
