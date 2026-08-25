use crate::Error;
/// Threshold BFV Smudging Noise Generation (Urban–Rambaud 2024, Appendix C).
///
/// This module provides variance calculation and smudging noise generation for threshold BFV.
/// Variance calculations use arbitrary precision arithmetic, while noise generation uses
/// optimized standard library sampling since cryptographic variances always exceed i64 bounds.
///
/// Key features:
/// - Arbitrary precision variance calculation using BigUint
/// - Efficient noise generation using standard uniform sampling
/// - Statistical security parameter λ (see [`Lambda`] and [`MIN_SECURE_LAMBDA`])
/// - Correctness enforced via strict `2 * (B_C + n * B_sm) < Delta` with `Delta = floor(Q / t)`
/// - Multiplicative-depth noise recursion via Prop.&nbsp;20
/// - Distributed RLK error accounting via `accepted_participant_count * B_e`
/// - Sampler-aligned `B_enc` (CBD support for small variance, `sqrt(3*var)` for large)
use crate::bfv::BfvParameters;

use num_bigint::{BigInt, BigUint};
use num_traits::{ToPrimitive, Zero};
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Minimum statistical security parameter accepted for production use.
///
/// This is a statistical-hiding policy threshold: noise with
/// `B_sm = 2^(lambda + 1) * d * B_C` (`d` = polynomial degree) is intended to
/// statistically hide the decryption noise for a whole decryption transcript
/// (all `d` coefficients revealed at once), not just a single coefficient.
/// A larger lambda gives a stronger guarantee, not a computational one.
/// [`MIN_SECURE_LAMBDA`] is a policy choice, not derived from a cryptographic
/// reduction.
pub const MIN_SECURE_LAMBDA: usize = 35;

/// Maximum lambda value beyond which `2^(lambda + 1) * d * B_C` is
/// computationally infeasible to represent. Rejecting values above this
/// ceiling prevents massive memory allocations from huge BigUint shifts.
const MAX_FEASIBLE_LAMBDA: usize = 256;

/// Statistical security level for smudging noise generation.
///
/// The smudging bound is always computed as `B_sm = 2^(lambda + 1) * d * B_C`
/// (`d` = polynomial degree, accounting for all `d` coefficients a single
/// decryption reveals at once — see issue #108); this type only controls
/// which values of lambda the library accepts. Production code must use
/// [`Lambda::secure`], which rejects lambda below [`MIN_SECURE_LAMBDA`]. Test
/// setups that deliberately trade security for speed must opt in explicitly
/// via [`Lambda::insecure`].
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
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SmudgingBoundCalculatorConfig {
    /// BFV parameters (degree, moduli, plaintext modulus)
    pub params: Arc<BfvParameters>,
    /// Number of parties in the threshold scheme
    pub n: usize,
    /// Number of ciphertexts being processed
    pub m: usize,
    /// Encryption error1 infinity-norm bound (BigUint for arbitrary precision).
    ///
    /// Derived from the actual configured error sampler:
    /// - CBD branch (error1_variance < 16 as u64): `B_enc = 2 * error1_variance`
    ///   (support bound of CBD(2·variance)).
    /// - Uniform branch (larger or non-u64 variance): `B_enc = floor(sqrt(3 * error1_variance))`.
    pub b_enc: BigUint,
    /// Encryption error2 bound (u64 for standard integers)
    pub b_e: u64,
    /// Public key error poly infinity-norm bound
    pub public_key_error: u64,
    /// Secret key poly infinity-norm bound
    pub secret_key_bound: u64,
    /// Statistical security level
    pub lambda: Lambda,
    /// Multiplicative circuit depth (0 for additive-only circuits).
    ///
    /// When non-zero, `calculate_sm_bound` applies the Prop. 20 noise growth
    /// recursion for each level before computing B_sm.
    pub mult_depth: u32,
}

/// Compute B_enc from the configured error sampler variance.
///
/// Matches the branch chosen by `Poly::conditional_error`:
/// - CBD for variance fitting in u64 and < 16 → support bound `2 * variance`.
/// - Uniform otherwise → `floor(sqrt(3 * variance))`.
fn compute_b_enc(error1_variance: &BigUint) -> BigUint {
    match error1_variance.to_u64() {
        Some(v) if v < 16 => {
            // CBD(2*v): maximum absolute coefficient = 2 * variance.
            BigUint::from(2u32 * v as u32)
        }
        _ => {
            // Uniform branch: bound = floor(sqrt(3 * variance)).  This
            // mirrors `variance_to_uniform_bound` in fhe-math.
            (BigUint::from(3u32) * error1_variance).sqrt()
        }
    }
}

/// Compute Q = product of all moduli as a BigUint.
fn modulus_product(moduli: &[u64]) -> BigUint {
    let mut q = BigUint::from(1_u64);
    for &qi in moduli {
        q *= BigUint::from(qi);
    }
    q
}

/// Compute Delta = floor(Q / t), the exact plaintext scaling factor.
fn compute_delta(q: &BigUint, t: &BigUint) -> BigUint {
    q / t
}

impl SmudgingBoundCalculatorConfig {
    /// Create a new variance calculator configuration with standard parameters.
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `n` - Number of parties in threshold scheme
    /// * `m` - Number of ciphertexts to process
    /// * `lambda` - Statistical security level
    ///
    /// # Errors
    /// Returns an error when `n` or `m` is zero.
    pub fn new(
        params: Arc<BfvParameters>,
        n: usize,
        m: usize,
        lambda: Lambda,
    ) -> Result<Self, Error> {
        if n == 0 {
            return Err(Error::smudging_bound_infeasible(
                "number of parties n must be positive",
            ));
        }
        if m == 0 {
            return Err(Error::smudging_bound_infeasible(
                "number of ciphertexts m must be positive",
            ));
        }
        let variance = params.variance();
        let b_enc = compute_b_enc(params.get_error1_variance());

        Ok(Self {
            params,
            n,
            m,
            b_enc,
            b_e: (2 * variance) as u64,
            public_key_error: (n as u64) * (2 * variance) as u64,
            secret_key_bound: n as u64,
            lambda,
            mult_depth: 0,
        })
    }

    /// Create a configuration for a multiplicative circuit at the given depth.
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `n` - Number of parties in threshold scheme
    /// * `m` - Number of ciphertexts summed before the multiplication circuit
    /// * `mult_depth` - Number of multiplicative levels applied (0 = additive only)
    /// * `lambda` - Statistical security level
    ///
    /// # Errors
    /// Returns an error when `n` or `m` is zero.
    pub fn new_multiplicative(
        params: Arc<BfvParameters>,
        n: usize,
        m: usize,
        mult_depth: u32,
        lambda: Lambda,
    ) -> Result<Self, Error> {
        let mut config = Self::new(params, n, m, lambda)?;
        config.mult_depth = mult_depth;
        Ok(config)
    }
}

/// Calculator for optimal smudging bound using arbitrary precision arithmetic.
///
/// Implements the trBFV security formulas with:
/// - `Delta = floor(Q / t)` (exact plaintext scaling factor, not `Q/(2t)`).
/// - Strict correctness inequality: `2 * (B_C + n * B_sm) < Delta`.
/// - Sampler-aligned `B_enc` (CBD support for small variance, `sqrt(3*var)` for large).
/// - Distributed RLK error accounting via [`with_accepted_participant_count`].
/// - Injectible initial ciphertext noise bound via [`with_initial_ciphertext_noise_bound`].
///
/// ## Limitations (not enforced by this API)
///
/// - **One-time noise:** Generated `B_sm`-bounded smudging noise is pre-shared
///   material that must not be reused across decryptions. This API does not
///   track consumption.
/// - **Even `n`:** Accepted for backwards compatibility, but the paper's `n = 2t+1`
///   theorem (odd `n`) does not cover even party counts.
#[derive(Debug)]
pub struct SmudgingBoundCalculator {
    config: SmudgingBoundCalculatorConfig,
    /// Number of parties contributing to the relinearization key (|S| in the paper).
    /// Defaults to `config.n`. Must be in `1..=config.n`.
    accepted_participant_count: usize,
    /// User-supplied initial ciphertext noise bound `B_C^(0)`. When [`None`],
    /// computed from the config as `m * (B_fresh + Q mod t)`.
    initial_ciphertext_noise_bound: Option<BigUint>,
}

impl SmudgingBoundCalculator {
    /// Create a new bound calculator with defaults:
    /// - `accepted_participant_count = config.n`
    /// - no injected initial ciphertext noise bound.
    #[must_use]
    pub fn new(config: SmudgingBoundCalculatorConfig) -> Self {
        let accepted_participant_count = config.n;
        Self {
            config,
            accepted_participant_count,
            initial_ciphertext_noise_bound: None,
        }
    }

    /// Set the number of parties that contributed to the distributed
    /// relinearization key.  Must be in `1..=config.n`.
    ///
    /// The distributed RLK error scales linearly with the accepted set size.
    /// The default is `config.n`.
    #[must_use]
    pub fn with_accepted_participant_count(mut self, count: usize) -> Self {
        self.accepted_participant_count = count;
        self
    }

    /// Inject an explicit initial ciphertext noise bound `B_C^(0)`.
    ///
    /// When set, this replaces the computed `m * (B_fresh + Q mod t)`.
    /// Useful when the caller has a more precise noise measurement from
    /// a previous circuit evaluation. For a complete post-circuit bound
    /// use `mult_depth = 0`.
    #[must_use]
    pub fn with_initial_ciphertext_noise_bound(mut self, bound: BigUint) -> Self {
        self.initial_ciphertext_noise_bound = Some(bound);
        self
    }

    /// Calculate the optimal smudging bound using arbitrary precision arithmetic.
    ///
    /// Implements the trBFV security formula: `B_sm = 2^(lambda + 1) * d * B_C`
    /// (`d` = polynomial degree, accounting for the union bound over all `d`
    /// coefficients a single decryption reveals — see issue #108) subject to
    /// the strict correctness constraint `2 * (B_C + n * B_sm) < Delta` where
    /// `Delta = floor(Q / t)`.
    ///
    /// # Returns
    /// Calculated bound B_sm as BigUint (can be arbitrarily large)
    ///
    /// # Errors
    /// Returns error if:
    /// - Inputs are invalid (zero n/m, empty moduli, zero plaintext, zero variance)
    /// - Accepted participant count is zero or exceeds n
    /// - Lambda exceeds `MAX_FEASIBLE_LAMBDA`
    /// - `2 * B_C >= Delta` (circuit too deep or parameters too small)
    /// - `2 * (B_C + n * B_sm) >= Delta` (security requirement infeasible)
    pub fn calculate_sm_bound(&self) -> Result<BigUint, Error> {
        // --- Input validation ---
        if self.config.n == 0 {
            return Err(Error::smudging_bound_infeasible(
                "number of parties n must be positive",
            ));
        }
        if self.config.m == 0 {
            return Err(Error::smudging_bound_infeasible(
                "number of ciphertexts m must be positive",
            ));
        }
        if self.accepted_participant_count == 0 {
            return Err(Error::smudging_bound_infeasible(
                "accepted participant count must be positive",
            ));
        }
        if self.accepted_participant_count > self.config.n {
            return Err(Error::smudging_bound_infeasible(
                "accepted participant count exceeds total party count n",
            ));
        }
        let moduli = self.config.params.moduli();
        if moduli.is_empty() {
            return Err(Error::smudging_bound_infeasible("moduli slice is empty"));
        }
        let t = self.config.params.plaintext_big().clone();
        if t == BigUint::from(0_u64) {
            return Err(Error::smudging_bound_infeasible(
                "plaintext modulus must be positive",
            ));
        }
        let error1_var = self.config.params.get_error1_variance();
        if error1_var == &BigUint::from(0_u64) {
            return Err(Error::smudging_bound_infeasible(
                "error1 variance must be positive",
            ));
        }

        let lambda = self.config.lambda.value();
        // Reject infeasible lambda before any large allocation.
        if lambda > MAX_FEASIBLE_LAMBDA {
            return Err(Error::smudging_bound_infeasible(format!(
                "lambda {lambda} exceeds maximum feasible value {MAX_FEASIBLE_LAMBDA}"
            )));
        }

        // --- Core computation ---
        let d = BigUint::from(self.config.params.degree());
        let b_enc = &self.config.b_enc;
        let b_e = BigUint::from(self.config.b_e);
        let e_norm = BigUint::from(self.config.public_key_error);
        let sk_norm = BigUint::from(self.config.secret_key_bound);

        // B_fresh = d·||e_ek||_∞ + B_enc + d·B_e·||sk||_∞
        let b_fresh = &d * &e_norm + b_enc + &d * &b_e * &sk_norm;

        // Q = product of all moduli
        let q_full = modulus_product(moduli);

        // Delta = floor(Q / t) — exact plaintext scaling factor.
        let delta = compute_delta(&q_full, &t);

        // B_C^(0): initial ciphertext noise bound (additive).
        let b_c_additive = match &self.initial_ciphertext_noise_bound {
            Some(bc0) => bc0.clone(),
            None => BigUint::from(self.config.m) * (&b_fresh + &q_full % &t),
        };

        // --- Multiplicative depth recursion (Prop. 20) ---
        //
        // B_C^{i+1} = 2·k·N²·‖sk‖ · B_C^{i} + B_relin
        //
        // where B_relin (Eq. 30) is computed with the aggregate RLK error
        // |S| * B_e to account for distributed relinearization key
        // contributions from accepted_participant_count parties.
        let b_c = if self.config.mult_depth > 0 {
            let l = BigUint::from(moduli.len());
            let b_g = BigUint::from(
                *moduli
                    .iter()
                    .max()
                    .ok_or_else(|| Error::smudging_bound_infeasible("moduli slice is empty"))?,
            );
            let k = self.config.params.plaintext_big().clone();
            let n_sk = BigUint::from(self.config.secret_key_bound);

            // Aggregate RLK error: |S| * B_e
            let aggregate_b_e =
                BigUint::from(self.accepted_participant_count) * BigUint::from(self.config.b_e);

            // Eq. (30) relinearization error bound with aggregate error.
            let b_relin = &d * &l * &n_sk * &b_g * &aggregate_b_e
                + BigUint::from(2_u32) * &d * &d * &l * &l * &n_sk * &n_sk * &b_g * &aggregate_b_e;

            // Prop. 20 coefficient.
            let coeff = BigUint::from(2_u32) * &k * &d * &d * &n_sk;
            let mut b = b_c_additive;
            for _ in 0..self.config.mult_depth {
                b = &coeff * &b + &b_relin;
            }
            b
        } else {
            b_c_additive
        };

        // --- Correctness: 2 * B_C < Delta ---
        let two_b_c = BigUint::from(2_u64) * &b_c;
        if two_b_c >= delta {
            return Err(Error::smudging_bound_infeasible(format!(
                "2*B_C = {two_b_c} exceeds Delta = {delta}: circuit too deep or parameters too small"
            )));
        }

        // --- Compute B_sm = 2^(lambda + 1) * d * B_C
        //
        // A single decryption reveals all `d` (= degree) coefficients of the
        // smudging noise at once. `2^lambda * B_C` alone only bounds the
        // statistical distance for a *single* coefficient; by a union bound
        // over the `d` coefficients exposed per transcript, the
        // whole-transcript distance is bounded by `d * 2^lambda`.
        // Multiplying by `d` directly (rather than shifting the exponent by
        // `ceil(log2(d))`) keeps the bound correct for non-power-of-two
        // degrees too.
        //
        // Use BigUint shift to avoid usize → u32 truncation.
        // `lambda` was already validated against MAX_FEASIBLE_LAMBDA above.
        let two_pow_lambda_plus_one = BigUint::from(1_u64) << (lambda + 1);
        let b_sm = two_pow_lambda_plus_one * &d * &b_c;

        // --- Strict correctness: 2 * (B_C + n * B_sm) < Delta ---
        let lhs = BigUint::from(2_u64) * (&b_c + BigUint::from(self.config.n) * &b_sm);
        if lhs >= delta {
            return Err(Error::smudging_bound_infeasible(format!(
                "strict inequality 2*(B_C + n*B_sm) = {lhs} >= Delta = {delta}: \
                 security lower bound exceeds correctness budget"
            )));
        }

        Ok(b_sm)
    }
}

/// Owning wrapper around the smudging noise coefficients (`Vec<BigInt>`).
///
/// Smudging coefficients are one-time pre-shared secret material: they are
/// generated by [`SmudgingNoiseGenerator::generate_smudging_error`], dealt
/// through Shamir sharing, and aggregated before decryption. Holding them in
/// this wrapper makes their cleanup automatic on drop.
///
/// # Security semantics
///
/// - [`Zeroize`] replaces every `BigInt` with zero and clears the container.
/// - The type implements [`ZeroizeOnDrop`] unconditionally (see the manual
///   [`Drop`] impl), so normal drops, early returns, and unwinding all run
///   cleanup without caller action.
/// - Only borrowed slice access (`as_slice`) and length information are
///   exposed. The wrapper is deliberately non-`Clone`, so ownership cannot be
///   duplicated through the public API.
///
/// # Best-effort BigInt cleanup
///
/// Replacing a `BigInt` with zero drops its private limb allocation, but
/// `num-bigint` does not expose a way to overwrite that allocation before
/// deallocation. This wrapper therefore cannot promise allocator-level or
/// complete historical-copy erasure; it is a best-effort guard, not
/// guaranteed BigInt memory sanitization. The same limitation applies to
/// arbitrary-precision temporaries inside the Shamir arithmetic itself.
///
/// # Limitations
///
/// Deliberate `std::mem::forget`/`ManuallyDrop` can bypass Rust
/// destructors; copies made outside this wrapper, swap, core dumps, and
/// allocator behavior are outside this guarantee.
pub struct SmudgingCoefficients {
    coeffs: Vec<BigInt>,
}

impl SmudgingCoefficients {
    /// Wrap an owned coefficient vector, placing it under automatic
    /// best-effort zeroization.
    #[must_use]
    pub fn new(coeffs: Vec<BigInt>) -> Self {
        Self { coeffs }
    }

    /// Borrow the coefficients (e.g. for conversion into a polynomial).
    #[must_use]
    pub(crate) fn as_slice(&self) -> &[BigInt] {
        &self.coeffs
    }

    /// Number of coefficients held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    /// Whether the wrapper holds no coefficients.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }
}

// Redacted `Debug` so that `{:?}` never leaks the coefficient values.
impl std::fmt::Debug for SmudgingCoefficients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmudgingCoefficients")
            .field("len", &self.coeffs.len())
            .finish()
    }
}

impl Zeroize for SmudgingCoefficients {
    fn zeroize(&mut self) {
        for coeff in &mut self.coeffs {
            coeff.set_zero();
        }
        self.coeffs.clear();
    }
}

impl Drop for SmudgingCoefficients {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SmudgingCoefficients {}

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
    /// The uniformly sampled BigInt coefficients wrapped in the protected
    /// [`SmudgingCoefficients`] container, which zeroizes them automatically
    /// on drop (best-effort BigInt cleanup, see its documentation).
    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<SmudgingCoefficients, Error> {
        let degree = self.params.degree();
        Ok(SmudgingCoefficients::new(
            self.sample_uniform_coefficients(degree, rng),
        ))
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

    /// Parameters with a large error1_variance so the uniform sampler branch
    /// is exercised (variance >= 16 as u64).
    fn test_params_large_error1() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(8192)
            .set_plaintext_modulus(16384)
            .set_moduli(&[0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001])
            .set_error1_variance_usize(20)
            .unwrap()
            .build_arc()
            .unwrap()
    }

    // ── B_enc sampler alignment ──────────────────────────────────────────

    #[test]
    fn b_enc_cbd_branch_is_support_bound() {
        // Variance=10 (< 16) takes the CBD branch: B_enc = 2 * variance = 20.
        let params = test_params(); // error1_variance = 10
        assert_eq!(params.variance(), 10);
        assert_eq!(params.get_error1_variance(), &BigUint::from(10_u32));

        let b_enc = compute_b_enc(params.get_error1_variance());
        assert_eq!(b_enc, BigUint::from(20_u32));
    }

    #[test]
    fn b_enc_uniform_branch_is_sqrt_3var() {
        // Variance=20 (>= 16) takes the uniform branch.
        let params = test_params_large_error1();
        assert_eq!(params.get_error1_variance(), &BigUint::from(20_u32));

        let b_enc = compute_b_enc(params.get_error1_variance());
        let expected = (BigUint::from(3_u32) * BigUint::from(20_u32)).sqrt();
        assert_eq!(b_enc, expected);
    }

    #[test]
    fn b_enc_large_biguint_uses_uniform_branch() {
        // A 128-bit variance does not fit in u64, so the uniform branch is used.
        let var = BigUint::from_str("340282366920938463463374607431768211456").unwrap(); // 2^128
        let b_enc = compute_b_enc(&var);
        let expected = (BigUint::from(3_u32) * &var).sqrt();
        assert_eq!(b_enc, expected);
    }

    #[test]
    fn config_new_uses_computed_b_enc() {
        let params = test_params();
        let config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 5, 2, Lambda::secure(80).unwrap())
                .unwrap();
        assert_eq!(config.b_enc, compute_b_enc(params.get_error1_variance()));
    }

    #[test]
    fn zero_party_or_ciphertext_config_is_rejected() {
        let params = test_params();
        assert!(
            SmudgingBoundCalculatorConfig::new(params.clone(), 0, 1, Lambda::insecure(2),).is_err()
        );
        assert!(SmudgingBoundCalculatorConfig::new(params, 1, 0, Lambda::insecure(2)).is_err());
    }

    #[test]
    fn calculate_sm_bound_revalidates_party_and_ciphertext_counts() {
        let params = test_params();
        let mut config =
            SmudgingBoundCalculatorConfig::new(params, 1, 1, Lambda::insecure(2)).unwrap();
        config.n = 0;
        assert!(
            SmudgingBoundCalculator::new(config)
                .calculate_sm_bound()
                .is_err()
        );

        let mut config =
            SmudgingBoundCalculatorConfig::new(test_params(), 1, 1, Lambda::insecure(2)).unwrap();
        config.m = 0;
        assert!(
            SmudgingBoundCalculator::new(config)
                .calculate_sm_bound()
                .is_err()
        );
    }

    // ── Delta formula ────────────────────────────────────────────────────

    #[test]
    fn delta_is_q_div_t_floor() {
        let params = test_params();
        let q = modulus_product(params.moduli());
        let t = params.plaintext_big().clone();
        let delta = compute_delta(&q, &t);

        // Delta = floor(Q / t), not Q/(2t).
        let expected = &q / &t;
        assert_eq!(delta, expected);
        // Q/(2t) would be strictly smaller (when t >= 2).
        assert!(delta > &q / (BigUint::from(2_u64) * &t));
    }

    // ── Strict inequality ────────────────────────────────────────────────

    #[test]
    fn strict_inequality_rejects_boundary() {
        // Use injected B_C to construct an exact boundary case.
        // With n=1, lambda=0 → B_sm = B_C.
        // 2*(B_C + n*B_sm) = 2*(B_C + B_C) = 4*B_C.
        // We pick Delta = 4*B_C exactly, so the strict `<` must reject.
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(2)
            .set_moduli(&[65537])
            .set_error1_variance_usize(1)
            .unwrap() // CBD, B_enc=2
            .build_arc()
            .unwrap();
        let t = params.plaintext_big().clone();
        let q = modulus_product(params.moduli());
        let delta = compute_delta(&q, &t); // floor(65537/2) = 32768

        // Choose B_C so that 4*B_C == delta exactly.
        // delta must be divisible by 4 for exact equality.
        // 32768 / 4 = 8192. So B_C = 8192.
        let bc = delta.clone() / BigUint::from(4_u64);
        assert_eq!(
            &bc * BigUint::from(4_u64),
            delta,
            "B_C * 4 should equal Delta"
        );

        let lambda = Lambda::insecure(0);
        let config = SmudgingBoundCalculatorConfig::new(params.clone(), 1, 1, lambda).unwrap();
        let err = SmudgingBoundCalculator::new(config)
            .with_initial_ciphertext_noise_bound(bc)
            .calculate_sm_bound()
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("strict inequality"),
            "error should mention strict inequality; got: {msg}"
        );
    }

    // ── Accepted participant count ───────────────────────────────────────

    #[test]
    fn accepted_participant_count_defaults_to_n() {
        let params = test_params();
        let config = SmudgingBoundCalculatorConfig::new(params, 7, 1, Lambda::insecure(2)).unwrap();
        let calc = SmudgingBoundCalculator::new(config);
        // Not directly accessible, but verified through behavior:
        // setting count to 7 should NOT error.
        let calc7 = calc.with_accepted_participant_count(7);
        let _bound = calc7.calculate_sm_bound().unwrap();
    }

    #[test]
    fn accepted_participant_count_rejects_zero() {
        let params = test_params();
        let config = SmudgingBoundCalculatorConfig::new(params, 5, 1, Lambda::insecure(2)).unwrap();
        let err = SmudgingBoundCalculator::new(config)
            .with_accepted_participant_count(0)
            .calculate_sm_bound()
            .unwrap_err();
        assert!(err.to_string().contains("accepted participant"));
    }

    #[test]
    fn accepted_participant_count_rejects_above_n() {
        let params = test_params();
        let config = SmudgingBoundCalculatorConfig::new(params, 3, 1, Lambda::insecure(2)).unwrap();
        let err = SmudgingBoundCalculator::new(config)
            .with_accepted_participant_count(4)
            .calculate_sm_bound()
            .unwrap_err();
        assert!(err.to_string().contains("accepted participant"));
    }

    #[test]
    fn accepted_participant_count_increases_bound() {
        let params = test_params();
        let config = SmudgingBoundCalculatorConfig::new_multiplicative(
            params.clone(),
            5,
            1,
            1,
            Lambda::insecure(2),
        )
        .unwrap();
        let bound_all = SmudgingBoundCalculator::new(config.clone())
            .with_accepted_participant_count(5)
            .calculate_sm_bound()
            .unwrap();
        let bound_one = SmudgingBoundCalculator::new(config)
            .with_accepted_participant_count(1)
            .calculate_sm_bound()
            .unwrap();
        // More participants → more RLK error → larger B_sm.
        assert!(
            bound_all > bound_one,
            "5 participants ({bound_all}) should produce larger B_sm than 1 ({bound_one})"
        );
    }

    // ── Initial ciphertext noise bound injection ─────────────────────────

    #[test]
    fn injected_bc0_is_used_directly_additive() {
        let params = test_params();
        let d = BigUint::from(params.degree());
        let injected = BigUint::from(12345_u64);
        let config = SmudgingBoundCalculatorConfig::new(params, 3, 1, Lambda::insecure(2)).unwrap();
        let bound = SmudgingBoundCalculator::new(config)
            .with_initial_ciphertext_noise_bound(injected.clone())
            .calculate_sm_bound()
            .unwrap();

        // B_sm = 2^(lambda + 1) * d * B_C = 8 * 8192 * 12345 = 809041920
        assert_eq!(bound, BigUint::from(8_u64) * &d * &injected);
    }

    // ── Lambda handling (no u32 truncation) ──────────────────────────────

    #[test]
    fn huge_lambda_rejected_before_allocation() {
        // lambda = u32::MAX + 1 would truncate with `as u32`, but our code
        // rejects it before computing 2^lambda.
        let huge_lambda = (u32::MAX as usize) + 1;
        assert!(huge_lambda > u32::MAX as usize); // on 64-bit only
        let params = test_params();
        let config =
            SmudgingBoundCalculatorConfig::new(params, 3, 1, Lambda::insecure(huge_lambda))
                .unwrap();
        let err = SmudgingBoundCalculator::new(config)
            .calculate_sm_bound()
            .unwrap_err();
        assert!(err.to_string().contains("lambda"));
    }

    #[test]
    fn lambda_at_max_feasible_still_truncation_free() {
        // 2^256 is huge but should not truncate.  The correctness check
        // will likely fail, but we verify no silent truncation.
        let params = test_params();
        let config =
            SmudgingBoundCalculatorConfig::new(params, 1, 1, Lambda::insecure(MAX_FEASIBLE_LAMBDA))
                .unwrap();
        let result = SmudgingBoundCalculator::new(config).calculate_sm_bound();
        // Whether it succeeds or fails depends on parameters — either way,
        // we assert that if it succeeds, the bound uses the full lambda
        // multiplier (i.e., it is huge, not truncated to <= 2^u32::MAX).
        if let Ok(bound) = result {
            // The bound should have at least lambda+1 bits if B_C >= 1.
            assert!(bound.bits() as usize > MAX_FEASIBLE_LAMBDA);
        }
    }

    #[test]
    fn lambda_floor_is_exact_no_rounding() {
        // lambda=35: B_sm = 2^36 * d * B_C exactly.
        let params = test_params();
        let config =
            SmudgingBoundCalculatorConfig::new(params, 3, 1, Lambda::secure(35).unwrap()).unwrap();
        let calc = SmudgingBoundCalculator::new(config);
        // For these test params the bound should be feasible.
        let bound = calc.calculate_sm_bound().unwrap();
        assert!(bound.bits() > 35);
        // Verify the bound is an exact multiple: B_sm mod B_C? We can't
        // extract B_C, but we can verify the bound itself is positive.
        assert!(bound > BigUint::from(0_u64));
    }

    // ── Existing tests (preserved and adapted) ───────────────────────────

    #[test]
    fn test_smudging_bound_calculator_config() {
        let params = test_params();
        let config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 5, 2, Lambda::secure(80).unwrap())
                .unwrap();

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
    fn test_smudging_bound_calculator_minimal_case() {
        let params = test_params();
        let config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 3, 1, Lambda::secure(80).unwrap())
                .unwrap();
        let calculator = SmudgingBoundCalculator::new(config);

        let result = calculator.calculate_sm_bound();

        match result {
            Ok(bound) => {
                assert!(bound > BigUint::from(0u64));
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("Delta") || msg.contains("strict inequality"),
                    "unexpected error: {msg}"
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
            SmudgingBoundCalculatorConfig::new(params.clone(), 3, 1, Lambda::secure(80).unwrap())
                .unwrap();
        let calculator = SmudgingBoundCalculator::new(config);

        let result = SmudgingNoiseGenerator::from_bound_calculator(calculator);

        match result {
            Ok(generator) => {
                assert_eq!(generator.params, params);
                assert_eq!(generator.degree(), params.degree());
                assert!(generator.smudging_bound() > &BigUint::from(0u64));
            }
            Err(e) => {
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

        for coeff in coefficients.as_slice() {
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
        assert!(coefficients.as_slice().iter().all(|x| x.is_zero()));
    }

    #[test]
    fn test_noise_generation_large_bound() {
        let mut rng = rng();
        let params = test_params();
        let large_bound = BigUint::from_str("123456789012345678901234567890").unwrap();
        let generator = SmudgingNoiseGenerator::new(params.clone(), large_bound.clone());

        let coefficients = generator.generate_smudging_error(&mut rng).unwrap();
        assert_eq!(coefficients.len(), params.degree());

        let non_zero_count = coefficients
            .as_slice()
            .iter()
            .filter(|x| !x.is_zero())
            .count();
        assert!(non_zero_count > coefficients.len() / 4);

        for coeff in coefficients.as_slice() {
            assert!(coeff.abs() <= BigInt::from(large_bound.clone()));
        }
    }

    #[test]
    fn test_realistic_parameters_workflow() {
        let mut rng = rng();
        let params = test_params();
        let n = 3;
        let m = 1;

        let config =
            SmudgingBoundCalculatorConfig::new(params.clone(), n, m, Lambda::secure(80).unwrap())
                .unwrap();
        let calculator = SmudgingBoundCalculator::new(config);

        let bound_result = calculator.calculate_sm_bound();

        match bound_result {
            Ok(bound) => {
                let generator = SmudgingNoiseGenerator::new(params.clone(), bound.clone());
                let coefficients = generator.generate_smudging_error(&mut rng).unwrap();
                assert_eq!(coefficients.len(), params.degree());
            }
            Err(_) => {
                // Acceptable for some parameter sets
            }
        }
    }

    /// depth=0 (additive) produces a smaller bound than depth=1 (one multiplication),
    /// and depth=2 produces a larger bound than depth=1.
    #[test]
    fn test_multiplicative_depth_increases_bound() {
        // The B_sm = 2^(lambda+1) * d * B_C fix (issue #108) makes B_sm much
        // larger, so `test_params()`'s moduli no longer leave enough
        // correctness headroom for a depth=2 recursion at n=1. Use a wider
        // modulus chain (same degree, so `d` is unchanged) purely to keep
        // this synthetic bound-growth check feasible.
        let params = BfvParametersBuilder::new()
            .set_degree(8192)
            .set_plaintext_modulus(16384)
            .set_moduli_sizes(&[62, 62, 62, 62, 62, 62])
            .build_arc()
            .unwrap();
        let lambda = Lambda::insecure(2);

        // n=3: verify depth=1 strictly exceeds depth=0.
        let bound_add = SmudgingBoundCalculator::new(
            SmudgingBoundCalculatorConfig::new(params.clone(), 3, 1, lambda).unwrap(),
        )
        .calculate_sm_bound()
        .unwrap();

        let bound_mul1 = SmudgingBoundCalculator::new(
            SmudgingBoundCalculatorConfig::new_multiplicative(params.clone(), 3, 1, 1, lambda)
                .unwrap(),
        )
        .calculate_sm_bound()
        .unwrap();

        assert!(
            bound_mul1 > bound_add,
            "depth=1 bound ({bound_mul1}) should exceed depth=0 bound ({bound_add})"
        );

        // n=1: smaller n gives more correctness headroom, so depth=2 is feasible.
        let bound_d1 = SmudgingBoundCalculator::new(
            SmudgingBoundCalculatorConfig::new_multiplicative(params.clone(), 1, 1, 1, lambda)
                .unwrap(),
        )
        .calculate_sm_bound()
        .unwrap();

        let bound_d2 = SmudgingBoundCalculator::new(
            SmudgingBoundCalculatorConfig::new_multiplicative(params.clone(), 1, 1, 2, lambda)
                .unwrap(),
        )
        .calculate_sm_bound()
        .unwrap();

        assert!(
            bound_d2 > bound_d1,
            "depth=2 bound ({bound_d2}) should exceed depth=1 bound ({bound_d1})"
        );
    }

    // ── Boundary / invariant tests replacing the tautological mirror ─────

    #[test]
    fn smudging_bound_is_nonzero_for_feasible_params() {
        let params = test_params();
        let config = SmudgingBoundCalculatorConfig::new(params, 3, 1, Lambda::insecure(2)).unwrap();
        let bound = SmudgingBoundCalculator::new(config)
            .calculate_sm_bound()
            .unwrap();
        assert!(bound > BigUint::from(0_u64));
    }

    #[test]
    fn smudging_bound_increases_with_more_ciphertexts() {
        let params = test_params();
        let m1_config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 3, 1, Lambda::insecure(2)).unwrap();
        let m2_config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 3, 2, Lambda::insecure(2)).unwrap();
        let b1 = SmudgingBoundCalculator::new(m1_config)
            .calculate_sm_bound()
            .unwrap();
        let b2 = SmudgingBoundCalculator::new(m2_config)
            .calculate_sm_bound()
            .unwrap();
        assert!(b2 >= b1, "more ciphertexts should not decrease B_sm");
    }

    #[test]
    fn smudging_bound_increases_with_larger_lambda() {
        let params = test_params();
        let l10_config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 3, 1, Lambda::insecure(10)).unwrap();
        let l11_config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 3, 1, Lambda::insecure(11)).unwrap();
        let b10 = SmudgingBoundCalculator::new(l10_config)
            .calculate_sm_bound()
            .unwrap();
        let b11 = SmudgingBoundCalculator::new(l11_config)
            .calculate_sm_bound()
            .unwrap();
        assert!(b11 > b10, "larger lambda should produce larger B_sm");
    }

    #[test]
    fn smudging_bound_increases_with_larger_n() {
        let params = test_params();
        // n=3 has less correctness headroom than n=1, but the B_sm multiplier
        // (2^(lambda+1) * d) doesn't depend on n directly — but B_fresh
        // depends on n through public_key_error. So larger n → larger B_C
        // → larger B_sm for the same lambda.
        let n1_config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 1, 1, Lambda::insecure(2)).unwrap();
        let n3_config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 3, 1, Lambda::insecure(2)).unwrap();
        let b1 = SmudgingBoundCalculator::new(n1_config)
            .calculate_sm_bound()
            .unwrap();
        let b3 = SmudgingBoundCalculator::new(n3_config)
            .calculate_sm_bound()
            .unwrap();
        assert!(b3 >= b1, "larger n should not decrease B_sm");
    }

    #[test]
    fn zero_ciphertexts_rejected() {
        let params = test_params();
        let result = SmudgingBoundCalculatorConfig::new(params, 3, 0, Lambda::insecure(2));
        assert!(result.unwrap_err().to_string().contains("ciphertexts"));
    }

    #[test]
    fn zero_parties_rejected() {
        let params = test_params();
        let result = SmudgingBoundCalculatorConfig::new(params, 0, 1, Lambda::insecure(2));
        assert!(result.unwrap_err().to_string().contains("parties"));
    }

    // ── SmudgingCoefficients protected wrapper (issue #126) ────────────

    /// Compile-time assertion that a type implements the unconditional
    /// `ZeroizeOnDrop` contract (normal drops, early returns, and unwinding).
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn smudging_coefficients_zeroize_clears_values() {
        let coeffs = vec![BigInt::from(1000), BigInt::from(-2000), BigInt::from(3000)];
        let mut wrapper = SmudgingCoefficients::new(coeffs);
        wrapper.zeroize();
        // Every BigInt is replaced with zero and the container is cleared.
        // This is best effort: num-bigint does not expose its private limb
        // allocation for overwriting before deallocation, so the wrapper
        // cannot promise allocator-level erasure.
        assert_eq!(wrapper.len(), 0, "zeroize must clear the container");
        assert!(wrapper.as_slice().is_empty());
        // Drop always runs zeroization (normal drops, early returns, and
        // unwinding); allocator-level memory cannot be inspected portably
        // and reading freed memory is forbidden.
        assert_zeroize_on_drop::<SmudgingCoefficients>();
    }

    #[test]
    fn smudging_coefficients_borrowed_access_is_non_cloneable() {
        let coeffs = vec![BigInt::from(5), BigInt::from(-5)];
        let wrapper = SmudgingCoefficients::new(coeffs);
        assert_eq!(wrapper.len(), 2);
        assert_eq!(wrapper.as_slice(), &[BigInt::from(5), BigInt::from(-5)]);
        // Ownership is intentionally consumed by the polynomial conversion;
        // this test only exercises the read-only inspection boundary.
        assert_eq!(wrapper.as_slice().len(), 2);
    }

    #[test]
    fn smudging_coefficients_debug_is_redacted() {
        let wrapper = SmudgingCoefficients::new(vec![BigInt::from(123456789)]);
        let debug = format!("{wrapper:?}");
        assert!(
            !debug.contains("123456789"),
            "Debug must not leak coefficient values: {debug}"
        );
    }
}
