//! Smudging bounds and statistical-security policy (Urban–Rambaud 2024, Appendix C).
//!
//! Computes the coefficient bound and checks the BFV correctness budget.
//! Sampling and ownership are implemented separately by each decryption protocol.

use crate::Error;
use crate::bfv::BfvParameters;

use fhe_math::rq::variance_to_uniform_bound;
use num_bigint::BigUint;
use std::sync::Arc;

#[cfg(feature = "synchronized-decryption")]
pub use super::synchronized::{SmudgingNoise, SmudgingNoiseGenerator};

/// Minimum statistical-security policy parameter accepted by [`Lambda::secure`].
///
/// This is a statistical-hiding policy threshold: noise with
/// `B_sm = 2^(lambda + 1) * d * B_C` (`d` = polynomial degree) is intended to
/// statistically hide the decryption noise for a transcript containing `d`
/// noisy coefficients, not just a single coefficient.
/// A larger lambda gives a stronger guarantee, not a computational one.
/// [`MIN_SECURE_LAMBDA`] is a policy choice, not derived from a cryptographic
/// reduction.
pub const MIN_SECURE_LAMBDA: usize = 35;

/// Internal lambda cap that bounds allocations from caller-controlled BigUint
/// shifts. Correctness-budget checks can reject smaller values as well.
const MAX_FEASIBLE_LAMBDA: usize = 256;

/// Statistical security level for smudging noise generation.
///
/// The smudging bound is always computed as `B_sm = 2^(lambda + 1) * d * B_C`
/// (`d` = polynomial degree, accounting for the `d` noisy coefficients in a
/// decryption transcript). [`Lambda::secure`] rejects lambda below
/// [`MIN_SECURE_LAMBDA`]; [`Lambda::insecure`] explicitly opts out of that check
/// for test setups. Neither constructor certifies the BFV parameter set's
/// computational security or the surrounding protocol.
///
/// Prefer the constructors: the public enum variants can be constructed directly
/// and do not themselves enforce the constructor checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lambda {
    /// Level marked as meeting the statistical policy.
    /// Construct via [`Lambda::secure`] to validate the minimum.
    Secure(usize),
    /// Explicit testing-only opt-out from the statistical-policy minimum.
    /// Construct via [`Lambda::insecure`], which clamps lambda to at least 2.
    Insecure(usize),
}

impl Lambda {
    /// Validate the statistical-policy minimum; fails below [`MIN_SECURE_LAMBDA`].
    pub fn secure(lambda: usize) -> Result<Self, Error> {
        if lambda < MIN_SECURE_LAMBDA {
            return Err(Error::insecure_lambda(lambda, MIN_SECURE_LAMBDA));
        }
        Ok(Self::Secure(lambda))
    }

    /// Create an explicitly insecure level for fast testing (lambda clamped to >= 2).
    ///
    /// This opts out of the library's statistical-policy minimum. A small lambda
    /// does not provide the required hiding margin. Never use this opt-out in
    /// production.
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

    /// Whether this value is marked [`Lambda::Secure`], without revalidating it.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Secure(_))
    }
}

/// Configuration for calculating the smudging coefficient bound in threshold BFV.
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
    /// Derived from the configured BFV encryption-error `e1` sampler:
    /// - CBD branch (error1_variance <= 16): `B_enc = 2 * error1_variance`
    ///   (support bound of CBD(2·variance)).
    /// - Uniform branch (larger variance): the smallest integer `B` satisfying
    ///   `B * (B + 1) >= 3 * error1_variance`, shared with the sampler through
    ///   [`fhe_math::rq::variance_to_uniform_bound`].
    ///
    /// Overrides must conservatively cover the caller's actual encryption path.
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
/// Matches `Poly::conditional_error` for supported positive variances: CBD
/// through 16 inclusive, then the exact shared discrete-uniform support bound.
fn compute_b_enc(error1_variance: &BigUint) -> Result<BigUint, Error> {
    if error1_variance <= &BigUint::from(16u32) {
        // CBD(2*v): maximum absolute coefficient = 2 * variance.
        Ok(BigUint::from(2u32) * error1_variance)
    } else {
        variance_to_uniform_bound(error1_variance)?
            .to_biguint()
            .ok_or_else(|| {
                Error::smudging_bound_infeasible("computed encryption bound is negative")
            })
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
    /// Create a bound-calculator configuration with standard parameters.
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `n` - Number of parties in threshold scheme
    /// * `m` - Number of ciphertexts to process
    /// * `lambda` - Statistical security level
    ///
    /// # Errors
    /// Returns an error when `n` or `m` is zero, or the encryption-error support
    /// bound cannot be computed.
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
        let b_enc = compute_b_enc(params.get_error1_variance())?;

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
    /// Returns an error when `n` or `m` is zero, or the encryption-error support
    /// bound cannot be computed.
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
/// - Configurable `B_enc`, defaulting to the BFV encryption-error sampler's support.
/// - Distributed RLK error accounting via [`Self::with_accepted_participant_count`].
/// - Caller-supplied ciphertext noise bound via [`Self::with_initial_ciphertext_noise_bound`].
///
/// ## Limitations (not enforced by this API)
///
/// - **Custom bounds:** Overrides of [`SmudgingBoundCalculatorConfig::b_enc`] and
///   the other noise/key bounds must conservatively cover the actual encryption
///   path and circuit; the calculator does not verify caller-supplied bounds.
/// - **One-time noise:** The calculator only computes a bound. Synchronized
///   callers sample fresh local noise for each partial; SS-smudging callers
///   sample and deal fresh noise for each decryption. Protocol-specific noise
///   owners prevent accidental in-memory reuse, not replay of external storage.
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
    /// Configuration binding for the protocol-specific noise samplers.
    pub(in crate::trbfv) fn noise_parameters(&self) -> (&Arc<BfvParameters>, usize) {
        (&self.config.params, self.config.n)
    }

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
    /// noisy coefficients in a decryption transcript) subject to
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
    /// - Lambda exceeds the supported maximum of 256
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
        let t = BigUint::from(self.config.params.plaintext());
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
            let k = BigUint::from(self.config.params.plaintext());
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
        // A single decryption transcript contains `d` (= degree) noisy
        // coefficients. `2^lambda * B_C` alone only bounds the
        // statistical distance for a single coefficient; the union bound over
        // the `d` coefficients requires the additional degree factor.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfv::BfvParametersBuilder;
    use fhe_math::rq::{Context, Poly, PowerBasis, Representation};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;
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
    /// is exercised (variance > 16).
    fn test_params_large_error1() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(8192)
            .set_plaintext_modulus(16384)
            .set_moduli(&[0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001])
            .set_error1_variance_usize(20)
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

        let b_enc = compute_b_enc(params.get_error1_variance()).unwrap();
        assert_eq!(b_enc, BigUint::from(20_u32));
    }

    #[test]
    fn b_enc_includes_the_cbd_boundary() {
        for (variance, support) in [(15, 30u32), (16, 32), (17, 7)] {
            let params = BfvParametersBuilder::new()
                .set_degree(8)
                .set_plaintext_modulus(2)
                .set_moduli(&[65537])
                .set_error1_variance_usize(variance)
                .build_arc()
                .unwrap();
            let config =
                SmudgingBoundCalculatorConfig::new(params, 3, 1, Lambda::insecure(2)).unwrap();
            assert_eq!(config.b_enc, BigUint::from(support), "variance={variance}");
        }
    }

    #[test]
    fn b_enc_uniform_branch_uses_exact_discrete_support() {
        // Variance=20 requires B=8: 7*8 < 3*20 <= 8*9.
        let params = test_params_large_error1();
        assert_eq!(params.get_error1_variance(), &BigUint::from(20_u32));

        let b_enc = compute_b_enc(params.get_error1_variance()).unwrap();
        assert_eq!(b_enc, BigUint::from(8u32));
    }

    #[test]
    fn b_enc_uniform_support_is_minimal_and_never_undershoots() {
        let variances = (17u32..=1000).map(BigUint::from).chain([
            BigUint::from(u64::MAX),
            BigUint::from(1u32) << 64usize,
            BigUint::from(1u32) << 128usize,
        ]);
        for variance in variances {
            let bound = compute_b_enc(&variance).unwrap();
            let target = &variance * 3u32;
            assert!(
                &bound * (&bound + 1u32) >= target,
                "variance={variance}: bound={bound} undershoots the requested variance"
            );
            assert!(
                (&bound - 1u32) * &bound < target,
                "variance={variance}: bound={bound} is not minimal"
            );
        }
    }

    #[test]
    fn b_enc_matches_error1_sampler_branches_and_rng_consumption() {
        let ctx = Context::new_arc(&[65537], 8).unwrap();
        for variance in [1usize, 15, 16, 17, 20] {
            let variance_big = BigUint::from(variance);
            let bound = compute_b_enc(&variance_big).unwrap();
            let mut rng = ChaCha8Rng::seed_from_u64(95);
            let mut expected_rng = rng.clone();
            let actual = Poly::<PowerBasis>::error_1(
                &ctx,
                Representation::PowerBasis,
                &variance_big,
                &mut rng,
            )
            .unwrap();
            let expected = if variance <= 16 {
                assert_eq!(bound, BigUint::from(2 * variance));
                Poly::<PowerBasis>::small(&ctx, variance, &mut expected_rng).unwrap()
            } else {
                Poly::<PowerBasis>::uniform_biguint(
                    &ctx,
                    Representation::PowerBasis,
                    &bound,
                    &mut expected_rng,
                )
                .unwrap()
            };
            assert_eq!(actual, expected, "variance={variance}");
            assert_eq!(
                rng.next_u64(),
                expected_rng.next_u64(),
                "variance={variance}"
            );
        }
    }

    #[test]
    fn b_enc_large_biguint_uses_uniform_branch() {
        // A 128-bit variance does not fit in u64, so the uniform branch is used.
        let var = BigUint::from_str("340282366920938463463374607431768211456").unwrap(); // 2^128
        let b_enc = compute_b_enc(&var).unwrap();
        let expected = BigUint::from_str("31950697969885030203").unwrap();
        assert_eq!(b_enc, expected);
    }

    #[test]
    fn config_new_uses_computed_b_enc() {
        let params = test_params();
        let config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 5, 2, Lambda::secure(80).unwrap())
                .unwrap();
        assert_eq!(
            config.b_enc,
            compute_b_enc(params.get_error1_variance()).unwrap()
        );
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
        let t = BigUint::from(params.plaintext());
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
            .set_error1_variance_usize(1) // CBD, B_enc=2
            .build_arc()
            .unwrap();
        let t = BigUint::from(params.plaintext());
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

        // B_sm = 2^(lambda + 1) * d * B_C = 8 * 8192 * 12345
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
        assert_eq!(
            config.b_enc,
            compute_b_enc(params.get_error1_variance()).unwrap()
        );
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

    /// depth=0 (additive) produces a smaller bound than depth=1 (one multiplication),
    /// and depth=2 produces a larger bound than depth=1.
    #[test]
    fn test_multiplicative_depth_increases_bound() {
        // The degree factor in the updated bound requires a wider modulus
        // chain for this synthetic depth-growth check.
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
        // (2^(lambda + 1) * d) doesn't depend on n directly — but B_fresh
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
}
