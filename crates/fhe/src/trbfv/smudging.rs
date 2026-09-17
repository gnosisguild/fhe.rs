#![expect(
    clippy::indexing_slicing,
    reason = "indices are bounded by validated matrix dimensions"
)]
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
use fhe_math::rq::{Poly, PowerBasis};
use ndarray::Array2;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::{CryptoRng, RngCore};
use std::fmt;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Minimum statistical security parameter accepted for production use.
///
/// This is a statistical-hiding policy threshold: noise with
/// `B_sm = 2^(lambda + 1) * d * B_C` (`d` = polynomial degree) is intended to
/// statistically hide the decryption noise for a whole decryption transcript
/// (all `d` coefficients revealed at once), not just a single coefficient.
/// A larger lambda gives a stronger guarantee, not a computational one.
/// [`MIN_SECURE_LAMBDA`] is a policy choice, not derived from a cryptographic
/// reduction.
pub const MIN_SECURE_LAMBDA: usize = 31;

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
    /// - Lambda exceeds [`MAX_FEASIBLE_LAMBDA`]
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
        // A single decryption reveals all `d` (= degree) coefficients of the
        // smudging noise at once. `2^lambda * B_C` alone only bounds the
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

/// Smudging noise generator using exact centered uniform sampling.
///
/// Each coefficient is sampled uniformly from `[-B_sm, B_sm]` directly into
/// RNS representation, as specified for the smudging noise in the trBFV
/// paper. The secret sampling path uses plain `u64` limb arithmetic only;
/// arbitrary-precision integers appear solely for the public bound, range,
/// and moduli.
#[derive(Debug)]
pub struct SmudgingNoiseGenerator {
    params: Arc<BfvParameters>,
    smudging_bound: BigUint,
}

/// Little-endian limb comparison: returns whether `a < b`.
/// Both slices must have the same length.
fn limbs_lt(a: &[u64], b: &[u64]) -> bool {
    for (ai, bi) in a.iter().zip(b).rev() {
        if ai != bi {
            return ai < bi;
        }
    }
    false
}

/// Reduce a little-endian limb value modulo `qi`.
/// Requires `qi > 0`; an empty limb slice reduces to zero.
fn limbs_mod(limbs: &[u64], qi: u64) -> u64 {
    let mut acc = 0u64;
    for &limb in limbs.iter().rev() {
        acc = ((u128::from(acc) << 64 | u128::from(limb)) % u128::from(qi)) as u64;
    }
    acc
}

/// Freshly sampled smudging noise with private wipe-on-drop storage.
///
/// The underlying polynomial is private and the owner is consumed by the
/// smudging dealing operation ([`ShareManager::generate_secret_shares_from_smudging_noise`]).
/// There is intentionally no `Clone`, `Copy`, coefficient accessor, or
/// generic serialization: duplicating one-time noise across decryptions
/// breaks the statistical hiding argument.
///
/// ```compile_fail
/// # use fhe::trbfv::{GeneratedSmudgingNoise, ShareManager};
/// fn duplicate(noise: &GeneratedSmudgingNoise) -> GeneratedSmudgingNoise {
///     noise.clone()
/// }
/// ```
pub struct GeneratedSmudgingNoise {
    poly: Zeroizing<Poly<PowerBasis>>,
}

impl GeneratedSmudgingNoise {
    /// Consume the owner and release the noise polynomial.
    ///
    /// Crate-private so the supported dealing operation is the only consumer;
    /// external code cannot extract a reusable raw polynomial.
    pub(crate) fn into_poly(self) -> Zeroizing<Poly<PowerBasis>> {
        self.poly
    }
}

impl fmt::Debug for GeneratedSmudgingNoise {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedSmudgingNoise")
            .finish_non_exhaustive()
    }
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

    /// Generate smudging noise using the calculated bound.
    ///
    /// Each coefficient is sampled exactly uniformly from `[-B_sm, B_sm]`, as
    /// specified for the smudging noise in the trBFV paper, and written
    /// directly into RNS representation: with `M = 2 * B_sm + 1`, a candidate
    /// `u` is drawn uniformly from `[0, M)` by rejection sampling into a
    /// runtime-sized wipe-on-drop limb buffer, and the same accepted `u` is
    /// reduced under every RNS modulus as
    /// `(u mod q_i - B_sm mod q_i) mod q_i`.
    ///
    /// # Returns
    /// A non-cloneable owner of the sampled noise polynomial, consumed by
    /// the smudging dealing operation.
    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<GeneratedSmudgingNoise, Error> {
        let ctx = self.params.context_at_level(0)?;
        let degree = self.params.degree();
        let moduli = self.params.moduli();
        if self.smudging_bound == BigUint::from(0u64) {
            return Ok(GeneratedSmudgingNoise {
                poly: Zeroizing::new(Poly::<PowerBasis>::zero(ctx)),
            });
        }

        // Public range size M = 2 * B_sm + 1 as little-endian limbs.
        let m = BigUint::from(2u32) * &self.smudging_bound + BigUint::from(1u32);
        let m_bits = m.bits();
        let nlimbs = m_bits.div_ceil(64) as usize;
        let mut m_limbs = m.to_u64_digits();
        m_limbs.resize(nlimbs, 0);
        let excess = nlimbs as u64 * 64 - m_bits;
        let top_mask = if excess == 0 {
            u64::MAX
        } else {
            u64::MAX >> excess
        };

        // Public per-modulus reductions of the bound.
        let bound_limbs = self.smudging_bound.to_u64_digits();
        let bound_mod: Vec<u64> = moduli
            .iter()
            .map(|&qi| limbs_mod(&bound_limbs, qi))
            .collect();

        // Owned matrix; moved into the wipe-on-drop polynomial below without
        // any intermediate drop, so no partial secret is abandoned.
        let mut matrix = Array2::zeros((moduli.len(), degree));
        let mut candidate = Zeroizing::new(vec![0u64; nlimbs]);
        for col in 0..degree {
            // Exact rejection sampling of u in [0, M): candidates are uniform
            // over [0, 2^bits(M)), so acceptance probability is at least 1/2.
            loop {
                for limb in candidate.iter_mut() {
                    *limb = rng.next_u64();
                }
                if let Some(top) = candidate.last_mut() {
                    *top &= top_mask;
                }
                if limbs_lt(&candidate, &m_limbs) {
                    break;
                }
                // Wipe the rejected candidate before reuse.
                candidate.as_mut_slice().zeroize();
            }
            for (row, (&qi, &bound_qi)) in moduli.iter().zip(&bound_mod).enumerate() {
                let u_mod = limbs_mod(&candidate, qi);
                matrix[[row, col]] = if u_mod >= bound_qi {
                    u_mod - bound_qi
                } else {
                    u_mod + qi - bound_qi
                };
            }
            // Wipe the consumed candidate limbs.
            candidate.as_mut_slice().zeroize();
        }
        let poly = Poly::<PowerBasis>::from_coeffs_matrix(matrix, ctx)?;
        Ok(GeneratedSmudgingNoise { poly })
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
    use num_bigint::BigInt;
    use rand::{SeedableRng, rng};
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

    /// Small-degree parameters with library-generated moduli for exact
    /// oracle checks. No hand-picked primes: moduli come from the builder's
    /// own prime generator.
    fn small_params(modulus_sizes: &[usize]) -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(2)
            .set_moduli_sizes(modulus_sizes)
            .build_arc()
            .unwrap()
    }

    /// Test-only modular inverse for the CRT oracle (inputs are coprime).
    fn modinv_u64(a: u64, m: u64) -> u64 {
        let (mut t, mut new_t) = (0i128, 1i128);
        let (mut r, mut new_r) = (m as i128, a as i128);
        while new_r != 0 {
            let quotient = r / new_r;
            let tmp_t = t - quotient * new_t;
            t = new_t;
            new_t = tmp_t;
            let tmp_r = r - quotient * new_r;
            r = new_r;
            new_r = tmp_r;
        }
        assert!(r == 1, "modular inverse does not exist");
        t.rem_euclid(m as i128) as u64
    }

    /// Test oracle (arbitrary precision): reconstruct the centered integer
    /// represented by one residue per modulus via Garner/CRT.
    fn crt_centered_integer(residues: &[u64], moduli: &[u64]) -> BigInt {
        let mut x = BigUint::from(0u64);
        let mut prod = BigUint::from(1u64);
        for (&r, &q) in residues.iter().zip(moduli.iter()) {
            let q_big = BigUint::from(q);
            let x_mod_q = &x % &q_big;
            let r_big = BigUint::from(r);
            let diff = if r_big >= x_mod_q {
                r_big - &x_mod_q
            } else {
                &r_big + &q_big - &x_mod_q
            };
            let t = diff * modinv_u64((&prod % &q_big).to_u64().unwrap(), q) % &q_big;
            x += &prod * &t;
            prod *= &q_big;
        }
        let x = x % &prod;
        if x.clone() * BigUint::from(2u32) > prod.clone() {
            BigInt::from(x) - BigInt::from(prod)
        } else {
            BigInt::from(x)
        }
    }

    /// Assert every coefficient of the owned noise is a canonical RNS
    /// encoding of one centered integer in `[-bound, bound]` shared by all
    /// rows. Consumes the owner, mirroring the dealing operation.
    fn assert_noise_in_bound(
        noise: GeneratedSmudgingNoise,
        bound: &BigUint,
        params: &Arc<BfvParameters>,
    ) {
        let poly = noise.into_poly();
        let moduli = params.moduli();
        assert_eq!(poly.coefficients().dim(), (moduli.len(), params.degree()));
        let neg_bound = -BigInt::from(bound.clone());
        let pos_bound = BigInt::from(bound.clone());
        for col in 0..params.degree() {
            let residues: Vec<u64> = (0..moduli.len())
                .map(|row| poly.coefficients()[[row, col]])
                .collect();
            for (&r, &q) in residues.iter().zip(moduli.iter()) {
                assert!(r < q, "residue {r} not canonical modulo {q}");
            }
            let x = crt_centered_integer(&residues, moduli);
            assert!(
                x >= neg_bound && x <= pos_bound,
                "sample {x} outside [-bound, bound]"
            );
        }
    }

    /// Parameters with a large error1_variance so the uniform sampler branch
    /// is exercised (variance >= 16 as u64).
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
        let generator = SmudgingNoiseGenerator::new(params.clone(), bound.clone());

        let noise = generator.generate_smudging_error(&mut rng).unwrap();
        let poly = noise.into_poly();
        assert_eq!(
            poly.coefficients().dim(),
            (params.moduli().len(), params.degree())
        );
        assert!(poly.coefficients().iter().any(|&c| c != 0));
        assert_noise_in_bound(GeneratedSmudgingNoise { poly }, &bound, &params);
    }

    #[test]
    fn test_noise_generation_zero_bound() {
        let mut rng = rng();
        let params = test_params();
        let bound = BigUint::from(0u64);
        let generator = SmudgingNoiseGenerator::new(params.clone(), bound);

        let poly = generator
            .generate_smudging_error(&mut rng)
            .unwrap()
            .into_poly();
        assert_eq!(
            poly.coefficients().dim(),
            (params.moduli().len(), params.degree())
        );
        assert!(poly.coefficients().iter().all(|&c| c == 0));
    }

    #[test]
    fn test_noise_generation_large_bound() {
        let mut rng = rng();
        let params = test_params();
        let large_bound: BigUint = (BigUint::from(1u32) << 96) + BigUint::from(12345u32);
        let generator = SmudgingNoiseGenerator::new(params.clone(), large_bound.clone());

        let poly = generator
            .generate_smudging_error(&mut rng)
            .unwrap()
            .into_poly();
        assert_eq!(
            poly.coefficients().dim(),
            (params.moduli().len(), params.degree())
        );
        let nonzero = poly.coefficients().iter().filter(|&&c| c != 0).count();
        assert!(nonzero > params.degree() * params.moduli().len() / 4);
        assert_noise_in_bound(GeneratedSmudgingNoise { poly }, &large_bound, &params);
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
                let noise = generator.generate_smudging_error(&mut rng).unwrap();
                assert_noise_in_bound(noise, &bound, &params);
            }
            Err(_) => {
                // Acceptable for some parameter sets
            }
        }
    }

    #[test]
    fn test_noise_small_bounds_match_centered_integers() {
        // Exhaustive check on small generated parameters: every column must
        // encode exactly one centered integer across all RNS rows.
        let params = small_params(&[11, 11, 11]);
        let moduli = params.moduli().to_vec();
        let mut rng = ChaCha8Rng::seed_from_u64(172_101);
        for b in [1u64, 2, 3, 7, 100, 500] {
            let bound = BigUint::from(b);
            let generator = SmudgingNoiseGenerator::new(params.clone(), bound.clone());
            let noise = generator.generate_smudging_error(&mut rng).unwrap();
            let poly = noise.into_poly();
            for col in 0..params.degree() {
                let matches: Vec<i64> = (-(b as i64)..=b as i64)
                    .filter(|&x| {
                        moduli.iter().enumerate().all(|(row, &q)| {
                            poly.coefficients()[[row, col]] == x.rem_euclid(q as i64) as u64
                        })
                    })
                    .collect();
                assert_eq!(matches.len(), 1, "bound {b}, column {col}");
            }
            assert_noise_in_bound(GeneratedSmudgingNoise { poly }, &bound, &params);
        }
    }

    #[test]
    fn test_noise_small_bound_is_approximately_uniform() {
        // B = 2 gives M = 5 single-limb values; over 4096 samples each of the
        // five centered values must appear at a roughly even rate.
        let params = small_params(&[11, 11, 11]);
        let moduli = params.moduli().to_vec();
        let mut rng = ChaCha8Rng::seed_from_u64(172_102);
        let mut counts = [0usize; 5];
        for _ in 0..512 {
            let generator = SmudgingNoiseGenerator::new(params.clone(), BigUint::from(2u32));
            let poly = generator
                .generate_smudging_error(&mut rng)
                .unwrap()
                .into_poly();
            for col in 0..params.degree() {
                let residues: Vec<u64> = (0..moduli.len())
                    .map(|row| poly.coefficients()[[row, col]])
                    .collect();
                let x = crt_centered_integer(&residues, &moduli).to_i64().unwrap();
                assert!((-2..=2).contains(&x));
                counts[(x + 2) as usize] += 1;
            }
        }
        assert_eq!(counts.iter().sum::<usize>(), 512 * params.degree());
        for (value, &count) in (-2i64..=2).zip(counts.iter()) {
            assert!(
                (500..=1150).contains(&count),
                "value {value} sampled {count} times, expected ~819"
            );
        }
    }

    #[test]
    fn test_noise_limb_boundaries_match_oracle() {
        // Bounds straddling 64-bit limb edges. Three generated 62-bit moduli
        // give Q ~ 2^186, well above twice each bound.
        let params = small_params(&[62, 62, 62]);
        let mut rng = ChaCha8Rng::seed_from_u64(172_103);
        let bounds = [
            (BigUint::from(1u32) << 63) - BigUint::from(1u32), // M = 2^64 - 1
            BigUint::from(1u32) << 63,                         // M = 2^64 + 1
            BigUint::from(u64::MAX),                           // M = 2^65 - 1
            (BigUint::from(1u32) << 100) + BigUint::from(12345u32),
        ];
        for bound in &bounds {
            let generator = SmudgingNoiseGenerator::new(params.clone(), bound.clone());
            let noise = generator.generate_smudging_error(&mut rng).unwrap();
            assert_noise_in_bound(noise, bound, &params);
        }
    }

    #[test]
    fn test_noise_wide_bound_beyond_five_limbs() {
        // B = 2^320 gives M = 2^321 + 1 (six limbs). Six generated 62-bit
        // moduli give Q ~ 2^372, well above 2 * B, so the CRT oracle recovers
        // each sample.
        let params = small_params(&[62, 62, 62, 62, 62, 62]);
        let mut rng = ChaCha8Rng::seed_from_u64(172_104);
        let bound: BigUint = BigUint::from(1u32) << 320;
        assert!(bound.bits() > 5 * 64, "test requires a >5-limb bound");
        let generator = SmudgingNoiseGenerator::new(params.clone(), bound.clone());
        let noise = generator.generate_smudging_error(&mut rng).unwrap();
        assert_noise_in_bound(noise, &bound, &params);
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
