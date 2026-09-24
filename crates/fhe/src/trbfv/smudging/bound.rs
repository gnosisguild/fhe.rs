//! Smudging-bound configuration and arithmetic.

use crate::Error;
use crate::bfv::BfvParameters;
use fhe_math::rq::error_coefficient_bound;
use num_bigint::BigUint;
use std::sync::Arc;

/// Maximum statistical security parameter accepted for the smudging bound.
///
/// The smudging bound is `B_sm = 2^(lambda + 1) * d * B_C` (`d` = polynomial
/// degree); larger values are computationally infeasible to represent, so
/// values above this ceiling are rejected to prevent massive allocations
/// from huge BigUint shifts. How much statistical hiding a given lambda
/// provides depends on the full parameter set (degree, moduli, plaintext
/// modulus, circuit depth), so this is the only lambda bound the library
/// enforces: callers choose lambda according to their deployment's policy.
pub const MAX_LAMBDA: usize = 256;

/// Configuration for calculating and generating threshold BFV smudging noise.
///
/// The bound is derived from these caller-selected inputs when a
/// [`crate::trbfv::smudging::SmudgingNoiseGenerator`] is created.
/// Configuration inputs validated by [`Self::new`] cannot be changed directly.
///
/// ```compile_fail
/// # use fhe::trbfv::smudging::SmudgingConfig;
/// fn change_party_count(config: &mut SmudgingConfig) {
///     config.n = 0;
/// }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SmudgingConfig {
    /// BFV parameters (degree, moduli, plaintext modulus)
    pub(super) params: Arc<BfvParameters>,
    /// Number of parties in the threshold scheme
    pub(super) n: usize,
    /// Number of ciphertexts being processed
    pub(super) m: usize,
    /// Statistical security parameter: the smudging bound grows as
    /// `2^(lambda + 1) * d * B_C`. Larger values give stronger statistical
    /// hiding; values above [`MAX_LAMBDA`] are rejected. Choosing lambda for
    /// a deployment is the caller's policy.
    pub(super) lambda: usize,
    /// Multiplicative circuit depth (0 for additive-only circuits).
    ///
    /// When non-zero, [`crate::trbfv::smudging::SmudgingNoiseGenerator::new`]
    /// applies the Prop. 20 noise growth recursion for each level before
    /// computing `B_sm`.
    pub(super) mult_depth: u32,
}

/// Compute a coefficient bound (B_enc) from the configured error sampler variance.
///
/// Uses the same worst-case coefficient bound as the encryption sampler.
pub(super) fn compute_b_enc(error1_variance: &BigUint) -> crate::Result<BigUint> {
    Ok(error_coefficient_bound(error1_variance)?)
}

/// Compute Q = product of all moduli as a BigUint.
pub(super) fn modulus_product(moduli: &[u64]) -> BigUint {
    let mut q = BigUint::from(1_u64);
    for &qi in moduli {
        q *= BigUint::from(qi);
    }
    q
}

/// Compute Delta = floor(Q / t), the exact plaintext scaling factor.
pub(super) fn compute_delta(q: &BigUint, t: &BigUint) -> BigUint {
    q / t
}

impl SmudgingConfig {
    /// Return the BFV parameters for this configuration.
    #[must_use]
    pub fn params(&self) -> &Arc<BfvParameters> {
        &self.params
    }

    /// Return the party count.
    #[must_use]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Return the ciphertext count.
    #[must_use]
    pub fn m(&self) -> usize {
        self.m
    }

    /// Return the statistical security parameter.
    #[must_use]
    pub fn lambda(&self) -> usize {
        self.lambda
    }

    /// Return the multiplicative depth (zero for additive-only circuits).
    #[must_use]
    pub fn mult_depth(&self) -> u32 {
        self.mult_depth
    }

    /// Set the circuit depth before creating a smudging noise generator.
    ///
    /// All `u32` depths are valid configuration inputs; feasibility of the
    /// resulting bound is checked by [`crate::trbfv::smudging::SmudgingNoiseGenerator::new`].
    #[must_use]
    pub fn with_mult_depth(mut self, depth: u32) -> Self {
        self.mult_depth = depth;
        self
    }

    /// Create a new smudging configuration with standard parameters.
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `n` - Number of parties in threshold scheme
    /// * `m` - Number of ciphertexts to process
    /// * `lambda` - Statistical security level
    ///
    /// # Errors
    /// Returns an error when `n` or `m` is zero, or when `lambda` exceeds
    /// [`MAX_LAMBDA`].
    pub fn new(
        params: Arc<BfvParameters>,
        n: usize,
        m: usize,
        lambda: usize,
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
        if lambda > MAX_LAMBDA {
            return Err(Error::smudging_bound_infeasible(format!(
                "lambda {lambda} exceeds maximum feasible value {MAX_LAMBDA}"
            )));
        }
        Ok(Self {
            params,
            n,
            m,
            lambda,
            mult_depth: 0,
        })
    }
}
