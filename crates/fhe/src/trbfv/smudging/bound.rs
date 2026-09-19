//! Smudging-bound configuration and arithmetic.

use crate::Error;
use crate::bfv::BfvParameters;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
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
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SmudgingConfig {
    /// BFV parameters (degree, moduli, plaintext modulus)
    pub params: Arc<BfvParameters>,
    /// Number of parties in the threshold scheme
    pub n: usize,
    /// Number of ciphertexts being processed
    pub m: usize,
    /// Statistical security parameter: the smudging bound grows as
    /// `2^(lambda + 1) * d * B_C`. Larger values give stronger statistical
    /// hiding; values above [`MAX_LAMBDA`] are rejected. Choosing lambda for
    /// a deployment is the caller's policy.
    pub lambda: usize,
    /// Multiplicative circuit depth (0 for additive-only circuits).
    ///
    /// When non-zero, [`crate::trbfv::smudging::SmudgingNoiseGenerator::new`]
    /// applies the Prop. 20 noise growth recursion for each level before
    /// computing `B_sm`.
    pub mult_depth: u32,
}

/// Compute a coefficient bound (B_enc) from the configured error sampler variance.
///
/// This mirrors `Poly::conditional_error`: CBD is used through variance 16,
/// while the uniform branch uses the smallest `B` whose variance
/// `B * (B + 1) / 3` reaches the requested variance.
pub(super) fn compute_b_enc(error1_variance: &BigUint) -> BigUint {
    match error1_variance.to_u64() {
        Some(v) if v <= 16 => {
            // CBD(2*v): maximum absolute coefficient = 2 * variance.
            BigUint::from(2u32 * v as u32)
        }
        _ => {
            // Uniform branch: find the smallest B with B*(B+1) >= 3*variance.
            let target = BigUint::from(3u32) * error1_variance;
            let mut bound = target.sqrt();
            while &bound * (&bound + 1u32) < target {
                bound += 1u32;
            }
            while bound > 0u32.into() && (&bound - 1u32) * &bound >= target {
                bound -= 1u32;
            }
            bound
        }
    }
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
