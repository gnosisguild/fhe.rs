//! Smudging-bound configuration and arithmetic.

use crate::Error;
use crate::bfv::BfvParameters;
use fhe_math::rq::error_coefficient_bound;
use num_bigint::BigUint;
use num_traits::Zero;
use std::sync::Arc;

/// Maximum statistical security parameter accepted for the smudging bound.
///
/// Caps `BigUint` shifts in `B_sm = 2^(lambda + 1) * d * B_C`.
/// Callers choose their own minimum statistical-hiding policy; this ceiling
/// is a resource limit, not a computational-security guarantee.
pub const MAX_LAMBDA: usize = 256;

/// Model of the encryption path that produced the fresh ciphertexts whose
/// decryption noise the smudging noise must hide.
///
/// Fresh public-key encryption noise under an aggregated threshold key is bounded by
///
/// > `B_fresh = d · u_bound · e_pk + B_enc + d · e2_bound · sk_bound`
///
/// Here `d` is the degree, `e2_bound = 2 · variance`, `sk_bound = n`, and
/// `e_pk = n · e2_bound`. `B_enc` comes from
/// [`fhe_math::rq::error_coefficient_bound`] applied to `error1_variance`.
/// Select the variant matching the actual sampler; for mixed paths, use the
/// largest bound. The library cannot verify ciphertext noise provenance.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshNoiseModel {
    /// Ciphertexts produced by `bfv::PublicKey::try_encrypt`, including keys
    /// aggregated from MBFV public-key shares (`mbfv::PublicKeyShare`).
    ///
    /// The encryption randomness is ternary (`‖u‖∞ ≤ 1`).
    BfvPublicKey,
    /// Ciphertexts produced by `lbfv::LBFVPublicKey::try_encrypt`, including
    /// keys aggregated from distributed l-BFV public-key shares.
    ///
    /// The encryption randomness is sampled with `Poly::small(variance)`
    /// (`‖u‖∞ ≤ 2 · variance`), so the fresh-noise bound is larger than for
    /// [`FreshNoiseModel::BfvPublicKey`] at otherwise identical parameters.
    LbfvPublicKey,
    /// Ciphertexts produced by `bfv::SecretKey::try_encrypt`.
    ///
    /// Secret-key encryption uses no randomness polynomial `u` and no
    /// public-key error: the fresh phase noise is a single small error with
    /// `‖e‖∞ ≤ 2 · variance`, so `B_fresh = 2 · variance`.
    BfvSecretKey,
    /// Caller-justified positive `B_fresh` for external keys or samplers.
    /// This bound is trusted, not checked: understating actual noise invalidates
    /// the smudging guarantee. For heterogeneous inputs, use their maximum bound.
    Custom(BigUint),
}

/// Configuration for calculating and generating threshold BFV smudging noise.
///
/// [`crate::trbfv::SmudgingNoiseGenerator::new`] derives the bound and checks
/// feasibility. Validated inputs cannot be changed directly.
///
/// # Caller responsibilities
///
/// Choose `m`, depth, `lambda`, and [`FreshNoiseModel`] for the actual circuit
/// and encryption path. There is no default model. `lambda` is a statistical
/// policy, not computational bit-security; the library enforces no minimum.
/// [`crate::trbfv::ShareManager::generate_smudging_shares`] checks only party
/// count and full BFV parameters, not these caller-selected assumptions.
///
/// # Choosing the circuit size `m`
///
/// `m` bounds the worst addition fan-in over **fresh** ciphertexts before the
/// modelled circuit, not outputs or independent decryptions:
///
/// - `a + b + c`: `m = 3`.
/// - `a * b * c` without pre-sums: `m = 1`.
/// - `(a + b) * c`: `m = 2`.
///
/// Additions of evaluated results after multiplication are not modelled
/// automatically. Analyze those circuits and supply a conservative
/// circuit-specific `m`; increasing it inflates the bound at a feasibility cost.
///
/// ```
/// use fhe::bfv::BfvParametersBuilder;
/// use fhe::trbfv::{FreshNoiseModel, SmudgingConfig};
///
/// // Toy parameters for demonstrating configuration, not deployment.
/// let params = BfvParametersBuilder::new()
///     .set_degree(8)
///     .set_plaintext_modulus(2)
///     .set_moduli(&[65537])
///     .build_arc()
///     .unwrap();
///
/// // A pure product has no pre-sum.
/// let no_pre_sum =
///     SmudgingConfig::new(params.clone(), 3, 1, 2, FreshNoiseModel::BfvPublicKey)?;
/// assert_eq!(no_pre_sum.m(), 1);
///
/// // `(a + b) * c` has a two-input pre-sum and one multiplication level.
/// let mixed = SmudgingConfig::new(params, 3, 2, 2, FreshNoiseModel::BfvPublicKey)?
///     .with_mult_depth(1);
/// assert_eq!(mixed.m(), 2);
/// assert_eq!(mixed.n(), 3);
/// assert_eq!(mixed.lambda(), 2);
/// assert_eq!(mixed.mult_depth(), 1);
/// # Ok::<(), fhe::Error>(())
/// ```
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
    /// Fresh-input pre-sum fan-in; see [`SmudgingConfig`].
    pub(super) m: usize,
    /// Caller-selected statistical-hiding policy, at most [`MAX_LAMBDA`].
    pub(super) lambda: usize,
    /// Multiplicative circuit depth (0 for additive-only circuits).
    /// Each level applies the Prop. 20 noise-growth recursion.
    pub(super) mult_depth: u32,
    /// Explicit encryption-path model for `B_fresh`.
    pub(super) model: FreshNoiseModel,
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

    /// Return the maximum number of fresh ciphertexts summed before the
    /// modelled circuit (`m`).
    ///
    /// This is the circuit-size input the caller chose: the worst fan-in of
    /// pre-circuit additions over fresh ciphertexts. It is not the number of
    /// output ciphertexts or independent decryptions; see
    /// [`SmudgingConfig`] for how to choose it.
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
    /// The resulting bound is checked for feasibility by
    /// [`crate::trbfv::smudging::SmudgingNoiseGenerator::new`], including
    /// during the depth recursion.
    #[must_use]
    pub fn with_mult_depth(mut self, depth: u32) -> Self {
        self.mult_depth = depth;
        self
    }

    /// Return the selected fresh-noise model.
    #[must_use]
    pub fn model(&self) -> &FreshNoiseModel {
        &self.model
    }

    /// Worst-case bound `B_fresh` on the decryption noise of a fresh
    /// ciphertext produced by this configuration's modelled encryption path.
    ///
    /// See [`FreshNoiseModel`] for the per-path derivation and the actual
    /// sampler supports this bound relies on.
    pub(super) fn fresh_noise_bound(&self) -> crate::Result<BigUint> {
        if let FreshNoiseModel::Custom(bound) = &self.model
            && bound.is_zero()
        {
            // Defense in depth against a configuration whose private fields
            // were corrupted after `new` validated them.
            return Err(Error::smudging_bound_infeasible(
                "custom fresh-noise bound must be positive",
            ));
        }
        let variance = self.params.variance();
        let b_e = BigUint::from((2 * variance) as u64);
        let d = BigUint::from(self.params.degree());
        let b_enc = compute_b_enc(self.params.get_error1_variance())?;
        // BigUint products throughout: a large party count must overflow into
        // an infeasible bound, never wrap into an understated one.
        let e_pk = BigUint::from(self.n) * &b_e;
        let sk_bound = BigUint::from(self.n);
        Ok(match &self.model {
            FreshNoiseModel::BfvPublicKey => &d * &e_pk + b_enc + &d * &b_e * &sk_bound,
            FreshNoiseModel::LbfvPublicKey => {
                // l-BFV samples `u` with `Poly::small(variance)`, whose
                // coefficient support reaches `2 * variance`.
                let u_bound = BigUint::from((2 * variance) as u64);
                &d * &u_bound * &e_pk + b_enc + &d * &b_e * &sk_bound
            }
            // Secret-key encryption samples no randomness `u`: the phase of a
            // fresh ciphertext is exactly `e + m`, so `B_fresh = 2 * variance`.
            FreshNoiseModel::BfvSecretKey => b_e,
            FreshNoiseModel::Custom(bound) => bound.clone(),
        })
    }

    /// Create a new smudging configuration with an explicit fresh-noise model.
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `n` - Number of parties in threshold scheme
    /// * `m` - Fresh-input pre-sum fan-in; see [`SmudgingConfig`].
    /// * `lambda` - Caller-selected statistical-hiding policy.
    /// * `model` - Actual encryption path, or a justified custom bound.
    ///
    /// # Errors
    /// Returns an error when `n` or `m` is zero, when `lambda` exceeds
    /// [`MAX_LAMBDA`], or when a [`FreshNoiseModel::Custom`] bound is zero.
    pub fn new(
        params: Arc<BfvParameters>,
        n: usize,
        m: usize,
        lambda: usize,
        model: FreshNoiseModel,
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
        if let FreshNoiseModel::Custom(bound) = &model
            && bound.is_zero()
        {
            return Err(Error::smudging_bound_infeasible(
                "custom fresh-noise bound must be positive",
            ));
        }
        Ok(Self {
            params,
            n,
            m,
            lambda,
            mult_depth: 0,
            model,
        })
    }
}
