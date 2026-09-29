//! Smudging-noise ownership and sampling.

use super::bound::{MAX_LAMBDA, SmudgingConfig, compute_delta, modulus_product};
use crate::Error;
use crate::bfv::BfvParameters;
use fhe_math::rq::{Poly, PowerBasis};
use fhe_math::zq::Modulus;
use ndarray::{Array2, ArrayViewMut1};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use std::fmt;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::{Zeroize, Zeroizing};

/// Smudging noise generator using exact centered uniform sampling.
///
/// Each coefficient is sampled uniformly from `[-B_sm, B_sm]` directly into
/// RNS representation, as specified for the smudging noise in the trBFV
/// paper. The secret sampling path uses constant-time `u64`/`u128` limb
/// arithmetic only.
///
/// The generator records the configuration's party count alongside the BFV
/// parameters, and every noise owner it produces carries that binding so a
/// dealer ([`crate::trbfv::ShareManager::generate_smudging_shares`]) can
/// reject noise sampled for a different committee or parameter set.
#[derive(Debug)]
pub struct SmudgingNoiseGenerator {
    params: Arc<BfvParameters>,
    /// Party count the bound was computed for (`SmudgingConfig::n`); sampled
    /// noise is bound to it.
    parties: usize,
    smudging_bound: BigUint,
}

impl SmudgingNoiseGenerator {
    /// Calculate the bound and create a noise generator.
    ///
    /// Implements the trBFV security formula: `B_sm = 2^(lambda + 1) * d * B_C`
    /// (`d` = polynomial degree). The union bound over the `d` coefficients a
    /// single decryption reveals contributes the degree factor; the remaining
    /// factor `2` beyond `2^lambda` is conservative slack in the hiding
    /// policy, not a term of the correctness inequality (see issue #108).
    /// Subject to the strict correctness constraint
    /// `2 * (B_C + n * B_sm) < Delta` where `Delta = floor(Q / t)`.
    ///
    /// The initial ciphertext-noise bound is
    /// `B_C^(0) = m * (B_fresh + Q mod t)`: the configuration's upper bound
    /// on fresh ciphertexts added together before the modelled circuit, where
    /// each of the up-to-`m` summed terms contributes at most its own fresh
    /// decryption noise plus the plaintext-rounding term `Q mod t`. The
    /// per-term fresh-ciphertext noise bound `B_fresh` is selected by the
    /// configuration's [`FreshNoiseModel`](super::FreshNoiseModel): the model
    /// must describe the encryption path that actually produced the input
    /// ciphertexts (issue #250). Multiplicative depth then grows `B_C` with
    /// the Prop. 20 recursion, independently of the model.
    ///
    /// # Errors
    /// Returns error if:
    /// - Inputs are invalid (zero n/m, empty moduli, zero plaintext, zero variance)
    /// - The plaintext modulus does not fit in a `u64` (see
    ///   [`crate::ParametersError::UnsupportedPlaintextModulus`]); the
    ///   threshold bound arithmetic requires a machine-word plaintext modulus
    /// - `lambda` exceeds [`MAX_LAMBDA`]
    /// - `2 * B_C >= Delta` (circuit too deep or parameters too small)
    /// - `2 * (B_C + n * B_sm) >= Delta` (security requirement infeasible)
    pub fn new(config: SmudgingConfig) -> Result<Self, Error> {
        // --- Input validation ---
        if config.n == 0 {
            return Err(Error::smudging_bound_infeasible(
                "number of parties n must be positive",
            ));
        }
        if config.m == 0 {
            return Err(Error::smudging_bound_infeasible(
                "number of ciphertexts m must be positive",
            ));
        }
        let moduli = config.params.moduli();
        if moduli.is_empty() {
            return Err(Error::smudging_bound_infeasible("moduli slice is empty"));
        }
        // The bound arithmetic below (Delta and the Prop. 20 recursion) binds
        // the plaintext modulus to a machine word, so a plaintext modulus
        // larger than `u64` is rejected here, before any plaintext access or
        // bound computation — including for depth-zero circuits (issue #252).
        let t_u64 = config.params.plaintext.as_u64().ok_or_else(|| {
            Error::ParametersError(crate::ParametersError::UnsupportedPlaintextModulus {
                reason: "threshold BFV smudging bound requires a u64 plaintext modulus".to_string(),
            })
        })?;
        let t = BigUint::from(t_u64);
        if t == BigUint::from(0_u64) {
            return Err(Error::smudging_bound_infeasible(
                "plaintext modulus must be positive",
            ));
        }
        let error1_var = config.params.get_error1_variance();
        if error1_var == &BigUint::from(0_u64) {
            return Err(Error::smudging_bound_infeasible(
                "error1 variance must be positive",
            ));
        }

        let lambda = config.lambda;
        // Reject infeasible lambda before any large allocation.
        if lambda > MAX_LAMBDA {
            return Err(Error::smudging_bound_infeasible(format!(
                "lambda {lambda} exceeds maximum feasible value {MAX_LAMBDA}"
            )));
        }

        // --- Core computation ---
        let d = BigUint::from(config.params.degree());
        let variance = config.params.variance();
        let b_e = BigUint::from((2 * variance) as u64);

        // B_fresh from the caller-selected fresh-noise model:
        // BfvPublicKey:       d·1·‖e_ek‖ + B_enc + d·B_e·‖sk‖
        // LbfvPublicKey:      d·(2·variance)·‖e_ek‖ + B_enc + d·B_e·‖sk‖
        // BfvSecretKey:       B_e (no randomness u, single small error)
        // Custom:             the caller-justified bound itself
        let b_fresh = config.fresh_noise_bound()?;

        // Q = product of all moduli
        let q_full = modulus_product(moduli);

        // Delta = floor(Q / t) — exact plaintext scaling factor.
        let delta = compute_delta(&q_full, &t);

        // B_C^(0): noise of the sum of up to `m` fresh ciphertexts, where
        // `m` is the caller's worst pre-circuit addition fan-in.
        let b_c_additive = BigUint::from(config.m) * (&b_fresh + &q_full % &t);

        // B_C grows with multiplicative depth. Once the correctness inequality
        // fails, later rounds cannot restore it, so reject before growing an
        // unbounded BigUint for an infeasible caller-provided depth.
        let check_correctness = |b_c: &BigUint| -> Result<(), Error> {
            let two_b_c = b_c << 1usize;
            if two_b_c >= delta {
                return Err(Error::smudging_bound_infeasible(format!(
                    "2*B_C = {two_b_c} >= Delta = {delta}: circuit too deep or parameters too small"
                )));
            }
            Ok(())
        };
        check_correctness(&b_c_additive)?;

        // --- Multiplicative depth recursion (Prop. 20) ---
        //
        // B_C^{i+1} = 2·k·N²·‖sk‖ · B_C^{i} + B_relin
        //
        // where B_relin (Eq. 30) is computed with the aggregate RLK error
        // |S| * B_e to account for distributed relinearization key
        // contributions from all n parties. This is intentionally a
        // conservative bound when fewer relinearization shares are used.
        let b_c = if config.mult_depth > 0 {
            let l = BigUint::from(moduli.len());
            let b_g = BigUint::from(
                *moduli
                    .iter()
                    .max()
                    .ok_or_else(|| Error::smudging_bound_infeasible("moduli slice is empty"))?,
            );
            // Reuse the single validated machine-word plaintext modulus for
            // the recursion coefficient `k` (issue #252).
            let k = BigUint::from(t_u64);
            let n_sk = BigUint::from(config.n as u64);

            // Aggregate RLK error: |S| * B_e
            let aggregate_b_e = BigUint::from(config.n as u64) * &b_e;

            // Eq. (30) relinearization error bound with aggregate error.
            let b_relin = &d * &l * &n_sk * &b_g * &aggregate_b_e
                + BigUint::from(2_u32) * &d * &d * &l * &l * &n_sk * &n_sk * &b_g * &aggregate_b_e;

            // Prop. 20 coefficient.
            let coeff = BigUint::from(2_u32) * &k * &d * &d * &n_sk;
            let mut b = b_c_additive;
            for _ in 0..config.mult_depth {
                b = &coeff * &b + &b_relin;
                check_correctness(&b)?;
            }
            b
        } else {
            b_c_additive
        };

        // --- Compute B_sm = 2^(lambda + 1) * d * B_C
        //
        // Statistical-hiding argument (issue #108): the integer smudging
        // noise is uniform on `[-B_sm, B_sm]`, and one decryption reveals all
        // `d` (= degree) coefficients of that noise at once. Hiding two
        // honest noise shifts `x`, `y` with `|x|, |y| <= B_C` costs at most
        // `min(1, 2 * B_C / (2 * B_sm + 1))` total variation distance per
        // coefficient; the union bound over the `d` revealed coefficients
        // multiplies this by the degree factor `d`. The remaining factor `2`
        // beyond `2^lambda` is conservative slack in the policy, not a term
        // of the correctness inequality. For `B_C > 0` the resulting
        // single-transcript distance is numerically below `2^-(lambda + 1)`;
        // `lambda` itself stays a caller-selected policy.
        // Use BigUint shift to avoid usize → u32 truncation.
        // `lambda` was already validated against MAX_LAMBDA above.
        let two_pow_lambda_plus_one = BigUint::from(1_u64) << (lambda + 1);
        let b_sm = two_pow_lambda_plus_one * &d * &b_c;

        // --- Strict correctness: 2 * (B_C + n * B_sm) < Delta ---
        let lhs = BigUint::from(2_u64) * (&b_c + BigUint::from(config.n) * &b_sm);
        if lhs >= delta {
            return Err(Error::smudging_bound_infeasible(format!(
                "strict inequality 2*(B_C + n*B_sm) = {lhs} >= Delta = {delta}: \
                 security lower bound exceeds correctness budget"
            )));
        }

        Ok(Self {
            params: config.params,
            parties: config.n,
            smudging_bound: b_sm,
        })
    }
}

/// Little-endian limb comparison: returns whether `a < b` in constant time.
///
/// The comparison walks every limb and never returns early: bailing out at
/// the first differing limb would leak the position of that limb, and with
/// it the top bits of the secret candidate, through timing. Instead each
/// limb is folded into a branch-free decision, so the running time depends
/// only on the (public) limb count. Both slices must have the same length.
fn limbs_lt(a: &[u64], b: &[u64]) -> bool {
    debug_assert_eq!(a.len(), b.len(), "limb comparison requires equal lengths");
    // Decision state: 0 = no difference seen yet, 1 = a < b, 2 = a > b.
    // `u64` comparisons compile to branchless flag instructions, and the
    // mask stops limbs after the first difference from changing the
    // decision, so the loop always scans all limbs.
    let mut decision = 0u64;
    for (ai, bi) in a.iter().zip(b).rev() {
        let step = ((ai < bi) as u64) | (((ai > bi) as u64) << 1);
        let undecided = ((decision == 0) as u64).wrapping_neg();
        decision |= undecided & step;
    }
    decision == 1
}

/// Reduce a little-endian limb value modulo `qi` in constant time.
///
/// Each step folds one 64-bit limb into an accumulator below `qi < 2^62`
/// and reduces the resulting 128-bit window with the modulus' Barrett
/// reduction. A hardware `u128 % u128` would compile to a `__umodti3` call
/// whose running time depends on the secret value being reduced. Requires
/// `qi <= 2^62` (all RNS moduli are NTT-compatible 62-bit primes); an
/// empty limb slice reduces to zero.
fn limbs_mod(limbs: &[u64], qi: &Modulus) -> u64 {
    let mut acc = 0u64;
    for &limb in limbs.iter().rev() {
        acc = qi.reduce_u128((u128::from(acc) << 64) | u128::from(limb));
    }
    acc
}

/// Freshly sampled smudging noise with private wipe-on-drop storage.
///
/// The underlying polynomial is private and the owner is consumed by the
/// smudging dealing operation
/// ([`ShareManager::generate_smudging_shares`](crate::trbfv::ShareManager::generate_smudging_shares)).
/// There is intentionally no `Clone`, `Copy`, coefficient accessor, or
/// generic serialization: duplicating one-time noise across decryptions
/// breaks the statistical hiding argument.
///
/// The owner also carries the binding of the generator that sampled it: the
/// party count and the complete BFV parameter set. The dealing operation
/// verifies this binding before accepting the noise, and the metadata is
/// unreachable from outside the crate, so it cannot be mutated to make
/// foreign noise look legitimate.
///
/// ```compile_fail
/// # use fhe::trbfv::{ShareManager, SmudgingNoise};
/// fn duplicate(noise: &SmudgingNoise) -> SmudgingNoise {
///     noise.clone()
/// }
/// ```
///
/// ```compile_fail
/// # use fhe::bfv::BfvParameters;
/// # use fhe::trbfv::SmudgingNoise;
/// # use std::sync::Arc;
/// fn read_binding(noise: &SmudgingNoise) -> (usize, Arc<BfvParameters>) {
///     (noise.parties, Arc::clone(&noise.params))
/// }
/// ```
pub struct SmudgingNoise {
    /// Party count of the generator that sampled this noise; a dealer
    /// rejects noise sized for a different committee.
    parties: usize,
    /// Complete BFV parameter set the noise was sampled under; a dealer
    /// rejects noise whose parameters differ in any value, including the
    /// plaintext modulus, ciphertext moduli, and error variances.
    params: Arc<BfvParameters>,
    poly: Zeroizing<Poly<PowerBasis>>,
}

impl SmudgingNoise {
    /// Consume the owner and release the noise polynomial.
    ///
    /// Crate-private so the supported dealing operation is the only consumer;
    /// external code cannot extract a reusable raw polynomial.
    pub(crate) fn into_poly(self) -> Zeroizing<Poly<PowerBasis>> {
        self.poly
    }

    /// Verify this owner was sampled for the dealer's party count and exact
    /// BFV parameters.
    ///
    /// Crate-private so the supported dealing operation
    /// ([`ShareManager::generate_smudging_shares`]) can run it at the dealing
    /// boundary, before the polynomial is extracted or any randomness is
    /// consumed. Party counts are compared exactly; parameters take the
    /// `Arc` pointer-equality fast path and then compare by value, so
    /// independently built but equivalent configurations are accepted while
    /// any differing field is rejected. The noise itself stays private under
    /// this wipe-on-drop owner either way.
    pub(crate) fn validate_dealer_binding(
        &self,
        dealer_parties: usize,
        dealer_params: &Arc<BfvParameters>,
    ) -> Result<(), Error> {
        if self.parties != dealer_parties {
            return Err(Error::smudging_noise_party_count_mismatch(
                self.parties,
                dealer_parties,
            ));
        }
        if !Arc::ptr_eq(&self.params, dealer_params) && self.params != *dealer_params {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::SmudgingNoise,
                right: crate::ParameterSource::Parameters,
            });
        }
        Ok(())
    }
}

impl fmt::Debug for SmudgingNoise {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmudgingNoise")
            .finish_non_exhaustive()
    }
}

/// Wipe-on-drop guard for the sampled smudging matrix.
///
/// The matrix holds secret-dependent residues from the first written cell,
/// so it is guarded from the moment it is allocated. Dropping the guard while
/// it owns the matrix (including an unwind mid-sampling) zeroizes each element,
/// even for non-standard layouts. On success, the matrix is transferred into
/// a guarded noise polynomial instead; the empty guard then drops.
struct GuardedMatrix {
    values: Array2<u64>,
    /// A local test can observe this guard's drop without instrumenting the
    /// generator or inspecting freed memory.
    #[cfg(test)]
    wipe_observer: Option<Arc<AtomicBool>>,
}

impl GuardedMatrix {
    fn zeros(shape: (usize, usize)) -> Self {
        Self {
            values: Array2::zeros(shape),
            #[cfg(test)]
            wipe_observer: None,
        }
    }

    /// One RNS column of the matrix, for writing one coefficient's residues.
    fn column_mut(&mut self, column: usize) -> ArrayViewMut1<'_, u64> {
        self.values.column_mut(column)
    }

    /// Transfers the completed matrix into `Poly::set_coefficients`.
    ///
    /// Callee ownership semantics: on success the coefficients move into the
    /// polynomial, which the caller keeps under a zeroizing owner; on a
    /// validation rejection the callee zeroizes every element of the rejected
    /// matrix before it is dropped. The by-value move below is the only
    /// instant the matrix is outside this guard. Honest limitation: a panic
    /// raised by the callee itself between receiving the matrix and running
    /// its validation zeroization would drop the matrix unwiped; no such
    /// panic source is known, but this transfer cannot promise safety
    /// against one.
    fn release_for_install(&mut self) -> Array2<u64> {
        std::mem::take(&mut self.values)
    }
}

impl Drop for GuardedMatrix {
    fn drop(&mut self) {
        #[cfg(test)]
        let had_data = self.wipe_observer.is_some() && self.values.iter().any(|&value| value != 0);
        self.values.iter_mut().for_each(|value| value.zeroize());
        #[cfg(test)]
        if let Some(observer) = &self.wipe_observer {
            observer.store(
                had_data && self.values.iter().all(|&value| value == 0),
                Ordering::SeqCst,
            );
        }
    }
}

impl SmudgingNoiseGenerator {
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
    /// The secret-dependent arithmetic is constant-time: the rejection
    /// comparison is branch-free, reductions use the modulus' Barrett
    /// reduction instead of `u128` division, and the centered subtraction is
    /// a constant-time modular addition. The rejection loop count depends
    /// only on the RNG stream, never on the accepted values.
    ///
    /// # Returns
    /// A non-cloneable owner of the sampled noise polynomial, consumed by
    /// the smudging dealing operation. The owner records this generator's
    /// party count and BFV parameters so the dealing operation can reject
    /// noise sampled for a different committee or configuration.
    pub fn generate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<SmudgingNoise, Error> {
        let ctx = self.params.context_at_level(0)?;
        let degree = self.params.degree();
        // Constant-time Barrett reduction operators, one per RNS modulus in
        // the same order as `self.params.moduli()`.
        let moduli = ctx.moduli_operators();
        if self.smudging_bound == BigUint::from(0u64) {
            return Ok(SmudgingNoise {
                parties: self.parties,
                params: Arc::clone(&self.params),
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
            .map(|qi| limbs_mod(&bound_limbs, qi))
            .collect();

        // An aborted sampling run never publishes or reuses this matrix: it
        // is guarded from allocation, so a panic unwind mid-sampling wipes
        // every already-written cell.
        let mut matrix = GuardedMatrix::zeros((moduli.len(), degree));
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
            for (cell, (qi, &bound_qi)) in matrix
                .column_mut(col)
                .iter_mut()
                .zip(moduli.iter().zip(&bound_mod))
            {
                let u_mod = limbs_mod(&candidate, qi);
                // (u - B_sm) mod qi as a constant-time modular negation and
                // addition: `neg` turns `-B_sm mod qi` into a canonical
                // residue and `add` performs the wrap-around conditional
                // subtraction itself, so no branch depends on the secret
                // residues. Both operands stay in [0, qi).
                *cell = qi.add(u_mod, qi.neg(bound_qi));
            }
            // Wipe the consumed candidate limbs.
            candidate.as_mut_slice().zeroize();
        }
        // Build the noise polynomial directly rather than through
        // `from_coeffs_matrix`. The polynomial is guarded before the secret
        // matrix is installed, and this guard itself is transferred into the
        // returned noise owner, so a failure after installation cannot drop
        // the secret polynomial unguarded. The matrix moves out of its guard
        // only for this call (see `release_for_install`).
        let mut poly = Zeroizing::new(Poly::<PowerBasis>::zero(ctx));
        poly.as_mut()
            .set_coefficients(matrix.release_for_install())?;
        Ok(SmudgingNoise {
            parties: self.parties,
            params: Arc::clone(&self.params),
            poly,
        })
    }

    /// Get the smudging variance.
    #[must_use]
    pub fn smudging_bound(&self) -> &BigUint {
        &self.smudging_bound
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests use fixed validated dimensions and simulate RNG failures"
)]
mod tests {
    use super::*;
    use crate::bfv::BfvParametersBuilder;
    use crate::support::presets::{insecure, secure8192};
    use crate::trbfv::smudging::{FreshNoiseModel, bound::compute_b_enc};
    use num_bigint::BigInt;
    use num_traits::{ToPrimitive, Zero};
    use rand::{RngCore, SeedableRng, rng};
    use rand_chacha::ChaCha8Rng;
    use std::str::FromStr;
    use std::sync::Arc;

    fn small_params(modulus_sizes: &[usize]) -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(2)
            .set_moduli_sizes(modulus_sizes)
            .build_arc()
            .unwrap()
    }

    fn generator_with_bound(params: Arc<BfvParameters>, bound: BigUint) -> SmudgingNoiseGenerator {
        SmudgingNoiseGenerator {
            params,
            parties: 1,
            smudging_bound: bound,
        }
    }

    fn modinv_u64(a: u64, m: u64) -> u64 {
        let (mut t, mut new_t) = (0i128, 1i128);
        let (mut r, mut new_r) = (m as i128, a as i128);
        while new_r != 0 {
            let quotient = r / new_r;
            (t, new_t) = (new_t, t - quotient * new_t);
            (r, new_r) = (new_r, r - quotient * new_r);
        }
        assert_eq!(r, 1, "modular inverse does not exist");
        t.rem_euclid(m as i128) as u64
    }

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

    fn assert_noise_in_bound(noise: SmudgingNoise, bound: &BigUint, params: &Arc<BfvParameters>) {
        let poly = noise.into_poly();
        let moduli = params.moduli();
        assert_eq!(poly.coefficients().dim(), (moduli.len(), params.degree()));
        let neg_bound = -BigInt::from(bound.clone());
        let pos_bound = BigInt::from(bound.clone());
        for col in 0..params.degree() {
            let residues: Vec<u64> = (0..moduli.len())
                .map(|row| poly.coefficients()[[row, col]])
                .collect();
            let x = crt_centered_integer(&residues, moduli);
            assert!(x >= neg_bound && x <= pos_bound, "sample {x} outside bound");
        }
    }

    #[test]
    fn b_enc_matches_cbd_boundary() {
        assert_eq!(
            compute_b_enc(&BigUint::from(16u32)).unwrap(),
            BigUint::from(32u32)
        );
    }

    #[test]
    fn b_enc_uniform_branch_uses_minimal_bound() {
        let variance = BigUint::from(20u32);
        assert_eq!(compute_b_enc(&variance).unwrap(), BigUint::from(8u32));
    }

    #[test]
    fn b_enc_large_biguint_uses_uniform_branch() {
        let variance = BigUint::from_str("340282366920938463463374607431768211456").unwrap();
        let mut expected = (BigUint::from(3u32) * &variance).sqrt();
        while &expected * (&expected + 1u32) < BigUint::from(3u32) * &variance {
            expected += 1u32;
        }
        assert_eq!(compute_b_enc(&variance).unwrap(), expected);
    }

    /// Issue #255: the circuit size `m` is the worst fan-in of
    /// fresh-ciphertext additions performed *before* the modelled circuit,
    /// not a count of outputs or independent decryptions. A circuit with no
    /// pre-sum (a single fresh ciphertext, or a pure product of fresh
    /// ciphertexts) uses `m = 1`; the mixed circuit `(a + b) * c` uses
    /// `m = 2` because its left branch sums two fresh ciphertexts.
    #[test]
    fn circuit_size_records_pre_sum_fan_in() {
        let params = small_params(&[62, 62, 62]);

        // No pre-sum: `a * b * c` feeds three fresh ciphertexts into pure
        // multiplications, so the tight circuit size is still `m = 1`.
        let no_pre_sum =
            SmudgingConfig::new(params.clone(), 3, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap();
        assert_eq!((no_pre_sum.m(), no_pre_sum.n()), (1, 3));

        // `(a + b) * c`: the left branch sums two fresh ciphertexts, so the
        // worst pre-multiplication fan-in is `m = 2` even though the circuit
        // has one output.
        let mixed = SmudgingConfig::new(params, 3, 2, 2, FreshNoiseModel::BfvPublicKey).unwrap();
        assert_eq!((mixed.m(), mixed.n(), mixed.lambda()), (2, 3, 2));

        // Overprovisioning `m` only inflates the bound: it never shrinks the
        // smudging noise, so a conservative choice stays safe.
        let bound_one = SmudgingNoiseGenerator::new(no_pre_sum)
            .unwrap()
            .smudging_bound()
            .clone();
        let bound_two = SmudgingNoiseGenerator::new(mixed)
            .unwrap()
            .smudging_bound()
            .clone();
        assert!(bound_two > bound_one);
    }

    #[test]
    fn config_validates_basic_inputs() {
        let params = secure8192().unwrap().parameters;
        assert!(
            SmudgingConfig::new(params.clone(), 0, 1, 2, FreshNoiseModel::BfvPublicKey).is_err()
        );
        assert!(
            SmudgingConfig::new(params.clone(), 1, 0, 2, FreshNoiseModel::BfvPublicKey).is_err()
        );
        assert!(
            SmudgingConfig::new(
                params.clone(),
                1,
                1,
                MAX_LAMBDA + 1,
                FreshNoiseModel::BfvPublicKey
            )
            .is_err()
        );
        assert!(
            SmudgingConfig::new(
                params.clone(),
                1,
                1,
                2,
                FreshNoiseModel::Custom(BigUint::from(0_u64))
            )
            .is_err()
        );

        let config = SmudgingConfig::new(params.clone(), 3, 2, 40, FreshNoiseModel::BfvPublicKey)
            .unwrap()
            .with_mult_depth(1);
        assert!(Arc::ptr_eq(config.params(), &params));
        assert_eq!((config.n(), config.m(), config.lambda()), (3, 2, 40));
        assert_eq!(config.mult_depth(), 1);
        assert_eq!(config.model(), &FreshNoiseModel::BfvPublicKey);
    }

    #[test]
    fn generator_revalidates_internally_corrupted_config() {
        let params = secure8192().unwrap().parameters;
        let mut config =
            SmudgingConfig::new(params.clone(), 1, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap();
        config.n = 0;
        assert!(SmudgingNoiseGenerator::new(config).is_err());

        let mut config =
            SmudgingConfig::new(params.clone(), 1, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap();
        config.m = 0;
        assert!(SmudgingNoiseGenerator::new(config).is_err());

        // A zero custom bound invalidated after construction is rejected the
        // same way, so corruption cannot sneak an empty fresh-noise bound in.
        let mut config = SmudgingConfig::new(
            params,
            1,
            1,
            2,
            FreshNoiseModel::Custom(BigUint::from(1234_u64)),
        )
        .unwrap();
        config.model = FreshNoiseModel::Custom(BigUint::from(0_u64));
        assert!(matches!(
            SmudgingNoiseGenerator::new(config),
            Err(Error::Threshold(
                crate::ThresholdError::SmudgingBoundInfeasible { .. }
            ))
        ));
    }
    #[test]
    fn delta_is_q_div_t_floor() {
        let params = secure8192().unwrap().parameters;
        let q = modulus_product(params.moduli());
        let t = BigUint::from(params.plaintext());
        let delta = compute_delta(&q, &t);
        assert_eq!(delta, &q / &t);
        assert!(delta > &q / (BigUint::from(2_u64) * &t));
    }

    #[test]
    fn strict_inequality_rejects_infeasible_configuration() {
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(2)
            .set_moduli(&[65537])
            .set_error1_variance_usize(1)
            .build_arc()
            .unwrap();
        let config = SmudgingConfig::new(params, 1, 1, 5, FreshNoiseModel::BfvPublicKey).unwrap();
        let error = SmudgingNoiseGenerator::new(config).unwrap_err();
        assert!(error.to_string().contains("strict inequality"));
    }

    #[test]
    fn lambda_at_max_is_not_truncated() {
        let config = SmudgingConfig::new(
            secure8192().unwrap().parameters,
            1,
            1,
            MAX_LAMBDA,
            FreshNoiseModel::BfvPublicKey,
        )
        .unwrap();
        if let Ok(generator) = SmudgingNoiseGenerator::new(config) {
            assert!(generator.smudging_bound().bits() as usize > MAX_LAMBDA);
        }
    }

    #[test]
    fn test_smudging_noise_generator_creation() {
        let params = secure8192().unwrap().parameters;
        let config =
            SmudgingConfig::new(params.clone(), 3, 1, 35, FreshNoiseModel::BfvPublicKey).unwrap();
        let generator = SmudgingNoiseGenerator::new(config).unwrap();
        assert_eq!(generator.params, params);
        assert_eq!(generator.parties, 3);
        assert!(generator.smudging_bound() > &BigUint::zero());
    }

    #[test]
    fn noise_owner_carries_generator_binding() {
        let mut rng = rng();
        let params = secure8192().unwrap().parameters;

        // The ordinary sampled-bound branch records the configuration.
        let generator = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params.clone(), 3, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap(),
        )
        .unwrap();
        let noise = generator.generate(&mut rng).unwrap();
        assert_eq!(noise.parties, 3);
        assert!(Arc::ptr_eq(&noise.params, &params));

        // The zero-bound branch records the same metadata.
        let zero_generator = generator_with_bound(params.clone(), BigUint::zero());
        let zero_noise = zero_generator.generate(&mut rng).unwrap();
        assert_eq!(zero_noise.parties, 1);
        assert!(Arc::ptr_eq(&zero_noise.params, &params));
    }

    #[test]
    fn dealer_binding_checks_are_exact() {
        let params = small_params(&[62, 62, 62]);
        let generator = generator_with_bound(params.clone(), BigUint::from(1000u64));
        let noise = generator.generate(&mut rng()).unwrap();

        // A matched dealer binding is accepted.
        noise.validate_dealer_binding(1, &params).unwrap();

        // A different party count with identical parameters is rejected.
        assert!(matches!(
            noise.validate_dealer_binding(5, &params),
            Err(Error::Threshold(
                crate::ThresholdError::SmudgingNoisePartyCountMismatch {
                    noise_parties: 1,
                    dealer_parties: 5
                }
            ))
        ));

        // The same ring but a different plaintext modulus is rejected with
        // the mismatch attributed to the noise owner's binding.
        let other_plaintext = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(5)
            .set_moduli_sizes(&[62, 62, 62])
            .build_arc()
            .unwrap();
        assert!(matches!(
            noise.validate_dealer_binding(1, &other_plaintext),
            Err(Error::ParameterMismatch {
                left: crate::ParameterSource::SmudgingNoise,
                right: crate::ParameterSource::Parameters,
            })
        ));

        // Independently built but equivalent parameters are accepted.
        let rebuilt = small_params(&[62, 62, 62]);
        assert!(!Arc::ptr_eq(&params, &rebuilt));
        noise.validate_dealer_binding(1, &rebuilt).unwrap();
    }

    #[test]
    fn test_noise_generation_small_bound() {
        let mut rng = rng();
        let params = secure8192().unwrap().parameters;
        let bound = BigUint::from(1000u64);
        let generator = generator_with_bound(params.clone(), bound.clone());
        let noise = generator.generate(&mut rng).unwrap();
        assert_noise_in_bound(noise, &bound, &params);
    }

    #[test]
    fn test_noise_generation_zero_bound() {
        let mut rng = rng();
        let params = secure8192().unwrap().parameters;
        let generator = generator_with_bound(params.clone(), BigUint::zero());
        let poly = generator.generate(&mut rng).unwrap().into_poly();
        assert!(poly.coefficients().iter().all(|&c| c == 0));
    }

    /// An RNG that returns a fixed nonzero candidate limb and panics after a
    /// fixed number of draws, simulating a mid-sampling RNG failure.
    struct PanickingAfterDraws {
        draws: usize,
        fail_after: usize,
    }

    impl RngCore for PanickingAfterDraws {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.draws += 1;
            #[expect(
                clippy::panic,
                reason = "test-only RNG simulating a mid-sampling RNG failure"
            )]
            if self.draws > self.fail_after {
                panic!("simulated RNG failure after earlier matrix columns were sampled");
            }
            // With the small bound used below, each accepted candidate is one
            // limb, so every written residue derives from this fixed value
            // and is nonzero (1729 - 1000 = 729 modulo each modulus).
            1729
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    impl CryptoRng for PanickingAfterDraws {}

    /// Exercise the real sampling loop with a failing RNG. The guard's
    /// drop-time wipe is checked separately below without observing freed
    /// storage from inside the generator.
    #[test]
    fn generation_unwinds_with_partially_sampled_matrix() {
        let generator = generator_with_bound(small_params(&[62, 62, 62]), BigUint::from(1000u64));
        let mut failing = PanickingAfterDraws {
            draws: 0,
            fail_after: 3,
        };

        // Each accepted draw writes one nonzero column (1729 - 1000 = 729).
        // The fourth draw panics after three columns have been written.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            generator.generate(&mut failing)
        }));
        assert!(result.is_err());
        assert_eq!(failing.draws, 4);
    }

    /// A test-local hook on the private matrix guard checks that its actual
    /// unwind drop sees nonzero residues and zeros them, for both contiguous
    /// and transposed storage. Removing the guard's wipe makes this fail.
    #[test]
    fn sampling_matrix_guard_wipes_on_unwind() {
        for transposed in [false, true] {
            let wiped = Arc::new(AtomicBool::new(false));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut matrix = GuardedMatrix::zeros((3, 8));
                if transposed {
                    matrix.values = Array2::zeros((8, 3)).reversed_axes();
                }
                matrix.wipe_observer = Some(Arc::clone(&wiped));
                matrix.column_mut(0).fill(729);
                panic!("simulated unwind while the sampled matrix is guarded");
            }));
            assert!(result.is_err());
            assert!(wiped.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn generation_installs_nonzero_noise_in_guarded_polynomial() {
        let params = small_params(&[62, 62, 62]);
        let generator = generator_with_bound(params.clone(), BigUint::from(1000u64));
        let noise = generator
            .generate(&mut ChaCha8Rng::seed_from_u64(172_109))
            .unwrap();
        let poly = noise.into_poly();
        assert_eq!(
            poly.coefficients().dim(),
            (params.moduli().len(), params.degree())
        );
        assert!(poly.coefficients().iter().any(|&value| value != 0));
    }

    #[test]
    fn limbs_lt_compares_without_early_exit() {
        let cases = [
            (vec![0u64], vec![0u64], false),
            (vec![0], vec![1], true),
            (vec![1], vec![0], false),
            (vec![u64::MAX], vec![0], false),
            (vec![0], vec![u64::MAX], true),
            (vec![u64::MAX, 5], vec![0, 5], false),
            (vec![0, 5], vec![u64::MAX, 5], true),
        ];
        for (a, b, expected) in cases {
            assert_eq!(limbs_lt(&a, &b), expected);
        }
        let mut rng = ChaCha8Rng::seed_from_u64(172_107);
        for _ in 0..512 {
            let a: Vec<u64> = (0..3).map(|_| rng.next_u64()).collect();
            let b: Vec<u64> = (0..3).map(|_| rng.next_u64()).collect();
            assert_eq!(
                limbs_lt(&a, &b),
                biguint_from_limbs(&a) < biguint_from_limbs(&b)
            );
        }
    }

    fn biguint_from_limbs(limbs: &[u64]) -> BigUint {
        limbs.iter().rev().fold(BigUint::zero(), |acc, &limb| {
            (acc << 64usize) | BigUint::from(limb)
        })
    }

    #[test]
    fn limbs_mod_matches_biguint_oracle() {
        for qi in [11u64, 1153, 0x1ffffffea0001] {
            let modulus = Modulus::new(qi).unwrap();
            assert_eq!(limbs_mod(&[], &modulus), 0);
            let mut rng = ChaCha8Rng::seed_from_u64(172_108);
            for _ in 0..256 {
                let nlimbs = 1 + (rng.next_u64() % 4) as usize;
                let limbs: Vec<u64> = (0..nlimbs).map(|_| rng.next_u64()).collect();
                assert_eq!(
                    limbs_mod(&limbs, &modulus),
                    (biguint_from_limbs(&limbs) % BigUint::from(qi))
                        .to_u64()
                        .unwrap()
                );
            }
        }
    }

    #[test]
    fn test_noise_limb_boundaries_match_oracle() {
        let params = small_params(&[62, 62, 62]);
        let mut rng = ChaCha8Rng::seed_from_u64(172_103);
        let bounds = [
            (BigUint::from(1u32) << 63) - BigUint::from(1u32),
            BigUint::from(1u32) << 63,
            BigUint::from(u64::MAX),
            (BigUint::from(1u32) << 100) + BigUint::from(12345u32),
        ];
        for bound in &bounds {
            let generator = generator_with_bound(params.clone(), bound.clone());
            assert_noise_in_bound(generator.generate(&mut rng).unwrap(), bound, &params);
        }
    }

    #[test]
    fn test_noise_wide_bound_beyond_five_limbs() {
        let params = small_params(&[62, 62, 62, 62, 62, 62]);
        let mut rng = ChaCha8Rng::seed_from_u64(172_104);
        let bound: BigUint = BigUint::from(1u32) << 320;
        let generator = generator_with_bound(params.clone(), bound.clone());
        assert_noise_in_bound(generator.generate(&mut rng).unwrap(), &bound, &params);
    }

    #[test]
    fn test_multiplicative_depth_increases_bound() {
        let params = BfvParametersBuilder::new()
            .set_degree(8192)
            .set_plaintext_modulus(16384)
            .set_moduli_sizes(&[62, 62, 62, 62, 62, 62])
            .build_arc()
            .unwrap();
        let additive =
            SmudgingConfig::new(params.clone(), 3, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap();
        let depth_one = additive.clone().with_mult_depth(1);
        let bound_add = SmudgingNoiseGenerator::new(additive)
            .unwrap()
            .smudging_bound()
            .clone();
        let bound_mul = SmudgingNoiseGenerator::new(depth_one)
            .unwrap()
            .smudging_bound()
            .clone();
        assert!(bound_mul > bound_add);
    }

    #[test]
    fn infeasible_depth_returns_before_unbounded_recursion() {
        let params = small_params(&[62, 62, 62]);
        let config =
            SmudgingConfig::new(params.clone(), 3, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap();
        assert!(SmudgingNoiseGenerator::new(config.clone().with_mult_depth(1)).is_ok());

        let error = SmudgingNoiseGenerator::new(config.with_mult_depth(u32::MAX)).unwrap_err();
        assert!(matches!(
            error,
            Error::Threshold(crate::ThresholdError::SmudgingBoundInfeasible { reason })
                if reason.contains(">= Delta")
        ));

        let additive_infeasible =
            SmudgingConfig::new(params, 3, usize::MAX, 2, FreshNoiseModel::BfvPublicKey).unwrap();
        assert!(matches!(
            SmudgingNoiseGenerator::new(additive_infeasible.with_mult_depth(u32::MAX)),
            Err(Error::Threshold(
                crate::ThresholdError::SmudgingBoundInfeasible { .. }
            ))
        ));
    }

    #[test]
    fn smudging_bound_monotonicity() {
        let params = secure8192().unwrap().parameters;
        let b1 = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params.clone(), 3, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap(),
        )
        .unwrap()
        .smudging_bound()
        .clone();
        let b2 = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params.clone(), 3, 2, 2, FreshNoiseModel::BfvPublicKey).unwrap(),
        )
        .unwrap()
        .smudging_bound()
        .clone();
        let b3 = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params, 3, 1, 10, FreshNoiseModel::BfvPublicKey).unwrap(),
        )
        .unwrap()
        .smudging_bound()
        .clone();
        assert!(b2 >= b1);
        assert!(b3 > b1);
    }

    /// Independently derive the smudging bound for a model from the documented
    /// per-path formula `B_fresh = d·u·e_pk + B_enc + d·B_e·‖sk‖` and the
    /// `B_C`/`B_sm` pipeline, for use as a regression oracle.
    fn expected_bound(
        params: &Arc<BfvParameters>,
        n: usize,
        m: usize,
        lambda: usize,
        u_bound: &BigUint,
    ) -> BigUint {
        let d = BigUint::from(params.degree());
        let b_e = BigUint::from((2 * params.variance()) as u64);
        let b_enc = compute_b_enc(params.get_error1_variance()).unwrap();
        let e_pk = BigUint::from(n) * &b_e;
        let sk_bound = BigUint::from(n);
        let b_fresh = &d * u_bound * &e_pk + b_enc + &d * &b_e * &sk_bound;
        let q = modulus_product(params.moduli());
        let t = BigUint::from(params.plaintext());
        let b_c = BigUint::from(m) * (&b_fresh + &q % &t);
        (BigUint::from(1_u64) << (lambda + 1)) * &d * &b_c
    }

    /// Issue #250 at depth zero: the l-BFV public-key path samples `u` with
    /// `Poly::small(variance)` (support `2 * variance`), so its bound must be
    /// strictly larger than the ternary BFV public-key bound, and both must
    /// match the documented formula exactly.
    #[test]
    fn bfv_vs_lbfv_public_key_depth0_bound_difference() {
        let preset = insecure().unwrap();
        let params = preset.parameters;
        let (n, m, lambda) = (preset.num_parties, preset.max_ciphertexts, preset.lambda);

        let bound_bfv = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params.clone(), n, m, lambda, FreshNoiseModel::BfvPublicKey)
                .unwrap(),
        )
        .unwrap()
        .smudging_bound()
        .clone();
        let bound_lbfv = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params.clone(), n, m, lambda, FreshNoiseModel::LbfvPublicKey)
                .unwrap(),
        )
        .unwrap()
        .smudging_bound()
        .clone();

        let ternary = BigUint::from(1_u64);
        let cbd = BigUint::from((2 * params.variance()) as u64);
        assert_eq!(bound_bfv, expected_bound(&params, n, m, lambda, &ternary));
        assert_eq!(bound_lbfv, expected_bound(&params, n, m, lambda, &cbd));

        // The u-support difference alone is material at depth 0 for this
        // preset's arithmetic: the review of issue #250 estimated a ~2.9x
        // fresh-bound underestimate.
        assert!(
            bound_lbfv > BigUint::from(2_u32) * &bound_bfv,
            "l-BFV bound {bound_lbfv} must exceed 2x the BFV bound {bound_bfv}"
        );
    }

    /// At depth > 0 the model difference propagates through the Prop. 20
    /// recursion: because the recursion is affine, the gap between the two
    /// models' bounds grows by exactly the recursion coefficient per level.
    #[test]
    fn depth_recursion_amplifies_model_difference() {
        let preset = insecure().unwrap();
        let params = preset.parameters;
        let (n, m, lambda) = (preset.num_parties, preset.max_ciphertexts, preset.lambda);

        let bound = |depth: u32, model: FreshNoiseModel| {
            SmudgingNoiseGenerator::new(
                SmudgingConfig::new(params.clone(), n, m, lambda, model)
                    .unwrap()
                    .with_mult_depth(depth),
            )
            .unwrap()
            .smudging_bound()
            .clone()
        };
        let bound0_bfv = bound(0, FreshNoiseModel::BfvPublicKey);
        let bound0_lbfv = bound(0, FreshNoiseModel::LbfvPublicKey);
        let bound1_bfv = bound(1, FreshNoiseModel::BfvPublicKey);
        let bound1_lbfv = bound(1, FreshNoiseModel::LbfvPublicKey);

        let diff0 = &bound0_lbfv - &bound0_bfv;
        let diff1 = &bound1_lbfv - &bound1_bfv;
        assert!(diff0 > BigUint::zero());
        assert!(diff1 > diff0, "depth must amplify the model difference");

        // Prop. 20: B_C^{i+1} = 2·t·d²·n·B_C^{i} + B_relin, and B_sm = 2^(lambda+1)·d·B_C
        // with a model-independent constant, so differences scale exactly by
        // the recursion coefficient.
        let coeff = BigUint::from(2_u32)
            * BigUint::from(params.plaintext())
            * BigUint::from(params.degree())
            * BigUint::from(params.degree())
            * BigUint::from(n as u64);
        assert_eq!(diff1, &coeff * &diff0);
    }

    /// The `Custom` model is used verbatim: the library neither widens nor
    /// shrinks a caller-justified bound, so an understated bound silently
    /// shrinks `B_sm` (the caller owns the justification).
    #[test]
    fn custom_bound_is_used_verbatim() {
        let params = small_params(&[62, 62, 62]);
        let (n, m, lambda) = (2usize, 1usize, 1usize);
        let custom = BigUint::from(123_456_u64);

        let config = SmudgingConfig::new(
            params.clone(),
            n,
            m,
            lambda,
            FreshNoiseModel::Custom(custom.clone()),
        )
        .unwrap();
        assert_eq!(config.model(), &FreshNoiseModel::Custom(custom.clone()));
        let bound = SmudgingNoiseGenerator::new(config)
            .unwrap()
            .smudging_bound()
            .clone();

        let d = BigUint::from(params.degree());
        let q = modulus_product(params.moduli());
        let t = BigUint::from(params.plaintext());
        let b_c = BigUint::from(m) * (&custom + &q % &t);
        assert_eq!(bound, (BigUint::from(1_u64) << (lambda + 1)) * &d * &b_c);

        // A small custom bound is honored even when every library path would
        // produce a larger fresh-noise bound: there is no silent widening.
        let small = BigUint::from(64_u64);
        let bound_small = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params.clone(), n, m, lambda, FreshNoiseModel::Custom(small))
                .unwrap(),
        )
        .unwrap()
        .smudging_bound()
        .clone();
        let ternary = BigUint::from(1_u64);
        let bfv_bound = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params.clone(), n, m, lambda, FreshNoiseModel::BfvPublicKey)
                .unwrap(),
        )
        .unwrap()
        .smudging_bound()
        .clone();
        assert!(bound_small < bfv_bound);
        assert_eq!(bfv_bound, expected_bound(&params, n, m, lambda, &ternary));
    }

    /// A zero custom bound cannot hide any real ciphertext's noise and is
    /// rejected at configuration time.
    #[test]
    fn custom_zero_bound_is_rejected() {
        let params = small_params(&[62, 62, 62]);
        let error = SmudgingConfig::new(
            params,
            1,
            1,
            2,
            FreshNoiseModel::Custom(BigUint::from(0_u64)),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("custom fresh-noise bound must be positive")
        );
    }

    /// Secret-key encryption samples no randomness `u`: the fresh phase noise
    /// is the single small error, so `B_fresh = 2 * variance` and the bound is
    /// strictly smaller than either public-key model at the same parameters.
    #[test]
    fn secret_key_model_uses_direct_small_error() {
        let params = small_params(&[62, 62, 62]);
        let (n, m, lambda) = (3usize, 1usize, 1usize);
        let variance = params.variance() as u64;

        let bound_sk = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params.clone(), n, m, lambda, FreshNoiseModel::BfvSecretKey)
                .unwrap(),
        )
        .unwrap()
        .smudging_bound()
        .clone();

        // B_sm = 2^(lambda+1) · d · m · (2·variance + Q mod t)
        let d = BigUint::from(params.degree());
        let q = modulus_product(params.moduli());
        let t = BigUint::from(params.plaintext());
        let b_fresh = BigUint::from(2 * variance);
        let b_c = BigUint::from(m) * (&b_fresh + &q % &t);
        assert_eq!(bound_sk, (BigUint::from(1_u64) << (lambda + 1)) * &d * &b_c);

        let bound_bfv = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params.clone(), n, m, lambda, FreshNoiseModel::BfvPublicKey)
                .unwrap(),
        )
        .unwrap()
        .smudging_bound()
        .clone();
        let bound_lbfv = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params, n, m, lambda, FreshNoiseModel::LbfvPublicKey).unwrap(),
        )
        .unwrap()
        .smudging_bound()
        .clone();
        assert!(bound_sk < bound_bfv);
        assert!(bound_bfv < bound_lbfv);
    }

    /// Largest lambda accepted by the generator for a model. `B_sm` grows
    /// monotonically with lambda, so the strict correctness inequality fails
    /// from the first infeasible lambda on.
    fn max_feasible_lambda(
        params: &Arc<BfvParameters>,
        n: usize,
        m: usize,
        model: FreshNoiseModel,
    ) -> usize {
        let mut feasible = None;
        for lambda in 0..=MAX_LAMBDA {
            match SmudgingNoiseGenerator::new(
                SmudgingConfig::new(params.clone(), n, m, lambda, model.clone()).unwrap(),
            ) {
                Ok(_) => feasible = Some(lambda),
                Err(_) => break,
            }
        }
        match feasible {
            Some(lambda) => lambda,
            None => panic!("boundary tests need a model feasible at lambda 0"),
        }
    }

    /// The feasibility boundary itself depends on the model: with a tiny
    /// correctness budget, the lambda at which `2*(B_C + n*B_sm) < Delta`
    /// stops holding is lower for the wider l-BFV `u` support and higher for
    /// the direct-error secret-key path.
    #[test]
    fn feasibility_boundary_depends_on_model() {
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(32)
            .set_error1_variance_usize(1)
            .build_arc()
            .unwrap();
        let (n, m) = (1usize, 1usize);

        let bfv_max = max_feasible_lambda(&params, n, m, FreshNoiseModel::BfvPublicKey);
        let lbfv_max = max_feasible_lambda(&params, n, m, FreshNoiseModel::LbfvPublicKey);
        let sk_max = max_feasible_lambda(&params, n, m, FreshNoiseModel::BfvSecretKey);

        assert!(
            lbfv_max < bfv_max,
            "wider u support must bound feasibility earlier"
        );
        assert!(
            bfv_max <= sk_max,
            "direct-error path must not be less feasible"
        );
        assert!(bfv_max > 0);

        // At the BFV model's boundary lambda the l-BFV model is already
        // excluded by the strict correctness inequality.
        let error = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params, n, m, bfv_max, FreshNoiseModel::LbfvPublicKey).unwrap(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("strict inequality"));
    }

    /// A party count large enough to overflow a naive u64 product of
    /// `n * (2 * variance)` must neither panic nor wrap into an understated
    /// public-key error bound: the bound is computed as a BigUint product, so
    /// the huge configuration is rejected by the feasibility checks with a
    /// typed error instead (both public-key models, issue #250 review).
    #[test]
    fn huge_party_count_does_not_truncate_public_key_error() {
        let params = small_params(&[62]);
        let (n, m, lambda) = (usize::MAX, 1usize, 2usize);
        let d = BigUint::from(params.degree());
        let b_e = BigUint::from((2 * params.variance()) as u64);
        let b_enc = compute_b_enc(params.get_error1_variance()).unwrap();
        let sk_bound = BigUint::from(n);
        let e_pk = &BigUint::from(n) * &b_e;

        for (model, u_bound) in [
            (FreshNoiseModel::BfvPublicKey, BigUint::from(1_u64)),
            (FreshNoiseModel::LbfvPublicKey, b_e.clone()),
        ] {
            let config = SmudgingConfig::new(params.clone(), n, m, lambda, model.clone()).unwrap();

            // The fresh bound equals the exact BigUint product `n · (2·variance)`
            // in the e_pk term: any u64 truncation would fail this comparison.
            let expected_fresh = &d * &u_bound * &e_pk + &b_enc + &d * &b_e * &sk_bound;
            assert_eq!(config.fresh_noise_bound().unwrap(), expected_fresh);

            // The generator then rejects the astronomic bound as infeasible
            // with the typed error instead of panicking on overflow.
            let error = SmudgingNoiseGenerator::new(config).unwrap_err();
            assert!(matches!(
                error,
                Error::Threshold(crate::ThresholdError::SmudgingBoundInfeasible { .. })
            ));
        }
    }
}
