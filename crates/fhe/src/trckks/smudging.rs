//! Threshold CKKS smudging (noise-flooding) bound calculation.
//!
//! # Why flooding is security-critical for CKKS
//!
//! CKKS decryption returns `m + e` — the message WITH its noise. Li &
//! Micciancio (Eurocrypt 2021) showed this leaks the secret key: given a
//! ciphertext and its decryption, `e` is recoverable, and RLWE noise is
//! key material — i.e. the relevant notion is IND-CPA-D, not IND-CPA. In the
//! threshold setting every decryption-share opening has the same shape, so
//! each share must carry flooding noise large enough to statistically hide
//! the ciphertext noise. The bound below is the standard smudging lemma
//! (Asharov–Jain–López-Alt–Tromer–Vaikuntanathan–Wichs, Eurocrypt 2012, via
//! AJW'11 Lemma 2.1) — a statistical-distance argument, the same route taken
//! by "Noah's Ark" (eprint 2023/815) and implemented by OpenFHE.
//! Li–Micciancio–Schultz–Sorrell (Crypto 2022) is the *alternative* tight
//! DP/Gaussian-mechanism analysis, which we do NOT use; note it also proves
//! that flooding tailored to an observed ciphertext's error (rather than a
//! static, circuit-derived worst case) is vulnerable to IND-CPA-D attacks —
//! relevant if this calculator is ever relaxed to an average-case `B_C`.
//!
//! # The bound
//!
//! Security (identical to trBFV, statistical-distance argument):
//!
//! ```text
//! B_sm >= 2^lambda * B_C
//! ```
//!
//! where `B_C` bounds the ciphertext noise after the homomorphic circuit
//! and `lambda` is the statistical security parameter.
//!
//! Correctness differs from BFV. BFV has a decode wall at `Q/(2t)`; CKKS
//! has no modular decode, so flooding noise lands **in the result** instead
//! of breaking it. Two constraints replace the wall:
//!
//! 1. **No wrap-around**: the plaintext ring element plus all noise must
//!    stay inside `(-Q_l/2, Q_l/2)` at the ciphertext's level `l`:
//!    `delta * B_msg + B_C + n * B_sm < Q_l / 2`.
//! 2. **Precision**: opening adds up to `n * B_sm` per coefficient, i.e.
//!    an absolute error of `n * B_sm / delta` in the decoded values. The
//!    application states the error it tolerates (`precision_loss`); the
//!    calculator enforces `n * B_sm <= precision_loss * delta`.
//!
//! Both walls must clear `2^lambda * B_C`, otherwise the parameters cannot
//! support secure threshold decryption for that circuit — the fix is a
//! larger `Q` (more/larger moduli), a smaller circuit bound, or an
//! explicitly relaxed precision target.
//!
//! `B_C` estimation for the supported operations (coefficient sup-norm,
//! worst-case):
//! - fresh encryption: `B_fresh = d*B_e*||u|| + B_e + d*B_e*||s||`
//!   (`u*e_pk + e0 + s*e1` with CBD-bounded `e`, ternary `u`, `s`)
//! - addition of `m` ciphertexts: `m * B_fresh`
//! - plaintext multiplication + rescale: noise scales with the plaintext
//!   sup-norm and divides by the dropped modulus; bounded here by
//!   `B * B_prev * d / q_dropped + B_rescale` where `B_rescale = (d+1)/2`.
//!
//! The calculator takes the conservative product form for `depth`
//! multiplicative levels. This is a worst-case (not average-case) analysis:
//! looser than Bossuat-style average-case tracking, but sound.

use crate::ckks::CkksParameters;
use crate::trbfv::Lambda;
use crate::{Error, Result};
use num_bigint::BigUint;
use std::sync::Arc;

/// Description of the homomorphic circuit a ciphertext went through before
/// threshold decryption, for noise-bound purposes.
#[derive(Debug, Clone)]
pub struct CkksCircuitShape {
    /// Number of fresh ciphertexts summed (1 = a single encryption).
    pub num_additions: usize,
    /// Multiplicative depth consumed (levels dropped by rescaling).
    pub depth: usize,
    /// Sup-norm bound on plaintext/mask values multiplied in at each level
    /// (e.g. the auction mask bound, or the input bound for ct-ct squares).
    pub mult_operand_bound: f64,
}

impl CkksCircuitShape {
    /// A pure aggregation circuit: `m` additions, no multiplications.
    #[must_use]
    pub fn additions(m: usize) -> Self {
        Self {
            num_additions: m.max(1),
            depth: 0,
            mult_operand_bound: 0.0,
        }
    }

    /// One multiplication level over `m` summed products (statistics,
    /// masked comparisons), with operands bounded by `operand_bound`.
    #[must_use]
    pub fn one_level(m: usize, operand_bound: f64) -> Self {
        Self {
            num_additions: m.max(1),
            depth: 1,
            mult_operand_bound: operand_bound,
        }
    }
}

/// Configuration for the CKKS smudging-bound calculation.
#[derive(Debug, Clone)]
pub struct CkksSmudgingConfig {
    /// CKKS parameters.
    pub params: Arc<CkksParameters>,
    /// Number of parties contributing smudging shares (worst case: all).
    pub n_parties: usize,
    /// The circuit shape being decrypted.
    pub circuit: CkksCircuitShape,
    /// Level of the ciphertext at decryption time (after rescales).
    pub level: usize,
    /// Sup-norm bound on encoded input values (application-level `B`).
    pub input_bound: f64,
    /// Maximum tolerated absolute error in decoded values from flooding
    /// (e.g. `0.01` for two decimal digits). The precision wall enforces
    /// `n * B_sm / delta <= precision_loss`.
    pub precision_loss: f64,
    /// Statistical security level (reuses the trBFV [`Lambda`] type;
    /// [`MIN_SECURE_LAMBDA`] applies).
    pub lambda: Lambda,
}

/// Calculator for the threshold-CKKS flooding bound.
#[derive(Debug)]
pub struct CkksSmudgingBoundCalculator {
    config: CkksSmudgingConfig,
}

impl CkksSmudgingBoundCalculator {
    /// Create a new calculator.
    #[must_use]
    pub fn new(config: CkksSmudgingConfig) -> Self {
        Self { config }
    }

    /// Worst-case ciphertext-noise bound `B_C` for the configured circuit.
    ///
    /// Fresh noise: `d*B_e*||u|| + B_e + d*B_e*||s||` with CBD bound
    /// `B_e = 2*variance` and ternary `u`, `s` (`||.|| = 1`).
    #[must_use]
    pub fn circuit_noise_bound(&self) -> BigUint {
        let d = BigUint::from(self.config.params.degree());
        let b_e = BigUint::from(2 * self.config.params.variance() as u64);

        // B_fresh = d*B_e + B_e + d*B_e = (2d + 1) * B_e
        let b_fresh = (BigUint::from(2u32) * &d + BigUint::from(1u32)) * &b_e;

        // Additions multiply the bound by m.
        let mut b_c = BigUint::from(self.config.circuit.num_additions) * b_fresh;

        // Each multiplicative level: operand (sup-norm <= bound * delta,
        // encoded) times noise, divided by the dropped modulus; plus
        // rescale rounding (d+1)/2. Conservative: assume the dropped
        // modulus only cancels delta (scale-matched moduli), leaving the
        // operand bound as multiplier.
        //
        // PLUS the relinearization key-switch noise, which the earlier
        // version of this bound OMITTED. Every ct×ct level relinearizes;
        // the key switch adds noise BEFORE the level's rescale, so it is
        // then divided by the dropped modulus like everything else.
        //
        // Key-switch noise before rescale (`ckks/hybrid.rs` module docs):
        //   RNS-decomposition key : ≈ L_ℓ · q_max · N · B_key
        //   hybrid key            : ≈ dnum · N · B_key · (D/P), D/P ≤ 1 by
        //                           construction (a digit never exceeds P)
        // where `B_key` is the relin KEY's error. The multiparty ceremony
        // key sums n parties' errors and round 2 multiplies by s_i (‖s‖≤1
        // ternary, but ‖·‖₁ ≤ N), so we charge B_key = 2·n·N·B_e —
        // conservative. Which key an E3 uses is a property of its params:
        // special primes present ⇒ hybrid, else RNS. We divide by q_min
        // (≤ the dropped modulus ⇒ a LARGER quotient ⇒ conservative).
        // At secure N this is what separates the two key types: the RNS
        // term is ~2^14 above the fresh noise at N=32768 (the measured
        // "garbage" of per-level keys), the hybrid term is ~2 bits.
        let moduli = self.config.params.moduli();
        let n_parties = BigUint::from(self.config.n_parties.max(1));
        let q_max = BigUint::from(moduli.iter().copied().max().unwrap_or(1));
        let q_min = BigUint::from(moduli.iter().copied().min().unwrap_or(1).max(1));
        let b_key = BigUint::from(2u32) * &n_parties * &d * &b_e;
        let hybrid = !self.config.params.special_moduli().is_empty();
        let dnum = BigUint::from(self.config.params.dnum().max(1));
        for level in 0..self.config.circuit.depth {
            let operand = self.config.circuit.mult_operand_bound.abs().ceil() as u64;
            let operand = BigUint::from(operand.max(1));
            let rescale_round = (&d + BigUint::from(1u32)) / BigUint::from(2u32);
            // Sanity: the dropped modulus must exist.
            debug_assert!(level + 1 < moduli.len(), "depth exceeds moduli chain");
            // Limbs remaining at this level (RNS key size L_ℓ).
            let l_level = BigUint::from(moduli.len().saturating_sub(level).max(1));
            let relin_pre_rescale = if hybrid {
                &dnum * &d * &b_key
            } else {
                &l_level * &q_max * &d * &b_key
            };
            let relin = relin_pre_rescale / &q_min + BigUint::from(1u32);
            b_c = operand * &d * b_c + rescale_round + relin;
        }
        b_c
    }

    /// `Q_l`: the modulus product at the decryption level.
    fn q_at_level(&self) -> Result<BigUint> {
        let ctx = self.config.params.context_at_level(self.config.level)?;
        let mut q = BigUint::from(1u32);
        for &m in ctx.moduli() {
            q *= BigUint::from(m);
        }
        Ok(q)
    }

    /// Effective scale of the ciphertext at decryption time.
    ///
    /// Each multiplication multiplies the scale by `delta` and the following
    /// rescale divides by the dropped modulus, so after `depth` levels the
    /// ciphertext's scale is `delta^(depth+1) / prod(dropped moduli)` — NOT
    /// the raw parameter scale. Both correctness walls must use this value:
    /// with scale-matched moduli it is close to `delta`, but for e.g. 40-bit
    /// scale over 45-bit moduli it is 2^5 smaller per level, which loosens
    /// the wrap wall and TIGHTENS the precision wall.
    fn effective_scale(&self) -> Result<f64> {
        let moduli = self.config.params.moduli();
        let depth = self.config.circuit.depth;
        if depth + 1 > moduli.len() {
            return Err(Error::DefaultError(
                "circuit depth exceeds the moduli chain".to_string(),
            ));
        }
        let mut eff = self.config.params.scale();
        // Rescale i drops moduli[len-1-i] (the chain drops from the end).
        for i in 0..depth {
            let dropped = moduli[moduli.len() - 1 - i] as f64;
            eff = eff * self.config.params.scale() / dropped;
        }
        if !(eff.is_finite() && eff >= 1.0) {
            return Err(Error::DefaultError(
                "effective scale is not representable".to_string(),
            ));
        }
        Ok(eff)
    }

    /// Calculate the flooding bound `B_sm = 2^lambda * B_C`, checking both
    /// CKKS correctness walls.
    ///
    /// # Errors
    /// - wrap-around wall: `delta*B_msg + B_C + n*B_sm >= Q_l/2`
    /// - precision wall: `n*B_sm > precision_loss * delta`
    /// - non-finite/invalid config values
    pub fn calculate_sm_bound(&self) -> Result<BigUint> {
        if !(self.config.input_bound.is_finite() && self.config.input_bound > 0.0) {
            return Err(Error::DefaultError("invalid input bound".to_string()));
        }
        if !(self.config.precision_loss.is_finite() && self.config.precision_loss > 0.0) {
            return Err(Error::DefaultError("invalid precision target".to_string()));
        }
        // `mult_operand_bound` feeds `circuit_noise_bound` through an
        // `f64 -> u64` cast: NaN casts to 0 (then `.max(1)`), so an invalid
        // operand bound would silently SHRINK B_C — and with it the flooding
        // requirement — instead of failing. That is the wrong direction to
        // fail in for a security bound. Reject it explicitly.
        if self.config.circuit.depth > 0
            && !(self.config.circuit.mult_operand_bound.is_finite()
                && self.config.circuit.mult_operand_bound >= 1.0)
        {
            return Err(Error::DefaultError(format!(
                "invalid mult_operand_bound {} (must be finite and >= 1 for a circuit of \
                 depth {})",
                self.config.circuit.mult_operand_bound, self.config.circuit.depth
            )));
        }
        // A ciphertext that went through `depth` rescales is at level >=
        // depth. Allowing level < depth would evaluate the wrap wall against
        // a larger Q than the ciphertext actually has — unsound.
        if self.config.level < self.config.circuit.depth {
            return Err(Error::DefaultError(format!(
                "inconsistent config: level {} < circuit depth {} (each multiplicative level \
                 consumes one rescale)",
                self.config.level, self.config.circuit.depth
            )));
        }

        let b_c = self.circuit_noise_bound();
        let lambda = self.config.lambda.value();
        let b_sm = BigUint::from(2u32).pow(lambda as u32) * &b_c;
        let n = BigUint::from(self.config.n_parties);

        // Wall 1: no wrap mod Q_l.
        // Message magnitude after the circuit: additions scale the message
        // bound too, and each mult level multiplies by the operand bound.
        // The coefficient magnitude is (effective scale) * msg_bound.
        let eff_scale = self.effective_scale()?;
        let mut msg_bound = self.config.input_bound * self.config.circuit.num_additions as f64;
        for _ in 0..self.config.circuit.depth {
            msg_bound *= self.config.circuit.mult_operand_bound.abs().max(1.0);
        }
        let delta_bmsg = BigUint::from((eff_scale * msg_bound).ceil() as u128);
        let q_l = self.q_at_level()?;
        let half_q = &q_l / BigUint::from(2u32);
        let total = &delta_bmsg + &b_c + &n * &b_sm;
        if total >= half_q {
            return Err(Error::smudging_bound_infeasible(
                "wrap-around wall: eff_scale*B_msg + B_C + n*B_sm >= Q_l/2; increase moduli, \
                 reduce lambda, or shrink the circuit",
            ));
        }

        // Wall 2: precision. n * B_sm <= precision_loss * effective scale
        // (the decoded error is flooding noise divided by the ciphertext's
        // actual scale at decryption time, not the raw parameter scale).
        let precision_budget =
            BigUint::from((self.config.precision_loss * eff_scale).floor() as u128);
        if &n * &b_sm > precision_budget {
            return Err(Error::smudging_bound_infeasible(
                "precision wall: n*B_sm exceeds precision_loss*eff_scale; raise the scale, relax \
                 the precision target, or reduce lambda",
            ));
        }

        Ok(b_sm)
    }

    /// The number of BITS of the flooding bound — the shape
    /// [`crate::trckks::TRCKKS::generate_smudging_error`] consumes.
    pub fn calculate_sm_bits(&self) -> Result<usize> {
        Ok(self.calculate_sm_bound()?.bits() as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckks::CkksParametersBuilder;
    use crate::trbfv::MIN_SECURE_LAMBDA;
    use std::error::Error as StdError;

    fn big_params() -> Arc<CkksParameters> {
        // Generous chain: enough room for lambda=40 flooding below the
        // wrap wall with scale 2^40 (delta huge => precision wall is the
        // binding one; pick precision_loss accordingly).
        CkksParametersBuilder::new()
            .set_degree(64)
            .set_moduli_sizes(&[60, 60, 60])
            .set_scale(2f64.powi(100))
            .build_arc()
            .unwrap()
    }

    #[test]
    fn additions_bound_is_feasible_with_room() -> std::result::Result<(), Box<dyn StdError>> {
        let params = big_params();
        let calc = CkksSmudgingBoundCalculator::new(CkksSmudgingConfig {
            params,
            n_parties: 5,
            circuit: CkksCircuitShape::additions(10),
            level: 0,
            input_bound: 100.0,
            precision_loss: 1e-9,
            lambda: Lambda::insecure(40),
        });
        let b = calc.calculate_sm_bound()?;
        assert!(b.bits() > 40, "bound must include the 2^lambda factor");
        // And the bits form is consistent.
        assert_eq!(calc.calculate_sm_bits()? as u64, b.bits());
        Ok(())
    }

    #[test]
    fn secure_lambda_enforced_by_type() {
        // The Lambda type itself rejects insecure "secure" values.
        assert!(Lambda::secure(MIN_SECURE_LAMBDA - 1).is_err());
        assert!(Lambda::secure(80).is_ok());
    }

    #[test]
    fn precision_wall_rejects_small_scale() {
        // Small scale => flooding noise visible in output => must error.
        let params = CkksParametersBuilder::new()
            .set_degree(64)
            .set_moduli_sizes(&[45, 45])
            .set_scale(2f64.powi(26))
            .build_arc()
            .unwrap();
        let calc = CkksSmudgingBoundCalculator::new(CkksSmudgingConfig {
            params,
            n_parties: 5,
            circuit: CkksCircuitShape::additions(3),
            level: 0,
            input_bound: 100.0,
            precision_loss: 0.01,
            lambda: Lambda::insecure(40),
        });
        let err = calc.calculate_sm_bound().unwrap_err();
        assert!(err.to_string().contains("wall"), "got: {err}");
    }

    #[test]
    fn wrap_wall_rejects_big_lambda_small_q() {
        let params = CkksParametersBuilder::new()
            .set_degree(64)
            .set_moduli_sizes(&[45, 45])
            .set_scale(2f64.powi(26))
            .build_arc()
            .unwrap();
        let calc = CkksSmudgingBoundCalculator::new(CkksSmudgingConfig {
            params,
            n_parties: 5,
            circuit: CkksCircuitShape::additions(3),
            level: 0,
            input_bound: 100.0,
            // Absurdly loose precision so only the wrap wall can fire.
            precision_loss: 1e30,
            lambda: Lambda::insecure(90),
        });
        let err = calc.calculate_sm_bound().unwrap_err();
        assert!(err.to_string().contains("wrap-around"), "got: {err}");
    }

    #[test]
    fn one_level_circuit_larger_than_additions() -> std::result::Result<(), Box<dyn StdError>> {
        let params = big_params();
        let add_calc = CkksSmudgingBoundCalculator::new(CkksSmudgingConfig {
            params: params.clone(),
            n_parties: 5,
            circuit: CkksCircuitShape::additions(3),
            level: 0,
            input_bound: 100.0,
            precision_loss: 1e-6,
            lambda: Lambda::insecure(20),
        });
        let mul_calc = CkksSmudgingBoundCalculator::new(CkksSmudgingConfig {
            params,
            n_parties: 5,
            circuit: CkksCircuitShape::one_level(3, 8.0),
            level: 1,
            input_bound: 100.0,
            precision_loss: 1e-6,
            lambda: Lambda::insecure(20),
        });
        assert!(mul_calc.circuit_noise_bound() > add_calc.circuit_noise_bound());
        Ok(())
    }

    /// The relin key-switch term is CHARGED (regression: the original bound
    /// omitted it). A one-level circuit with a trivial operand (bound 1) and
    /// one addition must still exceed `N · B_fresh + rescale_round` — the
    /// value the level would have WITHOUT any key-switch noise.
    #[test]
    fn relin_noise_is_charged_per_level() -> std::result::Result<(), Box<dyn StdError>> {
        let params = big_params();
        let d = BigUint::from(params.degree());
        let b_e = BigUint::from(2 * params.variance() as u64);
        let b_fresh = (BigUint::from(2u32) * &d + BigUint::from(1u32)) * &b_e;
        let no_relin = &d * &b_fresh + (&d + BigUint::from(1u32)) / BigUint::from(2u32);
        let calc = CkksSmudgingBoundCalculator::new(CkksSmudgingConfig {
            params: params.clone(),
            n_parties: 3,
            circuit: CkksCircuitShape::one_level(1, 1.0),
            level: 1,
            input_bound: 1.0,
            precision_loss: 1e-6,
            lambda: Lambda::insecure(20),
        });
        let with_relin = calc.circuit_noise_bound();
        assert!(
            with_relin > no_relin,
            "relin term missing: {with_relin} <= {no_relin}"
        );
        // ...and it scales with the committee size (B_key carries n).
        let calc5 = CkksSmudgingBoundCalculator::new(CkksSmudgingConfig {
            params,
            n_parties: 5,
            circuit: CkksCircuitShape::one_level(1, 1.0),
            level: 1,
            input_bound: 1.0,
            precision_loss: 1e-6,
            lambda: Lambda::insecure(20),
        });
        assert!(calc5.circuit_noise_bound() > with_relin);
        Ok(())
    }

    /// A NaN operand bound must be REJECTED, not silently cast to 0 and
    /// shrink the security bound.
    #[test]
    fn nan_operand_bound_is_rejected() {
        let params = big_params();
        let calc = CkksSmudgingBoundCalculator::new(CkksSmudgingConfig {
            params,
            n_parties: 3,
            circuit: CkksCircuitShape::one_level(1, f64::NAN),
            level: 1,
            input_bound: 1.0,
            precision_loss: 1e-6,
            lambda: Lambda::insecure(20),
        });
        let err = calc.calculate_sm_bound().unwrap_err();
        assert!(err.to_string().contains("mult_operand_bound"), "got: {err}");
    }
}
