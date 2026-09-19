//! Smudging-noise ownership and sampling.

use super::bound::{MAX_LAMBDA, SmudgingConfig, compute_b_enc, compute_delta, modulus_product};
use crate::Error;
use crate::bfv::BfvParameters;
use fhe_math::rq::{Poly, PowerBasis};
use fhe_math::zq::Modulus;
use ndarray::Array2;
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use std::fmt;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Smudging noise generator using exact centered uniform sampling.
///
/// Each coefficient is sampled uniformly from `[-B_sm, B_sm]` directly into
/// RNS representation, as specified for the smudging noise in the trBFV
/// paper. The secret sampling path uses constant-time `u64`/`u128` limb
/// arithmetic only.
#[derive(Debug)]
pub struct SmudgingNoiseGenerator {
    params: Arc<BfvParameters>,
    smudging_bound: BigUint,
}

impl SmudgingNoiseGenerator {
    /// Calculate the bound and create a noise generator.
    ///
    /// Implements the trBFV security formula: `B_sm = 2^(lambda + 1) * d * B_C`
    /// (`d` = polynomial degree, accounting for the union bound over all `d`
    /// coefficients a single decryption reveals — see issue #108) subject to
    /// the strict correctness constraint `2 * (B_C + n * B_sm) < Delta` where
    /// `Delta = floor(Q / t)`.
    ///
    /// # Errors
    /// Returns error if:
    /// - Inputs are invalid (zero n/m, empty moduli, zero plaintext, zero variance)
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
        let t = BigUint::from(config.params.plaintext());
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
        let b_enc = compute_b_enc(error1_var);
        let variance = config.params.variance();
        let b_e = BigUint::from((2 * variance) as u64);
        let e_norm = BigUint::from((config.n as u64) * (2 * variance) as u64);
        let sk_norm = BigUint::from(config.n as u64);

        // B_fresh = d·||e_ek||_∞ + B_enc + d·B_e·||sk||_∞
        let b_fresh = &d * &e_norm + b_enc + &d * &b_e * &sk_norm;

        // Q = product of all moduli
        let q_full = modulus_product(moduli);

        // Delta = floor(Q / t) — exact plaintext scaling factor.
        let delta = compute_delta(&q_full, &t);

        // B_C^(0): initial ciphertext noise bound (additive).
        let b_c_additive = BigUint::from(config.m) * (&b_fresh + &q_full % &t);

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
            let k = BigUint::from(config.params.plaintext());
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
/// smudging dealing operation ([`ShareManager::generate_secret_shares_from_smudging_noise`]).
/// There is intentionally no `Clone`, `Copy`, coefficient accessor, or
/// generic serialization: duplicating one-time noise across decryptions
/// breaks the statistical hiding argument.
///
/// ```compile_fail
/// # use fhe::trbfv::{ShareManager, SmudgingNoise};
/// fn duplicate(noise: &SmudgingNoise) -> SmudgingNoise {
///     noise.clone()
/// }
/// ```
pub struct SmudgingNoise {
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
}

impl fmt::Debug for SmudgingNoise {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmudgingNoise")
            .finish_non_exhaustive()
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
    /// the smudging dealing operation.
    pub fn generate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<SmudgingNoise, Error> {
        let ctx = self.params.context_at_level(0)?;
        let degree = self.params.degree();
        // Constant-time Barrett reduction operators, one per RNS modulus in
        // the same order as `self.params.moduli()`.
        let moduli = ctx.moduli_operators();
        if self.smudging_bound == BigUint::from(0u64) {
            return Ok(SmudgingNoise {
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

        // An aborted sampling run never publishes or reuses this matrix.
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
            for (row, (qi, &bound_qi)) in moduli.iter().zip(&bound_mod).enumerate() {
                let u_mod = limbs_mod(&candidate, qi);
                // (u - B_sm) mod qi as a constant-time modular negation and
                // addition: `neg` turns `-B_sm mod qi` into a canonical
                // residue and `add` performs the wrap-around conditional
                // subtraction itself, so no branch depends on the secret
                // residues. Both operands stay in [0, qi).
                matrix[[row, col]] = qi.add(u_mod, qi.neg(bound_qi));
            }
            // Wipe the consumed candidate limbs.
            candidate.as_mut_slice().zeroize();
        }
        // Build the noise polynomial directly rather than through
        // `from_coeffs_matrix`.
        let mut poly = Poly::<PowerBasis>::zero(ctx);
        poly.set_coefficients(matrix);
        Ok(SmudgingNoise {
            poly: Zeroizing::new(poly),
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
    reason = "tests use fixed validated dimensions"
)]
mod tests {
    use super::*;
    use crate::bfv::BfvParametersBuilder;
    use crate::trbfv::test_support::params_8192;
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
        assert_eq!(compute_b_enc(&BigUint::from(16u32)), BigUint::from(32u32));
    }

    #[test]
    fn b_enc_uniform_branch_uses_minimal_bound() {
        let variance = BigUint::from(20u32);
        assert_eq!(compute_b_enc(&variance), BigUint::from(8u32));
    }

    #[test]
    fn b_enc_large_biguint_uses_uniform_branch() {
        let variance = BigUint::from_str("340282366920938463463374607431768211456").unwrap();
        let mut expected = (BigUint::from(3u32) * &variance).sqrt();
        while &expected * (&expected + 1u32) < BigUint::from(3u32) * &variance {
            expected += 1u32;
        }
        assert_eq!(compute_b_enc(&variance), expected);
    }

    #[test]
    fn config_validates_basic_inputs() {
        let params = params_8192();
        assert!(SmudgingConfig::new(params.clone(), 0, 1, 2).is_err());
        assert!(SmudgingConfig::new(params.clone(), 1, 0, 2).is_err());
        assert!(SmudgingConfig::new(params, 1, 1, MAX_LAMBDA + 1).is_err());
    }

    #[test]
    fn generator_revalidates_public_config_fields() {
        let params = params_8192();
        let mut config = SmudgingConfig::new(params.clone(), 1, 1, 2).unwrap();
        config.n = 0;
        assert!(SmudgingNoiseGenerator::new(config).is_err());

        let mut config = SmudgingConfig::new(params, 1, 1, 2).unwrap();
        config.m = 0;
        assert!(SmudgingNoiseGenerator::new(config).is_err());
    }

    #[test]
    fn delta_is_q_div_t_floor() {
        let params = params_8192();
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
        let config = SmudgingConfig::new(params, 1, 1, 5).unwrap();
        let error = SmudgingNoiseGenerator::new(config).unwrap_err();
        assert!(error.to_string().contains("strict inequality"));
    }

    #[test]
    fn lambda_at_max_is_not_truncated() {
        let config = SmudgingConfig::new(params_8192(), 1, 1, MAX_LAMBDA).unwrap();
        if let Ok(generator) = SmudgingNoiseGenerator::new(config) {
            assert!(generator.smudging_bound().bits() as usize > MAX_LAMBDA);
        }
    }

    #[test]
    fn test_smudging_noise_generator_creation() {
        let params = params_8192();
        let config = SmudgingConfig::new(params.clone(), 3, 1, 35).unwrap();
        let generator = SmudgingNoiseGenerator::new(config).unwrap();
        assert_eq!(generator.params, params);
        assert!(generator.smudging_bound() > &BigUint::zero());
    }

    #[test]
    fn test_noise_generation_small_bound() {
        let mut rng = rng();
        let params = params_8192();
        let bound = BigUint::from(1000u64);
        let generator = generator_with_bound(params.clone(), bound.clone());
        let noise = generator.generate(&mut rng).unwrap();
        assert_noise_in_bound(noise, &bound, &params);
    }

    #[test]
    fn test_noise_generation_zero_bound() {
        let mut rng = rng();
        let params = params_8192();
        let generator = generator_with_bound(params.clone(), BigUint::zero());
        let poly = generator.generate(&mut rng).unwrap().into_poly();
        assert!(poly.coefficients().iter().all(|&c| c == 0));
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
        let additive = SmudgingConfig::new(params.clone(), 3, 1, 2).unwrap();
        let mut depth_one = additive.clone();
        depth_one.mult_depth = 1;
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
    fn smudging_bound_monotonicity() {
        let params = params_8192();
        let b1 = SmudgingNoiseGenerator::new(SmudgingConfig::new(params.clone(), 3, 1, 2).unwrap())
            .unwrap()
            .smudging_bound()
            .clone();
        let b2 = SmudgingNoiseGenerator::new(SmudgingConfig::new(params.clone(), 3, 2, 2).unwrap())
            .unwrap()
            .smudging_bound()
            .clone();
        let b3 = SmudgingNoiseGenerator::new(SmudgingConfig::new(params, 3, 1, 10).unwrap())
            .unwrap()
            .smudging_bound()
            .clone();
        assert!(b2 >= b1);
        assert!(b3 > b1);
    }
}
