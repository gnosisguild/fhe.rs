//! One-time local smudging using the existing bound calculator.

use super::arithmetic::SecretMatrix;
use crate::Error;
use crate::bfv::BfvParameters;
use crate::trbfv::{SmudgingBoundCalculator, SmudgingBoundCalculatorConfig};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_math::zq::Modulus;
use ndarray::Array2;
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Local-noise sampler for synchronized partial decryption.
///
/// Reuses the legacy bound calculator and [`Lambda`](crate::trbfv::Lambda)
/// policy. Samples exact centered-uniform coefficients directly into guarded
/// RNS storage. The bound remains `2^(lambda + 1) * degree * B_C`, with strict
/// correctness `2 * (B_C + n * B_sm) < floor(Q / t)`.
#[derive(Debug)]
pub struct SmudgingNoiseGenerator {
    params: Arc<BfvParameters>,
    committee_size: usize,
    smudging_bound: BigUint,
}

impl SmudgingNoiseGenerator {
    /// Calculate a bound for the supplied circuit and BFV configuration.
    ///
    /// The configuration's key/noise bounds must describe the actual encryption
    /// path. This constructor preserves the legacy calculator's assumptions.
    pub fn new(config: SmudgingBoundCalculatorConfig) -> Result<Self, Error> {
        Self::from_bound_calculator(SmudgingBoundCalculator::new(config))
    }

    /// Use an existing calculator, including an explicitly justified circuit bound.
    ///
    /// A plaintext modulus wider than `u64` is rejected before bound calculation.
    /// Applications remain responsible for the calculator's circuit assumptions
    /// and statistical policy; the noise owner binds the committee and full BFV
    /// parameters, not ciphertext-noise provenance.
    pub fn from_bound_calculator(calculator: SmudgingBoundCalculator) -> Result<Self, Error> {
        let (params, committee_size) = calculator.synchronized_binding();
        super::plaintext_modulus(params)?;
        let smudging_bound = calculator.calculate_sm_bound()?;
        Ok(Self {
            params: params.clone(),
            committee_size,
            smudging_bound,
        })
    }

    /// Sample fresh noise to be consumed by one partial-decryption call.
    ///
    /// All RNS rows represent the same centered integer in `[-B_sm, B_sm]`.
    /// Limb comparison and modular reduction use fixed-width arithmetic; the
    /// rejection count depends on the RNG stream, not on the accepted value.
    pub fn generate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<SmudgingNoise, Error> {
        let ctx = self.params.context_at_level(0)?;
        let degree = self.params.degree();
        let moduli = ctx.moduli_operators();
        let mut poly = Zeroizing::new(Poly::<PowerBasis>::zero(ctx));
        if self.smudging_bound != BigUint::from(0u64) {
            let range = BigUint::from(2u32) * &self.smudging_bound + BigUint::from(1u32);
            let bits = range.bits();
            let nlimbs = bits.div_ceil(64) as usize;
            let mut range_limbs = range.to_u64_digits();
            range_limbs.resize(nlimbs, 0);
            let excess = nlimbs as u64 * 64 - bits;
            let top_mask = if excess == 0 {
                u64::MAX
            } else {
                u64::MAX >> excess
            };
            let bound_limbs = self.smudging_bound.to_u64_digits();
            let bound_mod: Vec<u64> = moduli
                .iter()
                .map(|qi| limbs_mod(&bound_limbs, qi))
                .collect();
            let mut matrix = SecretMatrix(Array2::zeros((moduli.len(), degree)));
            let mut candidate = Zeroizing::new(vec![0u64; nlimbs]);
            for column in matrix.0.columns_mut() {
                loop {
                    for limb in candidate.iter_mut() {
                        *limb = rng.next_u64();
                    }
                    if let Some(top) = candidate.last_mut() {
                        *top &= top_mask;
                    }
                    if limbs_lt(&candidate, &range_limbs) {
                        break;
                    }
                    candidate.as_mut_slice().zeroize();
                }
                for (cell, (qi, &bound_qi)) in column.into_iter().zip(moduli.iter().zip(&bound_mod))
                {
                    *cell = qi.add(limbs_mod(&candidate, qi), qi.neg(bound_qi));
                }
                candidate.as_mut_slice().zeroize();
            }
            poly.set_coefficients(std::mem::take(&mut matrix.0));
        }
        Ok(SmudgingNoise {
            poly,
            committee_size: self.committee_size,
            params: self.params.clone(),
        })
    }

    /// Maximum absolute value of each sampled coefficient.
    #[must_use]
    pub fn smudging_bound(&self) -> &BigUint {
        &self.smudging_bound
    }
}

/// Fresh local noise, bound to its committee and BFV parameters and wiped on drop.
///
/// This owner has no public coefficient access or transport representation.
/// It is consumed by [`SynchronizedDecryptor::decryption_share`](super::SynchronizedDecryptor::decryption_share).
///
/// ```compile_fail
/// use fhe::trbfv::synchronized::SmudgingNoise;
/// fn duplicate(noise: &SmudgingNoise) -> SmudgingNoise {
///     noise.clone()
/// }
/// ```
///
/// ```compile_fail
/// use fhe::trbfv::synchronized::{PartyPrfKeys, SmudgingNoise, SynchronizedDecryptor};
/// use fhe::bfv::Ciphertext;
/// use fhe_math::rq::{Ntt, Poly};
/// fn reuse(d: &SynchronizedDecryptor, ct: &Ciphertext, sk: &Poly<Ntt>, noise: SmudgingNoise, keys: &PartyPrfKeys) {
///     let _ = d.decryption_share(ct, sk, 1, &[1, 2], noise, keys);
///     let _ = d.decryption_share(ct, sk, 1, &[1, 2], noise, keys);
/// }
/// ```
pub struct SmudgingNoise {
    poly: Zeroizing<Poly<PowerBasis>>,
    committee_size: usize,
    params: Arc<BfvParameters>,
}

impl SmudgingNoise {
    pub(super) fn into_poly(self) -> Zeroizing<Poly<PowerBasis>> {
        self.poly
    }

    pub(super) fn matches_configuration(
        &self,
        committee_size: usize,
        params: &BfvParameters,
    ) -> bool {
        self.committee_size == committee_size && self.params.as_ref() == params
    }

    pub(super) fn committee_size(&self) -> usize {
        self.committee_size
    }
}

impl std::fmt::Debug for SmudgingNoise {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SmudgingNoise")
            .finish_non_exhaustive()
    }
}

fn limbs_lt(a: &[u64], b: &[u64]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    let mut decision = 0u64;
    for (ai, bi) in a.iter().zip(b).rev() {
        let step = ((ai < bi) as u64) | (((ai > bi) as u64) << 1);
        let undecided = ((decision == 0) as u64).wrapping_neg();
        decision |= undecided & step;
    }
    decision == 1
}

fn limbs_mod(limbs: &[u64], qi: &Modulus) -> u64 {
    let mut acc = 0u64;
    for &limb in limbs.iter().rev() {
        acc = qi.reduce_u128((u128::from(acc) << 64) | u128::from(limb));
    }
    acc
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::bfv::BfvParametersBuilder;
    use crate::trbfv::Lambda;
    use num_bigint::BigInt;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(17)
            .set_moduli_sizes(&[62, 62, 62, 62, 62, 62])
            .build_arc()
            .unwrap()
    }

    #[test]
    fn sampled_centered_coefficients_match_bound_and_rns_rows() {
        let params = params();
        let mut rng = ChaCha8Rng::seed_from_u64(276);
        for bits in [0usize, 1, 63, 64, 65, 127, 128, 129, 330] {
            let bound = (BigUint::from(1u32) << bits) - BigUint::from(1u32);
            let generator = SmudgingNoiseGenerator {
                params: params.clone(),
                committee_size: 3,
                smudging_bound: bound.clone(),
            };
            let noise = generator.generate(&mut rng).unwrap();
            let q = noise.poly.ctx().modulus();
            let values = Vec::<BigUint>::from(noise.poly.as_ref());
            for (column, value) in values.into_iter().enumerate() {
                let centered = if value > q / 2u32 {
                    BigInt::from(value) - BigInt::from(q.clone())
                } else {
                    BigInt::from(value)
                };
                assert!(centered.magnitude() <= &bound);
                for (row, &qi) in params.moduli().iter().enumerate() {
                    let qi = BigInt::from(qi);
                    let expected = ((&centered % &qi) + &qi) % &qi;
                    assert_eq!(
                        expected,
                        BigInt::from(noise.poly.coefficients()[[row, column]])
                    );
                }
            }
        }
    }

    #[test]
    fn uses_legacy_bound_and_binds_full_parameters() {
        let params = params();
        let config =
            SmudgingBoundCalculatorConfig::new(params.clone(), 3, 2, Lambda::secure(40).unwrap())
                .unwrap();
        let expected = SmudgingBoundCalculator::new(config.clone())
            .calculate_sm_bound()
            .unwrap();
        let generator = SmudgingNoiseGenerator::new(config).unwrap();
        assert_eq!(generator.smudging_bound(), &expected);
        let noise = generator
            .generate(&mut ChaCha8Rng::seed_from_u64(280))
            .unwrap();
        assert!(noise.matches_configuration(3, &params));
        assert!(!noise.matches_configuration(5, &params));
        let other = BfvParametersBuilder::new()
            .set_degree(params.degree())
            .set_moduli(params.moduli())
            .set_plaintext_modulus(19)
            .build_arc()
            .unwrap();
        assert_eq!(
            params.context_at_level(0).unwrap(),
            other.context_at_level(0).unwrap()
        );
        assert!(!noise.matches_configuration(3, &other));
        assert!(noise.poly.coefficients().iter().any(|&v| v != 0));
    }

    #[test]
    fn limb_arithmetic_matches_biguint_oracle() {
        let mut rng = ChaCha8Rng::seed_from_u64(31);
        let qi = Modulus::new(4611686018427322369).unwrap();
        for length in 1..=7 {
            for _ in 0..64 {
                let a: Vec<_> = (0..length).map(|_| rng.next_u64()).collect();
                let b: Vec<_> = (0..length).map(|_| rng.next_u64()).collect();
                let as_big = |limbs: &[u64]| {
                    limbs
                        .iter()
                        .rev()
                        .fold(BigUint::from(0u32), |acc, &limb| (acc << 64) + limb)
                };
                assert_eq!(limbs_lt(&a, &b), as_big(&a) < as_big(&b));
                assert!(!limbs_lt(&a, &a));
                assert_eq!(BigUint::from(limbs_mod(&a, &qi)), as_big(&a) % *qi);
            }
        }
    }
}
