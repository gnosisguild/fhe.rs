//! Centered-uniform BigInt sampling, followed by signed-to-RNS conversion.

use crate::Error;
use crate::bfv::BfvParameters;
use crate::trbfv::{SmudgingBoundCalculator, SmudgingBoundCalculatorConfig};
use fhe_math::rq::{Poly, PowerBasis};
use num_bigint::{BigInt, BigUint};
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Noise generator for the SS smudging protocol.
///
/// Uses the common BigInt sampler, including its random-stream consumption.
/// Unlike synchronized local noise, generated noise must be Shamir-dealt before
/// partial decryption. BigInt sampling/conversion is variable-time;
/// owning the resulting polynomial does not erase transient BigInt allocations.
#[derive(Debug)]
pub struct SsSmudgingNoiseGenerator {
    params: Arc<BfvParameters>,
    smudging_bound: BigUint,
}

impl SsSmudgingNoiseGenerator {
    /// Calculate the smudging bound for this circuit and BFV configuration.
    pub fn new(config: SmudgingBoundCalculatorConfig) -> Result<Self, Error> {
        Self::from_bound_calculator(SmudgingBoundCalculator::new(config))
    }

    /// Retain calculator overrides, including RLK contributor count and initial
    /// ciphertext-noise bound.
    pub fn from_bound_calculator(calculator: SmudgingBoundCalculator) -> Result<Self, Error> {
        let params = calculator.noise_parameters().0.clone();
        let smudging_bound = calculator.calculate_sm_bound()?;
        Ok(Self::from_bound(params, smudging_bound))
    }

    /// Sample at an explicitly supplied bound.
    ///
    /// This low-level constructor does NOT check security, circuit assumptions,
    /// or feasibility. Prefer [`Self::new`] or [`Self::from_bound_calculator`].
    #[must_use]
    pub fn from_bound(params: Arc<BfvParameters>, smudging_bound: BigUint) -> Self {
        Self {
            params,
            smudging_bound,
        }
    }

    /// Sample centered integers, convert them to level-0 RNS,
    /// and return an owner consumed by [`super::super::ShareManager::generate_smudging_shares`].
    pub fn generate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<DealerSmudgingNoise, Error> {
        let coefficients = self.sample_uniform_coefficients(self.params.degree(), rng);
        DealerSmudgingNoise::from_signed_coefficients(&coefficients, &self.params)
    }

    fn sample_uniform_coefficients<R: RngCore + CryptoRng>(
        &self,
        count: usize,
        rng: &mut R,
    ) -> Vec<BigInt> {
        let bound = BigInt::from(self.smudging_bound.clone());
        fhe_math::rq::sample_uniform_coefficients_bigint(&bound, count, rng)
    }

    /// Number of coefficients in each sampled noise polynomial.
    #[must_use]
    pub fn degree(&self) -> usize {
        self.params.degree()
    }

    /// Maximum absolute sampled coefficient.
    #[must_use]
    pub fn smudging_bound(&self) -> &BigUint {
        &self.smudging_bound
    }
}

/// Fresh noise intended for Shamir dealing, not for synchronized PartDec.
///
/// This non-cloneable owner wipes its RNS polynomial on drop. Dealing consumes
/// it, including on failure. It is not the recipient's aggregate noise share.
///
/// ```compile_fail
/// use fhe::trbfv::DealerSmudgingNoise;
/// fn duplicate(noise: &DealerSmudgingNoise) -> DealerSmudgingNoise { noise.clone() }
/// ```
///
/// ```compile_fail
/// use fhe::trbfv::{DealerSmudgingNoise, ShareManager};
/// use rand::{CryptoRng, RngCore};
/// fn reuse<R: RngCore + CryptoRng>(manager: &mut ShareManager, noise: DealerSmudgingNoise, rng: &mut R) {
///     let _ = manager.generate_smudging_shares(noise, rng);
///     let _ = manager.generate_smudging_shares(noise, rng);
/// }
/// ```
pub struct DealerSmudgingNoise {
    pub(super) poly: Zeroizing<Poly<PowerBasis>>,
}

impl DealerSmudgingNoise {
    /// Explicitly import caller-sampled integers, using signed-to-RNS conversion.
    /// Checks length, not bounds, freshness, or uniformity.
    ///
    /// Useful when retaining signed proof witnesses. Callers must justify the
    /// sampling distribution and bound and erase retained integer copies.
    /// Prefer the generator when no signed witness is needed.
    pub fn from_signed_coefficients(
        coefficients: &[BigInt],
        params: &Arc<BfvParameters>,
    ) -> Result<Self, Error> {
        let poly = Poly::<PowerBasis>::from_bigints(coefficients, params.context_at_level(0)?)?;
        Ok(Self { poly })
    }
}

impl std::fmt::Debug for DealerSmudgingNoise {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DealerSmudgingNoise")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::bfv::BfvParametersBuilder;
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
    fn sampling_uses_the_common_bigint_sampler_without_extra_random_draws() {
        let params = params();
        for bits in [0usize, 1, 63, 64, 65, 127, 129, 330] {
            let bound = (BigUint::from(1u32) << bits) - 1u32;
            let generator = SsSmudgingNoiseGenerator::from_bound(params.clone(), bound.clone());
            let mut rng = ChaCha8Rng::seed_from_u64(900 + bits as u64);
            let mut expected_rng = rng.clone();
            let coefficients = fhe_math::rq::sample_uniform_coefficients_bigint(
                &BigInt::from(bound),
                params.degree(),
                &mut expected_rng,
            );
            let expected = Poly::<PowerBasis>::from_bigints(
                &coefficients,
                params.context_at_level(0).unwrap(),
            )
            .unwrap();
            let noise = generator.generate(&mut rng).unwrap();
            assert_eq!(noise.poly.coefficients(), expected.coefficients());
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
        }
    }

    #[test]
    fn sampled_coefficients_are_bounded_and_consistent_across_rns_rows() {
        let params = params();
        for bits in [0usize, 1, 63, 64, 65, 127, 129, 330] {
            let bound = (BigUint::from(1u32) << bits) - 1u32;
            let generator = SsSmudgingNoiseGenerator::from_bound(params.clone(), bound.clone());
            let mut rng = ChaCha8Rng::seed_from_u64(1000 + bits as u64);
            let noise = generator.generate(&mut rng).unwrap();
            let q = noise.poly.ctx().modulus();
            for (column, value) in Vec::<BigUint>::from(noise.poly.as_ref())
                .into_iter()
                .enumerate()
            {
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
                        BigInt::from(noise.poly.coefficients()[[row, column]]),
                        expected
                    );
                }
            }
            assert_eq!(format!("{noise:?}"), "DealerSmudgingNoise { .. }");
        }
    }

    #[test]
    fn signed_coefficient_import_preserves_endpoints_and_checks_length() {
        let params = params();
        let mut coefficients = vec![BigInt::from(0); params.degree()];
        coefficients[0] = BigInt::from(-5);
        coefficients[1] = BigInt::from(5);
        let noise = DealerSmudgingNoise::from_signed_coefficients(&coefficients, &params).unwrap();
        for (row, &q) in params.moduli().iter().enumerate() {
            assert_eq!(noise.poly.coefficients()[[row, 0]], q - 5);
            assert_eq!(noise.poly.coefficients()[[row, 1]], 5);
        }
        for length in [0, params.degree() - 1, params.degree() + 1] {
            assert!(
                DealerSmudgingNoise::from_signed_coefficients(
                    &vec![BigInt::from(0); length],
                    &params
                )
                .is_err()
            );
        }
    }
}
