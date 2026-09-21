//! Share collection and management for threshold BFV.
//!
//! This module provides the ShareManager struct that handles aggregation of secret shares
//! and computation of decryption shares in the threshold BFV scheme.

mod secret_key;
mod smudging;

pub use secret_key::{AggregatedSecretKeyShare, DealtSecretKeyShares, SecretKeyShare};
pub use smudging::{AggregatedSmudgingShare, DealtSmudgingShares, SmudgingShare};

use crate::Error;
use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::rns_shamir::RnsShamir;
use crate::trbfv::config::validate_threshold_config;
use crate::trbfv::smudging::SmudgingNoise;
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::zq::Modulus;
use fhe_math::{
    rns::{RnsContext, ScalingFactor},
    rq::{Context, Poly, PowerBasis, scaler::Scaler},
};
use itertools::Itertools;
use ndarray::Array2;
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use std::convert::TryFrom;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Manager for threshold BFV share operations.
///
/// ShareManager coordinates the collection and processing of secret shares in the threshold BFV scheme.
/// It handles both the aggregation of collected shares and the computation of decryption shares.
///
/// # Threshold semantics
///
/// `threshold` is the degree `T` of the Shamir sharing polynomial, read as the
/// maximum number of corrupted parties the deployment tolerates. Reconstruction
/// requires `T + 1` shares. `ShareManager` enforces the trBFV invariants
/// `n >= 3` and `T = (n - 1) / 2` (see [`validate_threshold_config`]).
///
/// # Protocol Flow
/// 1. Each party generates secret shares using secret sharing
/// 2. Parties exchange shares through secure channels
/// 3. ShareManager aggregates collected shares to reconstruct partial secrets
/// 4. During decryption, ShareManager computes decryption shares from ciphertext
/// 5. Finally, threshold number of decryption shares are combined to decrypt
///
/// The party count and threshold are immutable after construction so callers
/// cannot bypass the validated honest-majority configuration.
///
/// ```compile_fail
/// # use fhe::trbfv::ShareManager;
/// fn reconfigure(manager: &mut ShareManager) {
///     manager.n = 7;
///     manager.threshold = 3;
/// }
/// ```
#[derive(Debug)]
pub struct ShareManager {
    /// Number of parties in the threshold scheme (must be `>= 3`)
    n: usize,
    /// Degree `T` of the Shamir sharing polynomial, i.e. the maximum number of
    /// corrupted parties the deployment tolerates (must equal `(n - 1) / 2`).
    /// Reconstruction requires `T + 1` shares.
    threshold: usize,
    /// BFV parameters (degree, moduli, etc.)
    params: Arc<BfvParameters>,
}

impl ShareManager {
    /// Create a new share manager.
    ///
    /// # Arguments
    /// - `n`: Total number of parties (must be `>= 3`)
    /// - `threshold`: Degree `T` of the Shamir sharing polynomial, i.e. the
    ///   maximum number of corrupted parties the deployment tolerates. Must
    ///   equal `(n - 1) / 2`; reconstruction requires `T + 1` shares.
    /// - `params`: BFV parameters
    ///
    /// # Errors
    /// Returns an error if `n < 3` or `threshold != (n - 1) / 2` (a degree-0
    /// sharing polynomial would reveal the secret to every party), if the
    /// parameters have no moduli, or if `n` is not smaller than the smallest
    /// modulus (the MPC protocol assumes the Shamir evaluation points `1..=n`
    /// are distinct units modulo every modulus).
    pub fn new(n: usize, threshold: usize, params: Arc<BfvParameters>) -> Result<Self, Error> {
        // Enforce the `n >= 3` and `T = (n - 1) / 2` invariants of the trBFV protocol.
        validate_threshold_config(n, threshold)?;

        let min_modulus = params
            .moduli()
            .iter()
            .min()
            .ok_or(fhe_math::Error::EmptyModuli)?;
        if n >= usize::try_from(*min_modulus).unwrap_or(usize::MAX) {
            return Err(Error::party_count_exceeds_modulus(n, *min_modulus));
        }

        Ok(Self {
            n,
            threshold,
            params,
        })
    }

    /// Returns the number of parties in the threshold scheme.
    #[must_use]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Returns the degree of the Shamir sharing polynomial.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Returns the BFV parameters used by this manager.
    #[must_use]
    pub fn params(&self) -> &Arc<BfvParameters> {
        &self.params
    }
}

impl ShareManager {
    /// Utility to create a Zeroizing<Poly> from coefficients.
    ///
    /// # Arguments
    /// - `coeffs`: Coefficients that can be converted to Poly (Box<[i64]>, Array2<u64>, etc.)
    /// - `ctx`: BFV context to use for the polynomial
    ///
    /// # Returns
    /// A Zeroizing<Poly> in PowerBasis representation
    pub fn coeffs_to_poly<T>(
        &self,
        coeffs: T,
        ctx: &Arc<Context>,
    ) -> Result<Zeroizing<Poly<PowerBasis>>, Error>
    where
        Poly<PowerBasis>: TryConvertFrom<T>,
    {
        let poly = Poly::<PowerBasis>::try_convert_from(coeffs, ctx, false)?;
        Ok(Zeroizing::new(poly))
    }

    /// Convenience method using level 0 context from parameters.
    pub fn coeffs_to_poly_level0<T>(&self, coeffs: T) -> Result<Zeroizing<Poly<PowerBasis>>, Error>
    where
        Poly<PowerBasis>: TryConvertFrom<T>,
    {
        let ctx = self.params.context_at_level(0)?;
        self.coeffs_to_poly(coeffs, ctx)
    }
    /// Generate Shamir Secret Shares for smudging noise from a noise owner.
    ///
    /// This is the supported dealing operation for freshly sampled smudging
    /// noise: it consumes the [`SmudgingNoise`] owner and deals the
    /// underlying polynomial with the same layout as
    /// [`ShareManager::generate_secret_key_shares`].
    pub fn generate_smudging_shares<R: RngCore + CryptoRng>(
        &self,
        noise: SmudgingNoise,
        rng: &mut R,
    ) -> Result<DealtSmudgingShares, Error> {
        self.deal_poly(noise.into_poly(), rng)
            .map(DealtSmudgingShares::new)
    }

    /// Aggregate dealt smudging shares into one single-use decryption owner.
    ///
    /// The input shares are consumed.  This operation is intentionally
    /// separate from ordinary secret-key aggregation so smudging material
    /// cannot silently flow through a generic polynomial API.
    pub fn aggregate_smudging_shares(
        &self,
        shares: Vec<SmudgingShare>,
    ) -> Result<AggregatedSmudgingShare, Error> {
        let matrices: Vec<Array2<u64>> = shares
            .into_iter()
            .map(SmudgingShare::into_transport)
            .collect();
        self.aggregate_collected_matrices(matrices.iter())
            .map(AggregatedSmudgingShare::new)
    }

    /// Aggregate collected secret-key shares into a reusable owner.
    ///
    /// The input owners are consumed, while the resulting aggregate may be
    /// borrowed for any number of decryptions in the same key epoch.
    pub fn aggregate_secret_key_shares(
        &self,
        shares: Vec<SecretKeyShare>,
    ) -> Result<AggregatedSecretKeyShare, Error> {
        // Borrow the matrices while aggregating so malformed-input errors still
        // drop the owning SecretKeyShare values through their zeroizing Drop
        // implementation. The owners are consumed by this method regardless
        // of whether aggregation succeeds.
        self.aggregate_collected_matrices(shares.iter().map(|share| &share.coefficients))
            .map(AggregatedSecretKeyShare::from_power_basis)
    }

    /// Generate Shamir Secret Shares for polynomial coefficients from a pre-converted Poly.
    ///
    /// # One-time use
    ///
    /// Unlike [`ShareManager::generate_smudging_shares`],
    /// this method accepts any caller-provided polynomial and therefore
    /// cannot enforce one-time use: nothing here prevents dealing the same
    /// polynomial twice. Callers dealing smudging noise must sample it fresh
    /// for every decryption; reusing noise breaks the statistical hiding
    /// argument.
    pub fn generate_secret_key_shares<R: RngCore + CryptoRng>(
        &self,
        poly: Zeroizing<Poly<PowerBasis>>,
        rng: &mut R,
    ) -> Result<DealtSecretKeyShares, Error> {
        self.deal_poly(poly, rng).map(DealtSecretKeyShares::new)
    }

    fn deal_poly<R: RngCore + CryptoRng>(
        &self,
        poly: Zeroizing<Poly<PowerBasis>>,
        rng: &mut R,
    ) -> Result<Vec<Array2<u64>>, Error> {
        let ctx = self.params.context_at_level(0)?;
        if poly.ctx().as_ref() != ctx.as_ref() {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::Parameters,
            });
        }

        RnsShamir::new(
            ctx.moduli_operators(),
            self.params.degree(),
            self.n,
            self.threshold,
        )?
        .share(poly.coefficients(), rng)
        .map(|shares| shares.into_matrices())
    }
    /// Aggregate collected secret sharing shares to compute SK_i polynomial sum.
    ///
    /// This function takes shares collected from other parties and aggregates them
    /// to compute this party's share of the joint secret (the sum of the dealt
    /// secrets) needed for decryption.
    ///
    /// # Input invariant
    ///
    /// Every entry of every contribution matrix must be a canonical residue in
    /// `[0, q_i)`, where `q_i` is the modulus of the entry's row. Shares produced
    /// by [`ShareManager::generate_secret_key_shares`] already satisfy this
    /// invariant, but aggregation re-checks it because it is an input boundary for
    /// externally supplied matrices. Out-of-range entries are treated as malformed
    /// and rejected with `Error::Threshold(ThresholdError::MalformedShares { .. })`;
    /// they are never reduced or otherwise repaired.
    ///
    /// # Arguments
    /// - `collected`: One share matrix per contributing party (at most `n`;
    ///   fewer is allowed, e.g. when some parties aborted during dealing).
    ///   Each Array2<u64> has one row per modulus and one column per coefficient.
    ///
    /// # Returns
    /// A polynomial representing the aggregated secret key material
    ///
    /// # Errors
    /// Returns an error if no shares are provided, if more than `n` matrices are
    /// provided, if any matrix does not have shape `[moduli, degree]`, or if any
    /// coefficient is not a canonical residue below its row's modulus (`>= q_i` is
    /// malformed, never reduced).
    fn aggregate_collected_matrices<'a, I>(&self, matrices: I) -> Result<Poly<PowerBasis>, Error>
    where
        I: IntoIterator<Item = &'a Array2<u64>>,
    {
        let collected: Vec<&Array2<u64>> = matrices.into_iter().collect();
        if collected.is_empty() {
            return Err(Error::share_count_mismatch(0, 1));
        }
        if collected.len() > self.n {
            return Err(Error::share_count_mismatch(collected.len(), self.n));
        }
        let expected_shape = (self.params.moduli().len(), self.params.degree());
        for (party_idx, item) in collected.iter().enumerate() {
            if item.dim() != expected_shape {
                return Err(Error::malformed_shares(
                    party_idx,
                    format!(
                        "share matrix has shape {:?}, expected {expected_shape:?}",
                        item.dim()
                    ),
                ));
            }
        }
        let ctx = self.params.context_at_level(0)?;

        // Every coefficient of every contribution must be a canonical residue
        // below its own row's modulus `q_i` before anything is accumulated:
        // Modulus::add_vec below requires canonical inputs (it aborts or wraps
        // otherwise). Reducing here would silently accept malformed share
        // material and could change the represented share, so values `>= q_i`
        // are rejected instead. Shape was validated above, so the fallible
        // `moduli().get(row)` lookup is expected to succeed, but in keeping with
        // the workspace convention it stays fallible rather than indexed.
        for (party_idx, item) in collected.iter().enumerate() {
            for (row, item_row) in item.rows().into_iter().enumerate() {
                let q_i = self.params.moduli().get(row).copied().ok_or_else(|| {
                    Error::malformed_shares(party_idx, "modulus index out of range".to_string())
                })?;
                for (col, &value) in item_row.iter().enumerate() {
                    if value >= q_i {
                        return Err(Error::malformed_shares(
                            party_idx,
                            format!(
                                "share coefficient at row {row} (modulus q_i = {q_i}), column \
                                 {col} is not a canonical residue in [0, {q_i})"
                            ),
                        ));
                    }
                }
            }
        }

        // Sum the share matrices row-wise modulo each RNS modulus, copying
        // only once into the result polynomial (instead of cloning each
        // contribution into its own Poly and adding those).
        let mut sum = Array2::<u64>::zeros(expected_shape);
        for (row, mut acc_row) in sum.outer_iter_mut().enumerate() {
            let &modulus = self.params.moduli().get(row).ok_or_else(|| {
                Error::malformed_shares(row, "modulus index out of range".to_string())
            })?;
            let q = Modulus::new(modulus).map_err(Error::MathError)?;
            let acc = acc_row
                .as_slice_mut()
                .ok_or(fhe_math::Error::NonContiguousCoefficients)?;
            for item in &collected {
                let item_row = item.row(row);
                let share = item_row
                    .as_slice()
                    .ok_or(fhe_math::Error::NonContiguousCoefficients)?;
                q.add_vec(acc, share);
            }
        }

        let mut sum_poly = Poly::<PowerBasis>::zero(ctx);
        sum_poly.set_coefficients(sum);
        Ok(sum_poly)
    }

    /// Compute a decryption share from ciphertext and owned secret-key/smudging
    /// shares.
    ///
    /// This function computes a party's contribution to the threshold decryption process.
    /// Each party uses their aggregated key and noise shares to compute a decryption share.
    ///
    /// # Arguments
    /// - `ciphertext`: The ciphertext to decrypt (contains c0, c1 polynomials)
    /// - `secret_key`: This party's aggregated share of the joint secret key (output of
    ///   [`ShareManager::aggregate_secret_key_shares`]), not a party's own secret key
    /// - `smudging`: This party's aggregated share of the joint smudging noise,
    ///   aggregated the same way from the dealt noise shares
    ///
    /// # Returns
    /// A decryption share polynomial that contributes to the final decryption
    #[allow(clippy::indexing_slicing)] // BFV ciphertext always has exactly 2 components
    pub fn decryption_share(
        &self,
        ciphertext: Arc<Ciphertext>,
        secret_key: &AggregatedSecretKeyShare,
        smudging: AggregatedSmudgingShare,
    ) -> Result<Poly<PowerBasis>, Error> {
        self.validate_ciphertext(&ciphertext)?;
        let mut c0 = ciphertext.c[0].clone();
        c0.disallow_variable_time_computations();
        let c0 = c0.into_power_basis();
        let mut c1 = ciphertext.c[1].clone();
        c1.disallow_variable_time_computations();
        let secret_key = secret_key.as_ntt();
        let mut smudging = smudging.into_poly();
        smudging.disallow_variable_time_computations();
        if secret_key.ctx() != c1.ctx() || smudging.ctx() != c0.ctx() {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::Ciphertext,
            });
        }
        let ciphertext_times_secret_key = (&c1 * secret_key).into_power_basis();
        // Move the consumed noise into the returned share while leaving a
        // zero polynomial behind for the zeroizing owner to drop. The
        // zeroize crate's `Zeroizing` wrapper intentionally has no
        // `into_inner`; replacing it avoids an unsafe extraction that would
        // bypass the wipe-on-drop guarantee.
        let ctx = smudging.ctx().clone();
        let replacement = Poly::zero(&ctx);
        let smudging = std::mem::replace(&mut *smudging, replacement);
        let decryption_share = c0 + ciphertext_times_secret_key + smudging;
        Ok(decryption_share)
    }

    /// Decrypt ciphertext from collected decryption shares.
    ///
    /// This function performs the final step of threshold decryption by combining
    /// decryption shares from exactly `threshold + 1` parties to reconstruct the plaintext.
    ///
    /// # Arguments
    /// - `decryption_shares`: Exactly `threshold + 1` decryption shares
    /// - `reconstructing_parties`: The 1-based party indices the shares came from, in
    ///   the same order as `decryption_shares`; indices must be distinct and in `1..=n`
    /// - `ciphertext`: The original ciphertext being decrypted
    ///
    /// # Returns
    /// The decrypted plaintext
    // All indexing is on vectors built with known sizes matching the index ranges
    #[allow(clippy::indexing_slicing)]
    pub fn decrypt_from_shares(
        &self,
        decryption_shares: Vec<Poly<PowerBasis>>,
        reconstructing_parties: Vec<usize>,
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext, Error> {
        self.validate_ciphertext_parameters(&ciphertext)?;
        let ctx = self.params.context_at_level(0)?;
        for decryption_share in &decryption_shares {
            if decryption_share.ctx().as_ref() != ctx.as_ref() {
                return Err(Error::ParameterMismatch {
                    left: crate::ParameterSource::Polynomial,
                    right: crate::ParameterSource::Parameters,
                });
            }
        }
        let share_views: Vec<_> = decryption_shares
            .iter()
            .map(|share| share.coefficients())
            .collect();
        let arr_matrix = RnsShamir::new(
            ctx.moduli_operators(),
            self.params.degree(),
            self.n,
            self.threshold,
        )?
        .reconstruct(&share_views, &reconstructing_parties)?
        .into_matrix();
        self.validate_ciphertext_shape(&ciphertext)?;

        // Scale the reconstructed polynomial into the plaintext space.
        let mut result_poly = Poly::<PowerBasis>::zero(ctx);
        result_poly.set_coefficients(arr_matrix);

        let plaintext_ctx = Context::new_arc(&self.params.moduli()[..1], self.params.degree())
            .map_err(Error::MathError)?;

        let scalers: Result<Vec<_>, Error> = (0..self.params.moduli().len())
            .into_par_iter()
            .map(|i| {
                let rns = RnsContext::new(&self.params.moduli()[..self.params.moduli().len() - i])
                    .map_err(Error::MathError)?;
                let ctx_i = Context::new_arc(
                    &self.params.moduli()[..self.params.moduli().len() - i],
                    self.params.degree(),
                )
                .map_err(Error::MathError)?;
                Scaler::new(
                    &ctx_i,
                    &plaintext_ctx,
                    ScalingFactor::new(&BigUint::from(self.params.plaintext()), rns.modulus()),
                )
                .map_err(Error::MathError)
            })
            .collect();
        let scalers = scalers?;

        let par = ciphertext.params.clone();
        let ptxt_u64 = par.plaintext.as_u64().ok_or_else(|| {
            Error::ParametersError(crate::ParametersError::UnsupportedPlaintextModulus {
                reason: "threshold BFV decrypt_from_shares requires a u64 plaintext modulus"
                    .to_string(),
            })
        })?;

        let d = Zeroizing::new(
            result_poly
                .scale(&scalers[ciphertext.level])
                .map_err(Error::MathError)?,
        );
        let v = Zeroizing::new(
            Vec::<u64>::try_from(d.as_ref())
                .map_err(Error::from)?
                .into_iter()
                .map(|vi| vi + ptxt_u64)
                .collect_vec(),
        );
        let mut w = v[..par.degree()].to_vec();
        let q = Modulus::new(par.moduli()[0]).map_err(Error::MathError)?;
        q.reduce_vec(&mut w);
        Modulus::new(ptxt_u64)
            .map_err(Error::MathError)?
            .reduce_vec(&mut w);

        let poly =
            Poly::<PowerBasis>::try_convert_from(&w, ciphertext.c[0].ctx(), false)?.into_ntt();

        let pt = Plaintext {
            params: par.clone(),
            encoding: None,
            poly_ntt: poly,
        };
        Ok(pt)
    }

    /// Validate the ciphertext accepted by threshold decryption.
    fn validate_ciphertext(&self, ciphertext: &Ciphertext) -> Result<(), Error> {
        self.validate_ciphertext_parameters(ciphertext)?;
        self.validate_ciphertext_shape(ciphertext)
    }

    fn validate_ciphertext_parameters(&self, ciphertext: &Ciphertext) -> Result<(), Error> {
        if ciphertext.params != self.params {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Ciphertext,
                right: crate::ParameterSource::Parameters,
            });
        }
        if ciphertext.level != 0 {
            return Err(Error::InvalidLevel {
                level: ciphertext.level,
                min_level: 0,
                max_level: 0,
            });
        }
        Ok(())
    }

    fn validate_ciphertext_shape(&self, ciphertext: &Ciphertext) -> Result<(), Error> {
        // A degree-2 (unrelinearized) ciphertext has 3 components; silently
        // ignoring c[2] would produce a wrong plaintext.
        if ciphertext.c.len() != 2 {
            return Err(crate::CiphertextError::InvalidPolynomialCount {
                operation: crate::CiphertextOperation::MultipartyKeySwitch,
                actual: ciphertext.c.len(),
                expected: 2,
            }
            .into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic
    )]
    use super::*;
    use crate::ThresholdError;
    use crate::bfv::{Encoding, PublicKey, SecretKey};
    use crate::support::{insecure, secure8192};
    use crate::trbfv::smudging::{SmudgingConfig, SmudgingNoiseGenerator};
    use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
    use rand::rng;

    #[test]
    fn test_share_manager_creation() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        assert_eq!(manager.n(), 5);
        assert_eq!(manager.threshold(), 2);
        assert_eq!(manager.params(), &params);
    }

    #[test]
    fn test_share_manager_rejects_threshold_zero() {
        // A degree-0 Shamir sharing polynomial is the secret itself, so every
        // party would hold the full secret.
        let params = insecure().unwrap().parameters;
        let err = ShareManager::new(5, 0, params)
            .expect_err("threshold 0 must be rejected (degree-0 sharing reveals the secret)");
        assert!(matches!(
            err,
            Error::Threshold(ThresholdError::InvalidThreshold {
                threshold: 0,
                n: 5,
                expected: 2
            })
        ));
    }

    #[test]
    fn test_share_manager_rejects_invalid_threshold_config() {
        let params = insecure().unwrap().parameters;

        for (n, threshold) in [(0usize, 1usize), (1, 0), (1, 1), (2, 0), (2, 1)] {
            assert!(
                ShareManager::new(n, threshold, params.clone()).is_err(),
                "ShareManager::new({n}, {threshold}) must be rejected"
            );
        }

        for n in [3usize, 5, 20] {
            assert!(
                ShareManager::new(n, 0, params.clone()).is_err(),
                "ShareManager::new({n}, 0) must be rejected"
            );
        }

        for (n, threshold) in [(5usize, 3usize), (5, 4), (5, 5), (5, 6), (3, 2)] {
            assert!(
                ShareManager::new(n, threshold, params.clone()).is_err(),
                "ShareManager::new({n}, {threshold}) must be rejected"
            );
        }

        for (n, threshold) in [(20usize, 8usize), (20, 7), (10, 3)] {
            assert!(
                ShareManager::new(n, threshold, params.clone()).is_err(),
                "ShareManager::new({n}, {threshold}) must be rejected"
            );
        }

        assert!(ShareManager::new(20, 10, params.clone()).is_err());
        assert!(ShareManager::new(4, 2, params.clone()).is_err());
    }

    #[test]
    fn test_share_manager_accepts_valid_threshold_config() {
        let params = insecure().unwrap().parameters;
        for (n, threshold) in [(3usize, 1usize), (4, 1), (5, 2), (10, 4), (20, 9), (21, 10)] {
            let manager = ShareManager::new(n, threshold, params.clone())
                .expect("a valid threshold config must be accepted");
            assert_eq!(manager.n(), n);
            assert_eq!(manager.threshold(), threshold);
        }
    }

    #[test]
    fn test_coeffs_to_poly_utility() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();

        // Test with i64 coefficients
        let coeffs = vec![1i64, 2, 3, 4].into_boxed_slice();
        let ctx = params.context_at_level(0).unwrap();
        let poly = manager.coeffs_to_poly(coeffs.as_ref(), ctx).unwrap();
        assert_eq!(poly.ctx(), ctx);

        // Test convenience method
        let coeffs2 = vec![5i64, 6, 7, 8].into_boxed_slice();
        let poly2 = manager.coeffs_to_poly_level0(coeffs2.as_ref()).unwrap();
        assert_eq!(poly2.ctx(), ctx);
    }

    #[test]
    fn test_smudging_noise_dealing_consumes_owner() {
        let params = insecure().unwrap().parameters;
        let n = 5;
        let threshold = 2;
        let manager = ShareManager::new(n, threshold, params.clone()).unwrap();
        let mut rng = rng();

        let generator =
            SmudgingNoiseGenerator::new(SmudgingConfig::new(params.clone(), n, 1, 0).unwrap())
                .unwrap();
        let noise = generator.generate(&mut rng).unwrap();
        let shares = manager
            .generate_smudging_shares(noise, &mut rng)
            .unwrap()
            .into_transport();

        // Same layout as secret-key dealing: one [n, degree] matrix per modulus.
        assert_eq!(shares.len(), params.moduli().len());
        for (share_matrix, &qi) in shares.into_iter().zip(params.moduli().iter()) {
            assert_eq!(share_matrix.dim(), (n, params.degree()));
            for &value in share_matrix.iter() {
                assert!(value < qi);
            }
        }
        // The one-time owner is moved into the call above and cannot be dealt twice.
    }

    #[test]
    fn smudging_noise_deals_shares() {
        let params = secure8192().unwrap().parameters;
        let n = 3;
        let threshold = 1;
        let manager = ShareManager::new(n, threshold, params.clone()).unwrap();
        let mut rng = rng();

        // The supported flow: compute the bound with the smudging machinery,
        // sample the noise, and deal it into Shamir shares immediately.
        let config = SmudgingConfig::new(params.clone(), n, 1, 45).unwrap();
        let generator = SmudgingNoiseGenerator::new(config).unwrap();
        let noise = generator.generate(&mut rng).unwrap();
        let shares = manager
            .generate_smudging_shares(noise, &mut rng)
            .unwrap()
            .into_transport();
        assert_eq!(shares.len(), params.moduli().len());
        for share_matrix in &shares {
            assert_eq!(share_matrix.dim(), (n, params.degree()));
        }
        // Smudging noise at a secure bound is overwhelmingly nonzero.
        assert!(
            shares.iter().any(|m| m.iter().any(|&c| c != 0)),
            "secure smudging shares should not all be zero"
        );
    }

    #[test]
    fn test_share_generation_rejects_wrong_context_and_noncanonical_secret() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let mut rng = rng();

        let wrong_context = params.context_at_level(1).unwrap();
        let wrong_context_poly = Zeroizing::new(Poly::<PowerBasis>::zero(wrong_context));
        assert!(matches!(
            manager.generate_secret_key_shares(wrong_context_poly, &mut rng),
            Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::Parameters,
            })
        ));

        let context = params.context_at_level(0).unwrap();
        let mut noncanonical = Poly::<PowerBasis>::zero(context);
        let mut coefficients = Array2::zeros((params.moduli().len(), params.degree()));
        coefficients[[1, 7]] = params.moduli()[1];
        noncanonical.set_coefficients(coefficients);
        let error = manager
            .generate_secret_key_shares(Zeroizing::new(noncanonical), &mut rng)
            .expect_err("noncanonical secret coefficients must be rejected");
        assert!(matches!(
            error,
            Error::Threshold(ThresholdError::MalformedShares { .. })
        ));
    }

    #[test]
    fn test_decryption_share_computation() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let n = 3;
        // ShareManager now enforces T = (n - 1) / 2, so the minimal valid
        // configuration is (n = 3, threshold = 1), requiring two shares.
        let threshold = 1;
        let manager = ShareManager::new(n, threshold, params.clone()).unwrap();

        // Setup: Generate keys and encrypt a plaintext
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let mut plaintext_data = vec![42u64, 10, 40];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct: Arc<Ciphertext> = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Generate polynomials for decryption share.
        let mut secret_key_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
        let ctx = params.context_at_level(0).unwrap();
        let variable_time = fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
        secret_key_poly.allow_variable_time_computations(variable_time);
        let mut smudging_poly = Poly::<PowerBasis>::zero(ctx);
        smudging_poly.allow_variable_time_computations(variable_time);
        assert!(ct.c[1].allows_variable_time_computations());
        let key_share = AggregatedSecretKeyShare::from_power_basis((*secret_key_poly).clone());

        // Compute decryption share.
        let decryption_share = manager
            .decryption_share(
                ct.clone(),
                &key_share,
                AggregatedSmudgingShare::new(smudging_poly),
            )
            .unwrap();
        assert!(!decryption_share.allows_variable_time_computations());

        // The aggregated key owner is reusable; only the smudging owner is
        // consumed by each decryption-share computation.
        let second_decryption_share = manager
            .decryption_share(
                ct.clone(),
                &key_share,
                AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(
                    params.context_at_level(0).unwrap(),
                )),
            )
            .unwrap();
        assert!(!second_decryption_share.allows_variable_time_computations());

        // This test uses the full secret as the "aggregate" for both parties;
        // two identical values at distinct Shamir x-coordinates reconstruct the
        // same value needed for plaintext recovery.
        let shares = vec![decryption_share, second_decryption_share];

        // Parties are 1-based; reconstruction needs threshold + 1 = 2 shares.
        let reconstructing = vec![1, 2];
        let result = manager.decrypt_from_shares(shares, reconstructing, ct);
        let plaintext_found = result.expect("Failed to decrypt from shares");

        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");

        assert_eq!(decoded, plaintext_data);
    }

    #[test]
    fn test_decryption_share_rejects_nonzero_ciphertext_level() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng);
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &params).unwrap();
        let mut ciphertext = public_key.try_encrypt(&plaintext, &mut rng).unwrap();
        ciphertext.switch_down().unwrap();

        let secret_poly = manager
            .coeffs_to_poly_level0(secret_key.coeffs.as_ref())
            .unwrap();
        let context = params.context_at_level(0).unwrap();
        let key_share = AggregatedSecretKeyShare::from_power_basis((*secret_poly).clone());
        let result = manager.decryption_share(
            Arc::new(ciphertext),
            &key_share,
            AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(context)),
        );

        assert_eq!(
            result,
            Err(Error::InvalidLevel {
                level: 1,
                min_level: 0,
                max_level: 0,
            })
        );
    }

    #[test]
    fn test_decrypt_from_shares_rejects_nonzero_ciphertext_level() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng);
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &params).unwrap();
        let mut ciphertext = public_key.try_encrypt(&plaintext, &mut rng).unwrap();
        ciphertext.switch_down().unwrap();

        let context = params.context_at_level(0).unwrap();
        let shares = vec![Poly::<PowerBasis>::zero(context)];
        let result = manager.decrypt_from_shares(shares, vec![1], Arc::new(ciphertext));

        assert_eq!(
            result,
            Err(Error::InvalidLevel {
                level: 1,
                min_level: 0,
                max_level: 0,
            })
        );
    }

    #[test]
    fn test_decrypt_from_shares_rejects_invalid_ciphertext_shape() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng);
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &params).unwrap();
        let mut ciphertext = public_key.try_encrypt(&plaintext, &mut rng).unwrap();
        ciphertext.c.pop();

        let context = params.context_at_level(0).unwrap();
        let result = manager.decrypt_from_shares(
            vec![
                Poly::<PowerBasis>::zero(context),
                Poly::<PowerBasis>::zero(context),
            ],
            vec![1, 2],
            Arc::new(ciphertext),
        );

        assert!(matches!(
            result,
            Err(Error::Ciphertext(
                crate::CiphertextError::InvalidPolynomialCount {
                    actual: 1,
                    expected: 2,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn test_threshold_decryption_workflow() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let n = 3;
        let threshold = 1;

        // Setup multiple share managers (simulating different parties)
        let managers: Vec<ShareManager> = (0..n)
            .map(|_| ShareManager::new(n, threshold, params.clone()).unwrap())
            .collect();

        // One party generates the secret key and secret shares it among the other parties
        let secret_key = SecretKey::random(&params, &mut rng);

        let secret_key_poly = managers[0]
            .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
            .unwrap();

        let secret_key_dealt = managers[0]
            .generate_secret_key_shares(secret_key_poly, &mut rng)
            .unwrap()
            .into_transport();

        let mut secret_key_collected: Vec<Vec<Array2<u64>>> = vec![vec![], vec![], vec![]];

        let mut secret_key_aggregates: Vec<Option<AggregatedSecretKeyShare>> =
            (0..n).map(|_| None).collect();

        for i in 0..n {
            let mut secret_key_rows = Array2::zeros((0, params.degree()));
            for secret_key_plane in secret_key_dealt.iter().take(params.moduli().len()) {
                secret_key_rows
                    .push_row(ndarray::ArrayView::from(secret_key_plane.row(i)))
                    .unwrap();
            }
            secret_key_collected[i].push(secret_key_rows);

            secret_key_aggregates[i] = Some(
                managers[i]
                    .aggregate_secret_key_shares(
                        std::mem::take(&mut secret_key_collected[i])
                            .into_iter()
                            .map(SecretKeyShare::from_transport)
                            .collect(),
                    )
                    .unwrap(),
            );
        }

        // Create a test ciphertext
        let pk = PublicKey::new(&secret_key, &mut rng);
        let mut plaintext_data = vec![23u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Each party generates their decryption share
        let mut decryption_shares = Vec::new();

        //Testing for decryption between parties 0 and 1
        //TODO Add tests for decyption between different parties than the first ones
        for i in 0..(threshold + 1) {
            let ctx = params.context_at_level(0).unwrap();
            //Setting smuding noise to be zero in this test
            let smudging_poly = Poly::<PowerBasis>::zero(ctx);

            let share = managers[i]
                .decryption_share(
                    ct.clone(),
                    secret_key_aggregates[i].as_ref().unwrap(),
                    AggregatedSmudgingShare::new(smudging_poly),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with parties 1 and 2 reconstructing
        let reconstructing = vec![1, 2];
        let result =
            managers[0].decrypt_from_shares(decryption_shares.clone(), reconstructing, ct.clone());
        assert!(result.is_ok());

        // Test if we had correct decyption
        let plaintext_found = result.expect("Failed to decrypt from shares");
        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");

        assert_eq!(decoded, plaintext_data);
    }

    #[test]
    fn test_threshold_decryption_workflow_arbitrary_parties_small() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let n = 5;
        let threshold = 2; // need 3 parties

        // Setup multiple share managers (simulating different parties)
        let managers: Vec<ShareManager> = (0..n)
            .map(|_| ShareManager::new(n, threshold, params.clone()).unwrap())
            .collect();

        // One party generates the secret key and secret shares it among the other parties
        let secret_key = SecretKey::random(&params, &mut rng);

        let secret_key_poly = managers[0]
            .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
            .unwrap();

        let secret_key_dealt = managers[0]
            .generate_secret_key_shares(secret_key_poly, &mut rng)
            .unwrap()
            .into_transport();

        let mut secret_key_collected: Vec<Vec<Array2<u64>>> =
            vec![vec![], vec![], vec![], vec![], vec![]];

        let mut secret_key_aggregates: Vec<Option<AggregatedSecretKeyShare>> =
            (0..n).map(|_| None).collect();

        for i in 0..n {
            let mut secret_key_rows = Array2::zeros((0, params.degree()));
            for secret_key_plane in secret_key_dealt.iter().take(params.moduli().len()) {
                secret_key_rows
                    .push_row(ndarray::ArrayView::from(secret_key_plane.row(i)))
                    .unwrap();
            }
            secret_key_collected[i].push(secret_key_rows);

            secret_key_aggregates[i] = Some(
                managers[i]
                    .aggregate_secret_key_shares(
                        std::mem::take(&mut secret_key_collected[i])
                            .into_iter()
                            .map(SecretKeyShare::from_transport)
                            .collect(),
                    )
                    .unwrap(),
            );
        }

        // Create a test ciphertext
        let pk = PublicKey::new(&secret_key, &mut rng);
        let mut plaintext_data = vec![32u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Choose arbitrary reconstructing parties (1-based indices): {2, 4, 5}
        // Corresponding 0-based indices in vectors: {1, 3, 4}
        let chosen_indices = vec![1usize, 3usize, 4usize];
        let reconstructing: Vec<usize> = chosen_indices.iter().map(|x| x + 1).collect();

        // Each chosen party generates their decryption share
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            let ctx = params.context_at_level(0).unwrap();
            let smudging_poly = Poly::<PowerBasis>::zero(ctx);
            let share = managers[i]
                .decryption_share(
                    ct.clone(),
                    secret_key_aggregates[i].as_ref().unwrap(),
                    AggregatedSmudgingShare::new(smudging_poly),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with selected parties
        let result =
            managers[0].decrypt_from_shares(decryption_shares.clone(), reconstructing, ct.clone());
        assert!(result.is_ok());

        // Validate plaintext
        let plaintext_found = result.expect("Failed to decrypt from shares");
        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");
        assert_eq!(decoded, plaintext_data);
    }

    #[test]
    fn test_threshold_decryption_workflow_arbitrary_parties_large() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let n = 20;
        let threshold = 9; // (n - 1) / 2 for n = 20; need 10 parties

        // Setup multiple share managers (simulating different parties)
        let managers: Vec<ShareManager> = (0..n)
            .map(|_| ShareManager::new(n, threshold, params.clone()).unwrap())
            .collect();

        // One party generates the secret key and secret shares it among the other parties
        let secret_key = SecretKey::random(&params, &mut rng);

        let secret_key_poly = managers[0]
            .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
            .unwrap();

        let secret_key_dealt = managers[0]
            .generate_secret_key_shares(secret_key_poly, &mut rng)
            .unwrap()
            .into_transport();

        let mut secret_key_collected: Vec<Vec<Array2<u64>>> = (0..n).map(|_| vec![]).collect();

        let mut secret_key_aggregates: Vec<Option<AggregatedSecretKeyShare>> =
            (0..n).map(|_| None).collect();

        for i in 0..n {
            let mut secret_key_rows = Array2::zeros((0, params.degree()));
            for secret_key_plane in secret_key_dealt.iter().take(params.moduli().len()) {
                secret_key_rows
                    .push_row(ndarray::ArrayView::from(secret_key_plane.row(i)))
                    .unwrap();
            }
            secret_key_collected[i].push(secret_key_rows);

            secret_key_aggregates[i] = Some(
                managers[i]
                    .aggregate_secret_key_shares(
                        std::mem::take(&mut secret_key_collected[i])
                            .into_iter()
                            .map(SecretKeyShare::from_transport)
                            .collect(),
                    )
                    .unwrap(),
            );
        }

        // Create a test ciphertext
        let pk = PublicKey::new(&secret_key, &mut rng);
        let mut plaintext_data = vec![77u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Choose arbitrary reconstructing parties (1-based indices):
        // {2,4,5,7,11,13,15,17,19,20}
        // Corresponding 0-based indices: {1,3,4,6,10,12,14,16,18,19}
        let chosen_indices = vec![
            1usize, 3usize, 4usize, 6usize, 10usize, 12usize, 14usize, 16usize, 18usize, 19usize,
        ];
        let reconstructing: Vec<usize> = chosen_indices.iter().map(|x| x + 1).collect();

        // Each chosen party generates their decryption share
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            let ctx = params.context_at_level(0).unwrap();
            let smudging_poly = Poly::<PowerBasis>::zero(ctx);
            let share = managers[i]
                .decryption_share(
                    ct.clone(),
                    secret_key_aggregates[i].as_ref().unwrap(),
                    AggregatedSmudgingShare::new(smudging_poly),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with selected parties
        let result =
            managers[0].decrypt_from_shares(decryption_shares.clone(), reconstructing, ct.clone());
        assert!(result.is_ok());

        // Validate plaintext
        let plaintext_found = result.expect("Failed to decrypt from shares");
        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");
        assert_eq!(decoded, plaintext_data);
    }

    #[test]
    fn test_threshold_decryption_wrong_indices_fails() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let n = 10;
        let threshold = 4; // need 5 parties

        // Setup multiple share managers (simulating different parties)
        let managers: Vec<ShareManager> = (0..n)
            .map(|_| ShareManager::new(n, threshold, params.clone()).unwrap())
            .collect();

        // One party generates the secret key and secret shares it among the other parties
        let secret_key = SecretKey::random(&params, &mut rng);

        let secret_key_poly = managers[0]
            .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
            .unwrap();

        let secret_key_dealt = managers[0]
            .generate_secret_key_shares(secret_key_poly, &mut rng)
            .unwrap()
            .into_transport();

        let mut secret_key_collected: Vec<Vec<Array2<u64>>> = (0..n).map(|_| vec![]).collect();

        let mut secret_key_aggregates: Vec<Option<AggregatedSecretKeyShare>> =
            (0..n).map(|_| None).collect();

        for i in 0..n {
            let mut secret_key_rows = Array2::zeros((0, params.degree()));
            for secret_key_plane in secret_key_dealt.iter().take(params.moduli().len()) {
                secret_key_rows
                    .push_row(ndarray::ArrayView::from(secret_key_plane.row(i)))
                    .unwrap();
            }
            secret_key_collected[i].push(secret_key_rows);

            secret_key_aggregates[i] = Some(
                managers[i]
                    .aggregate_secret_key_shares(
                        std::mem::take(&mut secret_key_collected[i])
                            .into_iter()
                            .map(SecretKeyShare::from_transport)
                            .collect(),
                    )
                    .unwrap(),
            );
        }

        // Create a test ciphertext
        let pk = PublicKey::new(&secret_key, &mut rng);
        let mut plaintext_data = vec![55u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Choose 5 fixed distinct parties (0-based): {0,2,3,6,8}
        let chosen_indices: Vec<usize> = vec![0usize, 2usize, 3usize, 6usize, 8usize];
        let reconstructing_correct: Vec<usize> = chosen_indices.iter().map(|x| x + 1).collect();

        // Each chosen party generates their decryption share
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            let ctx = params.context_at_level(0).unwrap();
            let smudging_poly = Poly::<PowerBasis>::zero(ctx);
            let share = managers[i]
                .decryption_share(
                    ct.clone(),
                    secret_key_aggregates[i].as_ref().unwrap(),
                    AggregatedSmudgingShare::new(smudging_poly),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Decrypt with correct indices -> should succeed and match plaintext
        let result_ok = managers[0].decrypt_from_shares(
            decryption_shares.clone(),
            reconstructing_correct.clone(),
            ct.clone(),
        );
        assert!(result_ok.is_ok());
        let plaintext_found_ok =
            result_ok.expect("Failed to decrypt from shares with correct indices");
        let decoded_ok: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found_ok, Encoding::poly())
            .expect("Decoding plaintext failed");
        assert_eq!(decoded_ok, plaintext_data);

        // Prepare wrong indices: replace one correct index with a non-selected party
        // Pick a fixed non-selected party: 5 (0-based), which is not in chosen_indices
        let non_selected: usize = 5;

        let mut reconstructing_wrong = reconstructing_correct.clone();
        reconstructing_wrong[0] = non_selected + 1; // introduce an incorrect party id (1-based)

        // Decrypt with wrong indices -> should not match plaintext (but may still return Ok)
        let result_bad = managers[0].decrypt_from_shares(
            decryption_shares.clone(),
            reconstructing_wrong,
            ct.clone(),
        );
        assert!(result_bad.is_ok());
        let plaintext_found_bad =
            result_bad.expect("Decryption unexpectedly failed with wrong indices");
        let decoded_bad: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found_bad, Encoding::poly())
            .expect("Decoding plaintext failed");
        assert_ne!(
            decoded_bad, plaintext_data,
            "Decryption should not match with wrong indices"
        );
    }

    #[test]
    fn test_aggregate_smudging_shares_rejects_bad_input() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let shape = (params.moduli().len(), params.degree());
        let share = || SmudgingShare::from_transport(Array2::zeros(shape));

        assert!(manager.aggregate_smudging_shares(Vec::new()).is_err());
        assert!(
            manager
                .aggregate_smudging_shares((0..4).map(|_| share()).collect())
                .is_err()
        );
        assert!(
            manager
                .aggregate_smudging_shares(vec![SmudgingShare::from_transport(Array2::zeros((
                    params.degree(),
                    params.moduli().len(),
                )))])
                .is_err()
        );

        let mut noncanonical = Array2::zeros(shape);
        noncanonical[[0, 0]] = params.moduli()[0];
        assert!(
            manager
                .aggregate_smudging_shares(vec![SmudgingShare::from_transport(noncanonical)])
                .is_err()
        );

        assert!(manager.aggregate_smudging_shares(vec![share()]).is_ok());
    }

    #[test]
    fn test_aggregate_secret_key_shares_rejects_bad_input() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let shape = (params.moduli().len(), params.degree());
        let share = || SecretKeyShare::from_transport(Array2::zeros(shape));

        assert!(manager.aggregate_secret_key_shares(Vec::new()).is_err());
        assert!(
            manager
                .aggregate_secret_key_shares((0..4).map(|_| share()).collect())
                .is_err()
        );
        assert!(
            manager
                .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(Array2::zeros((
                    params.degree(),
                    params.moduli().len(),
                )))])
                .is_err()
        );

        let mut noncanonical = Array2::zeros(shape);
        noncanonical[[0, 0]] = params.moduli()[0];
        assert!(
            manager
                .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(noncanonical)])
                .is_err()
        );

        assert!(manager.aggregate_secret_key_shares(vec![share()]).is_ok());
    }

    #[test]
    fn test_aggregate_secret_key_shares_rejects_non_canonical_q_at_each_row() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());

        // A coefficient equal to its row's modulus q_i is not a canonical
        // residue and must be rejected against that row's own modulus, not a
        // global bound shared across rows.
        for (row, &q_i) in moduli.iter().enumerate() {
            let mut coefficients = Array2::zeros(shape);
            coefficients[[row, 3]] = q_i;
            let err = manager
                .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(coefficients)])
                .expect_err("coefficient equal to the row modulus must be rejected");
            let Error::Threshold(ThresholdError::MalformedShares { party_id, reason }) = &err
            else {
                panic!("expected MalformedShares, got: {err}");
            };
            assert_eq!(*party_id, 0, "contribution index must be reported");
            assert!(
                reason.contains(&format!("row {row}")),
                "row index missing from reason: {reason}"
            );
            assert!(
                reason.contains("column 3"),
                "column index missing from reason: {reason}"
            );
            assert!(
                reason.contains(&q_i.to_string()),
                "expected row modulus (and offending value) missing from reason: {reason}"
            );
        }
    }

    #[test]
    fn test_aggregate_secret_key_shares_rejects_u64_max() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());

        // u64::MAX would wrap to a small residue if reduced; it must be
        // rejected as malformed instead of being reduced. The error reports
        // party, row, column, and modulus only: secret share values must not
        // appear in error strings.
        let mut coefficients = Array2::zeros(shape);
        coefficients[[0, 0]] = u64::MAX;
        let err = manager
            .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(coefficients)])
            .expect_err("u64::MAX share entry must be rejected");
        let Error::Threshold(ThresholdError::MalformedShares { party_id, reason }) = &err else {
            panic!("expected MalformedShares, got: {err}");
        };
        assert_eq!(*party_id, 0);
        assert!(
            reason.contains("row 0") && reason.contains("column 0"),
            "row/column context missing from reason: {reason}"
        );
        assert!(
            reason.contains(&moduli[0].to_string()),
            "row modulus missing from reason: {reason}"
        );
        assert!(
            !reason.contains(&u64::MAX.to_string()),
            "secret share value must not appear in reason: {reason}"
        );
    }

    #[test]
    fn test_aggregate_secret_key_shares_accepts_q_minus_one_boundary() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());

        // q_i - 1 is the largest valid canonical residue for each row; all
        // rows must be accepted against their own distinct moduli.
        let mut coefficients = Array2::zeros(shape);
        for (row, &q_i) in moduli.iter().enumerate() {
            coefficients.row_mut(row).fill(q_i - 1);
        }
        manager
            .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(coefficients)])
            .expect("maximal canonical residues must be accepted");
    }

    #[test]
    fn test_aggregate_secret_key_shares_rejects_invalid_after_valid() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());
        let q1 = moduli[1];

        // A valid first contribution followed by a malformed later one must
        // still surface the later contribution's error rather than reaching
        // Modulus::add_vec with the bad entry.
        let valid = SecretKeyShare::from_transport(Array2::zeros(shape));
        let mut invalid_coefficients = Array2::zeros(shape);
        invalid_coefficients[[1, 5]] = q1;
        let invalid = SecretKeyShare::from_transport(invalid_coefficients);
        let err = manager
            .aggregate_secret_key_shares(vec![valid, invalid])
            .expect_err("out-of-range entry in a later contribution must be rejected");
        let Error::Threshold(ThresholdError::MalformedShares { party_id, reason }) = &err else {
            panic!("expected MalformedShares, got: {err}");
        };
        assert_eq!(*party_id, 1, "the invalid contribution must be identified");
        assert!(
            reason.contains("row 1") && reason.contains("column 5"),
            "row/column context missing from reason: {reason}"
        );
    }

    #[test]
    fn test_decrypt_from_shares_rejects_invalid_party_indices() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let n = 5;
        let threshold = 2; // needs exactly 3 shares
        let manager = ShareManager::new(n, threshold, params.clone()).unwrap();

        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let pt = Plaintext::try_encode(&[1u64], Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        let ctx = params.context_at_level(0).unwrap();
        let shares: Vec<Poly<PowerBasis>> = (0..3).map(|_| Poly::<PowerBasis>::zero(ctx)).collect();

        // Duplicate index
        let result = manager.decrypt_from_shares(shares.clone(), vec![1, 2, 2], ct.clone());
        assert!(result.is_err());

        // Index 0 (would evaluate the sharing polynomial at the secret)
        let result = manager.decrypt_from_shares(shares.clone(), vec![0, 1, 2], ct.clone());
        assert!(result.is_err());

        // Index > n
        let result = manager.decrypt_from_shares(shares.clone(), vec![1, 2, 6], ct.clone());
        assert!(result.is_err());

        // Wrong share count: more than threshold + 1 is rejected
        let four: Vec<Poly<PowerBasis>> = (0..4).map(|_| Poly::<PowerBasis>::zero(ctx)).collect();
        let result = manager.decrypt_from_shares(four, vec![1, 2, 3, 4], ct.clone());
        assert!(result.is_err());

        // Shares from a different RNS level are rejected before reconstruction.
        let level_one = params.context_at_level(1).unwrap();
        let wrong_context: Vec<Poly<PowerBasis>> = (0..3)
            .map(|_| Poly::<PowerBasis>::zero(level_one))
            .collect();
        let result = manager.decrypt_from_shares(wrong_context, vec![1, 2, 3], ct.clone());
        assert!(matches!(result, Err(Error::ParameterMismatch { .. })));

        // Residues equal to a row modulus are malformed, not implicitly reduced.
        let mut noncanonical: Vec<Poly<PowerBasis>> =
            (0..3).map(|_| Poly::<PowerBasis>::zero(ctx)).collect();
        let mut coefficients = Array2::zeros((params.moduli().len(), params.degree()));
        coefficients[[0, 0]] = params.moduli()[0];
        noncanonical[1].set_coefficients(coefficients);
        let result = manager.decrypt_from_shares(noncanonical, vec![1, 2, 3], ct.clone());
        assert!(matches!(
            result,
            Err(Error::Threshold(ThresholdError::MalformedShares { .. }))
        ));

        // Fewer than threshold + 1 is rejected
        let two: Vec<Poly<PowerBasis>> = (0..2).map(|_| Poly::<PowerBasis>::zero(ctx)).collect();
        let result = manager.decrypt_from_shares(two, vec![1, 2], ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_decryption_random_party_order() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let n = 15;
        let threshold = 7; // need 8 parties

        // Setup multiple share managers (simulating different parties)
        let managers: Vec<ShareManager> = (0..n)
            .map(|_| ShareManager::new(n, threshold, params.clone()).unwrap())
            .collect();

        // One party generates the secret key and secret shares it among the other parties
        let secret_key = SecretKey::random(&params, &mut rng);

        let secret_key_poly = managers[0]
            .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
            .unwrap();

        let secret_key_dealt = managers[0]
            .generate_secret_key_shares(secret_key_poly, &mut rng)
            .unwrap()
            .into_transport();

        let mut secret_key_collected: Vec<Vec<Array2<u64>>> = (0..n).map(|_| vec![]).collect();

        let mut secret_key_aggregates: Vec<Option<AggregatedSecretKeyShare>> =
            (0..n).map(|_| None).collect();

        for i in 0..n {
            let mut secret_key_rows = Array2::zeros((0, params.degree()));
            for secret_key_plane in secret_key_dealt.iter().take(params.moduli().len()) {
                secret_key_rows
                    .push_row(ndarray::ArrayView::from(secret_key_plane.row(i)))
                    .unwrap();
            }
            secret_key_collected[i].push(secret_key_rows);

            secret_key_aggregates[i] = Some(
                managers[i]
                    .aggregate_secret_key_shares(
                        std::mem::take(&mut secret_key_collected[i])
                            .into_iter()
                            .map(SecretKeyShare::from_transport)
                            .collect(),
                    )
                    .unwrap(),
            );
        }

        // Create a test ciphertext
        let pk = PublicKey::new(&secret_key, &mut rng);
        let mut plaintext_data = vec![22u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Choose non-increasing reconstructing parties (0-based) of size threshold+1
        // Example: {9,10,14,7,5,3,2,1} => (1-based) {10,11,15,8,6,4,3,2}
        let chosen_indices = vec![
            9usize, 10usize, 14usize, 7usize, 5usize, 3usize, 2usize, 1usize,
        ];
        let reconstructing: Vec<usize> = chosen_indices.iter().map(|x| x + 1).collect();

        // Each chosen party generates their decryption share in the same (non-increasing) order
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            let ctx = params.context_at_level(0).unwrap();
            let smudging_poly = Poly::<PowerBasis>::zero(ctx);
            let share = managers[i]
                .decryption_share(
                    ct.clone(),
                    secret_key_aggregates[i].as_ref().unwrap(),
                    AggregatedSmudgingShare::new(smudging_poly),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with non-increasing party order
        let result =
            managers[0].decrypt_from_shares(decryption_shares.clone(), reconstructing, ct.clone());
        assert!(result.is_ok());

        // Validate plaintext
        let plaintext_found = result.expect("Failed to decrypt from shares");
        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");
        assert_eq!(decoded, plaintext_data);
    }
}
