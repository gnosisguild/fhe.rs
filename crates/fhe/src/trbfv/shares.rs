//! Share collection and management for threshold BFV.
//!
//! This module provides the ShareManager struct that handles aggregation of secret shares
//! and computation of decryption shares in the threshold BFV scheme.

use crate::Error;
use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::rns_shamir::RnsShamir;
use crate::trbfv::config::validate_threshold_config;
use crate::trbfv::prf::PartyPrfKeys;
use crate::trbfv::smudging::SmudgingNoise;
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::zq::Modulus;
use fhe_math::{
    rns::{RnsContext, ScalingFactor},
    rq::{Context, Ntt, Poly, PowerBasis, scaler::Scaler},
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
/// 4. During decryption, each designated party computes a partial decryption
///    for a known set `S` using its key share, local smudging noise, and PRF mask
/// 5. Finally, the `|S| = threshold + 1` partial decryptions are summed
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

    /// Sample the committee PRF keys used by partial decryption.
    ///
    /// Each party receives `2n` keys. Call this once during setup instead of
    /// dealing smudging-noise shares.
    pub fn generate_prf_keys<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Vec<PartyPrfKeys>, Error> {
        PartyPrfKeys::generate_committee(self.n, rng)
    }

    fn rns_shamir(&self) -> Result<RnsShamir<'_>, Error> {
        let ctx = self.params.context_at_level(0)?;
        RnsShamir::new(
            ctx.moduli_operators(),
            self.params.degree(),
            self.n,
            self.threshold,
        )
    }

    /// Generate Shamir Secret Shares for polynomial coefficients from a pre-converted Poly.
    ///
    /// # One-time use
    ///
    /// This method accepts any caller-provided polynomial and therefore
    /// cannot enforce one-time use: nothing here prevents dealing the same
    /// polynomial twice.
    pub fn generate_secret_shares_from_poly<R: RngCore + CryptoRng>(
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
    /// by [`ShareManager::generate_secret_shares_from_poly`] already satisfy this
    /// invariant, but aggregation re-checks it because it is an input boundary for
    /// externally supplied matrices. Out-of-range entries are treated as malformed
    /// and rejected with `Error::Threshold(ThresholdError::MalformedShares { .. })`;
    /// they are never reduced or otherwise repaired.
    ///
    /// # Arguments
    /// - `sk_sss_collected`: One share matrix per contributing party (at most `n`;
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
    pub fn aggregate_collected_shares(
        &self,
        sk_sss_collected: &[Array2<u64>], // collected sk sss shares from other parties
    ) -> Result<Poly<PowerBasis>, Error> {
        if sk_sss_collected.is_empty() {
            return Err(Error::share_count_mismatch(0, 1));
        }
        if sk_sss_collected.len() > self.n {
            return Err(Error::share_count_mismatch(sk_sss_collected.len(), self.n));
        }
        let expected_shape = (self.params.moduli().len(), self.params.degree());
        for (party_idx, item) in sk_sss_collected.iter().enumerate() {
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
        for (party_idx, item) in sk_sss_collected.iter().enumerate() {
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
            for item in sk_sss_collected {
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
    /// Compute a partial decryption for a designated decryptor set `S`.
    ///
    /// Implements PartDec of Colin de Verdière–Passelègue–Stehlé 2026:
    /// `p_i^S = λ_i^S · a · sh_i + e_i + r_i^{S,ct}`. The Lagrange coefficient
    /// is applied locally, smudging is sampled by the caller, and `r_i` is the
    /// committee PRF mask. The second ciphertext component `b` is added in
    /// [`ShareManager::decrypt_from_shares`].
    ///
    /// # Arguments
    /// - `ciphertext`: The ciphertext to decrypt (contains `a`, `b`)
    /// - `sk_i`: This party's aggregated share of the joint secret key
    /// - `party_id`: 1-based identity of this party; must belong to `S`
    /// - `reconstructing_parties`: The designated set `S`, 1-based, size
    ///   `threshold + 1`
    /// - `noise`: Fresh local smudging noise, consumed here
    /// - `prf_keys`: This party's `2n` committee PRF keys
    #[allow(clippy::indexing_slicing)] // BFV ciphertext always has exactly 2 components
    pub fn decryption_share(
        &self,
        ciphertext: Arc<Ciphertext>,
        sk_i: Poly<Ntt>,
        party_id: usize,
        reconstructing_parties: &[usize],
        noise: SmudgingNoise,
        prf_keys: &PartyPrfKeys,
    ) -> Result<Poly<PowerBasis>, Error> {
        self.validate_ciphertext(&ciphertext)?;
        if prf_keys.party_count() != self.n {
            return Err(Error::invalid_party_count(prf_keys.party_count(), self.n));
        }
        if prf_keys.party_id() != party_id {
            return Err(Error::invalid_party_id(prf_keys.party_id(), self.n));
        }

        let shamir = self.rns_shamir()?;
        shamir.validate_decryptor_set(reconstructing_parties)?;
        let party_index = reconstructing_parties
            .iter()
            .position(|&id| id == party_id)
            .ok_or_else(|| Error::invalid_party_id(party_id, self.n))?;

        let mut c1 = ciphertext.c[1].clone();
        c1.disallow_variable_time_computations();
        let mut sk_i = sk_i;
        sk_i.disallow_variable_time_computations();
        let mut es_i = noise.into_poly();
        es_i.disallow_variable_time_computations();
        if sk_i.ctx() != c1.ctx() || es_i.ctx() != c1.ctx() {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::Ciphertext,
            });
        }

        let mut c1sk = (&c1 * &sk_i).into_power_basis();
        c1sk.disallow_variable_time_computations();
        let mut scaled = c1sk.coefficients().to_owned();
        let ctx = c1.ctx();
        for (row_index, modulus) in ctx.moduli_operators().iter().enumerate() {
            let weights = shamir.lagrange_weights(modulus, reconstructing_parties)?;
            let lambda = weights
                .get(party_index)
                .copied()
                .ok_or_else(|| Error::invalid_party_id(party_id, self.n))?;
            let mut row = scaled.row_mut(row_index);
            let row_slice = row
                .as_slice_mut()
                .ok_or(fhe_math::Error::NonContiguousCoefficients)?;
            modulus.scalar_mul_vec(row_slice, lambda);
        }
        c1sk.set_coefficients(scaled);

        let mask = prf_keys.mask(reconstructing_parties, ciphertext.as_ref())?;
        let mut d_share_poly = c1sk;
        d_share_poly += es_i.as_ref();
        d_share_poly += &mask;
        Ok(d_share_poly)
    }

    /// Combine partial decryptions for a designated set `S`.
    ///
    /// Implements FinDec of Colin de Verdière–Passelègue–Stehlé 2026:
    /// `b + Σ_{i∈S} p_i`. Lagrange interpolation is already applied in
    /// [`ShareManager::decryption_share`]; this step only sums the shares
    /// and adds the second ciphertext component.
    ///
    /// # Arguments
    /// - `d_share_polys`: Exactly `threshold + 1` decryption shares
    /// - `reconstructing_parties`: The 1-based party indices the shares came from, in
    ///   the same order as `d_share_polys`; indices must be distinct and in `1..=n`
    /// - `ciphertext`: The original ciphertext being decrypted
    ///
    /// # Returns
    /// The decrypted plaintext
    // All indexing is on vectors built with known sizes matching the index ranges
    #[allow(clippy::indexing_slicing)]
    pub fn decrypt_from_shares(
        &self,
        d_share_polys: Vec<Poly<PowerBasis>>,
        reconstructing_parties: Vec<usize>,
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext, Error> {
        self.validate_ciphertext_parameters(&ciphertext)?;
        let ctx = self.params.context_at_level(0)?;
        if d_share_polys.len() != reconstructing_parties.len() {
            return Err(Error::share_count_mismatch(
                reconstructing_parties.len(),
                d_share_polys.len(),
            ));
        }
        let shamir = self.rns_shamir()?;
        shamir.validate_decryptor_set(&reconstructing_parties)?;
        for (d_share_poly, &party_id) in d_share_polys.iter().zip(&reconstructing_parties) {
            if d_share_poly.ctx().as_ref() != ctx.as_ref() {
                return Err(Error::ParameterMismatch {
                    left: crate::ParameterSource::Polynomial,
                    right: crate::ParameterSource::Parameters,
                });
            }
            shamir.validate_matrix(d_share_poly.coefficients(), party_id, "share")?;
        }
        self.validate_ciphertext_shape(&ciphertext)?;

        let mut result_poly = d_share_polys
            .first()
            .cloned()
            .ok_or_else(|| Error::share_count_mismatch(0, self.threshold + 1))?;
        result_poly.disallow_variable_time_computations();
        for share in d_share_polys.iter().skip(1) {
            result_poly += share;
        }

        let mut c0 = ciphertext.c[0].clone();
        c0.disallow_variable_time_computations();
        result_poly += &c0.into_power_basis();

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
    use crate::trbfv::prf::PartyPrfKeys;
    use crate::trbfv::smudging::{SmudgingConfig, SmudgingNoiseGenerator};
    use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
    use rand::rng;

    fn zero_smudging(params: &Arc<BfvParameters>) -> SmudgingNoise {
        let ctx = params.context_at_level(0).unwrap();
        SmudgingNoise::from_poly(Zeroizing::new(Poly::<PowerBasis>::zero(ctx)))
    }

    fn part_dec(
        manager: &ShareManager,
        ciphertext: Arc<Ciphertext>,
        sk_i: Poly<PowerBasis>,
        party_id: usize,
        reconstructing: &[usize],
        prf_keys: &PartyPrfKeys,
        params: &Arc<BfvParameters>,
    ) -> Poly<PowerBasis> {
        manager
            .decryption_share(
                ciphertext,
                sk_i.into_ntt(),
                party_id,
                reconstructing,
                zero_smudging(params),
                prf_keys,
            )
            .unwrap()
    }

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
    fn test_local_smudging_is_consumed_by_partial_decryption() {
        let params = insecure().unwrap().parameters;
        let n = 5;
        let threshold = 2;
        let manager = ShareManager::new(n, threshold, params.clone()).unwrap();
        let mut rng = rng();
        let prf_keys = manager.generate_prf_keys(&mut rng).unwrap();

        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let pt = Plaintext::try_encode(&[1u64], Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());
        let sk_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
        let reconstructing = vec![1, 2, 3];

        let generator =
            SmudgingNoiseGenerator::new(SmudgingConfig::new(params.clone(), n, 1, 0).unwrap())
                .unwrap();
        let noise = generator.generate(&mut rng).unwrap();
        let share = manager
            .decryption_share(
                ct,
                (*sk_poly).clone().into_ntt(),
                1,
                &reconstructing,
                noise,
                &prf_keys[0],
            )
            .unwrap();
        assert!(!share.allows_variable_time_computations());
    }

    #[test]
    fn local_smudging_at_secure_bound_is_nonzero() {
        let params = secure8192().unwrap().parameters;
        let n = 3;
        let mut rng = rng();

        let config = SmudgingConfig::new(params.clone(), n, 1, 45).unwrap();
        let generator = SmudgingNoiseGenerator::new(config).unwrap();
        let noise = generator.generate(&mut rng).unwrap();
        let poly = noise.into_poly();
        assert!(
            poly.coefficients().iter().any(|&c| c != 0),
            "secure local smudging should not be the zero polynomial"
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
            manager.generate_secret_shares_from_poly(wrong_context_poly, &mut rng),
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
            .generate_secret_shares_from_poly(Zeroizing::new(noncanonical), &mut rng)
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
        let prf_keys = manager.generate_prf_keys(&mut rng).unwrap();
        let reconstructing = vec![1, 2];

        // Generate polynomials for decryption share.
        let mut sk_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
        let variable_time = fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
        sk_poly.allow_variable_time_computations(variable_time);
        assert!(ct.c[1].allows_variable_time_computations());

        // This test uses the full secret as the "aggregate" for both parties.
        // Lagrange coefficients still sum to 1 on a constant polynomial.
        let share_one = manager
            .decryption_share(
                ct.clone(),
                (*sk_poly).clone().into_ntt(),
                1,
                &reconstructing,
                zero_smudging(&params),
                &prf_keys[0],
            )
            .unwrap();
        let share_two = manager
            .decryption_share(
                ct.clone(),
                (*sk_poly).clone().into_ntt(),
                2,
                &reconstructing,
                zero_smudging(&params),
                &prf_keys[1],
            )
            .unwrap();
        assert!(!share_one.allows_variable_time_computations());

        let shares = vec![share_one, share_two];
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
        let prf_keys = manager.generate_prf_keys(&mut rng).unwrap();
        let result = manager.decryption_share(
            Arc::new(ciphertext),
            (*secret_poly).clone().into_ntt(),
            1,
            &[1, 2],
            zero_smudging(&params),
            &prf_keys[0],
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

        let ctx = params.context_at_level(0).unwrap();

        // Setup multiple share managers (simulating different parties)
        let managers: Vec<ShareManager> = (0..n)
            .map(|_| ShareManager::new(n, threshold, params.clone()).unwrap())
            .collect();

        // One party generates the secret key and secret shares it among the other parties
        let secret_key = SecretKey::random(&params, &mut rng);

        let sk_poly = managers[0]
            .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
            .unwrap();

        let sk_sss = managers[0]
            .generate_secret_shares_from_poly(sk_poly, &mut rng)
            .unwrap();

        let mut sk_sss_collected: Vec<Vec<Array2<u64>>> = vec![vec![], vec![], vec![]];

        let mut sk_poly_sums: Vec<Poly<PowerBasis>> =
            (0..n).map(|_| Poly::<PowerBasis>::zero(ctx)).collect();

        for i in 0..n {
            let mut node_share_m = Array2::zeros((0, params.degree()));
            for sk_sss_m in sk_sss.iter().take(params.moduli().len()) {
                node_share_m
                    .push_row(ndarray::ArrayView::from(sk_sss_m.row(i)))
                    .unwrap();
            }
            sk_sss_collected[i].push(node_share_m);

            let share_slice: &[Array2<u64>] = &sk_sss_collected[i];
            sk_poly_sums[i] = managers[i].aggregate_collected_shares(share_slice).unwrap();
        }

        // Create a test ciphertext
        let pk = PublicKey::new(&secret_key, &mut rng);
        let mut plaintext_data = vec![23u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());
        let prf_keys = managers[0].generate_prf_keys(&mut rng).unwrap();
        let reconstructing = vec![1, 2];

        // Each party generates their decryption share
        let mut decryption_shares = Vec::new();

        // Testing for decryption between parties 0 and 1
        for i in 0..(threshold + 1) {
            decryption_shares.push(part_dec(
                &managers[i],
                ct.clone(),
                sk_poly_sums[i].clone(),
                i + 1,
                &reconstructing,
                &prf_keys[i],
                &params,
            ));
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

        let ctx = params.context_at_level(0).unwrap();

        // Setup multiple share managers (simulating different parties)
        let managers: Vec<ShareManager> = (0..n)
            .map(|_| ShareManager::new(n, threshold, params.clone()).unwrap())
            .collect();

        // One party generates the secret key and secret shares it among the other parties
        let secret_key = SecretKey::random(&params, &mut rng);

        let sk_poly = managers[0]
            .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
            .unwrap();

        let sk_sss = managers[0]
            .generate_secret_shares_from_poly(sk_poly, &mut rng)
            .unwrap();

        let mut sk_sss_collected: Vec<Vec<Array2<u64>>> =
            vec![vec![], vec![], vec![], vec![], vec![]];

        let mut sk_poly_sums: Vec<Poly<PowerBasis>> =
            (0..n).map(|_| Poly::<PowerBasis>::zero(ctx)).collect();

        for i in 0..n {
            let mut node_share_m = Array2::zeros((0, params.degree()));
            for sk_sss_m in sk_sss.iter().take(params.moduli().len()) {
                node_share_m
                    .push_row(ndarray::ArrayView::from(sk_sss_m.row(i)))
                    .unwrap();
            }
            sk_sss_collected[i].push(node_share_m);

            let share_slice: &[Array2<u64>] = &sk_sss_collected[i];
            sk_poly_sums[i] = managers[i].aggregate_collected_shares(share_slice).unwrap();
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
        let prf_keys = managers[0].generate_prf_keys(&mut rng).unwrap();

        // Each chosen party generates their decryption share
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            decryption_shares.push(part_dec(
                &managers[i],
                ct.clone(),
                sk_poly_sums[i].clone(),
                i + 1,
                &reconstructing,
                &prf_keys[i],
                &params,
            ));
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

        let ctx = params.context_at_level(0).unwrap();

        // Setup multiple share managers (simulating different parties)
        let managers: Vec<ShareManager> = (0..n)
            .map(|_| ShareManager::new(n, threshold, params.clone()).unwrap())
            .collect();

        // One party generates the secret key and secret shares it among the other parties
        let secret_key = SecretKey::random(&params, &mut rng);

        let sk_poly = managers[0]
            .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
            .unwrap();

        let sk_sss = managers[0]
            .generate_secret_shares_from_poly(sk_poly, &mut rng)
            .unwrap();

        let mut sk_sss_collected: Vec<Vec<Array2<u64>>> = (0..n).map(|_| vec![]).collect();

        let mut sk_poly_sums: Vec<Poly<PowerBasis>> =
            (0..n).map(|_| Poly::<PowerBasis>::zero(ctx)).collect();

        for i in 0..n {
            let mut node_share_m = Array2::zeros((0, params.degree()));
            for sk_sss_m in sk_sss.iter().take(params.moduli().len()) {
                node_share_m
                    .push_row(ndarray::ArrayView::from(sk_sss_m.row(i)))
                    .unwrap();
            }
            sk_sss_collected[i].push(node_share_m);

            let share_slice: &[Array2<u64>] = &sk_sss_collected[i];
            sk_poly_sums[i] = managers[i].aggregate_collected_shares(share_slice).unwrap();
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
        let prf_keys = managers[0].generate_prf_keys(&mut rng).unwrap();

        // Each chosen party generates their decryption share
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            decryption_shares.push(part_dec(
                &managers[i],
                ct.clone(),
                sk_poly_sums[i].clone(),
                i + 1,
                &reconstructing,
                &prf_keys[i],
                &params,
            ));
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

        let ctx = params.context_at_level(0).unwrap();

        // Setup multiple share managers (simulating different parties)
        let managers: Vec<ShareManager> = (0..n)
            .map(|_| ShareManager::new(n, threshold, params.clone()).unwrap())
            .collect();

        // One party generates the secret key and secret shares it among the other parties
        let secret_key = SecretKey::random(&params, &mut rng);

        let sk_poly = managers[0]
            .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
            .unwrap();

        let sk_sss = managers[0]
            .generate_secret_shares_from_poly(sk_poly, &mut rng)
            .unwrap();

        let mut sk_sss_collected: Vec<Vec<Array2<u64>>> = (0..n).map(|_| vec![]).collect();

        let mut sk_poly_sums: Vec<Poly<PowerBasis>> =
            (0..n).map(|_| Poly::<PowerBasis>::zero(ctx)).collect();

        for i in 0..n {
            let mut node_share_m = Array2::zeros((0, params.degree()));
            for sk_sss_m in sk_sss.iter().take(params.moduli().len()) {
                node_share_m
                    .push_row(ndarray::ArrayView::from(sk_sss_m.row(i)))
                    .unwrap();
            }
            sk_sss_collected[i].push(node_share_m);

            let share_slice: &[Array2<u64>] = &sk_sss_collected[i];
            sk_poly_sums[i] = managers[i].aggregate_collected_shares(share_slice).unwrap();
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
        let prf_keys = managers[0].generate_prf_keys(&mut rng).unwrap();

        // Each chosen party generates their decryption share for S
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            decryption_shares.push(part_dec(
                &managers[i],
                ct.clone(),
                sk_poly_sums[i].clone(),
                i + 1,
                &reconstructing_correct,
                &prf_keys[i],
                &params,
            ));
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Decrypt with shares crafted for S -> should succeed and match plaintext
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

        // Mix in a partial decryption crafted for a different designated set S'
        // that still contains party 1.
        let mut reconstructing_other = reconstructing_correct.clone();
        reconstructing_other[4] = 10;
        let mixed_share = part_dec(
            &managers[chosen_indices[0]],
            ct.clone(),
            sk_poly_sums[chosen_indices[0]].clone(),
            chosen_indices[0] + 1,
            &reconstructing_other,
            &prf_keys[chosen_indices[0]],
            &params,
        );
        let mut mixed_shares = decryption_shares.clone();
        mixed_shares[0] = mixed_share;
        let result_bad = managers[0].decrypt_from_shares(
            mixed_shares,
            reconstructing_correct,
            ct.clone(),
        );
        assert!(result_bad.is_ok());
        let plaintext_found_bad =
            result_bad.expect("Decryption unexpectedly failed with mixed designated sets");
        let decoded_bad: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found_bad, Encoding::poly())
            .expect("Decoding plaintext failed");
        assert_ne!(
            decoded_bad, plaintext_data,
            "Partial decryptions from distinct designated sets must not combine"
        );
    }

    #[test]
    fn test_aggregate_collected_shares_rejects_bad_input() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let shape = (params.moduli().len(), params.degree());

        // Empty input
        assert!(manager.aggregate_collected_shares(&[]).is_err());

        // More matrices than parties
        let matrices: Vec<Array2<u64>> = (0..6).map(|_| Array2::zeros(shape)).collect();
        assert!(manager.aggregate_collected_shares(&matrices).is_err());

        // Wrong shape (rows and columns swapped)
        let bad = vec![Array2::zeros((params.degree(), params.moduli().len()))];
        assert!(manager.aggregate_collected_shares(&bad).is_err());

        // Valid: between 1 and n well-formed matrices
        let ok: Vec<Array2<u64>> = (0..3).map(|_| Array2::zeros(shape)).collect();
        assert!(manager.aggregate_collected_shares(&ok).is_ok());
    }

    #[test]
    fn test_aggregate_collected_shares_rejects_non_canonical_q_at_each_row() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());

        // A coefficient equal to its row's modulus q_i is not a canonical
        // residue and must be rejected against that row's own modulus, not a
        // global bound shared across rows.
        for (row, &q_i) in moduli.iter().enumerate() {
            let mut shares = Array2::zeros(shape);
            shares[[row, 3]] = q_i;
            let err = manager
                .aggregate_collected_shares(std::slice::from_ref(&shares))
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
    fn test_aggregate_collected_shares_rejects_u64_max() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());

        // u64::MAX would wrap to a small residue if reduced; it must be
        // rejected as malformed instead of being reduced. The error reports
        // party, row, column, and modulus only: secret share values must not
        // appear in error strings.
        let mut shares = Array2::zeros(shape);
        shares[[0, 0]] = u64::MAX;
        let err = manager
            .aggregate_collected_shares(std::slice::from_ref(&shares))
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
    fn test_aggregate_collected_shares_accepts_q_minus_one_boundary() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());

        // q_i - 1 is the largest valid canonical residue for each row; all
        // rows must be accepted against their own distinct moduli.
        let mut shares = Array2::zeros(shape);
        for (row, &q_i) in moduli.iter().enumerate() {
            shares.row_mut(row).fill(q_i - 1);
        }
        let result = manager
            .aggregate_collected_shares(std::slice::from_ref(&shares))
            .expect("maximal canonical residues must be accepted");

        // A single aggregate preserves the input values exactly (the sum of a
        // single matrix is the matrix itself) and the accumulator does not
        // reduce them beyond the canonical residues supplied.
        assert_eq!(result.coefficients().into_owned(), shares);
    }

    #[test]
    fn test_aggregate_collected_shares_rejects_invalid_after_valid() {
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());
        let q1 = moduli[1];

        // A valid first contribution followed by a malformed later one must
        // still surface the later contribution's error rather than reaching
        // Modulus::add_vec with the bad entry.
        let valid = Array2::zeros(shape);
        let mut invalid = Array2::zeros(shape);
        invalid[[1, 5]] = q1;
        let err = manager
            .aggregate_collected_shares(&[valid, invalid])
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

        let ctx = params.context_at_level(0).unwrap();

        // Setup multiple share managers (simulating different parties)
        let managers: Vec<ShareManager> = (0..n)
            .map(|_| ShareManager::new(n, threshold, params.clone()).unwrap())
            .collect();

        // One party generates the secret key and secret shares it among the other parties
        let secret_key = SecretKey::random(&params, &mut rng);

        let sk_poly = managers[0]
            .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
            .unwrap();

        let sk_sss = managers[0]
            .generate_secret_shares_from_poly(sk_poly, &mut rng)
            .unwrap();

        let mut sk_sss_collected: Vec<Vec<Array2<u64>>> = (0..n).map(|_| vec![]).collect();

        let mut sk_poly_sums: Vec<Poly<PowerBasis>> =
            (0..n).map(|_| Poly::<PowerBasis>::zero(ctx)).collect();

        for i in 0..n {
            let mut node_share_m = Array2::zeros((0, params.degree()));
            for sk_sss_m in sk_sss.iter().take(params.moduli().len()) {
                node_share_m
                    .push_row(ndarray::ArrayView::from(sk_sss_m.row(i)))
                    .unwrap();
            }
            sk_sss_collected[i].push(node_share_m);

            let share_slice: &[Array2<u64>] = &sk_sss_collected[i];
            sk_poly_sums[i] = managers[i].aggregate_collected_shares(share_slice).unwrap();
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
        let prf_keys = managers[0].generate_prf_keys(&mut rng).unwrap();

        // Each chosen party generates their decryption share in the same (non-increasing) order
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            decryption_shares.push(part_dec(
                &managers[i],
                ct.clone(),
                sk_poly_sums[i].clone(),
                i + 1,
                &reconstructing,
                &prf_keys[i],
                &params,
            ));
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
