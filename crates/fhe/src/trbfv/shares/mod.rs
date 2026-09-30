//! Share collection and management for threshold BFV.
//!
//! This module provides the ShareManager struct that handles aggregation of secret shares
//! and computation of decryption shares in the threshold BFV scheme.

mod secret_key;
mod smudging;

pub use secret_key::{AggregatedSecretKeyShare, DealtSecretKeyShares, SecretKeyShare};
pub use smudging::{AggregatedSmudgingShare, DealtSmudgingShares, SmudgingShare};

use super::rns_shamir::RnsShamir;
use crate::Error;
use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::trbfv::config::validate_threshold_config;
use crate::trbfv::smudging::SmudgingNoise;
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::rq::{Context, Poly, PowerBasis};
use fhe_math::zq::Modulus;
use itertools::Itertools;
use ndarray::{Array2, ArrayView2};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use std::convert::TryFrom;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Manager for threshold BFV share operations.
///
/// Deals and aggregates Shamir shares, computes decryption shares, and
/// reconstructs plaintexts. `threshold` is the Shamir degree `T`; reconstruction
/// requires `T + 1` shares. Immutable committee settings enforce `n >= 3` and
/// `T = (n - 1) / 2`. Even `n` is accepted but outside the paper's theorem.
/// Authentication, participant/session binding, and replay prevention are
/// protocol responsibilities; this manager does not provide robustness.
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
    /// Convert coefficients into a wipe-on-drop power-basis polynomial at `ctx`.
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
    /// Consumes the owner and checks party count and full BFV-parameter equality
    /// before reading noise or drawing randomness. Independently built equal
    /// parameters are accepted; rejected owners are wiped unread. Circuit size,
    /// depth, `lambda`, and noise-model assumptions remain caller responsibilities.
    pub fn generate_smudging_shares<R: RngCore + CryptoRng>(
        &self,
        noise: SmudgingNoise,
        rng: &mut R,
    ) -> Result<DealtSmudgingShares, Error> {
        // Reject foreign noise before extraction or RNG use.
        noise.validate_dealer_binding(self.n, &self.params)?;
        self.deal_poly(noise.into_poly(), rng)
            .map(DealtSmudgingShares::new)
    }

    /// Aggregate dealt smudging shares into one single-use decryption owner.
    ///
    /// The input shares are consumed.  This operation is intentionally
    /// separate from ordinary secret-key aggregation so smudging material
    /// cannot silently flow through a generic polynomial API. Owned inputs
    /// remain under their zeroizing owners even when validation fails.
    /// Requires 1..=n matrices of shape `[moduli, degree]` with canonical residues
    /// below each row's modulus, as in [`Self::aggregate_secret_key_shares`].
    pub fn aggregate_smudging_shares(
        &self,
        shares: Vec<SmudgingShare>,
    ) -> Result<AggregatedSmudgingShare, Error> {
        // Keep the matrices under their zeroizing owners while validating and
        // aggregating, including when malformed input returns an error.
        self.aggregate_collected_matrices(shares.iter().map(|share| &share.coefficients))
            .map(AggregatedSmudgingShare::new)
    }

    /// Aggregate collected secret-key shares into a reusable owner.
    ///
    /// The input owners are consumed (and zeroized on failure), while the
    /// resulting aggregate may be borrowed for any number of decryptions in
    /// the same key epoch.
    /// Requires 1..=n contribution matrices of shape `[moduli, degree]`;
    /// noncanonical residues (`>= q_i`) are rejected, never reduced.
    pub fn aggregate_secret_key_shares(
        &self,
        shares: Vec<SecretKeyShare>,
    ) -> Result<AggregatedSecretKeyShare, Error> {
        // Borrow matrices so owners still wipe them on validation failure.
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
    ///
    /// # Errors
    /// Returns a parameter error if the polynomial's context differs, or a math
    /// error if its coefficient matrix violates the context's shape or
    /// canonical-residue invariants. The coefficient validation is defense in
    /// depth; safe polynomial construction already enforces these invariants.
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
        validate_poly_coefficients(
            poly.coefficients(),
            self.params.moduli(),
            self.params.degree(),
        )?;

        RnsShamir::new(
            ctx.moduli_operators(),
            self.params.degree(),
            self.n,
            self.threshold,
        )?
        .share(poly.coefficients(), rng)
        .map(|shares| shares.into_matrices())
    }
    /// Sum 1..=n contribution matrices of shape `[moduli, degree]`.
    /// Reject noncanonical residues (`>= q_i`) rather than reducing them.
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
            if coefficient_matrix_shape(item.view(), expected_shape.0, expected_shape.1).is_some() {
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

        // add_vec requires canonical inputs; reject all malformed contributions
        // before accumulating rather than silently reducing them.
        for (party_idx, item) in collected.iter().enumerate() {
            if let Some((row, column, _value, modulus)) =
                first_noncanonical_coefficient(item.view(), self.params.moduli())
            {
                return Err(Error::malformed_shares(
                    party_idx,
                    format!(
                        "share coefficient at row {row} (modulus q_i = {modulus}), column \
                         {column} is not a canonical residue in [0, {modulus})"
                    ),
                ));
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
        sum_poly.set_coefficients(sum)?;
        Ok(sum_poly)
    }

    /// Compute `c0 + c1 * s_i + noise_i` for one decrypting party.
    ///
    /// # Arguments
    /// - `ciphertext`: Borrowed ciphertext to decrypt (contains c0, c1 polynomials)
    /// - `secret_key`: This party's aggregated share of the joint secret key (output of
    ///   [`ShareManager::aggregate_secret_key_shares`]), not a party's own secret key
    /// - `smudging`: This party's aggregated share of the joint smudging noise,
    ///   aggregated the same way from the dealt noise shares
    ///
    /// # Secret handling
    /// Borrows the reusable key share and consumes one-time noise. Intermediate
    /// arithmetic is constant-time and wipe-on-drop guarded, except during the
    /// move-based inverse NTT and transfer to the returned caller-owned polynomial.
    #[allow(clippy::indexing_slicing)] // BFV ciphertext always has exactly 2 components
    pub fn decryption_share(
        &self,
        ciphertext: &Ciphertext,
        secret_key: &AggregatedSecretKeyShare,
        smudging: AggregatedSmudgingShare,
    ) -> Result<Poly<PowerBasis>, Error> {
        self.validate_ciphertext(ciphertext)?;
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
        // Guard before multiplication so partial secret products wipe on unwind.
        let mut product = Zeroizing::new(c1);
        product.disallow_variable_time_computations();
        *product.as_mut() *= secret_key;
        // Move-based inverse NTT temporarily leaves the product unguarded;
        // an unwind inside the transform is not covered by wipe-on-drop.
        let replacement = Poly::zero(product.ctx());
        let product = std::mem::replace(product.as_mut(), replacement).into_power_basis();
        // The phase accumulated on top of the product stays in a wipe-on-drop
        // owner until its allocation is transferred into the returned share.
        let mut phase = Zeroizing::new(product);
        // In-place additions avoid unguarded secret temporaries.
        *phase.as_mut() += &c0;
        *phase.as_mut() += smudging.as_ref();
        let ctx = phase.ctx().clone();
        Ok(std::mem::replace(
            phase.as_mut(),
            Poly::<PowerBasis>::zero(&ctx),
        ))
    }

    /// Decrypt ciphertext from collected decryption shares.
    ///
    /// # Arguments
    /// - `decryption_shares`: Exactly `threshold + 1` decryption shares
    /// - `reconstructing_parties`: The 1-based party indices the shares came from, in
    ///   the same order as `decryption_shares`; indices must be distinct and in `1..=n`
    /// - `ciphertext`: The original ciphertext being decrypted
    ///
    /// # Errors
    /// Rejects invalid shares, party IDs, or ciphertexts. Returns
    /// [`ParametersError::UnsupportedPlaintextModulus`](crate::ParametersError::UnsupportedPlaintextModulus)
    /// before reconstruction when the plaintext modulus does not fit in `u64`.
    // All indexing is on vectors built with known sizes matching the index ranges
    #[allow(clippy::indexing_slicing)]
    pub fn decrypt_from_shares(
        &self,
        decryption_shares: &[Poly<PowerBasis>],
        reconstructing_parties: &[usize],
        ciphertext: &Ciphertext,
    ) -> Result<Plaintext, Error> {
        self.validate_ciphertext_parameters(ciphertext)?;
        // Reject unsupported plaintext moduli before reconstruction work.
        let ptxt_u64 = self.params.plaintext.as_u64().ok_or_else(|| {
            Error::ParametersError(crate::ParametersError::UnsupportedPlaintextModulus {
                reason: "threshold BFV decrypt_from_shares requires a u64 plaintext modulus"
                    .to_string(),
            })
        })?;
        // Reject a level whose ciphertext modulus cannot encode plaintexts
        // before reconstructing or converting anything.
        self.params.validate_plaintext_level(ciphertext.level)?;
        let ctx = self.params.context_at_level(0)?;
        for decryption_share in decryption_shares {
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
        .reconstruct(&share_views, reconstructing_parties)?
        .into_matrix();
        self.validate_ciphertext_shape(ciphertext)?;

        // Scale the reconstructed polynomial into the plaintext space.
        let mut result_poly = Poly::<PowerBasis>::zero(ctx);
        result_poly.set_coefficients(arr_matrix)?;

        let par = ciphertext.params.clone();

        // Scale the reconstructed phase by t/Q with the precomputed bridge for
        // the ciphertext level. Its plaintext context has enough moduli for
        // full-precision lifting when q_0 cannot represent plaintexts.
        let ctx_lvl = self.params.context_level_at(ciphertext.level)?;
        let d = Zeroizing::new(
            result_poly
                .scale(&ctx_lvl.cipher_plain_context.scaler)
                .map_err(Error::MathError)?,
        );

        let poly = if self.params.u64_decrypt_fast_path_is_exact() {
            // 2t <= q_0: reducing through q_0 preserves every plaintext value.
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
            Poly::<PowerBasis>::try_convert_from(&w, ciphertext.c[0].ctx(), false)?.into_ntt()
        } else {
            // q_0 < 2t (in particular q_0 < t): reducing through q_0 alone
            // loses values near t, so lift through the plaintext-context
            // modulus before reducing, as in secret-key decryption.
            let v: Vec<BigUint> = Vec::<BigUint>::try_from(d.as_ref())
                .map_err(Error::from)?
                .into_iter()
                .map(|vi| vi + BigUint::from(ptxt_u64))
                .collect_vec();
            let mut w = v[..par.degree()].to_vec();
            let q_poly = d.as_ref().ctx().modulus();
            w.iter_mut().for_each(|wi| *wi %= q_poly);
            par.plaintext.reduce_vec(&mut w);
            Poly::<PowerBasis>::try_convert_from(w.as_slice(), ciphertext.c[0].ctx(), false)?
                .into_ntt()
        };

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

fn validate_poly_coefficients(
    coefficients: ArrayView2<'_, u64>,
    moduli: &[u64],
    degree: usize,
) -> Result<(), Error> {
    let expected_shape = (moduli.len(), degree);
    if let Some((actual_rows, actual_columns)) =
        coefficient_matrix_shape(coefficients, expected_shape.0, expected_shape.1)
    {
        return Err(fhe_math::Error::InvalidCoefficientShape {
            actual_rows,
            actual_columns,
            expected_rows: expected_shape.0,
            expected_columns: expected_shape.1,
        }
        .into());
    }

    if let Some((_, _, value, modulus)) = first_noncanonical_coefficient(coefficients, moduli) {
        return Err(fhe_math::Error::NonCanonicalValue { value, modulus }.into());
    }
    Ok(())
}

fn coefficient_matrix_shape(
    coefficients: ArrayView2<'_, u64>,
    expected_rows: usize,
    expected_columns: usize,
) -> Option<(usize, usize)> {
    let (actual_rows, actual_columns) = coefficients.dim();
    (actual_rows != expected_rows || actual_columns != expected_columns)
        .then_some((actual_rows, actual_columns))
}

fn first_noncanonical_coefficient(
    coefficients: ArrayView2<'_, u64>,
    moduli: &[u64],
) -> Option<(usize, usize, u64, u64)> {
    coefficients
        .outer_iter()
        .zip(moduli)
        .enumerate()
        .find_map(|(row, (values, &modulus))| {
            values
                .iter()
                .enumerate()
                .find(|(_, value)| **value >= modulus)
                .map(|(column, &value)| (row, column, value, modulus))
        })
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
    use crate::bfv::{BfvParametersBuilder, Encoding, PublicKey, SecretKey};
    use crate::support::presets::{insecure, insecure_128, secure8192};
    use crate::trbfv::smudging::{
        FreshNoiseModel, MAX_LAMBDA, SmudgingConfig, SmudgingNoiseGenerator,
    };
    use fhe_math::rq::{Ntt, RepresentationTag};
    use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
    use rand::rng;
    use std::sync::atomic::{AtomicBool, Ordering};
    use zeroize::Zeroize;

    #[test]
    fn poly_coefficient_guard_returns_math_error_for_noncanonical_values() {
        let params = insecure().unwrap().parameters;
        let mut coefficients = Array2::zeros((params.moduli().len(), params.degree()));
        coefficients[[1, 7]] = params.moduli()[1];

        assert_eq!(
            validate_poly_coefficients(coefficients.view(), params.moduli(), params.degree()),
            Err(Error::MathError(fhe_math::Error::NonCanonicalValue {
                value: params.moduli()[1],
                modulus: params.moduli()[1],
            }))
        );
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

        // Degree-zero sharing reveals the secret to every party.
        assert!(matches!(
            ShareManager::new(5, 0, params.clone()),
            Err(Error::Threshold(ThresholdError::InvalidThreshold {
                threshold: 0,
                n: 5,
                expected: 2
            }))
        ));

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
            assert_eq!(manager.params(), &params);
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

        let generator = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params.clone(), n, 1, 0, FreshNoiseModel::BfvPublicKey).unwrap(),
        )
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

    /// Build threshold-BFV parameters from explicit values so a single field
    /// can be varied while the rest (and often the ring context) is fixed.
    fn binding_params(
        plaintext: u64,
        moduli: &[u64],
        variance: usize,
        error1_variance: &str,
    ) -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(insecure_128::DEGREE)
            .set_plaintext_modulus(plaintext)
            .set_moduli(moduli)
            .set_variance(variance)
            .set_error1_variance_str(error1_variance)
            .unwrap()
            .build_arc()
            .unwrap()
    }

    /// The supplied degree-128 threshold profile values, as an independent
    /// builder invocation of [`crate::support::presets::insecure`].
    fn insecure_threshold_binding_params() -> Arc<BfvParameters> {
        binding_params(
            insecure_128::threshold::PLAINTEXT_MODULUS,
            insecure_128::threshold::MODULI,
            insecure_128::threshold::VARIANCE,
            insecure_128::threshold::ERROR1_VARIANCE,
        )
    }

    /// Assert that a noise generator built over `generator_params` is
    /// rejected by a manager over `manager_params` with a parameter mismatch
    /// before any dealing randomness is consumed.
    fn assert_dealing_rejects_mismatched_params(
        manager_params: Arc<BfvParameters>,
        generator_params: Arc<BfvParameters>,
    ) {
        let manager = ShareManager::new(5, 2, manager_params).unwrap();
        let generator = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(generator_params, 5, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap(),
        )
        .unwrap();
        let mut rng = crate::support::presets::rng(172);
        let noise = generator.generate(&mut rng).unwrap();

        let rng_snapshot = rng.clone();
        let result = manager.generate_smudging_shares(noise, &mut rng);
        assert!(matches!(
            result,
            Err(Error::ParameterMismatch {
                left: crate::ParameterSource::SmudgingNoise,
                right: crate::ParameterSource::Parameters,
            })
        ));
        // The rejection happened before any dealing randomness was consumed.
        assert_eq!(rng, rng_snapshot);
    }

    #[test]
    fn smudging_dealing_accepts_independently_built_equal_params() {
        // The manager and the generator were configured from independent
        // builder invocations; full value equality must accept equivalent
        // configurations, not just identical allocations.
        let manager_params = insecure_threshold_binding_params();
        let generator_params = insecure_threshold_binding_params();
        assert_ne!(Arc::as_ptr(&manager_params), Arc::as_ptr(&generator_params));
        let manager = ShareManager::new(5, 2, manager_params).unwrap();
        let generator = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(generator_params, 5, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap(),
        )
        .unwrap();
        let mut rng = rng();
        let noise = generator.generate(&mut rng).unwrap();
        assert!(manager.generate_smudging_shares(noise, &mut rng).is_ok());
    }

    #[test]
    fn smudging_dealing_rejects_party_count_mismatch_before_randomness() {
        let params = insecure_threshold_binding_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        // Noise sized for one party,
        // dealt by a five-party manager.
        let generator = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params, 1, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap(),
        )
        .unwrap();
        let mut rng = crate::support::presets::rng(172);
        let noise = generator.generate(&mut rng).unwrap();

        let rng_snapshot = rng.clone();
        let error = manager
            .generate_smudging_shares(noise, &mut rng)
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Threshold(ThresholdError::SmudgingNoisePartyCountMismatch {
                noise_parties: 1,
                dealer_parties: 5,
            })
        ));
        // The rejection happened before any dealing randomness was consumed.
        assert_eq!(rng, rng_snapshot);
    }

    #[test]
    fn smudging_dealing_rejects_plaintext_modulus_mismatch_same_ring() {
        // Same degree, ciphertext moduli, and variances: only the plaintext
        // modulus differs, so ring-context equality alone cannot catch this.
        assert_dealing_rejects_mismatched_params(
            insecure_threshold_binding_params(),
            binding_params(
                101,
                insecure_128::threshold::MODULI,
                insecure_128::threshold::VARIANCE,
                insecure_128::threshold::ERROR1_VARIANCE,
            ),
        );
    }

    #[test]
    fn smudging_dealing_rejects_ciphertext_moduli_mismatch() {
        assert_dealing_rejects_mismatched_params(
            insecure_threshold_binding_params(),
            binding_params(
                insecure_128::threshold::PLAINTEXT_MODULUS,
                insecure_128::share_enc::MODULI,
                insecure_128::threshold::VARIANCE,
                insecure_128::threshold::ERROR1_VARIANCE,
            ),
        );
    }

    #[test]
    fn smudging_dealing_rejects_variance_mismatch_same_ring() {
        assert_dealing_rejects_mismatched_params(
            insecure_threshold_binding_params(),
            binding_params(
                insecure_128::threshold::PLAINTEXT_MODULUS,
                insecure_128::threshold::MODULI,
                insecure_128::threshold::VARIANCE - 1,
                insecure_128::threshold::ERROR1_VARIANCE,
            ),
        );
    }

    #[test]
    fn smudging_dealing_rejects_error1_variance_mismatch_same_ring() {
        let mut mismatched_error1_variance = insecure_128::threshold::ERROR1_VARIANCE.to_string();
        mismatched_error1_variance.pop();
        mismatched_error1_variance.push('1');
        assert_dealing_rejects_mismatched_params(
            insecure_threshold_binding_params(),
            binding_params(
                insecure_128::threshold::PLAINTEXT_MODULUS,
                insecure_128::threshold::MODULI,
                insecure_128::threshold::VARIANCE,
                &mismatched_error1_variance,
            ),
        );
    }

    /// Largest lambda accepted by `SmudgingNoiseGenerator::new` for a
    /// configuration. `B_sm` grows monotonically with lambda, so the strict
    /// correctness inequality fails from the first infeasible lambda on.
    fn max_feasible_lambda(params: &Arc<BfvParameters>, n: usize, m: usize) -> usize {
        let mut feasible = 0;
        for lambda in 0..=MAX_LAMBDA {
            match SmudgingNoiseGenerator::new(
                SmudgingConfig::new(params.clone(), n, m, lambda, FreshNoiseModel::BfvPublicKey)
                    .unwrap(),
            ) {
                Ok(_) => feasible = lambda,
                Err(_) => break,
            }
        }
        feasible
    }

    #[test]
    fn smudging_dealing_rejects_reported_misdecryption_configurations() {
        // Reject configurations that cause misdecryption: wrong party count
        // or same-ring parameters with a different plaintext modulus. Compute
        // maximal feasible lambdas, retaining the reproducer's lower bounds.
        // Matched real-smudging decryption is covered by tests/trbfv_e2e.rs.
        let manager_params = secure8192().unwrap().parameters;
        let same_ring_params = BfvParametersBuilder::new()
            .set_degree(8192)
            .set_plaintext_modulus(2)
            .set_moduli(&[0x0400000000c00001, 0x0400000000a40001, 0x0400000000990001])
            .set_variance(10)
            .set_error1_variance_str("17723039943798878305460955570711717478400")
            .unwrap()
            .build_arc()
            .unwrap();
        let manager = ShareManager::new(5, 2, manager_params.clone()).unwrap();
        let mut rng = crate::support::presets::rng(7);

        // Wrong party count: a one-party generator over the manager's exact
        // parameters.
        let parties_lambda = max_feasible_lambda(&manager_params, 1, 1);
        assert!(
            parties_lambda >= 71,
            "recorded review lambda 71 must remain feasible for the reported configuration"
        );
        let noise = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(
                manager_params.clone(),
                1,
                1,
                parties_lambda,
                FreshNoiseModel::BfvPublicKey,
            )
            .unwrap(),
        )
        .unwrap()
        .generate(&mut rng)
        .unwrap();
        let rng_snapshot = rng.clone();
        assert!(matches!(
            manager.generate_smudging_shares(noise, &mut rng),
            Err(Error::Threshold(
                ThresholdError::SmudgingNoisePartyCountMismatch {
                    noise_parties: 1,
                    dealer_parties: 5,
                }
            ))
        ));
        // Rejected before any dealing randomness was consumed.
        assert_eq!(rng, rng_snapshot);

        // Same ring, plaintext modulus t = 2 instead of t = 1,000,000, at
        // this configuration's largest feasible lambda.
        let plaintext_lambda = max_feasible_lambda(&same_ring_params, 5, 1);
        assert!(
            plaintext_lambda >= 88,
            "recorded review lambda 88 must remain feasible for the reported configuration"
        );
        let noise = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(
                same_ring_params,
                5,
                1,
                plaintext_lambda,
                FreshNoiseModel::BfvPublicKey,
            )
            .unwrap(),
        )
        .unwrap()
        .generate(&mut rng)
        .unwrap();
        let rng_snapshot = rng.clone();
        assert!(matches!(
            manager.generate_smudging_shares(noise, &mut rng),
            Err(Error::ParameterMismatch {
                left: crate::ParameterSource::SmudgingNoise,
                right: crate::ParameterSource::Parameters,
            })
        ));
        // Rejected before any dealing randomness was consumed.
        assert_eq!(rng, rng_snapshot);

        // The matched n = 5 configuration at its own largest feasible lambda
        // (recorded: 69) is still accepted.
        let matched_lambda = max_feasible_lambda(&manager_params, 5, 1);
        assert!(
            matched_lambda >= 69,
            "recorded review lambda 69 must remain feasible for the matched configuration"
        );
        let noise = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(
                manager_params.clone(),
                5,
                1,
                matched_lambda,
                FreshNoiseModel::BfvPublicKey,
            )
            .unwrap(),
        )
        .unwrap()
        .generate(&mut rng)
        .unwrap();
        assert!(manager.generate_smudging_shares(noise, &mut rng).is_ok());
    }

    #[test]
    fn test_share_generation_rejects_wrong_context_and_setter_rejects_noncanonical_secret() {
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
        assert!(matches!(
            noncanonical.set_coefficients(coefficients),
            Err(fhe_math::Error::NonCanonicalValue { .. })
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
        let pk = PublicKey::new(&sk, &mut rng).unwrap();

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
            .decryption_share(&ct, &key_share, AggregatedSmudgingShare::new(smudging_poly))
            .unwrap();
        assert!(!decryption_share.allows_variable_time_computations());
        let mut expected = Zeroizing::new((&ct.c[1] * key_share.as_ntt()).into_power_basis());
        *expected.as_mut() += &ct.c[0].clone().into_power_basis();
        assert_eq!(decryption_share, *expected);

        // The aggregated key owner is reusable; only the smudging owner is
        // consumed by each decryption-share computation.
        let second_decryption_share = manager
            .decryption_share(
                &ct,
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
        let result = manager.decrypt_from_shares(&shares, &reconstructing, &ct);
        let plaintext_found = result.expect("Failed to decrypt from shares");
        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");

        assert_eq!(decoded, plaintext_data);
    }

    #[test]
    fn decrypt_from_shares_lifts_through_plaintext_context_when_q0_below_t() {
        // q0 = 1153 < t = 4099 < Q = 1153 * 12289 keeps level 0 valid, but the
        // one-modulus reduction would silently truncate coefficients in
        // [q0, t). Reconstruction must lift through the plaintext context.
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(4099)
            .set_moduli(&[1153, 12289])
            .build_arc()
            .unwrap();
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let values = vec![4098u64; params.degree()];
        let pt = Plaintext::try_encode(&values, Encoding::poly(), &params).unwrap();
        let ctx = params.context_at_level(0).unwrap();

        // Constant Shamir control: every share carries the full phase
        // c0 = encode(m) with c1 = 0, so threshold reconstruction returns it
        // unchanged regardless of the party subset.
        let phase = Zeroizing::new(pt.to_poly().unwrap());
        let shares = vec![
            phase.as_ref().clone().into_power_basis(),
            phase.as_ref().clone().into_power_basis(),
        ];
        let ct = Ciphertext::new(
            vec![phase.as_ref().clone(), Poly::<Ntt>::zero(ctx)],
            &params,
        )
        .unwrap();

        let plaintext = manager.decrypt_from_shares(&shares, &[1, 2], &ct).unwrap();
        assert_eq!(
            Vec::<u64>::try_decode(&plaintext, Encoding::poly()).unwrap(),
            values
        );
    }

    #[test]
    fn test_decryption_share_rejects_nonzero_ciphertext_level() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng).unwrap();
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &params).unwrap();
        let mut ciphertext = public_key.try_encrypt(&plaintext, &mut rng).unwrap();
        ciphertext.switch_down().unwrap();

        let secret_poly = manager
            .coeffs_to_poly_level0(secret_key.coeffs.as_ref())
            .unwrap();
        let context = params.context_at_level(0).unwrap();
        let key_share = AggregatedSecretKeyShare::from_power_basis((*secret_poly).clone());
        let result = manager.decryption_share(
            &ciphertext,
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

    /// Observe `Zeroizing` calling `Poly::zeroize` on unwind without reading
    /// freed storage or adding instrumentation to ShareManager.
    struct PolyWipeProbe<R: RepresentationTag> {
        poly: Poly<R>,
        wiped: Arc<AtomicBool>,
    }

    impl<R: RepresentationTag> Zeroize for PolyWipeProbe<R> {
        fn zeroize(&mut self) {
            let had_data = self.poly.coefficients().iter().any(|&value| value != 0);
            self.poly.zeroize();
            self.wiped.store(
                had_data && self.poly.coefficients().iter().all(|&value| value == 0),
                Ordering::SeqCst,
            );
        }
    }

    /// The product and phase use the same `Zeroizing<Poly>` ownership in
    /// `decryption_share`. This checks the wipe mechanism for both NTT and
    /// power-basis polynomials; it does not inject a panic into that function.
    #[test]
    fn decryption_polynomial_guards_wipe_on_unwind() {
        let params = insecure().unwrap().parameters;
        let ctx = params.context_at_level(0).unwrap();
        let mut rng = crate::support::presets::rng(245);

        fn check<R: RepresentationTag>(poly: Poly<R>) {
            let wiped = Arc::new(AtomicBool::new(false));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = Zeroizing::new(PolyWipeProbe {
                    poly,
                    wiped: Arc::clone(&wiped),
                });
                panic!("simulated unwind while a polynomial is guarded");
            }));
            assert!(result.is_err());
            assert!(wiped.load(Ordering::SeqCst));
        }

        check(Poly::<Ntt>::random(ctx, &mut rng));
        check(Poly::<PowerBasis>::random(ctx, &mut rng));
    }

    #[test]
    fn decryption_share_rejects_mismatched_smudging_context() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();

        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng).unwrap();
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &params).unwrap();
        let ct = pk.try_encrypt(&plaintext, &mut rng).unwrap();

        let secret_key_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
        let key_share = AggregatedSecretKeyShare::from_power_basis((*secret_key_poly).clone());

        // Smudging built over a different ring level is rejected before any
        // secret product exists; the consumed smudging owner is then wiped by
        // its zeroizing drop.
        let other_context = params.context_at_level(1).unwrap();
        let smudging = AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(other_context));
        let result = manager.decryption_share(&ct, &key_share, smudging);

        assert!(matches!(
            result,
            Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::Ciphertext,
            })
        ));
    }

    #[test]
    fn test_decrypt_from_shares_rejects_nonzero_ciphertext_level() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng).unwrap();
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &params).unwrap();
        let mut ciphertext = public_key.try_encrypt(&plaintext, &mut rng).unwrap();
        ciphertext.switch_down().unwrap();

        let context = params.context_at_level(0).unwrap();
        let shares = vec![Poly::<PowerBasis>::zero(context)];
        let result = manager.decrypt_from_shares(&shares, &[1], &ciphertext);

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
        let public_key = PublicKey::new(&secret_key, &mut rng).unwrap();
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &params).unwrap();
        let mut ciphertext = public_key.try_encrypt(&plaintext, &mut rng).unwrap();
        ciphertext.c.pop();

        let context = params.context_at_level(0).unwrap();
        let result = manager.decrypt_from_shares(
            &[
                Poly::<PowerBasis>::zero(context),
                Poly::<PowerBasis>::zero(context),
            ],
            &[1, 2],
            &ciphertext,
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

    struct DecryptionFixture {
        manager: ShareManager,
        ciphertext: Ciphertext,
        shares: Vec<Poly<PowerBasis>>,
        values: Vec<u64>,
    }

    /// One dealer, zero smudging: isolates ShareManager reconstruction and
    /// party-ID ordering. Real smudging is covered by tests/trbfv_e2e.rs.
    fn decryption_fixture(n: usize, reconstructing: &[usize]) -> DecryptionFixture {
        let mut rng = crate::support::presets::rng(180);
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(n, (n - 1) / 2, params.clone()).unwrap();
        let secret_key = SecretKey::random(&params, &mut rng);
        let secret_key_poly = manager
            .coeffs_to_poly_level0(secret_key.coeffs.as_ref())
            .unwrap();
        let dealt = manager
            .generate_secret_key_shares(secret_key_poly, &mut rng)
            .unwrap()
            .into_transport();
        let pk = PublicKey::new(&secret_key, &mut rng).unwrap();
        let mut values = vec![42u64];
        values.resize(params.degree(), 0);
        let plaintext = Plaintext::try_encode(&values, Encoding::poly(), &params).unwrap();
        let ciphertext = pk.try_encrypt(&plaintext, &mut rng).unwrap();
        let ctx = params.context_at_level(0).unwrap();
        let shares = reconstructing
            .iter()
            .map(|&party_id| {
                let mut rows = Array2::zeros((params.moduli().len(), params.degree()));
                for (mut row, matrix) in rows.outer_iter_mut().zip(&dealt) {
                    row.assign(&matrix.row(party_id - 1));
                }
                let key_share = manager
                    .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(rows)])
                    .unwrap();
                manager
                    .decryption_share(
                        &ciphertext,
                        &key_share,
                        AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(ctx)),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(shares.len(), manager.threshold() + 1);
        DecryptionFixture {
            manager,
            ciphertext,
            shares,
            values,
        }
    }

    #[test]
    fn threshold_decryption_handles_committee_sizes_subsets_and_party_order() {
        let cases: &[(usize, &[usize])] = &[
            (3, &[1, 2]),
            (5, &[2, 4, 5]),
            (20, &[2, 4, 5, 7, 11, 13, 15, 17, 19, 20]),
            (15, &[10, 11, 15, 8, 6, 4, 3, 2]),
        ];
        for &(n, reconstructing) in cases {
            let fixture = decryption_fixture(n, reconstructing);
            let plaintext = fixture
                .manager
                .decrypt_from_shares(&fixture.shares, reconstructing, &fixture.ciphertext)
                .unwrap();
            assert_eq!(
                Vec::<u64>::try_decode(&plaintext, Encoding::poly()).unwrap(),
                fixture.values,
                "n={n}, parties={reconstructing:?}"
            );
        }
    }

    #[test]
    fn test_threshold_decryption_wrong_indices_fails() {
        let reconstructing = [1, 3, 4, 7, 9];
        let fixture = decryption_fixture(10, &reconstructing);
        let correct = fixture
            .manager
            .decrypt_from_shares(&fixture.shares, &reconstructing, &fixture.ciphertext)
            .unwrap();
        assert_eq!(
            Vec::<u64>::try_decode(&correct, Encoding::poly()).unwrap(),
            fixture.values
        );

        // A valid but wrong ID is not authenticated by this arithmetic layer.
        let wrong = [6, 3, 4, 7, 9];
        let incorrect = fixture
            .manager
            .decrypt_from_shares(&fixture.shares, &wrong, &fixture.ciphertext)
            .unwrap();
        assert_ne!(
            Vec::<u64>::try_decode(&incorrect, Encoding::poly()).unwrap(),
            fixture.values,
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
        let pk = PublicKey::new(&sk, &mut rng).unwrap();
        let pt = Plaintext::try_encode(&[1u64], Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        let ctx = params.context_at_level(0).unwrap();
        let shares: Vec<Poly<PowerBasis>> = (0..3).map(|_| Poly::<PowerBasis>::zero(ctx)).collect();

        // Duplicate index
        let result = manager.decrypt_from_shares(&shares, &[1, 2, 2], &ct);
        assert!(result.is_err());

        // Index 0 (would evaluate the sharing polynomial at the secret)
        let result = manager.decrypt_from_shares(&shares, &[0, 1, 2], &ct);
        assert!(result.is_err());

        // Index > n
        let result = manager.decrypt_from_shares(&shares, &[1, 2, 6], &ct);
        assert!(result.is_err());

        // Wrong share count: more than threshold + 1 is rejected
        let four: Vec<Poly<PowerBasis>> = (0..4).map(|_| Poly::<PowerBasis>::zero(ctx)).collect();
        let result = manager.decrypt_from_shares(&four, &[1, 2, 3, 4], &ct);
        assert!(result.is_err());

        // Shares from a different RNS level are rejected before reconstruction.
        let level_one = params.context_at_level(1).unwrap();
        let wrong_context: Vec<Poly<PowerBasis>> = (0..3)
            .map(|_| Poly::<PowerBasis>::zero(level_one))
            .collect();
        let result = manager.decrypt_from_shares(&wrong_context, &[1, 2, 3], &ct);
        assert!(matches!(result, Err(Error::ParameterMismatch { .. })));

        // Fewer than threshold + 1 is rejected
        let two: Vec<Poly<PowerBasis>> = (0..2).map(|_| Poly::<PowerBasis>::zero(ctx)).collect();
        let result = manager.decrypt_from_shares(&two, &[1, 2], &ct);
        assert!(result.is_err());
    }
}
