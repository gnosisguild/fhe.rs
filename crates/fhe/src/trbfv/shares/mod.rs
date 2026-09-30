//! Share collection and management for threshold BFV.
//!
//! This module provides the ShareManager struct that handles aggregation of secret shares
//! and computation of decryption shares in the threshold BFV scheme.

mod decryption;
mod secret_key;

pub use decryption::DecryptionShare;
pub use secret_key::{AggregatedSecretKeyShare, DealtSecretKeyShares, SecretKeyShare};

use super::prf::PartyPrfKeys;
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
use zeroize::{Zeroize, Zeroizing};

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
/// `n >= 3` and `T = (n - 1) / 2` (see `validate_threshold_config`).
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
    /// Utility to create a `Zeroizing<Poly>` from coefficients.
    ///
    /// # Arguments
    /// - `coeffs`: Coefficients that can be converted to `Poly` (`Box<[i64]>`,
    ///   `Array2<u64>`, etc.)
    /// - `ctx`: BFV context to use for the polynomial
    ///
    /// # Returns
    /// A `Zeroizing<Poly<PowerBasis>>` in `PowerBasis` representation.
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

    /// Aggregate collected secret-key shares into a reusable owner.
    ///
    /// The input owners are consumed (and zeroized on failure), while the
    /// resulting aggregate may be borrowed for any number of decryptions in
    /// the same key epoch.
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

    /// Generate Shamir secret shares of a caller-provided polynomial.
    ///
    /// Secret-key material is reusable across decryptions in the same key
    /// epoch. Fresh smudging noise is sampled locally at each partial
    /// decryption rather than dealt here.
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

        // Every coefficient of every contribution must be a canonical residue
        // below its own row's modulus `q_i` before anything is accumulated:
        // Modulus::add_vec below requires canonical inputs (it aborts or wraps
        // otherwise). Reducing here would silently accept malformed share
        // material and could change the represented share, so values `>= q_i`
        // are rejected instead. Shape was validated above.
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

    fn rns_shamir(&self) -> Result<RnsShamir<'_>, Error> {
        let ctx = self.params.context_at_level(0)?;
        RnsShamir::new(
            ctx.moduli_operators(),
            self.params.degree(),
            self.n,
            self.threshold,
        )
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
    /// - `ciphertext`: Borrowed ciphertext to decrypt (contains `a`, `b`)
    /// - `secret_key`: This party's aggregated share of the joint secret key
    /// - `party_id`: 1-based identity of this party; must belong to `S`
    /// - `reconstructing_parties`: The designated set `S`, 1-based, size
    ///   `threshold + 1`
    /// - `noise`: Fresh local smudging sampled for this manager's `n` and
    ///   parameters; consumed here
    /// - `prf_keys`: This party's `2n` committee PRF keys
    #[allow(clippy::indexing_slicing)] // BFV ciphertext always has exactly 2 components
    pub fn decryption_share(
        &self,
        ciphertext: &Ciphertext,
        secret_key: &AggregatedSecretKeyShare,
        party_id: usize,
        reconstructing_parties: &[usize],
        noise: SmudgingNoise,
        prf_keys: &PartyPrfKeys,
    ) -> Result<DecryptionShare, Error> {
        self.validate_ciphertext(ciphertext)?;
        if !noise.matches_configuration(self.n, &self.params) {
            return Err(Error::smudging_configuration_mismatch(
                noise.committee_size(),
                self.n,
            ));
        }
        if prf_keys.committee_size() != self.n {
            return Err(Error::invalid_party_count(
                prf_keys.committee_size(),
                self.n,
            ));
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
        let secret_key = secret_key.as_ntt();
        let mut es_i = noise.into_poly();
        es_i.disallow_variable_time_computations();
        if secret_key.ctx() != c1.ctx() || es_i.ctx() != c1.ctx() {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::Ciphertext,
            });
        }

        // Keep the secret product guarded before multiplication and through
        // the inverse NTT. The product is then guarded in coefficient form
        // while applying the public per-modulus Lagrange weights.
        let ctx = c1.ctx().clone();
        let mut product = Zeroizing::new(c1);
        product.disallow_variable_time_computations();
        *product.as_mut() *= secret_key;
        let replacement = Poly::zero(product.ctx());
        let c1sk = std::mem::replace(product.as_mut(), replacement).into_power_basis();
        let mut c1sk = Zeroizing::new(c1sk);
        c1sk.disallow_variable_time_computations();
        let mut scaled = ZeroizingArray2(c1sk.coefficients().to_owned());
        for (row_index, modulus) in ctx.moduli_operators().iter().enumerate() {
            let weights = shamir.lagrange_weights(modulus, reconstructing_parties)?;
            let lambda = weights
                .get(party_index)
                .copied()
                .ok_or_else(|| Error::invalid_party_id(party_id, self.n))?;
            let mut row = scaled.0.row_mut(row_index);
            let row_slice = row
                .as_slice_mut()
                .ok_or(fhe_math::Error::NonContiguousCoefficients)?;
            modulus.scalar_mul_vec(row_slice, lambda);
        }
        c1sk.as_mut()
            .set_coefficients(std::mem::take(&mut scaled.0))?;

        let mask = prf_keys.mask(reconstructing_parties, ciphertext)?;
        let d_share_poly = std::mem::replace(c1sk.as_mut(), Poly::<PowerBasis>::zero(&ctx));
        let mut d_share_poly = Zeroizing::new(d_share_poly);
        *d_share_poly.as_mut() += es_i.as_ref();
        *d_share_poly.as_mut() += &mask;
        let decryptors = super::prf::canonical_decryptors(reconstructing_parties);
        let digest = super::prf::context_digest(&decryptors, ciphertext)?;
        Ok(DecryptionShare {
            poly: std::mem::replace(d_share_poly.as_mut(), Poly::<PowerBasis>::zero(&ctx)),
            party_id,
            decryptors,
            digest,
        })
    }

    /// Combine partial decryptions for a designated set `S`.
    ///
    /// Implements FinDec of Colin de Verdière–Passelègue–Stehlé 2026:
    /// `b + Σ_{i∈S} p_i`. Lagrange interpolation is already applied in
    /// [`ShareManager::decryption_share`]; this step only sums the shares
    /// and adds the second ciphertext component. Every share must have been
    /// produced for the same designated set and ciphertext.
    ///
    /// # Arguments
    /// - `decryption_shares`: Exactly `threshold + 1` decryption shares
    /// - `ciphertext`: The original ciphertext being decrypted
    ///
    /// # Returns
    /// The decrypted plaintext
    // All indexing is on vectors built with known sizes matching the index ranges
    #[allow(clippy::indexing_slicing)]
    pub fn decrypt_from_shares(
        &self,
        decryption_shares: &[DecryptionShare],
        ciphertext: &Ciphertext,
    ) -> Result<Plaintext, Error> {
        self.validate_ciphertext_parameters(ciphertext)?;
        let par = ciphertext.params.clone();
        let ptxt_u64 = par.plaintext.as_u64().ok_or_else(|| {
            Error::ParametersError(crate::ParametersError::UnsupportedPlaintextModulus {
                reason: "threshold BFV decrypt_from_shares requires a u64 plaintext modulus"
                    .to_string(),
            })
        })?;
        self.params.validate_plaintext_level(ciphertext.level)?;

        if decryption_shares.len() != self.threshold + 1 {
            return Err(Error::share_count_mismatch(
                decryption_shares.len(),
                self.threshold + 1,
            ));
        }
        self.validate_ciphertext_shape(ciphertext)?;
        let Some(first) = decryption_shares.first() else {
            return Err(Error::share_count_mismatch(0, self.threshold + 1));
        };
        let expected_digest = super::prf::context_digest(&first.decryptors, ciphertext)?;
        if first.digest != expected_digest {
            return Err(Error::inconsistent_decryption_shares());
        }
        let shamir = self.rns_shamir()?;
        shamir.validate_decryptor_set(&first.decryptors)?;
        let ctx = self.params.context_at_level(0)?;
        let mut seen = std::collections::BTreeSet::new();
        for share in decryption_shares {
            if share.decryptors != first.decryptors || share.digest != expected_digest {
                return Err(Error::inconsistent_decryption_shares());
            }
            if !share.decryptors.contains(&share.party_id) {
                return Err(Error::invalid_party_id(share.party_id, self.n));
            }
            if !seen.insert(share.party_id) {
                return Err(Error::duplicate_party_id(share.party_id));
            }
            if share.poly.ctx().as_ref() != ctx.as_ref() {
                return Err(Error::ParameterMismatch {
                    left: crate::ParameterSource::Polynomial,
                    right: crate::ParameterSource::Parameters,
                });
            }
            shamir.validate_matrix(share.poly.coefficients(), share.party_id, "share")?;
        }
        if seen.len() != first.decryptors.len()
            || first.decryptors.iter().any(|id| !seen.contains(id))
        {
            return Err(Error::inconsistent_decryption_shares());
        }

        let mut result_poly = Zeroizing::new(first.poly.clone());
        result_poly.disallow_variable_time_computations();
        for share in decryption_shares.iter().skip(1) {
            *result_poly.as_mut() += &share.poly;
        }

        let mut c0 = ciphertext.c[0].clone();
        c0.disallow_variable_time_computations();
        *result_poly.as_mut() += &c0.into_power_basis();

        let level = self.params.context_level_at(ciphertext.level)?;
        let d = Zeroizing::new(
            result_poly
                .as_ref()
                .scale(&level.cipher_plain_context.scaler)
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
            let mut w = Zeroizing::new(v[..par.degree()].to_vec());
            let q = Modulus::new(par.moduli()[0]).map_err(Error::MathError)?;
            q.reduce_vec(&mut w);
            Modulus::new(ptxt_u64)
                .map_err(Error::MathError)?
                .reduce_vec(&mut w);
            Poly::<PowerBasis>::try_convert_from(w.as_slice(), ciphertext.c[0].ctx(), false)?
                .into_ntt()
        } else {
            // q_0 < 2t: lift through the plaintext-context modulus before
            // reducing, as in secret-key decryption.
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

/// Wipe-on-drop owner for coefficient matrices copied while weighting a
/// partial-decryption polynomial.
struct ZeroizingArray2(Array2<u64>);

impl Drop for ZeroizingArray2 {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(Zeroize::zeroize);
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
    use crate::support::examples::simulated_committee_prf_keys;
    use crate::support::presets::{insecure, secure8192};
    use crate::trbfv::prf::PartyPrfKeys;
    use crate::trbfv::smudging::{FreshNoiseModel, SmudgingConfig, SmudgingNoiseGenerator};
    use fhe_math::rq::{Ntt, RepresentationTag};
    use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
    use rand::rng;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn zero_smudging(params: &Arc<BfvParameters>, n: usize) -> SmudgingNoise {
        let ctx = params.context_at_level(0).unwrap();
        SmudgingNoise::from_poly(
            Zeroizing::new(Poly::<PowerBasis>::zero(ctx)),
            n,
            params.clone(),
        )
    }

    fn part_dec(
        manager: &ShareManager,
        ciphertext: &Ciphertext,
        secret_key: &AggregatedSecretKeyShare,
        party_id: usize,
        reconstructing: &[usize],
        prf_keys: &PartyPrfKeys,
        params: &Arc<BfvParameters>,
    ) -> DecryptionShare {
        manager
            .decryption_share(
                ciphertext,
                secret_key,
                party_id,
                reconstructing,
                zero_smudging(params, manager.n()),
                prf_keys,
            )
            .unwrap()
    }

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
        let generator = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params.clone(), n, 1, 0, FreshNoiseModel::BfvPublicKey).unwrap(),
        )
        .unwrap();
        let manager = ShareManager::new(n, threshold, params.clone()).unwrap();
        let mut rng = rng();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng).unwrap();
        let pt = Plaintext::try_encode(&[1u64], Encoding::poly(), &params).unwrap();
        let ct = pk.try_encrypt(&pt, &mut rng).unwrap();
        let key_share = AggregatedSecretKeyShare::from_power_basis(
            (*manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap()).clone(),
        );
        let prf_keys = simulated_committee_prf_keys(n, &mut rng);
        let reconstructing = vec![1usize, 2, 3];
        let noise = generator.generate(&mut rng).unwrap();
        assert!(
            manager
                .decryption_share(&ct, &key_share, 1, &reconstructing, noise, &prf_keys[0],)
                .is_ok()
        );
    }

    #[test]
    fn local_smudging_at_secure_bound_is_nonzero() {
        let params = secure8192().unwrap().parameters;
        let n = 3;
        let mut rng = rng();
        let config =
            SmudgingConfig::new(params.clone(), n, 1, 45, FreshNoiseModel::BfvPublicKey).unwrap();
        let generator = SmudgingNoiseGenerator::new(config).unwrap();
        let manager = ShareManager::new(n, 1, params.clone()).unwrap();
        let noise = generator.generate(&mut rng).unwrap();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng).unwrap();
        let pt = Plaintext::try_encode(&[1u64], Encoding::poly(), &params).unwrap();
        let ct = pk.try_encrypt(&pt, &mut rng).unwrap();
        let key_share = AggregatedSecretKeyShare::from_power_basis(
            (*manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap()).clone(),
        );
        let prf_keys = simulated_committee_prf_keys(n, &mut rng);
        let share = manager
            .decryption_share(&ct, &key_share, 1, &[1, 2], noise, &prf_keys[0])
            .unwrap();
        assert!(
            share.coefficients().iter().any(|&c| c != 0),
            "secure smudging should not be the zero polynomial"
        );
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
        let prf_keys = simulated_committee_prf_keys(n, &mut rng);
        let reconstructing = vec![1usize, 2];
        let _ = smudging_poly;

        // Compute decryption share.
        let decryption_share = part_dec(
            &manager,
            &ct,
            &key_share,
            1,
            &reconstructing,
            &prf_keys[0],
            &params,
        );
        assert!(!decryption_share.allows_variable_time_computations());

        // The aggregated key owner is reusable; smudging is consumed per call.
        let second_decryption_share = part_dec(
            &manager,
            &ct,
            &key_share,
            2,
            &reconstructing,
            &prf_keys[1],
            &params,
        );
        assert!(!second_decryption_share.allows_variable_time_computations());

        // This test uses the full secret as the "aggregate" for both parties;
        // two identical values at distinct Shamir x-coordinates reconstruct the
        // same value needed for plaintext recovery.
        let shares = vec![decryption_share, second_decryption_share];

        let result = manager.decrypt_from_shares(&shares, &ct);
        let plaintext_found = result.expect("Failed to decrypt from shares");
        assert_eq!(
            manager.decrypt_from_shares(&shares, &ct).unwrap(),
            plaintext_found
        );

        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");

        assert_eq!(decoded, plaintext_data);
    }

    #[test]
    fn decrypt_from_shares_lifts_through_plaintext_context_when_q0_below_t() {
        // q0 = 1153 < t = 4099 < Q = 1153 * 12289. Reducing only through
        // q0 would truncate plaintext coefficients in [q0, t).
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
        let phase = pt.to_poly().unwrap();
        let ciphertext = Ciphertext::new(vec![phase, Poly::<Ntt>::zero(ctx)], &params).unwrap();
        let decryptors = vec![1, 2];
        let shares = decryptors
            .iter()
            .copied()
            .map(|party_id| {
                DecryptionShare::from_parts(
                    Poly::<PowerBasis>::zero(ctx),
                    party_id,
                    decryptors.clone(),
                    &ciphertext,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let plaintext = manager.decrypt_from_shares(&shares, &ciphertext).unwrap();
        assert_eq!(
            Vec::<u64>::try_decode(&plaintext, Encoding::poly()).unwrap(),
            values
        );
    }

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

    #[test]
    fn decryption_polynomial_guards_wipe_on_unwind() {
        let params = insecure().unwrap().parameters;
        let ctx = params.context_at_level(0).unwrap();
        let mut rng = rng();

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
        let key_share = AggregatedSecretKeyShare::from_power_basis((*secret_poly).clone());
        let prf_keys = simulated_committee_prf_keys(manager.n(), &mut rng);
        let result = manager.decryption_share(
            &ciphertext,
            &key_share,
            1,
            &[1, 2],
            zero_smudging(&params, manager.n()),
            &prf_keys[0],
        );

        assert!(matches!(
            result,
            Err(Error::InvalidLevel {
                level: 1,
                min_level: 0,
                max_level: 0,
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

        let ctx = params.context_at_level(0).unwrap();
        let shares = vec![
            DecryptionShare::from_parts(Poly::<PowerBasis>::zero(ctx), 1, vec![1, 2], &ciphertext)
                .unwrap(),
            DecryptionShare::from_parts(Poly::<PowerBasis>::zero(ctx), 2, vec![1, 2], &ciphertext)
                .unwrap(),
        ];
        let result = manager.decrypt_from_shares(&shares, &ciphertext);

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

        let ctx = params.context_at_level(0).unwrap();
        let shares = vec![
            DecryptionShare::from_parts(Poly::<PowerBasis>::zero(ctx), 1, vec![1, 2], &ciphertext)
                .unwrap(),
            DecryptionShare::from_parts(Poly::<PowerBasis>::zero(ctx), 2, vec![1, 2], &ciphertext)
                .unwrap(),
        ];
        let result = manager.decrypt_from_shares(&shares, &ciphertext);

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

        let secret_key_shares_dealt = managers[0]
            .generate_secret_key_shares(secret_key_poly, &mut rng)
            .unwrap()
            .into_transport();

        let mut secret_key_collected: Vec<Vec<Array2<u64>>> = vec![vec![], vec![], vec![]];

        let mut secret_key_aggregates: Vec<Option<AggregatedSecretKeyShare>> =
            (0..n).map(|_| None).collect();

        for i in 0..n {
            let mut secret_key_rows = Array2::zeros((0, params.degree()));
            for secret_key_qi_matrix in secret_key_shares_dealt.iter().take(params.moduli().len()) {
                secret_key_rows
                    .push_row(ndarray::ArrayView::from(secret_key_qi_matrix.row(i)))
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
        let pk = PublicKey::new(&secret_key, &mut rng).unwrap();
        let mut plaintext_data = vec![23u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        let reconstructing = vec![1, 2];
        let prf_keys = simulated_committee_prf_keys(n, &mut rng);

        // Each party generates their decryption share
        let mut decryption_shares = Vec::new();

        // Testing for decryption between parties 0 and 1
        for i in 0..(threshold + 1) {
            let share = part_dec(
                &managers[i],
                &ct,
                secret_key_aggregates[i].as_ref().unwrap(),
                i + 1,
                &reconstructing,
                &prf_keys[i],
                &params,
            );
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with parties 1 and 2 reconstructing
        let result = managers[0].decrypt_from_shares(&decryption_shares, &ct);
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

        let secret_key_shares_dealt = managers[0]
            .generate_secret_key_shares(secret_key_poly, &mut rng)
            .unwrap()
            .into_transport();

        let mut secret_key_collected: Vec<Vec<Array2<u64>>> =
            vec![vec![], vec![], vec![], vec![], vec![]];

        let mut secret_key_aggregates: Vec<Option<AggregatedSecretKeyShare>> =
            (0..n).map(|_| None).collect();

        for i in 0..n {
            let mut secret_key_rows = Array2::zeros((0, params.degree()));
            for secret_key_qi_matrix in secret_key_shares_dealt.iter().take(params.moduli().len()) {
                secret_key_rows
                    .push_row(ndarray::ArrayView::from(secret_key_qi_matrix.row(i)))
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
        let pk = PublicKey::new(&secret_key, &mut rng).unwrap();
        let mut plaintext_data = vec![32u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Choose arbitrary reconstructing parties (1-based indices): {2, 4, 5}
        // Corresponding 0-based indices in vectors: {1, 3, 4}
        let chosen_indices = vec![1usize, 3usize, 4usize];
        let reconstructing: Vec<usize> = chosen_indices.iter().map(|x| x + 1).collect();
        let prf_keys = simulated_committee_prf_keys(n, &mut rng);

        // Each chosen party generates their decryption share
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            let share = part_dec(
                &managers[i],
                &ct,
                secret_key_aggregates[i].as_ref().unwrap(),
                i + 1,
                &reconstructing,
                &prf_keys[i],
                &params,
            );
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with selected parties
        let result = managers[0].decrypt_from_shares(&decryption_shares, &ct);
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

        let secret_key_shares_dealt = managers[0]
            .generate_secret_key_shares(secret_key_poly, &mut rng)
            .unwrap()
            .into_transport();

        let mut secret_key_collected: Vec<Vec<Array2<u64>>> = (0..n).map(|_| vec![]).collect();

        let mut secret_key_aggregates: Vec<Option<AggregatedSecretKeyShare>> =
            (0..n).map(|_| None).collect();

        for i in 0..n {
            let mut secret_key_rows = Array2::zeros((0, params.degree()));
            for secret_key_qi_matrix in secret_key_shares_dealt.iter().take(params.moduli().len()) {
                secret_key_rows
                    .push_row(ndarray::ArrayView::from(secret_key_qi_matrix.row(i)))
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
        let pk = PublicKey::new(&secret_key, &mut rng).unwrap();
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
        let prf_keys = simulated_committee_prf_keys(n, &mut rng);

        // Each chosen party generates their decryption share
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            let share = part_dec(
                &managers[i],
                &ct,
                secret_key_aggregates[i].as_ref().unwrap(),
                i + 1,
                &reconstructing,
                &prf_keys[i],
                &params,
            );
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with selected parties
        let result = managers[0].decrypt_from_shares(&decryption_shares, &ct);
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

        let secret_key_shares_dealt = managers[0]
            .generate_secret_key_shares(secret_key_poly, &mut rng)
            .unwrap()
            .into_transport();

        let mut secret_key_collected: Vec<Vec<Array2<u64>>> = (0..n).map(|_| vec![]).collect();

        let mut secret_key_aggregates: Vec<Option<AggregatedSecretKeyShare>> =
            (0..n).map(|_| None).collect();

        for i in 0..n {
            let mut secret_key_rows = Array2::zeros((0, params.degree()));
            for secret_key_qi_matrix in secret_key_shares_dealt.iter().take(params.moduli().len()) {
                secret_key_rows
                    .push_row(ndarray::ArrayView::from(secret_key_qi_matrix.row(i)))
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
        let pk = PublicKey::new(&secret_key, &mut rng).unwrap();
        let mut plaintext_data = vec![55u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Choose 5 fixed distinct parties (0-based): {0,2,3,6,8}
        let chosen_indices: Vec<usize> = vec![0usize, 2usize, 3usize, 6usize, 8usize];
        let reconstructing_correct: Vec<usize> = chosen_indices.iter().map(|x| x + 1).collect();
        let prf_keys = simulated_committee_prf_keys(n, &mut rng);

        // Each chosen party generates their decryption share
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            let share = part_dec(
                &managers[i],
                &ct,
                secret_key_aggregates[i].as_ref().unwrap(),
                i + 1,
                &reconstructing_correct,
                &prf_keys[i],
                &params,
            );
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Decrypt with correct indices -> should succeed and match plaintext
        let result_ok = managers[0].decrypt_from_shares(&decryption_shares, &ct);
        assert!(result_ok.is_ok());
        let plaintext_found_ok =
            result_ok.expect("Failed to decrypt from shares with correct indices");
        let decoded_ok: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found_ok, Encoding::poly())
            .expect("Decoding plaintext failed");
        assert_eq!(decoded_ok, plaintext_data);

        // Mix in a partial decryption crafted for a different designated set S'.
        let mut reconstructing_other = reconstructing_correct.clone();
        reconstructing_other[4] = 10;
        let mixed_share = part_dec(
            &managers[chosen_indices[0]],
            &ct,
            secret_key_aggregates[chosen_indices[0]].as_ref().unwrap(),
            chosen_indices[0] + 1,
            &reconstructing_other,
            &prf_keys[chosen_indices[0]],
            &params,
        );
        let mut mixed_shares = decryption_shares.clone();
        mixed_shares[0] = mixed_share;
        let result_bad = managers[0].decrypt_from_shares(&mixed_shares, &ct);
        assert!(
            result_bad.is_err(),
            "Partial decryptions from distinct designated sets must not combine"
        );
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
        let dummy = |party_id: usize, decryptors: Vec<usize>| {
            DecryptionShare::from_parts(Poly::<PowerBasis>::zero(ctx), party_id, decryptors, &ct)
                .unwrap()
        };
        let invalid_party_id = |party_id: usize, valid_party_id: usize, decryptors: Vec<usize>| {
            let mut share = dummy(valid_party_id, decryptors);
            // Model a malformed/deserialized share that bypassed `from_parts`;
            // constructor-level validation is covered separately.
            share.party_id = party_id;
            share
        };
        let decryptors = vec![1usize, 2, 3];

        let shares = vec![
            dummy(1, decryptors.clone()),
            dummy(2, decryptors.clone()),
            dummy(2, decryptors.clone()),
        ];
        let result = manager.decrypt_from_shares(&shares, &ct);
        assert!(result.is_err());

        let shares = vec![
            invalid_party_id(0, 1, decryptors.clone()),
            dummy(1, decryptors.clone()),
            dummy(2, decryptors.clone()),
        ];
        let result = manager.decrypt_from_shares(&shares, &ct);
        assert!(result.is_err());

        let shares = vec![
            dummy(1, decryptors.clone()),
            dummy(2, decryptors.clone()),
            invalid_party_id(6, 1, decryptors.clone()),
        ];
        let result = manager.decrypt_from_shares(&shares, &ct);
        assert!(result.is_err());

        let four = vec![
            dummy(1, vec![1, 2, 3, 4]),
            dummy(2, vec![1, 2, 3, 4]),
            dummy(3, vec![1, 2, 3, 4]),
            dummy(4, vec![1, 2, 3, 4]),
        ];
        let result = manager.decrypt_from_shares(&four, &ct);
        assert!(result.is_err());

        let level_one = params.context_at_level(1).unwrap();
        let wrong_context: Vec<_> = (1..=3)
            .map(|party_id| {
                DecryptionShare::from_parts(
                    Poly::<PowerBasis>::zero(level_one),
                    party_id,
                    decryptors.clone(),
                    &ct,
                )
                .unwrap()
            })
            .collect();
        let result = manager.decrypt_from_shares(&wrong_context, &ct);
        assert!(matches!(result, Err(Error::ParameterMismatch { .. })));

        let two = vec![dummy(1, vec![1, 2]), dummy(2, vec![1, 2])];
        let result = manager.decrypt_from_shares(&two, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_decryption_share_rejects_mismatched_smudging_configuration() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng).unwrap();
        let pt = Plaintext::try_encode(&[1u64], Encoding::poly(), &params).unwrap();
        let ct = pk.try_encrypt(&pt, &mut rng).unwrap();
        let key_share = AggregatedSecretKeyShare::from_power_basis(
            (*manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap()).clone(),
        );
        let prf_keys = simulated_committee_prf_keys(manager.n(), &mut rng);

        let err = manager
            .decryption_share(
                &ct,
                &key_share,
                1,
                &[1, 2],
                zero_smudging(&params, 1),
                &prf_keys[0],
            )
            .unwrap_err();
        assert_eq!(err, Error::smudging_configuration_mismatch(1, 3));
    }

    #[test]
    fn decryption_share_rejects_mismatched_smudging_context() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng).unwrap();
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &params).unwrap();
        let ciphertext = pk.try_encrypt(&plaintext, &mut rng).unwrap();
        let secret_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
        let key_share = AggregatedSecretKeyShare::from_power_basis((*secret_poly).clone());
        let prf_keys = simulated_committee_prf_keys(manager.n(), &mut rng);

        let other_context = params.context_at_level(1).unwrap();
        let smudging = SmudgingNoise::from_poly(
            Zeroizing::new(Poly::<PowerBasis>::zero(other_context)),
            3,
            params,
        );
        let result =
            manager.decryption_share(&ciphertext, &key_share, 1, &[1, 2], smudging, &prf_keys[0]);

        assert!(matches!(
            result,
            Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::Ciphertext,
            })
        ));
    }

    #[test]
    fn decryption_share_rejects_noise_from_different_parameters() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let other_params = secure8192().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng).unwrap();
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &params).unwrap();
        let ciphertext = pk.try_encrypt(&plaintext, &mut rng).unwrap();
        let secret_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
        let key_share = AggregatedSecretKeyShare::from_power_basis((*secret_poly).clone());
        let prf_keys = simulated_committee_prf_keys(manager.n(), &mut rng);

        let other_context = other_params.context_at_level(0).unwrap();
        let smudging = SmudgingNoise::from_poly(
            Zeroizing::new(Poly::<PowerBasis>::zero(other_context)),
            3,
            other_params,
        );
        let result =
            manager.decryption_share(&ciphertext, &key_share, 1, &[1, 2], smudging, &prf_keys[0]);

        assert_eq!(
            result.unwrap_err(),
            Error::smudging_configuration_mismatch(3, 3)
        );
    }

    #[test]
    fn decryption_share_roundtrips_through_parts() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng).unwrap();
        let pt = Plaintext::try_encode(&[7u64], Encoding::poly(), &params).unwrap();
        let ct = pk.try_encrypt(&pt, &mut rng).unwrap();
        let key_share = AggregatedSecretKeyShare::from_power_basis(
            (*manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap()).clone(),
        );
        let prf_keys = simulated_committee_prf_keys(manager.n(), &mut rng);
        let reconstructing = [1usize, 2];
        let original = part_dec(
            &manager,
            &ct,
            &key_share,
            1,
            &reconstructing,
            &prf_keys[0],
            &params,
        );
        let (poly, party_id, mut decryptors) = original.clone().into_parts();
        assert_eq!(poly, original.poly);
        assert_eq!(party_id, 1);
        assert_eq!(decryptors.as_slice(), &reconstructing);
        decryptors.reverse();
        let restored =
            crate::trbfv::DecryptionShare::from_parts(poly, party_id, decryptors, &ct).unwrap();
        assert_eq!(restored.poly, original.poly);
        assert_eq!(restored.party_id, original.party_id);
        assert_eq!(restored.decryptors, original.decryptors);
        assert_eq!(restored.digest, original.digest);
        assert!(matches!(
            crate::trbfv::DecryptionShare::from_parts(
                original.poly.clone(),
                original.party_id,
                vec![1, 2, 1],
                &ct,
            ),
            Err(Error::Threshold(ThresholdError::DuplicatePartyId {
                party_id: 1
            }))
        ));
        for (party_id, decryptors) in [(0, vec![1, 2]), (1, vec![0, 2]), (3, vec![1, 2])] {
            assert!(
                crate::trbfv::DecryptionShare::from_parts(
                    original.poly.clone(),
                    party_id,
                    decryptors,
                    &ct,
                )
                .is_err()
            );
        }
        let other = part_dec(
            &manager,
            &ct,
            &key_share,
            2,
            &reconstructing,
            &prf_keys[1],
            &params,
        );
        let plaintext = manager
            .decrypt_from_shares(&[restored, other], &ct)
            .unwrap();
        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext, Encoding::poly()).unwrap();
        assert_eq!(decoded[0], 7);
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

        let secret_key_shares_dealt = managers[0]
            .generate_secret_key_shares(secret_key_poly, &mut rng)
            .unwrap()
            .into_transport();

        let mut secret_key_collected: Vec<Vec<Array2<u64>>> = (0..n).map(|_| vec![]).collect();

        let mut secret_key_aggregates: Vec<Option<AggregatedSecretKeyShare>> =
            (0..n).map(|_| None).collect();

        for i in 0..n {
            let mut secret_key_rows = Array2::zeros((0, params.degree()));
            for secret_key_qi_matrix in secret_key_shares_dealt.iter().take(params.moduli().len()) {
                secret_key_rows
                    .push_row(ndarray::ArrayView::from(secret_key_qi_matrix.row(i)))
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
        let pk = PublicKey::new(&secret_key, &mut rng).unwrap();
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
        let prf_keys = simulated_committee_prf_keys(n, &mut rng);

        // Each chosen party generates their decryption share in the same (non-increasing) order
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            let share = part_dec(
                &managers[i],
                &ct,
                secret_key_aggregates[i].as_ref().unwrap(),
                i + 1,
                &reconstructing,
                &prf_keys[i],
                &params,
            );
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with non-increasing party order
        let result = managers[0].decrypt_from_shares(&decryption_shares, &ct);
        assert!(result.is_ok());

        // Validate plaintext
        let plaintext_found = result.expect("Failed to decrypt from shares");
        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");
        assert_eq!(decoded, plaintext_data);
    }
}
