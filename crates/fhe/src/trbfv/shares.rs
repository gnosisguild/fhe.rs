use crate::Error;
/// Share collection and management for threshold BFV.
///
/// This module provides the ShareManager struct that handles aggregation of secret shares
/// and computation of decryption shares in the threshold BFV scheme.
use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::trbfv::config::validate_threshold_config;
use crate::trbfv::smudging::SmudgingCoefficients;
use crate::trbfv::{ContributionBinding, ParticipantSet, SessionId};
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::zq::Modulus;
use fhe_math::{
    rns::{RnsContext, ScalingFactor},
    rq::{Context, Ntt, Poly, PowerBasis, RepresentationTag, scaler::Scaler},
};
use ndarray::{Array2, ArrayView1};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use shamir_rns::{BarrettField, Error as ShamirError, ShamirScheme, ShareMatrix as RnsShareMatrix};
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

fn map_shamir_error(error: ShamirError, party_id: usize, num_shares: usize) -> Error {
    match error {
        ShamirError::InvalidThreshold {
            shares_needed,
            num_shares,
        } => Error::invalid_threshold(shares_needed.saturating_sub(1), num_shares),
        ShamirError::TooManyShares {
            num_shares,
            modulus,
        } => Error::party_count_exceeds_modulus(num_shares, modulus),
        ShamirError::WrongShareCount { expected, actual } => {
            Error::share_count_mismatch(actual, expected)
        }
        ShamirError::InvalidPartyId { party_id } => Error::invalid_party_id(party_id, num_shares),
        ShamirError::DuplicatePartyId { party_id } => Error::duplicate_party_id(party_id),
        ShamirError::NonCanonicalShare { modulus, .. } => Error::malformed_shares(
            party_id,
            format!("non-canonical share residue for modulus {modulus}"),
        ),
        ShamirError::NonCanonicalSecret { modulus, .. } => Error::secret_sharing(format!(
            "non-canonical secret residue for modulus {modulus}"
        )),
        ShamirError::NonInvertible => Error::non_invertible_shares(),
        error @ (ShamirError::InvalidModulus { .. }
        | ShamirError::CompositeModulus { .. }
        | ShamirError::InvalidMatrixShape { .. }
        | ShamirError::InvalidMatrixStorage
        | ShamirError::EmptyBasis) => Error::secret_sharing(error.to_string()),
    }
}

/// Owning wrapper around a secret-key share coefficient matrix (`Array2<u64>`).
///
/// Generated shares, shares collected from other parties, and per-modulus
/// secret-key share matrices are all held in this wrapper so that the secret
/// material is erased when the value is dropped.
///
/// # Security semantics
///
/// - [`Zeroize`] overwrites every `u64` through safe mutable iteration.
/// - The type implements [`ZeroizeOnDrop`] unconditionally (see the manual
///   [`Drop`] impl), so ordinary `Vec<SecretShareMatrix>` storage, early
///   returns, and unwinding all zeroize the matrix without caller action.
/// - The inner matrix is private: callers can only borrow narrow row views
///   (see [`SecretShareMatrix::row`]) and shape information, and `Clone`
///   produces another protected owner. There is no raw-value escape.
/// - [`std::mem::forget`] or [`std::mem::ManuallyDrop`] can bypass Rust
///   destructors entirely; that language-level caveat applies to every
///   drop-based cleanup path and is not a supported API.
///
/// # Limitations
///
/// Copies made outside this wrapper (e.g. a row converted into a transport
/// buffer) are not erased by dropping the wrapper; external buffers, swap,
/// core dumps, and allocator behavior are outside this guarantee.
#[derive(Clone)]
pub struct SecretShareMatrix {
    matrix: Array2<u64>,
}

/// A non-cloneable protected matrix carrying one-time smudging-noise shares.
///
/// This type is deliberately distinct from [`SecretShareMatrix`]. Noise
/// generated for one decryption use cannot be cloned while it is dealt,
/// transported, or collected; ownership must eventually be consumed by
/// [`NoiseShareContribution::new`].
pub struct NoiseShareMatrix {
    matrix: Array2<u64>,
}

/// A cloneable, identified key-share contribution.
#[derive(Clone, Debug)]
pub struct KeyShareContribution {
    binding: ContributionBinding,
    matrix: SecretShareMatrix,
}

impl KeyShareContribution {
    /// Bind a protected receiver matrix to its contributing party.
    #[must_use]
    pub fn new(binding: ContributionBinding, matrix: SecretShareMatrix) -> Self {
        Self { binding, matrix }
    }

    /// The consistency metadata attached to this contribution.
    #[must_use]
    pub fn binding(&self) -> &ContributionBinding {
        &self.binding
    }
}

/// A consumed, non-cloneable identified noise-share contribution.
#[derive(Debug)]
pub struct NoiseShareContribution {
    binding: ContributionBinding,
    matrix: NoiseShareMatrix,
}

impl NoiseShareContribution {
    /// Bind a non-cloneable noise receiver matrix, consuming its owner.
    #[must_use]
    pub fn new(binding: ContributionBinding, matrix: NoiseShareMatrix) -> Self {
        Self { binding, matrix }
    }

    /// The consistency metadata attached to this contribution.
    #[must_use]
    pub fn binding(&self) -> &ContributionBinding {
        &self.binding
    }
}

impl Zeroize for KeyShareContribution {
    fn zeroize(&mut self) {
        self.matrix.zeroize();
    }
}

impl Drop for KeyShareContribution {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyShareContribution {}

impl Zeroize for NoiseShareContribution {
    fn zeroize(&mut self) {
        self.matrix.zeroize();
    }
}

impl Drop for NoiseShareContribution {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for NoiseShareContribution {}

impl SecretShareMatrix {
    /// Wrap an owned share matrix, placing it under automatic zeroization.
    ///
    /// The matrix is expected to hold canonical residues; validation of
    /// shapes and residues happens at the aggregation boundary, not here.
    #[must_use]
    pub fn new(matrix: Array2<u64>) -> Self {
        Self { matrix }
    }

    /// Assemble a protected matrix from borrowed party rows.
    ///
    /// The destination is preallocated and wrapped in [`Self`] before any row
    /// contents are copied. This guarantees that no unguarded accumulating
    /// allocation exists at any point, including error paths. The input rows
    /// remain borrowed and are never owned by the constructor.
    ///
    /// # Errors
    /// Returns an error when the rows do not all have the same length.
    pub fn from_rows(rows: &[ArrayView1<'_, u64>]) -> Result<Self, Error> {
        let columns = rows.first().map_or(0, |row| row.len());
        if let Some(row) = rows.iter().find(|row| row.len() != columns) {
            return Err(Error::inconsistent_degree(columns, row.len()));
        }
        let mut result = Self::new(Array2::zeros((rows.len(), columns)));
        for (mut destination, source) in result.matrix.outer_iter_mut().zip(rows) {
            destination.assign(source);
        }
        Ok(result)
    }

    /// The matrix shape as `(rows, columns)`.
    #[must_use]
    pub fn dim(&self) -> (usize, usize) {
        self.matrix.dim()
    }

    /// Number of rows in the matrix.
    #[must_use]
    pub fn nrows(&self) -> usize {
        self.matrix.nrows()
    }

    /// Number of columns in the matrix.
    #[must_use]
    pub fn ncols(&self) -> usize {
        self.matrix.ncols()
    }

    /// Borrow a single row of the matrix.
    ///
    /// This is the narrow view used for transport and collection (e.g.
    /// encrypting the share row addressed to one party). It is fallible so
    /// that out-of-bounds access is an error rather than a panic.
    ///
    /// # Errors
    /// Returns an error if `index >= nrows()`.
    pub fn row(&self, index: usize) -> Result<ArrayView1<'_, u64>, Error> {
        if index >= self.nrows() {
            return Err(Error::DefaultError(format!(
                "share matrix row index {index} out of bounds (nrows = {})",
                self.nrows()
            )));
        }
        Ok(self.matrix.row(index))
    }
}

impl NoiseShareMatrix {
    /// Wrap an owned noise-share matrix under automatic zeroization.
    #[must_use]
    pub fn new(matrix: Array2<u64>) -> Self {
        Self { matrix }
    }

    /// Assemble a non-cloneable noise matrix from borrowed party rows.
    pub fn from_rows(rows: &[ArrayView1<'_, u64>]) -> Result<Self, Error> {
        let columns = rows.first().map_or(0, |row| row.len());
        if let Some(row) = rows.iter().find(|row| row.len() != columns) {
            return Err(Error::inconsistent_degree(columns, row.len()));
        }
        let mut result = Self::new(Array2::zeros((rows.len(), columns)));
        for (mut destination, source) in result.matrix.outer_iter_mut().zip(rows) {
            destination.assign(source);
        }
        Ok(result)
    }

    /// The matrix shape as `(rows, columns)`.
    #[must_use]
    pub fn dim(&self) -> (usize, usize) {
        self.matrix.dim()
    }

    /// Borrow a single noise-share row for transport.
    pub fn row(&self, index: usize) -> Result<ArrayView1<'_, u64>, Error> {
        if index >= self.matrix.nrows() {
            return Err(Error::DefaultError(format!(
                "noise share matrix row index {index} out of bounds (nrows = {})",
                self.matrix.nrows()
            )));
        }
        Ok(self.matrix.row(index))
    }
}

// Redacted `Debug` so that `{:?}` never leaks the share values.
impl std::fmt::Debug for SecretShareMatrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretShareMatrix")
            .field("dim", &self.matrix.dim())
            .finish()
    }
}

impl Zeroize for SecretShareMatrix {
    fn zeroize(&mut self) {
        for value in self.matrix.iter_mut() {
            value.zeroize();
        }
    }
}

impl Drop for SecretShareMatrix {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretShareMatrix {}

impl std::fmt::Debug for NoiseShareMatrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseShareMatrix")
            .field("dim", &self.matrix.dim())
            .finish()
    }
}

impl Zeroize for NoiseShareMatrix {
    fn zeroize(&mut self) {
        for value in self.matrix.iter_mut() {
            value.zeroize();
        }
    }
}

impl Drop for NoiseShareMatrix {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for NoiseShareMatrix {}

trait ShareMatrixView {
    fn dim(&self) -> (usize, usize);
    fn row(&self, index: usize) -> Result<ArrayView1<'_, u64>, Error>;
}

trait ShareMatrixDestination: ShareMatrixView {
    fn zeroed(shape: (usize, usize)) -> Self;
    fn copy_from_rns(&mut self, source: &RnsShareMatrix) -> Result<(), Error>;
}

impl ShareMatrixView for SecretShareMatrix {
    fn dim(&self) -> (usize, usize) {
        self.dim()
    }

    fn row(&self, index: usize) -> Result<ArrayView1<'_, u64>, Error> {
        self.row(index)
    }
}

impl ShareMatrixView for NoiseShareMatrix {
    fn dim(&self) -> (usize, usize) {
        self.dim()
    }

    fn row(&self, index: usize) -> Result<ArrayView1<'_, u64>, Error> {
        self.row(index)
    }
}

impl ShareMatrixDestination for SecretShareMatrix {
    fn zeroed(shape: (usize, usize)) -> Self {
        Self::new(Array2::zeros(shape))
    }

    fn copy_from_rns(&mut self, source: &RnsShareMatrix) -> Result<(), Error> {
        let source = source.as_slice();
        for (destination, value) in self.matrix.iter_mut().zip(source) {
            *destination = *value;
        }
        Ok(())
    }
}

impl ShareMatrixDestination for NoiseShareMatrix {
    fn zeroed(shape: (usize, usize)) -> Self {
        Self::new(Array2::zeros(shape))
    }

    fn copy_from_rns(&mut self, source: &RnsShareMatrix) -> Result<(), Error> {
        let source = source.as_slice();
        for (destination, value) in self.matrix.iter_mut().zip(source) {
            *destination = *value;
        }
        Ok(())
    }
}

/// Owning wrapper around a secret polynomial (`Poly<R>`).
///
/// Used for the input to share dealing, the aggregated secret-key and
/// smudging polynomials, and the final decryption share. The inner
/// polynomial is erased on drop (delegating to `Poly::zeroize`) across normal
/// drops, early returns, and unwinding, including the representation
/// conversions [`SecretPoly::into_ntt`] and [`SecretPoly::into_power_basis`].
/// The underlying `fhe-math` consuming conversions guard their input while the
/// transform runs and guard freshly-built Shoup output while it is populated,
/// so a panic during conversion zeroizes both source and partial output.
/// `SecretPoly` enforces constant-time discipline: secret-bearing polynomials
/// never dispatch variable-time arithmetic, regardless of the source
/// polynomial's variable-time flag.
/// This normalization changes only the `allow_variable_time` metadata bit;
/// coefficient values and the protobuf wire format are otherwise unchanged.
/// With `protobuf`, serializing `SecretPoly::inner()` and deserializing it
/// round-trips the same coefficients with the dispatch flag normalized to
/// constant-time.
///
/// # Security semantics
///
/// - [`Zeroize`] delegates to [`Poly::zeroize`].
/// - The type implements [`ZeroizeOnDrop`] unconditionally (see the manual
///   [`Drop`] impl).
/// - Only borrowed access (`inner`, `coefficients`, `ctx`) and consuming
///   representation conversions that return another `SecretPoly`
///   ([`SecretPoly::into_ntt`], [`SecretPoly::into_power_basis`]) are
///   exposed. There is no public raw-polynomial extraction and no
///   raw-owner `Deref`.
/// - The final decryption share is a protocol message: it must remain
///   intact until transmitted/consumed. Zeroization-on-drop is a post-use
///   defense, not an in-flight erasure.
///
/// # Limitations
///
/// Copies made outside this wrapper, allocator behavior, swap, core dumps,
/// and already-recorded external buffers are outside this guarantee;
/// deliberate `std::mem::forget`/`ManuallyDrop` can bypass destructors.
#[derive(Clone)]
pub struct SecretPoly<R: RepresentationTag> {
    poly: Poly<R>,
}

/// A protected, metadata-bearing aggregate of key-share contributions.
#[derive(Clone, Debug)]
pub struct AggregatedKeyShare<R: RepresentationTag> {
    poly: SecretPoly<R>,
    participant_set: ParticipantSet,
}

impl<R: RepresentationTag> AggregatedKeyShare<R> {
    /// Borrow the participant set bound to this aggregate.
    #[must_use]
    pub fn participant_set(&self) -> &ParticipantSet {
        &self.participant_set
    }

    /// Borrow the protected aggregate's coefficient matrix.
    #[must_use]
    pub fn coefficients(&self) -> ndarray::ArrayView2<'_, u64> {
        self.poly.coefficients()
    }

    fn into_parts(mut self) -> (SecretPoly<R>, ParticipantSet) {
        let participant_set = self.participant_set.clone();
        let ctx = self.poly.ctx().clone();
        let poly = std::mem::replace(&mut self.poly, SecretPoly::new(Poly::<R>::zero(&ctx)));
        (poly, participant_set)
    }
}

impl AggregatedKeyShare<PowerBasis> {
    /// Consume this aggregate and transform its polynomial into NTT form.
    pub fn into_ntt(self) -> Result<AggregatedKeyShare<Ntt>, Error> {
        let (poly, participant_set) = self.into_parts();
        let poly = poly.into_ntt()?;
        Ok(AggregatedKeyShare {
            poly,
            participant_set,
        })
    }
}

impl AggregatedKeyShare<Ntt> {
    /// Consume this aggregate and transform its polynomial into power-basis form.
    pub fn into_power_basis(self) -> Result<AggregatedKeyShare<PowerBasis>, Error> {
        let (poly, participant_set) = self.into_parts();
        let poly = poly.into_power_basis()?;
        Ok(AggregatedKeyShare {
            poly,
            participant_set,
        })
    }
}

/// A non-cloneable aggregate of one decryption-use session's noise.
#[derive(Debug)]
pub struct OneTimeNoiseShare {
    poly: SecretPoly<PowerBasis>,
    participant_set: ParticipantSet,
    use_session: SessionId,
}

impl Zeroize for OneTimeNoiseShare {
    fn zeroize(&mut self) {
        self.poly.zeroize();
    }
}

impl Drop for OneTimeNoiseShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OneTimeNoiseShare {}

impl OneTimeNoiseShare {
    /// The key epoch and accepted participant set for this noise.
    #[must_use]
    pub fn participant_set(&self) -> &ParticipantSet {
        &self.participant_set
    }

    /// The caller-supplied one-time decryption-use identifier.
    #[must_use]
    pub fn use_session(&self) -> SessionId {
        self.use_session
    }
}

/// An identified protected decryption share.
#[derive(Clone, Debug)]
pub struct DecryptionShare {
    party_id: u32,
    participant_set: ParticipantSet,
    use_session: SessionId,
    poly: SecretPoly<PowerBasis>,
}

impl DecryptionShare {
    /// The party identifier inseparable from this share polynomial.
    #[must_use]
    pub fn party_id(&self) -> u32 {
        self.party_id
    }

    /// The key epoch participant set.
    #[must_use]
    pub fn participant_set(&self) -> &ParticipantSet {
        &self.participant_set
    }

    /// The decryption-use identifier.
    #[must_use]
    pub fn use_session(&self) -> SessionId {
        self.use_session
    }

    /// Borrow the protected polynomial's RNS coefficient matrix.
    #[must_use]
    pub fn coefficients(&self) -> ndarray::ArrayView2<'_, u64> {
        self.poly.coefficients()
    }

    /// Borrow the protected share polynomial for transport or diagnostics.
    #[must_use]
    pub(crate) fn poly(&self) -> &SecretPoly<PowerBasis> {
        &self.poly
    }
}

impl<R: RepresentationTag> SecretPoly<R> {
    /// Wrap an owned polynomial, placing it under automatic zeroization.
    ///
    /// The value is immediately owned by the protected wrapper; no
    /// unprotected access to the inner polynomial is exposed. The wrapper
    /// clears the source's variable-time flag before taking ownership, so
    /// secret-bearing arithmetic always uses constant-time dispatch.
    #[must_use]
    pub fn new(mut poly: Poly<R>) -> Self {
        poly.disallow_variable_time_computations();
        Self { poly }
    }

    /// The context of the wrapped polynomial.
    #[must_use]
    pub fn ctx(&self) -> &Arc<Context> {
        self.poly.ctx()
    }

    /// Borrow the RNS coefficient matrix of the wrapped polynomial.
    #[must_use]
    pub fn coefficients(&self) -> ndarray::ArrayView2<'_, u64> {
        self.poly.coefficients()
    }

    /// Borrow the inner polynomial for protocol arithmetic.
    ///
    /// The borrow cannot be consumed into an ordinary secret-bearing
    /// container; ownership always remains with the protected wrapper.
    #[must_use]
    pub fn inner(&self) -> &Poly<R> {
        &self.poly
    }
}

// Redacted `Debug` so that `{:?}` never leaks the polynomial coefficients.
impl<R: RepresentationTag> std::fmt::Debug for SecretPoly<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretPoly")
            .field("representation", &self.poly.representation())
            .field("ctx", &self.poly.ctx())
            .finish()
    }
}

impl<R: RepresentationTag> Zeroize for SecretPoly<R> {
    fn zeroize(&mut self) {
        self.poly.zeroize();
    }
}

impl<R: RepresentationTag> Drop for SecretPoly<R> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<R: RepresentationTag> ZeroizeOnDrop for SecretPoly<R> {}

impl<R: RepresentationTag> Zeroize for AggregatedKeyShare<R> {
    fn zeroize(&mut self) {
        self.poly.zeroize();
    }
}

impl<R: RepresentationTag> Drop for AggregatedKeyShare<R> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<R: RepresentationTag> ZeroizeOnDrop for AggregatedKeyShare<R> {}

impl SecretPoly<PowerBasis> {
    /// Consume the protected polynomial and return its NTT form, still
    /// protected. Used to prepare the secret input to decryption without
    /// extracting an unprotected polynomial.
    ///
    /// The underlying `fhe-math` conversion keeps the source polynomial under
    /// a zeroizing guard for the duration of the transform.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected polynomial dimensions do not match
    /// its context.
    #[must_use = "the protected conversion result must be checked"]
    pub fn into_ntt(mut self) -> Result<SecretPoly<Ntt>, Error> {
        // The wrapper implements Drop, so the inner polynomial cannot be
        // moved out directly; swap in an empty default that the wrapper's
        // drop zeroizes harmlessly.
        Ok(SecretPoly::new(std::mem::take(&mut self.poly).into_ntt()?))
    }
}

impl SecretPoly<Ntt> {
    /// Consume the protected NTT polynomial and return its PowerBasis form,
    /// still protected.
    ///
    /// The underlying `fhe-math` conversion keeps the source polynomial under
    /// a zeroizing guard for the duration of the transform.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected polynomial dimensions do not match
    /// its context.
    #[must_use = "the protected conversion result must be checked"]
    pub fn into_power_basis(mut self) -> Result<SecretPoly<PowerBasis>, Error> {
        Ok(SecretPoly::new(
            std::mem::take(&mut self.poly).into_power_basis()?,
        ))
    }
}

/// A non-cloneable protected polynomial containing one-time smudging noise.
///
/// The wrapper intentionally exposes no coefficient or polynomial borrow. It
/// can only be consumed by noise-share dealing, which preserves one-time
/// ownership until receiver aggregation.
#[derive(Debug)]
pub struct NoisePoly {
    poly: SecretPoly<PowerBasis>,
}

impl NoisePoly {
    fn into_secret_poly(mut self) -> SecretPoly<PowerBasis> {
        let ctx = self.poly.ctx().clone();
        std::mem::replace(
            &mut self.poly,
            SecretPoly::new(Poly::<PowerBasis>::zero(&ctx)),
        )
    }
}

impl Zeroize for NoisePoly {
    fn zeroize(&mut self) {
        self.poly.zeroize();
    }
}

impl Drop for NoisePoly {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for NoisePoly {}

/// Manager for threshold BFV share operations.
///
/// ShareManager coordinates the collection and processing of secret shares in the threshold BFV scheme.
/// It handles both the aggregation of collected shares and the computation of decryption shares.
///
/// # Threshold semantics
///
/// `threshold` is the degree `T` of the Shamir sharing polynomial, read as the
/// maximum number of corrupted parties the deployment tolerates. Reconstruction
/// requires `T + 1` shares. As a trBFV type, `ShareManager` enforces the same
/// invariants as [`TRBFV`](crate::trbfv::TRBFV): `n >= 3` and `T = (n - 1) / 2`
/// (see [`validate_threshold_config`]).
///
/// # Protocol Flow
/// 1. Each party generates secret shares using secret sharing
/// 2. Parties exchange shares through secure channels
/// 3. ShareManager aggregates collected shares to reconstruct partial secrets
/// 4. During decryption, ShareManager computes decryption shares from ciphertext
/// 5. Finally, threshold number of decryption shares are combined to decrypt
#[derive(Debug)]
pub struct ShareManager {
    /// Number of parties in the threshold scheme (must be `>= 3`)
    pub n: usize,
    /// Degree `T` of the Shamir sharing polynomial, i.e. the maximum number of
    /// corrupted parties the deployment tolerates (must equal `(n - 1) / 2`).
    /// Reconstruction requires `T + 1` shares.
    pub threshold: usize,
    /// BFV parameters (degree, moduli, etc.)
    pub params: Arc<BfvParameters>,
}

impl ShareManager {
    fn validate_decryption_level(&self, ciphertext: &Ciphertext) -> Result<(), Error> {
        if ciphertext.level != 0 {
            return Err(Error::invalid_ciphertext(format!(
                "threshold BFV decryption requires ciphertext level 0, got level {}",
                ciphertext.level
            )));
        }
        Ok(())
    }

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
        // Enforce the same `n >= 3` and `T = (n - 1) / 2` invariants as TRBFV.
        validate_threshold_config(n, threshold)?;

        //Note that in case we consider in the future using qi's that are not prime numbers (so
        //they would be only satisfying the condition of being coprime to each other which is
        //sufficient for Greco etc), we can use the utility get_smallest_prime_factor implemented
        //in crates/fhe-util/src/lib.rs

        let min_modulus = params
            .moduli()
            .iter()
            .min()
            .ok_or_else(|| Error::DefaultError("parameters have no moduli".to_string()))?;
        if (n as u128) >= *min_modulus as u128 {
            return Err(Error::party_count_exceeds_modulus(n, *min_modulus));
        }

        Ok(Self {
            n,
            threshold,
            params,
        })
    }

    /// Utility to create a protected polynomial from coefficients.
    ///
    /// # Arguments
    /// - `coeffs`: Coefficients that can be converted to Poly (Box<[i64]>, Array2<u64>, etc.)
    /// - `ctx`: BFV context to use for the polynomial
    ///
    /// # Returns
    /// A [`SecretPoly`] in PowerBasis representation, zeroized automatically
    /// on drop.
    pub fn coeffs_to_poly<T>(
        &self,
        coeffs: T,
        ctx: &Arc<Context>,
    ) -> Result<SecretPoly<PowerBasis>, Error>
    where
        Poly<PowerBasis>: TryConvertFrom<T>,
    {
        let poly = Poly::<PowerBasis>::try_convert_from(coeffs, ctx, false)?;
        Ok(SecretPoly::new(poly))
    }

    /// Convenience method using level 0 context from parameters.
    pub fn coeffs_to_poly_level0<T>(&self, coeffs: T) -> Result<SecretPoly<PowerBasis>, Error>
    where
        Poly<PowerBasis>: TryConvertFrom<T>,
    {
        let ctx = self.params.context_at_level(0)?;
        self.coeffs_to_poly(coeffs, ctx)
    }
    /// Convert one-time BigInt coefficients into a non-cloneable noise owner
    /// in full RNS representation at level 0 using the BFV context.
    ///
    /// The coefficients are read from the protected
    /// [`SmudgingCoefficients`] wrapper so that generated smudging material
    /// never crosses a raw `&[BigInt]` boundary.
    pub fn bigints_to_poly(&self, bigints: SmudgingCoefficients) -> Result<NoisePoly, Error> {
        let ctx = self.params.context_at_level(0)?;
        let mut poly =
            Poly::<PowerBasis>::from_bigints(bigints.as_slice(), ctx).map_err(Error::from)?;
        // `Zeroizing` cannot be unwrapped by value in this zeroize version;
        // swap the polynomial out so the guard drops an empty default and the
        // secret moves directly into the protected wrapper.
        Ok(NoisePoly {
            poly: SecretPoly::new(std::mem::take(&mut *poly)),
        })
    }

    /// Generate Shamir secret shares for polynomial coefficients from a
    /// pre-converted polynomial.
    pub fn generate_secret_shares_from_poly<R: RngCore + CryptoRng>(
        &mut self,
        poly: SecretPoly<PowerBasis>,
        rng: &mut R,
    ) -> Result<Vec<SecretShareMatrix>, Error> {
        self.generate_share_matrices(poly, rng)
    }

    /// Generate Shamir secret shares for one-time smudging noise.
    pub fn generate_noise_shares_from_poly<R: RngCore + CryptoRng>(
        &mut self,
        poly: NoisePoly,
        rng: &mut R,
    ) -> Result<Vec<NoiseShareMatrix>, Error> {
        self.generate_share_matrices(poly.into_secret_poly(), rng)
    }

    fn generate_share_matrices<R, M>(
        &mut self,
        poly: SecretPoly<PowerBasis>,
        rng: &mut R,
    ) -> Result<Vec<M>, Error>
    where
        R: RngCore + CryptoRng,
        M: ShareMatrixDestination + Send,
    {
        let moduli: Vec<u64> = poly.ctx().moduli().to_vec();
        let expected_moduli = self.params.moduli();
        let expected_shape = (expected_moduli.len(), self.params.degree());
        let generated_shape = (self.n, self.params.degree());
        if poly.ctx().as_ref() != self.params.context_at_level(0)?.as_ref()
            || moduli.as_slice() != expected_moduli
        {
            return Err(Error::inconsistent_moduli(
                moduli.len(),
                expected_moduli.len(),
            ));
        }

        let min_modulus = moduli
            .iter()
            .min()
            .ok_or_else(|| Error::DefaultError("moduli vector is empty".to_string()))?;

        if (self.n as u128) >= *min_modulus as u128 {
            return Err(Error::party_count_exceeds_modulus(self.n, *min_modulus));
        }

        let coefficients = poly.coefficients();
        if coefficients.dim() != expected_shape {
            return Err(Error::malformed_shares(
                0,
                format!(
                    "secret polynomial has shape {:?}, expected {expected_shape:?}",
                    coefficients.dim()
                ),
            ));
        }
        let coeff_rows: Vec<_> = coefficients.outer_iter().collect();

        // Generate one independent deterministic ChaCha20 seed per modulus.
        // The seed owner is zeroized after all parallel tasks complete.
        let mut seeds = Zeroizing::new(Vec::<[u8; 32]>::with_capacity(moduli.len()));
        for _ in &moduli {
            let mut seed = [0_u8; 32];
            rng.fill_bytes(&mut seed);
            seeds.push(seed);
            seed.zeroize();
        }

        let return_vec: Result<Vec<M>, Error> = moduli
            .par_iter()
            .zip(coeff_rows.par_iter())
            .enumerate()
            .map(|(i, (m, p))| -> Result<M, Error> {
                let seed = seeds
                    .get(i)
                    .copied()
                    .ok_or_else(|| Error::inconsistent_moduli(moduli.len(), seeds.len()))?;
                let mut seed = seed;
                let mut modulus_rng = ChaCha20Rng::from_seed(seed);
                seed.zeroize();
                let scheme = ShamirScheme::<BarrettField>::new(self.threshold + 1, self.n, *m)
                    .map_err(|error| map_shamir_error(error, 0, self.n))?;
                let coefficients = p.as_slice().ok_or_else(|| {
                    Error::DefaultError("non-contiguous coefficient row".to_string())
                })?;
                let matrix = scheme
                    .share_batch(coefficients, &mut modulus_rng)
                    .map_err(|error| map_shamir_error(error, 0, self.n))?;
                if (matrix.rows(), matrix.columns()) != generated_shape {
                    return Err(Error::malformed_shares(
                        0,
                        format!(
                            "generated share matrix has shape [{}, {}], expected {generated_shape:?}",
                            matrix.rows(),
                            matrix.columns()
                        ),
                    ));
                }
                let mut output = M::zeroed(generated_shape);
                output.copy_from_rns(&matrix)?;
                Ok(output)
            })
            .collect();

        return_vec
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
    /// - `sk_sss_collected`: One secret-key share matrix per contributing party (at most `n`;
    ///   fewer is allowed, e.g. when some parties aborted during dealing).
    ///   Each [`SecretShareMatrix`] has one row per modulus and one column per
    ///   coefficient. Smudging noise uses the separate consuming
    ///   [`ShareManager::aggregate_noise_shares`] API and
    ///   [`NoiseShareMatrix`] type; both material types are sensitive and are
    ///   zeroized automatically on drop.
    ///
    /// # Returns
    /// A protected polynomial representing the aggregated secret key material
    ///
    /// # Errors
    /// Returns an error if no shares are provided, if more than `n` matrices are
    /// provided, if any matrix does not have shape `[moduli, degree]`, or if any
    /// coefficient is not a canonical residue below its row's modulus (`>= q_i` is
    /// malformed, never reduced).
    pub fn aggregate_collected_shares(
        &self,
        participant_set: &ParticipantSet,
        contributions: &[KeyShareContribution],
    ) -> Result<AggregatedKeyShare<PowerBasis>, Error> {
        self.validate_contribution_bindings(
            participant_set,
            contributions.iter().map(KeyShareContribution::binding),
        )?;
        self.aggregate_matrices(
            participant_set,
            contributions
                .iter()
                .map(|contribution| &contribution.matrix),
        )
    }

    /// Consume and aggregate one identified noise contribution for one use.
    pub fn aggregate_noise_shares(
        &self,
        participant_set: &ParticipantSet,
        use_session: SessionId,
        contributions: Vec<NoiseShareContribution>,
    ) -> Result<OneTimeNoiseShare, Error> {
        self.validate_contribution_bindings(
            participant_set,
            contributions.iter().map(NoiseShareContribution::binding),
        )?;
        let poly = self.aggregate_matrices(
            participant_set,
            contributions
                .iter()
                .map(|contribution| &contribution.matrix),
        )?;
        let (poly, participant_set) = poly.into_parts();
        Ok(OneTimeNoiseShare {
            poly,
            participant_set,
            use_session,
        })
    }

    fn validate_contribution_bindings<'a, I>(
        &self,
        participant_set: &ParticipantSet,
        bindings: I,
    ) -> crate::Result<()>
    where
        I: IntoIterator<Item = &'a ContributionBinding>,
    {
        let invalid_id = participant_set
            .participant_ids()
            .iter()
            .copied()
            .find(|party_id| (*party_id as usize) > self.n);
        if let Some(participant_id) = invalid_id {
            return Err(Error::Threshold(
                crate::ThresholdError::InvalidParticipantId {
                    participant_id,
                    n: self.n,
                },
            ));
        }
        let bindings: Vec<_> = bindings.into_iter().collect();
        if bindings.len() > self.n {
            return Err(Error::share_count_mismatch(bindings.len(), self.n));
        }
        participant_set.validate_contributions(bindings.iter().copied())
    }

    fn aggregate_matrices<'a, I, M>(
        &self,
        participant_set: &ParticipantSet,
        matrices: I,
    ) -> Result<AggregatedKeyShare<PowerBasis>, Error>
    where
        I: IntoIterator<Item = &'a M>,
        M: ShareMatrixView + 'a,
    {
        let sk_sss_collected: Vec<_> = matrices.into_iter().collect();
        if sk_sss_collected.is_empty() {
            return Err(Error::share_count_mismatch(
                0,
                participant_set.participant_ids().len(),
            ));
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
            for row in 0..item.dim().0 {
                let q_i =
                    self.params.moduli().get(row).copied().ok_or_else(|| {
                        Error::DefaultError("modulus index out of range".to_string())
                    })?;
                let item_row = item.row(row)?;
                for (col, &value) in item_row.iter().enumerate() {
                    if value >= q_i {
                        return Err(Error::malformed_shares(
                            party_idx,
                            format!(
                                "share coefficient at row {row} (modulus q_i = {q_i}), column \
                                 {col} is not canonical; expected a residue in [0, {q_i})"
                            ),
                        ));
                    }
                }
            }
        }

        // Sum the share matrices row-wise modulo each RNS modulus, copying
        // only once into the result polynomial (instead of cloning each
        // contribution into its own Poly and adding those). The accumulator
        // holds secret material as soon as the first row is added, so it is
        // held in the protected share-matrix wrapper until it is moved into
        // the protected result polynomial.
        let mut sum = SecretShareMatrix::new(Array2::<u64>::zeros(expected_shape));
        for (row, mut acc_row) in sum.matrix.outer_iter_mut().enumerate() {
            let &modulus = self
                .params
                .moduli()
                .get(row)
                .ok_or_else(|| Error::DefaultError("modulus index out of range".to_string()))?;
            let q = Modulus::new(modulus).map_err(Error::MathError)?;
            let acc = acc_row
                .as_slice_mut()
                .ok_or_else(|| Error::DefaultError("non-contiguous row".to_string()))?;
            for item in &sk_sss_collected {
                let item_row = item.row(row)?;
                let share = item_row
                    .as_slice()
                    .ok_or_else(|| Error::DefaultError("non-contiguous row".to_string()))?;
                q.add_vec(acc, share);
            }
        }

        let mut sum_poly = Poly::<PowerBasis>::zero(ctx);
        sum_poly
            .set_coefficients(std::mem::take(&mut sum.matrix))
            .map_err(Error::MathError)?;
        Ok(AggregatedKeyShare {
            poly: SecretPoly::new(sum_poly),
            participant_set: participant_set.clone(),
        })
    }

    /// Compute decryption share from ciphertext and secret/smudging polynomials.
    ///
    /// This function computes a party's contribution to the threshold decryption process.
    /// Each party uses their aggregated key and noise shares to compute a decryption share.
    ///
    /// # Arguments
    /// - `ciphertext`: The ciphertext to decrypt (contains c0, c1 polynomials)
    /// - `sk_i`: This party's aggregated share of the joint secret key (output of
    ///   [`ShareManager::aggregate_collected_shares`]), not a party's own secret key
    /// - `es_i`: This party's aggregated share of the joint smudging noise,
    ///   aggregated the same way from the dealt noise shares
    ///
    /// # Returns
    /// A protected decryption share polynomial that contributes to the final
    /// decryption. The ciphertext must be at level 0; non-zero levels return
    /// [`Error::InvalidCiphertext`]. The returned share remains protected
    /// (it is not erased before transmission or reconstruction) and is
    /// zeroized automatically once dropped after use.
    #[allow(clippy::indexing_slicing)] // BFV ciphertext always has exactly 2 components
    pub fn decryption_share(
        &self,
        ciphertext: Arc<Ciphertext>,
        party_id: u32,
        sk_i: AggregatedKeyShare<Ntt>,
        use_session: SessionId,
        es_i: OneTimeNoiseShare,
    ) -> Result<DecryptionShare, Error> {
        if party_id == 0 || (party_id as usize) > self.n {
            return Err(Error::invalid_party_id(party_id as usize, self.n));
        }
        if sk_i.participant_set != es_i.participant_set {
            return Err(Error::Threshold(
                crate::ThresholdError::KeyNoiseBindingMismatch,
            ));
        }
        if es_i.use_session != use_session {
            return Err(Error::Threshold(
                crate::ThresholdError::DecryptionSessionMismatch,
            ));
        }
        if ciphertext.params != self.params {
            return Err(Error::invalid_ciphertext(
                "ciphertext parameters do not match this ShareManager's parameters",
            ));
        }
        self.validate_decryption_level(&ciphertext)?;
        // A degree-2 (unrelinearized) ciphertext has 3 components; silently
        // ignoring c[2] would produce a wrong plaintext.
        if ciphertext.c.len() != 2 {
            return Err(Error::invalid_ciphertext(format!(
                "expected 2 ciphertext components, got {}; relinearize before threshold \
                 decryption",
                ciphertext.c.len()
            )));
        }
        let mut c0 = ciphertext.c[0].clone();
        c0.disallow_variable_time_computations();
        let c0 = c0.into_power_basis()?;
        let mut c1 = ciphertext.c[1].clone();
        c1.disallow_variable_time_computations();
        if sk_i.poly.ctx() != c1.ctx() || es_i.poly.ctx() != c0.ctx() {
            return Err(Error::context_mismatch(
                &"share polynomial context",
                &"ciphertext context",
            ));
        }
        // c1sk = c1 * sk_i is the secret part of the decryption share; it is
        // computed from the borrowed inner polynomial and guarded immediately.
        let mut c1sk = Zeroizing::new((&c1 * sk_i.poly.inner()).into_power_basis()?);
        // `&c0 + &*c1sk` would clone the left operand into a fresh allocation
        // (fhe-math/src/rq/ops.rs `impl Add<&Poly> for &Poly`), leaving an
        // abandoned unzeroized copy behind. Instead the guarded `c1sk` buffer
        // is moved into the result (`std::mem::take` swaps in a default the
        // guard zeroizes harmlessly) and `c0` is added in place, so the secret
        // polynomial keeps exactly one owner under its guard throughout.
        let mut d_share = Zeroizing::new(std::mem::take(&mut *c1sk));
        *d_share += &c0;
        *d_share += es_i.poly.inner();
        Ok(DecryptionShare {
            party_id,
            participant_set: sk_i.participant_set.clone(),
            use_session,
            poly: SecretPoly::new(std::mem::take(&mut *d_share)),
        })
    }

    /// Decrypt ciphertext from collected decryption shares.
    ///
    /// This function performs the final step of threshold decryption by combining
    /// decryption shares from exactly `threshold + 1` parties to reconstruct the plaintext.
    ///
    /// # Arguments
    /// - `d_shares`: Exactly `threshold + 1` identified protected decryption
    ///   shares. Party IDs and binding metadata are carried by each share and
    ///   validated before reconstruction.
    /// - `ciphertext`: The original ciphertext being decrypted
    ///
    /// # Returns
    /// The decrypted plaintext. The ciphertext must be at level 0; non-zero
    /// levels return [`Error::InvalidCiphertext`].
    // All indexing is on vectors built with known sizes matching the index ranges
    #[allow(clippy::indexing_slicing)]
    pub fn decrypt_from_shares(
        &self,
        d_shares: Vec<DecryptionShare>,
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext, Error> {
        if ciphertext.params != self.params {
            return Err(Error::invalid_ciphertext(
                "ciphertext parameters do not match this ShareManager's parameters",
            ));
        }
        self.validate_decryption_level(&ciphertext)?;
        // Reconstruction consumes exactly threshold + 1 shares; requiring
        // exactness (rather than truncating extras) avoids silently depending
        // on the order of the provided shares.
        if d_shares.len() != self.threshold + 1 {
            return Err(Error::share_count_mismatch(
                d_shares.len(),
                self.threshold + 1,
            ));
        }
        let first = d_shares
            .first()
            .ok_or_else(|| Error::share_count_mismatch(0, 1))?;
        let participant_set = first.participant_set.clone();
        let use_session = first.use_session;
        let invalid_id = participant_set
            .participant_ids()
            .iter()
            .copied()
            .find(|party_id| *party_id == 0 || (*party_id as usize) > self.n);
        if let Some(participant_id) = invalid_id {
            return Err(Error::Threshold(
                crate::ThresholdError::InvalidParticipantId {
                    participant_id,
                    n: self.n,
                },
            ));
        }
        for share in &d_shares {
            if share.participant_set != participant_set || share.use_session != use_session {
                return Err(Error::Threshold(
                    crate::ThresholdError::IdentifiedShareMismatch,
                ));
            }
        }
        let reconstructing_parties: Vec<usize> = d_shares
            .iter()
            .map(|share| share.party_id as usize)
            .collect();
        // Shamir x-coordinates are 1-based, bounded by n, and must be distinct:
        // index 0 would evaluate the sharing polynomial at the secret itself,
        // and duplicates make the Lagrange denominators non-invertible.
        let mut seen = vec![false; self.n + 1];
        for &idx in &reconstructing_parties {
            if idx == 0 || idx > self.n {
                return Err(Error::invalid_party_id(idx, self.n));
            }
            if seen[idx] {
                return Err(Error::duplicate_party_id(idx));
            }
            seen[idx] = true;
        }
        // Validate share polynomial shapes before indexing into them: each
        // share must carry all RNS rows and all coefficient columns.
        let expected_shape = (self.params.moduli().len(), self.params.degree());
        let expected_ctx = self.params.context_at_level(0)?;
        let d_share_polys: Vec<&SecretPoly<PowerBasis>> =
            d_shares.iter().map(DecryptionShare::poly).collect();
        for (i, d_share_poly) in d_share_polys.iter().enumerate() {
            let party_id = reconstructing_parties.get(i).copied().ok_or_else(|| {
                Error::share_count_mismatch(reconstructing_parties.len(), d_share_polys.len())
            })?;
            if d_share_poly.ctx().as_ref() != expected_ctx.as_ref() {
                return Err(Error::context_mismatch(
                    &"decryption share polynomial context",
                    &"ShareManager level-zero context",
                ));
            }
            if d_share_poly.coefficients().dim() != expected_shape {
                return Err(Error::malformed_shares(
                    party_id,
                    format!(
                        "decryption share has shape {:?}, expected {expected_shape:?}",
                        d_share_poly.coefficients().dim()
                    ),
                ));
            }
        }
        // Each recovered row (one per modulus) holds secret coefficients; the
        // row is placed under a zeroizing guard before it is returned, so the
        // per-modulus allocations never live unguarded in the collected
        // vector, including error paths.
        let recovered: Result<Vec<Zeroizing<Vec<u64>>>, Error> = (0..self.params.moduli().len())
            .into_par_iter()
            .map(|m| -> Result<Zeroizing<Vec<u64>>, Error> {
                let modulus = self
                    .params
                    .moduli()
                    .get(m)
                    .copied()
                    .ok_or_else(|| Error::inconsistent_moduli(self.params.moduli().len(), m))?;
                let scheme = ShamirScheme::<BarrettField>::new(self.threshold + 1, self.n, modulus)
                    .map_err(|error| map_shamir_error(error, 0, self.n))?;
                let mut values = Zeroizing::new(Vec::with_capacity(
                    d_share_polys.len() * self.params.degree(),
                ));
                for (share_index, d_share_poly) in d_share_polys.iter().enumerate() {
                    let coefficients = d_share_poly.coefficients();
                    let row = coefficients.outer_iter().nth(m).ok_or_else(|| {
                        Error::malformed_shares(
                            reconstructing_parties
                                .get(share_index)
                                .copied()
                                .unwrap_or(0),
                            "missing modulus row".to_string(),
                        )
                    })?;
                    if row.iter().any(|value| *value >= modulus) {
                        let party_id = reconstructing_parties
                            .get(share_index)
                            .copied()
                            .unwrap_or(0);
                        return Err(Error::malformed_shares(
                            party_id,
                            format!(
                                "decryption share contains a non-canonical residue for modulus {modulus}"
                            ),
                        ));
                    }
                    values.extend(row.iter().copied());
                }
                let matrix = RnsShareMatrix::new(
                    d_share_polys.len(),
                    self.params.degree(),
                    std::mem::take(&mut *values),
                )
                .map_err(|error| map_shamir_error(error, 0, self.n))?;
                let reconstructed = scheme
                    .reconstruct_batch(&matrix, &reconstructing_parties)
                    .map_err(|error| {
                        let party_id = reconstructing_parties.first().copied().unwrap_or(0);
                        map_shamir_error(error, party_id, self.n)
                    })?;
                Ok(Zeroizing::new(reconstructed))
            })
            .collect();
        // Flat recovered-coefficient buffer is secret; guarded across the
        // assembly into the result polynomial. The rows are copied in while
        // their guards are still active and are zeroized when `recovered`
        // drops.
        let mut m_data = Zeroizing::new(Vec::with_capacity(
            self.params.moduli().len() * self.params.degree(),
        ));
        for row in recovered? {
            m_data.extend_from_slice(&row);
        }

        // scale result poly: the shaped recovered-coefficient matrix is secret
        // and is held in the protected wrapper until it is moved into the
        // result polynomial, so error paths drop it through the guard. The
        // matrix is shaped infallibly (`Array2::zeros`) and filled from the
        // guarded `m_data` while the guard is still alive;
        // `Array2::from_shape_vec` would require moving the raw `Vec<u64>` out
        // of the guard first, which would drop it unzeroized if shaping failed.
        if m_data.len() != self.params.moduli().len() * self.params.degree() {
            return Err(Error::DefaultError(
                "Failed to assemble recovered coefficients".to_string(),
            ));
        }
        let mut matrix = Array2::zeros((self.params.moduli().len(), self.params.degree()));
        for (slot, value) in matrix.iter_mut().zip(m_data.iter()) {
            *slot = *value;
        }
        let mut arr_matrix = SecretShareMatrix::new(matrix);
        let ctx = self.params.context_at_level(0)?;
        let mut result_poly = Zeroizing::new(Poly::<PowerBasis>::zero(ctx));
        result_poly.set_coefficients(std::mem::take(&mut arr_matrix.matrix))?;

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
                let factor = ScalingFactor::new(self.params.plaintext_big(), rns.modulus())
                    .map_err(Error::MathError)?;
                Scaler::new(&ctx_i, &plaintext_ctx, factor).map_err(Error::MathError)
            })
            .collect();
        let scalers = scalers?;

        let params = ciphertext.params.clone();
        // The threshold-decryption contract is u64 arithmetic: the plaintext
        // modulus must fit in u64 (checked representation-independently via
        // `try_plaintext`, so Large-stored values through `u64::MAX` are not
        // misclassified) and must construct the u64 `Modulus` used for the
        // final reduction (`Modulus::new` rejects values >= 2^62). Values
        // outside the contract return a typed error; the coefficient
        // accumulation below additionally uses checked addition so a future
        // bound relaxation cannot overflow silently.
        let ptxt_u64 = params.try_plaintext()?;
        let ptxt_modulus = Modulus::new(ptxt_u64).map_err(Error::MathError)?;

        let d = Zeroizing::new(
            result_poly
                .scale(&scalers[ciphertext.level])
                .map_err(Error::MathError)?,
        );
        let v = Zeroizing::new(
            Vec::<u64>::try_from(d.as_ref())
                .map_err(Error::from)?
                .into_iter()
                .map(|vi| {
                    vi.checked_add(ptxt_u64).ok_or_else(|| {
                        Error::DefaultError(
                            "threshold BFV decrypt_from_shares coefficient addition overflowed"
                                .to_string(),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        let mut w = Zeroizing::new(v[..params.degree()].to_vec());
        let q = Modulus::new(params.moduli()[0]).map_err(Error::MathError)?;
        q.reduce_vec(&mut w);
        ptxt_modulus.reduce_vec(&mut w);

        let poly =
            Poly::<PowerBasis>::try_convert_from(w.as_slice(), ciphertext.c[0].ctx(), false)?
                .into_ntt()?;

        let pt = Plaintext {
            params: params.clone(),
            value: crate::bfv::PlaintextValues::Small(std::mem::take(&mut *w).into_boxed_slice()),
            encoding: None,
            poly_ntt: poly,
            level: ciphertext.level,
        };
        Ok(pt)
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::ThresholdError;
    use crate::bfv::{BfvParametersBuilder, Encoding, PublicKey, SecretKey};
    #[cfg(feature = "protobuf")]
    use fhe_traits::{DeserializeWithContext, Serialize};
    use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
    use ndarray::Array2;
    use num_bigint::{BigInt, BigUint};
    use rand::{SeedableRng, rng};
    use rand_chacha::ChaCha8Rng;
    use shamir_rns::{BarrettField, ShamirScheme};

    // Error-path reachability notes for the zeroization guards (issue #126):
    //
    // - `generate_secret_shares_from_poly` and
    //   `generate_noise_shares_from_poly` allocate their destination wrapper
    //   before copying any Shamir output. The destination therefore remains
    //   zeroizing if a later operation unwinds.
    // - The infallible `Array2::zeros` + guarded-copy reconstruction assembly in
    //   `decrypt_from_shares` keeps the flat `Zeroizing<Vec<u64>>` buffer guarded
    //   until after shaping. The preserved length-mismatch error is unreachable
    //   through the public API: the coefficient matrix always has exactly
    //   `degree` entries per modulus row, so `m_data.len()` always equals the
    //   shape product (the checks are defensive behavior preservation).
    // - The per-modulus reconstruction buffers in `decrypt_from_shares` are
    //   returned under `Zeroizing` guards. The field-level batch API validates
    //   exact rows, IDs, and canonical values before interpolation.
    // - The Shamir interpolation error path (non-invertible Lagrange
    //   denominator) is validated in the independent shamir-rns crate.

    fn test_params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(4096)
            .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
            .build_arc()
            .unwrap()
    }

    fn test_participant_set(n: usize) -> ParticipantSet {
        ParticipantSet::new(
            SessionId::new([9; 32]),
            (1..=n).map(|party_id| party_id as u32).collect(),
        )
        .unwrap()
    }

    fn identified_key(
        poly: SecretPoly<Ntt>,
        participant_set: ParticipantSet,
    ) -> AggregatedKeyShare<Ntt> {
        AggregatedKeyShare {
            poly,
            participant_set,
        }
    }

    fn identified_noise(
        poly: SecretPoly<PowerBasis>,
        participant_set: ParticipantSet,
        use_session: SessionId,
    ) -> OneTimeNoiseShare {
        OneTimeNoiseShare {
            poly,
            participant_set,
            use_session,
        }
    }

    fn identified_decryption_share(
        poly: SecretPoly<PowerBasis>,
        party_id: u32,
        participant_set: ParticipantSet,
        use_session: SessionId,
    ) -> DecryptionShare {
        DecryptionShare {
            party_id,
            participant_set,
            use_session,
            poly,
        }
    }

    fn aggregate_receiver_key(
        manager: &ShareManager,
        participant_set: &ParticipantSet,
        matrix: SecretShareMatrix,
    ) -> AggregatedKeyShare<PowerBasis> {
        let shape = matrix.dim();
        let mut first = Some(matrix);
        let contributions = participant_set
            .participant_ids()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, party_id)| {
                let matrix = if index == 0 {
                    first.take().unwrap()
                } else {
                    SecretShareMatrix::new(Array2::zeros(shape))
                };
                KeyShareContribution::new(
                    ContributionBinding::new(participant_set.clone(), party_id).unwrap(),
                    matrix,
                )
            })
            .collect::<Vec<_>>();
        manager
            .aggregate_collected_shares(participant_set, &contributions)
            .unwrap()
    }

    fn key_contributions(
        participant_set: &ParticipantSet,
        matrices: Vec<SecretShareMatrix>,
    ) -> Vec<KeyShareContribution> {
        matrices
            .into_iter()
            .enumerate()
            .map(|(index, matrix)| {
                let party_id = participant_set
                    .participant_ids()
                    .get(index)
                    .copied()
                    .unwrap_or(1);
                KeyShareContribution::new(
                    ContributionBinding::new(participant_set.clone(), party_id).unwrap(),
                    matrix,
                )
            })
            .collect()
    }

    fn aggregate_zero_noise(
        manager: &ShareManager,
        participant_set: &ParticipantSet,
        use_session: SessionId,
    ) -> OneTimeNoiseShare {
        let shape = (manager.params.moduli().len(), manager.params.degree());
        let contributions = participant_set
            .participant_ids()
            .iter()
            .copied()
            .map(|party_id| {
                NoiseShareContribution::new(
                    ContributionBinding::new(participant_set.clone(), party_id).unwrap(),
                    NoiseShareMatrix::new(Array2::zeros(shape)),
                )
            })
            .collect();
        manager
            .aggregate_noise_shares(participant_set, use_session, contributions)
            .unwrap()
    }

    #[test]
    fn test_share_manager_creation() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        assert_eq!(manager.n, 5);
        assert_eq!(manager.threshold, 2);
        assert_eq!(manager.params, params);
    }

    #[test]
    fn secret_share_matrix_from_rows_validates_and_preserves_content() {
        let source = Array2::from_shape_vec((2, 3), vec![1, 2, 3, 4, 5, 6]).unwrap();
        let rows = source.outer_iter().collect::<Vec<_>>();
        let matrix = SecretShareMatrix::from_rows(&rows).unwrap();
        assert_eq!(matrix.dim(), (2, 3));
        assert_eq!(matrix.row(0).unwrap(), source.row(0));
        assert_eq!(matrix.row(1).unwrap(), source.row(1));

        let short = Array2::from_shape_vec((1, 2), vec![7, 8]).unwrap();
        let rows = vec![source.row(0), short.row(0)];
        assert!(SecretShareMatrix::from_rows(&rows).is_err());
    }

    #[test]
    fn shamir_errors_map_to_threshold_categories() {
        assert!(matches!(
            map_shamir_error(
                ShamirError::WrongShareCount {
                    expected: 3,
                    actual: 2,
                },
                1,
                5,
            ),
            Error::Threshold(ThresholdError::ShareCountMismatch {
                expected: 3,
                actual: 2,
            })
        ));
        assert!(matches!(
            map_shamir_error(ShamirError::DuplicatePartyId { party_id: 2 }, 2, 5,),
            Error::Threshold(ThresholdError::DuplicatePartyId { party_id: 2 })
        ));
        assert!(matches!(
            map_shamir_error(
                ShamirError::NonCanonicalShare {
                    value: 1613,
                    modulus: 1613,
                },
                2,
                5,
            ),
            Error::Threshold(ThresholdError::MalformedShares { party_id: 2, .. })
        ));
        assert!(matches!(
            map_shamir_error(ShamirError::NonInvertible, 2, 5),
            Error::Threshold(ThresholdError::NonInvertibleShares)
        ));
        assert!(matches!(
            map_shamir_error(ShamirError::EmptyBasis, 2, 5),
            Error::UnspecifiedInput(message)
                if message == "Secret sharing error: RNS basis must contain at least one modulus"
        ));
    }

    #[test]
    fn test_share_manager_rejects_threshold_zero() {
        // Regression: `ShareManager::new(5, 0)` was previously accepted even
        // though a degree-0 Shamir sharing polynomial is the secret itself, so
        // every party would hold the full secret.
        let params = test_params();
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
        let params = test_params();

        // n < 3 cannot host any valid threshold.
        for (n, threshold) in [(0usize, 1usize), (1, 0), (1, 1), (2, 0), (2, 1)] {
            assert!(
                ShareManager::new(n, threshold, params.clone()).is_err(),
                "ShareManager::new({n}, {threshold}) must be rejected"
            );
        }

        // threshold == 0 (a degree-0 sharing reveals the secret to every party).
        for n in [3usize, 5, 20] {
            assert!(
                ShareManager::new(n, 0, params.clone()).is_err(),
                "ShareManager::new({n}, 0) must be rejected"
            );
        }

        // threshold above (n - 1) / 2: the honest parties could not gather
        // threshold + 1 shares, losing guaranteed reconstruction.
        for (n, threshold) in [(5usize, 3usize), (5, 4), (5, 5), (5, 6), (3, 2)] {
            assert!(
                ShareManager::new(n, threshold, params.clone()).is_err(),
                "ShareManager::new({n}, {threshold}) must be rejected"
            );
        }

        // threshold below (n - 1) / 2: a maximal corrupted coalition would
        // hold threshold + 1 shares and reconstruct the secret on its own.
        for (n, threshold) in [(20usize, 8usize), (20, 7), (10, 3)] {
            assert!(
                ShareManager::new(n, threshold, params.clone()).is_err(),
                "ShareManager::new({n}, {threshold}) must be rejected"
            );
        }

        // For even n, T = n / 2 also fails under the (n - 1) / 2 cap.
        assert!(ShareManager::new(20, 10, params.clone()).is_err());
        assert!(ShareManager::new(4, 2, params.clone()).is_err());
    }

    #[test]
    fn test_share_manager_accepts_valid_threshold_config() {
        let params = test_params();
        // Exactly T = (n - 1) / 2, covering odd n, even n, and the minimum n.
        for (n, threshold) in [(3usize, 1usize), (4, 1), (5, 2), (10, 4), (20, 9), (21, 10)] {
            let manager = ShareManager::new(n, threshold, params.clone())
                .expect("a valid threshold config must be accepted");
            assert_eq!(manager.n, n);
            assert_eq!(manager.threshold, threshold);
        }
    }

    #[test]
    fn test_coeffs_to_poly_utility() {
        let params = test_params();
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
    fn test_bigints_to_poly() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();

        // Create BigInt coefficients (full degree)
        let degree = params.degree();
        let bigints: Vec<BigInt> = (0..degree).map(|i| BigInt::from(i as i64)).collect();

        let poly = manager
            .bigints_to_poly(SmudgingCoefficients::new(bigints))
            .unwrap();
        assert_eq!(poly.poly.coefficients().ncols(), degree);
        assert_eq!(poly.poly.coefficients().nrows(), params.moduli().len());
    }

    #[test]
    fn test_bigints_to_poly_wrong_size() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();

        // Wrong number of coefficients
        let bigints = vec![BigInt::from(1), BigInt::from(2)]; // Too few
        let result = manager.bigints_to_poly(SmudgingCoefficients::new(bigints));
        assert!(result.is_err());
    }

    #[test]
    fn test_decryption_share_computation() {
        let mut rng = rng();
        let params = test_params();
        let n = 3;
        // ShareManager now enforces T = (n - 1) / 2, so the minimal valid
        // configuration is (n = 3, threshold = 1), requiring two shares.
        let threshold = 1;
        let manager = ShareManager::new(n, threshold, params.clone()).unwrap();

        // Setup: Generate keys and encrypt a plaintext
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng).unwrap();

        let mut plaintext_data = vec![42u64, 100, 400];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct: Arc<Ciphertext> = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Generate polynomials for decryption share.
        let ctx = params.context_at_level(0).unwrap();
        let mut flagged_sk_source =
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx, false).unwrap();
        unsafe { flagged_sk_source.allow_variable_time_computations() }
        let flagged_sk = SecretPoly::new(flagged_sk_source.into_ntt().unwrap());
        assert!(!flagged_sk.inner().allows_variable_time_computations());
        let participant_set = test_participant_set(n);
        let use_session = SessionId::new([10; 32]);

        // The secret-key flag is normalized independently of the noise input.
        let flagged_sk_key = identified_key(flagged_sk, participant_set.clone());
        let decryption_share_from_flagged_sk = manager
            .decryption_share(
                ct.clone(),
                1,
                flagged_sk_key.clone(),
                use_session,
                identified_noise(
                    SecretPoly::new(Poly::<PowerBasis>::zero(ctx)),
                    participant_set.clone(),
                    use_session,
                ),
            )
            .unwrap();
        assert!(ct.c.get(1).unwrap().allows_variable_time_computations());
        assert!(
            !decryption_share_from_flagged_sk
                .poly()
                .inner()
                .allows_variable_time_computations()
        );

        // The smudging-noise flag is normalized independently of the key input.
        let unflagged_sk_source =
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx, false).unwrap();
        let unflagged_sk = SecretPoly::new(unflagged_sk_source.into_ntt().unwrap());
        let mut flagged_es_source = Poly::<PowerBasis>::zero(ctx);
        unsafe { flagged_es_source.allow_variable_time_computations() }
        let flagged_es = SecretPoly::new(flagged_es_source);
        assert!(!flagged_es.inner().allows_variable_time_computations());
        let flagged_es_key = identified_key(unflagged_sk, participant_set.clone());
        let decryption_share_from_flagged_es = manager
            .decryption_share(
                ct.clone(),
                1,
                flagged_es_key.clone(),
                use_session,
                identified_noise(flagged_es, participant_set.clone(), use_session),
            )
            .unwrap();
        assert!(
            !decryption_share_from_flagged_es
                .poly()
                .inner()
                .allows_variable_time_computations()
        );

        // Both independently flagged inputs must preserve functional
        // decryption. Two identical values at distinct Shamir x-coordinates
        // interpolate to a constant polynomial.
        for (decryption_share, key) in [
            (decryption_share_from_flagged_sk, flagged_sk_key),
            (decryption_share_from_flagged_es, flagged_es_key),
        ] {
            let second_share = manager
                .decryption_share(
                    ct.clone(),
                    2,
                    key,
                    use_session,
                    aggregate_zero_noise(&manager, &participant_set, use_session),
                )
                .unwrap();
            let shares = vec![decryption_share, second_share];
            let result = manager.decrypt_from_shares(shares, ct.clone());
            let plaintext_found = result.expect("Failed to decrypt from shares");
            let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
                .expect("Decoding plaintext failed");
            assert_eq!(decoded, plaintext_data);
        }
    }

    #[cfg(feature = "protobuf")]
    #[test]
    fn secret_poly_protobuf_roundtrip_preserves_coefficients_and_ct_flag() {
        let params = test_params();
        let ctx = params.context_at_level(0).unwrap();
        let coefficients = (0..params.degree())
            .map(|index| (index % 7) as i64)
            .collect::<Vec<_>>();
        let mut source = Poly::<PowerBasis>::try_convert_from(&coefficients, ctx, false).unwrap();
        unsafe { source.allow_variable_time_computations() }

        let wrapped = SecretPoly::new(source);
        assert!(!wrapped.inner().allows_variable_time_computations());

        let serialized = wrapped.inner().to_bytes();
        let round_tripped = Poly::<PowerBasis>::from_bytes(&serialized, ctx).unwrap();
        assert_eq!(round_tripped.coefficients(), wrapped.coefficients());
        assert!(!round_tripped.allows_variable_time_computations());
    }

    #[test]
    fn test_decryption_share_rejects_nonzero_ciphertext_level() {
        let mut rng = rng();
        let params = test_params();
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
        let participant_set = test_participant_set(3);
        let use_session = SessionId::new([10; 32]);
        let result = manager.decryption_share(
            Arc::new(ciphertext),
            1,
            identified_key(secret_poly.into_ntt().unwrap(), participant_set.clone()),
            use_session,
            identified_noise(
                SecretPoly::new(Poly::<PowerBasis>::zero(context)),
                participant_set,
                use_session,
            ),
        );

        assert_eq!(
            result.unwrap_err().to_string(),
            Error::invalid_ciphertext(
                "threshold BFV decryption requires ciphertext level 0, got level 1",
            )
            .to_string()
        );
    }

    #[test]
    fn test_decrypt_from_shares_rejects_nonzero_ciphertext_level() {
        let mut rng = rng();
        let params = test_params();
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng).unwrap();
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &params).unwrap();
        let mut ciphertext = public_key.try_encrypt(&plaintext, &mut rng).unwrap();
        ciphertext.switch_down().unwrap();

        let context = params.context_at_level(0).unwrap();
        let participant_set = test_participant_set(3);
        let use_session = SessionId::new([10; 32]);
        let shares = vec![identified_decryption_share(
            SecretPoly::new(Poly::<PowerBasis>::zero(context)),
            1,
            participant_set,
            use_session,
        )];
        let result = manager.decrypt_from_shares(shares, Arc::new(ciphertext));

        assert_eq!(
            result.unwrap_err().to_string(),
            Error::invalid_ciphertext(
                "threshold BFV decryption requires ciphertext level 0, got level 1",
            )
            .to_string()
        );
    }

    #[test]
    fn test_threshold_decryption_workflow() {
        let mut rng = rng();
        let params = test_params();
        let n = 3;
        let threshold = 1;

        // Setup multiple share managers (simulating different parties)
        let mut managers: Vec<ShareManager> = (0..n)
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

        let participant_set = test_participant_set(n);
        let use_session = SessionId::new([10; 32]);
        let mut sk_poly_sums = Vec::with_capacity(n);

        for (i, manager) in managers.iter().enumerate() {
            let mut node_share_m = Array2::zeros((0, params.degree()));
            for sk_sss_m in sk_sss.iter().take(params.moduli().len()) {
                node_share_m.push_row(sk_sss_m.row(i).unwrap()).unwrap();
            }
            sk_poly_sums.push(aggregate_receiver_key(
                manager,
                &participant_set,
                SecretShareMatrix::new(node_share_m),
            ));
        }

        // Create a test ciphertext
        let pk = PublicKey::new(&secret_key, &mut rng).unwrap();
        let mut plaintext_data = vec![123u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Each party generates their decryption share
        let mut decryption_shares = Vec::new();

        //Testing for decryption between parties 0 and 1
        //TODO Add tests for decyption between different parties than the first ones
        for i in 0..(threshold + 1) {
            let share = managers[i]
                .decryption_share(
                    ct.clone(),
                    (i + 1) as u32,
                    sk_poly_sums[i].clone().into_ntt().unwrap(),
                    use_session,
                    aggregate_zero_noise(&managers[i], &participant_set, use_session),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with parties 1 and 2 reconstructing
        let result = managers[0].decrypt_from_shares(decryption_shares.clone(), ct.clone());
        assert!(result.is_ok());

        // Test if we had correct decyption
        let plaintext_found = result.expect("Failed to decrypt from shares");
        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");

        assert_eq!(decoded, plaintext_data);
    }

    /// Run the n = 3, threshold = 1 threshold-decryption workflow with `params`
    /// and return the result of `decrypt_from_shares`. `plaintext_value` is
    /// encoded as the constant coefficient of a poly-encoded plaintext.
    fn threshold_decrypt_with_params(
        params: Arc<BfvParameters>,
        plaintext_value: u64,
    ) -> Result<Plaintext, Error> {
        let mut rng = rng();
        let n = 3;
        let threshold = 1;

        let mut managers: Vec<ShareManager> = (0..n)
            .map(|_| ShareManager::new(n, threshold, params.clone()).unwrap())
            .collect();

        let secret_key = SecretKey::random(&params, &mut rng);
        let sk_poly = managers[0]
            .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
            .unwrap();
        let sk_sss = managers[0]
            .generate_secret_shares_from_poly(sk_poly, &mut rng)
            .unwrap();

        let participant_set = test_participant_set(n);
        let use_session = SessionId::new([10; 32]);
        let mut sk_poly_sums = Vec::with_capacity(n);
        for (i, manager) in managers.iter().enumerate() {
            let mut node_share_m = Array2::zeros((0, params.degree()));
            for sk_sss_m in sk_sss.iter().take(params.moduli().len()) {
                node_share_m.push_row(sk_sss_m.row(i).unwrap()).unwrap();
            }
            sk_poly_sums.push(aggregate_receiver_key(
                manager,
                &participant_set,
                SecretShareMatrix::new(node_share_m),
            ));
        }

        let pk = PublicKey::new(&secret_key, &mut rng).unwrap();
        let mut plaintext_data = vec![plaintext_value];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        let mut decryption_shares = Vec::new();
        for i in 0..(threshold + 1) {
            let share = managers[i]
                .decryption_share(
                    ct.clone(),
                    (i + 1) as u32,
                    sk_poly_sums[i].clone().into_ntt().unwrap(),
                    use_session,
                    aggregate_zero_noise(&managers[i], &participant_set, use_session),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        managers[0].decrypt_from_shares(decryption_shares, ct)
    }

    #[test]
    fn decrypt_from_shares_rejects_plaintext_above_u64() {
        // A plaintext modulus above u64::MAX is stored in the Large
        // representation; the u64 threshold-decryption contract must surface
        // the representation-independent typed error (`PlaintextModulusNotU64`)
        // rather than a representation-dependent rejection.
        let p = BigUint::parse_bytes(b"340282366920938463463374607431768211507", 10).unwrap();
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus_biguint(p)
            .set_moduli_sizes(&[62, 62, 62, 62, 62])
            .build_arc()
            .unwrap();
        let err = threshold_decrypt_with_params(params, 123).unwrap_err();
        assert!(matches!(
            err,
            Error::ParametersError(crate::ParametersError::PlaintextModulusNotU64 { .. })
        ));
    }

    #[test]
    fn decrypt_from_shares_rejects_large_representation_outside_operational_bound() {
        // u64::MAX fits in u64 (so `try_plaintext` accepts it) but cannot
        // construct the u64 `Modulus` used for the final reduction (values
        // >= 2^62 are rejected): the operational bound must produce a typed
        // error, never an overflow or panic in the coefficient accumulation.
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus_biguint(BigUint::from(u64::MAX))
            .set_moduli(&[4611686018427387617, 4611686018427387329])
            .build_arc()
            .unwrap();
        let err = threshold_decrypt_with_params(params, 123).unwrap_err();
        assert!(matches!(
            err,
            Error::MathError(fhe_math::Error::InvalidModulus(_))
        ));
    }

    #[test]
    fn decrypt_from_shares_succeeds_with_u64_contract_plaintext() {
        // A plaintext modulus within the u64 operational bound decrypts
        // correctly through the representation-independent contract path.
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(1153)
            .set_moduli(&[4611686018427387617, 4611686018427387329])
            .build_arc()
            .unwrap();
        let plaintext = threshold_decrypt_with_params(params, 123).unwrap();
        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext, Encoding::poly()).unwrap();
        assert_eq!(decoded[0], 123);
    }

    #[test]
    fn test_threshold_decryption_workflow_arbitrary_parties_small() {
        let mut rng = rng();
        let params = test_params();
        let n = 5;
        let threshold = 2; // need 3 parties

        // Setup multiple share managers (simulating different parties)
        let mut managers: Vec<ShareManager> = (0..n)
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

        let participant_set = test_participant_set(n);
        let use_session = SessionId::new([10; 32]);
        let mut sk_poly_sums = Vec::with_capacity(n);

        for (i, manager) in managers.iter().enumerate() {
            let mut node_share_m = Array2::zeros((0, params.degree()));
            for sk_sss_m in sk_sss.iter().take(params.moduli().len()) {
                node_share_m.push_row(sk_sss_m.row(i).unwrap()).unwrap();
            }
            sk_poly_sums.push(aggregate_receiver_key(
                manager,
                &participant_set,
                SecretShareMatrix::new(node_share_m),
            ));
        }

        // Create a test ciphertext
        let pk = PublicKey::new(&secret_key, &mut rng).unwrap();
        let mut plaintext_data = vec![321u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Choose arbitrary reconstructing parties (1-based indices): {2, 4, 5}
        // Corresponding 0-based indices in vectors: {1, 3, 4}
        let chosen_indices = vec![1usize, 3usize, 4usize];

        // Each chosen party generates their decryption share
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            let share = managers[i]
                .decryption_share(
                    ct.clone(),
                    (i + 1) as u32,
                    sk_poly_sums[i].clone().into_ntt().unwrap(),
                    use_session,
                    aggregate_zero_noise(&managers[i], &participant_set, use_session),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with selected parties
        let result = managers[0].decrypt_from_shares(decryption_shares.clone(), ct.clone());
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
        let params = test_params();
        let n = 20;
        let threshold = 9; // (n - 1) / 2 for n = 20; need 10 parties

        // Setup multiple share managers (simulating different parties)
        let mut managers: Vec<ShareManager> = (0..n)
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

        let participant_set = test_participant_set(n);
        let use_session = SessionId::new([10; 32]);
        let mut sk_poly_sums = Vec::with_capacity(n);

        for (i, manager) in managers.iter().enumerate() {
            let mut node_share_m = Array2::zeros((0, params.degree()));
            for sk_sss_m in sk_sss.iter().take(params.moduli().len()) {
                node_share_m.push_row(sk_sss_m.row(i).unwrap()).unwrap();
            }
            sk_poly_sums.push(aggregate_receiver_key(
                manager,
                &participant_set,
                SecretShareMatrix::new(node_share_m),
            ));
        }

        // Create a test ciphertext
        let pk = PublicKey::new(&secret_key, &mut rng).unwrap();
        let mut plaintext_data = vec![777u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Choose arbitrary reconstructing parties (1-based indices): {2,4,5,7,11,13,15,17,19,20}
        // Corresponding 0-based indices: {1,3,4,6,10,12,14,16,18,19}
        let chosen_indices = vec![
            1usize, 3usize, 4usize, 6usize, 10usize, 12usize, 14usize, 16usize, 18usize, 19usize,
        ];
        // Each chosen party generates their decryption share
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            let share = managers[i]
                .decryption_share(
                    ct.clone(),
                    (i + 1) as u32,
                    sk_poly_sums[i].clone().into_ntt().unwrap(),
                    use_session,
                    aggregate_zero_noise(&managers[i], &participant_set, use_session),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with selected parties
        let result = managers[0].decrypt_from_shares(decryption_shares.clone(), ct.clone());
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
        let params = test_params();
        let n = 10;
        let threshold = 4; // need 5 parties

        // Setup multiple share managers (simulating different parties)
        let mut managers: Vec<ShareManager> = (0..n)
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

        let participant_set = test_participant_set(n);
        let use_session = SessionId::new([10; 32]);
        let mut sk_poly_sums = Vec::with_capacity(n);

        for (i, manager) in managers.iter().enumerate() {
            let mut node_share_m = Array2::zeros((0, params.degree()));
            for sk_sss_m in sk_sss.iter().take(params.moduli().len()) {
                node_share_m.push_row(sk_sss_m.row(i).unwrap()).unwrap();
            }
            sk_poly_sums.push(aggregate_receiver_key(
                manager,
                &participant_set,
                SecretShareMatrix::new(node_share_m),
            ));
        }

        // Create a test ciphertext
        let pk = PublicKey::new(&secret_key, &mut rng).unwrap();
        let mut plaintext_data = vec![555u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        let ctx = params.context_at_level(0).unwrap();
        // Choose 5 fixed distinct parties (0-based): {0,2,3,6,8}
        let chosen_indices: Vec<usize> = vec![0usize, 2usize, 3usize, 6usize, 8usize];
        // Each chosen party generates their decryption share
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            let share = managers[i]
                .decryption_share(
                    ct.clone(),
                    (i + 1) as u32,
                    sk_poly_sums[i].clone().into_ntt().unwrap(),
                    use_session,
                    aggregate_zero_noise(&managers[i], &participant_set, use_session),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Decrypt with correct indices -> should succeed and match plaintext
        let result_ok = managers[0].decrypt_from_shares(decryption_shares.clone(), ct.clone());
        assert!(result_ok.is_ok());
        let plaintext_found_ok =
            result_ok.expect("Failed to decrypt from shares with correct indices");
        let decoded_ok: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found_ok, Encoding::poly())
            .expect("Decoding plaintext failed");
        assert_eq!(decoded_ok, plaintext_data);

        // A share cannot be relabelled after creation. A duplicate or
        // unexpected embedded party ID is rejected instead of being paired
        // positionally with an external ID vector.
        let duplicate = vec![decryption_shares[0].clone(), decryption_shares[0].clone()];
        assert!(
            managers[0]
                .decrypt_from_shares(duplicate, ct.clone())
                .is_err()
        );
        let unexpected = vec![
            decryption_shares[0].clone(),
            identified_decryption_share(
                SecretPoly::new(Poly::<PowerBasis>::zero(ctx)),
                11,
                participant_set,
                use_session,
            ),
        ];
        assert!(managers[0].decrypt_from_shares(unexpected, ct).is_err());
    }

    #[test]
    fn test_aggregate_collected_shares_rejects_bad_input() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let shape = (params.moduli().len(), params.degree());
        let participant_set = test_participant_set(5);

        // Empty input
        assert!(
            manager
                .aggregate_collected_shares(&participant_set, &[])
                .is_err()
        );

        // More matrices than parties
        let matrices: Vec<SecretShareMatrix> = (0..6)
            .map(|_| SecretShareMatrix::new(Array2::zeros(shape)))
            .collect();
        let matrices = key_contributions(&participant_set, matrices);
        assert!(
            manager
                .aggregate_collected_shares(&participant_set, &matrices)
                .is_err()
        );

        // Wrong shape (rows and columns swapped)
        let bad = std::iter::once(SecretShareMatrix::new(Array2::zeros((
            params.degree(),
            params.moduli().len(),
        ))))
        .chain((1..5).map(|_| SecretShareMatrix::new(Array2::zeros(shape))))
        .collect();
        let bad = key_contributions(&participant_set, bad);
        assert!(
            manager
                .aggregate_collected_shares(&participant_set, &bad)
                .is_err()
        );

        // Valid: between 1 and n well-formed matrices
        let ok: Vec<SecretShareMatrix> = (0..5)
            .map(|_| SecretShareMatrix::new(Array2::zeros(shape)))
            .collect();
        let ok = key_contributions(&participant_set, ok);
        assert!(
            manager
                .aggregate_collected_shares(&participant_set, &ok)
                .is_ok()
        );
    }

    #[test]
    fn identified_aggregates_preserve_metadata_and_key_cloneability() {
        let params = test_params();
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let set = ParticipantSet::new(SessionId::new([9; 32]), vec![1, 2]).unwrap();
        let shape = (params.moduli().len(), params.degree());
        let contributions = vec![
            KeyShareContribution::new(
                ContributionBinding::new(set.clone(), 1).unwrap(),
                SecretShareMatrix::new(Array2::zeros(shape)),
            ),
            KeyShareContribution::new(
                ContributionBinding::new(set.clone(), 2).unwrap(),
                SecretShareMatrix::new(Array2::zeros(shape)),
            ),
        ];
        let key = manager
            .aggregate_collected_shares(&set, &contributions)
            .unwrap();
        let key_copy = key.clone();
        assert_eq!(key_copy.participant_set(), &set);
        let round_trip = key.into_ntt().unwrap().into_power_basis().unwrap();
        assert_eq!(round_trip.participant_set(), &set);
        assert_eq!(round_trip.coefficients(), key_copy.coefficients());
    }

    #[test]
    fn identified_metadata_errors_and_subset_decryptors() {
        let mut rng = rng();
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let accepted_set = ParticipantSet::new(SessionId::new([1; 32]), vec![1, 2]).unwrap();
        let foreign_epoch = ParticipantSet::new(SessionId::new([2; 32]), vec![1, 2]).unwrap();
        let different_set = ParticipantSet::new(SessionId::new([1; 32]), vec![1, 3]).unwrap();
        let shape = (params.moduli().len(), params.degree());

        let make_key_contribution = |binding_set: ParticipantSet| {
            binding_set
                .participant_ids()
                .iter()
                .copied()
                .map(|party_id| {
                    KeyShareContribution::new(
                        ContributionBinding::new(binding_set.clone(), party_id).unwrap(),
                        SecretShareMatrix::new(Array2::zeros(shape)),
                    )
                })
                .collect::<Vec<_>>()
        };
        let foreign_error = manager
            .aggregate_collected_shares(&accepted_set, &make_key_contribution(foreign_epoch))
            .unwrap_err();
        assert!(matches!(
            foreign_error,
            Error::Threshold(ThresholdError::ContributionSetMismatch)
        ));
        let different_set_error = manager
            .aggregate_collected_shares(&accepted_set, &make_key_contribution(different_set))
            .unwrap_err();
        assert!(matches!(
            different_set_error,
            Error::Threshold(ThresholdError::ContributionSetMismatch)
        ));
        let zero_noise_error = manager
            .aggregate_noise_shares(&accepted_set, SessionId::new([3; 32]), Vec::new())
            .unwrap_err();
        assert!(matches!(
            zero_noise_error,
            Error::Threshold(ThresholdError::MissingContribution)
        ));

        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng).unwrap();
        let plaintext = Plaintext::try_encode(&[7_u64], Encoding::poly(), &params).unwrap();
        let ciphertext = Arc::new(public_key.try_encrypt(&plaintext, &mut rng).unwrap());
        let ctx = params.context_at_level(0).unwrap();
        let key_poly = manager
            .coeffs_to_poly_level0(secret_key.coeffs.as_ref())
            .unwrap()
            .into_ntt()
            .unwrap();
        let key = identified_key(key_poly, accepted_set.clone());
        let noise_set = ParticipantSet::new(SessionId::new([4; 32]), vec![1, 2]).unwrap();
        let binding_error = manager
            .decryption_share(
                ciphertext.clone(),
                1,
                key.clone(),
                SessionId::new([5; 32]),
                identified_noise(
                    SecretPoly::new(Poly::<PowerBasis>::zero(ctx)),
                    noise_set,
                    SessionId::new([5; 32]),
                ),
            )
            .unwrap_err();
        assert!(matches!(
            binding_error,
            Error::Threshold(ThresholdError::KeyNoiseBindingMismatch)
        ));
        let session_error = manager
            .decryption_share(
                ciphertext.clone(),
                1,
                key.clone(),
                SessionId::new([6; 32]),
                identified_noise(
                    SecretPoly::new(Poly::<PowerBasis>::zero(ctx)),
                    accepted_set.clone(),
                    SessionId::new([5; 32]),
                ),
            )
            .unwrap_err();
        assert!(matches!(
            session_error,
            Error::Threshold(ThresholdError::DecryptionSessionMismatch)
        ));

        let use_session = SessionId::new([7; 32]);
        let decryptors = [4_u32, 5, 3]
            .into_iter()
            .map(|party_id| {
                manager
                    .decryption_share(
                        ciphertext.clone(),
                        party_id,
                        key.clone(),
                        use_session,
                        identified_noise(
                            SecretPoly::new(Poly::<PowerBasis>::zero(ctx)),
                            accepted_set.clone(),
                            use_session,
                        ),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let opened = manager
            .decrypt_from_shares(decryptors, ciphertext.clone())
            .unwrap();
        let decoded = Vec::<u64>::try_decode(&opened, Encoding::poly()).unwrap();
        assert_eq!(decoded.first().copied(), Some(7));
    }

    #[test]
    fn false_valid_party_label_can_produce_wrong_plaintext() {
        let mut rng = ChaCha8Rng::seed_from_u64(0x1d_125);
        let params = test_params();
        let n = 5;
        let threshold = 2;
        let mut managers: Vec<ShareManager> = (0..n)
            .map(|_| ShareManager::new(n, threshold, params.clone()).unwrap())
            .collect();
        let secret_key = SecretKey::random(&params, &mut rng);
        let sk_poly = managers[0]
            .coeffs_to_poly_level0(secret_key.coeffs.as_ref())
            .unwrap();
        let sk_sss = managers[0]
            .generate_secret_shares_from_poly(sk_poly, &mut rng)
            .unwrap();
        let participant_set =
            ParticipantSet::new(SessionId::new([0x31; 32]), (1..=n as u32).collect()).unwrap();
        let use_session = SessionId::new([0x32; 32]);
        let mut sk_poly_sums = Vec::with_capacity(n);
        for (receiver_index, manager) in managers.iter().enumerate() {
            let mut receiver_rows = Array2::zeros((0, params.degree()));
            for share_matrix in &sk_sss {
                receiver_rows
                    .push_row(share_matrix.row(receiver_index).unwrap())
                    .unwrap();
            }
            sk_poly_sums.push(aggregate_receiver_key(
                manager,
                &participant_set,
                SecretShareMatrix::new(receiver_rows),
            ));
        }

        let plaintext_data = {
            let mut values = vec![37_u64];
            values.resize(params.degree(), 0);
            values
        };
        let public_key = PublicKey::new(&secret_key, &mut rng).unwrap();
        let plaintext = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ciphertext = Arc::new(public_key.try_encrypt(&plaintext, &mut rng).unwrap());

        let actual_party_one = managers[0]
            .decryption_share(
                ciphertext.clone(),
                1,
                sk_poly_sums[0].clone().into_ntt().unwrap(),
                use_session,
                aggregate_zero_noise(&managers[0], &participant_set, use_session),
            )
            .unwrap();
        let actual_party_two = managers[1]
            .decryption_share(
                ciphertext.clone(),
                2,
                sk_poly_sums[1].clone().into_ntt().unwrap(),
                use_session,
                aggregate_zero_noise(&managers[1], &participant_set, use_session),
            )
            .unwrap();
        let actual_party_four = managers[3]
            .decryption_share(
                ciphertext.clone(),
                4,
                sk_poly_sums[3].clone().into_ntt().unwrap(),
                use_session,
                aggregate_zero_noise(&managers[3], &participant_set, use_session),
            )
            .unwrap();

        // The polynomial was computed for party 2, but its valid-range label is
        // deliberately changed to party 3. The type system accepts this because
        // labels are metadata, not authenticated claims; callers must bind and
        // authenticate party identity through the transport/orchestration layer.
        let relabeled_party_three = identified_decryption_share(
            actual_party_two.poly.clone(),
            3,
            participant_set,
            use_session,
        );
        let opened = managers[0]
            .decrypt_from_shares(
                vec![actual_party_one, relabeled_party_three, actual_party_four],
                ciphertext,
            )
            .unwrap();
        let decoded = Vec::<u64>::try_decode(&opened, Encoding::poly()).unwrap();
        assert_ne!(
            decoded, plaintext_data,
            "a false valid party label must change reconstruction"
        );
    }

    #[test]
    fn test_aggregate_collected_shares_rejects_non_canonical_q_at_each_row() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());
        let participant_set = test_participant_set(5);

        // A coefficient equal to its row's modulus q_i is not a canonical
        // residue and must be rejected against that row's own modulus, not a
        // global bound shared across rows.
        for (row, &q_i) in moduli.iter().enumerate() {
            let mut shares = Array2::zeros(shape);
            shares[[row, 3]] = q_i;
            let contributions = std::iter::once(SecretShareMatrix::new(shares))
                .chain((1..5).map(|_| SecretShareMatrix::new(Array2::zeros(shape))))
                .collect();
            let contributions = key_contributions(&participant_set, contributions);
            let err = manager
                .aggregate_collected_shares(&participant_set, &contributions)
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
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());
        let participant_set = test_participant_set(5);

        // u64::MAX would wrap to a small residue if reduced; it must be
        // rejected as malformed instead of being reduced.
        let mut shares = Array2::zeros(shape);
        shares[[0, 0]] = u64::MAX;
        let contributions = std::iter::once(SecretShareMatrix::new(shares))
            .chain((1..5).map(|_| SecretShareMatrix::new(Array2::zeros(shape))))
            .collect();
        let contributions = key_contributions(&participant_set, contributions);
        let err = manager
            .aggregate_collected_shares(&participant_set, &contributions)
            .expect_err("u64::MAX share entry must be rejected");
        let Error::Threshold(ThresholdError::MalformedShares { party_id, reason }) = &err else {
            panic!("expected MalformedShares, got: {err}");
        };
        assert_eq!(*party_id, 0);
        assert!(reason.contains("row 0") && reason.contains("column 0"));
        let first_modulus = moduli.first().copied().unwrap_or(0);
        assert!(reason.contains(&first_modulus.to_string()));
        let debug = format!("{err:?}");
        let display = format!("{err}");
        assert!(!debug.contains(&u64::MAX.to_string()));
        assert!(!display.contains(&u64::MAX.to_string()));
    }

    #[test]
    fn test_aggregate_collected_shares_accepts_q_minus_one_boundary() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());
        let participant_set = test_participant_set(5);

        // q_i - 1 is the largest valid canonical residue for each row; all
        // rows must be accepted against their own distinct moduli.
        let mut shares = Array2::zeros(shape);
        for (row, &q_i) in moduli.iter().enumerate() {
            shares.row_mut(row).fill(q_i - 1);
        }
        // Keep a test-only copy for the equality assertion; the wrapped
        // matrix moves into the protected wrapper for aggregation.
        let expected = shares.clone();
        let contributions = std::iter::once(SecretShareMatrix::new(shares))
            .chain((1..5).map(|_| SecretShareMatrix::new(Array2::zeros(shape))))
            .collect();
        let contributions = key_contributions(&participant_set, contributions);
        let result = manager
            .aggregate_collected_shares(&participant_set, &contributions)
            .expect("maximal canonical residues must be accepted");

        // A single aggregate preserves the input values exactly (the sum of a
        // single matrix is the matrix itself) and the accumulator does not
        // reduce them beyond the canonical residues supplied.
        assert_eq!(result.coefficients().into_owned(), expected);
    }

    #[test]
    fn test_aggregate_collected_shares_rejects_invalid_after_valid() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());
        let q1 = moduli[1];
        let participant_set = test_participant_set(5);

        // A valid first contribution followed by a malformed later one must
        // still surface the later contribution's error rather than reaching
        // Modulus::add_vec with the bad entry.
        let valid = Array2::zeros(shape);
        let mut invalid = Array2::zeros(shape);
        invalid[[1, 5]] = q1;
        let contributions = vec![
            SecretShareMatrix::new(valid),
            SecretShareMatrix::new(invalid),
            SecretShareMatrix::new(Array2::zeros(shape)),
            SecretShareMatrix::new(Array2::zeros(shape)),
            SecretShareMatrix::new(Array2::zeros(shape)),
        ];
        let contributions = key_contributions(&participant_set, contributions);
        let err = manager
            .aggregate_collected_shares(&participant_set, &contributions)
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
        let params = test_params();
        let n = 5;
        let threshold = 2; // needs exactly 3 shares
        let manager = ShareManager::new(n, threshold, params.clone()).unwrap();

        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng).unwrap();
        let pt = Plaintext::try_encode(&[1u64], Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        let ctx = params.context_at_level(0).unwrap();
        let participant_set = test_participant_set(n);
        let use_session = SessionId::new([10; 32]);
        let shares = |party_ids: &[u32]| {
            party_ids
                .iter()
                .copied()
                .map(|party_id| {
                    identified_decryption_share(
                        SecretPoly::new(Poly::<PowerBasis>::zero(ctx)),
                        party_id,
                        participant_set.clone(),
                        use_session,
                    )
                })
                .collect::<Vec<_>>()
        };

        // Duplicate index
        let result = manager.decrypt_from_shares(shares(&[1, 2, 2]), ct.clone());
        assert!(result.is_err());

        // Index 0 (would evaluate the sharing polynomial at the secret)
        let result = manager.decrypt_from_shares(shares(&[0, 1, 2]), ct.clone());
        assert!(result.is_err());

        // Index > n
        let result = manager.decrypt_from_shares(shares(&[1, 2, 6]), ct.clone());
        assert!(result.is_err());

        // Wrong share count: more than threshold + 1 is rejected
        let result = manager.decrypt_from_shares(shares(&[1, 2, 3, 4]), ct.clone());
        assert!(result.is_err());

        // Fewer than threshold + 1 is rejected
        let result = manager.decrypt_from_shares(shares(&[1, 2]), ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_from_shares_rejects_same_shape_foreign_context() {
        let mut rng = rng();
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng).unwrap();
        let plaintext = Plaintext::try_encode(&[1_u64], Encoding::poly(), &params).unwrap();
        let ciphertext = Arc::new(pk.try_encrypt(&plaintext, &mut rng).unwrap());
        let foreign_ctx =
            Context::new_arc(&[0xffffc4001, 0xffffee001, 0x1ffffe0001], params.degree()).unwrap();
        let shares = (0..3)
            .map(|party_id| {
                identified_decryption_share(
                    SecretPoly::new(Poly::<PowerBasis>::zero(&foreign_ctx)),
                    party_id + 1,
                    ParticipantSet::new(SessionId::new([9; 32]), vec![1, 2, 3]).unwrap(),
                    SessionId::new([10; 32]),
                )
            })
            .collect();

        let error = manager
            .decrypt_from_shares(shares, ciphertext)
            .expect_err("same-shape decryption shares from a foreign context must be rejected");
        assert!(matches!(error, Error::ContextMismatch { .. }));
    }

    // ── Protected wrapper contracts (issue #126) ─────────────────────────

    /// Compile-time assertion that a type implements the unconditional
    /// `ZeroizeOnDrop` contract, including representation conversions guarded
    /// by the underlying `fhe-math` polynomial implementation.
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn secret_share_matrix_zeroize_clears_every_entry() {
        // The wrapper must overwrite every u64 through safe mutable iteration.
        let matrix = Array2::from_shape_vec((2, 3), (1u64..=6).collect()).unwrap();
        let mut wrapper = SecretShareMatrix::new(matrix);
        wrapper.zeroize();
        for row in 0..wrapper.nrows() {
            let row_view = wrapper.row(row).unwrap();
            assert!(
                row_view.iter().all(|&value| value == 0),
                "zeroize must clear every matrix entry, row {row} still holds secrets"
            );
        }
        // Drop always runs zeroization; the in-place test above covers the
        // buffer contents while owned because the backing allocation cannot
        // be inspected after release (reading freed memory is forbidden).
        assert_zeroize_on_drop::<SecretShareMatrix>();
    }

    #[test]
    fn secret_share_matrix_clone_is_an_independent_protected_owner() {
        let matrix = Array2::from_shape_vec((2, 2), vec![7, 8, 9, 10]).unwrap();
        let original = SecretShareMatrix::new(matrix);
        let mut clone = original.clone();
        clone.zeroize();
        // Zeroizing the clone must not affect the original owner.
        for row in 0..original.nrows() {
            let row_view = original.row(row).unwrap();
            let expected = [7 + row as u64 * 2, 8 + row as u64 * 2];
            assert_eq!(row_view.to_vec(), expected);
        }
    }

    #[test]
    fn secret_share_matrix_row_access_is_fallible() {
        let matrix = Array2::from_shape_vec((2, 2), vec![1, 2, 3, 4]).unwrap();
        let wrapper = SecretShareMatrix::new(matrix);
        assert_eq!(wrapper.dim(), (2, 2));
        assert_eq!(wrapper.row(1).unwrap().to_vec(), vec![3, 4]);
        assert!(
            wrapper.row(2).is_err(),
            "out-of-bounds row must be an error, not a panic"
        );
        assert!(wrapper.row(usize::MAX).is_err());
    }

    #[test]
    fn secret_share_matrix_debug_is_redacted() {
        let matrix = Array2::from_shape_vec((2, 2), vec![123456, 654321, 111111, 222222]).unwrap();
        let wrapper = SecretShareMatrix::new(matrix);
        let debug = format!("{wrapper:?}");
        assert!(
            !debug.contains("123456") && !debug.contains("654321"),
            "Debug must not leak matrix values: {debug}"
        );
    }

    #[test]
    fn noise_share_matrix_zeroize_and_debug_are_protected() {
        let matrix = Array2::from_shape_vec((2, 2), vec![123456, 654321, 111111, 222222]).unwrap();
        let mut wrapper = NoiseShareMatrix::new(matrix);
        let debug = format!("{wrapper:?}");
        assert!(!debug.contains("123456") && !debug.contains("654321"));
        wrapper.zeroize();
        for row in 0..wrapper.dim().0 {
            assert!(wrapper.row(row).unwrap().iter().all(|&value| value == 0));
        }
        assert_zeroize_on_drop::<NoiseShareMatrix>();
    }

    #[test]
    fn noise_share_contribution_zeroize_and_debug_are_protected() {
        let set = test_participant_set(3);
        let binding = ContributionBinding::new(set, 1).unwrap();
        let matrix = NoiseShareMatrix::new(
            Array2::from_shape_vec((2, 2), vec![123456, 654321, 111111, 222222]).unwrap(),
        );
        let mut contribution = NoiseShareContribution::new(binding, matrix);
        let debug = format!("{contribution:?}");
        assert!(!debug.contains("123456") && !debug.contains("654321"));
        contribution.zeroize();
        assert!(contribution.matrix.matrix.iter().all(|&value| value == 0));
        assert_zeroize_on_drop::<NoiseShareContribution>();
    }

    #[test]
    fn secret_poly_zeroize_clears_coefficients() {
        let params = test_params();
        let ctx = params.context_at_level(0).unwrap();
        let coeffs: Vec<i64> = (1..=params.degree() as i64).collect();
        let poly = Poly::<PowerBasis>::try_convert_from(&coeffs, ctx, false).unwrap();
        let mut wrapper = SecretPoly::new(poly);
        wrapper.zeroize();
        assert!(
            wrapper.coefficients().iter().all(|&value| value == 0),
            "zeroize must clear every RNS coefficient"
        );
        assert_zeroize_on_drop::<SecretPoly<PowerBasis>>();
    }

    #[test]
    fn secret_poly_representation_conversions_stay_protected() {
        let params = test_params();
        let ctx = params.context_at_level(0).unwrap();
        let coeffs: Vec<i64> = (1..=params.degree() as i64).collect();
        let poly = Poly::<PowerBasis>::try_convert_from(&coeffs, ctx, false).unwrap();
        let wrapper = SecretPoly::new(poly);

        // into_ntt must return another protected owner, never a raw Poly.
        let ntt: SecretPoly<Ntt> = wrapper.into_ntt().unwrap();
        assert_eq!(
            ntt.coefficients().dim(),
            (params.moduli().len(), params.degree())
        );
        let power_basis: SecretPoly<PowerBasis> = ntt.into_power_basis().unwrap();
        assert_eq!(power_basis.ctx(), ctx);
        assert_zeroize_on_drop::<SecretPoly<Ntt>>();
    }

    #[test]
    fn secret_poly_debug_is_redacted() {
        let params = test_params();
        let ctx = params.context_at_level(0).unwrap();
        let coeffs: Vec<i64> = (1..=params.degree() as i64).collect();
        let poly = Poly::<PowerBasis>::try_convert_from(&coeffs, ctx, false).unwrap();
        let wrapper = SecretPoly::new(poly);
        let debug = format!("{wrapper:?}");
        assert!(
            !debug.contains("32767") && !debug.contains("coeff"),
            "Debug must not leak polynomial coefficients: {debug}"
        );
    }

    #[test]
    fn noise_poly_zeroize_and_debug_are_protected() {
        let params = test_params();
        let ctx = params.context_at_level(0).unwrap();
        let coeffs = vec![123456_i64; params.degree()];
        let poly = Poly::<PowerBasis>::try_convert_from(&coeffs, ctx, false).unwrap();
        let mut wrapper = NoisePoly {
            poly: SecretPoly::new(poly),
        };
        let debug = format!("{wrapper:?}");
        assert!(!debug.contains("123456") && !debug.contains("coeff"));
        wrapper.zeroize();
        assert!(wrapper.poly.coefficients().iter().all(|&value| value == 0));
        assert_zeroize_on_drop::<NoisePoly>();
    }

    #[test]
    fn aggregate_and_one_time_noise_zeroize_and_debug_are_protected() {
        let params = test_params();
        let ctx = params.context_at_level(0).unwrap();
        let coeffs = vec![123456_i64; params.degree()];
        let participant_set = test_participant_set(3);
        let use_session = SessionId::new([10; 32]);

        let noise_poly =
            SecretPoly::new(Poly::<PowerBasis>::try_convert_from(&coeffs, ctx, false).unwrap());
        let mut noise = identified_noise(noise_poly, participant_set.clone(), use_session);
        let noise_debug = format!("{noise:?}");
        assert!(!noise_debug.contains("123456") && !noise_debug.contains("coeff"));
        noise.zeroize();
        assert!(noise.poly.coefficients().iter().all(|&value| value == 0));
        assert_zeroize_on_drop::<OneTimeNoiseShare>();

        let key_poly =
            SecretPoly::new(Poly::<PowerBasis>::try_convert_from(&coeffs, ctx, false).unwrap())
                .into_ntt()
                .unwrap();
        let mut key = identified_key(key_poly, participant_set);
        let key_debug = format!("{key:?}");
        assert!(!key_debug.contains("123456") && !key_debug.contains("coeff"));
        key.zeroize();
        assert!(key.coefficients().iter().all(|&value| value == 0));
        assert_zeroize_on_drop::<AggregatedKeyShare<PowerBasis>>();
        assert_zeroize_on_drop::<AggregatedKeyShare<Ntt>>();
    }

    #[test]
    fn test_threshold_decryption_random_party_order() {
        let mut rng = rng();
        let params = test_params();
        let n = 15;
        let threshold = 7; // need 8 parties

        // Setup multiple share managers (simulating different parties)
        let mut managers: Vec<ShareManager> = (0..n)
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

        let participant_set = test_participant_set(n);
        let use_session = SessionId::new([10; 32]);
        let mut sk_poly_sums = Vec::with_capacity(n);

        for (i, manager) in managers.iter().enumerate() {
            let mut node_share_m = Array2::zeros((0, params.degree()));
            for sk_sss_m in sk_sss.iter().take(params.moduli().len()) {
                node_share_m.push_row(sk_sss_m.row(i).unwrap()).unwrap();
            }
            sk_poly_sums.push(aggregate_receiver_key(
                manager,
                &participant_set,
                SecretShareMatrix::new(node_share_m),
            ));
        }

        // Create a test ciphertext
        let pk = PublicKey::new(&secret_key, &mut rng).unwrap();
        let mut plaintext_data = vec![222u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Choose non-increasing reconstructing parties (0-based) of size threshold+1
        // Example: {9,10,14,7,5,3,2,1} => (1-based) {10,11,15,8,6,4,3,2}
        let chosen_indices = vec![
            9usize, 10usize, 14usize, 7usize, 5usize, 3usize, 2usize, 1usize,
        ];
        // Each chosen party generates their decryption share in the same (non-increasing) order
        let mut decryption_shares = Vec::new();
        for &i in &chosen_indices {
            let share = managers[i]
                .decryption_share(
                    ct.clone(),
                    (i + 1) as u32,
                    sk_poly_sums[i].clone().into_ntt().unwrap(),
                    use_session,
                    aggregate_zero_noise(&managers[i], &participant_set, use_session),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with non-increasing party order
        let result = managers[0].decrypt_from_shares(decryption_shares.clone(), ct.clone());
        assert!(result.is_ok());

        // Validate plaintext
        let plaintext_found = result.expect("Failed to decrypt from shares");
        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");
        assert_eq!(decoded, plaintext_data);
    }

    #[test]
    fn test_generated_shares_recover_to_secret_per_modulus() {
        // Regression coverage for the migrated batch path: each per-modulus
        // matrix is party-major and reconstructs the dealt canonical
        // polynomial coefficient vector without BigInt interpolation.
        let params = test_params();
        let mut manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let ctx = params.context_at_level(0).unwrap();
        let coeffs: Vec<i64> = (0..params.degree() as i64).map(|i| i % 7).collect();
        let secret_poly =
            SecretPoly::new(Poly::<PowerBasis>::try_convert_from(&coeffs, ctx, false).unwrap());

        let shares = manager
            .generate_secret_shares_from_poly(secret_poly, &mut rng())
            .unwrap();
        assert_eq!(shares.len(), params.moduli().len());
        for share in &shares {
            assert_eq!(share.dim(), (manager.n, params.degree()));
        }

        // Recover the dealt secret per modulus from the rows of
        // `threshold + 1` distinct parties. The 1-based party ids are the
        // Shamir x-coordinates; row `party - 1` of each per-modulus matrix is
        // that party's share.
        let parties: Vec<usize> = vec![1, 2, 3];
        for (m, q) in params.moduli().iter().copied().enumerate() {
            let shamir_ss =
                ShamirScheme::<BarrettField>::new(manager.threshold + 1, manager.n, q).unwrap();
            let values = parties
                .iter()
                .map(|party| {
                    let row = shares[m].row(party - 1).unwrap();
                    row.iter().copied().collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let selected = RnsShareMatrix::new(
                parties.len(),
                params.degree(),
                values.into_iter().flatten().collect(),
            )
            .unwrap();
            let recovered = shamir_ss.reconstruct_batch(&selected, &parties).unwrap();
            for (expected, actual) in coeffs.iter().zip(recovered) {
                assert_eq!(
                    actual, *expected as u64,
                    "modulus {m}: recovered share must equal the dealt secret"
                );
            }
        }
    }
}
