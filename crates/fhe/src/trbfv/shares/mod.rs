//! Share collection and management for threshold BFV.
//!
//! This module provides the ShareManager struct that handles aggregation of secret shares
//! and computation of decryption shares in the threshold BFV scheme.

mod secret_key;
mod smudging;

pub use secret_key::{AggregatedSecretKeyShare, DealtSecretKeyShares, SecretKeyShare};
pub use smudging::{AggregatedSmudgingShare, DealtSmudgingShares, SmudgingShare};

use super::rns_shamir::RnsShamir;
use super::transport::{NoiseWitnessProvenance, SmudgingNoiseWitness};
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
    /// - `coeffs`: Coefficients that can be converted to Poly (`Box<[i64]>`, `Array2<u64>`, etc.)
    /// - `ctx`: BFV context to use for the polynomial
    ///
    /// # Returns
    /// A `Zeroizing<Poly>` in PowerBasis representation
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
    ///
    /// # Binding checks
    ///
    /// Before the polynomial is extracted or any randomness is consumed, the
    /// noise owner must have been sampled for this manager's party count and
    /// its complete BFV parameter set must equal this manager's parameters
    /// (pointer-equality fast path, then value equality, so independently
    /// built equivalent configurations are accepted). This rejects noise
    /// dealt under a different party count, plaintext modulus, ciphertext
    /// moduli, or error variance — cases ring-context equality alone cannot
    /// catch. A rejected owner is dropped unread and wiped through its
    /// zeroizing storage.
    ///
    /// The circuit size `m`, multiplicative depth, and `lambda` that drive
    /// the ciphertext-noise and smudging bounds (and whether the bound is
    /// feasible) are caller choices and are deliberately not verified here.
    pub fn generate_smudging_shares<R: RngCore + CryptoRng>(
        &self,
        noise: SmudgingNoise,
        rng: &mut R,
    ) -> Result<DealtSmudgingShares, Error> {
        // The binding check runs first: no polynomial extraction and no
        // dealing randomness before the noise is known to match this
        // manager. On failure the owner is dropped here, and `Zeroizing`
        // wipes the never-read noise.
        noise.validate_dealer_binding(self.n, &self.params)?;
        self.deal_poly(noise.into_poly(), rng)
            .map(DealtSmudgingShares::new)
    }

    /// Deal smudging shares and also return a proof witness of the dealt
    /// noise (opt-in).
    ///
    /// This is the witness-returning variant of
    /// [`ShareManager::generate_smudging_shares`]: the standard path is
    /// unchanged, and callers only pay for the witness when they ask for it.
    /// It exists so an external proof system can be handed the *exact* noise
    /// that was dealt, without the library exposing a raw noise accessor or
    /// leaving the noise owner usable twice.
    ///
    /// # Binding checks come first
    ///
    /// The dealer-binding check runs before the noise polynomial is read,
    /// before the witness copy is made, and before any dealing randomness is
    /// consumed; a rejected owner is dropped unread and wiped. The same holds
    /// on a dealing failure after the witness copy: both the dealt matrices
    /// and the witness drop and wipe, so a failed call leaves nothing live.
    ///
    /// # Returns
    /// The dealt shares (as in the standard path) plus a non-cloneable
    /// [`SmudgingNoiseWitness`] holding a guarded copy of the dealt noise in
    /// RNS encoding. The witness's only escape is
    /// [`SmudgingNoiseWitness::into_proof_bytes`]; converting the RNS
    /// residues into the centered integers a proof system expects, and
    /// binding the witness to the session and proof statement, are integrator
    /// responsibilities. The witness has no one-time guarantee once its
    /// bytes exist.
    pub fn generate_smudging_shares_with_witness<R: RngCore + CryptoRng>(
        &self,
        noise: SmudgingNoise,
        rng: &mut R,
    ) -> Result<(DealtSmudgingShares, SmudgingNoiseWitness), Error> {
        // The binding check runs first: no polynomial extraction, no witness
        // copy, and no dealing randomness before the noise is known to match
        // this manager. On failure the owner is dropped here, and `Zeroizing`
        // wipes the never-read noise.
        noise.validate_dealer_binding(self.n, &self.params)?;
        let poly = noise.into_poly();
        // A guarded copy of the exact noise about to be dealt: the copy is
        // accumulated in place into a zero polynomial, so it never exists
        // outside a wipe-on-drop owner. If the dealing below fails, this
        // witness drops with the call and wipes.
        let mut witness_poly = Zeroizing::new(Poly::<PowerBasis>::zero(poly.ctx()));
        *witness_poly.as_mut() += poly.as_ref();
        let witness = SmudgingNoiseWitness::new(
            NoiseWitnessProvenance::Dealt,
            witness_poly,
            Arc::clone(&self.params),
        );
        let dealt = self.deal_poly(poly, rng).map(DealtSmudgingShares::new)?;
        Ok((dealt, witness))
    }

    /// Aggregate dealt smudging shares into one single-use decryption owner.
    ///
    /// The input shares are consumed.  This operation is intentionally
    /// separate from ordinary secret-key aggregation so smudging material
    /// cannot silently flow through a generic polynomial API. Owned inputs
    /// remain under their zeroizing owners even when validation fails.
    pub fn aggregate_smudging_shares(
        &self,
        shares: Vec<SmudgingShare>,
    ) -> Result<AggregatedSmudgingShare, Error> {
        // Keep the matrices under their zeroizing owners while validating and
        // aggregating, including when malformed input returns an error.
        self.aggregate_collected_matrices(shares.iter().map(|share| &share.coefficients))
            .map(|poly| AggregatedSmudgingShare::new(poly, &self.params))
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
            .map(|poly| AggregatedSecretKeyShare::from_power_basis(poly, &self.params))
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

    /// Compute a decryption share from ciphertext and owned secret-key/smudging
    /// shares.
    ///
    /// This function computes a party's contribution to the threshold decryption process.
    /// Each party uses their aggregated key and noise shares to compute a decryption share.
    ///
    /// # Arguments
    /// - `ciphertext`: Borrowed ciphertext to decrypt (contains c0, c1 polynomials)
    /// - `secret_key`: This party's aggregated share of the joint secret key (output of
    ///   [`ShareManager::aggregate_secret_key_shares`]), not a party's own secret key
    /// - `smudging`: This party's aggregated share of the joint smudging noise,
    ///   aggregated the same way from the dealt noise shares
    ///
    /// # Returns
    /// A decryption share polynomial that contributes to the final decryption
    ///
    /// # Parameter binding
    ///
    /// After the ciphertext checks, both aggregated owners are bound to this
    /// manager's *complete* BFV parameter set (pointer-equality fast path,
    /// then full value comparison): an aggregated key or noise share recorded
    /// under a different plaintext modulus, modulus chain, degree, or error
    /// variance is rejected even when its ring context matches the
    /// ciphertext. The key binding is checked before the smudging binding,
    /// and both run before the noise is read or any secret-dependent
    /// arithmetic happens. This full-parameter validation is part of the
    /// standard decryption path, not only of the witness variant.
    ///
    /// # Secret handling
    /// The decryption product `c1 * s_i` and the decryption phase
    /// `c0 + c1 * s_i` accumulated on top of it are secret-dependent. The
    /// ciphertext clone is guarded before the secret key is multiplied into
    /// it in place, and the phase is kept in a wipe-on-drop owner until it is
    /// moved into the returned share; the additions accumulate in place, so
    /// no secret-dependent by-value intermediate is created or dropped. Two
    /// narrow move-based windows remain, consistent with the rest of this
    /// crate: the inverse-NTT conversion of the product (see the inline
    /// comment) and the transfer of the finished share into the returned
    /// polynomial, whose allocation the caller owns from then on. The
    /// consumed smudging owner wipes its noise when this function returns.
    ///
    /// Proof-oriented callers that must reference the exact noise used here
    /// should use
    /// [`ShareManager::decryption_share_with_witness`], which shares this
    /// entire code path and additionally returns a
    /// [`SmudgingNoiseWitness`].
    #[allow(clippy::indexing_slicing)] // BFV ciphertext always has exactly 2 components
    pub fn decryption_share(
        &self,
        ciphertext: &Ciphertext,
        secret_key: &AggregatedSecretKeyShare,
        smudging: AggregatedSmudgingShare,
    ) -> Result<Poly<PowerBasis>, Error> {
        self.decryption_share_guarded(ciphertext, secret_key, smudging, false)
            .map(|(share, _witness)| share)
    }

    /// Compute a decryption share and also return a proof witness of the
    /// exact noise it used (opt-in).
    ///
    /// This is the witness-returning variant of
    /// [`ShareManager::decryption_share`] and shares its entire code path and
    /// secret-handling guarantees, including the full-parameter binding
    /// checks (the owners' recorded parameter sets must equal this manager's
    /// parameters). The smudging aggregate is consumed the same way, so **no
    /// second decryption can use the live owner**; on any failure the owner
    /// is dropped and wiped and no witness is produced. Because the binding
    /// checks run before the witness copy, a witness is only ever labeled
    /// with parameters the consumed owners were validated against.
    ///
    /// # Returns
    /// The decryption share (identical to what the standard path computes)
    /// plus a non-cloneable [`SmudgingNoiseWitness`] holding a guarded copy
    /// of the noise that entered this decryption share, tagged with the
    /// [`NoiseWitnessProvenance::Decryption`] provenance. The witness's only
    /// escape is [`SmudgingNoiseWitness::into_proof_bytes`]; an external
    /// proof system (for example a C6-style proof of correct decryption) can
    /// be built against those exact noise values. Converting the RNS
    /// residues into the proof's centered-integer representation, and binding
    /// the witness to the ciphertext and decryption domain, are integrator
    /// responsibilities. The witness has no one-time guarantee once its bytes
    /// exist.
    #[allow(clippy::indexing_slicing)] // BFV ciphertext always has exactly 2 components
    pub fn decryption_share_with_witness(
        &self,
        ciphertext: &Ciphertext,
        secret_key: &AggregatedSecretKeyShare,
        smudging: AggregatedSmudgingShare,
    ) -> Result<(Poly<PowerBasis>, SmudgingNoiseWitness), Error> {
        self.decryption_share_guarded(ciphertext, secret_key, smudging, true)
            .and_then(|(share, witness)| {
                witness
                    .map(|witness| (share, witness))
                    .ok_or_else(|| Error::DefaultError("witness was not captured".to_string()))
            })
    }

    /// Shared core of [`ShareManager::decryption_share`] and
    /// [`ShareManager::decryption_share_with_witness`].
    ///
    /// `capture_witness` selects whether a guarded copy of the smudging noise
    /// is captured (after all validation, before the noise enters the phase).
    /// On every error path the consumed smudging owner drops and wipes and no
    /// witness escapes.
    ///
    /// Validation order: ciphertext parameters/level/shape, then the key
    /// aggregate's recorded-parameter binding, then the smudging aggregate's
    /// recorded-parameter binding, then the ring-context checks, then the
    /// witness capture. The binding checks precede every read of the smudging
    /// polynomial and all secret-dependent arithmetic, and precede the
    /// witness copy, so a rejected call leaves no witness and a produced
    /// witness is always labeled with parameters both owners were validated
    /// against.
    #[allow(clippy::indexing_slicing)] // BFV ciphertext always has exactly 2 components
    fn decryption_share_guarded(
        &self,
        ciphertext: &Ciphertext,
        secret_key: &AggregatedSecretKeyShare,
        smudging: AggregatedSmudgingShare,
        capture_witness: bool,
    ) -> Result<(Poly<PowerBasis>, Option<SmudgingNoiseWitness>), Error> {
        self.validate_ciphertext(ciphertext)?;
        // Full-parameter binding of both owners: the recorded sets must equal
        // this manager's parameters, so same-ring aggregates recorded under a
        // different plaintext modulus or error variance are rejected before
        // the noise is read or any secret-dependent math runs.
        secret_key.validate_binding(&self.params)?;
        smudging.validate_binding(&self.params)?;
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
        // Witness capture happens after every validation and before the noise
        // enters the decryption phase: the copy is accumulated in place into
        // a zero polynomial, so the witnessed noise never exists outside a
        // wipe-on-drop owner. Because the parameter bindings above passed,
        // the witness can safely be labeled with this manager's parameters.
        // If a later step fails or unwinds, the witness drops with this call
        // and wipes.
        let witness = capture_witness.then(|| {
            let mut copy = Zeroizing::new(Poly::<PowerBasis>::zero(smudging.ctx()));
            *copy.as_mut() += smudging.as_ref();
            SmudgingNoiseWitness::new(
                NoiseWitnessProvenance::Decryption,
                copy,
                Arc::clone(&self.params),
            )
        });
        // The decryption product becomes secret-dependent as soon as the
        // secret key is multiplied in: guard the ciphertext clone first, then
        // run the multiplication in place inside the guard, so a partial
        // multiplication unwinds into the guard's wipe-on-drop.
        let mut product = Zeroizing::new(c1);
        product.disallow_variable_time_computations();
        *product.as_mut() *= secret_key;
        // Move the multiplied product out of its guard for the inverse
        // transform, leaving a zero polynomial behind for the guard to drop.
        // Honest limitation: the moved value is unguarded while
        // `into_power_basis` performs the inverse NTT in place — a brief
        // move-based gap. The transform has no known panic source on
        // standard-layout coefficients, but an unwind through the transform
        // itself is not covered by a guard here.
        let replacement = Poly::zero(product.ctx());
        let product = std::mem::replace(product.as_mut(), replacement).into_power_basis();
        // The phase accumulated on top of the product stays in a wipe-on-drop
        // owner until its allocation is transferred into the returned share.
        let mut phase = Zeroizing::new(product);
        // In-place additions only: `AddAssign` borrows the operands, so no
        // separate `c0 + c1 * s_i` intermediate is created. Every operand
        // disallowed variable-time computations above, so the additions use
        // the constant-time path. The smudging owner keeps its noise until
        // this function returns, then wipes it.
        *phase.as_mut() += &c0;
        *phase.as_mut() += smudging.as_ref();
        let ctx = phase.ctx().clone();
        let share = std::mem::replace(phase.as_mut(), Poly::<PowerBasis>::zero(&ctx));
        Ok((share, witness))
    }

    /// Decrypt ciphertext from collected decryption shares.
    ///
    /// This function performs the final step of threshold decryption by combining
    /// decryption shares from exactly `threshold + 1` parties to reconstruct the plaintext.
    /// The shares, party indices, and ciphertext are borrowed and can be held by
    /// the calling protocol throughout reconstruction.
    ///
    /// # Arguments
    /// - `decryption_shares`: Exactly `threshold + 1` decryption shares
    /// - `reconstructing_parties`: The 1-based party indices the shares came from, in
    ///   the same order as `decryption_shares`; indices must be distinct and in `1..=n`
    /// - `ciphertext`: The original ciphertext being decrypted
    ///
    /// # Returns
    /// The decrypted plaintext
    ///
    /// # Errors
    /// Returns
    /// [`ParametersError::UnsupportedPlaintextModulus`](crate::ParametersError::UnsupportedPlaintextModulus)
    /// immediately after the ciphertext-parameter checks when the plaintext
    /// modulus does not fit in a `u64`: the final scaling step of threshold
    /// decryption requires a machine-word plaintext modulus, and the check
    /// runs before any share validation or reconstruction work (issue #252).
    // All indexing is on vectors built with known sizes matching the index ranges
    #[allow(clippy::indexing_slicing)]
    pub fn decrypt_from_shares(
        &self,
        decryption_shares: &[Poly<PowerBasis>],
        reconstructing_parties: &[usize],
        ciphertext: &Ciphertext,
    ) -> Result<Plaintext, Error> {
        self.validate_ciphertext_parameters(ciphertext)?;
        // The final scaling step requires a machine-word plaintext modulus;
        // reject larger plaintexts before any context setup, share validation,
        // or reconstruction work (issue #252).
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

    /// The witness-returning dealing variant must produce a witness holding
    /// exactly the dealt noise, tagged with the dealt provenance and the
    /// manager's parameters, and the dealt shares must be usable end to end.
    #[test]
    fn dealing_with_witness_witnesses_the_dealt_noise() {
        let params = insecure().unwrap().parameters;
        let n = 3;
        let threshold = 1;
        let manager = ShareManager::new(n, threshold, params.clone()).unwrap();
        let mut rng = rng();
        let generator = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params.clone(), n, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap(),
        )
        .unwrap();

        let noise = generator.generate(&mut rng).unwrap();
        // Crate-internal check material: the exact coefficients the witness
        // must reproduce, read before the owner is consumed by the dealing
        // call.
        let expected_coefficients = noise.poly.coefficients().to_owned();

        let (dealt, witness) = manager
            .generate_smudging_shares_with_witness(noise, &mut rng)
            .unwrap();

        // The witness carries the exact dealt noise in RNS encoding.
        assert_eq!(witness.poly.coefficients(), expected_coefficients);
        assert_eq!(
            witness.provenance(),
            crate::trbfv::NoiseWitnessProvenance::Dealt
        );
        assert!(Arc::ptr_eq(witness.params(), &params));

        // The witness exports to a validating envelope for its provenance and
        // is rejected under the other provenance's role tag.
        let proof_bytes = witness.into_proof_bytes().unwrap();
        crate::trbfv::SmudgingNoiseWitness::validate_proof_bytes(
            proof_bytes.as_slice(),
            &params,
            crate::trbfv::NoiseWitnessProvenance::Dealt,
        )
        .unwrap();
        assert!(
            crate::trbfv::SmudgingNoiseWitness::validate_proof_bytes(
                proof_bytes.as_slice(),
                &params,
                crate::trbfv::NoiseWitnessProvenance::Decryption,
            )
            .is_err()
        );

        // The dealt shares still aggregate (same layout as the standard path).
        let matrices = dealt.into_transport();
        assert_eq!(matrices.len(), params.moduli().len());
    }

    /// A rejected dealer binding must happen before the noise is read, the
    /// witness is copied, or any dealing randomness is consumed.
    #[test]
    fn dealing_with_witness_rejects_binding_before_randomness_or_witness() {
        let params = insecure_threshold_binding_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        // Noise sampled for a one-party committee.
        let generator = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params, 1, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap(),
        )
        .unwrap();
        let mut rng = crate::support::presets::rng(173);
        let noise = generator.generate(&mut rng).unwrap();

        let rng_snapshot = rng.clone();
        let result = manager.generate_smudging_shares_with_witness(noise, &mut rng);
        assert!(matches!(
            result,
            Err(Error::Threshold(
                ThresholdError::SmudgingNoisePartyCountMismatch {
                    noise_parties: 1,
                    dealer_parties: 5,
                }
            ))
        ));
        // Rejected before any dealing randomness was consumed (and hence
        // before any witness copy was made).
        assert_eq!(rng, rng_snapshot);
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
        let config =
            SmudgingConfig::new(params.clone(), n, 1, 45, FreshNoiseModel::BfvPublicKey).unwrap();
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
    fn smudging_dealing_accepts_matched_binding() {
        let params = insecure_threshold_binding_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let generator = SmudgingNoiseGenerator::new(
            SmudgingConfig::new(params, 5, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap(),
        )
        .unwrap();
        let mut rng = rng();
        let noise = generator.generate(&mut rng).unwrap();
        assert!(manager.generate_smudging_shares(noise, &mut rng).is_ok());
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
        // The review reproducer configuration: noise sized for one party,
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
        // Issue #241 recorded a five-party reproduction (degree-8192
        // parameters, n = 5, threshold = 2, m = 1) in which dealing used to
        // succeed without error and the plaintext later decoded incorrectly
        // (2,590 and 8,192 of 8,192 coefficients respectively), for two
        // configuration classes:
        // - a generator configured for n = 1 at its largest feasible lambda
        //   (recorded: 71), and
        // - a same-ring generator with plaintext modulus t = 2 instead of
        //   t = 1,000,000, at its largest feasible lambda (recorded: 88).
        // Both classes must now be rejected at dealing, before any dealing
        // randomness is consumed, while the matched n = 5 generator at its
        // own largest feasible lambda (recorded: 69) is still accepted.
        // The lambdas are computed dynamically so later bound changes cannot
        // make the test brittle; each must stay at least the recorded value
        // for this test to keep speaking about the reported configurations.
        // The review's decryption-side evidence establishes what used to
        // happen; matched decryption with real smudging is covered by
        // `tests/trbfv_e2e.rs`.
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
        let key_share =
            AggregatedSecretKeyShare::from_power_basis((*secret_key_poly).clone(), &params);

        // Compute decryption share.
        let decryption_share = manager
            .decryption_share(
                &ct,
                &key_share,
                AggregatedSmudgingShare::new(smudging_poly, &params),
            )
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
                AggregatedSmudgingShare::new(
                    Poly::<PowerBasis>::zero(params.context_at_level(0).unwrap()),
                    &params,
                ),
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
        assert_eq!(
            manager
                .decrypt_from_shares(&shares, &reconstructing, &ct)
                .unwrap(),
            plaintext_found
        );

        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");

        assert_eq!(decoded, plaintext_data);
    }

    #[test]
    fn decrypt_from_shares_lifts_through_plaintext_context_when_q0_below_t() {
        // q0 = 1153 < t = 4099 < Q = 1153 * 12289 keeps level 0 valid, but the
        // legacy one-modulus reduction silently truncated coefficients in
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
        let public_key = PublicKey::new(&secret_key, &mut rng);
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &params).unwrap();
        let mut ciphertext = public_key.try_encrypt(&plaintext, &mut rng).unwrap();
        ciphertext.switch_down().unwrap();

        let secret_poly = manager
            .coeffs_to_poly_level0(secret_key.coeffs.as_ref())
            .unwrap();
        let context = params.context_at_level(0).unwrap();
        let key_share = AggregatedSecretKeyShare::from_power_basis((*secret_poly).clone(), &params);
        let result = manager.decryption_share(
            &ciphertext,
            &key_share,
            AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(context), &params),
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
        let pk = PublicKey::new(&sk, &mut rng);
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &params).unwrap();
        let ct = pk.try_encrypt(&plaintext, &mut rng).unwrap();

        let secret_key_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
        let key_share =
            AggregatedSecretKeyShare::from_power_basis((*secret_key_poly).clone(), &params);

        // Smudging built over a different ring level is rejected before any
        // secret product exists; the consumed smudging owner is then wiped by
        // its zeroizing drop.
        let other_context = params.context_at_level(1).unwrap();
        let smudging =
            AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(other_context), &params);
        let result = manager.decryption_share(&ct, &key_share, smudging);

        assert!(matches!(
            result,
            Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::Ciphertext,
            })
        ));
    }

    /// The witness-returning decryption variant must compute the same share
    /// as the standard path and return a decryption-provenance witness of the
    /// exact noise that entered the share. On failure the noise owner is
    /// consumed and no witness is produced.
    #[test]
    fn decryption_share_with_witness_matches_standard_path() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();

        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let plaintext = Plaintext::try_encode(&[7u64], Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&plaintext, &mut rng).unwrap());

        let secret_key_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
        let key_share =
            AggregatedSecretKeyShare::from_power_basis((*secret_key_poly).clone(), &params);

        // Two identical zero-noise aggregates: one for each code path.
        let ctx = params.context_at_level(0).unwrap();
        let standard_smudging =
            AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(ctx), &params);
        let witness_smudging = AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(ctx), &params);

        let standard_share = manager
            .decryption_share(&ct, &key_share, standard_smudging)
            .unwrap();
        let (witness_share, witness) = manager
            .decryption_share_with_witness(&ct, &key_share, witness_smudging)
            .unwrap();
        assert_eq!(standard_share, witness_share);

        assert_eq!(
            witness.provenance(),
            crate::trbfv::NoiseWitnessProvenance::Decryption
        );
        assert!(Arc::ptr_eq(witness.params(), &params));
        let proof_bytes = witness.into_proof_bytes().unwrap();
        crate::trbfv::SmudgingNoiseWitness::validate_proof_bytes(
            proof_bytes.as_slice(),
            &params,
            crate::trbfv::NoiseWitnessProvenance::Decryption,
        )
        .unwrap();
        // A decryption witness must not validate as a dealing witness, and a
        // foreign parameter set must be rejected.
        assert!(
            crate::trbfv::SmudgingNoiseWitness::validate_proof_bytes(
                proof_bytes.as_slice(),
                &params,
                crate::trbfv::NoiseWitnessProvenance::Dealt,
            )
            .is_err()
        );
        let other_params = BfvParametersBuilder::new()
            .set_degree(64)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[40, 40])
            .build_arc()
            .unwrap();
        assert!(
            crate::trbfv::SmudgingNoiseWitness::validate_proof_bytes(
                proof_bytes.as_slice(),
                &other_params,
                crate::trbfv::NoiseWitnessProvenance::Decryption,
            )
            .is_err()
        );

        // A failing call (wrong smudging context) consumes the owner and
        // produces no witness: nothing is returned on the error path.
        let mismatched = AggregatedSmudgingShare::new(
            Poly::<PowerBasis>::zero(params.context_at_level(1).unwrap()),
            &params,
        );
        assert!(
            manager
                .decryption_share_with_witness(&ct, &key_share, mismatched)
                .is_err()
        );
    }

    /// The decryption witness must hold the exact nonzero noise consumed by
    /// the call, and the returned share must equal the standard path's output
    /// for an equivalent nonzero aggregate. A zero-only comparison could not
    /// tell a wrong witness from a correct one.
    #[test]
    fn decryption_share_with_witness_witnesses_nonzero_noise() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();

        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let plaintext = Plaintext::try_encode(&[7u64], Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&plaintext, &mut rng).unwrap());
        let secret_key_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
        let key_share =
            AggregatedSecretKeyShare::from_power_basis((*secret_key_poly).clone(), &params);

        // Real nonzero smudging noise through the supported flow, aggregated
        // for one recipient.
        let config =
            SmudgingConfig::new(params.clone(), 3, 1, 2, FreshNoiseModel::BfvPublicKey).unwrap();
        let noise = SmudgingNoiseGenerator::new(config)
            .unwrap()
            .generate(&mut rng)
            .unwrap();
        let dealt = manager
            .generate_smudging_shares(noise, &mut rng)
            .unwrap()
            .into_transport();
        let mut rows = Array2::zeros((0, params.degree()));
        for matrix in dealt.iter().take(params.moduli().len()) {
            rows.push_row(ndarray::ArrayView::from(matrix.row(0)))
                .unwrap();
        }
        let aggregate = manager
            .aggregate_smudging_shares(vec![SmudgingShare::from_transport(rows)])
            .unwrap();

        let noise_coefficients = aggregate.poly.coefficients().to_owned();
        assert!(
            noise_coefficients.iter().any(|&value| value != 0),
            "the test requires nonzero noise"
        );

        let (share, witness) = manager
            .decryption_share_with_witness(&ct, &key_share, aggregate)
            .unwrap();

        // The witness holds the exact nonzero noise that entered the share.
        assert_eq!(witness.poly.coefficients(), noise_coefficients);

        // Standard path with an equivalent nonzero aggregate: identical
        // share. The twin is rebuilt from the same canonical coefficients, so
        // any witness/noise divergence would show here.
        let mut twin_poly = Poly::<PowerBasis>::zero(params.context_at_level(0).unwrap());
        twin_poly
            .set_coefficients(noise_coefficients.clone())
            .unwrap();
        let standard_share = manager
            .decryption_share(
                &ct,
                &key_share,
                AggregatedSmudgingShare::new(twin_poly, &params),
            )
            .unwrap();
        assert_eq!(standard_share, share);
    }

    /// Both decryption variants bind the aggregated owners to the manager's
    /// *full* parameter set before the noise is read, the witness is copied,
    /// or any secret-dependent arithmetic runs: a same-ring parameter set
    /// that differs in the plaintext modulus or either error variance is
    /// rejected, while independently built but equivalent parameters are
    /// accepted.
    #[test]
    fn decryption_share_binds_owners_to_full_parameters() {
        let manager_params = insecure_threshold_binding_params();
        let manager = ShareManager::new(5, 2, manager_params.clone()).unwrap();
        let mut rng = rng();

        let sk = SecretKey::random(&manager_params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let plaintext = Plaintext::try_encode(&[42u64], Encoding::poly(), &manager_params).unwrap();
        let ct = pk.try_encrypt(&plaintext, &mut rng).unwrap();
        let key_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
        let ctx = manager_params.context_at_level(0).unwrap();

        // Same degree, moduli, and ring context; exactly one scalar field
        // differs in each variant.
        let other_plaintext = binding_params(
            101,
            insecure_128::threshold::MODULI,
            insecure_128::threshold::VARIANCE,
            insecure_128::threshold::ERROR1_VARIANCE,
        );
        let other_variance = binding_params(
            insecure_128::threshold::PLAINTEXT_MODULUS,
            insecure_128::threshold::MODULI,
            insecure_128::threshold::VARIANCE - 1,
            insecure_128::threshold::ERROR1_VARIANCE,
        );
        let mut other_error1 = insecure_128::threshold::ERROR1_VARIANCE.to_string();
        other_error1.pop();
        other_error1.push('1');
        let other_error1 = binding_params(
            insecure_128::threshold::PLAINTEXT_MODULUS,
            insecure_128::threshold::MODULI,
            insecure_128::threshold::VARIANCE,
            &other_error1,
        );
        let foreign_params = [&other_plaintext, &other_variance, &other_error1];

        // A foreign key aggregate is rejected by both variants with the
        // key-attributed mismatch, and no witness is produced on the error
        // path (the owners are consumed by the failed call).
        for foreign in foreign_params {
            let foreign_key =
                AggregatedSecretKeyShare::from_power_basis((*key_poly).clone(), foreign);
            assert!(matches!(
                manager.decryption_share(
                    &ct,
                    &foreign_key,
                    AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(ctx), &manager_params),
                ),
                Err(Error::ParameterMismatch {
                    left: crate::ParameterSource::SecretKey,
                    right: crate::ParameterSource::Parameters,
                })
            ));
            let foreign_key =
                AggregatedSecretKeyShare::from_power_basis((*key_poly).clone(), foreign);
            assert!(
                manager
                    .decryption_share_with_witness(
                        &ct,
                        &foreign_key,
                        AggregatedSmudgingShare::new(
                            Poly::<PowerBasis>::zero(ctx),
                            &manager_params
                        ),
                    )
                    .is_err()
            );
        }

        // A foreign smudging aggregate is likewise rejected before any
        // secret-dependent math, with the smudging-attributed mismatch.
        let matching_key = key_poly_as_aggregate(&manager, &sk);
        for foreign in foreign_params {
            let foreign_smudging =
                AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(ctx), foreign);
            assert!(matches!(
                manager.decryption_share(&ct, &matching_key, foreign_smudging),
                Err(Error::ParameterMismatch {
                    left: crate::ParameterSource::AggregatedSmudgingShare,
                    right: crate::ParameterSource::Parameters,
                })
            ));
            let foreign_smudging =
                AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(ctx), foreign);
            assert!(
                manager
                    .decryption_share_with_witness(&ct, &matching_key, foreign_smudging)
                    .is_err()
            );
        }

        // Independently built but equivalent parameters are accepted by both
        // variants, and the produced witness is labeled with the parameters
        // the owners were validated against.
        let rebuilt = insecure_threshold_binding_params();
        assert!(!Arc::ptr_eq(&manager_params, &rebuilt));
        let rebuilt_key = AggregatedSecretKeyShare::from_power_basis((*key_poly).clone(), &rebuilt);
        manager
            .decryption_share(
                &ct,
                &rebuilt_key,
                AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(ctx), &rebuilt),
            )
            .unwrap();
        let (_, witness) = manager
            .decryption_share_with_witness(
                &ct,
                &rebuilt_key,
                AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(ctx), &rebuilt),
            )
            .unwrap();
        assert!(Arc::ptr_eq(witness.params(), &manager_params));
    }

    /// Helper for the binding test: build a manager-matching aggregated key
    /// from the secret key.
    fn key_poly_as_aggregate(manager: &ShareManager, sk: &SecretKey) -> AggregatedSecretKeyShare {
        let poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
        AggregatedSecretKeyShare::from_power_basis((*poly).clone(), manager.params())
    }

    /// Both aggregate owners round-trip through the consuming persistence
    /// boundary: the restored owners carry the same polynomial, the imported
    /// key stays reusable, the imported noise owner stays single-use, and a
    /// copied envelope can be imported twice (the documented, unpreventable
    /// replay).
    #[test]
    fn aggregate_persistence_round_trip_and_role_separation() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();

        // Aggregated key from a real dealing.
        let sk = SecretKey::random(&params, &mut rng);
        let secret_key_poly = manager
            .coeffs_to_poly_level0(sk.coeffs.clone().as_ref())
            .unwrap();
        let dealt = manager
            .generate_secret_key_shares(secret_key_poly, &mut rng)
            .unwrap();
        let mut rows = Array2::zeros((0, params.degree()));
        for matrix in dealt.into_transport() {
            rows.push_row(ndarray::ArrayView::from(matrix.row(0)))
                .unwrap();
        }
        let key_aggregate = manager
            .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(rows)])
            .unwrap();

        // Aggregated noise (zero for determinism).
        let ctx = params.context_at_level(0).unwrap();
        let noise_aggregate = AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(ctx), &params);

        // Export consumes both owners.
        let key_bytes = key_aggregate.into_persisted_bytes().unwrap();
        let noise_bytes = noise_aggregate.into_persisted_bytes().unwrap();

        // Role separation: neither payload can be imported as the other type.
        assert!(
            AggregatedSmudgingShare::from_persisted_bytes(
                Zeroizing::new(key_bytes.as_slice().to_vec()),
                &params
            )
            .is_err()
        );
        assert!(
            AggregatedSecretKeyShare::from_persisted_bytes(
                Zeroizing::new(noise_bytes.as_slice().to_vec()),
                &params
            )
            .is_err()
        );

        // The key round-trips and the restored owner matches the original.
        let restored_key = AggregatedSecretKeyShare::from_persisted_bytes(
            Zeroizing::new(key_bytes.as_slice().to_vec()),
            &params,
        )
        .unwrap();
        assert_eq!(restored_key.poly, {
            let original = AggregatedSecretKeyShare::from_persisted_bytes(
                Zeroizing::new(key_bytes.as_slice().to_vec()),
                &params,
            )
            .unwrap();
            original.poly
        });

        // The restored key is reusable across two decryptions.
        let pk = PublicKey::new(&sk, &mut rng);
        let plaintext = Plaintext::try_encode(&[5u64], Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&plaintext, &mut rng).unwrap());
        manager
            .decryption_share(
                &ct,
                &restored_key,
                AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(ctx), &params),
            )
            .unwrap();
        manager
            .decryption_share(
                &ct,
                &restored_key,
                AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(ctx), &params),
            )
            .unwrap();

        // The noise owner round-trips into a single-use owner.
        let restored_noise = AggregatedSmudgingShare::from_persisted_bytes(
            Zeroizing::new(noise_bytes.as_slice().to_vec()),
            &params,
        )
        .unwrap();
        manager
            .decryption_share(&ct, &restored_key, restored_noise)
            .unwrap();

        // Copying the envelope cannot be prevented: the same noise bytes can
        // be imported a second time, producing a second independent
        // single-use owner. This is the documented replay the application
        // must prevent; the library cannot.
        let replayed_noise = AggregatedSmudgingShare::from_persisted_bytes(
            Zeroizing::new(noise_bytes.as_slice().to_vec()),
            &params,
        )
        .unwrap();
        manager
            .decryption_share(&ct, &restored_key, replayed_noise)
            .unwrap();
    }

    /// Malformed, truncated, corrupted, oversized, and foreign-parameter
    /// persistence payloads are all rejected before an owner is produced.
    #[test]
    fn aggregate_persistence_rejects_malformed_payloads() {
        let params = insecure().unwrap().parameters;
        let ctx = params.context_at_level(0).unwrap();
        let aggregate = AggregatedSmudgingShare::new(Poly::<PowerBasis>::zero(ctx), &params);
        let envelope = aggregate.into_persisted_bytes().unwrap();
        let bytes = envelope.as_slice();

        // Empty and truncated payloads.
        assert!(
            AggregatedSmudgingShare::from_persisted_bytes(Zeroizing::new(Vec::new()), &params)
                .is_err()
        );
        assert!(
            AggregatedSmudgingShare::from_persisted_bytes(
                Zeroizing::new(bytes[..bytes.len() / 2].to_vec()),
                &params
            )
            .is_err()
        );
        assert!(
            AggregatedSmudgingShare::from_persisted_bytes(
                Zeroizing::new(bytes[..13].to_vec()),
                &params
            )
            .is_err()
        );

        // Trailing garbage.
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(
            AggregatedSmudgingShare::from_persisted_bytes(Zeroizing::new(trailing), &params)
                .is_err()
        );

        // Wrong magic.
        let mut magic = bytes.to_vec();
        magic[0] = b'!';
        assert!(
            AggregatedSmudgingShare::from_persisted_bytes(Zeroizing::new(magic), &params).is_err()
        );

        // Oversized declared section length (bounded before decoding).
        let mut oversized = bytes.to_vec();
        oversized[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            AggregatedSmudgingShare::from_persisted_bytes(Zeroizing::new(oversized), &params)
                .is_err()
        );

        // Polynomial section truncated (with the declared length adjusted so
        // the header accounting still passes): the protobuf payload no longer
        // decodes.
        let mut truncated_poly = bytes.to_vec();
        let poly_len = u32::from_le_bytes(truncated_poly[10..14].try_into().expect("length field"));
        truncated_poly[10..14].copy_from_slice(&(poly_len - 1).to_le_bytes());
        truncated_poly.pop();
        assert!(
            AggregatedSmudgingShare::from_persisted_bytes(Zeroizing::new(truncated_poly), &params)
                .is_err()
        );
        // Note: a *canonical-looking* corrupted payload (for example a single
        // flipped coefficient byte that stays below the modulus) decodes as
        // different-but-valid material. The envelope has no integrity tag;
        // authentication is an integrator responsibility (see the README
        // threat model).

        // Wrong parameter binding on import.
        let other_params = BfvParametersBuilder::new()
            .set_degree(64)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[40, 40])
            .build_arc()
            .unwrap();
        assert!(matches!(
            AggregatedSmudgingShare::from_persisted_bytes(
                Zeroizing::new(bytes.to_vec()),
                &other_params
            ),
            Err(Error::ParameterMismatch {
                left: crate::ParameterSource::PersistedShare,
                right: crate::ParameterSource::Parameters,
            })
        ));
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
        let public_key = PublicKey::new(&secret_key, &mut rng);
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
                    &ct,
                    secret_key_aggregates[i].as_ref().unwrap(),
                    AggregatedSmudgingShare::new(smudging_poly, &params),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with parties 1 and 2 reconstructing
        let reconstructing = vec![1, 2];
        let result = managers[0].decrypt_from_shares(&decryption_shares, &reconstructing, &ct);
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
                    &ct,
                    secret_key_aggregates[i].as_ref().unwrap(),
                    AggregatedSmudgingShare::new(smudging_poly, &params),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with selected parties
        let result = managers[0].decrypt_from_shares(&decryption_shares, &reconstructing, &ct);
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
                    &ct,
                    secret_key_aggregates[i].as_ref().unwrap(),
                    AggregatedSmudgingShare::new(smudging_poly, &params),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with selected parties
        let result = managers[0].decrypt_from_shares(&decryption_shares, &reconstructing, &ct);
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
                    &ct,
                    secret_key_aggregates[i].as_ref().unwrap(),
                    AggregatedSmudgingShare::new(smudging_poly, &params),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Decrypt with correct indices -> should succeed and match plaintext
        let result_ok =
            managers[0].decrypt_from_shares(&decryption_shares, &reconstructing_correct, &ct);
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
        let result_bad =
            managers[0].decrypt_from_shares(&decryption_shares, &reconstructing_wrong, &ct);
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
                    &ct,
                    secret_key_aggregates[i].as_ref().unwrap(),
                    AggregatedSmudgingShare::new(smudging_poly, &params),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares with non-increasing party order
        let result = managers[0].decrypt_from_shares(&decryption_shares, &reconstructing, &ct);
        assert!(result.is_ok());

        // Validate plaintext
        let plaintext_found = result.expect("Failed to decrypt from shares");
        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");
        assert_eq!(decoded, plaintext_data);
    }
}
