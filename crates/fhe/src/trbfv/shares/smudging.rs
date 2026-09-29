//! Single-use owners for smudging shares.
//!
//! Noise generation lives in [`super::super::smudging`]. This module owns the
//! share-layer material created from that noise and consumed by threshold
//! decryption.

use std::sync::Arc;

use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{DeserializeWithContext, Serialize};
use ndarray::Array2;
use zeroize::{Zeroize, Zeroizing};

use super::super::transport::{TransportRole, decode_envelope, encode_envelope};
use crate::Error;
use crate::bfv::BfvParameters;

/// The result of dealing one smudging polynomial.
///
/// Each entry is a per-`q_i` share matrix with shape `[n, degree]`. It is deliberately
/// distinct from [`SmudgingShare`], whose transport shape is
/// `[moduli, degree]` for one recipient. The two layouts must be transposed by
/// the protocol layer before aggregation.
pub struct DealtSmudgingShares {
    pub(crate) matrices: Vec<Array2<u64>>,
}

impl DealtSmudgingShares {
    pub(crate) fn new(matrices: Vec<Array2<u64>>) -> Self {
        Self { matrices }
    }

    /// Consume the dealt result at an application transport boundary. The
    /// matrices are ordered by modulus `q_i`, each with rows ordered by
    /// recipient; the application transposes them into `[moduli, degree]`
    /// matrices for [`SmudgingShare::from_transport`]. Ownership (and
    /// responsibility for clearing discarded buffers) passes to the caller.
    #[must_use]
    pub fn into_transport(mut self) -> Vec<Array2<u64>> {
        std::mem::take(&mut self.matrices)
    }
}

impl Drop for DealtSmudgingShares {
    fn drop(&mut self) {
        for matrix in &mut self.matrices {
            matrix.iter_mut().for_each(u64::zeroize);
        }
    }
}

impl std::fmt::Debug for DealtSmudgingShares {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DealtSmudgingShares")
            .finish_non_exhaustive()
    }
}

/// One recipient's smudging share after the dealt per-`q_i` matrices have been
/// transposed into the `[moduli, degree]` transport layout.
///
/// This type deliberately does not implement `Clone` or `Copy`. A share is
/// consumed when it is aggregated, so the supported API cannot accidentally
/// put the same live share into two aggregates.
///
/// ```compile_fail
/// # use fhe::trbfv::SmudgingShare;
/// fn duplicate(share: &SmudgingShare) -> SmudgingShare {
///     share.clone()
/// }
/// ```
pub struct SmudgingShare {
    pub(crate) coefficients: Array2<u64>,
}

impl SmudgingShare {
    pub(crate) fn new(coefficients: Array2<u64>) -> Self {
        Self { coefficients }
    }

    /// Rehydrate one share at an explicit application transport boundary.
    #[must_use]
    pub fn from_transport(coefficients: Array2<u64>) -> Self {
        Self::new(coefficients)
    }

    /// Consume the owner into application transport storage.
    #[must_use]
    pub fn into_transport(mut self) -> Array2<u64> {
        // `Drop` zeroizes the field, so replace it before moving the matrix
        // out of the owner.
        std::mem::take(&mut self.coefficients)
    }
}

impl Drop for SmudgingShare {
    fn drop(&mut self) {
        self.coefficients.iter_mut().for_each(u64::zeroize);
    }
}

impl std::fmt::Debug for SmudgingShare {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SmudgingShare")
            .finish_non_exhaustive()
    }
}

/// One aggregate smudging share for one decryption.
///
/// The owner is consumed by [`super::ShareManager::decryption_share`] (and by
/// the witness-returning
/// [`decryption_share_with_witness`](super::ShareManager::decryption_share_with_witness)
/// variant), so safe Rust cannot use one live owner in two decryptions.
///
/// # Persistence boundary
///
/// There is no generic serializer, no `Clone`, and no raw polynomial
/// accessor. Applications that must persist the aggregate across a restart
/// use the explicit consuming boundary:
/// [`into_persisted_bytes`](Self::into_persisted_bytes) consumes the owner
/// and returns a versioned, parameter-bound
/// [`Zeroizing<Vec<u8>>`] envelope, and
/// [`from_persisted_bytes`](Self::from_persisted_bytes) consumes such an
/// envelope and restores a fresh single-use owner. The one-live-owner
/// guarantee covers the live values on both sides of that boundary; it does
/// **not** cover the bytes themselves. A copied envelope can be imported
/// twice, yielding two independent one-use owners, and no in-memory Rust type
/// can prevent that: durable replay prevention, ciphertext/decryption-domain
/// binding, authentication, and storage encryption remain integrator
/// responsibilities.
///
/// ```compile_fail
/// # use fhe::trbfv::AggregatedSmudgingShare;
/// fn duplicate(share: &AggregatedSmudgingShare) -> AggregatedSmudgingShare {
///     share.clone()
/// }
/// ```
///
/// Reusing one live owner in two decryption calls is also rejected:
///
/// ```compile_fail
/// # use fhe::bfv::Ciphertext;
/// # use fhe::trbfv::{AggregatedSecretKeyShare, AggregatedSmudgingShare, ShareManager};
/// fn reuse(
///     manager: &ShareManager,
///     ciphertext: &Ciphertext,
///     secret_key: &AggregatedSecretKeyShare,
///     noise: AggregatedSmudgingShare,
/// ) {
///     let _ = manager.decryption_share(ciphertext, secret_key, noise);
///     let _ = manager.decryption_share(ciphertext, secret_key, noise);
/// }
/// ```
pub struct AggregatedSmudgingShare {
    pub(crate) poly: Zeroizing<Poly<PowerBasis>>,
    /// Parameter set this aggregate was aggregated (or imported) under; the
    /// transport envelope embeds it as the import-time binding.
    pub(crate) params: Arc<BfvParameters>,
}

impl AggregatedSmudgingShare {
    pub(crate) fn new(poly: Poly<PowerBasis>, params: &Arc<BfvParameters>) -> Self {
        Self {
            poly: Zeroizing::new(poly),
            params: Arc::clone(params),
        }
    }

    pub(crate) fn into_poly(self) -> Zeroizing<Poly<PowerBasis>> {
        self.poly
    }

    /// Verify this owner was aggregated (or imported) under the manager's
    /// exact BFV parameters.
    ///
    /// Crate-private so the decryption operations can run it before the noise
    /// is read or copied into a witness. Parameters take the `Arc`
    /// pointer-equality fast path and then compare by full value, so
    /// independently built but equivalent configurations are accepted while
    /// any differing field — including the plaintext modulus and the error
    /// variances, which ring contexts cannot distinguish — is rejected.
    pub(crate) fn validate_binding(
        &self,
        manager_params: &Arc<BfvParameters>,
    ) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.params, manager_params) && self.params != *manager_params {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::AggregatedSmudgingShare,
                right: crate::ParameterSource::Parameters,
            });
        }
        Ok(())
    }

    /// Consume the single-use owner into a versioned, parameter-bound
    /// persistence envelope.
    ///
    /// This is the supported way for an aggregated noise share to survive an
    /// application restart (for example when the decryption proof workflow
    /// is resumed after a crash). The envelope layout is documented in the
    /// [transport module](super::super::transport). The owner is consumed;
    /// the noise polynomial is serialized in its canonical PowerBasis RNS
    /// encoding, and every secret-bearing buffer this side of the boundary
    /// owns — the owner polynomial, the exported polynomial copy, and the
    /// envelope — is wiped on drop. The serialized parameter section is
    /// public data and is intentionally kept in an ordinary, unwiped buffer.
    ///
    /// The returned envelope **may be cloned after this boundary**. Exported
    /// bytes have no one-time semantics: importing the same bytes twice
    /// yields two independent single-use owners, which is exactly the
    /// replay a durable application must prevent itself. Integrators own the
    /// binding of an imported owner to one ciphertext and decryption domain.
    ///
    /// # Memory limits
    ///
    /// The envelope and the exported polynomial copy are wipe-on-drop, but
    /// the underlying `Poly::to_bytes` serializer also builds short-lived
    /// internal buffers that the math crate does not wipe; see the trBFV
    /// README's documented library limits for transient serializer
    /// allocations.
    pub fn into_persisted_bytes(self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let poly_bytes = Zeroizing::new(self.poly.to_bytes());
        encode_envelope(
            TransportRole::AggregatedSmudgingShare,
            &self.params,
            &poly_bytes,
        )
    }

    /// Restore the single-use owner from persistence bytes produced by
    /// [`into_persisted_bytes`](Self::into_persisted_bytes).
    ///
    /// The envelope is consumed and wiped when this call returns — on success
    /// and on every rejection. The payload must carry the smudging-aggregate
    /// role tag (a persisted key share cannot be imported as noise), an
    /// implemented format version, a parameter set equal to `params` by full
    /// value, and a PowerBasis polynomial that decodes at level 0 with
    /// canonical RNS residues.
    ///
    /// The restored owner is single-use exactly like an aggregated owner:
    /// one call to
    /// [`ShareManager::decryption_share`](super::ShareManager::decryption_share)
    /// consumes it. Importing the same envelope twice creates two such
    /// owners; the library cannot prevent that copy, so durable replay
    /// prevention stays with the application.
    ///
    /// # Errors
    /// Returns [`Error::SerializationError`] for malformed, truncated,
    /// oversized, wrong-role, or wrong-version payloads,
    /// [`Error::ParameterMismatch`] with
    /// [`ParameterSource::PersistedShare`](crate::ParameterSource::PersistedShare)
    /// when the embedded parameter set does not match `params`, and
    /// [`Error::MathError`] when the polynomial payload violates the
    /// parameter set's context, shape, or canonical-residue invariants.
    pub fn from_persisted_bytes(
        bytes: Zeroizing<Vec<u8>>,
        params: &Arc<BfvParameters>,
    ) -> Result<Self, Error> {
        let poly_bytes = decode_envelope(
            bytes.as_slice(),
            TransportRole::AggregatedSmudgingShare,
            params,
        )?;
        let ctx = params.context_at_level(0)?;
        let mut poly = Poly::<PowerBasis>::from_bytes(poly_bytes, ctx)?;
        poly.disallow_variable_time_computations();
        // `bytes` (the consumed envelope) is dropped — and wiped — when this
        // function returns, on success and on every error path above.
        Ok(Self {
            poly: Zeroizing::new(poly),
            params: Arc::clone(params),
        })
    }
}

impl std::fmt::Debug for AggregatedSmudgingShare {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AggregatedSmudgingShare")
            .finish_non_exhaustive()
    }
}
