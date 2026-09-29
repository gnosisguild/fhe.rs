//! Reusable, zeroizing owners for threshold secret-key shares.

use std::sync::Arc;

use fhe_math::rq::{Ntt, Poly, PowerBasis};
use fhe_traits::{DeserializeWithContext, Serialize};
use ndarray::Array2;
use zeroize::{Zeroize, Zeroizing};

use super::super::transport::{TransportRole, decode_envelope, encode_envelope};
use crate::Error;
use crate::bfv::BfvParameters;

/// The per-`q_i` output of dealing one secret-key polynomial.
///
/// Each matrix has shape `[n, degree]`. It is distinct from
/// [`SecretKeyShare`], whose recipient transport shape is `[moduli, degree]`.
///
/// ```compile_fail
/// # use fhe::trbfv::DealtSecretKeyShares;
/// fn duplicate(shares: &DealtSecretKeyShares) -> DealtSecretKeyShares {
///     shares.clone()
/// }
/// ```
pub struct DealtSecretKeyShares {
    pub(crate) matrices: Vec<Array2<u64>>,
}

impl DealtSecretKeyShares {
    pub(crate) fn new(matrices: Vec<Array2<u64>>) -> Self {
        Self { matrices }
    }

    /// Consume the dealt result at an explicit application transport boundary.
    /// The returned matrices are ordered by modulus `q_i`, each with rows
    /// ordered by recipient; the application transposes them into one
    /// `[moduli, degree]` matrix per recipient before calling
    /// [`SecretKeyShare::from_transport`]. Ownership (and responsibility for
    /// clearing discarded buffers) passes to the caller.
    #[must_use]
    pub fn into_transport(mut self) -> Vec<Array2<u64>> {
        // `Drop` zeroizes the field, so replace it before moving the matrices
        // out of the owner.
        std::mem::take(&mut self.matrices)
    }
}

impl Drop for DealtSecretKeyShares {
    fn drop(&mut self) {
        for matrix in &mut self.matrices {
            matrix.iter_mut().for_each(u64::zeroize);
        }
    }
}

impl std::fmt::Debug for DealtSecretKeyShares {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DealtSecretKeyShares")
            .finish_non_exhaustive()
    }
}

/// One recipient's secret-key share in `[moduli, degree]` layout.
///
/// The owner is consumed by key aggregation and cannot be cloned.
///
/// ```compile_fail
/// # use fhe::trbfv::SecretKeyShare;
/// fn duplicate(share: &SecretKeyShare) -> SecretKeyShare {
///     share.clone()
/// }
/// ```
pub struct SecretKeyShare {
    pub(crate) coefficients: Array2<u64>,
}

impl SecretKeyShare {
    /// Rehydrate one share at an explicit application transport boundary.
    #[must_use]
    pub fn from_transport(coefficients: Array2<u64>) -> Self {
        Self { coefficients }
    }

    /// Consume the owner into application transport storage.
    #[must_use]
    pub fn into_transport(mut self) -> Array2<u64> {
        // `Drop` zeroizes the field, so replace it before moving the matrix
        // out of the owner.
        std::mem::take(&mut self.coefficients)
    }
}

impl Drop for SecretKeyShare {
    fn drop(&mut self) {
        self.coefficients.iter_mut().for_each(u64::zeroize);
    }
}

impl std::fmt::Debug for SecretKeyShare {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretKeyShare")
            .finish_non_exhaustive()
    }
}

/// A reusable aggregate secret-key share.
///
/// This owner is deliberately reusable because one key epoch may decrypt many
/// ciphertexts. It is non-cloneable and must be borrowed by decryption; fresh
/// smudging noise remains the one-time input. It records the parameter set it
/// was aggregated under so the persistence boundary in
/// [`into_persisted_bytes`](Self::into_persisted_bytes) can embed a full
/// parameter-set binding.
///
/// ```compile_fail
/// # use fhe::trbfv::AggregatedSecretKeyShare;
/// fn duplicate(key: &AggregatedSecretKeyShare) -> AggregatedSecretKeyShare {
///     key.clone()
/// }
/// ```
pub struct AggregatedSecretKeyShare {
    pub(crate) poly: Zeroizing<Poly<Ntt>>,
    /// Parameter set this aggregate was aggregated (or imported) under; the
    /// transport envelope embeds it as the import-time binding.
    pub(crate) params: Arc<BfvParameters>,
}

impl AggregatedSecretKeyShare {
    pub(crate) fn from_power_basis(poly: Poly<PowerBasis>, params: &Arc<BfvParameters>) -> Self {
        let mut poly = poly.into_ntt();
        poly.disallow_variable_time_computations();
        Self {
            poly: Zeroizing::new(poly),
            params: Arc::clone(params),
        }
    }

    pub(crate) fn as_ntt(&self) -> &Poly<Ntt> {
        &self.poly
    }

    /// Verify this owner was aggregated (or imported) under the manager's
    /// exact BFV parameters.
    ///
    /// Crate-private so the decryption operations can run it before any
    /// secret-dependent arithmetic. Parameters take the `Arc` pointer-equality
    /// fast path and then compare by full value, so independently built but
    /// equivalent configurations are accepted while any differing field —
    /// including the plaintext modulus and the error variances, which ring
    /// contexts cannot distinguish — is rejected.
    pub(crate) fn validate_binding(
        &self,
        manager_params: &Arc<BfvParameters>,
    ) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.params, manager_params) && self.params != *manager_params {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::SecretKey,
                right: crate::ParameterSource::Parameters,
            });
        }
        Ok(())
    }

    /// Consume the owner into a versioned, parameter-bound persistence
    /// envelope.
    ///
    /// This is the supported way for the aggregated key to survive an
    /// application restart. The returned [`Zeroizing<Vec<u8>>`] carries a
    /// role tag, a format version, the full parameter set, and the key
    /// polynomial in its canonical NTT RNS encoding; see the
    /// [module documentation](super::super::transport) for the layout. The
    /// owner is consumed, so the live value cannot be exported twice without
    /// passing through an import.
    ///
    /// The returned envelope **may be cloned after this boundary**: exported
    /// bytes are ordinary data, and the library cannot prevent copies from
    /// being made, stored, or replayed. The key material itself is
    /// long-lived, so a copied key envelope is as sensitive as the key;
    /// integrators own authentication, storage encryption, and the epoch
    /// identity of every persisted copy.
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
            TransportRole::AggregatedSecretKeyShare,
            &self.params,
            &poly_bytes,
        )
    }

    /// Restore the owner from persistence bytes produced by
    /// [`into_persisted_bytes`](Self::into_persisted_bytes).
    ///
    /// The envelope is consumed and wiped when this call returns — on success
    /// and on every rejection. Validation happens in phases: the
    /// envelope-level checks (whole-input size bound, header, the key-share
    /// role tag, format version, declared section lengths, truncation,
    /// trailing data) run on lengths and headers alone; the embedded
    /// parameter section is then decoded and must equal `params` by full
    /// value; finally the polynomial payload is decoded at level 0, which
    /// validates its representation, shape, and canonical RNS residues. Only
    /// after all of that is the owner constructed.
    ///
    /// Importing the same bytes twice yields two independent owners; the
    /// library cannot detect that the bytes were copied or replayed, so
    /// durable replay prevention and epoch identity remain integrator
    /// responsibilities. Any clone of the envelope made *before* this call is
    /// likewise outside library control.
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
            TransportRole::AggregatedSecretKeyShare,
            params,
        )?;
        let ctx = params.context_at_level(0)?;
        let mut poly = Poly::<Ntt>::from_bytes(poly_bytes, ctx)?;
        poly.disallow_variable_time_computations();
        // `bytes` (the consumed envelope) is dropped — and wiped — when this
        // function returns, on success and on every error path above.
        Ok(Self {
            poly: Zeroizing::new(poly),
            params: Arc::clone(params),
        })
    }
}

impl std::fmt::Debug for AggregatedSecretKeyShare {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AggregatedSecretKeyShare")
            .finish_non_exhaustive()
    }
}
