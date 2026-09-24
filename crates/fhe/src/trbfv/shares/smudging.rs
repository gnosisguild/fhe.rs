//! Single-use owners for smudging shares.
//!
//! Noise generation lives in [`super::super::smudging`]. This module owns the
//! share-layer material created from that noise and consumed by threshold
//! decryption.

use fhe_math::rq::{Poly, PowerBasis};
use ndarray::Array2;
use zeroize::{Zeroize, Zeroizing};

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
/// The owner is consumed by [`super::ShareManager::decryption_share`]. It is
/// not serializable by this type: applications that need transport must use
/// an explicit consuming adapter at their protocol boundary.
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
}

impl AggregatedSmudgingShare {
    pub(crate) fn new(poly: Poly<PowerBasis>) -> Self {
        Self {
            poly: Zeroizing::new(poly),
        }
    }

    pub(crate) fn into_poly(self) -> Zeroizing<Poly<PowerBasis>> {
        self.poly
    }
}

impl std::fmt::Debug for AggregatedSmudgingShare {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AggregatedSmudgingShare")
            .finish_non_exhaustive()
    }
}
