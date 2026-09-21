//! Opaque, single-use owners for smudging shares.

use fhe_math::rq::{Poly, PowerBasis};
use ndarray::Array2;
use zeroize::{Zeroize, Zeroizing};

/// One recipient's dealt share of a smudging polynomial.
///
/// This type deliberately does not implement `Clone` or `Copy`.  A share is
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

/// One recipient's aggregate smudging share for one decryption.
///
/// The owner is consumed by `ShareManager::decryption_share`.  It is not
/// serializable by this type: applications that need transport must use an
/// explicit consuming adapter at their protocol boundary.
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
/// # use std::sync::Arc;
/// # use fhe::bfv::Ciphertext;
/// # use fhe::trbfv::{AggregatedSmudgingShare, ShareManager};
/// # use fhe_math::rq::{Ntt, Poly};
/// fn reuse(
///     manager: &ShareManager,
///     ciphertext: Arc<Ciphertext>,
///     secret_share: Poly<Ntt>,
///     noise: AggregatedSmudgingShare,
/// ) {
///     let _ = manager.decryption_share(
///         ciphertext.clone(),
///         secret_share.clone(),
///         noise,
///     );
///     let _ = manager.decryption_share(ciphertext, secret_share, noise);
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
