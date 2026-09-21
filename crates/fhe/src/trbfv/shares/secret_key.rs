//! Reusable, zeroizing owners for threshold secret-key shares.

use fhe_math::rq::{Ntt, Poly, PowerBasis};
use ndarray::Array2;
use zeroize::{Zeroize, Zeroizing};

/// The modulus-plane output of dealing one secret-key polynomial.
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
/// smudging noise remains the one-time input.
///
/// ```compile_fail
/// # use fhe::trbfv::AggregatedSecretKeyShare;
/// fn duplicate(key: &AggregatedSecretKeyShare) -> AggregatedSecretKeyShare {
///     key.clone()
/// }
/// ```
pub struct AggregatedSecretKeyShare {
    pub(crate) poly: Zeroizing<Poly<Ntt>>,
}

impl AggregatedSecretKeyShare {
    pub(crate) fn from_power_basis(poly: Poly<PowerBasis>) -> Self {
        let mut poly = poly.into_ntt();
        poly.disallow_variable_time_computations();
        Self {
            poly: Zeroizing::new(poly),
        }
    }

    pub(crate) fn as_poly(&self) -> &Poly<Ntt> {
        &self.poly
    }
}

impl std::fmt::Debug for AggregatedSecretKeyShare {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AggregatedSecretKeyShare")
            .finish_non_exhaustive()
    }
}
