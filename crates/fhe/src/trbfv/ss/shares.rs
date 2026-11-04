//! Typed noise owners using the common Shamir dealing and aggregation methods.

use super::smudging::DealerSmudgingNoise;
use crate::Error;
use crate::trbfv::ShareManager;
use crate::trbfv::buffers::SecretMatrix;
use crate::trbfv::config::{validate_matrix, validate_sharing_parameters};
use fhe_math::rq::{Poly, PowerBasis};
use ndarray::Array2;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

struct SecretMatrices(Vec<Array2<u64>>);

impl Drop for SecretMatrices {
    fn drop(&mut self) {
        for matrix in std::mem::take(&mut self.0) {
            drop(SecretMatrix(matrix));
        }
    }
}

impl Zeroize for SecretMatrices {
    fn zeroize(&mut self) {
        for matrix in &mut self.0 {
            matrix.iter_mut().for_each(Zeroize::zeroize);
        }
    }
}

/// One dealer's output: one `[n, degree]` matrix per RNS modulus.
///
/// This layout is intentionally distinct from [`RecipientSmudgingShare`]. The
/// application transposes/selects rows at the explicit transport boundary before
/// aggregation. Owned matrices are wiped on drop; copies made after transport
/// are the application's responsibility.
///
/// ```compile_fail
/// use fhe::trbfv::DealtSmudgingShares;
/// fn duplicate(shares: &DealtSmudgingShares) -> DealtSmudgingShares { shares.clone() }
/// ```
pub struct DealtSmudgingShares {
    matrices: SecretMatrices,
}

impl DealtSmudgingShares {
    /// Consume into the per-modulus transport layout. The caller
    /// assumes responsibility for confidential transport and clearing the buffers.
    #[must_use]
    pub fn into_transport(mut self) -> Vec<Array2<u64>> {
        std::mem::take(&mut self.matrices.0)
    }
}

/// One dealer-to-recipient contribution of shape `[number_of_moduli, degree]`.
///
/// Aggregation checks the shape, residues, and contribution count. Identity,
/// accepted-dealer agreement, authentication, and replay handling remain external.
/// This owner is non-cloneable and wipes its matrix on drop.
///
/// ```compile_fail
/// use fhe::trbfv::RecipientSmudgingShare;
/// fn duplicate(share: &RecipientSmudgingShare) -> RecipientSmudgingShare { share.clone() }
/// ```
pub struct RecipientSmudgingShare {
    matrix: Array2<u64>,
}

impl RecipientSmudgingShare {
    /// Import an application-transported contribution. Aggregation validates its
    /// shape and residues; this does not authenticate or verify the dealer.
    #[must_use]
    pub fn from_transport(matrix: Array2<u64>) -> Self {
        Self { matrix }
    }

    /// Consume into application-owned transport storage; clearing copies becomes
    /// the application's responsibility.
    #[must_use]
    pub fn into_transport(mut self) -> Array2<u64> {
        std::mem::take(&mut self.matrix)
    }
}

impl Drop for RecipientSmudgingShare {
    fn drop(&mut self) {
        drop(SecretMatrix(std::mem::take(&mut self.matrix)));
    }
}

impl Zeroize for RecipientSmudgingShare {
    fn zeroize(&mut self) {
        self.matrix.iter_mut().for_each(Zeroize::zeroize);
    }
}

/// Recipient's single-use aggregate of the dealt smudging contributions.
///
/// Consumed by [`super::SsSmudgingDecryptor::decryption_share`], including
/// on error. This is a Shamir evaluation, not a small local noise polynomial.
/// Serialized/copied transport can be replayed; owners prevent only accidental
/// in-memory reuse, not rollback or reuse after importing saved bytes.
///
/// ```compile_fail
/// use fhe::trbfv::AggregatedSmudgingShare;
/// fn duplicate(noise: &AggregatedSmudgingShare) -> AggregatedSmudgingShare { noise.clone() }
/// ```
///
/// ```compile_fail
/// use fhe::bfv::Ciphertext;
/// use fhe::trbfv::{AggregatedSmudgingShare, SsSmudgingDecryptor};
/// use fhe_math::rq::{Ntt, Poly};
/// fn reuse(d: &SsSmudgingDecryptor, ct: &Ciphertext, sk: &Poly<Ntt>, noise: AggregatedSmudgingShare) {
///     let _ = d.decryption_share(ct, sk, noise);
///     let _ = d.decryption_share(ct, sk, noise);
/// }
/// ```
///
/// Fresh dealer noise must be dealt and aggregated, not used directly:
///
/// ```compile_fail
/// use fhe::bfv::Ciphertext;
/// use fhe::trbfv::{DealerSmudgingNoise, SsSmudgingDecryptor};
/// use fhe_math::rq::{Ntt, Poly};
/// fn wrong(d: &SsSmudgingDecryptor, ct: &Ciphertext, sk: &Poly<Ntt>, noise: DealerSmudgingNoise) {
///     let _ = d.decryption_share(ct, sk, noise);
/// }
/// ```
pub struct AggregatedSmudgingShare {
    pub(super) poly: Zeroizing<Poly<PowerBasis>>,
}

impl AggregatedSmudgingShare {
    /// Explicitly import an aggregate from application storage. The application
    /// must verify its origin, key epoch, full BFV configuration, and one-time
    /// allocation. Decryption checks the RNS context, shape/layout, and residues;
    /// the transported polynomial does not encode the committee or noise provenance.
    #[must_use]
    pub fn from_transport(poly: Zeroizing<Poly<PowerBasis>>) -> Self {
        Self { poly }
    }

    /// Consume into guarded application storage. Persisted material must not be
    /// imported for more than one decryption request.
    #[must_use]
    pub fn into_transport(self) -> Zeroizing<Poly<PowerBasis>> {
        self.poly
    }
}

impl ShareManager {
    /// Deal freshly sampled SS-protocol noise using the common Shamir
    /// implementation. The noise is consumed even if dealing fails. Context,
    /// shape/layout, and residue checks run before consuming randomness.
    pub fn generate_smudging_shares<R: RngCore + CryptoRng>(
        &mut self,
        noise: DealerSmudgingNoise,
        rng: &mut R,
    ) -> Result<DealtSmudgingShares, Error> {
        validate_sharing_parameters(self.n, self.threshold, &self.params)?;
        if noise.poly.ctx() != self.params.context_at_level(0)? {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::Parameters,
            });
        }
        validate_matrix(
            noise.poly.coefficients(),
            self.params.moduli(),
            self.params.degree(),
            0,
        )?;
        let matrices = self.generate_secret_shares_from_poly(noise.poly, rng)?;
        Ok(DealtSmudgingShares {
            matrices: SecretMatrices(matrices),
        })
    }

    /// Consume received noise contributions and validate their shape, residues,
    /// and count during aggregation. Nonempty subsets of up to `n`
    /// contributions are accepted; this is not a new security policy for subsets.
    /// All recipients must use the same externally agreed dealer set.
    pub fn aggregate_smudging_shares(
        &self,
        shares: Vec<RecipientSmudgingShare>,
    ) -> Result<AggregatedSmudgingShare, Error> {
        validate_sharing_parameters(self.n, self.threshold, &self.params)?;
        let matrices = SecretMatrices(
            shares
                .into_iter()
                .map(RecipientSmudgingShare::into_transport)
                .collect(),
        );
        let poly = self.aggregate_collected_shares(&matrices.0)?;
        Ok(AggregatedSmudgingShare {
            poly: Zeroizing::new(poly),
        })
    }
}

macro_rules! redacted_debug {
    ($($owner:ident),+ $(,)?) => {$(
        impl std::fmt::Debug for $owner {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($owner)).finish_non_exhaustive()
            }
        }
    )+};
}

redacted_debug!(
    DealtSmudgingShares,
    RecipientSmudgingShare,
    AggregatedSmudgingShare
);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::bfv::BfvParametersBuilder;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn rejects_malformed_dealer_noise_before_consuming_randomness() {
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(17)
            .set_moduli_sizes(&[50, 50, 50])
            .build_arc()
            .unwrap();
        let mut manager = ShareManager::new(3, 1, params.clone()).unwrap();
        for matrix in [
            Array2::zeros((1, 8)),
            Array2::from_elem((3, 8), u64::MAX),
            Array2::zeros((8, 3)).reversed_axes(),
        ] {
            let mut poly = Zeroizing::new(Poly::zero(params.context_at_level(0).unwrap()));
            poly.set_coefficients(matrix);
            let mut rng = ChaCha8Rng::seed_from_u64(19);
            let mut expected_rng = rng.clone();
            assert!(
                manager
                    .generate_smudging_shares(DealerSmudgingNoise { poly }, &mut rng)
                    .is_err()
            );
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
        }
        let poly = Zeroizing::new(Poly::zero(params.context_at_level(1).unwrap()));
        let mut rng = ChaCha8Rng::seed_from_u64(20);
        let mut expected_rng = rng.clone();
        assert!(
            manager
                .generate_smudging_shares(DealerSmudgingNoise { poly }, &mut rng)
                .is_err()
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }

    #[test]
    fn drop_cleanup_zeroizes_owned_matrices_without_changing_layout() {
        let mut matrices = SecretMatrices(vec![Array2::from_elem((3, 8), 42)]);
        matrices.zeroize();
        assert!(
            matrices
                .0
                .iter()
                .all(|matrix| matrix.dim() == (3, 8) && matrix.iter().all(|&v| v == 0))
        );
        let mut recipient = RecipientSmudgingShare::from_transport(Array2::from_elem((3, 8), 43));
        recipient.zeroize();
        assert_eq!(recipient.matrix.dim(), (3, 8));
        assert!(recipient.matrix.iter().all(|&v| v == 0));
        assert_eq!(format!("{recipient:?}"), "RecipientSmudgingShare { .. }");
    }
}
