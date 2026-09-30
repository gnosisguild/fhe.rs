//! Partial decryption shares and their application transport boundary.

use crate::Error;
use crate::bfv::Ciphertext;
use crate::trbfv::prf::{ContextDigest, context_digest};
use fhe_math::rq::{Poly, PowerBasis};

/// A partial decryption bound to one party, designated set `S`, and ciphertext.
///
/// Created by [`ShareManager::decryption_share`](super::ShareManager::decryption_share)
/// or reconstructed after transport with [`DecryptionShare::from_parts`]. FinDec
/// rejects a slice whose members were produced for different sets or ciphertexts.
#[derive(Clone)]
pub struct DecryptionShare {
    pub(super) poly: Poly<PowerBasis>,
    pub(super) party_id: usize,
    pub(super) decryptors: Vec<usize>,
    pub(super) digest: ContextDigest,
}

impl std::fmt::Debug for DecryptionShare {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecryptionShare")
            .field("party_id", &self.party_id)
            .finish_non_exhaustive()
    }
}

impl DecryptionShare {
    /// Rehydrate a partial decryption after application transport.
    ///
    /// The digest `H(S, ct)` is recomputed from `decryptors` and `ciphertext`.
    /// Authentication of the polynomial remains the application's
    /// responsibility.
    pub fn from_parts(
        poly: Poly<PowerBasis>,
        party_id: usize,
        decryptors: Vec<usize>,
        ciphertext: &Ciphertext,
    ) -> Result<Self, Error> {
        let digest = context_digest(&decryptors, ciphertext)?;
        Ok(Self {
            poly,
            party_id,
            decryptors,
            digest,
        })
    }

    /// Consume the share into transport parts: polynomial, 1-based party id,
    /// and designated set `S`.
    #[must_use]
    pub fn into_parts(self) -> (Poly<PowerBasis>, usize, Vec<usize>) {
        (self.poly, self.party_id, self.decryptors)
    }
}

#[cfg(test)]
impl DecryptionShare {
    pub(super) fn allows_variable_time_computations(&self) -> bool {
        self.poly.allows_variable_time_computations()
    }

    pub(super) fn coefficients(&self) -> ndarray::ArrayView2<'_, u64> {
        self.poly.coefficients()
    }
}
