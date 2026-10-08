//! Partial decryptions and their application transport boundary.

use super::prf::{ContextDigest, context_digest};
use crate::Error;
use crate::bfv::Ciphertext;
use fhe_math::rq::{Poly, PowerBasis};

/// A synchronized partial decryption bound to a party, designated set and ciphertext.
///
/// These shares are combined by
/// [`SynchronizedDecryptor::decrypt_from_shares`](super::SynchronizedDecryptor::decrypt_from_shares).
/// They are not the unweighted polynomial shares accepted by the legacy API.
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
    /// Rehydrate an application-transported partial decryption.
    ///
    /// Rejects zero/duplicate IDs and requires the owner to belong to the set.
    /// The ciphertext digest is recomputed; it does not authenticate the supplied
    /// polynomial. Applications must authenticate its sender, ciphertext, set and
    /// key epoch. Reconstruction checks committee bounds and polynomial validity.
    pub fn from_parts(
        poly: Poly<PowerBasis>,
        party_id: usize,
        mut decryptors: Vec<usize>,
        ciphertext: &Ciphertext,
    ) -> Result<Self, Error> {
        if party_id == 0 || decryptors.contains(&0) {
            return Err(Error::malformed_shares(
                party_id,
                "party identifiers must be nonzero".to_string(),
            ));
        }
        decryptors.sort_unstable();
        for (&first, &second) in decryptors.iter().zip(decryptors.iter().skip(1)) {
            if first == second {
                return Err(Error::duplicate_party_id(first));
            }
        }
        if decryptors.binary_search(&party_id).is_err() {
            return Err(Error::malformed_shares(
                party_id,
                "share party must belong to the decryptor set".to_string(),
            ));
        }
        let digest = context_digest(&decryptors, ciphertext)?;
        let mut canonical = Poly::<PowerBasis>::zero(poly.ctx());
        canonical.set_coefficients(poly.coefficients().to_owned());
        Ok(Self {
            poly: canonical,
            party_id,
            decryptors,
            digest,
        })
    }

    /// Consume this share into polynomial, 1-based owner ID and designated set.
    #[must_use]
    pub fn into_parts(self) -> (Poly<PowerBasis>, usize, Vec<usize>) {
        (self.poly, self.party_id, self.decryptors)
    }
}
