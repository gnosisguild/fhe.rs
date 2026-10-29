//! Partial decryption, share transport, and final reconstruction.
//!
//! Implements PartDec/FinDec from Colin de Verdière–Passelègue–Stehlé 2026
//! ([ePrint 2026/031](https://eprint.iacr.org/2026/031)). A designated set `S`
//! applies Lagrange weights locally, adds fresh unshared smudging noise, and
//! cancels pairwise PRF masks when its partial decryptions are summed.
//!
//! Use the existing [`ShareManager`](crate::trbfv::ShareManager) to deal and aggregate
//! secret-key shares. Its aggregate, converted to NTT form, is reusable here.
//! See the `trbfv_sync_dec` example for both setup and repeated decryptions.
//!
//! The application supplies matching pairwise keys, authenticated transport,
//! agreement on `S` and the ciphertext, key-epoch/session binding, and replay
//! prevention. The digest binds `S` and ciphertext coefficients; it is not a
//! proof of correct partial decryption or a distributed key-setup protocol.

use super::arithmetic::{SecretMatrix, lagrange_weight, validate_decryptors, validate_matrix};
use super::config::{plaintext_modulus, validate_ciphertext, validate_sharing_parameters};
use super::errors::SynchronizedDecryptionError;
use super::prf::{self, ContextDigest, PartyPrfKeys, context_digest};
use super::smudging::SmudgingNoise;
use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::{Error, ParameterSource};
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::rq::{Ntt, Poly, PowerBasis};
use fhe_math::zq::Modulus;
use num_bigint::BigUint;
use std::collections::BTreeSet;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Decrypts BFV ciphertexts using a designated set of `threshold + 1` parties.
///
/// Configuration is immutable. As with [`super::ShareManager`], `n >= 3` and
/// `threshold = (n - 1) / 2`. Ciphertexts must have two components at level zero
/// and a plaintext modulus fitting in `u64`.
#[derive(Debug)]
pub struct SynchronizedDecryptor {
    n: usize,
    threshold: usize,
    params: Arc<BfvParameters>,
}

impl SynchronizedDecryptor {
    /// Validate a configuration compatible with the existing Shamir sharing API.
    pub fn new(n: usize, threshold: usize, params: Arc<BfvParameters>) -> Result<Self, Error> {
        validate_sharing_parameters(n, threshold, &params)?;
        plaintext_modulus(&params)?;
        Ok(Self {
            n,
            threshold,
            params,
        })
    }

    /// Total committee size, including parties outside the designated set.
    #[must_use]
    pub fn committee_size(&self) -> usize {
        self.n
    }

    /// Degree of the sharing polynomial; reconstruction requires one more share.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// BFV parameters used by this decryptor.
    #[must_use]
    pub fn params(&self) -> &Arc<BfvParameters> {
        &self.params
    }

    /// Compute `lambda_i * c1 * sk_i + e_i + r_i` for the designated set.
    ///
    /// `secret_key` is this party's aggregate Shamir share, for example the NTT
    /// conversion of [`super::ShareManager::aggregate_collected_shares`], not
    /// its original BFV secret key. Keep it in a zeroizing owner between calls.
    /// `noise` is freshly sampled locally and consumed even if validation fails.
    /// The reusable PRF bundle must belong to `party_id` in this committee.
    /// All parties must agree on the same set before computing their shares.
    pub fn decryption_share(
        &self,
        ciphertext: &Ciphertext,
        secret_key: &Poly<Ntt>,
        party_id: usize,
        decryptors: &[usize],
        noise: SmudgingNoise,
        prf_keys: &PartyPrfKeys,
    ) -> Result<DecryptionShare, Error> {
        self.validate_ciphertext(ciphertext)?;
        validate_decryptors(decryptors, self.n, self.threshold)?;
        if !decryptors.contains(&party_id) {
            return Err(Error::invalid_party_id(party_id, self.n));
        }
        if prf_keys.committee_size() != self.n {
            return Err(Error::invalid_party_count(
                prf_keys.committee_size(),
                self.n,
            ));
        }
        if prf_keys.party_id() != party_id {
            return Err(Error::invalid_party_id(prf_keys.party_id(), self.n));
        }
        if !noise.matches_configuration(self.n, &self.params) {
            return Err(SynchronizedDecryptionError::SmudgingConfigurationMismatch {
                actual_n: noise.committee_size(),
                expected_n: self.n,
            }
            .into());
        }
        let ctx = self.params.context_at_level(0)?;
        if secret_key.ctx() != ctx {
            return Err(Error::ParameterMismatch {
                left: ParameterSource::Polynomial,
                right: ParameterSource::Parameters,
            });
        }
        validate_matrix(
            secret_key.coefficients(),
            self.params.moduli(),
            self.params.degree(),
            party_id,
        )?;

        let c1 = ciphertext
            .c
            .get(1)
            .ok_or_else(|| Error::malformed_shares(party_id, "missing c1".to_string()))?;
        // Main's raw polynomial APIs can retain lazy/variable-time metadata.
        // Install the validated canonical residues into fresh constant-time owners.
        let mut product = Zeroizing::new(Poly::<Ntt>::zero(ctx));
        product.set_coefficients(c1.coefficients().to_owned());
        let mut key = Zeroizing::new(Poly::<Ntt>::zero(ctx));
        key.set_coefficients(secret_key.coefficients().to_owned());
        *product.as_mut() *= key.as_ref();
        let product =
            std::mem::replace(product.as_mut(), Poly::<Ntt>::zero(ctx)).into_power_basis();
        let mut product = Zeroizing::new(product);
        let mut weighted = SecretMatrix(product.coefficients().to_owned());
        for (mut row, modulus) in weighted.0.outer_iter_mut().zip(ctx.moduli_operators()) {
            let lambda = lagrange_weight(modulus, decryptors, party_id)?;
            modulus.scalar_mul_vec(
                row.as_slice_mut()
                    .ok_or(fhe_math::Error::NonContiguousCoefficients)?,
                lambda,
            );
        }
        // Main's setter drops the old allocation without wiping it.
        product.zeroize();
        product.set_coefficients(std::mem::take(&mut weighted.0));
        let (mask, digest) = prf_keys.mask_with_digest(decryptors, ciphertext)?;
        let mask = Zeroizing::new(mask);
        let noise = noise.into_poly();
        *product.as_mut() += noise.as_ref();
        *product.as_mut() += mask.as_ref();
        let decryptors = prf::canonical_decryptors(decryptors);
        Ok(DecryptionShare {
            poly: std::mem::replace(product.as_mut(), Poly::<PowerBasis>::zero(ctx)),
            party_id,
            decryptors,
            digest,
        })
    }

    /// Sum the designated partial decryptions, add `c0`, and decode the phase.
    ///
    /// Requires exactly one share from every designated party, all for the same
    /// set and ciphertext. Share ordering is immaterial. This checks metadata and
    /// polynomial validity; authentication/proofs of share correctness are external.
    pub fn decrypt_from_shares(
        &self,
        shares: &[DecryptionShare],
        ciphertext: &Ciphertext,
    ) -> Result<Plaintext, Error> {
        self.validate_ciphertext(ciphertext)?;
        if shares.len() != self.threshold + 1 {
            return Err(Error::share_count_mismatch(
                shares.len(),
                self.threshold + 1,
            ));
        }
        let first = shares
            .first()
            .ok_or_else(|| Error::share_count_mismatch(0, self.threshold + 1))?;
        validate_decryptors(&first.decryptors, self.n, self.threshold)?;
        let expected_digest = prf::context_digest(&first.decryptors, ciphertext)?;
        let ctx = self.params.context_at_level(0)?;
        let mut seen = BTreeSet::new();
        for share in shares {
            if share.decryptors != first.decryptors || share.digest != expected_digest {
                return Err(SynchronizedDecryptionError::InconsistentDecryptionShares.into());
            }
            if !first.decryptors.contains(&share.party_id) {
                return Err(Error::invalid_party_id(share.party_id, self.n));
            }
            if !seen.insert(share.party_id) {
                return Err(Error::duplicate_party_id(share.party_id));
            }
            if share.poly.ctx() != ctx {
                return Err(Error::ParameterMismatch {
                    left: ParameterSource::Polynomial,
                    right: ParameterSource::Parameters,
                });
            }
            validate_matrix(
                share.poly.coefficients(),
                self.params.moduli(),
                self.params.degree(),
                share.party_id,
            )?;
        }
        let mut phase = Zeroizing::new(Poly::<PowerBasis>::zero(ctx));
        for share in shares {
            *phase.as_mut() += &share.poly;
        }
        let c0 = ciphertext
            .c
            .first()
            .ok_or_else(|| Error::malformed_shares(0, "missing c0".to_string()))?;
        let mut canonical_c0 = Poly::<Ntt>::zero(ctx);
        canonical_c0.set_coefficients(c0.coefficients().to_owned());
        *phase.as_mut() += &canonical_c0.into_power_basis();
        self.decode_phase(phase)
    }

    fn validate_ciphertext(&self, ciphertext: &Ciphertext) -> Result<(), Error> {
        if ciphertext.params != self.params {
            return Err(Error::ParameterMismatch {
                left: ParameterSource::Ciphertext,
                right: ParameterSource::Parameters,
            });
        }
        validate_ciphertext(ciphertext)
    }

    fn decode_phase(&self, phase: Zeroizing<Poly<PowerBasis>>) -> Result<Plaintext, Error> {
        let t = plaintext_modulus(&self.params)?;
        let level = self.params.context_level_at(0)?;
        let scaled = Zeroizing::new(phase.scale(&level.cipher_plain_context.scaler)?);
        let ctx = self.params.context_at_level(0)?;
        let q0 = *self
            .params
            .moduli()
            .first()
            .ok_or(fhe_math::Error::EmptyModuli)?;
        let poly = if t.checked_mul(2).is_some_and(|twice_t| twice_t <= q0) {
            let residues = Zeroizing::new(Vec::<u64>::try_from(scaled.as_ref())?);
            // The conversion can return multiple RNS rows. In this fast path,
            // the first row alone represents every plaintext coefficient exactly.
            let mut coefficients = Zeroizing::new(
                residues
                    .get(..self.params.degree())
                    .ok_or_else(|| {
                        Error::malformed_shares(0, "incomplete scaled polynomial".to_string())
                    })?
                    .to_vec(),
            );
            for value in coefficients.iter_mut() {
                *value += t;
            }
            Modulus::new(q0)?.reduce_vec(&mut coefficients);
            Modulus::new(t)?.reduce_vec(&mut coefficients);
            Poly::<PowerBasis>::try_convert_from(coefficients.as_slice(), ctx, false)?.into_ntt()
        } else {
            // Lift through the actual plaintext-scaling context when q0 < 2t;
            // reducing through q0 would truncate valid plaintext coefficients.
            let mut coefficients = Vec::<BigUint>::from(scaled.as_ref());
            coefficients.truncate(self.params.degree());
            for value in &mut coefficients {
                *value += t;
                *value %= scaled.ctx().modulus();
            }
            self.params.plaintext.reduce_vec(&mut coefficients);
            Poly::<PowerBasis>::try_convert_from(coefficients.as_slice(), ctx, false)?.into_ntt()
        };
        Ok(Plaintext {
            params: self.params.clone(),
            encoding: None,
            poly_ntt: poly,
        })
    }
}

/// A synchronized partial decryption bound to a party, designated set and ciphertext.
///
/// These shares are combined by [`SynchronizedDecryptor::decrypt_from_shares`].
/// These are locally weighted partials, not Shamir polynomial evaluations.
#[derive(Clone)]
pub struct DecryptionShare {
    poly: Poly<PowerBasis>,
    party_id: usize,
    decryptors: Vec<usize>,
    digest: ContextDigest,
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
