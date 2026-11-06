//! SS-noise partial decryption, interpolation, and final decoding.
//!
//! This protocol interpolates complete partials and uses its own decoder rather
//! than the synchronized protocol's weighted-key summation and decoding path.

use super::shares::AggregatedSmudgingShare;
use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::trbfv::buffers::SecretMatrix;
use crate::trbfv::config::{validate_ciphertext, validate_matrix};
use crate::trbfv::{ShamirSecretSharing, SsSmudgingDecryptionConfig};
use crate::{Error, ParameterSource};
use fhe_math::rns::{RnsContext, ScalingFactor};
use fhe_math::rq::scaler::Scaler;
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::rq::{Context, Ntt, Poly, PowerBasis};
use fhe_math::zq::Modulus;
use ndarray::Array2;
use num_bigint::{BigInt, BigUint};
use num_traits::ToPrimitive;
use rayon::prelude::*;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Decryptor for the SS smudging protocol.
///
/// This protocol has no pairwise PRF keys or designated-set hashes. Each partial
/// contains `c0`; interpolation, not summation, reconstructs the phase. Use only
/// [`SsSmudgingDecryptionShare`] values with this decryptor.
#[derive(Debug)]
pub struct SsSmudgingDecryptor {
    n: usize,
    threshold: usize,
    params: Arc<BfvParameters>,
}

impl SsSmudgingDecryptor {
    /// Construct from a validated SS-protocol configuration.
    #[must_use]
    pub fn new(config: SsSmudgingDecryptionConfig) -> Self {
        Self {
            n: config.committee_size(),
            threshold: config.threshold(),
            params: config.params().clone(),
        }
    }

    /// Total committee size, not the number of partials to collect.
    #[must_use]
    pub fn committee_size(&self) -> usize {
        self.n
    }

    /// Shamir polynomial degree; reconstruction requires `threshold + 1` shares.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Underlying BFV parameters.
    #[must_use]
    pub fn params(&self) -> &Arc<BfvParameters> {
        &self.params
    }

    /// Compute the `c0 + c1 * sk_i + es_i` partial.
    ///
    /// `secret_key` is the reusable aggregate Shamir key share, not a party's
    /// original BFV key. `noise` is the aggregate of received, dealt noise shares
    /// and is consumed even on failure. The reconstructing set need not be known.
    /// Contexts, matrix shapes/layouts, and canonical residues are checked before
    /// rebuilding inputs into constant-time polynomial storage. The borrowed key
    /// remains owned by the caller and should be kept in a zeroizing owner.
    #[allow(clippy::indexing_slicing)] // Ciphertext components are validated before indexing.
    pub fn decryption_share(
        &self,
        ciphertext: &Ciphertext,
        secret_key: &Poly<Ntt>,
        noise: AggregatedSmudgingShare,
    ) -> Result<SsSmudgingDecryptionShare, Error> {
        self.validate_ciphertext(ciphertext)?;
        let ctx = self.params.context_at_level(0)?;
        if secret_key.ctx() != ctx || noise.poly.ctx() != ctx {
            return Err(Error::ParameterMismatch {
                left: ParameterSource::Polynomial,
                right: ParameterSource::Ciphertext,
            });
        }
        for coefficients in [secret_key.coefficients(), noise.poly.coefficients()] {
            validate_matrix(coefficients, self.params.moduli(), self.params.degree(), 0)?;
        }

        // Rebuild validated coefficients so raw lazy/timing metadata cannot
        // affect secret arithmetic. Guard the key product until noise is added.
        let mut c0 = Poly::<Ntt>::zero(ctx);
        c0.set_coefficients(ciphertext.c[0].coefficients().to_owned());
        let mut c1sk = Zeroizing::new(Poly::<Ntt>::zero(ctx));
        c1sk.set_coefficients(ciphertext.c[1].coefficients().to_owned());
        let mut sk_i = Zeroizing::new(Poly::<Ntt>::zero(ctx));
        sk_i.set_coefficients(secret_key.coefficients().to_owned());
        *c1sk.as_mut() *= sk_i.as_ref();
        let c1sk = Zeroizing::new(
            std::mem::replace(c1sk.as_mut(), Poly::<Ntt>::zero(ctx)).into_power_basis(),
        );
        let mut es_i = Zeroizing::new(Poly::<PowerBasis>::zero(ctx));
        es_i.set_coefficients(noise.poly.coefficients().to_owned());
        let mut poly = Zeroizing::new(c0.into_power_basis());
        *poly.as_mut() += c1sk.as_ref();
        *poly.as_mut() += es_i.as_ref();
        Ok(SsSmudgingDecryptionShare {
            poly: std::mem::replace(poly.as_mut(), Poly::<PowerBasis>::zero(ctx)),
        })
    }

    /// Interpolate exactly `threshold + 1` partials, then decode.
    ///
    /// Party IDs are 1-based and match the partials' order. Their agreement,
    /// authentication and correct association with partials remain external,
    /// without verifying proofs or ciphertext binding.
    pub fn decrypt_from_shares(
        &self,
        shares: &[SsSmudgingDecryptionShare],
        reconstructing_parties: &[usize],
        ciphertext: &Ciphertext,
    ) -> Result<Plaintext, Error> {
        self.validate_ciphertext(ciphertext)?;
        let phase = self.reconstruct_phase(shares, reconstructing_parties)?;
        self.decode_phase(phase, ciphertext)
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

    #[allow(clippy::indexing_slicing)] // Party counts, indices, and shapes are checked before recovery.
    fn reconstruct_phase(
        &self,
        shares: &[SsSmudgingDecryptionShare],
        reconstructing_parties: &[usize],
    ) -> Result<Zeroizing<Poly<PowerBasis>>, Error> {
        if shares.len() != self.threshold + 1 {
            return Err(Error::share_count_mismatch(
                shares.len(),
                self.threshold + 1,
            ));
        }
        if reconstructing_parties.len() != shares.len() {
            return Err(Error::share_count_mismatch(
                reconstructing_parties.len(),
                shares.len(),
            ));
        }
        let mut seen = vec![false; self.n + 1];
        for &idx in reconstructing_parties {
            if idx == 0 || idx > self.n {
                return Err(Error::invalid_party_id(idx, self.n));
            }
            if seen[idx] {
                return Err(Error::duplicate_party_id(idx));
            }
            seen[idx] = true;
        }
        let ctx = self.params.context_at_level(0)?;
        for (&party_id, share) in reconstructing_parties.iter().zip(shares) {
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
                party_id,
            )?;
        }
        let recovered: Result<Vec<Vec<Zeroizing<u64>>>, Error> = (0..self.params.moduli().len())
            .into_par_iter()
            .map(|m| {
                let shamir_ss = ShamirSecretSharing::new(
                    self.threshold,
                    self.n,
                    BigInt::from(self.params.moduli[m]),
                );
                (0..self.params.degree())
                    .into_par_iter()
                    .map(|i| -> Result<Zeroizing<u64>, Error> {
                        let mut points = Vec::with_capacity(self.threshold + 1);
                        for (&party_id, share) in reconstructing_parties.iter().zip(shares) {
                            let coefficients = share.poly.coefficients();
                            points.push((party_id, BigInt::from(coefficients[[m, i]])));
                        }
                        let coefficient =
                            shamir_ss.recover(&points)?.to_u64().ok_or_else(|| {
                                Error::malformed_shares(
                                    0,
                                    "recovered Shamir coefficient does not fit in u64".to_string(),
                                )
                            })?;
                        Ok(Zeroizing::new(coefficient))
                    })
                    .collect::<Result<Vec<_>, Error>>()
            })
            .collect();
        let recovered = recovered?;
        let mut matrix = SecretMatrix(Array2::zeros((
            self.params.moduli().len(),
            self.params.degree(),
        )));
        for (mut row, coefficients) in matrix.0.rows_mut().into_iter().zip(&recovered) {
            for (cell, value) in row.iter_mut().zip(coefficients) {
                *cell = **value;
            }
        }
        let mut phase = Zeroizing::new(Poly::<PowerBasis>::zero(ctx));
        phase.set_coefficients(std::mem::take(&mut matrix.0));
        Ok(phase)
    }

    #[allow(clippy::indexing_slicing)] // Scaler construction and first-row decoding use validated contexts.
    fn decode_phase(
        &self,
        phase: Zeroizing<Poly<PowerBasis>>,
        ciphertext: &Ciphertext,
    ) -> Result<Plaintext, Error> {
        let params = ciphertext.params.clone();
        let ptxt_u64 = params.plaintext.as_u64().ok_or_else(|| {
            Error::ParametersError(crate::ParametersError::UnsupportedPlaintextModulus {
                reason: "threshold BFV decrypt_from_shares requires a u64 plaintext modulus"
                    .to_string(),
            })
        })?;
        let plaintext_ctx = Context::new_arc(&self.params.moduli()[..1], self.params.degree())
            .map_err(Error::MathError)?;
        let scalers: Result<Vec<_>, Error> = (0..self.params.moduli().len())
            .into_par_iter()
            .map(|i| {
                let rns = RnsContext::new(&self.params.moduli()[..self.params.moduli().len() - i])
                    .map_err(Error::MathError)?;
                let ctx_i = Context::new_arc(
                    &self.params.moduli()[..self.params.moduli().len() - i],
                    self.params.degree(),
                )
                .map_err(Error::MathError)?;
                Scaler::new(
                    &ctx_i,
                    &plaintext_ctx,
                    ScalingFactor::new(&BigUint::from(ptxt_u64), rns.modulus()),
                )
                .map_err(Error::MathError)
            })
            .collect();
        let scalers = scalers?;
        let d = Zeroizing::new(
            phase
                .scale(&scalers[ciphertext.level])
                .map_err(Error::MathError)?,
        );
        let mut v = Zeroizing::new(Vec::<u64>::try_from(d.as_ref()).map_err(Error::from)?);
        for value in v.iter_mut() {
            // Both the scaled residue and the native plaintext modulus fit in
            // the library's at-most-62-bit Modulus representation.
            *value += ptxt_u64;
        }
        let mut w = Zeroizing::new(v[..params.degree()].to_vec());
        let q = Modulus::new(params.moduli()[0]).map_err(Error::MathError)?;
        q.reduce_vec(w.as_mut_slice());
        Modulus::new(ptxt_u64)
            .map_err(Error::MathError)?
            .reduce_vec(w.as_mut_slice());
        let poly =
            Poly::<PowerBasis>::try_convert_from(w.as_slice(), ciphertext.c[0].ctx(), false)?
                .into_ntt();
        Ok(Plaintext {
            params,
            encoding: None,
            poly_ntt: poly,
        })
    }
}

/// An SS-smudging partial, not a synchronized partial.
///
/// Contains `c0` and requires Shamir interpolation. Identity, request binding,
/// authentication, and proofs remain application responsibilities. Cloning or
/// retransmitting this public result does not duplicate the consumed noise owner.
#[derive(Clone)]
pub struct SsSmudgingDecryptionShare {
    poly: Poly<PowerBasis>,
}

impl SsSmudgingDecryptionShare {
    /// Explicitly import a partial polynomial from application transport.
    /// Reconstruction checks contexts, shapes, canonical residues, and party counts.
    #[must_use]
    pub fn from_parts(poly: Poly<PowerBasis>) -> Self {
        Self { poly }
    }

    /// Consume into the polynomial transport representation.
    #[must_use]
    pub fn into_parts(self) -> Poly<PowerBasis> {
        self.poly
    }
}

impl std::fmt::Debug for SsSmudgingDecryptionShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsSmudgingDecryptionShare")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::bfv::BfvParametersBuilder;

    #[test]
    fn decoding_rejects_unsupported_plaintext_width_without_panicking() {
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus_biguint((BigUint::from(1u32) << 80usize) + 7u32)
            .set_moduli_sizes(&[50, 50, 50])
            .build_arc()
            .unwrap();
        let decryptor = SsSmudgingDecryptor::new(
            SsSmudgingDecryptionConfig::new(3, 1, params.clone()).unwrap(),
        );
        let ctx = params.context_at_level(0).unwrap();
        let ciphertext = Ciphertext::new(vec![Poly::zero(ctx), Poly::zero(ctx)], &params).unwrap();
        let partial = SsSmudgingDecryptionShare::from_parts(Poly::zero(ctx));
        assert!(matches!(
            decryptor.decrypt_from_shares(&[partial.clone(), partial], &[1, 2], &ciphertext),
            Err(Error::ParametersError(
                crate::ParametersError::UnsupportedPlaintextModulus { .. }
            ))
        ));
    }

    #[test]
    fn interpolation_recovers_the_constant_term_for_arbitrary_parties() {
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(17)
            .set_moduli_sizes(&[50, 50, 50])
            .build_arc()
            .unwrap();
        let decryptor = SsSmudgingDecryptor::new(
            SsSmudgingDecryptionConfig::new(5, 2, params.clone()).unwrap(),
        );
        let ids = [5, 2, 4];
        let partials: Vec<_> = ids
            .iter()
            .map(|&id| {
                // A degree-two sharing polynomial with constant term column + 1.
                let matrix = Array2::from_shape_fn((3, 8), |(row, column)| {
                    (column as u64 + 1 + 100 * id as u64 + (row as u64 + 7) * (id as u64).pow(2))
                        % params.moduli()[row]
                });
                let poly = Poly::<PowerBasis>::from_coeffs_matrix(
                    matrix,
                    params.context_at_level(0).unwrap(),
                )
                .unwrap();
                SsSmudgingDecryptionShare::from_parts((*poly).clone())
            })
            .collect();
        let phase = decryptor.reconstruct_phase(&partials, &ids).unwrap();
        for row in phase.coefficients().rows() {
            assert_eq!(row.to_vec(), (1..=8).collect::<Vec<u64>>());
        }
    }
}
