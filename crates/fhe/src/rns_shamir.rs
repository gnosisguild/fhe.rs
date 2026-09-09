//! Shamir sharing directly over an RNS basis.

#![expect(
    clippy::indexing_slicing,
    reason = "indices are bounded by validated matrix dimensions"
)]

use std::fmt;

use fhe_math::zq::Modulus;
use ndarray::{Array2, ArrayView2};
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, ThresholdError};

/// Wipe-on-drop Shamir shares with layout `[modulus][party][coefficient]`.
pub(crate) struct RnsShareSet {
    matrices: Vec<SecretShareMatrix>,
}

impl RnsShareSet {
    /// Transfers shares to the established unprotected TRBFV API boundary.
    pub(crate) fn into_matrices(mut self) -> Vec<Array2<u64>> {
        let mut matrices = Vec::with_capacity(self.matrices.len());
        for matrix in &mut self.matrices {
            matrices.push(std::mem::take(&mut matrix.values));
        }
        matrices
    }
}

impl fmt::Debug for RnsShareSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnsShareSet")
            .field("modulus_count", &self.matrices.len())
            .finish_non_exhaustive()
    }
}

/// Wipe-on-drop RNS matrix with layout `[modulus][coefficient]`.
pub(crate) struct SecretRnsMatrix {
    values: Array2<u64>,
}

impl SecretRnsMatrix {
    /// Transfers the reconstructed matrix to its caller.
    pub(crate) fn into_matrix(mut self) -> Array2<u64> {
        std::mem::take(&mut self.values)
    }
}

impl Drop for SecretRnsMatrix {
    fn drop(&mut self) {
        self.values.iter_mut().for_each(|value| value.zeroize());
    }
}

impl fmt::Debug for SecretRnsMatrix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRnsMatrix")
            .field("shape", &self.values.dim())
            .finish_non_exhaustive()
    }
}

struct SecretShareMatrix {
    values: Array2<u64>,
}

impl Drop for SecretShareMatrix {
    fn drop(&mut self) {
        self.values.iter_mut().for_each(|value| value.zeroize());
    }
}

struct SecretVec {
    values: Vec<u64>,
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        self.values.zeroize();
    }
}

/// Validated Shamir operations over each modulus of an RNS basis.
///
/// Every modulus must be prime. Current callers obtain these operators from a
/// validated [`fhe_math::rq::Context`].
pub(crate) struct RnsShamir<'a> {
    moduli: &'a [Modulus],
    degree: usize,
    party_count: usize,
    threshold: usize,
}

impl<'a> RnsShamir<'a> {
    /// Creates direct RNS Shamir operations over prime modulus operators.
    ///
    /// Callers must source `moduli` from a context that validates primality.
    pub(crate) fn new(
        moduli: &'a [Modulus],
        degree: usize,
        party_count: usize,
        threshold: usize,
    ) -> Result<Self, Error> {
        if moduli.is_empty() {
            return Err(fhe_math::Error::EmptyModuli.into());
        }
        if party_count == 0 {
            return Err(Error::invalid_party_count(0, 1));
        }
        if threshold >= party_count {
            return Err(Error::Threshold(ThresholdError::InvalidShamirThreshold {
                threshold,
                party_count,
            }));
        }

        let min_modulus = moduli
            .iter()
            .map(|modulus| **modulus)
            .min()
            .ok_or(fhe_math::Error::EmptyModuli)?;
        if u64::try_from(party_count).unwrap_or(u64::MAX) >= min_modulus {
            return Err(Error::party_count_exceeds_modulus(party_count, min_modulus));
        }

        Ok(Self {
            moduli,
            degree,
            party_count,
            threshold,
        })
    }

    /// Shares one canonical `[modulus, coefficient]` secret matrix.
    pub(crate) fn share<R: RngCore + CryptoRng>(
        &self,
        secrets: ArrayView2<'_, u64>,
        rng: &mut R,
    ) -> Result<RnsShareSet, Error> {
        self.validate_matrix(secrets, 0, "secret")?;
        let random_coefficient_count =
            self.threshold.checked_mul(self.degree).ok_or_else(|| {
                Error::malformed_shares(0, "Shamir coefficient dimensions overflow".to_string())
            })?;

        // Sampling before Rayon makes output independent of thread scheduling
        // without leaving expanded child-RNG state behind on worker threads.
        let random_coefficients: Vec<Zeroizing<Vec<u64>>> = self
            .moduli
            .iter()
            .map(|modulus| {
                let mut coefficients = Zeroizing::new(vec![0u64; random_coefficient_count]);
                modulus.fill_random(&mut coefficients, rng);
                coefficients
            })
            .collect();

        let matrices = self
            .moduli
            .par_iter()
            .zip(random_coefficients.par_iter())
            .enumerate()
            .map(
                |(modulus_index, (modulus, random_coefficients))| -> Result<
                    SecretShareMatrix,
                    Error,
                > {
                    let secret_row = secrets.row(modulus_index);
                    let mut values = Array2::zeros((self.party_count, self.degree));
                    for (party_index, mut share_row) in values.outer_iter_mut().enumerate() {
                        let x = (party_index + 1) as u64;
                        let share_values = share_row
                            .as_slice_mut()
                            .ok_or(fhe_math::Error::NonContiguousCoefficients)?;
                        if self.degree != 0 {
                            for coefficients_at_degree in
                                random_coefficients.chunks_exact(self.degree).rev()
                            {
                                modulus.scalar_mul_vec(share_values, x);
                                modulus.add_vec(share_values, coefficients_at_degree);
                            }
                            modulus.scalar_mul_vec(share_values, x);
                        }
                        for (share, secret) in share_values.iter_mut().zip(secret_row) {
                            *share = modulus.add(*share, *secret);
                        }
                    }

                    Ok(SecretShareMatrix { values })
                },
            )
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(RnsShareSet { matrices })
    }

    /// Reconstructs one canonical RNS matrix from exactly `threshold + 1` shares.
    pub(crate) fn reconstruct(
        &self,
        shares: &[ArrayView2<'_, u64>],
        party_ids: &[usize],
    ) -> Result<SecretRnsMatrix, Error> {
        let required = self.threshold + 1;
        if shares.len() != required {
            return Err(Error::share_count_mismatch(shares.len(), required));
        }
        if party_ids.len() != shares.len() {
            return Err(Error::share_count_mismatch(party_ids.len(), shares.len()));
        }

        for (index, &party_id) in party_ids.iter().enumerate() {
            if party_id == 0 || party_id > self.party_count {
                return Err(Error::invalid_party_id(party_id, self.party_count));
            }
            if party_ids[..index].contains(&party_id) {
                return Err(Error::duplicate_party_id(party_id));
            }
        }

        for (&party_id, share) in party_ids.iter().zip(shares) {
            self.validate_matrix(*share, party_id, "share")?;
        }

        let rows = self
            .moduli
            .par_iter()
            .enumerate()
            .map(|(modulus_index, modulus)| -> Result<SecretVec, Error> {
                let weights = self.lagrange_weights(modulus, party_ids)?;
                let weight_shoups = modulus.shoup_vec(&weights);
                let mut values = vec![0u64; self.degree];

                for coefficient_index in 0..self.degree {
                    let mut value = 0;
                    for share_index in 0..shares.len() {
                        let term = modulus.mul_shoup(
                            shares[share_index][[modulus_index, coefficient_index]],
                            weights[share_index],
                            weight_shoups[share_index],
                        );
                        value = modulus.add(value, term);
                    }
                    values[coefficient_index] = value;
                }

                Ok(SecretVec { values })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let mut values = Array2::zeros((self.moduli.len(), self.degree));
        for (mut output_row, input_row) in values.outer_iter_mut().zip(&rows) {
            for (output, input) in output_row.iter_mut().zip(&input_row.values) {
                *output = *input;
            }
        }

        Ok(SecretRnsMatrix { values })
    }

    fn validate_matrix(
        &self,
        matrix: ArrayView2<'_, u64>,
        party_id: usize,
        kind: &str,
    ) -> Result<(), Error> {
        let expected_shape = (self.moduli.len(), self.degree);
        if matrix.dim() != expected_shape {
            return Err(Error::malformed_shares(
                party_id,
                format!(
                    "{kind} matrix has shape {:?}, expected {expected_shape:?}",
                    matrix.dim()
                ),
            ));
        }

        for (row_index, (row, modulus)) in matrix.outer_iter().zip(self.moduli).enumerate() {
            if let Some(column_index) = row.iter().position(|&value| value >= **modulus) {
                return Err(Error::malformed_shares(
                    party_id,
                    format!(
                        "{kind} coefficient at row {row_index}, column {column_index} is not a \
                         canonical residue modulo {}",
                        **modulus
                    ),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn lagrange_weights(
        &self,
        modulus: &Modulus,
        party_ids: &[usize],
    ) -> Result<Vec<u64>, Error> {
        let coordinates: Vec<u64> = party_ids
            .iter()
            .map(|&party_id| {
                u64::try_from(party_id)
                    .map_err(|_| Error::invalid_party_id(party_id, self.party_count))
            })
            .collect::<Result<_, _>>()?;
        let mut numerators = vec![1u64; coordinates.len()];
        let mut denominators = vec![1u64; coordinates.len()];

        for current in 0..coordinates.len() {
            for other in 0..coordinates.len() {
                if current != other {
                    numerators[current] =
                        modulus.mul(numerators[current], modulus.neg(coordinates[other]));
                    denominators[current] = modulus.mul(
                        denominators[current],
                        modulus.sub(coordinates[current], coordinates[other]),
                    );
                }
            }
        }

        let inverse_denominators = Self::batch_invert(modulus, &denominators)?;
        Ok(numerators
            .into_iter()
            .zip(inverse_denominators)
            .map(|(numerator, inverse)| modulus.mul(numerator, inverse))
            .collect())
    }

    fn batch_invert(modulus: &Modulus, values: &[u64]) -> Result<Vec<u64>, Error> {
        if values.is_empty() {
            return Err(Error::share_count_mismatch(0, 1));
        }
        let mut prefixes = vec![1u64; values.len()];
        for index in 1..values.len() {
            prefixes[index] = modulus.mul(prefixes[index - 1], values[index - 1]);
        }

        let product = modulus.mul(prefixes[values.len() - 1], values[values.len() - 1]);
        let mut inverse = modulus
            .inv(product)
            .ok_or_else(Error::non_invertible_shares)?;
        let mut inverses = vec![0u64; values.len()];
        for index in (0..values.len()).rev() {
            inverses[index] = modulus.mul(inverse, prefixes[index]);
            inverse = modulus.mul(inverse, values[index]);
        }
        Ok(inverses)
    }
}
