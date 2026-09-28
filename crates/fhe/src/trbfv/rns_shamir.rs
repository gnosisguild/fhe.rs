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
use zeroize::Zeroize;

#[cfg(test)]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::{Error, ThresholdError};

/// Wipe-on-drop Shamir shares with layout `[modulus][party][coefficient]`.
pub(crate) struct RnsShareSet {
    matrices: Vec<SecretShareMatrix>,
}

impl RnsShareSet {
    /// Transfers shares to the established unprotected trBFV API boundary.
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
#[cfg(test)]
pub(crate) struct SecretRnsMatrix {
    values: Array2<u64>,
}

#[cfg(test)]
impl SecretRnsMatrix {
    /// Transfers the reconstructed matrix to its caller.
    pub(crate) fn into_matrix(mut self) -> Array2<u64> {
        std::mem::take(&mut self.values)
    }
}

#[cfg(test)]
impl Drop for SecretRnsMatrix {
    fn drop(&mut self) {
        self.values.iter_mut().for_each(|value| value.zeroize());
    }
}

#[cfg(test)]
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
    #[cfg(test)]
    wipe_observer: Option<Arc<AtomicBool>>,
}

impl SecretVec {
    fn new(values: Vec<u64>) -> Self {
        Self {
            values,
            #[cfg(test)]
            wipe_observer: None,
        }
    }

    #[cfg(test)]
    fn with_wipe_observer(values: Vec<u64>, wipe_observer: Arc<AtomicBool>) -> Self {
        Self {
            values,
            wipe_observer: Some(wipe_observer),
        }
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        self.values.iter_mut().for_each(Zeroize::zeroize);
        #[cfg(test)]
        if let Some(observer) = &self.wipe_observer {
            observer.store(
                self.values.iter().all(|&value| value == 0),
                Ordering::SeqCst,
            );
        }
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
        let random_coefficients: Vec<SecretVec> = self
            .moduli
            .iter()
            .map(|modulus| {
                let mut coefficients = SecretVec::new(vec![0u64; random_coefficient_count]);
                modulus.fill_random(&mut coefficients.values, rng);
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
                                random_coefficients.values.chunks_exact(self.degree).rev()
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
    #[cfg(test)]
    pub(crate) fn reconstruct(
        &self,
        shares: &[ArrayView2<'_, u64>],
        party_ids: &[usize],
    ) -> Result<SecretRnsMatrix, Error> {
        if party_ids.len() != shares.len() {
            return Err(Error::share_count_mismatch(party_ids.len(), shares.len()));
        }
        self.validate_decryptor_set(party_ids)?;

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

                Ok(SecretVec::new(values))
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

    pub(crate) fn validate_matrix(
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

    /// Checks that `party_ids` is a designated decryptor set: exactly
    /// `threshold + 1` distinct indices in `1..=n`.
    pub(crate) fn validate_decryptor_set(&self, party_ids: &[usize]) -> Result<(), Error> {
        let required = self.threshold + 1;
        if party_ids.len() != required {
            return Err(Error::share_count_mismatch(party_ids.len(), required));
        }
        for (index, &party_id) in party_ids.iter().enumerate() {
            if party_id == 0 || party_id > self.party_count {
                return Err(Error::invalid_party_id(party_id, self.party_count));
            }
            if party_ids[..index].contains(&party_id) {
                return Err(Error::duplicate_party_id(party_id));
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
            return Err(Error::Threshold(ThresholdError::EmptyBatchInversion));
        }
        let mut prefixes = vec![1u64; values.len()];
        for index in 1..values.len() {
            prefixes[index] = modulus.mul(prefixes[index - 1], values[index - 1]);
        }

        let product = modulus.mul(prefixes[values.len() - 1], values[values.len() - 1]);
        if product == 0 {
            return Err(Error::non_invertible_shares());
        }
        // RNS Shamir only accepts context-validated prime moduli, so Fermat
        // inversion avoids repeating Modulus::inv's primality test here.
        let mut inverse = modulus.pow(product, **modulus - 2);
        debug_assert_eq!(modulus.mul(product, inverse), 1);
        let mut inverses = vec![0u64; values.len()];
        for index in (0..values.len()).rev() {
            inverses[index] = modulus.mul(inverse, prefixes[index]);
            inverse = modulus.mul(inverse, values[index]);
        }
        Ok(inverses)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use ndarray::{Array2, array};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn moduli() -> Vec<Modulus> {
        [1613, 2017]
            .into_iter()
            .map(|value| Modulus::new(value).unwrap())
            .collect()
    }

    fn party_matrices(modulus_shares: &[Array2<u64>], party_count: usize) -> Vec<Array2<u64>> {
        let modulus_count = modulus_shares.len();
        let degree = modulus_shares[0].ncols();
        (0..party_count)
            .map(|party_index| {
                Array2::from_shape_fn((modulus_count, degree), |(modulus_index, coefficient)| {
                    modulus_shares[modulus_index][[party_index, coefficient]]
                })
            })
            .collect()
    }

    #[test]
    fn reconstructs_every_threshold_subset_and_permutation() {
        let moduli = moduli();
        let shamir = RnsShamir::new(&moduli, 3, 5, 2).unwrap();
        let secrets = array![[1234, 0, 1612], [42, 2016, 900]];
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let modulus_shares = shamir
            .share(secrets.view(), &mut rng)
            .unwrap()
            .into_matrices();
        let shares = party_matrices(&modulus_shares, 5);

        for subset in (1usize..=5).combinations(3) {
            for ids in subset.into_iter().permutations(3) {
                let selected: Vec<_> = ids.iter().map(|&id| shares[id - 1].view()).collect();
                let recovered = shamir.reconstruct(&selected, &ids).unwrap().into_matrix();
                assert_eq!(recovered, secrets);
            }
        }
    }

    #[test]
    fn sharing_is_independent_of_rayon_thread_count() {
        let moduli = moduli();
        let secrets = array![[12, 34, 56], [78, 90, 123]];

        let generate = |thread_count| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(thread_count)
                .build()
                .unwrap()
                .install(|| {
                    let shamir = RnsShamir::new(&moduli, 3, 5, 2).unwrap();
                    let mut rng = ChaCha8Rng::seed_from_u64(99);
                    shamir
                        .share(secrets.view(), &mut rng)
                        .unwrap()
                        .into_matrices()
                })
        };

        assert_eq!(generate(1), generate(2));
        assert_eq!(generate(1), generate(4));
    }

    #[test]
    fn reconstructs_combined_dealer_contributions() {
        let moduli = moduli();
        let shamir = RnsShamir::new(&moduli, 3, 5, 2).unwrap();
        let first_secret = array![[100, 200, 300], [400, 500, 600]];
        let second_secret = array![[11, 22, 33], [44, 55, 66]];
        let mut first_rng = ChaCha8Rng::seed_from_u64(21);
        let first = shamir
            .share(first_secret.view(), &mut first_rng)
            .unwrap()
            .into_matrices();
        let mut second_rng = ChaCha8Rng::seed_from_u64(22);
        let second = shamir
            .share(second_secret.view(), &mut second_rng)
            .unwrap()
            .into_matrices();
        let mut combined: Vec<Array2<u64>> = (0..5).map(|_| Array2::zeros((2, 3))).collect();

        for (modulus_index, modulus) in moduli.iter().enumerate() {
            for party_index in 0..5 {
                for coefficient_index in 0..3 {
                    combined[party_index][[modulus_index, coefficient_index]] = modulus.add(
                        first[modulus_index][[party_index, coefficient_index]],
                        second[modulus_index][[party_index, coefficient_index]],
                    );
                }
            }
        }

        let party_ids = [5usize, 2, 4];
        let selected: Vec<_> = party_ids
            .iter()
            .map(|&party_id| combined[party_id - 1].view())
            .collect();
        let recovered = shamir
            .reconstruct(&selected, &party_ids)
            .unwrap()
            .into_matrix();
        for (modulus_index, modulus) in moduli.iter().enumerate() {
            for coefficient_index in 0..3 {
                assert_eq!(
                    recovered[[modulus_index, coefficient_index]],
                    modulus.add(
                        first_secret[[modulus_index, coefficient_index]],
                        second_secret[[modulus_index, coefficient_index]],
                    )
                );
            }
        }
    }

    #[test]
    fn secret_buffers_are_zeroized_on_success_and_error_returns() {
        fn return_with_secret_buffer(observer: Arc<AtomicBool>, fail: bool) -> Result<(), Error> {
            let _secret = SecretVec::with_wipe_observer(vec![7, 11, 13], observer);
            if fail {
                Err(Error::Threshold(ThresholdError::EmptyBatchInversion))
            } else {
                Ok(())
            }
        }

        let success_observer = Arc::new(AtomicBool::new(false));
        return_with_secret_buffer(success_observer.clone(), false).unwrap();
        assert!(success_observer.load(Ordering::SeqCst));

        let error_observer = Arc::new(AtomicBool::new(false));
        assert!(return_with_secret_buffer(error_observer.clone(), true).is_err());
        assert!(error_observer.load(Ordering::SeqCst));
    }

    #[test]
    fn rejects_invalid_inputs() {
        let moduli = moduli();
        assert!(RnsShamir::new(&[], 2, 3, 1).is_err());
        assert!(RnsShamir::new(&moduli, 2, 0, 0).is_err());
        assert!(RnsShamir::new(&moduli, 2, 3, 3).is_err());
        assert!(RnsShamir::new(&moduli, 2, 3, 4).is_err());

        let small_modulus = [Modulus::new(5).unwrap()];
        assert!(RnsShamir::new(&small_modulus, 2, 5, 2).is_err());
        assert!(RnsShamir::new(&small_modulus, 2, 4, 1).is_ok());

        let shamir = RnsShamir::new(&moduli, 2, 3, 1).unwrap();
        assert!(matches!(
            shamir.lagrange_weights(&moduli[0], &[]),
            Err(Error::Threshold(ThresholdError::EmptyBatchInversion))
        ));
        let mut rng = ChaCha8Rng::seed_from_u64(4);
        assert!(
            shamir
                .share(Array2::zeros((1, 2)).view(), &mut rng)
                .is_err()
        );

        let valid = Array2::zeros((2, 2));
        let mut noncanonical = valid.clone();
        noncanonical[[1, 0]] = 2017;
        assert!(
            shamir
                .reconstruct(&[valid.view(), noncanonical.view()], &[1, 2])
                .is_err()
        );
        assert!(
            shamir
                .reconstruct(&[valid.view(), valid.view()], &[1, 1])
                .is_err()
        );
        assert!(
            shamir
                .reconstruct(&[valid.view(), valid.view()], &[0, 2])
                .is_err()
        );
    }
}
