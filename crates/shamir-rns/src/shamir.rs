//! Shamir sharing over a runtime prime field.

use core::fmt;
use std::collections::HashSet;

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "rayon")]
use rayon::prelude::*;

use crate::{BarrettField, Error, Field};

/// Secret shares in party-major layout.
///
/// A matrix with shape `[rows, columns]` stores each party's complete row
/// contiguously. `rows` is the number of parties represented and `columns` is
/// the number of independently shared secrets. Values are canonical residues
/// modulo the scheme modulus. The owned storage is zeroized on drop; a plain
/// `Vec<u64>` returned by a single-secret API remains the caller's ownership
/// responsibility.
pub struct ShareMatrix {
    rows: usize,
    columns: usize,
    values: Vec<u64>,
}

impl ShareMatrix {
    /// Construct a matrix from party-major values.
    ///
    /// # Errors
    /// Returns [`Error::InvalidMatrixStorage`] when `values.len()` is not the
    /// product of `rows` and `columns`.
    pub fn new(rows: usize, columns: usize, values: Vec<u64>) -> Result<Self, Error> {
        let Some(expected) = rows.checked_mul(columns) else {
            let mut values = values;
            values.zeroize();
            return Err(Error::InvalidMatrixStorage);
        };
        if values.len() != expected {
            let mut values = values;
            values.zeroize();
            return Err(Error::InvalidMatrixStorage);
        }
        Ok(Self {
            rows,
            columns,
            values,
        })
    }

    /// Return the number of party rows.
    #[must_use]
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Return the number of party rows (`num_shares` in scheme terminology).
    #[must_use]
    pub fn num_shares(&self) -> usize {
        self.rows
    }

    /// Return the number of secrets in each row.
    #[must_use]
    pub fn columns(&self) -> usize {
        self.columns
    }

    /// Return the number of shared secrets (`num_secrets` in scheme terminology).
    #[must_use]
    pub fn num_secrets(&self) -> usize {
        self.columns
    }

    /// Return the flat party-major storage.
    #[must_use]
    pub fn as_slice(&self) -> &[u64] {
        &self.values
    }

    /// Return one party row by zero-based matrix row.
    #[must_use]
    pub fn row(&self, row: usize) -> Option<&[u64]> {
        let start = row.checked_mul(self.columns)?;
        let end = start.checked_add(self.columns)?;
        self.values.get(start..end)
    }
}

impl Clone for ShareMatrix {
    fn clone(&self) -> Self {
        Self {
            rows: self.rows,
            columns: self.columns,
            values: self.values.clone(),
        }
    }
}

impl fmt::Debug for ShareMatrix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShareMatrix")
            .field("rows", &self.rows)
            .field("columns", &self.columns)
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Drop for ShareMatrix {
    fn drop(&mut self) {
        self.values.zeroize();
    }
}

impl Zeroize for ShareMatrix {
    fn zeroize(&mut self) {
        self.values.zeroize();
    }
}

impl ZeroizeOnDrop for ShareMatrix {}

/// A Shamir scheme over a runtime odd prime field.
///
/// `shares_needed` is the exact reconstruction count, not a polynomial
/// threshold. The sharing polynomial has degree `shares_needed - 1`, the
/// secret is its value at `x = 0`, and party points are exactly `1..=n`.
/// This primitive does not provide commitments, verifiability, robust DKG,
/// transport authentication, or a complete threshold protocol.
#[derive(Clone, Debug)]
pub struct ShamirScheme<F: Field = BarrettField> {
    field: F,
    shares_needed: usize,
    num_shares: usize,
}

impl<F: Field> ShamirScheme<F> {
    /// Construct a scheme with exactly `shares_needed` required shares and
    /// `num_shares` available parties.
    ///
    /// # Errors
    /// Rejects zero counts, `shares_needed > num_shares`, a party count not
    /// below the modulus, and a non-prime or unsupported modulus.
    pub fn new(shares_needed: usize, num_shares: usize, modulus: u64) -> Result<Self, Error> {
        if shares_needed == 0 || shares_needed > num_shares {
            return Err(Error::InvalidThreshold {
                shares_needed,
                num_shares,
            });
        }
        let field = F::try_new(modulus)?;
        if (num_shares as u128) >= modulus as u128 {
            return Err(Error::TooManyShares {
                num_shares,
                modulus,
            });
        }
        Ok(Self {
            field,
            shares_needed,
            num_shares,
        })
    }

    /// Return the exact number of shares required for reconstruction.
    #[must_use]
    pub fn shares_needed(&self) -> usize {
        self.shares_needed
    }

    /// Return the total number of canonical party points.
    #[must_use]
    pub fn num_shares(&self) -> usize {
        self.num_shares
    }

    /// Return the runtime field modulus.
    #[must_use]
    pub fn modulus(&self) -> u64 {
        self.field.modulus()
    }

    /// Return the canonical 1-based party identifiers.
    #[must_use]
    pub fn points(&self) -> Vec<usize> {
        (1..=self.num_shares).collect()
    }

    /// Share one canonical secret, returning values ordered by party ID.
    ///
    /// A fresh ChaCha20 stream is forked for every random polynomial
    /// coefficient from the caller's cryptographic RNG. The fork schedule is
    /// deterministic for an identically seeded caller RNG.
    ///
    /// # Errors
    /// Returns [`Error::NonCanonicalSecret`] when `secret >= q`.
    pub fn share<R: RngCore + CryptoRng>(
        &self,
        secret: u64,
        rng: &mut R,
    ) -> Result<Vec<u64>, Error> {
        self.validate_secret(secret)?;
        let mut seed = [0_u8; 32];
        rng.fill_bytes(&mut seed);
        let mut fork = ChaCha20Rng::from_seed(seed);
        seed.zeroize();
        self.share_with_rng(secret, &mut fork)
    }

    fn share_with_rng<R: RngCore + CryptoRng>(
        &self,
        secret: u64,
        rng: &mut R,
    ) -> Result<Vec<u64>, Error> {
        let coefficients = self.sample_coefficients(secret, rng);
        let mut shares = Vec::with_capacity(self.num_shares);
        for point in 1..=self.num_shares {
            let x = point as u64;
            let mut value = 0_u64;
            for coefficient in coefficients.iter().rev() {
                value = self.field.add(self.field.mul(value, x), *coefficient);
            }
            shares.push(value);
        }
        Ok(shares)
    }

    /// Share many canonical secrets into a party-major matrix.
    ///
    /// Empty secret batches are valid and return a matrix with `num_shares`
    /// rows and zero columns. Each secret consumes the same deterministic
    /// fork sequence as an independent call to [`Self::share`].
    pub fn share_batch<R: RngCore + CryptoRng>(
        &self,
        secrets: &[u64],
        rng: &mut R,
    ) -> Result<ShareMatrix, Error> {
        for secret in secrets {
            self.validate_secret(*secret)?;
        }
        let mut seeds = Zeroizing::new(Vec::<[u8; 32]>::with_capacity(secrets.len()));
        for _ in secrets {
            let mut seed = [0_u8; 32];
            rng.fill_bytes(&mut seed);
            seeds.push(seed);
            seed.zeroize();
        }
        #[cfg(feature = "rayon")]
        let by_secret: Vec<Zeroizing<Vec<u64>>> = secrets
            .par_iter()
            .zip(seeds.par_iter())
            .map(|(secret, source_seed)| {
                let mut seed = *source_seed;
                let mut fork = ChaCha20Rng::from_seed(seed);
                let result = self.share_with_rng(*secret, &mut fork).map(Zeroizing::new);
                seed.zeroize();
                result
            })
            .collect::<Result<_, _>>()?;
        #[cfg(not(feature = "rayon"))]
        let by_secret: Vec<Zeroizing<Vec<u64>>> = secrets
            .iter()
            .zip(seeds.iter())
            .map(|(secret, source_seed)| {
                let mut seed = *source_seed;
                let mut fork = ChaCha20Rng::from_seed(seed);
                let result = self.share_with_rng(*secret, &mut fork).map(Zeroizing::new);
                seed.zeroize();
                result
            })
            .collect::<Result<_, _>>()?;
        let mut values = Zeroizing::new(Vec::with_capacity(
            self.num_shares.saturating_mul(secrets.len()),
        ));
        let mut iterators = by_secret
            .iter()
            .map(|shares| shares.iter())
            .collect::<Vec<_>>();
        for _ in 0..self.num_shares {
            for iterator in &mut iterators {
                let value = iterator.next().ok_or(Error::InvalidMatrixStorage)?;
                values.push(*value);
            }
        }
        ShareMatrix::new(self.num_shares, secrets.len(), std::mem::take(&mut *values))
    }

    /// Reconstruct one secret from exactly `shares_needed` `(party_id, value)`
    /// pairs.
    ///
    /// # Errors
    /// Rejects wrong counts, zero/out-of-range or duplicate IDs, and values
    /// outside the canonical residue range.
    pub fn reconstruct(&self, shares: &[(usize, u64)]) -> Result<u64, Error> {
        self.validate_share_pairs(shares)?;
        let points = shares
            .iter()
            .map(|(point, _)| *point as u64)
            .collect::<Vec<_>>();
        let values = Zeroizing::new(shares.iter().map(|(_, value)| *value).collect::<Vec<_>>());
        let mut terms = Zeroizing::new(Vec::with_capacity(shares.len()));
        for (index, (point, value)) in points.iter().zip(values.iter()).enumerate() {
            let mut numerator = 1_u64;
            let mut denominator = 1_u64;
            for (other_index, other_point) in points.iter().enumerate() {
                if index != other_index {
                    numerator = self.field.mul(numerator, self.field.sub(0, *other_point));
                    denominator = self
                        .field
                        .mul(denominator, self.field.sub(*point, *other_point));
                }
            }
            let inverse = self.field.invert(denominator).ok_or(Error::NonInvertible)?;
            let weight = self.field.mul(numerator, inverse);
            terms.push(self.field.mul(weight, *value));
        }
        Ok(terms.iter().fold(0_u64, |accumulator, term| {
            self.field.add(accumulator, *term)
        }))
    }

    /// Reconstruct a batch from a party-major matrix containing exactly the
    /// selected party rows and their corresponding 1-based IDs.
    pub fn reconstruct_batch(
        &self,
        shares: &ShareMatrix,
        party_ids: &[usize],
    ) -> Result<Vec<u64>, Error> {
        if shares.rows() != self.shares_needed || party_ids.len() != self.shares_needed {
            return Err(Error::WrongShareCount {
                expected: self.shares_needed,
                actual: if shares.rows() != self.shares_needed {
                    shares.rows()
                } else {
                    party_ids.len()
                },
            });
        }
        let mut seen = HashSet::with_capacity(party_ids.len());
        for party_id in party_ids {
            self.validate_party_id(*party_id)?;
            if !seen.insert(*party_id) {
                return Err(Error::DuplicatePartyId {
                    party_id: *party_id,
                });
            }
        }
        for value in shares.as_slice() {
            self.validate_share_value(*value)?;
        }
        let mut result = Zeroizing::new(Vec::with_capacity(shares.columns()));
        for column in 0..shares.columns() {
            let pairs = Zeroizing::new(
                party_ids
                    .iter()
                    .enumerate()
                    .map(|(row, party_id)| {
                        let value = shares
                            .row(row)
                            .and_then(|values| values.get(column))
                            .copied()
                            .ok_or(Error::InvalidMatrixStorage)?;
                        Ok((*party_id, value))
                    })
                    .collect::<Result<Vec<_>, Error>>()?,
            );
            result.push(self.reconstruct(&pairs)?);
        }
        Ok(std::mem::take(&mut *result))
    }

    /// Reconstruct a batch from explicit `(party_id, row)` pairs.
    pub fn reconstruct_batch_rows(&self, shares: &[(usize, &[u64])]) -> Result<Vec<u64>, Error> {
        if shares.len() != self.shares_needed {
            return Err(Error::WrongShareCount {
                expected: self.shares_needed,
                actual: shares.len(),
            });
        }
        let columns = shares.first().map_or(0, |(_, row)| row.len());
        if shares.iter().any(|(_, row)| row.len() != columns) {
            return Err(Error::InvalidMatrixShape {
                expected_rows: shares.len(),
                expected_columns: columns,
                actual_rows: shares.len(),
                actual_columns: shares
                    .iter()
                    .find_map(|(_, row)| (row.len() != columns).then_some(row.len()))
                    .unwrap_or(columns),
            });
        }
        let mut values = Zeroizing::new(
            shares
                .iter()
                .flat_map(|(_, row)| row.iter().copied())
                .collect::<Vec<_>>(),
        );
        let matrix = ShareMatrix::new(shares.len(), columns, std::mem::take(&mut *values))?;
        let party_ids = shares
            .iter()
            .map(|(party_id, _)| *party_id)
            .collect::<Vec<_>>();
        self.reconstruct_batch(&matrix, &party_ids)
    }

    fn sample_coefficients<R: RngCore + CryptoRng>(
        &self,
        secret: u64,
        rng: &mut R,
    ) -> Zeroizing<Vec<u64>> {
        let mut coefficients = Zeroizing::new(Vec::with_capacity(self.shares_needed));
        coefficients.push(secret);
        for _ in 1..self.shares_needed {
            let mut seed = [0_u8; 32];
            rng.fill_bytes(&mut seed);
            let mut coefficient_rng = ChaCha20Rng::from_seed(seed);
            coefficients.push(self.field.sample(&mut coefficient_rng));
            seed.zeroize();
        }
        coefficients
    }

    fn validate_secret(&self, secret: u64) -> Result<(), Error> {
        if secret >= self.modulus() {
            Err(Error::NonCanonicalSecret {
                value: secret,
                modulus: self.modulus(),
            })
        } else {
            Ok(())
        }
    }

    fn validate_share_value(&self, value: u64) -> Result<(), Error> {
        if value >= self.modulus() {
            Err(Error::NonCanonicalShare {
                value,
                modulus: self.modulus(),
            })
        } else {
            Ok(())
        }
    }

    fn validate_party_id(&self, party_id: usize) -> Result<(), Error> {
        if party_id == 0 || party_id > self.num_shares {
            Err(Error::InvalidPartyId { party_id })
        } else {
            Ok(())
        }
    }

    fn validate_share_pairs(&self, shares: &[(usize, u64)]) -> Result<(), Error> {
        if shares.len() != self.shares_needed {
            return Err(Error::WrongShareCount {
                expected: self.shares_needed,
                actual: shares.len(),
            });
        }
        let mut seen = HashSet::with_capacity(shares.len());
        for (party_id, value) in shares {
            self.validate_party_id(*party_id)?;
            if !seen.insert(*party_id) {
                return Err(Error::DuplicatePartyId {
                    party_id: *party_id,
                });
            }
            self.validate_share_value(*value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use zeroize::Zeroize;

    use super::{ShamirScheme, ShareMatrix};
    use crate::{BarrettField, Error, MontgomeryField};

    fn wikipedia<F: crate::Field>() {
        let scheme = ShamirScheme::<F>::new(3, 6, 1613).unwrap();
        let coefficients = [1234_u64, 166, 94];
        let mut shares = Vec::new();
        for point in 1..=6_u64 {
            let mut value = 0;
            for coefficient in coefficients.iter().rev() {
                value = (value * point + coefficient) % 1613;
            }
            shares.push((point as usize, value));
        }
        assert_eq!(
            shares.iter().map(|(_, value)| *value).collect::<Vec<_>>(),
            [1494, 329, 965, 176, 1188, 775]
        );
        let selected = shares.get(..3).unwrap();
        assert_eq!(scheme.reconstruct(selected), Ok(1234));
    }

    #[test]
    fn wikipedia_both_backends() {
        wikipedia::<BarrettField>();
        wikipedia::<MontgomeryField>();
    }

    #[test]
    fn strict_validation_and_party_major_batch() {
        let scheme = ShamirScheme::<BarrettField>::new(2, 3, 1613).unwrap();
        assert!(matches!(
            scheme.share(1613, &mut ChaCha20Rng::from_seed([1; 32])),
            Err(Error::NonCanonicalSecret { .. })
        ));
        let mut rng = ChaCha20Rng::from_seed([2; 32]);
        let matrix = scheme.share_batch(&[10, 20, 30], &mut rng).unwrap();
        assert_eq!(matrix.rows(), 3);
        assert_eq!(matrix.columns(), 3);
        assert_eq!(matrix.row(0).unwrap().len(), 3);
        let ids = [1, 3];
        let selected = ShareMatrix::new(
            2,
            3,
            [
                matrix.row(0).unwrap().to_vec(),
                matrix.row(2).unwrap().to_vec(),
            ]
            .concat(),
        )
        .unwrap();
        assert_eq!(
            scheme.reconstruct_batch(&selected, &ids).unwrap(),
            [10, 20, 30]
        );
        assert!(scheme.reconstruct(&[(1, 0), (1, 0)]).is_err());
        assert!(scheme.reconstruct(&[(0, 0), (1, 0)]).is_err());
        assert!(scheme.reconstruct(&[(1, 0), (4, 0)]).is_err());
        assert!(scheme.reconstruct(&[(1, 0), (2, 1613)]).is_err());
        assert!(scheme.reconstruct(&[(1, 0)]).is_err());
        let empty = scheme.share_batch(&[], &mut rng).unwrap();
        assert_eq!(empty.rows(), scheme.num_shares());
        assert_eq!(empty.columns(), 0);
        let selected_empty = ShareMatrix::new(2, 0, Vec::new()).unwrap();
        assert_eq!(
            scheme.reconstruct_batch(&selected_empty, &[1, 2]).unwrap(),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn determinism_and_batch_single_equivalence() {
        let scheme = ShamirScheme::<BarrettField>::new(3, 5, 4611686018326724609).unwrap();
        let mut first = ChaCha20Rng::from_seed([9; 32]);
        let mut second = ChaCha20Rng::from_seed([9; 32]);
        let batch = scheme.share_batch(&[1, 2, 3], &mut first).unwrap();
        let singles = [1_u64, 2, 3]
            .into_iter()
            .map(|secret| scheme.share(secret, &mut second).unwrap())
            .collect::<Vec<_>>();
        for party in 0..scheme.num_shares() {
            for (column, single) in singles.iter().enumerate() {
                assert_eq!(batch.row(party).unwrap().get(column), single.get(party));
            }
        }
    }

    #[test]
    fn owned_matrix_zeroizes_and_redacts_values() {
        let mut matrix = ShareMatrix::new(1, 2, vec![11, 22]).unwrap();
        assert!(!format!("{matrix:?}").contains("11"));
        matrix.zeroize();
        assert!(matrix.as_slice().is_empty());
    }

    fn malformed_rejections<F: crate::Field>(
        shares_needed: usize,
        num_shares: usize,
        modulus: u64,
        secret: u64,
    ) -> bool {
        let scheme = ShamirScheme::<F>::new(shares_needed, num_shares, modulus).unwrap();
        let mut rng = ChaCha20Rng::from_seed([23; 32]);
        let shares = scheme.share(secret, &mut rng).unwrap();
        let valid = (1..=shares_needed)
            .filter_map(|party_id| {
                shares
                    .get(party_id - 1)
                    .copied()
                    .map(|value| (party_id, value))
            })
            .collect::<Vec<_>>();
        let fewer = valid
            .iter()
            .take(shares_needed.saturating_sub(1))
            .copied()
            .collect::<Vec<_>>();
        let duplicate = if shares_needed == 1 {
            valid
                .first()
                .copied()
                .map(|pair| vec![pair, pair])
                .unwrap_or_default()
        } else {
            let mut pairs = valid.clone();
            if let (Some(first), Some(last)) = (valid.first().copied(), pairs.last_mut()) {
                *last = first;
            }
            pairs
        };
        let mut zero_id = valid.clone();
        if let Some(first) = zero_id.first_mut() {
            first.0 = 0;
        }
        let mut out_of_range_id = valid.clone();
        if let Some(first) = out_of_range_id.first_mut() {
            first.0 = num_shares + 1;
        }
        let mut noncanonical = valid;
        if let Some(first) = noncanonical.first_mut() {
            first.1 = modulus;
        }
        scheme.reconstruct(&fewer).is_err()
            && scheme.reconstruct(&duplicate).is_err()
            && scheme.reconstruct(&zero_id).is_err()
            && scheme.reconstruct(&out_of_range_id).is_err()
            && scheme.reconstruct(&noncanonical).is_err()
    }

    proptest! {
        #[test]
        fn preset_prime_roundtrips(
            modulus in prop::sample::select(vec![
                4_611_686_018_326_724_609_u64,
                4_611_686_018_309_947_393,
                4_611_686_018_282_684_417,
                4_611_686_018_257_518_593,
            ]),
            shares_needed in 1_usize..=5,
            extra_shares in 0_usize..=7,
            subset_seed: u64,
            secret: u64,
        ) {
            let num_shares = shares_needed + extra_shares;
            let secret = secret % modulus;
            let barrett = ShamirScheme::<BarrettField>::new(shares_needed, num_shares, modulus).unwrap();
            let montgomery = ShamirScheme::<MontgomeryField>::new(shares_needed, num_shares, modulus).unwrap();
            let mut barrett_rng = ChaCha20Rng::from_seed([21; 32]);
            let mut montgomery_rng = ChaCha20Rng::from_seed([21; 32]);
            let barrett_shares = barrett.share(secret, &mut barrett_rng).unwrap();
            let montgomery_shares = montgomery.share(secret, &mut montgomery_rng).unwrap();
            prop_assert_eq!(&barrett_shares, &montgomery_shares);
            let mut party_ids = (1..=num_shares).collect::<Vec<_>>();
            let mut subset_rng = ChaCha20Rng::from_seed(subset_seed.to_le_bytes().repeat(4).try_into().unwrap());
            for index in (1..party_ids.len()).rev() {
                let selected = (subset_rng.next_u64() as usize) % (index + 1);
                party_ids.swap(index, selected);
            }
            party_ids.truncate(shares_needed);
            party_ids.sort_unstable();
            let pairs = party_ids
                .iter()
                .map(|party| (*party, *barrett_shares.get(*party - 1).unwrap()))
                .collect::<Vec<_>>();
            prop_assert_eq!(barrett.reconstruct(&pairs), Ok(secret));
            prop_assert_eq!(montgomery.reconstruct(&pairs), Ok(secret));
        }

        #[test]
        fn malformed_subsets_are_rejected_by_both_backends(
            modulus in prop::sample::select(vec![
                4_611_686_018_326_724_609_u64,
                4_611_686_018_309_947_393,
                4_611_686_018_282_684_417,
                4_611_686_018_257_518_593,
            ]),
            shares_needed in 1_usize..=5,
            extra_shares in 0_usize..=7,
            secret: u64,
        ) {
            let num_shares = shares_needed + extra_shares;
            let secret = secret % modulus;
            prop_assert!(malformed_rejections::<BarrettField>(
                shares_needed,
                num_shares,
                modulus,
                secret,
            ));
            prop_assert!(malformed_rejections::<MontgomeryField>(
                shares_needed,
                num_shares,
                modulus,
                secret,
            ));
        }
    }

    #[test]
    fn every_three_party_subset_reconstructs() {
        let scheme = ShamirScheme::<BarrettField>::new(3, 6, 1613).unwrap();
        let mut rng = ChaCha20Rng::from_seed([31; 32]);
        let shares = scheme.share(987, &mut rng).unwrap();
        for first in 1..=4 {
            for second in (first + 1)..=5 {
                for third in (second + 1)..=6 {
                    let pairs = [first, second, third]
                        .into_iter()
                        .map(|party| (party, *shares.get(party - 1).unwrap()))
                        .collect::<Vec<_>>();
                    assert_eq!(scheme.reconstruct(&pairs), Ok(987));
                }
            }
        }
    }
}
