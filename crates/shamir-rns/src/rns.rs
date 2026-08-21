//! Thin ordered RNS composition of independent prime-field Shamir instances.

use core::fmt;
use std::collections::HashSet;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{BarrettField, Error, Field, ShamirScheme, ShareMatrix};

/// Ordered independent Shamir schemes for an RNS basis.
///
/// Each modulus owns a separate prime-field sharing scheme. This type never
/// performs arithmetic modulo the composite product of the basis. Inputs and
/// outputs are residue vectors in the original modulus order.
#[derive(Clone)]
pub struct RnsShamir<F: Field = BarrettField> {
    schemes: Vec<ShamirScheme<F>>,
}

impl<F: Field> fmt::Debug for RnsShamir<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RnsShamir")
            .field("moduli", &self.moduli())
            .field("shares_needed", &self.shares_needed())
            .field("num_shares", &self.num_shares())
            .finish()
    }
}

impl<F: Field> RnsShamir<F> {
    /// Construct one independent field scheme per ordered RNS modulus.
    ///
    /// # Errors
    /// Returns a field or threshold validation error. An empty basis is
    /// rejected because an RNS value must have at least one residue.
    pub fn new(shares_needed: usize, num_shares: usize, moduli: &[u64]) -> Result<Self, Error> {
        if moduli.is_empty() {
            return Err(Error::InvalidMatrixStorage);
        }
        let schemes = moduli
            .iter()
            .copied()
            .map(|modulus| ShamirScheme::<F>::new(shares_needed, num_shares, modulus))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { schemes })
    }

    /// Return the ordered RNS basis.
    #[must_use]
    pub fn moduli(&self) -> Vec<u64> {
        self.schemes.iter().map(ShamirScheme::modulus).collect()
    }

    /// Return the number of independent basis moduli.
    #[must_use]
    pub fn num_moduli(&self) -> usize {
        self.schemes.len()
    }

    /// Return the exact reconstruction count.
    #[must_use]
    pub fn shares_needed(&self) -> usize {
        self.schemes.first().map_or(0, ShamirScheme::shares_needed)
    }

    /// Return the configured party count.
    #[must_use]
    pub fn num_shares(&self) -> usize {
        self.schemes.first().map_or(0, ShamirScheme::num_shares)
    }

    /// Share one RNS value, returning one party-ordered share vector per modulus.
    pub fn share<R: RngCore + CryptoRng>(
        &self,
        residues: &[u64],
        rng: &mut R,
    ) -> Result<Vec<Vec<u64>>, Error> {
        if residues.len() != self.num_moduli() {
            return Err(Error::InvalidMatrixShape {
                expected_rows: self.num_moduli(),
                expected_columns: 1,
                actual_rows: residues.len(),
                actual_columns: 1,
            });
        }
        let mut protected = Vec::with_capacity(self.num_moduli());
        for (scheme, residue) in self.schemes.iter().zip(residues.iter().copied()) {
            protected.push(Zeroizing::new(scheme.share(residue, rng)?));
        }
        let mut result = Vec::with_capacity(protected.len());
        for mut shares in protected {
            result.push(std::mem::take(&mut *shares));
        }
        Ok(result)
    }

    /// Share a batch of RNS values.
    ///
    /// `residues` is modulus-major: each inner vector contains the secrets in
    /// original column order for one basis modulus. The result has one
    /// party-major [`ShareMatrix`] per modulus in the same order.
    pub fn share_batch<R: RngCore + CryptoRng>(
        &self,
        residues: &[Vec<u64>],
        rng: &mut R,
    ) -> Result<Vec<ShareMatrix>, Error> {
        if residues.len() != self.num_moduli() {
            return Err(Error::InvalidMatrixShape {
                expected_rows: self.num_moduli(),
                expected_columns: 0,
                actual_rows: residues.len(),
                actual_columns: residues.first().map_or(0, Vec::len),
            });
        }
        let columns = residues.first().map_or(0, Vec::len);
        if residues.iter().any(|values| values.len() != columns) {
            let actual_columns = residues
                .iter()
                .find_map(|values| (values.len() != columns).then_some(values.len()))
                .unwrap_or(columns);
            return Err(Error::InvalidMatrixShape {
                expected_rows: self.num_moduli(),
                expected_columns: columns,
                actual_rows: residues.len(),
                actual_columns,
            });
        }
        self.schemes
            .iter()
            .zip(residues.iter())
            .map(|(scheme, values)| scheme.share_batch(values, rng))
            .collect()
    }

    /// Reconstruct one RNS value from one party/value set per modulus.
    pub fn reconstruct(&self, shares: &[Vec<(usize, u64)>]) -> Result<Vec<u64>, Error> {
        if shares.len() != self.num_moduli() {
            return Err(Error::InvalidMatrixShape {
                expected_rows: self.num_moduli(),
                expected_columns: self.shares_needed(),
                actual_rows: shares.len(),
                actual_columns: shares.first().map_or(0, Vec::len),
            });
        }
        let mut protected = Vec::with_capacity(self.num_moduli());
        for (scheme, values) in self.schemes.iter().zip(shares.iter()) {
            protected.push(Zeroizing::new(scheme.reconstruct(values)?));
        }
        let mut result = Vec::with_capacity(protected.len());
        for mut secret in protected {
            result.push(std::mem::take(&mut *secret));
        }
        Ok(result)
    }

    /// Reconstruct a batch of RNS values from one selected party matrix per
    /// modulus. Results are secret-major: each inner vector is an ordered RNS
    /// residue vector for one original input column.
    pub fn reconstruct_batch(
        &self,
        shares: &[ShareMatrix],
        party_ids: &[usize],
    ) -> Result<Vec<Vec<u64>>, Error> {
        if shares.len() != self.num_moduli() {
            return Err(Error::InvalidMatrixShape {
                expected_rows: self.num_moduli(),
                expected_columns: self.shares_needed(),
                actual_rows: shares.len(),
                actual_columns: shares.first().map_or(0, ShareMatrix::columns),
            });
        }
        let columns = shares.first().map_or(0, ShareMatrix::columns);
        if party_ids.len() != self.shares_needed() {
            return Err(Error::WrongShareCount {
                expected: self.shares_needed(),
                actual: party_ids.len(),
            });
        }
        let mut seen = HashSet::with_capacity(party_ids.len());
        for party_id in party_ids {
            if *party_id == 0 || *party_id > self.num_shares() {
                return Err(Error::InvalidPartyId {
                    party_id: *party_id,
                });
            }
            if !seen.insert(*party_id) {
                return Err(Error::DuplicatePartyId {
                    party_id: *party_id,
                });
            }
        }
        for (scheme, matrix) in self.schemes.iter().zip(shares.iter()) {
            if matrix.rows() != self.shares_needed() || matrix.columns() != columns {
                return Err(Error::InvalidMatrixShape {
                    expected_rows: self.shares_needed(),
                    expected_columns: columns,
                    actual_rows: matrix.rows(),
                    actual_columns: matrix.columns(),
                });
            }
            if let Some(&value) = matrix
                .as_slice()
                .iter()
                .find(|value| **value >= scheme.modulus())
            {
                return Err(Error::NonCanonicalShare {
                    value,
                    modulus: scheme.modulus(),
                });
            }
        }
        let per_modulus = self
            .schemes
            .iter()
            .zip(shares.iter())
            .map(|(scheme, matrix)| scheme.reconstruct_batch(matrix, party_ids))
            .map(|result| result.map(Zeroizing::new))
            .collect::<Result<Vec<_>, _>>()?;
        let mut result = Zeroizing::new(
            (0..columns)
                .map(|_| Vec::with_capacity(self.num_moduli()))
                .collect::<Vec<_>>(),
        );
        for residues in per_modulus {
            if residues.len() != columns {
                return Err(Error::InvalidMatrixStorage);
            }
            for (output, residue) in result.iter_mut().zip(residues.iter()) {
                output.push(*residue);
            }
        }
        Ok(std::mem::take(&mut *result))
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::RnsShamir;
    use crate::{BarrettField, Field, MontgomeryField};

    fn crt(residues: &[u64], moduli: &[u64]) -> BigUint {
        let product = moduli
            .iter()
            .fold(BigUint::from(1_u64), |acc, modulus| acc * modulus);
        let mut result = BigUint::from(0_u64);
        for (residue, modulus) in residues.iter().zip(moduli) {
            let partial = &product / modulus;
            let exponent = BigUint::from(modulus - 2);
            let inverse = partial.modpow(&exponent, &BigUint::from(*modulus));
            result += BigUint::from(*residue) * partial * inverse;
        }
        result % product
    }

    #[test]
    fn rns_batch_roundtrip_matches_crt_oracle() {
        let moduli = [1613_u64, 2017_u64];
        let wrapper = RnsShamir::<BarrettField>::new(3, 5, &moduli).unwrap();
        let value = BigUint::from(2_000_000_u64);
        let residues = moduli
            .iter()
            .map(|modulus| {
                (&value % modulus)
                    .to_u64_digits()
                    .first()
                    .copied()
                    .unwrap_or(0)
            })
            .collect::<Vec<_>>();
        assert_eq!(crt(&residues, &moduli), value);

        let second_residue = residues.iter().copied().nth(1).unwrap_or(0);
        let batch_input = vec![residues.clone(), vec![second_residue, 2]];
        let mut rng = ChaCha20Rng::from_seed([44; 32]);
        let matrices = wrapper.share_batch(&batch_input, &mut rng).unwrap();
        let selected = matrices
            .iter()
            .map(|matrix| {
                let values = [0_usize, 2, 4]
                    .into_iter()
                    .flat_map(|row| matrix.row(row).unwrap().iter().copied())
                    .collect::<Vec<_>>();
                crate::ShareMatrix::new(3, 2, values).unwrap()
            })
            .collect::<Vec<_>>();
        let recovered = wrapper.reconstruct_batch(&selected, &[1, 3, 5]).unwrap();
        let first_residue = residues.iter().copied().next().unwrap_or(0);
        assert_eq!(
            recovered,
            vec![vec![first_residue, second_residue], vec![second_residue, 2]]
        );
        assert_eq!(crt(recovered.first().unwrap(), &moduli), value);
    }

    #[test]
    fn rns_rejects_wrong_basis_shape() {
        let wrapper = RnsShamir::<BarrettField>::new(2, 3, &[1613, 2017]).unwrap();
        let mut rng = ChaCha20Rng::from_seed([45; 32]);
        assert!(wrapper.share(&[1], &mut rng).is_err());
        assert!(wrapper.share_batch(&[vec![1]], &mut rng).is_err());
    }

    fn check_batch_boundaries<F: Field>() {
        let wrapper = RnsShamir::<F>::new(2, 4, &[1613, 2017]).unwrap();
        let mut rng = ChaCha20Rng::from_seed([46; 32]);
        let matrices = wrapper
            .share_batch(&[Vec::new(), Vec::new()], &mut rng)
            .unwrap();
        assert_eq!(matrices.len(), 2);
        assert!(matrices.iter().all(|matrix| matrix.rows() == 4));
        assert!(matrices.iter().all(|matrix| matrix.columns() == 0));
        let selected = matrices
            .iter()
            .map(|_| crate::ShareMatrix::new(2, 0, Vec::new()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            wrapper.reconstruct_batch(&selected, &[1, 4]).unwrap(),
            Vec::<Vec<u64>>::new()
        );

        let malformed = vec![
            crate::ShareMatrix::new(1, 0, Vec::new()).unwrap(),
            crate::ShareMatrix::new(2, 0, Vec::new()).unwrap(),
        ];
        assert!(wrapper.reconstruct_batch(&malformed, &[1, 2]).is_err());
    }

    #[test]
    fn rns_batch_boundaries_cover_both_backends() {
        check_batch_boundaries::<BarrettField>();
        check_batch_boundaries::<MontgomeryField>();
    }
}
