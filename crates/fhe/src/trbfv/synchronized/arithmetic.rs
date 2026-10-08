//! Local validation and public interpolation weights for synchronized decryption.

use crate::Error;
use fhe_math::zq::Modulus;
use ndarray::{Array2, ArrayView2};
use zeroize::Zeroize;

pub(super) fn validate_decryptors(ids: &[usize], n: usize, threshold: usize) -> Result<(), Error> {
    if ids.len() != threshold + 1 {
        return Err(Error::share_count_mismatch(ids.len(), threshold + 1));
    }
    for (index, &id) in ids.iter().enumerate() {
        if id == 0 || id > n {
            return Err(Error::invalid_party_id(id, n));
        }
        if ids.iter().take(index).any(|&other| other == id) {
            return Err(Error::duplicate_party_id(id));
        }
    }
    Ok(())
}

pub(super) fn validate_matrix(
    matrix: ArrayView2<'_, u64>,
    moduli: &[u64],
    degree: usize,
    party_id: usize,
) -> Result<(), Error> {
    if matrix.dim() != (moduli.len(), degree) {
        return Err(Error::malformed_shares(
            party_id,
            format!(
                "polynomial has shape {:?}, expected ({}, {degree})",
                matrix.dim(),
                moduli.len()
            ),
        ));
    }
    for (row, (values, &modulus)) in matrix.outer_iter().zip(moduli).enumerate() {
        if values.as_slice().is_none() {
            return Err(fhe_math::Error::NonContiguousCoefficients.into());
        }
        if let Some(column) = values.iter().position(|&value| value >= modulus) {
            return Err(Error::malformed_shares(
                party_id,
                format!("noncanonical coefficient at row {row}, column {column}"),
            ));
        }
    }
    Ok(())
}

/// Weight at zero of `party_id` in an already validated designated set.
pub(super) fn lagrange_weight(
    modulus: &Modulus,
    ids: &[usize],
    party_id: usize,
) -> Result<u64, Error> {
    let x = u64::try_from(party_id).map_err(|_| Error::non_invertible_shares())?;
    let mut numerator = 1;
    let mut denominator = 1;
    for &other in ids {
        if other != party_id {
            let y = u64::try_from(other).map_err(|_| Error::non_invertible_shares())?;
            numerator = modulus.mul(numerator, modulus.neg(y));
            denominator = modulus.mul(denominator, modulus.sub(x, y));
        }
    }
    // The constructor checks n < min(q_i), and BFV contexts use prime moduli.
    if denominator == 0 {
        return Err(Error::non_invertible_shares());
    }
    Ok(modulus.mul(numerator, modulus.pow(denominator, **modulus - 2)))
}

/// Guard temporary secret coefficients until they move into a guarded polynomial.
pub(super) struct SecretMatrix(pub(super) Array2<u64>);

impl Drop for SecretMatrix {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(Zeroize::zeroize);
    }
}
