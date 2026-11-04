//! Internal guards for temporary secret RNS coefficients.

use ndarray::Array2;
use zeroize::Zeroize;

/// Keep secret coefficients guarded until they move into a guarded polynomial.
pub(super) struct SecretMatrix(pub(super) Array2<u64>);

impl Zeroize for SecretMatrix {
    fn zeroize(&mut self) {
        self.0.iter_mut().for_each(Zeroize::zeroize);
    }
}

impl Drop for SecretMatrix {
    fn drop(&mut self) {
        let (mut storage, _) = std::mem::take(&mut self.0).into_raw_vec_and_offset();
        storage.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroizes_standard_and_strided_matrix_values() {
        for matrix in [
            Array2::from_elem((3, 8), 42),
            Array2::from_elem((8, 3), 43).reversed_axes(),
        ] {
            let mut secret = SecretMatrix(matrix);
            secret.zeroize();
            assert_eq!(secret.0.dim(), (3, 8));
            assert!(secret.0.iter().all(|&value| value == 0));
        }
    }
}
