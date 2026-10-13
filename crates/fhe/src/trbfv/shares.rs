//! Shamir key sharing, polynomial conversion, and share aggregation.

use crate::Error;
use crate::bfv::BfvParameters;
use crate::trbfv::config::validate_sharing_parameters;
use crate::trbfv::shamir::ShamirSecretSharing;
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::rq::{Context, Poly, PowerBasis};
use fhe_math::zq::Modulus;
use ndarray::Array2;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::convert::TryFrom;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Manager for threshold BFV key-share operations.
///
/// # Threshold semantics
///
/// `threshold` is the degree `T` of the Shamir sharing polynomial, read as the
/// maximum number of corrupted parties the deployment tolerates. Reconstruction
/// requires `T + 1` shares. Configuration requires `n >= 3` and
/// `T = (n - 1) / 2` (see [`validate_threshold_config`](super::config::validate_threshold_config)).
///
/// Each party deals its key contribution, exchanges shares through secure
/// channels, and aggregates the received matrices into its share of the joint
/// secret. Keep the NTT conversion in a zeroizing owner for decryption.
#[derive(Debug)]
pub struct ShareManager {
    /// Number of parties in the threshold scheme (must be `>= 3`)
    pub n: usize,
    /// Degree `T` of the Shamir sharing polynomial, i.e. the maximum number of
    /// corrupted parties the deployment tolerates (must equal `(n - 1) / 2`).
    /// Reconstruction requires `T + 1` shares.
    pub threshold: usize,
    /// BFV parameters (degree, moduli, etc.)
    pub params: Arc<BfvParameters>,
}

impl ShareManager {
    /// Create a new share manager.
    ///
    /// # Arguments
    /// - `n`: Total number of parties (must be `>= 3`)
    /// - `threshold`: Degree `T` of the Shamir sharing polynomial, i.e. the
    ///   maximum number of corrupted parties the deployment tolerates. Must
    ///   equal `(n - 1) / 2`; reconstruction requires `T + 1` shares.
    /// - `params`: BFV parameters
    ///
    /// # Errors
    /// Returns an error if `n < 3` or `threshold != (n - 1) / 2` (a degree-0
    /// sharing polynomial would reveal the secret to every party), if the
    /// parameters have no moduli, or if `n` is not smaller than the smallest
    /// modulus (the MPC protocol assumes the Shamir evaluation points `1..=n`
    /// are distinct units modulo every modulus).
    pub fn new(n: usize, threshold: usize, params: Arc<BfvParameters>) -> Result<Self, Error> {
        validate_sharing_parameters(n, threshold, &params)?;
        Ok(Self {
            n,
            threshold,
            params,
        })
    }

    /// Create a `Zeroizing<Poly>` from coefficients.
    ///
    /// # Arguments
    /// - `coeffs`: Coefficients convertible to `Poly`, such as `&[i64]` or `Array2<u64>`.
    /// - `ctx`: BFV context to use for the polynomial
    ///
    /// # Returns
    /// A `Zeroizing<Poly>` in `PowerBasis` representation
    pub fn coeffs_to_poly<T>(
        &self,
        coeffs: T,
        ctx: &Arc<Context>,
    ) -> Result<Zeroizing<Poly<PowerBasis>>, Error>
    where
        Poly<PowerBasis>: TryConvertFrom<T>,
    {
        let poly = Poly::<PowerBasis>::try_convert_from(coeffs, ctx, false)?;
        Ok(Zeroizing::new(poly))
    }

    /// Convenience method using level 0 context from parameters.
    pub fn coeffs_to_poly_level0<T>(&self, coeffs: T) -> Result<Zeroizing<Poly<PowerBasis>>, Error>
    where
        Poly<PowerBasis>: TryConvertFrom<T>,
    {
        let ctx = self.params.context_at_level(0)?;
        self.coeffs_to_poly(coeffs, ctx)
    }
    /// Convert a vector of BigInt coefficients into a Poly in full RNS representation
    /// at level 0 using the BFV context.
    pub fn bigints_to_poly(
        &self,
        bigints: &[BigInt],
    ) -> Result<Zeroizing<Poly<PowerBasis>>, Error> {
        let ctx = self.params.context_at_level(0)?;
        Poly::<PowerBasis>::from_bigints(bigints, ctx).map_err(Error::from)
    }

    /// Generate Shamir Secret Shares for polynomial coefficients from a pre-converted Poly.
    // seeds[i] is indexed for i in 0..moduli.len(), which equals seeds.len()
    #[allow(clippy::indexing_slicing)]
    pub fn generate_secret_shares_from_poly<R: RngCore + CryptoRng>(
        &mut self,
        poly: Zeroizing<Poly<PowerBasis>>,
        rng: &mut R,
    ) -> Result<Vec<Array2<u64>>, Error> {
        let moduli: Vec<u64> = poly.ctx().moduli().to_vec();

        let min_modulus = moduli.iter().min().ok_or(fhe_math::Error::EmptyModuli)?;

        if self.n >= usize::try_from(*min_modulus).unwrap_or(usize::MAX) {
            return Err(Error::party_count_exceeds_modulus(self.n, *min_modulus));
        }

        let coefficients = poly.coefficients();
        let coeff_rows: Vec<_> = coefficients.outer_iter().collect();

        // Generate seeds deterministically from the input RNG
        let seeds: Vec<[u8; 32]> = (0..moduli.len())
            .map(|_| crate::trbfv::shamir::fork_seed(rng))
            .collect();

        let return_vec: Result<Vec<Array2<u64>>, Error> = moduli
            .par_iter()
            .zip(coeff_rows.par_iter())
            .enumerate()
            .map(|(i, (m, p))| -> Result<Array2<u64>, Error> {
                // Get rng from seed
                let mut rng = ChaCha20Rng::from_seed(seeds[i]);

                // Create shamir object
                let shamir = ShamirSecretSharing {
                    threshold: self.threshold,
                    share_amount: self.n,
                    prime: BigInt::from(*m),
                };

                let mut m_data: Vec<u64> = Vec::new();

                // For each coeff in the polynomial p under the current modulus m
                for c in p.iter() {
                    // Split the coeff into n shares (u64 -> BigInt is infallible)
                    let secret = BigInt::from(*c);

                    let c_shares = shamir.split(secret, &mut rng)?;

                    // For each share convert to u64; shares are reduced modulo
                    // the (u64) prime, so this only fails on malformed input
                    let mut c_vec: Vec<u64> = Vec::with_capacity(self.n);
                    for (_, c_share) in c_shares.iter() {
                        c_vec.push(c_share.to_u64().ok_or_else(|| {
                            Error::malformed_shares(
                                0,
                                "Shamir share does not fit in u64".to_string(),
                            )
                        })?);
                    }
                    m_data.extend_from_slice(&c_vec);
                }

                // convert flat vector of coeffs to array2
                let arr_matrix = Array2::from_shape_vec((self.params.degree(), self.n), m_data)
                    .map_err(|_| {
                        Error::malformed_shares(
                            0,
                            "Failed to create coefficient matrix".to_string(),
                        )
                    })?;
                // reverse the columns and rows
                let reversed_axes = arr_matrix.t();
                Ok(reversed_axes.to_owned())
            })
            .collect();

        return_vec
    }

    /// Aggregate collected secret sharing shares to compute SK_i polynomial sum.
    ///
    /// This function takes shares collected from other parties and aggregates them
    /// to compute this party's share of the joint secret (the sum of the dealt
    /// secrets) needed for decryption.
    ///
    /// # Input invariant
    ///
    /// Every entry of every contribution matrix must be a canonical residue in
    /// `[0, q_i)`, where `q_i` is the modulus of the entry's row. Shares produced
    /// by [`ShareManager::generate_secret_shares_from_poly`] already satisfy this
    /// invariant, but aggregation re-checks it because it is an input boundary for
    /// externally supplied matrices. Out-of-range entries are treated as malformed
    /// and rejected with `Error::Threshold(ThresholdError::MalformedShares { .. })`;
    /// they are never reduced or otherwise repaired.
    ///
    /// # Arguments
    /// - `sk_sss_collected`: One share matrix per contributing party (at most `n`;
    ///   fewer is allowed, e.g. when some parties aborted during dealing).
    ///   Each `Array2<u64>` has one row per modulus and one column per coefficient.
    ///
    /// # Returns
    /// A polynomial representing the aggregated secret key material
    ///
    /// # Errors
    /// Returns an error if no shares are provided, if more than `n` matrices are
    /// provided, if any matrix does not have shape `[moduli, degree]`, or if any
    /// coefficient is not a canonical residue below its row's modulus (`>= q_i` is
    /// malformed, never reduced).
    pub fn aggregate_collected_shares(
        &self,
        sk_sss_collected: &[Array2<u64>], // collected sk sss shares from other parties
    ) -> Result<Poly<PowerBasis>, Error> {
        if sk_sss_collected.is_empty() {
            return Err(Error::share_count_mismatch(0, 1));
        }
        if sk_sss_collected.len() > self.n {
            return Err(Error::share_count_mismatch(sk_sss_collected.len(), self.n));
        }
        let expected_shape = (self.params.moduli().len(), self.params.degree());
        for (party_idx, item) in sk_sss_collected.iter().enumerate() {
            if item.dim() != expected_shape {
                return Err(Error::malformed_shares(
                    party_idx,
                    format!(
                        "share matrix has shape {:?}, expected {expected_shape:?}",
                        item.dim()
                    ),
                ));
            }
        }
        let ctx = self.params.context_at_level(0)?;

        // Every coefficient of every contribution must be a canonical residue
        // below its own row's modulus `q_i` before anything is accumulated:
        // Modulus::add_vec below requires canonical inputs (it aborts or wraps
        // otherwise). Reducing here would silently accept malformed share
        // material and could change the represented share, so values `>= q_i`
        // are rejected instead. Shape was validated above, so the fallible
        // `moduli().get(row)` lookup is expected to succeed, but in keeping with
        // the workspace convention it stays fallible rather than indexed.
        for (party_idx, item) in sk_sss_collected.iter().enumerate() {
            for (row, item_row) in item.rows().into_iter().enumerate() {
                let q_i =
                    self.params.moduli().get(row).copied().ok_or_else(|| {
                        Error::DefaultError("modulus index out of range".to_string())
                    })?;
                for (col, &value) in item_row.iter().enumerate() {
                    if value >= q_i {
                        return Err(Error::malformed_shares(
                            party_idx,
                            format!(
                                "share coefficient at row {row} (modulus q_i = {q_i}), column \
                                 {col} is {value}; expected a canonical residue in [0, {q_i})"
                            ),
                        ));
                    }
                }
            }
        }

        // Sum the share matrices row-wise modulo each RNS modulus, copying
        // only once into the result polynomial (instead of cloning each
        // contribution into its own Poly and adding those).
        let mut sum = Array2::<u64>::zeros(expected_shape);
        for (row, mut acc_row) in sum.outer_iter_mut().enumerate() {
            let &modulus = self.params.moduli().get(row).ok_or_else(|| {
                Error::malformed_shares(row, "modulus index out of range".to_string())
            })?;
            let q = Modulus::new(modulus).map_err(Error::MathError)?;
            let acc = acc_row
                .as_slice_mut()
                .ok_or(fhe_math::Error::NonContiguousCoefficients)?;
            for item in sk_sss_collected {
                let item_row = item.row(row);
                let share = item_row
                    .as_slice()
                    .ok_or(fhe_math::Error::NonContiguousCoefficients)?;
                q.add_vec(acc, share);
            }
        }

        let mut sum_poly = Poly::<PowerBasis>::zero(ctx);
        sum_poly.set_coefficients(sum);
        Ok(sum_poly)
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::ThresholdError;
    use crate::bfv::BfvParametersBuilder;

    fn test_params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(4096)
            .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
            .build_arc()
            .unwrap()
    }

    #[test]
    fn distributed_key_shares_reconstruct_the_aggregate_for_arbitrary_parties() {
        use rand::SeedableRng;
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(17)
            .set_moduli(&[97, 193])
            .build_arc()
            .unwrap();
        let mut manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(285);
        let dealt: Vec<_> = (1..=5i64)
            .map(|value| {
                let coefficients = vec![value; params.degree()];
                let poly = manager
                    .coeffs_to_poly_level0(coefficients.as_slice())
                    .unwrap();
                let shares = manager
                    .generate_secret_shares_from_poly(poly, &mut rng)
                    .unwrap();
                for (row, matrix) in shares.iter().enumerate() {
                    assert_eq!(matrix.dim(), (5, params.degree()));
                    assert!(
                        matrix
                            .iter()
                            .all(|&coefficient| coefficient < params.moduli()[row])
                    );
                }
                shares
            })
            .collect();
        let ids = [5, 2, 4];
        let aggregates: Vec<_> = ids
            .iter()
            .map(|&id| {
                let matrices: Vec<_> = dealt
                    .iter()
                    .map(|sender| {
                        Array2::from_shape_fn(
                            (params.moduli().len(), params.degree()),
                            |(row, column)| sender[row][[id - 1, column]],
                        )
                    })
                    .collect();
                manager.aggregate_collected_shares(&matrices).unwrap()
            })
            .collect();
        for (row, &q) in params.moduli().iter().enumerate() {
            let shamir = ShamirSecretSharing::new(2, 5, BigInt::from(q));
            for column in 0..params.degree() {
                let shares: Vec<_> = ids
                    .iter()
                    .zip(&aggregates)
                    .map(|(&id, poly)| (id, BigInt::from(poly.coefficients()[[row, column]])))
                    .collect();
                assert_eq!(shamir.recover(&shares).unwrap(), BigInt::from(15));
            }
        }
    }

    #[test]
    fn test_share_manager_creation() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        assert_eq!(manager.n, 5);
        assert_eq!(manager.threshold, 2);
        assert_eq!(manager.params, params);
    }

    #[test]
    fn test_share_manager_rejects_threshold_zero() {
        // A degree-0 Shamir sharing polynomial is the secret itself, so every
        // party would hold the full secret.
        let params = test_params();
        let err = ShareManager::new(5, 0, params)
            .expect_err("threshold 0 must be rejected (degree-0 sharing reveals the secret)");
        assert!(matches!(
            err,
            Error::Threshold(ThresholdError::InvalidThreshold {
                threshold: 0,
                n: 5,
                expected: 2
            })
        ));
    }

    #[test]
    fn test_share_manager_rejects_invalid_threshold_config() {
        let params = test_params();

        for (n, threshold) in [(0usize, 1usize), (1, 0), (1, 1), (2, 0), (2, 1)] {
            assert!(
                ShareManager::new(n, threshold, params.clone()).is_err(),
                "ShareManager::new({n}, {threshold}) must be rejected"
            );
        }

        for n in [3usize, 5, 20] {
            assert!(
                ShareManager::new(n, 0, params.clone()).is_err(),
                "ShareManager::new({n}, 0) must be rejected"
            );
        }

        for (n, threshold) in [(5usize, 3usize), (5, 4), (5, 5), (5, 6), (3, 2)] {
            assert!(
                ShareManager::new(n, threshold, params.clone()).is_err(),
                "ShareManager::new({n}, {threshold}) must be rejected"
            );
        }

        for (n, threshold) in [(20usize, 8usize), (20, 7), (10, 3)] {
            assert!(
                ShareManager::new(n, threshold, params.clone()).is_err(),
                "ShareManager::new({n}, {threshold}) must be rejected"
            );
        }

        assert!(ShareManager::new(20, 10, params.clone()).is_err());
        assert!(ShareManager::new(4, 2, params.clone()).is_err());
    }

    #[test]
    fn test_share_manager_accepts_valid_threshold_config() {
        let params = test_params();
        for (n, threshold) in [(3usize, 1usize), (4, 1), (5, 2), (10, 4), (20, 9), (21, 10)] {
            let manager = ShareManager::new(n, threshold, params.clone())
                .expect("a valid threshold config must be accepted");
            assert_eq!(manager.n, n);
            assert_eq!(manager.threshold, threshold);
        }
    }

    #[test]
    fn test_coeffs_to_poly_utility() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();

        // Test with i64 coefficients
        let coeffs = vec![1i64, 2, 3, 4].into_boxed_slice();
        let ctx = params.context_at_level(0).unwrap();
        let poly = manager.coeffs_to_poly(coeffs.as_ref(), ctx).unwrap();
        assert_eq!(poly.ctx(), ctx);

        // Test convenience method
        let coeffs2 = vec![5i64, 6, 7, 8].into_boxed_slice();
        let poly2 = manager.coeffs_to_poly_level0(coeffs2.as_ref()).unwrap();
        assert_eq!(poly2.ctx(), ctx);
    }

    #[test]
    fn test_bigints_to_poly() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();

        // Create BigInt coefficients (full degree)
        let degree = params.degree();
        let bigints: Vec<BigInt> = (0..degree).map(|i| BigInt::from(i as i64)).collect();

        let poly = manager.bigints_to_poly(&bigints).unwrap();
        assert_eq!(poly.coefficients().ncols(), degree);
        assert_eq!(poly.coefficients().nrows(), params.moduli().len());
    }

    #[test]
    fn test_bigints_to_poly_wrong_size() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();

        // Wrong number of coefficients
        let bigints = vec![BigInt::from(1), BigInt::from(2)]; // Too few
        let result = manager.bigints_to_poly(&bigints);
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_collected_shares_rejects_bad_input() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let shape = (params.moduli().len(), params.degree());

        // Empty input
        assert!(manager.aggregate_collected_shares(&[]).is_err());

        // More matrices than parties
        let matrices: Vec<Array2<u64>> = (0..6).map(|_| Array2::zeros(shape)).collect();
        assert!(manager.aggregate_collected_shares(&matrices).is_err());

        // Wrong shape (rows and columns swapped)
        let bad = vec![Array2::zeros((params.degree(), params.moduli().len()))];
        assert!(manager.aggregate_collected_shares(&bad).is_err());

        // Valid: between 1 and n well-formed matrices
        let ok: Vec<Array2<u64>> = (0..3).map(|_| Array2::zeros(shape)).collect();
        assert!(manager.aggregate_collected_shares(&ok).is_ok());
    }

    #[test]
    fn test_aggregate_collected_shares_rejects_non_canonical_q_at_each_row() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());

        // A coefficient equal to its row's modulus q_i is not a canonical
        // residue and must be rejected against that row's own modulus, not a
        // global bound shared across rows.
        for (row, &q_i) in moduli.iter().enumerate() {
            let mut shares = Array2::zeros(shape);
            shares[[row, 3]] = q_i;
            let err = manager
                .aggregate_collected_shares(std::slice::from_ref(&shares))
                .expect_err("coefficient equal to the row modulus must be rejected");
            let Error::Threshold(ThresholdError::MalformedShares { party_id, reason }) = &err
            else {
                panic!("expected MalformedShares, got: {err}");
            };
            assert_eq!(*party_id, 0, "contribution index must be reported");
            assert!(
                reason.contains(&format!("row {row}")),
                "row index missing from reason: {reason}"
            );
            assert!(
                reason.contains("column 3"),
                "column index missing from reason: {reason}"
            );
            assert!(
                reason.contains(&q_i.to_string()),
                "expected row modulus (and offending value) missing from reason: {reason}"
            );
        }
    }

    #[test]
    fn test_aggregate_collected_shares_rejects_u64_max() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());

        // u64::MAX would wrap to a small residue if reduced; it must be
        // rejected as malformed instead of being reduced.
        let mut shares = Array2::zeros(shape);
        shares[[0, 0]] = u64::MAX;
        let err = manager
            .aggregate_collected_shares(std::slice::from_ref(&shares))
            .expect_err("u64::MAX share entry must be rejected");
        let Error::Threshold(ThresholdError::MalformedShares { party_id, reason }) = &err else {
            panic!("expected MalformedShares, got: {err}");
        };
        assert_eq!(*party_id, 0);
        assert!(
            reason.contains(&u64::MAX.to_string()),
            "offending value missing from reason: {reason}"
        );
    }

    #[test]
    fn test_aggregate_collected_shares_accepts_q_minus_one_boundary() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());

        // q_i - 1 is the largest valid canonical residue for each row; all
        // rows must be accepted against their own distinct moduli.
        let mut shares = Array2::zeros(shape);
        for (row, &q_i) in moduli.iter().enumerate() {
            shares.row_mut(row).fill(q_i - 1);
        }
        let result = manager
            .aggregate_collected_shares(std::slice::from_ref(&shares))
            .expect("maximal canonical residues must be accepted");

        // A single aggregate preserves the input values exactly (the sum of a
        // single matrix is the matrix itself) and the accumulator does not
        // reduce them beyond the canonical residues supplied.
        assert_eq!(result.coefficients().into_owned(), shares);
    }

    #[test]
    fn test_aggregate_collected_shares_rejects_invalid_after_valid() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let moduli = params.moduli().to_vec();
        let shape = (moduli.len(), params.degree());
        let q1 = moduli[1];

        // A valid first contribution followed by a malformed later one must
        // still surface the later contribution's error rather than reaching
        // Modulus::add_vec with the bad entry.
        let valid = Array2::zeros(shape);
        let mut invalid = Array2::zeros(shape);
        invalid[[1, 5]] = q1;
        let err = manager
            .aggregate_collected_shares(&[valid, invalid])
            .expect_err("out-of-range entry in a later contribution must be rejected");
        let Error::Threshold(ThresholdError::MalformedShares { party_id, reason }) = &err else {
            panic!("expected MalformedShares, got: {err}");
        };
        assert_eq!(*party_id, 1, "the invalid contribution must be identified");
        assert!(
            reason.contains("row 1") && reason.contains("column 5"),
            "row/column context missing from reason: {reason}"
        );
    }
}
