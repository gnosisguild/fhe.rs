//! Common parameter and ciphertext validation for threshold BFV.

use crate::Error;
use crate::bfv::{BfvParameters, Ciphertext};
use ndarray::ArrayView2;
use std::sync::Arc;

/// Validated configuration for synchronized, pairwise-PRF decryption.
///
/// Noise/circuit assumptions remain configured through
/// [`super::SmudgingBoundCalculatorConfig`].
#[cfg(feature = "synchronized-decryption")]
#[derive(Debug, Clone)]
pub struct SynchronizedDecryptionConfig {
    n: usize,
    threshold: usize,
    params: Arc<BfvParameters>,
}

#[cfg(feature = "synchronized-decryption")]
impl SynchronizedDecryptionConfig {
    /// Validate the same parameters as [`super::SynchronizedDecryptor::new`].
    pub fn new(n: usize, threshold: usize, params: Arc<BfvParameters>) -> Result<Self, Error> {
        validate_sharing_parameters(n, threshold, &params)?;
        plaintext_modulus(&params)?;
        Ok(Self {
            n,
            threshold,
            params,
        })
    }

    /// Total committee size.
    #[must_use]
    pub fn committee_size(&self) -> usize {
        self.n
    }

    /// Shamir polynomial degree; reconstruction needs one more share.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Underlying BFV parameters.
    #[must_use]
    pub fn params(&self) -> &Arc<BfvParameters> {
        &self.params
    }
}

/// Validated configuration for the SS smudging protocol.
///
/// This is deliberately distinct from the synchronized configuration. It uses
/// the common Shamir sharing validation, without the synchronized constructor's
/// additional early plaintext-modulus check. Noise/circuit assumptions belong
/// to [`super::SmudgingBoundCalculatorConfig`].
#[derive(Debug, Clone)]
pub struct SsSmudgingDecryptionConfig {
    n: usize,
    threshold: usize,
    params: Arc<BfvParameters>,
}

impl SsSmudgingDecryptionConfig {
    /// Validate the same parameters as the Shamir share manager.
    pub fn new(n: usize, threshold: usize, params: Arc<BfvParameters>) -> Result<Self, Error> {
        validate_sharing_parameters(n, threshold, &params)?;
        Ok(Self {
            n,
            threshold,
            params,
        })
    }

    /// Total committee size, not the number of reconstructing parties.
    #[must_use]
    pub fn committee_size(&self) -> usize {
        self.n
    }

    /// Shamir polynomial degree; reconstruction needs one more share.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Underlying BFV parameters.
    #[must_use]
    pub fn params(&self) -> &Arc<BfvParameters> {
        &self.params
    }
}

/// Validates threshold configuration parameters.
///
/// # Parameters
/// - `n`: Number of parties in the threshold scheme
/// - `threshold`: Degree `T` of the Shamir sharing polynomial, read as the
///   maximum number of corrupted parties the deployment tolerates.
///   Reconstruction requires `T + 1` shares.
///
/// # Security model
///
/// With `M` corrupted parties (and shares verifiable, e.g. via ZKPs, so honest
/// parties never mix in bad shares), the scheme needs two properties:
///
/// 1. Corrupted parties cannot reconstruct alone: `M < T + 1`, i.e. `M <= T`.
/// 2. Honest parties can reconstruct without the corrupted ones:
///    `n - M >= T + 1`.
///
/// We assume corruption at the honest-majority maximum, `M = (n - 1) / 2`
/// (integer division), so we require exactly `T = (n - 1) / 2`:
///
/// - `T < (n - 1) / 2` is rejected: the maximal corrupted coalition would
///   hold `M >= T + 1` shares and could reconstruct the secret on its own.
/// - `T > (n - 1) / 2` is rejected: the honest parties alone could not
///   gather `T + 1` shares, losing guaranteed reconstruction. (For even `n`,
///   `T = n / 2` would still satisfy both properties, but `T = n / 2 - 1`
///   tolerates the same corruption count with one fewer share to pool, so we
///   require the latter.)
///
/// This forces `n >= 3` (the smallest `n` with a nonzero `T`; a degree-0
/// sharing polynomial is the secret itself, so every party would hold it).
pub fn validate_threshold_config(n: usize, threshold: usize) -> Result<(), Error> {
    if n == 0 {
        return Err(Error::invalid_party_count(n, 1));
    }
    if n < 3 {
        return Err(Error::invalid_party_count(n, 3));
    }
    let max_corruption = (n - 1) / 2;
    if threshold != max_corruption {
        return Err(Error::invalid_threshold(threshold, n));
    }
    Ok(())
}

/// Common key-sharing/decryption validation: Shamir points must be distinct
/// units under every (prime) BFV modulus.
pub(super) fn validate_sharing_parameters(
    n: usize,
    threshold: usize,
    params: &BfvParameters,
) -> Result<(), Error> {
    validate_threshold_config(n, threshold)?;
    let min_modulus = params
        .moduli()
        .iter()
        .min()
        .ok_or(fhe_math::Error::EmptyModuli)?;
    if n >= usize::try_from(*min_modulus).unwrap_or(usize::MAX) {
        return Err(Error::party_count_exceeds_modulus(n, *min_modulus));
    }
    Ok(())
}

#[cfg(feature = "synchronized-decryption")]
pub(super) fn plaintext_modulus(params: &BfvParameters) -> Result<u64, Error> {
    params.plaintext.as_u64().ok_or_else(|| {
        crate::ParametersError::UnsupportedPlaintextModulus {
            reason: "synchronized decryption requires a u64 plaintext modulus".to_string(),
        }
        .into()
    })
}

pub(super) fn validate_ciphertext(ciphertext: &Ciphertext) -> Result<(), Error> {
    if ciphertext.level != 0 {
        return Err(Error::InvalidLevel {
            level: ciphertext.level,
            min_level: 0,
            max_level: 0,
        });
    }
    if ciphertext.c.len() != 2 {
        return Err(crate::CiphertextError::InvalidPolynomialCount {
            operation: crate::CiphertextOperation::MultipartyKeySwitch,
            actual: ciphertext.c.len(),
            expected: 2,
        }
        .into());
    }
    let ctx = ciphertext.params.context_at_level(0)?;
    for poly in &ciphertext.c {
        if poly.ctx() != ctx {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::Ciphertext,
            });
        }
        validate_matrix(
            poly.coefficients(),
            ciphertext.params.moduli(),
            ciphertext.params.degree(),
            0,
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "synchronized-decryption")]
    #[test]
    #[allow(clippy::unwrap_used)]
    fn synchronized_config_preserves_existing_constructor_validation() {
        let params = crate::bfv::BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(17)
            .set_moduli_sizes(&[50, 50, 50])
            .build_arc()
            .unwrap();
        for (n, t) in [(0, 0), (2, 0), (3, 0), (5, 1), (5, 3)] {
            assert!(SynchronizedDecryptionConfig::new(n, t, params.clone()).is_err());
        }
        let config = SynchronizedDecryptionConfig::new(5, 2, params.clone()).unwrap();
        let decryptor = crate::trbfv::SynchronizedDecryptor::from_config(config.clone()).unwrap();
        assert_eq!(decryptor.committee_size(), config.committee_size());
        assert_eq!(decryptor.threshold(), config.threshold());
        assert_eq!(decryptor.params(), config.params());
        let wide = crate::bfv::BfvParametersBuilder::new()
            .set_degree(8)
            .set_moduli(params.moduli())
            .set_plaintext_modulus_biguint((num_bigint::BigUint::from(1u32) << 80usize) + 7u32)
            .build_arc()
            .unwrap();
        assert!(matches!(
            SynchronizedDecryptionConfig::new(3, 1, wide),
            Err(Error::ParametersError(_))
        ));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn sharing_parameters_require_distinct_evaluation_points() {
        let params = crate::bfv::BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(2)
            .set_moduli(&[17])
            .build_arc()
            .unwrap();
        assert!(validate_sharing_parameters(16, 7, &params).is_ok());
        assert!(matches!(
            validate_sharing_parameters(17, 8, &params),
            Err(Error::Threshold(
                crate::ThresholdError::PartyCountExceedsModulus { .. }
            ))
        ));
    }

    #[test]
    fn test_valid_threshold_config() {
        assert!(validate_threshold_config(5, 2).is_ok());
        assert!(validate_threshold_config(3, 1).is_ok());
        assert!(validate_threshold_config(10, 4).is_ok());

        // Maximal corruption tolerance: T = (n - 1) / 2.
        assert!(validate_threshold_config(20, 9).is_ok());
        assert!(validate_threshold_config(21, 10).is_ok());
    }

    #[test]
    fn test_supported_deployment_configs() {
        let deployments = [
            ("minimum", 3, 2, 1),
            ("", 4, 3, 1),
            ("", 5, 3, 2),
            ("", 6, 4, 2),
            ("", 7, 4, 3),
            ("", 8, 5, 3),
            ("micro", 9, 5, 4),
            ("", 10, 6, 4),
            ("", 11, 6, 5),
            ("", 12, 7, 5),
            ("", 13, 7, 6),
            ("", 14, 8, 6),
            ("", 15, 8, 7),
            ("", 16, 9, 7),
            ("", 17, 9, 8),
            ("", 18, 10, 8),
            ("small", 19, 10, 9),
            ("", 20, 11, 9),
        ];
        for (name, n, h, t) in deployments {
            assert!(
                validate_threshold_config(n, t).is_ok(),
                "deployment {name} (n={n}, T={t}) must validate"
            );
            // T is the maximal tolerance for this n...
            assert_eq!(t, (n - 1) / 2, "n={n}");
            // ...and the honest majority can reconstruct on its own
            // (h >= t + 1, i.e. h > t).
            assert_eq!(h, n - t, "n={n}");
            assert!(h > t, "n={n}");
        }
    }

    #[test]
    fn test_invalid_threshold_config() {
        // n = 0
        assert!(validate_threshold_config(0, 1).is_err());

        // threshold = 0: every party would hold the full secret
        assert!(validate_threshold_config(5, 0).is_err());
        assert!(validate_threshold_config(1, 0).is_err());

        // threshold > (n-1)/2
        assert!(validate_threshold_config(5, 6).is_err());
        assert!(validate_threshold_config(5, 5).is_err());
        assert!(validate_threshold_config(5, 4).is_err());
        assert!(validate_threshold_config(5, 3).is_err());

        assert!(validate_threshold_config(4, 2).is_err());
        // For even n, T = n/2 also fails under the (n-1)/2 cap (we prefer
        // n/2 - 1: same corruption count, one fewer share to pool).
        assert!(validate_threshold_config(20, 10).is_err());

        // Below-maximal threshold is rejected: a maximal corrupted coalition
        // (9 of 20) would hold T + 1 = 8 shares and reconstruct on its own.
        assert!(validate_threshold_config(20, 7).is_err());
        assert!(validate_threshold_config(20, 8).is_err());

        // n < 3 cannot host any valid threshold
        assert!(validate_threshold_config(1, 1).is_err());
        assert!(validate_threshold_config(2, 1).is_err());
    }
}
