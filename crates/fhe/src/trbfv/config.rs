/// Configuration and validation for threshold BFV.
///
/// This module provides configuration validation logic for threshold BFV operations.
use crate::Error;

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
        return Err(Error::UnspecifiedInput(format!(
            "Threshold must be exactly (n - 1) / 2 = {max_corruption} for n = {n} parties \
             (got {threshold}): smaller thresholds let a maximal corrupted minority \
             reconstruct on its own, larger ones break honest-party reconstruction"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ("minimum", 5, 3, 2),
            ("", 6, 4, 2),
            ("", 7, 4, 3),
            ("", 8, 5, 3),
            ("", 9, 5, 4),
            ("micro", 10, 6, 4),
            ("", 11, 6, 5),
            ("", 12, 7, 5),
            ("", 13, 7, 6),
            ("", 14, 8, 6),
            ("", 15, 8, 7),
            ("", 16, 9, 7),
            ("", 17, 9, 8),
            ("", 18, 10, 8),
            ("", 19, 10, 9),
            ("small", 20, 11, 9),
        ];
        for (name, n, h, t) in deployments {
            assert!(
                validate_threshold_config(n, t).is_ok(),
                "deployment {name} (n={n}, T={t}) must validate"
            );
            // T is the maximal tolerance for this n...
            assert_eq!(t, (n - 1) / 2, "n={n}");
            // ...and the honest majority can reconstruct on its own.
            assert_eq!(h, n - t, "n={n}");
            assert!(h >= t + 1, "n={n}");
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
