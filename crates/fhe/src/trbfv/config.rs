/// Configuration and validation for threshold BFV (Urban–Rambaud 2024).
///
/// This module enforces `n >= 3` and `T = (n - 1) / 2` for the honest-majority
/// model. **Even `n` is accepted**, but Urban–Rambaud&nbsp;2024
/// proves security only for odd party counts under the `n = 2t + 1` theorem.
/// Even-`n` deployments fall outside the paper's coverage and have not been
/// independently analyzed.
use crate::Error;

/// Require `n >= 3` and Shamir degree `T = (n - 1) / 2`.
/// With `M = (n - 1) / 2` corruptions, `M < T + 1 <= n - M` allows honest
/// reconstruction without letting the corrupted coalition reconstruct alone,
/// assuming verifiable shares. Degree zero would reveal the secret to every party.
pub(crate) fn validate_threshold_config(n: usize, threshold: usize) -> Result<(), Error> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
            ("", 21, 11, 10),
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
