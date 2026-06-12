//! Error types for threshold BFV operations.
//!
//! The matchable variants live in [`crate::ThresholdError`]; the helpers here
//! construct them wrapped in the crate-level [`Error`].

use crate::{Error, ThresholdError};

/// Helper functions to create threshold-specific errors using the general Error types.
impl Error {
    /// Create an invalid party count error.
    #[must_use]
    pub fn invalid_party_count(got: usize, min: usize) -> Self {
        Error::TooFewValues {
            actual: got,
            minimum: min,
        }
    }

    /// Create an insufficient shares error.
    #[must_use]
    pub fn insufficient_shares(got: usize, required: usize) -> Self {
        Error::Threshold(ThresholdError::ShareCountMismatch {
            actual: got,
            expected: required,
        })
    }

    /// Create an invalid threshold error (must be exactly `(n - 1) / 2`).
    #[must_use]
    pub fn invalid_threshold(threshold: usize, n: usize) -> Self {
        Error::Threshold(ThresholdError::InvalidThreshold {
            threshold,
            n,
            expected: n.saturating_sub(1) / 2,
        })
    }

    /// Create an invalid party ID error.
    #[must_use]
    pub fn invalid_party_id(party_id: usize, n: usize) -> Self {
        Error::Threshold(ThresholdError::InvalidPartyId { party_id, n })
    }

    /// Create a duplicate party ID error.
    #[must_use]
    pub fn duplicate_party_id(party_id: usize) -> Self {
        Error::Threshold(ThresholdError::DuplicatePartyId { party_id })
    }

    /// Create a secret sharing error.
    pub fn secret_sharing<S: Into<String>>(msg: S) -> Self {
        let msg = msg.into();
        Error::UnspecifiedInput(format!("Secret sharing error: {msg}"))
    }

    /// Create a smudging error.
    #[must_use]
    pub fn smudging(msg: String) -> Self {
        Error::UnspecifiedInput(msg)
    }

    /// Create a share operation error.
    pub fn share_operation<S: Into<String>>(msg: S) -> Self {
        let msg = msg.into();
        Error::UnspecifiedInput(format!("Share operation error: {msg}"))
    }

    /// Create a decryption share error.
    pub fn decryption_share<S: Into<String>>(msg: S) -> Self {
        let msg = msg.into();
        Error::UnspecifiedInput(format!("Decryption share computation failed: {msg}"))
    }

    /// Create a decryption reconstruction error.
    pub fn decryption_reconstruction<S: Into<String>>(msg: S) -> Self {
        let msg = msg.into();
        Error::UnspecifiedInput(format!("Decryption reconstruction failed: {msg}"))
    }

    /// Create a malformed shares error.
    #[must_use]
    pub fn malformed_shares(party_id: usize, reason: String) -> Self {
        Error::Threshold(ThresholdError::MalformedShares { party_id, reason })
    }

    /// Create a non-invertible Lagrange denominator error.
    #[must_use]
    pub fn non_invertible_shares() -> Self {
        Error::Threshold(ThresholdError::NonInvertibleShares)
    }

    /// Create an insecure lambda error.
    #[must_use]
    pub fn insecure_lambda(lambda: usize, min: usize) -> Self {
        Error::Threshold(ThresholdError::InsecureLambda { lambda, min })
    }

    /// Create a smudging bound infeasibility error.
    pub fn smudging_bound_infeasible<S: Into<String>>(reason: S) -> Self {
        Error::Threshold(ThresholdError::SmudgingBoundInfeasible {
            reason: reason.into(),
        })
    }

    /// Create a party-count-exceeds-modulus error.
    #[must_use]
    pub fn party_count_exceeds_modulus(n: usize, min_modulus: u64) -> Self {
        Error::Threshold(ThresholdError::PartyCountExceedsModulus { n, min_modulus })
    }

    /// Create an inconsistent degree error.
    #[must_use]
    pub fn inconsistent_degree(expected: usize, got: usize) -> Self {
        Error::UnspecifiedInput(format!(
            "Inconsistent polynomial degree: expected {expected}, found {got}"
        ))
    }

    /// Create an inconsistent moduli error.
    #[must_use]
    pub fn inconsistent_moduli(expected: usize, got: usize) -> Self {
        Error::UnspecifiedInput(format!(
            "Inconsistent moduli: expected {expected} moduli, found {got}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_error_helpers() {
        let error = Error::invalid_party_count(2, 3);
        assert_eq!(
            error.to_string(),
            "Too few values provided: 2 is below minimum 3"
        );

        let error = Error::invalid_threshold(5, 20);
        assert!(matches!(
            error,
            Error::Threshold(ThresholdError::InvalidThreshold {
                threshold: 5,
                n: 20,
                expected: 9
            })
        ));

        let error = Error::insufficient_shares(2, 3);
        assert!(matches!(
            error,
            Error::Threshold(ThresholdError::ShareCountMismatch {
                actual: 2,
                expected: 3
            })
        ));
        assert_eq!(
            error.to_string(),
            "Threshold error: wrong share count: expected 3, got 2"
        );

        let error = Error::invalid_party_id(5, 3);
        assert!(matches!(
            error,
            Error::Threshold(ThresholdError::InvalidPartyId { party_id: 5, n: 3 })
        ));
        assert_eq!(
            error.to_string(),
            "Threshold error: invalid party ID 5: must be between 1 and 3"
        );

        let error = Error::duplicate_party_id(2);
        assert!(matches!(
            error,
            Error::Threshold(ThresholdError::DuplicatePartyId { party_id: 2 })
        ));

        let error = Error::malformed_shares(1, "Test reason".to_string());
        assert!(matches!(
            error,
            Error::Threshold(ThresholdError::MalformedShares { party_id: 1, .. })
        ));
        assert_eq!(
            error.to_string(),
            "Threshold error: malformed shares from party 1: Test reason"
        );

        let error = Error::non_invertible_shares();
        assert!(matches!(
            error,
            Error::Threshold(ThresholdError::NonInvertibleShares)
        ));

        let error = Error::insecure_lambda(2, 50);
        assert!(matches!(
            error,
            Error::Threshold(ThresholdError::InsecureLambda { lambda: 2, min: 50 })
        ));

        let error = Error::smudging_bound_infeasible("test");
        assert!(matches!(
            error,
            Error::Threshold(ThresholdError::SmudgingBoundInfeasible { .. })
        ));

        let error = Error::party_count_exceeds_modulus(70000, 65537);
        assert!(matches!(
            error,
            Error::Threshold(ThresholdError::PartyCountExceedsModulus {
                n: 70000,
                min_modulus: 65537
            })
        ));

        // Legacy string helpers still produce errors
        let error = Error::secret_sharing("Test secret sharing error");
        assert_eq!(
            error.to_string(),
            "Secret sharing error: Test secret sharing error"
        );
        let error = Error::inconsistent_degree(2048, 1024);
        assert_eq!(
            error.to_string(),
            "Inconsistent polynomial degree: expected 2048, found 1024"
        );
    }
}
