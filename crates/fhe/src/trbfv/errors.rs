//! Error types for threshold BFV operations.

use crate::Error;

/// Helper functions to create threshold-specific errors using the general Error types.
impl Error {
    /// Create an invalid party count error.
    pub fn invalid_party_count(got: usize, min: usize) -> Self {
        Error::TooFewValues(got, min)
    }

    /// Create an insufficient shares error.
    pub fn insufficient_shares(got: usize, required: usize) -> Self {
        Error::TooFewValues(got, required)
    }

    /// Create a threshold too large error.
    pub fn threshold_too_large(threshold: usize, n: usize) -> Self {
        Error::UnspecifiedInput(format!(
            "Threshold {} must be less than number of parties {}",
            threshold, n
        ))
    }

    /// Create an invalid party ID error.
    pub fn invalid_party_id(party_id: usize, max_party_id: usize) -> Self {
        Error::UnspecifiedInput(format!(
            "Invalid party ID: {}, must be between 0 and {}",
            party_id, max_party_id
        ))
    }

    /// Create a secret sharing error.
    pub fn secret_sharing<S: Into<String>>(msg: S) -> Self {
        Error::UnspecifiedInput(format!("Secret sharing error: {}", msg.into()))
    }

    /// Create a smudging error.
    pub fn smudging(msg: String) -> Self {
        Error::UnspecifiedInput(msg)
    }

    /// Create a share operation error.
    pub fn share_operation<S: Into<String>>(msg: S) -> Self {
        Error::UnspecifiedInput(format!("Share operation error: {}", msg.into()))
    }

    /// Create a decryption share error.
    pub fn decryption_share<S: Into<String>>(msg: S) -> Self {
        Error::UnspecifiedInput(format!(
            "Decryption share computation failed: {}",
            msg.into()
        ))
    }

    /// Create a decryption reconstruction error.
    pub fn decryption_reconstruction<S: Into<String>>(msg: S) -> Self {
        Error::UnspecifiedInput(format!("Decryption reconstruction failed: {}", msg.into()))
    }

    /// Create a malformed shares error.
    pub fn malformed_shares(party_id: usize, reason: String) -> Self {
        Error::UnspecifiedInput(format!(
            "Malformed shares from party {}: {}",
            party_id, reason
        ))
    }

    /// Create an inconsistent degree error.
    pub fn inconsistent_degree(expected: usize, got: usize) -> Self {
        Error::UnspecifiedInput(format!(
            "Inconsistent polynomial degree: expected {}, found {}",
            expected, got
        ))
    }

    /// Create an inconsistent moduli error.
    pub fn inconsistent_moduli(expected: usize, got: usize) -> Self {
        Error::UnspecifiedInput(format!(
            "Inconsistent moduli: expected {} moduli, found {}",
            expected, got
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
            "Too few values provided: 2 is below limit 3"
        );

        let error = Error::threshold_too_large(5, 3);
        assert_eq!(
            error.to_string(),
            "Threshold 5 must be less than number of parties 3"
        );

        let error = Error::inconsistent_degree(2048, 1024);
        assert_eq!(
            error.to_string(),
            "Inconsistent polynomial degree: expected 2048, found 1024"
        );

        let error = Error::inconsistent_moduli(3, 2);
        assert_eq!(
            error.to_string(),
            "Inconsistent moduli: expected 3 moduli, found 2"
        );

        let error = Error::insufficient_shares(2, 3);
        assert_eq!(
            error.to_string(),
            "Too few values provided: 2 is below limit 3"
        );

        let error = Error::smudging("Test smudging error".to_string());
        assert_eq!(error.to_string(), "Test smudging error");

        let error = Error::invalid_party_id(5, 3);
        assert_eq!(
            error.to_string(),
            "Invalid party ID: 5, must be between 0 and 3"
        );

        let error = Error::secret_sharing("Test secret sharing error");
        assert_eq!(
            error.to_string(),
            "Secret sharing error: Test secret sharing error"
        );

        let error = Error::share_operation("Test share operation error");
        assert_eq!(
            error.to_string(),
            "Share operation error: Test share operation error"
        );

        let error = Error::decryption_share("Test decryption share error");
        assert_eq!(
            error.to_string(),
            "Decryption share computation failed: Test decryption share error"
        );

        let error = Error::decryption_reconstruction("Test decryption reconstruction error");
        assert_eq!(
            error.to_string(),
            "Decryption reconstruction failed: Test decryption reconstruction error"
        );

        let error = Error::malformed_shares(1, "Test reason".to_string());
        assert_eq!(
            error.to_string(),
            "Malformed shares from party 1: Test reason"
        );
    }
}
