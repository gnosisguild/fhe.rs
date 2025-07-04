//! Error types for threshold BFV operations.

/// The Result type for threshold BFV operations.
pub type ThresholdResult<T> = std::result::Result<T, crate::Error>;

/// Helper functions to create threshold-specific errors using the general Error types.
impl crate::Error {
    /// Create an invalid party count error.
    pub fn invalid_party_count(provided: usize, minimum: usize) -> Self {
        Self::TooFewValues(provided, minimum)
    }

    /// Create an insufficient shares error.
    pub fn insufficient_shares(provided: usize, required: usize) -> Self {
        Self::TooFewValues(provided, required)
    }

    /// Create a too many shares error.
    pub fn too_many_shares(provided: usize, maximum: usize) -> Self {
        Self::TooManyValues(provided, maximum)
    }

    /// Create a threshold too large error.
    pub fn threshold_too_large(threshold: usize, parties: usize) -> Self {
        Self::UnspecifiedInput(format!(
            "Threshold {} must be less than number of parties {}",
            threshold, parties
        ))
    }

    /// Create an invalid party ID error.
    pub fn invalid_party_id(party_id: usize, max_party_id: usize) -> Self {
        Self::UnspecifiedInput(format!(
            "Invalid party ID: {}, must be between 0 and {}",
            party_id, max_party_id
        ))
    }

    /// Create a secret sharing error.
    pub fn secret_sharing<S: Into<String>>(msg: S) -> Self {
        Self::UnspecifiedInput(format!("Secret sharing error: {}", msg.into()))
    }

    /// Create a smudging error.
    pub fn smudging<S: Into<String>>(msg: S) -> Self {
        Self::UnspecifiedInput(format!("Smudging error: {}", msg.into()))
    }

    /// Create a share operation error.
    pub fn share_operation<S: Into<String>>(msg: S) -> Self {
        Self::UnspecifiedInput(format!("Share operation error: {}", msg.into()))
    }

    /// Create a decryption share error.
    pub fn decryption_share<S: Into<String>>(msg: S) -> Self {
        Self::UnspecifiedInput(format!(
            "Decryption share computation failed: {}",
            msg.into()
        ))
    }

    /// Create a decryption reconstruction error.
    pub fn decryption_reconstruction<S: Into<String>>(msg: S) -> Self {
        Self::UnspecifiedInput(format!("Decryption reconstruction failed: {}", msg.into()))
    }

    /// Create a malformed shares error.
    pub fn malformed_shares(party_id: usize, reason: String) -> Self {
        Self::UnspecifiedInput(format!(
            "Malformed shares from party {}: {}",
            party_id, reason
        ))
    }

    /// Create an inconsistent degree error.
    pub fn inconsistent_degree(expected: usize, found: usize) -> Self {
        Self::UnspecifiedInput(format!(
            "Inconsistent polynomial degree: expected {}, found {}",
            expected, found
        ))
    }

    /// Create an inconsistent moduli error.
    pub fn inconsistent_moduli(expected: usize, found: usize) -> Self {
        Self::UnspecifiedInput(format!(
            "Inconsistent moduli: expected {} moduli, found {}",
            expected, found
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::Error;

    #[test]
    fn test_threshold_error_helpers() {
        let error = Error::invalid_party_count(0, 1);
        assert_eq!(
            error.to_string(),
            "Too few values provided: 0 is below limit 1"
        );

        let error = Error::insufficient_shares(2, 3);
        assert_eq!(
            error.to_string(),
            "Too few values provided: 2 is below limit 3"
        );

        let error = Error::too_many_shares(10, 5);
        assert_eq!(
            error.to_string(),
            "Too many values provided: 10 exceeds limit 5"
        );

        let error = Error::threshold_too_large(5, 3);
        assert_eq!(
            error.to_string(),
            "Threshold 5 must be less than number of parties 3"
        );

        let error = Error::secret_sharing("test message");
        assert_eq!(error.to_string(), "Secret sharing error: test message");
    }
}
