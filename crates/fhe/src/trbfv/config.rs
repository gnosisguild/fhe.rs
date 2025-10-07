/// Configuration and validation for threshold BFV.
///
/// This module provides configuration validation logic for threshold BFV operations.
use crate::Error;

/// Validates threshold configuration parameters.
///
/// # Parameters
/// - `n`: Number of parties in the threshold scheme
/// - `threshold`: Minimum number of parties required for reconstruction
pub fn validate_threshold_config(n: usize, threshold: usize) -> Result<(), Error> {
    if n == 0 {
        return Err(Error::invalid_party_count(n, 1));
    }
    if threshold > (n - 1) / 2 {
        return Err(Error::threshold_too_large(threshold, n));
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
    }

    #[test]
    fn test_invalid_threshold_config() {
        // n = 0
        assert!(validate_threshold_config(0, 1).is_err());

        // threshold > (n-1)/2
        assert!(validate_threshold_config(5, 6).is_err());
        assert!(validate_threshold_config(5, 5).is_err());
        assert!(validate_threshold_config(5, 4).is_err());
        assert!(validate_threshold_config(5, 3).is_err());

        assert!(validate_threshold_config(4, 2).is_err());
    }
}
