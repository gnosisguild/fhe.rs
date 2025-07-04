/// Configuration and validation for threshold BFV.
///
/// This module provides configuration validation logic for threshold BFV operations.

use crate::Error;

/// Validates threshold configuration parameters.
pub fn validate_threshold_config(n: usize, threshold: usize) -> Result<(), Error> {
    if n == 0 {
        return Err(Error::invalid_party_count(n, 1));
    }
    if threshold >= n {
        return Err(Error::threshold_too_large(threshold, n));
    }
    if threshold == 0 {
        return Err(Error::UnspecifiedInput(
            "Threshold must be at least 1".to_string(),
        ));
    }
    Ok(())
}

/// Validates smudging variance parameter.
pub fn validate_smudging_variance(variance: usize) -> Result<(), Error> {
    if variance == 0 {
        return Err(Error::UnspecifiedInput(
            "Smudging variance must be greater than 0".to_string(),
        ));
    }
    Ok(())
}

/// Validates all threshold BFV configuration parameters.
pub fn validate_all_params(n: usize, threshold: usize, smudging_variance: usize) -> Result<(), Error> {
    validate_threshold_config(n, threshold)?;
    validate_smudging_variance(smudging_variance)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_threshold_config() {
        assert!(validate_threshold_config(5, 3).is_ok());
        assert!(validate_threshold_config(3, 2).is_ok());
        assert!(validate_threshold_config(10, 7).is_ok());
    }

    #[test]
    fn test_invalid_threshold_config() {
        // n = 0
        assert!(validate_threshold_config(0, 1).is_err());
        
        // threshold >= n
        assert!(validate_threshold_config(5, 5).is_err());
        assert!(validate_threshold_config(5, 6).is_err());
        
        // threshold = 0
        assert!(validate_threshold_config(5, 0).is_err());
    }

    #[test]
    fn test_valid_smudging_variance() {
        assert!(validate_smudging_variance(1).is_ok());
        assert!(validate_smudging_variance(160).is_ok());
        assert!(validate_smudging_variance(1000).is_ok());
    }

    #[test]
    fn test_invalid_smudging_variance() {
        assert!(validate_smudging_variance(0).is_err());
    }

    #[test]
    fn test_validate_all_params() {
        assert!(validate_all_params(5, 3, 160).is_ok());
        assert!(validate_all_params(0, 3, 160).is_err());
        assert!(validate_all_params(5, 5, 160).is_err());
        assert!(validate_all_params(5, 3, 0).is_err());
    }
} 