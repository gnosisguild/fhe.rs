#![expect(
    missing_docs,
    reason = "error enums rely on variant docs and error messages"
)]

use thiserror::Error;

/// The Result type for this library.
pub type Result<T> = std::result::Result<T, Error>;

/// Enum encapsulating all the possible errors from this library.
#[derive(Debug, Error, PartialEq, Eq)]
#[expect(missing_docs, reason = "error variants are documented inline")]
#[non_exhaustive]
pub enum Error {
    /// Indicates that an error from the underlying mathematical library was
    /// encountered.
    #[error("Math library error: {0}")]
    MathError(fhe_math::Error),

    /// Indicates a mismatch between contexts
    #[error("Context mismatch: found {found}, expected {expected}")]
    ContextMismatch { found: String, expected: String },

    /// Indicates a mismatch between polynomial formats
    #[error("Polynomial format mismatch: found {found:?}, expected {expected:?}")]
    PolyFormatMismatch {
        found: fhe_math::rq::Representation,
        expected: fhe_math::rq::Representation,
    },

    /// Indicates a mismatch between encoding types
    #[error("Encoding mismatch: found {found}, expected {expected}")]
    EncodingMismatch { found: String, expected: String },

    /// Indicates that the encoding is not supported for the given parameters
    #[error("Encoding '{encoding}' not supported for parameters: {reason}")]
    EncodingNotSupported { encoding: String, reason: String },

    /// Indicates data values exceeding a modulus
    #[error("Data value {value} exceeds modulus {modulus}")]
    DataExceedsModulus { value: u64, modulus: u64 },

    /// Indicates values exceeding a limit during encoding
    #[error("Encoding data size {actual} exceeds limit {limit} for degree {degree}")]
    EncodingDataExceedsLimit {
        actual: usize,
        limit: usize,
        degree: usize,
    },

    /// Indicates that too many values were provided.
    #[error("Too many values provided: {actual} exceeds limit {limit}")]
    TooManyValues { actual: usize, limit: usize },

    /// Indicates that too few values were provided.
    #[error("Too few values provided: {actual} is below minimum {minimum}")]
    TooFewValues { actual: usize, minimum: usize },

    /// Indicates a level is out of bounds
    #[error("Level {level} out of bounds: valid range is [{min_level}, {max_level}]")]
    InvalidLevel {
        /// The invalid level
        level: usize,
        /// Minimum allowed level
        min_level: usize,
        /// Maximum allowed level
        max_level: usize,
    },

    /// Indicates an invalid ciphertext structure
    #[error("Invalid ciphertext: {reason}")]
    InvalidCiphertext { reason: String },

    /// Indicates an invalid plaintext structure
    #[error("Invalid plaintext: {reason}")]
    InvalidPlaintext { reason: String },

    /// Indicates an invalid secret key
    #[error("Invalid secret key: {reason}")]
    InvalidSecretKey { reason: String },

    /// Indicates secret key is incompatible with context
    #[error("Secret key incompatible with context: {reason}")]
    IncompatibleSecretKey { reason: String },

    /// Indicates an invalid Galois element
    #[error("Invalid Galois element {element}: {reason}")]
    InvalidGaloisElement { element: u64, reason: String },

    /// Indicates an invalid rotation step
    #[error("Invalid rotation step {step}: must be in range [{min}, {max}]")]
    InvalidRotationStep { step: i64, min: i64, max: i64 },

    /// Indicates SIMD operations not supported with current parameters
    #[error("SIMD operations not supported: {reason}")]
    SimdNotSupported { reason: String },

    /// Indicates no decryptor available when needed
    #[error("No decryptor available for operation")]
    NoDecryptor,

    /// Indicates a parameter error.
    #[error("Parameters error: {0}")]
    ParametersError(ParametersError),

    /// Indicates a serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(SerializationError),

    /// Indicates dimension mismatch in operations
    #[error("Dimension mismatch: {operation} requires dimensions {expected}, got {actual}")]
    DimensionMismatch {
        operation: String,
        expected: String,
        actual: String,
    },

    /// Indicates security parameter validation failure
    #[error("Security validation failed: {reason}")]
    SecurityValidationError { reason: String },

    /// Indicates a threshold BFV (trbfv) error
    #[error("Threshold error: {0}")]
    Threshold(#[from] ThresholdError),

    /// Catch-all for unexpected errors (should be minimized)
    #[error("Unexpected error: {message}")]
    UnexpectedError { message: String },

    /// Legacy catch-all error (deprecated).
    #[error("{0}")]
    DefaultError(String),

    /// Invalid or unspecified input (threshold BFV and legacy call sites).
    #[error("{0}")]
    UnspecifiedInput(String),
}

impl From<fhe_math::Error> for Error {
    fn from(e: fhe_math::Error) -> Self {
        Error::MathError(e)
    }
}

/// Errors specific to threshold BFV (trbfv) operations.
///
/// These are matchable variants so implementors can react to specific failure
/// modes (e.g. identify the misbehaving party) instead of parsing strings.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ThresholdError {
    /// A party index is outside the valid range `1..=n`.
    #[error("invalid party ID {party_id}: must be between 1 and {n}")]
    InvalidPartyId {
        /// The offending party index
        party_id: usize,
        /// Number of parties in the scheme
        n: usize,
    },

    /// The same party index was provided more than once.
    #[error("duplicate party ID {party_id} in reconstructing parties")]
    DuplicatePartyId {
        /// The duplicated party index
        party_id: usize,
    },

    /// The threshold does not satisfy the honest-majority requirement.
    #[error(
        "threshold must be exactly (n - 1) / 2 = {expected} for n = {n} parties (got \
         {threshold}): smaller thresholds let a maximal corrupted minority reconstruct on \
         its own, larger ones break honest-party reconstruction"
    )]
    InvalidThreshold {
        /// The provided threshold
        threshold: usize,
        /// Number of parties in the scheme
        n: usize,
        /// The required threshold for this n
        expected: usize,
    },

    /// A wrong number of shares or contributions was provided.
    #[error("wrong share count: expected {expected}, got {actual}")]
    ShareCountMismatch {
        /// Number of shares provided
        actual: usize,
        /// Number of shares required
        expected: usize,
    },

    /// A share from a specific party is malformed (wrong shape or values).
    #[error("malformed shares from party {party_id}: {reason}")]
    MalformedShares {
        /// 0-based index of the contribution (or 1-based party id where known)
        party_id: usize,
        /// Description of the problem
        reason: String,
    },

    /// Lagrange reconstruction hit a non-invertible denominator.
    #[error("non-invertible Lagrange denominator (duplicate or invalid share indices)")]
    NonInvertibleShares,

    /// The statistical security parameter is below the secure minimum.
    #[error(
        "lambda {lambda} is below the secure minimum {min}; for testing, opt in explicitly \
         with Lambda::insecure"
    )]
    InsecureLambda {
        /// The provided lambda
        lambda: usize,
        /// The minimum secure lambda
        min: usize,
    },

    /// The smudging bound cannot satisfy both security and correctness.
    #[error("smudging bound infeasible: {reason}")]
    SmudgingBoundInfeasible {
        /// Description of the violated constraint
        reason: String,
    },

    /// The number of parties is too large for the modulus chain.
    #[error(
        "n {n} is not smaller than the smallest modulus {min_modulus}; the MPC protocol \
         assumes n is smaller than the smallest modulus defining the ciphertext space"
    )]
    PartyCountExceedsModulus {
        /// Number of parties
        n: usize,
        /// The smallest modulus
        min_modulus: u64,
    },
}

impl Error {
    pub fn context_mismatch<T, U>(found: &T, expected: &U) -> Self
    where
        T: std::fmt::Debug,
        U: std::fmt::Debug,
    {
        Self::ContextMismatch {
            found: format!("{found:?}"),
            expected: format!("{expected:?}"),
        }
    }

    pub fn invalid_ciphertext<S: Into<String>>(reason: S) -> Self {
        Self::InvalidCiphertext {
            reason: reason.into(),
        }
    }

    pub fn encoding_not_supported<S1, S2>(encoding: S1, reason: S2) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Self::EncodingNotSupported {
            encoding: encoding.into(),
            reason: reason.into(),
        }
    }
}

/// Separate enum for errors arising from serialization.
#[derive(Debug, Error, PartialEq, Eq)]
#[expect(missing_docs, reason = "error variants are documented inline")]
#[non_exhaustive]
pub enum SerializationError {
    /// Indicates polynomial context was not found during deserialization
    #[error("Polynomial context not found: {context_id}")]
    PolynomialContextNotFound { context_id: String },

    /// Indicates wrong number of polynomials in structure
    #[error("{structure_type} has wrong number of polynomials: expected {expected}, got {actual}")]
    WrongPolynomialCount {
        structure_type: String,
        expected: usize,
        actual: usize,
    },

    /// Indicates invalid serialized data format
    #[error("Invalid serialized format: {reason}")]
    InvalidFormat { reason: String },

    /// Indicates version mismatch in serialized data
    #[error(
        "Version mismatch: serialized with {serialized_version}, current version is {current_version}"
    )]
    VersionMismatch {
        serialized_version: String,
        current_version: String,
    },

    /// Indicates corrupted serialized data
    #[error("Corrupted data detected: {details}")]
    CorruptedData { details: String },

    /// Indicates missing required field in serialization
    #[error("Missing required field: {field_name}")]
    MissingField { field_name: String },

    /// Indicates IO error during serialization/deserialization
    #[error("IO error: {error}")]
    IOError { error: String },

    /// Indicates protobuf encoding/decoding error
    #[error("Protobuf error: {message}")]
    ProtobufError { message: String },
}

impl From<std::io::Error> for SerializationError {
    fn from(error: std::io::Error) -> Self {
        SerializationError::IOError {
            error: error.to_string(),
        }
    }
}

/// Separate enum to indicate parameters-related errors.
#[derive(Debug, Error, PartialEq, Eq)]
#[expect(missing_docs, reason = "error variants are documented inline")]
#[non_exhaustive]
pub enum ParametersError {
    /// Indicates that the degree is invalid.
    #[error("Invalid polynomial degree {degree}: must be a power of 2 between {min} and {max}")]
    InvalidDegree {
        degree: usize,
        min: usize,
        max: usize,
    },

    /// Indicates that the plaintext modulus is invalid.
    #[error("Invalid plaintext modulus {modulus}: {reason}")]
    InvalidPlaintextModulus { modulus: u64, reason: String },

    /// Indicates that a ciphertext modulus is invalid.
    #[error("Invalid ciphertext modulus at index {index}: {modulus} ({reason})")]
    InvalidCiphertextModulus {
        index: usize,
        modulus: u64,
        reason: String,
    },

    /// Indicates that the moduli sizes are invalid.
    #[error("Invalid modulus size at index {index}: {size}, expected between {min} and {max}")]
    InvalidModulusSize {
        index: usize,
        size: usize,
        min: usize,
        max: usize,
    },

    /// Indicates that there are not enough primes of a given size
    #[error(
        "Not enough primes of size {size} for degree {degree}: need {needed}, found {available}"
    )]
    NotEnoughPrimes {
        size: usize,
        degree: usize,
        needed: usize,
        available: usize,
    },

    /// Indicates duplicate moduli
    #[error("Duplicate moduli detected: {modulus} appears at indices {indices:?}")]
    DuplicateModuli { modulus: u64, indices: Vec<usize> },

    /// Indicates moduli are not coprime
    #[error("Moduli {modulus1} and {modulus2} are not coprime (gcd = {gcd})")]
    ModuliNotCoprime {
        modulus1: u64,
        modulus2: u64,
        gcd: u64,
    },

    /// Indicates plaintext modulus is not NTT-friendly
    #[error("Plaintext modulus {modulus} is not NTT-friendly for degree {degree}")]
    PlaintextNotNttFriendly { modulus: u64, degree: usize },

    /// Indicates ciphertext modulus is not NTT-friendly
    #[error(
        "Ciphertext modulus {modulus} at index {index} is not NTT-friendly for degree {degree}"
    )]
    CiphertextModulusNotNttFriendly {
        index: usize,
        modulus: u64,
        degree: usize,
    },

    /// Indicates plaintext modulus is too large relative to ciphertext moduli
    #[error(
        "Plaintext modulus {plaintext_modulus} exceeds ciphertext modulus {ciphertext_modulus} at index {index}"
    )]
    PlaintextModulusTooLarge {
        plaintext_modulus: u64,
        ciphertext_modulus: u64,
        index: usize,
    },

    /// Indicates insecure parameters according to standard
    #[error(
        "Parameters provide insufficient security: estimated security level {actual} bits, minimum required {minimum} bits"
    )]
    InsufficientSecurity { actual: u32, minimum: u32 },

    /// Indicates variance parameter out of range
    #[error("Invalid variance {variance}: must be between {min} and {max}")]
    InvalidVariance {
        variance: usize,
        min: usize,
        max: usize,
    },

    /// Indicates conflicting parameter specifications
    #[error("Conflicting parameters: {conflict}")]
    ConflictingParameters { conflict: String },

    /// Indicates missing required parameter
    #[error("Missing required parameter: {parameter}")]
    MissingParameter { parameter: String },

    /// Indicates no parameters are available after filtering
    #[error("No parameters available: {reason}")]
    NoParametersAvailable { reason: String },
}

impl ParametersError {
    #[must_use]
    pub fn invalid_degree_with_bounds(degree: usize) -> Self {
        Self::InvalidDegree {
            degree,
            min: 8,
            max: 65536,
        }
    }

    #[must_use]
    pub fn insufficient_security(actual: u32) -> Self {
        Self::InsufficientSecurity {
            actual,
            minimum: 128,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, ParametersError, SerializationError};

    #[test]
    fn error_strings() {
        assert_eq!(
            Error::MathError(fhe_math::Error::InvalidContext).to_string(),
            "Math library error: Invalid context provided."
        );
        assert_eq!(
            Error::ContextMismatch {
                found: "a".into(),
                expected: "b".into()
            }
            .to_string(),
            "Context mismatch: found a, expected b"
        );
        assert_eq!(
            Error::TooManyValues {
                actual: 20,
                limit: 17
            }
            .to_string(),
            "Too many values provided: 20 exceeds limit 17"
        );
        assert_eq!(
            Error::TooFewValues {
                actual: 10,
                minimum: 17
            }
            .to_string(),
            "Too few values provided: 10 is below minimum 17"
        );
        assert_eq!(
            Error::EncodingMismatch {
                found: "enc1".into(),
                expected: "enc2".into()
            }
            .to_string(),
            "Encoding mismatch: found enc1, expected enc2"
        );
        assert_eq!(
            Error::EncodingNotSupported {
                encoding: "test".into(),
                reason: "oops".into()
            }
            .to_string(),
            "Encoding 'test' not supported for parameters: oops"
        );
        assert_eq!(
            Error::SerializationError(SerializationError::InvalidFormat {
                reason: "bad".into()
            })
            .to_string(),
            "Serialization error: Invalid serialized format: bad"
        );
        assert_eq!(
            Error::ParametersError(ParametersError::invalid_degree_with_bounds(10)).to_string(),
            "Parameters error: Invalid polynomial degree 10: must be a power of 2 between 8 and 65536"
        );
    }
}
