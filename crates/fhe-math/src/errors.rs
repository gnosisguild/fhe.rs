use thiserror::Error;

use crate::rq::Representation;

/// The Result type for this library.
pub type Result<T> = std::result::Result<T, Error>;

/// Enum encapsulation all the possible errors from this library.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Indicates an invalid modulus
    #[error("Invalid modulus: modulus {0} should be between 2 and (1 << 62) - 1.")]
    InvalidModulus(u64),

    /// Indicates an error in the serialization / deserialization.
    #[error("{0}")]
    Serialization(String),

    /// Indicates that there is no more contexts to switch to.
    #[error("This is the last context.")]
    NoMoreContext,

    /// Indicates that the provided context is invalid.
    #[error("Invalid context provided.")]
    InvalidContext,

    /// Indicates an incorrect representation.
    #[error("Incorrect representation: got {0:?}, expected {1:?}.")]
    IncorrectRepresentation(Representation, Representation),

    /// Indicates that a polynomial coefficient matrix has the wrong shape.
    #[error(
        "Invalid polynomial dimensions: expected ({expected_rows}, {expected_columns}), got ({actual_rows}, {actual_columns})."
    )]
    InvalidPolynomialDimensions {
        /// Expected number of coefficient rows.
        expected_rows: usize,
        /// Expected number of coefficients per row.
        expected_columns: usize,
        /// Actual number of coefficient rows.
        actual_rows: usize,
        /// Actual number of coefficients per row.
        actual_columns: usize,
    },

    /// Indicates that the seed size is incorrect.
    #[error("Invalid seed: got {0} bytes, expected {1} bytes.")]
    InvalidSeedSize(usize, usize),

    /// Indicates that a serialized coefficient is not a canonical
    /// representative of its modulus.
    #[error("Non-canonical coefficient: value {value} is not in [0, {modulus}).")]
    NonCanonicalCoefficient {
        /// The modulus the coefficient belongs to.
        modulus: u64,
        /// The offending coefficient value.
        value: u64,
    },

    /// Indicates that packed bytes do not encode a whole number of
    /// coefficients.
    #[error(
        "Invalid packed length: {actual} bytes do not encode a whole number of {bits}-bit coefficients."
    )]
    InvalidPackedLength {
        /// The number of bytes provided.
        actual: usize,
        /// The number of bits per coefficient.
        bits: usize,
    },

    /// Indicates that a residue vector does not have exactly one entry per
    /// modulus of the context.
    #[error("Invalid number of residues: got {actual}, expected {expected}.")]
    InvalidResidueCount {
        /// The expected number of residues.
        expected: usize,
        /// The number of residues provided.
        actual: usize,
    },

    /// Indicates that a residue is not a canonical representative of its
    /// modulus.
    #[error("Invalid residue: value {value} is not in [0, {modulus}).")]
    InvalidResidue {
        /// The modulus the residue belongs to.
        modulus: u64,
        /// The offending residue value.
        value: u64,
    },

    /// Indicates that a raw context import received invalid data.
    #[error("Invalid raw RNS context: {0}")]
    InvalidRawContext(String),

    /// Indicates that a scaling factor has a zero denominator.
    #[error("The scaling denominator cannot be zero.")]
    ZeroScalingDenominator,

    /// Indicates that an optimized reduction was requested for a modulus that
    /// does not support the optimized arithmetic.
    #[error("Optimized reduction is not supported for modulus {modulus}.")]
    UnsupportedOptimizedReduction {
        /// The modulus for which the optimized reduction is unsupported.
        modulus: u64,
    },

    /// Indicates that a u128 input to an optimized reduction is not below the
    /// square of the modulus.
    #[error(
        "Invalid optimized reduction input: {value} is not below the square of modulus {modulus}."
    )]
    InvalidOptimizedReductionInput {
        /// The modulus of the reduction.
        modulus: u64,
        /// The out-of-range input value.
        value: u128,
    },

    /// Indicates a default error
    /// TODO: To delete when transition is over
    #[error("{0}")]
    Default(String),
}

#[cfg(test)]
mod tests {
    use crate::{Error, rq::Representation};

    #[test]
    fn error_strings() {
        assert_eq!(
            Error::InvalidModulus(0).to_string(),
            "Invalid modulus: modulus 0 should be between 2 and (1 << 62) - 1."
        );
        assert_eq!(Error::Serialization("test".to_string()).to_string(), "test");
        assert_eq!(
            Error::NoMoreContext.to_string(),
            "This is the last context."
        );
        assert_eq!(
            Error::InvalidContext.to_string(),
            "Invalid context provided."
        );
        assert_eq!(
            Error::IncorrectRepresentation(Representation::Ntt, Representation::NttShoup)
                .to_string(),
            "Incorrect representation: got Ntt, expected NttShoup."
        );
        assert_eq!(
            Error::InvalidSeedSize(0, 1).to_string(),
            "Invalid seed: got 0 bytes, expected 1 bytes."
        );
        assert_eq!(
            Error::NonCanonicalCoefficient {
                modulus: 1153,
                value: 1153,
            }
            .to_string(),
            "Non-canonical coefficient: value 1153 is not in [0, 1153)."
        );
        assert_eq!(
            Error::InvalidPackedLength {
                actual: 1,
                bits: 62
            }
            .to_string(),
            "Invalid packed length: 1 bytes do not encode a whole number of 62-bit coefficients."
        );
        assert_eq!(
            Error::InvalidResidueCount {
                expected: 3,
                actual: 2,
            }
            .to_string(),
            "Invalid number of residues: got 2, expected 3."
        );
        assert_eq!(
            Error::InvalidResidue {
                modulus: 4,
                value: 4,
            }
            .to_string(),
            "Invalid residue: value 4 is not in [0, 4)."
        );
        assert_eq!(
            Error::InvalidRawContext("bad moduli".to_string()).to_string(),
            "Invalid raw RNS context: bad moduli"
        );
        assert_eq!(
            Error::ZeroScalingDenominator.to_string(),
            "The scaling denominator cannot be zero."
        );
        assert_eq!(
            Error::UnsupportedOptimizedReduction { modulus: 17 }.to_string(),
            "Optimized reduction is not supported for modulus 17."
        );
        assert_eq!(
            Error::InvalidOptimizedReductionInput {
                modulus: 17,
                value: 300,
            }
            .to_string(),
            "Invalid optimized reduction input: 300 is not below the square of modulus 17."
        );
    }
}
