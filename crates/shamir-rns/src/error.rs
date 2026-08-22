//! Errors returned by field construction and Shamir operations.

use core::fmt;

/// Errors from the independent prime-field Shamir primitive.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Error {
    /// The modulus is outside the supported odd-word range.
    InvalidModulus {
        /// The rejected modulus.
        modulus: u64,
    },
    /// The modulus passed deterministic Miller–Rabin as composite.
    CompositeModulus {
        /// The composite modulus.
        modulus: u64,
    },
    /// The threshold count is zero or exceeds the party count.
    InvalidThreshold {
        /// The requested reconstruction count.
        shares_needed: usize,
        /// The configured party count.
        num_shares: usize,
    },
    /// The party count would make canonical points collide modulo the field.
    TooManyShares {
        /// The configured party count.
        num_shares: usize,
        /// The field modulus.
        modulus: u64,
    },
    /// A secret is not a canonical residue in `[0, q)`.
    NonCanonicalSecret {
        /// The supplied secret.
        value: u64,
        /// The field modulus.
        modulus: u64,
    },
    /// A share is not a canonical residue in `[0, q)`.
    NonCanonicalShare {
        /// The supplied share.
        value: u64,
        /// The field modulus.
        modulus: u64,
    },
    /// Reconstruction requires exactly `shares_needed` shares.
    WrongShareCount {
        /// The required number of shares.
        expected: usize,
        /// The supplied number of shares.
        actual: usize,
    },
    /// A party identifier is zero or outside `1..=num_shares`.
    InvalidPartyId {
        /// The rejected identifier.
        party_id: usize,
    },
    /// A party identifier occurs more than once.
    DuplicatePartyId {
        /// The duplicated identifier.
        party_id: usize,
    },
    /// A matrix has a different row or column shape than required.
    InvalidMatrixShape {
        /// Required row count.
        expected_rows: usize,
        /// Required column count.
        expected_columns: usize,
        /// Supplied row count.
        actual_rows: usize,
        /// Supplied column count.
        actual_columns: usize,
    },
    /// A matrix's flat storage length does not match its declared shape.
    InvalidMatrixStorage,
    /// An RNS basis contains no moduli.
    EmptyBasis,
    /// A nonzero denominator could not be inverted.
    NonInvertible,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidModulus { modulus } => write!(formatter, "invalid modulus {modulus}"),
            Self::CompositeModulus { modulus } => write!(formatter, "composite modulus {modulus}"),
            Self::InvalidThreshold {
                shares_needed,
                num_shares,
            } => write!(
                formatter,
                "invalid threshold: need {shares_needed} of {num_shares} shares"
            ),
            Self::TooManyShares {
                num_shares,
                modulus,
            } => write!(
                formatter,
                "party count {num_shares} is not below modulus {modulus}"
            ),
            Self::NonCanonicalSecret { modulus, .. } => {
                write!(formatter, "secret value is not canonical modulo {modulus}")
            }
            Self::NonCanonicalShare { modulus, .. } => {
                write!(formatter, "share value is not canonical modulo {modulus}")
            }
            Self::WrongShareCount { expected, actual } => {
                write!(formatter, "expected {expected} shares, got {actual}")
            }
            Self::InvalidPartyId { party_id } => write!(formatter, "invalid party id {party_id}"),
            Self::DuplicatePartyId { party_id } => {
                write!(formatter, "duplicate party id {party_id}")
            }
            Self::InvalidMatrixShape {
                expected_rows,
                expected_columns,
                actual_rows,
                actual_columns,
            } => write!(
                formatter,
                "expected matrix shape [{expected_rows}, {expected_columns}], got [{actual_rows}, {actual_columns}]"
            ),
            Self::InvalidMatrixStorage => {
                write!(formatter, "matrix storage does not match its shape")
            }
            Self::EmptyBasis => write!(formatter, "RNS basis must contain at least one modulus"),
            Self::NonInvertible => write!(formatter, "field denominator is not invertible"),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalSecret { modulus, .. } => formatter
                .debug_struct("NonCanonicalSecret")
                .field("value", &"<redacted>")
                .field("modulus", modulus)
                .finish(),
            Self::NonCanonicalShare { modulus, .. } => formatter
                .debug_struct("NonCanonicalShare")
                .field("value", &"<redacted>")
                .field("modulus", modulus)
                .finish(),
            Self::InvalidModulus { modulus } => formatter
                .debug_struct("InvalidModulus")
                .field("modulus", modulus)
                .finish(),
            Self::CompositeModulus { modulus } => formatter
                .debug_struct("CompositeModulus")
                .field("modulus", modulus)
                .finish(),
            Self::InvalidThreshold {
                shares_needed,
                num_shares,
            } => formatter
                .debug_struct("InvalidThreshold")
                .field("shares_needed", shares_needed)
                .field("num_shares", num_shares)
                .finish(),
            Self::TooManyShares {
                num_shares,
                modulus,
            } => formatter
                .debug_struct("TooManyShares")
                .field("num_shares", num_shares)
                .field("modulus", modulus)
                .finish(),
            Self::WrongShareCount { expected, actual } => formatter
                .debug_struct("WrongShareCount")
                .field("expected", expected)
                .field("actual", actual)
                .finish(),
            Self::InvalidPartyId { party_id } => formatter
                .debug_struct("InvalidPartyId")
                .field("party_id", party_id)
                .finish(),
            Self::DuplicatePartyId { party_id } => formatter
                .debug_struct("DuplicatePartyId")
                .field("party_id", party_id)
                .finish(),
            Self::InvalidMatrixShape {
                expected_rows,
                expected_columns,
                actual_rows,
                actual_columns,
            } => formatter
                .debug_struct("InvalidMatrixShape")
                .field("expected_rows", expected_rows)
                .field("expected_columns", expected_columns)
                .field("actual_rows", actual_rows)
                .field("actual_columns", actual_columns)
                .finish(),
            Self::InvalidMatrixStorage => formatter.write_str("InvalidMatrixStorage"),
            Self::EmptyBasis => formatter.write_str("EmptyBasis"),
            Self::NonInvertible => formatter.write_str("NonInvertible"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn secret_and_share_values_are_redacted() {
        let secret = Error::NonCanonicalSecret {
            value: 987_654_321,
            modulus: 1613,
        };
        let share = Error::NonCanonicalShare {
            value: 123_456_789,
            modulus: 2017,
        };
        assert!(!format!("{secret:?}").contains("987654321"));
        assert!(!format!("{secret}").contains("987654321"));
        assert!(!format!("{share:?}").contains("123456789"));
        assert!(!format!("{share}").contains("123456789"));
    }
}
