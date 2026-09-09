#![crate_name = "fhe"]
#![crate_type = "lib"]
#![doc = include_str!("../README.md")]

mod errors;
mod rns_shamir;
// Keep internal tests outside `src` without recompiling the implementation as
// a second integration-test crate.
#[cfg(test)]
#[path = "../tests/internal/rns_shamir.rs"]
mod rns_shamir_tests;

pub mod aggregate;
pub mod bfv;
pub mod lbfv;
#[cfg(feature = "experimental-mbfv")]
pub mod mbfv;
pub mod proto;
pub mod trbfv;
pub mod trlbfv;
pub use errors::{
    CiphertextError, CiphertextOperation, DotProductError, EncodingError, Error,
    EvaluationKeyComponent, EvaluationKeyError, EvaluationOperation, MultipartyError,
    ParameterSource, ParametersError, PlaintextError, Result, SerializationError, SerializedField,
    SerializedObject, SerializedPolynomialComponent, ThresholdError,
};

// Test the source code included in the README.
#[macro_use]
extern crate doc_comment;
doctest!("../README.md");
