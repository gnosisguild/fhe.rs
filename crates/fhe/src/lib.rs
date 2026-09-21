#![crate_name = "fhe"]
#![crate_type = "lib"]
#![doc = include_str!("../README.md")]

#[cfg(test)]
extern crate self as fhe;

#[cfg(test)]
#[path = "../support/mod.rs"]
mod support;

mod errors;
mod rns_shamir;
mod serialization;

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
