#![crate_name = "fhe_math"]
#![crate_type = "lib"]

//! Mathematical utilities for the fhe.rs library.

mod errors;
mod proto;

pub mod ntt;
pub mod rns;
pub mod rq;
pub mod zq;

pub use errors::{Error, PolynomialSerializationError, Result};
/// Polynomial wire format, re-exported so threshold schemes can build the
/// explicit transport boundary for protected smudging material on the same
/// encoding as every other polynomial.
pub use proto::rq::Rq;

#[cfg(test)]
#[macro_use]
extern crate proptest;
