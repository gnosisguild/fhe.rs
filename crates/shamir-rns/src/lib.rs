#![forbid(unsafe_code)]
#![warn(missing_docs, unused_imports)]

//! Independent Shamir secret sharing for canonical `u64` RNS residues.
//!
//! The crate implements a prime field with runtime modulus validation and
//! Shamir polynomials whose secret is at `x = 0` and whose party points are
//! `x = 1..=n`. It provides no commitments, verifiability, robust DKG,
//! authentication, transport protection, or complete threshold protocol.
//! The arithmetic kernels and fixed-schedule inversion are designed with a
//! bounded constant-time goal, but rejection sampling, rayon scheduling when
//! enabled, memory allocation, and code outside this crate are not covered by
//! that claim. This unaudited library is not a security proof.

mod error;
mod primality;

pub mod field;
pub mod rns;
pub mod shamir;

pub use error::Error;
pub use field::{
    Barrett, BarrettBackend, BarrettField, Field, FieldBackend, Montgomery, MontgomeryBackend,
    MontgomeryField,
};
pub use rns::RnsShamir;
pub use shamir::{ShamirScheme, ShareMatrix};
