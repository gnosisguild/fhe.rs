#![crate_name = "fhe"]
#![crate_type = "lib"]
#![warn(missing_docs, unused_imports)]
#![doc = include_str!("../README.md")]

mod errors;

pub mod bfv;
pub mod lbfv;
pub mod mbfv;
pub mod proto;
pub mod trbfv;
pub use errors::{Error, ParametersError, Result};

// Test the source code included in the README.
#[macro_use]
extern crate doc_comment;
doctest!("../README.md");
