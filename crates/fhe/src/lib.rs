#![crate_name = "fhe"]
#![crate_type = "lib"]
#![doc = include_str!("../README.md")]

mod errors;
pub mod identity;

pub mod bfv;
pub mod lbfv;
pub mod mbfv;
#[cfg(feature = "protobuf")]
pub mod proto;
pub mod trbfv;
pub mod trlbfv;
pub use errors::{Error, ParametersError, Result, SerializationError, ThresholdError};
pub use identity::{ContributionBinding, ParticipantSet, SessionId};

// Test the source code included in the README.
#[macro_use]
extern crate doc_comment;
doctest!("../README.md");
