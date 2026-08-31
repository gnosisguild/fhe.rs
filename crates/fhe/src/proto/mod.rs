//! Protobuf definitions and serialization for FHE types.

/// Protobuf for the BFV encryption scheme.
pub mod bfv;
/// Protobuf for the L-BFV encryption scheme.
pub mod lbfv;
/// Protobuf for the MBFV encryption scheme (experimental).
#[cfg(feature = "experimental-mbfv")]
pub mod mbfv;
/// Protobuf for Threshold BFV (TRBFV).
pub mod trbfv;
/// Protobuf for Threshold L-BFV (TRLBFV).
pub mod trlbfv;
