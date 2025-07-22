//! TRBFV protobuf definitions and serialization.

#[allow(clippy::all)]
mod generated;
mod serialization;

// Re-export generated protobuf types
pub use generated::*;

// Re-export serialization functions
pub use serialization::{
    deserialize_decryption_share, deserialize_secret_share, deserialize_smudging_data,
    serialize_decryption_share, serialize_secret_share, serialize_smudging_data,
};
