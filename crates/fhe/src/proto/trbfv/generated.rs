#![allow(missing_docs)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Parameters {
    #[prost(uint32, tag = "1")]
    pub degree: u32,
    #[prost(uint64, repeated, tag = "2")]
    pub moduli: ::prost::alloc::vec::Vec<u64>,
    #[prost(uint64, tag = "3")]
    pub plaintext: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TrbfvConfig {
    #[prost(uint32, tag = "1")]
    pub n: u32,
    #[prost(uint32, tag = "2")]
    pub threshold: u32,
    #[prost(message, optional, tag = "3")]
    pub params: ::core::option::Option<Parameters>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SecretShare {
    #[prost(message, repeated, tag = "1")]
    pub moduli_shares: ::prost::alloc::vec::Vec<SecretShareModulus>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SecretShareModulus {
    #[prost(uint64, repeated, tag = "1")]
    pub coefficients: ::prost::alloc::vec::Vec<u64>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptionShare {
    #[prost(bytes = "vec", tag = "1")]
    pub poly_data: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ThresholdDecryptionRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub ciphertext: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub party_id: u32,
    #[prost(uint64, tag = "3")]
    pub timestamp: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ThresholdDecryptionResponse {
    #[prost(message, optional, tag = "1")]
    pub share: ::core::option::Option<DecryptionShare>,
    #[prost(uint32, tag = "2")]
    pub party_id: u32,
    #[prost(bool, tag = "3")]
    pub success: bool,
    #[prost(string, tag = "4")]
    pub error_message: ::prost::alloc::string::String,
}
