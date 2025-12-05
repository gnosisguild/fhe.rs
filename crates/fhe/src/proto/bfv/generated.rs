#![allow(missing_docs)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ciphertext {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub c: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "2")]
    pub seed: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub level: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RgswCiphertext {
    #[prost(message, optional, tag = "1")]
    pub ksk0: ::core::option::Option<KeySwitchingKey>,
    #[prost(message, optional, tag = "2")]
    pub ksk1: ::core::option::Option<KeySwitchingKey>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeySwitchingKey {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub c0: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub c1: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "3")]
    pub seed: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub ciphertext_level: u32,
    #[prost(uint32, tag = "5")]
    pub ksk_level: u32,
    #[prost(uint32, tag = "6")]
    pub log_base: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RelinearizationKey {
    #[prost(message, optional, tag = "1")]
    pub ksk: ::core::option::Option<KeySwitchingKey>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LbfvRelinearizationKey {
    #[prost(message, optional, tag = "1")]
    pub ksk_r_to_s: ::core::option::Option<KeySwitchingKey>,
    #[prost(message, optional, tag = "2")]
    pub ksk_s_to_r: ::core::option::Option<KeySwitchingKey>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub b_vec: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GaloisKey {
    #[prost(message, optional, tag = "1")]
    pub ksk: ::core::option::Option<KeySwitchingKey>,
    #[prost(uint32, tag = "2")]
    pub exponent: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EvaluationKey {
    #[prost(message, repeated, tag = "2")]
    pub gk: ::prost::alloc::vec::Vec<GaloisKey>,
    #[prost(uint32, tag = "3")]
    pub ciphertext_level: u32,
    #[prost(uint32, tag = "4")]
    pub evaluation_key_level: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Parameters {
    #[prost(uint32, tag = "1")]
    pub degree: u32,
    #[prost(uint64, repeated, tag = "2")]
    pub moduli: ::prost::alloc::vec::Vec<u64>,
    #[prost(uint64, tag = "3")]
    pub plaintext: u64,
    #[prost(uint32, tag = "4")]
    pub variance: u32,
    /// Extended fields for full serialization (to avoid rebuilding)
    ///
    /// BigUint serialized as bytes
    #[prost(bytes = "vec", tag = "5")]
    pub error1_variance: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, repeated, tag = "6")]
    pub moduli_sizes: ::prost::alloc::vec::Vec<u64>,
    #[prost(uint64, repeated, tag = "7")]
    pub q_mod_t: ::prost::alloc::vec::Vec<u64>,
    #[prost(uint64, repeated, tag = "8")]
    pub matrix_reps_index_map: ::prost::alloc::vec::Vec<u64>,
    /// Serialized Poly objects
    #[prost(bytes = "vec", repeated, tag = "9")]
    pub delta_polynomials: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// Whether op is Some or None
    #[prost(bool, tag = "10")]
    pub has_ntt_operator: bool,
    /// Serialized Context objects (one per level)
    #[prost(bytes = "vec", repeated, tag = "11")]
    pub contexts: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// Serialized NttOperator (if has_ntt_operator is true)
    #[prost(bytes = "vec", tag = "12")]
    pub ntt_operator: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKey {
    #[prost(message, optional, tag = "1")]
    pub c: ::core::option::Option<Ciphertext>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LbfvPublicKey {
    #[prost(message, repeated, tag = "1")]
    pub c: ::prost::alloc::vec::Vec<Ciphertext>,
    #[prost(uint32, tag = "2")]
    pub l: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub seed: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKeyShare {
    #[prost(message, optional, tag = "1")]
    pub p0: ::core::option::Option<Poly>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Poly {
    #[prost(message, optional, boxed, tag = "1")]
    pub p0: ::core::option::Option<::prost::alloc::boxed::Box<Poly>>,
}
