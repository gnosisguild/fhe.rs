#![allow(missing_docs)]
// Hand-written prost structs mirroring ckks.proto (same convention as the
// generated BFV/TRBFV modules).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ciphertext {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub c: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint32, tag = "2")]
    pub level: u32,
    #[prost(double, tag = "3")]
    pub scale: f64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKey {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub c: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SecretKey {
    #[prost(sint64, repeated, tag = "1")]
    pub coeffs: ::prost::alloc::vec::Vec<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Parameters {
    #[prost(uint32, tag = "1")]
    pub degree: u32,
    #[prost(uint64, repeated, tag = "2")]
    pub moduli: ::prost::alloc::vec::Vec<u64>,
    #[prost(uint32, tag = "3")]
    pub variance: u32,
    #[prost(double, tag = "4")]
    pub scale: f64,
    /// Special primes `p_1..p_k` for hybrid key switching (empty = disabled).
    #[prost(uint64, repeated, tag = "5")]
    pub special_moduli: ::prost::alloc::vec::Vec<u64>,
    /// Number of gadget digits of hybrid keys (0 = default `ceil(L/k)`).
    #[prost(uint32, tag = "6")]
    pub dnum: u32,
}
