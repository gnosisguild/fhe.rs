//! The Multiparty BFV scheme, as described by Christian Mouchet et. al.
//! in [Multiparty Homomorphic Encryption from Ring-Learning-with-Errors](https://eprint.iacr.org/2020/304.pdf).

mod key_gen;

pub use key_gen::PublicKeyShare;