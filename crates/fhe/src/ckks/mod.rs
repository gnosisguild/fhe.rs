#![warn(missing_docs)]
// Expect indexing in CKKS cryptographic operations for performance
#![expect(
    clippy::indexing_slicing,
    reason = "performance or example code relies on validated indices"
)]

//! The Cheon-Kim-Kim-Song (CKKS) approximate homomorphic encryption scheme.
//!
//! Single-key CKKS (Cheon–Kim–Kim–Song, *Homomorphic Encryption for
//! Arithmetic of Approximate Numbers*, <https://eprint.iacr.org/2016/421>)
//! in its RNS form (Cheon–Han–Kim–Kim–Song, <https://eprint.iacr.org/2018/931>):
//!
//! - [`parameters`]: `CkksParameters` — degree, RNS modulus chain
//!   (level `l` = first `L - l` limbs), scale `delta`.
//! - [`encoder`]: canonical-embedding encoder (`N/2` real slots).
//! - [`keys`]: `CkksSecretKey` (CBD-sampled, zeroized on drop) and
//!   `CkksPublicKey`; `try_encrypt_extended` exposes the encryption
//!   randomness for proof-of-encryption circuits.
//! - [`ops`]: add/sub/neg, plaintext add/mul, ciphertext mul (three
//!   components), rescale, level alignment.
//! - [`relin_key`]: leveled RNS-decomposition relinearization key
//!   (`s^2 -> s`).
//! - [`hybrid`]: hybrid (special-prime + digit-decomposition) key switching
//!   — ONE `CkksHybridRelinKey` at modulus `Q·P` serves every level with
//!   `dnum ≈ L/k` digits and `1/P`-reduced noise; also the generic
//!   `CkksHybridKeySwitchKey` (`s' -> s`). Enabled by
//!   `CkksParametersBuilder::set_special_moduli_sizes`.
//!
//! The threshold / multiparty layer lives in [`crate::trckks`].
//!
//! Unlike BFV, CKKS encodes vectors of real numbers into ring elements with a
//! scale factor `delta`. Decryption is approximate: the decrypted values carry
//! a small error that depends on the encryption noise and the scale.

mod ciphertext;
mod encoder;
pub(crate) mod hybrid;
mod keys;
mod ops;
mod parameters;
mod plaintext;
mod relin_key;
pub(crate) mod wire;

pub use ciphertext::CkksCiphertext;
pub use encoder::CkksEncoder;
pub use hybrid::{CkksHybridKeySwitchKey, CkksHybridRelinKey, CkksQpPoly};
pub use keys::{CkksPublicKey, CkksSecretKey};
pub use parameters::{CkksParameters, CkksParametersBuilder};
pub use plaintext::CkksPlaintext;
pub use relin_key::CkksRelinearizationKey;
