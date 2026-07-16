#![warn(missing_docs)]
// Expect indexing in BFV cryptographic operations for performance
#![expect(
    clippy::indexing_slicing,
    reason = "performance or example code relies on validated indices"
)]

//! The Brakerski-Fan-Vercauteren homomorphic encryption scheme.
//!
//! # Ciphertext addition and subtraction
//!
//! Ciphertext-to-ciphertext addition and subtraction are fallible because the
//! operands must use the same [`BfvParameters`] instance and ciphertext level.
//! The `+` and `-` operators therefore return [`crate::Result<Ciphertext>`]:
//!
//! ```
//! # use fhe::bfv::{BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
//! # use fhe_traits::{FheEncoder, FheEncrypter};
//! # use rand::rng;
//! # fn example() -> fhe::Result<()> {
//! # let parameters = BfvParametersBuilder::new()
//! #     .set_degree(2048)
//! #     .set_moduli(&[0x3fffffff000001])
//! #     .set_plaintext_modulus(1 << 10)
//! #     .build_arc()?;
//! # let secret_key = SecretKey::random(&parameters, &mut rng());
//! # let plaintext = Plaintext::try_encode(&[1_u64], Encoding::poly(), &parameters)?;
//! # let lhs: Ciphertext = secret_key.try_encrypt(&plaintext, &mut rng())?;
//! # let rhs: Ciphertext = secret_key.try_encrypt(&plaintext, &mut rng())?;
//! let sum = (&lhs + &rhs)?;
//! let difference = (&lhs - &rhs)?;
//! # let _ = (sum, difference);
//! # Ok(())
//! # }
//! ```
//!
//! For accumulation, use [`Ciphertext::try_add_assign`] or
//! [`Ciphertext::try_sub_assign`]. Ciphertext `+=` and `-=` are intentionally
//! not implemented because Rust's assignment operator traits cannot return an
//! error.
//!
//! Ciphertexts may have different component counts, for example after an
//! unrelinearized multiplication. Addition and subtraction treat missing
//! higher-degree components as zero and return the larger component count.

mod ciphertext;
mod context;
mod encoding;
mod keys;
mod ops;
mod parameters;
mod plaintext;
mod plaintext_vec;
mod rgsw_ciphertext;

pub mod traits;
pub use ciphertext::Ciphertext;
pub use context::{CipherPlainContext, ContextLevel};
pub use encoding::Encoding;
pub use keys::{
    EvaluationKey, EvaluationKeyBuilder, KeySwitchingKey, PublicKey, RelinearizationKey, SecretKey,
};
pub use ops::{Multiplicator, dot_product_scalar};
pub(crate) use parameters::PlaintextModulus;
pub use parameters::{BfvParameters, BfvParametersBuilder};
pub use plaintext::Plaintext;
pub(crate) use plaintext::PlaintextValues;
pub use plaintext_vec::PlaintextVec;
pub use rgsw_ciphertext::RGSWCiphertext;
