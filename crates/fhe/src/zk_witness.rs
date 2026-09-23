//! Witness values for zero-knowledge proofs of BFV operations.
//!
//! Each type has private fields and zeroizes its polynomials when dropped. Keep a witness only
//! while constructing its proof input.

use fhe_math::rq::{Ntt, Poly};
use zeroize::Zeroize;

/// BFV public-key generation intermediates required by a proof.
pub struct BfvKeyGeneration {
    pub(crate) a: Poly<Ntt>,
    pub(crate) secret_key: Poly<Ntt>,
    pub(crate) error: Poly<Ntt>,
}

impl BfvKeyGeneration {
    /// Returns the sampled polynomial `a`.
    #[must_use]
    pub fn a(&self) -> &Poly<Ntt> {
        &self.a
    }

    /// Returns the secret-key polynomial in NTT form.
    #[must_use]
    pub fn secret_key(&self) -> &Poly<Ntt> {
        &self.secret_key
    }

    /// Returns the public-key error polynomial.
    #[must_use]
    pub fn error(&self) -> &Poly<Ntt> {
        &self.error
    }
}

impl Zeroize for BfvKeyGeneration {
    fn zeroize(&mut self) {
        self.a.zeroize();
        self.secret_key.zeroize();
        self.error.zeroize();
    }
}

impl Drop for BfvKeyGeneration {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Intermediates required to prove a BFV or l-BFV encryption.
pub struct Encryption {
    pub(crate) randomness: Poly<Ntt>,
    pub(crate) error_0: Poly<Ntt>,
    pub(crate) error_1: Poly<Ntt>,
}

impl Encryption {
    /// Returns the encryption randomness polynomial.
    #[must_use]
    pub fn randomness(&self) -> &Poly<Ntt> {
        &self.randomness
    }

    /// Returns the first encryption error polynomial.
    #[must_use]
    pub fn error_0(&self) -> &Poly<Ntt> {
        &self.error_0
    }

    /// Returns the second encryption error polynomial.
    #[must_use]
    pub fn error_1(&self) -> &Poly<Ntt> {
        &self.error_1
    }
}

impl Zeroize for Encryption {
    fn zeroize(&mut self) {
        self.randomness.zeroize();
        self.error_0.zeroize();
        self.error_1.zeroize();
    }
}

impl Drop for Encryption {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Intermediates required to prove multiparty BFV public-key share generation.
pub struct MbfvPublicKeyShare {
    pub(crate) secret_key: Poly<Ntt>,
    pub(crate) error: Poly<Ntt>,
}

impl MbfvPublicKeyShare {
    /// Returns the secret-key share polynomial in NTT form.
    #[must_use]
    pub fn secret_key(&self) -> &Poly<Ntt> {
        &self.secret_key
    }

    /// Returns the public-key share error polynomial.
    #[must_use]
    pub fn error(&self) -> &Poly<Ntt> {
        &self.error
    }
}

impl Zeroize for MbfvPublicKeyShare {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
        self.error.zeroize();
    }
}

impl Drop for MbfvPublicKeyShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}
