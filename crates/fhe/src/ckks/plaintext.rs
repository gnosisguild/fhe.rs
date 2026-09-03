//! Plaintext type for the CKKS encryption scheme.

use crate::ckks::CkksParameters;
use fhe_math::rq::{Ntt, Poly};
use fhe_traits::FheParametrized;
use std::sync::Arc;

/// A CKKS plaintext: a ring element carrying encoded, scaled real values.
///
/// The `scale` records the factor `delta` applied at encoding time; decoding
/// divides by it. Unlike BFV, there is no plaintext modulus: the plaintext
/// polynomial lives directly in `R_q`.
#[derive(Debug, Clone)]
pub struct CkksPlaintext {
    /// The CKKS parameters.
    pub(crate) par: Arc<CkksParameters>,

    /// The plaintext polynomial in NTT representation.
    pub(crate) poly: Poly<Ntt>,

    /// The scale factor applied at encoding time.
    pub scale: f64,

    /// The level of the plaintext (0 = full moduli chain).
    pub level: usize,
}

impl CkksPlaintext {
    /// Returns the plaintext polynomial.
    #[must_use]
    pub fn poly(&self) -> &Poly<Ntt> {
        &self.poly
    }
}

impl FheParametrized for CkksPlaintext {
    type Parameters = CkksParameters;
}
