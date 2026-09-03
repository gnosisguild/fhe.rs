//! Ciphertext type for the CKKS encryption scheme.

use crate::ckks::CkksParameters;
use crate::proto::ckks::Ciphertext as CiphertextProto;
use crate::{Error, Result, SerializationError};
use fhe_math::rq::{Ntt, Poly};
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, FheParametrized, Serialize};
use prost::Message;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

/// A CKKS ciphertext.
///
/// Carries the scale of the underlying plaintext so that decryption and
/// decoding can undo the encoding factor. Fresh ciphertexts have two
/// polynomial components `(c0, c1)` such that `c0 + c1*s ~ delta*m + e`.
#[derive(Debug, Clone, PartialEq)]
pub struct CkksCiphertext {
    /// The parameters of the underlying CKKS encryption scheme.
    pub(crate) par: Arc<CkksParameters>,

    /// The ciphertext elements.
    pub(crate) c: Vec<Poly<Ntt>>,

    /// The ciphertext level.
    pub level: usize,

    /// The scale carried by the encrypted plaintext.
    pub scale: f64,
}

impl Deref for CkksCiphertext {
    type Target = [Poly<Ntt>];

    fn deref(&self) -> &Self::Target {
        &self.c
    }
}

impl DerefMut for CkksCiphertext {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.c
    }
}

impl CkksCiphertext {
    /// Create a ciphertext from a vector of polynomials.
    ///
    /// A ciphertext must contain at least two polynomials in NTT
    /// representation sharing the same context.
    pub fn new(
        c: Vec<Poly<Ntt>>,
        scale: f64,
        level: usize,
        par: &Arc<CkksParameters>,
    ) -> Result<Self> {
        if c.len() < 2 {
            return Err(Error::TooFewValues {
                actual: c.len(),
                minimum: 2,
            });
        }
        let expected_ctx = par.context_at_level(level)?;
        for ci in &c {
            if ci.ctx() != expected_ctx {
                return Err(Error::MathError(fhe_math::Error::InvalidContext));
            }
        }
        Ok(Self {
            par: par.clone(),
            c,
            level,
            scale,
        })
    }
}

impl FheParametrized for CkksCiphertext {
    type Parameters = CkksParameters;
}

impl From<&CkksCiphertext> for CiphertextProto {
    fn from(ct: &CkksCiphertext) -> Self {
        CiphertextProto {
            c: ct.c.iter().map(|p| p.to_bytes()).collect(),
            level: ct.level as u32,
            scale: ct.scale,
        }
    }
}

impl Serialize for CkksCiphertext {
    fn to_bytes(&self) -> Vec<u8> {
        CiphertextProto::from(self).encode_to_vec()
    }
}

impl DeserializeParametrized for CkksCiphertext {
    type Error = Error;

    fn from_bytes(bytes: &[u8], par: &Arc<CkksParameters>) -> Result<Self> {
        let proto: CiphertextProto = Message::decode(bytes).map_err(|_| {
            Error::SerializationError(SerializationError::ProtobufError {
                message: "CkksCiphertext decode".into(),
            })
        })?;
        if !(proto.scale.is_finite() && proto.scale >= 1.0) {
            return Err(Error::SerializationError(
                SerializationError::InvalidFormat {
                    reason: format!("invalid CKKS scale: {}", proto.scale),
                },
            ));
        }
        let level = proto.level as usize;
        let ctx = par.context_at_level(level)?;
        let c = proto
            .c
            .iter()
            .map(|b| Poly::<Ntt>::from_bytes(b, ctx).map_err(Error::MathError))
            .collect::<Result<Vec<_>>>()?;
        Self::new(c, proto.scale, level, par)
    }
}
