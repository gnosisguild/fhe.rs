use super::LBFVPublicKey;
use crate::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
use crate::proto::lbfv::LbfvPublicKeyShare;
use crate::{EvaluationKeyError, Result, SerializationError, SerializedField, SerializedObject};
use fhe_math::rq::{Ntt, Poly};
use fhe_traits::{DeserializeParametrized, FheParametrized, Serialize};
use prost::Message;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

/// One party's public contribution `(bᵢ, a)` to a collective l-BFV public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyShare(pub(super) LBFVPublicKey);

impl PublicKeyShare {
    /// Generate under the committee's shared CRS seed.
    pub fn contribute_with_seed<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        seed: [u8; 32],
        rng: &mut R,
    ) -> Result<Self> {
        LBFVPublicKey::try_new_with_seed(sk, seed, rng).map(Self)
    }

    /// Generate using explicit CRS polynomials.
    pub fn contribute_with_polys<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        a: &[Poly<Ntt>],
        rng: &mut R,
    ) -> Result<Self> {
        LBFVPublicKey::from_crs(sk, a.to_vec(), None, rng).map(Self)
    }

    /// Generate from a shared vector, retaining its verified seed if present.
    pub fn contribute_with_crp<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        crp: &CommonRandomPolyVec,
        rng: &mut R,
    ) -> Result<Self> {
        LBFVPublicKey::new_with_crp(sk, crp, rng).map(Self)
    }

    /// Import a contribution's concrete public rows and optional CRS seed.
    pub fn from_parts(
        b: Vec<Poly<Ntt>>,
        a: Vec<Poly<Ntt>>,
        params: Arc<BfvParameters>,
        seed: Option<[u8; 32]>,
    ) -> Result<Self> {
        LBFVPublicKey::from_parts(b, a, params, seed).map(Self)
    }

    /// Clone the contribution's `b` components in gadget-row order.
    pub fn b_components(&self) -> Result<Vec<Poly<Ntt>>> {
        self.components(0)
    }

    /// Clone the concrete CRS components in gadget-row order.
    pub fn a_components(&self) -> Result<Vec<Poly<Ntt>>> {
        self.components(1)
    }

    fn components(&self, index: usize) -> Result<Vec<Poly<Ntt>>> {
        self.0
            .c
            .iter()
            .map(|row| {
                row.get(index).cloned().ok_or_else(|| {
                    EvaluationKeyError::InvalidLbfvLayout {
                        reason: "public-key contribution is missing a row component",
                    }
                    .into()
                })
            })
            .collect()
    }
}

impl FheParametrized for PublicKeyShare {
    type Parameters = BfvParameters;
}

impl Serialize for PublicKeyShare {
    fn to_bytes(&self) -> Vec<u8> {
        LbfvPublicKeyShare {
            key: Some((&self.0).into()),
        }
        .encode_to_vec()
    }
}

impl DeserializeParametrized for PublicKeyShare {
    type Error = crate::Error;

    fn from_bytes(bytes: &[u8], params: &Arc<BfvParameters>) -> Result<Self> {
        let envelope =
            LbfvPublicKeyShare::decode(bytes).map_err(|_| SerializationError::Decode {
                object: SerializedObject::TrlbfvPublicKeyShare,
            })?;
        let key = envelope.key.ok_or(SerializationError::MissingField {
            field: SerializedField::PublicKeyShareKey,
        })?;
        LBFVPublicKey::from_proto(key, params).map(Self)
    }
}
