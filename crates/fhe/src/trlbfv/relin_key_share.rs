use crate::bfv::{BfvParameters, CommonRandomPolyVec, KeySwitchingKey, SecretKey};
use crate::lbfv::keys::components::{Components, KeyRows, RelinInputs, row_count};
use crate::proto::lbfv::{LbfvRelinKeyContribution, LbfvRelinKeyShare};
use crate::{Result, SerializationError, SerializedField, SerializedObject};
use fhe_math::rq::{NttShoup, Poly};
use fhe_traits::{DeserializeParametrized, FheParametrized, Serialize};
use prost::Message;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Private witness for proving correct construction of a relinearization share.
/// The ephemeral key and each error row are wiped on drop.
pub struct RelinKeyWitness {
    /// Ephemeral secret `r`.
    pub r: Zeroizing<SecretKey>,
    /// Errors in `d0 = -s*d1 + e0 + g*r`.
    pub errors_d0: Vec<Zeroizing<Poly<NttShoup>>>,
    /// Errors in `d2 = r*a + e2 + g*s`.
    pub errors_d2: Vec<Zeroizing<Poly<NttShoup>>>,
}

/// One party's contribution `(d0ᵢ, d2ᵢ)` with the shared `d1` and `a` rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelinKeyShare(pub(super) Components);

impl RelinKeyShare {
    /// Generate with independent URS and CRS seeds, in that order. The CRS
    /// seed must match the public-key contribution's seed.
    pub fn contribute_with_seed<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        d1: [u8; 32],
        a: [u8; 32],
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let count = row_count(&sk.params, ciphertext_level, key_level)?;
        let ctx = sk.params.context_at_level(0)?;
        let inputs = RelinInputs::new(
            &sk.params,
            ciphertext_level,
            KeyRows::seeded(ctx, count, d1),
            KeyRows::seeded(ctx, count, a),
        )?;
        Self::generate(sk, inputs, rng)
    }

    /// Generate from exactly one explicit URS and CRS row per ciphertext modulus.
    pub fn contribute_with_polys<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        d1: Vec<Poly<NttShoup>>,
        a: Vec<Poly<NttShoup>>,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        row_count(&sk.params, ciphertext_level, key_level)?;
        let ctx = sk.params.context_at_level(0)?;
        let inputs = RelinInputs::new(
            &sk.params,
            ciphertext_level,
            KeyRows::explicit(d1, ctx)?,
            KeyRows::explicit(a, ctx)?,
        )?;
        Self::generate(sk, inputs, rng)
    }

    /// Use the leading `#moduli - ciphertext_level` rows of each shared vector.
    /// The key level is zero; the ciphertext context needs at least two moduli.
    pub fn contribute_with_crp<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        d1: &CommonRandomPolyVec,
        a: &CommonRandomPolyVec,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        Self::generate(
            sk,
            Self::crp_inputs(sk, d1, a, ciphertext_level, key_level)?,
            rng,
        )
    }

    /// Like [`Self::contribute_with_crp`], additionally returning the guarded witness.
    pub fn contribute_with_crp_and_witness<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        d1: &CommonRandomPolyVec,
        a: &CommonRandomPolyVec,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<(Self, RelinKeyWitness)> {
        let inputs = Self::crp_inputs(sk, d1, a, ciphertext_level, key_level)?;
        sk.validate_coefficient_count()?;
        let r = Zeroizing::new(SecretKey::random(&sk.params, rng));
        let (parts, errors_d0, errors_d2) =
            inputs.generate_using(sk, &r, rng, |key, from, rows, level, rng| {
                KeySwitchingKey::new_with_c1_guarded(key, from, rows, level, 0, rng)
            })?;
        Ok((
            Self(parts),
            RelinKeyWitness {
                r,
                errors_d0,
                errors_d2,
            },
        ))
    }

    fn crp_inputs(
        sk: &SecretKey,
        d1: &CommonRandomPolyVec,
        a: &CommonRandomPolyVec,
        level: usize,
        key_level: usize,
    ) -> Result<RelinInputs> {
        let count = row_count(&sk.params, level, key_level)?;
        let ctx = sk.params.context_at_level(0)?;
        let d1 = KeyRows::from_crp(d1, ctx, count)?;
        d1.check_crp_tail(a)?;
        RelinInputs::new(&sk.params, level, d1, KeyRows::from_crp(a, ctx, count)?)
    }

    fn generate<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        inputs: RelinInputs,
        rng: &mut R,
    ) -> Result<Self> {
        sk.validate_coefficient_count()?;
        inputs
            .generate(sk, &SecretKey::random(&sk.params, rng), rng)
            .map(Self)
    }

    /// Borrow `d0` in gadget-row order.
    #[must_use]
    pub fn d0_components(&self) -> &[Poly<NttShoup>] {
        &self.0.r_to_s.c0
    }
    /// Borrow the shared URS in gadget-row order.
    #[must_use]
    pub fn d1_components(&self) -> &[Poly<NttShoup>] {
        &self.0.r_to_s.c1
    }
    /// Borrow `d2` in gadget-row order.
    #[must_use]
    pub fn d2_components(&self) -> &[Poly<NttShoup>] {
        &self.0.s_to_r.c0
    }
    /// Borrow the shared CRS in gadget-row order.
    #[must_use]
    pub fn a_components(&self) -> &[Poly<NttShoup>] {
        &self.0.s_to_r.c1
    }
    /// Ciphertext level the resulting key can relinearize.
    #[must_use]
    pub const fn ciphertext_level(&self) -> usize {
        self.0.r_to_s.ciphertext_level
    }
    /// Level of the key-switching rows.
    #[must_use]
    pub const fn key_level(&self) -> usize {
        self.0.r_to_s.ksk_level
    }
}

impl FheParametrized for RelinKeyShare {
    type Parameters = BfvParameters;
}

impl Serialize for RelinKeyShare {
    fn to_bytes(&self) -> Vec<u8> {
        LbfvRelinKeyShare {
            contribution: Some(LbfvRelinKeyContribution {
                ksk_r_to_s: Some((&self.0.r_to_s).into()),
                ksk_s_to_r: Some((&self.0.s_to_r).into()),
            }),
        }
        .encode_to_vec()
    }
}

impl DeserializeParametrized for RelinKeyShare {
    type Error = crate::Error;

    fn from_bytes(bytes: &[u8], params: &Arc<BfvParameters>) -> Result<Self> {
        let envelope =
            LbfvRelinKeyShare::decode(bytes).map_err(|_| SerializationError::Decode {
                object: SerializedObject::RelinKeyShare,
            })?;
        let part = envelope
            .contribution
            .ok_or(SerializationError::MissingField {
                field: SerializedField::RelinKeyShareContribution,
            })?;
        Components::from_protos(part.ksk_r_to_s.as_ref(), part.ksk_s_to_r.as_ref(), params)
            .map(Self)
    }
}
