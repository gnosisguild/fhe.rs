use std::sync::Arc;

use fhe_math::rq::{Ntt, Poly};
use fhe_traits::{DeserializeParametrized, Serialize};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
use crate::lbfv::LBFVPublicKey;
use crate::proto::lbfv::{LbfvPublicKey as LBFVPublicKeyProto, LbfvPublicKeyShare};
use crate::{Error, Result, SerializationError, SerializedField, SerializedObject};
use prost::Message;

/// A party's additive contribution to threshold l-BFV public-key generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyShare {
    pub(crate) key: LBFVPublicKey,
}

impl PublicKeyShare {
    /// Return cloned public-key `b` components (`c[0]`) in gadget-row order.
    pub fn b_components(&self) -> Result<Vec<Poly<Ntt>>> {
        self.key.validate_structure()?;
        self.key
            .c
            .iter()
            .enumerate()
            .map(|(index, ciphertext)| {
                ciphertext.c.first().cloned().ok_or_else(|| {
                    Error::DefaultError(format!(
                        "LBFV public-key ciphertext {index} is missing b component"
                    ))
                })
            })
            .collect()
    }

    /// Return cloned concrete CRS `a` components (`c[1]`) in gadget-row order.
    pub fn a_components(&self) -> Result<Vec<Poly<Ntt>>> {
        self.key.validate_structure()?;
        self.key
            .c
            .iter()
            .enumerate()
            .map(|(index, ciphertext)| {
                ciphertext.c.get(1).cloned().ok_or_else(|| {
                    Error::DefaultError(format!(
                        "LBFV public-key ciphertext {index} is missing a component"
                    ))
                })
            })
            .collect()
    }

    /// Create a public-key contribution from a secret-key contribution and a
    /// shared CRS seed.
    pub fn contribute_with_seed<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Result<Self> {
        Ok(Self {
            key: LBFVPublicKey::new_with_seed(sk, seed, rng)?,
        })
    }

    /// Create a public-key contribution from explicit CRS polynomials.
    ///
    /// The CRS is borrowed so multiple parties can contribute using the same
    /// rows. [`Self::from_parts`] consumes its polynomials to build an owner.
    pub fn contribute_with_polys<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        a_polynomials: &[Poly<Ntt>],
        rng: &mut R,
    ) -> Result<Self> {
        Ok(Self {
            key: LBFVPublicKey::from_crs(sk, a_polynomials, None, rng)?,
        })
    }

    /// Create a public-key contribution from a shared CRS vector.
    pub fn contribute_with_crp<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        crp: &CommonRandomPolyVec,
        rng: &mut R,
    ) -> Result<Self> {
        let a_polys = crp.to_polys();
        Ok(Self {
            key: LBFVPublicKey::from_crs(sk, &a_polys, crp.seed(), rng)?,
        })
    }

    /// Build a public-key contribution from explicit key polynomials.
    ///
    /// Takes ownership of the rows and validates their count, context, and
    /// optional seed. Use [`Self::contribute_with_polys`] to borrow a reusable
    /// CRS instead.
    pub fn from_parts(
        b_polynomials: Vec<Poly<Ntt>>,
        a_polynomials: Vec<Poly<Ntt>>,
        params: Arc<BfvParameters>,
        seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
    ) -> Result<Self> {
        Ok(Self {
            key: LBFVPublicKey::from_parts(b_polynomials, a_polynomials, params, seed)?,
        })
    }
}

impl fhe_traits::FheParametrized for PublicKeyShare {
    type Parameters = BfvParameters;
}

impl Serialize for PublicKeyShare {
    fn to_bytes(&self) -> Vec<u8> {
        LbfvPublicKeyShare {
            key: Some(LBFVPublicKeyProto::from(&self.key)),
        }
        .encode_to_vec()
    }
}

impl DeserializeParametrized for PublicKeyShare {
    type Error = crate::Error;

    fn from_bytes(bytes: &[u8], params: &Arc<BfvParameters>) -> Result<Self> {
        let envelope: LbfvPublicKeyShare =
            crate::serialization::decode(bytes, SerializedObject::TrlbfvPublicKeyShare)?;
        let key = envelope.key.ok_or(Error::SerializationError(
            SerializationError::MissingField {
                field: SerializedField::PublicKeyShareKey,
            },
        ))?;
        Ok(Self {
            key: LBFVPublicKey::from_proto(key, params)?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::aggregate::{Aggregate, AggregateIter};
    use crate::bfv::{Encoding, Plaintext, SecretKey};
    use crate::proto::lbfv::LbfvPublicKeySeeded;
    use crate::support::presets::insecure;
    use fhe_traits::{FheDecrypter, FheEncoder, FheEncrypter};
    use rand::{SeedableRng, rng};

    #[test]
    fn public_key_share_envelope_has_stable_wire_fixture() {
        const FIXTURE: &[u8] = &[
            0x0a, 0x0b, 0x10, 0x02, 0x2a, 0x07, 0x0a, 0x01, 0xaa, 0x12, 0x02, 0xbb, 0xcc,
        ];

        let envelope = LbfvPublicKeyShare {
            key: Some(LBFVPublicKeyProto {
                l: 2,
                explicit: None,
                seeded: Some(LbfvPublicKeySeeded {
                    b: vec![vec![0xaa]],
                    seed: vec![0xbb, 0xcc],
                }),
            }),
        };

        assert_eq!(envelope.encode_to_vec(), FIXTURE);
        assert_eq!(LbfvPublicKeyShare::decode(FIXTURE).unwrap(), envelope);
    }

    #[test]
    fn contributions_aggregate_into_operational_key() -> Result<()> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sks = [
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
        ];
        let seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let shares = sks
            .iter()
            .map(|sk| PublicKeyShare::contribute_with_seed(sk, seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;

        let aggregated: LBFVPublicKey = shares.into_iter().aggregate()?;
        let joint_coeffs = (0..params.degree())
            .map(|index| sks.iter().map(|sk| sk.coeffs[index]).sum())
            .collect();
        let joint_sk = SecretKey::new(joint_coeffs, &params);
        let plaintext = Plaintext::try_encode(&[7u64], Encoding::poly(), &params)?;
        let ciphertext = aggregated.try_encrypt(&plaintext, &mut rng)?;

        assert_eq!(joint_sk.try_decrypt(&ciphertext)?, plaintext);
        Ok(())
    }

    #[test]
    fn aggregation_rejects_inconsistent_crs() -> Result<()> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk1 = SecretKey::random(&params, &mut rng);
        let sk2 = SecretKey::random(&params, &mut rng);
        let seed1 = <ChaCha8Rng as SeedableRng>::Seed::default();
        let mut seed2 = seed1;
        seed2[0] = 1;
        let share1 = PublicKeyShare::contribute_with_seed(&sk1, seed1, &mut rng)?;
        let share2 = PublicKeyShare::contribute_with_seed(&sk2, seed2, &mut rng)?;

        assert!(
            <LBFVPublicKey as Aggregate<PublicKeyShare>>::from_shares([share1, share2]).is_err()
        );
        Ok(())
    }

    #[test]
    fn crp_components_and_serialization_roundtrip() -> Result<()> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let crp = CommonRandomPolyVec::from_seed(&params, [7u8; 32])?;
        let share = PublicKeyShare::contribute_with_crp(&sk, &crp, &mut rng)?;
        let explicit_crs = crp.to_polys();
        let from_polys = PublicKeyShare::contribute_with_polys(&sk, &explicit_crs, &mut rng)?;
        assert_eq!(from_polys.a_components()?, explicit_crs);
        assert!(from_polys.key.seed.is_none());

        assert_eq!(share.key.seed, crp.seed());
        assert_eq!(share.a_components()?, crp.to_polys());
        assert_eq!(share.b_components()?.len(), params.moduli().len());
        let seeded_bytes = share.to_bytes();
        let envelope = LbfvPublicKeyShare::decode(seeded_bytes.as_slice()).unwrap();
        let key = envelope.key.unwrap();
        assert!(key.explicit.is_none());
        assert!(key.seeded.is_some());
        assert_eq!(PublicKeyShare::from_bytes(&seeded_bytes, &params)?, share);

        let explicit = PublicKeyShare::from_parts(
            share.b_components()?,
            share.a_components()?,
            params.clone(),
            None,
        )?;
        let explicit_bytes = explicit.to_bytes();
        assert_eq!(
            PublicKeyShare::from_bytes(&explicit_bytes, &params)?,
            explicit
        );
        assert!(seeded_bytes.len() < explicit_bytes.len());
        Ok(())
    }

    #[test]
    fn contribution_and_operational_key_wire_types_are_not_interchangeable() -> Result<()> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let share = PublicKeyShare::contribute_with_seed(
            &sk,
            <ChaCha8Rng as SeedableRng>::Seed::default(),
            &mut rng,
        )?;
        let operational = share.key.clone();

        assert!(LBFVPublicKey::from_bytes(&share.to_bytes(), &params).is_err());
        assert!(PublicKeyShare::from_bytes(&operational.to_bytes(), &params).is_err());
        Ok(())
    }

    #[test]
    fn aggregation_rejects_zero_shares() {
        let result = Vec::<PublicKeyShare>::new()
            .into_iter()
            .aggregate::<LBFVPublicKey>();
        assert!(result.is_err());
    }
}
