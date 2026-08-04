use std::sync::Arc;

use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::Result;
use crate::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
use crate::lbfv::LBFVPublicKey;
use fhe_math::rq::{Ntt, Poly};

use super::ContributionBinding;

/// A party's bound contribution to threshold l-BFV public-key generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyShare {
    pub(crate) key: LBFVPublicKey,
    pub(crate) binding: Option<ContributionBinding>,
}

impl PublicKeyShare {
    /// Create a bound public-key contribution from a secret-key contribution
    /// and a shared CRS seed.
    pub fn new_with_seed_and_binding<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        binding: ContributionBinding,
        rng: &mut R,
    ) -> Result<Self> {
        let key = LBFVPublicKey::new_with_seed(sk, seed, rng)?;
        Ok(Self {
            key,
            binding: Some(binding),
        })
    }

    /// Create an unbound public-key contribution from explicit CRS polynomials.
    pub fn contribute<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        a_polynomials: &[Poly<Ntt>],
        rng: &mut R,
    ) -> Result<Self> {
        // Use from_crs to build the key from explicit a polynomials; carry no seed.
        let key = LBFVPublicKey::from_crs(sk, a_polynomials, None, rng)?;
        Ok(Self { key, binding: None })
    }

    /// Create a bound public-key contribution from explicit CRS polynomials.
    pub fn contribute_with_binding<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        a_polynomials: &[Poly<Ntt>],
        binding: ContributionBinding,
        rng: &mut R,
    ) -> Result<Self> {
        let key = LBFVPublicKey::from_crs(sk, a_polynomials, None, rng)?;
        Ok(Self {
            key,
            binding: Some(binding),
        })
    }

    /// Create an unbound public-key contribution from a shared CRS vector.
    pub fn contribute_with_crp<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        crp: &CommonRandomPolyVec,
        rng: &mut R,
    ) -> Result<Self> {
        let a_polys = crp.to_polys();
        let key = LBFVPublicKey::from_crs(sk, &a_polys, crp.seed(), rng)?;
        Ok(Self { key, binding: None })
    }

    /// Create a bound public-key contribution from a shared CRS vector.
    pub fn contribute_with_crp_and_binding<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        crp: &CommonRandomPolyVec,
        binding: ContributionBinding,
        rng: &mut R,
    ) -> Result<Self> {
        let a_polys = crp.to_polys();
        let key = LBFVPublicKey::from_crs(sk, &a_polys, crp.seed(), rng)?;
        Ok(Self {
            key,
            binding: Some(binding),
        })
    }

    /// Build a bound public-key contribution from explicit key polynomials.
    pub fn from_parts_with_binding(
        b_polynomials: Vec<Poly<Ntt>>,
        a_polynomials: Vec<Poly<Ntt>>,
        params: Arc<BfvParameters>,
        seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
        binding: ContributionBinding,
    ) -> Result<Self> {
        let key = LBFVPublicKey::from_parts(b_polynomials, a_polynomials, params, seed)?;
        Ok(Self {
            key,
            binding: Some(binding),
        })
    }
}

impl fhe_traits::FheParametrized for PublicKeyShare {
    type Parameters = BfvParameters;
}

#[cfg(feature = "protobuf")]
mod protobuf {
    use super::*;
    use crate::SerializationError;
    use crate::proto::bfv::{LbfvBinding, LbfvPublicKey as LbfvPublicKeyProto};
    use fhe_traits::{DeserializeParametrized, Serialize};
    use prost::Message;

    impl Serialize for PublicKeyShare {
        fn to_bytes(&self) -> Vec<u8> {
            let mut proto: LbfvPublicKeyProto = LbfvPublicKeyProto::from(&self.key);
            if let Some(ref binding) = self.binding {
                proto.binding = Some(LbfvBinding {
                    session_id: binding.participant_set().session_id().to_vec(),
                    participant_ids: binding.participant_set().participant_ids().to_vec(),
                    participant_id: binding.participant_id(),
                    aggregate: false,
                });
            }
            proto.encode_to_vec()
        }
    }

    impl DeserializeParametrized for PublicKeyShare {
        type Error = crate::Error;

        fn from_bytes(bytes: &[u8], params: &Arc<BfvParameters>) -> Result<Self> {
            let proto: LbfvPublicKeyProto = Message::decode(bytes).map_err(|e| {
                crate::Error::SerializationError(SerializationError::ProtobufError {
                    message: e.to_string(),
                })
            })?;

            let binding = match proto.binding {
                Some(ref b) => {
                    if b.aggregate {
                        return Err(crate::Error::SerializationError(
                            SerializationError::InvalidFormat {
                                reason:
                                    "PublicKeyShare binding has aggregate=true; expected contribution binding"
                                        .to_string(),
                            },
                        ));
                    }
                    let session_id: [u8; 32] =
                        b.session_id.as_slice().try_into().map_err(|_| {
                            crate::Error::SerializationError(SerializationError::InvalidFormat {
                                reason: "Invalid session_id length in binding".to_string(),
                            })
                        })?;
                    let participant_set =
                        super::super::ParticipantSet::new(session_id, b.participant_ids.clone())?;
                    let contribution_binding =
                        super::super::ContributionBinding::new(participant_set, b.participant_id)?;
                    Some(contribution_binding)
                }
                None => None,
            };

            // Build the inner key from the proto, clearing the binding first.
            let mut key_proto = proto.clone();
            key_proto.binding = None;
            let key_bytes = key_proto.encode_to_vec();
            let key = LBFVPublicKey::from_bytes(&key_bytes, params)?;

            Ok(Self { key, binding })
        }
    }

    #[cfg(test)]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    mod tests {
        use super::*;

        use crate::bfv::{BfvParameters, SecretKey};
        use crate::trlbfv::{ContributionBinding, ParticipantSet};
        use fhe_traits::{DeserializeParametrized, Serialize};
        use rand::SeedableRng;
        use rand::rng;
        use rand_chacha::ChaCha8Rng;

        #[test]
        fn bound_public_key_share_roundtrip() -> Result<()> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            let participant_set = ParticipantSet::new([1u8; 32], vec![1, 2, 3])?;
            let binding = ContributionBinding::new(participant_set, 2)?;

            let share =
                PublicKeyShare::new_with_seed_and_binding(&sk, seed, binding.clone(), &mut rng)?;
            let bytes = share.to_bytes();
            let restored = PublicKeyShare::from_bytes(&bytes, &params)?;
            assert_eq!(restored.key, share.key);
            assert_eq!(restored.binding, Some(binding));
            Ok(())
        }

        #[test]
        fn unbound_public_key_share_roundtrip() -> Result<()> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let seed = <ChaCha8Rng as SeedableRng>::Seed::default();

            // An unbound share doesn't carry binding.
            let unbounded = PublicKeyShare {
                key: LBFVPublicKey::new_with_seed(&sk, seed, &mut rng)?,
                binding: None,
            };
            let bytes = unbounded.to_bytes();
            let restored = PublicKeyShare::from_bytes(&bytes, &params)?;
            assert_eq!(restored.key, unbounded.key);
            assert_eq!(restored.binding, None);
            Ok(())
        }

        #[test]
        fn rejects_aggregate_binding() -> Result<()> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let seed = <ChaCha8Rng as SeedableRng>::Seed::default();

            let participant_set = ParticipantSet::new([1u8; 32], vec![1, 2])?;
            let binding = ContributionBinding::new(participant_set, 1)?;
            let share = PublicKeyShare::new_with_seed_and_binding(&sk, seed, binding, &mut rng)?;
            let mut proto: LbfvPublicKeyProto = LbfvPublicKeyProto::from(&share.key);
            proto.binding = Some(LbfvBinding {
                session_id: vec![1u8; 32],
                participant_ids: vec![1, 2],
                participant_id: 0,
                aggregate: true,
            });
            let bytes = proto.encode_to_vec();
            assert!(
                PublicKeyShare::from_bytes(&bytes, &params).is_err(),
                "Deserialization must reject aggregate binding on a PublicKeyShare"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
    use crate::mbfv::{Aggregate, AggregateIter};
    use crate::trlbfv::{AggregatedPublicKey, ContributionBinding, ParticipantSet};
    use fhe_traits::{FheDecrypter, FheEncoder, FheEncrypter};
    use rand::{SeedableRng, rng};
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_contribute_and_aggregate() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let participant_set = ParticipantSet::new([1u8; 32], vec![1, 2, 3])?;

        let sks = [
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
        ];

        let seed = [42u8; 32];

        let shares: Vec<PublicKeyShare> = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = ContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                PublicKeyShare::new_with_seed_and_binding(sk, seed, binding, &mut rng)
            })
            .collect::<Result<Vec<_>>>()?;

        let aggregated: AggregatedPublicKey = shares.into_iter().aggregate()?;
        assert_eq!(aggregated.participant_set(), &participant_set);

        // The operational key should encrypt/decrypt correctly with the joint SK.
        let joint_coeffs: Vec<i64> = (0..params.degree())
            .map(|d| sks.iter().map(|sk| sk.coeffs[d]).sum())
            .collect();
        let joint_sk = SecretKey::new(joint_coeffs, &params);
        let pt = crate::bfv::Plaintext::try_encode(&[7u64], crate::bfv::Encoding::poly(), &params)?;
        let ct = aggregated.operational().try_encrypt(&pt, &mut rng)?;
        let dec = joint_sk.try_decrypt(&ct)?;
        assert_eq!(dec, pt);
        Ok(())
    }

    #[test]
    fn test_aggregate_rejects_inconsistent_a_polys() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let participant_set = ParticipantSet::new([2u8; 32], vec![1, 2])?;

        let sk1 = SecretKey::random(&params, &mut rng);
        let sk2 = SecretKey::random(&params, &mut rng);

        // Use different seeds to get different a polys.
        let seed1 = <ChaCha8Rng as SeedableRng>::Seed::default();
        let mut seed2 = <ChaCha8Rng as SeedableRng>::Seed::default();
        seed2[0] ^= 1;

        let share1 = PublicKeyShare::new_with_seed_and_binding(
            &sk1,
            seed1,
            ContributionBinding::new(participant_set.clone(), 1)?,
            &mut rng,
        )?;
        let share2 = PublicKeyShare::new_with_seed_and_binding(
            &sk2,
            seed2,
            ContributionBinding::new(participant_set, 2)?,
            &mut rng,
        )?;

        let result =
            <AggregatedPublicKey as Aggregate<PublicKeyShare>>::from_shares(vec![share1, share2]);
        assert!(
            result.is_err(),
            "Aggregation must reject inconsistent a polynomials"
        );
        Ok(())
    }

    #[test]
    fn aggregate_requires_bound_complete_public_key_set() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let participant_set = ParticipantSet::new([3u8; 32], vec![1, 2, 3])?;

        let sks = [
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
        ];

        let seed = <ChaCha8Rng as SeedableRng>::Seed::default();

        // Only provide 2 out of 3 shares.
        let shares: Vec<PublicKeyShare> = sks
            .iter()
            .take(2)
            .enumerate()
            .map(|(i, sk)| {
                let binding = ContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                PublicKeyShare::new_with_seed_and_binding(sk, seed, binding, &mut rng)
            })
            .collect::<Result<Vec<_>>>()?;

        let result: Result<AggregatedPublicKey> = shares.into_iter().aggregate();
        assert!(
            result.is_err(),
            "Aggregation must reject incomplete participant set"
        );
        Ok(())
    }

    #[test]
    fn contribute_with_crp_preserves_seed_metadata() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);

        let crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        let share = PublicKeyShare::contribute_with_crp(&sk, &crp, &mut rng)?;

        // The inner key should carry the CRP's seed (if any) or be seedless.
        assert_eq!(share.key.seed, crp.seed());
        assert_eq!(share.binding, None);
        Ok(())
    }

    #[test]
    fn aggregation_rejects_unbound_shares() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);

        let sk1 = SecretKey::random(&params, &mut rng);
        let sk2 = SecretKey::random(&params, &mut rng);
        let seed = <ChaCha8Rng as SeedableRng>::Seed::default();

        let share1 = PublicKeyShare {
            key: LBFVPublicKey::new_with_seed(&sk1, seed, &mut rng)?,
            binding: None,
        };
        let share2 = PublicKeyShare {
            key: LBFVPublicKey::new_with_seed(&sk2, seed, &mut rng)?,
            binding: None,
        };

        let result: Result<AggregatedPublicKey> = vec![share1, share2].into_iter().aggregate();
        assert!(result.is_err(), "Aggregation must reject unbound shares");
        Ok(())
    }
}
