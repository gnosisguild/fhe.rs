use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use zeroize::Zeroizing;

use crate::Result;
use crate::bfv::{BfvParameters, CommonRandomPolyVec, KeySwitchingKey, SecretKey};
use crate::lbfv::LBFVRelinearizationKey;
use fhe_math::rq::{NttShoup, Poly};
use fhe_traits::FheParametrized;

use super::ContributionBinding;
use crate::SerializationError;
use crate::bfv::traits::TryConvertFrom;
use crate::proto::bfv::{KeySwitchingKey as KeySwitchingKeyProto, LbfvBinding, LbfvRelinKeyShare};
use fhe_traits::{DeserializeParametrized, Serialize};
use prost::Message;
use std::sync::Arc;

/// Witness material produced alongside an [`RelinKeyShare`] for ZK proof generation.
///
/// Holds the private values that a party must commit to in order to prove
/// correct construction of its relinearization-key contribution.  The witness
/// must be kept confidential and **zeroized after use**.
pub struct RlkWitness {
    /// Ephemeral randomness key used during RLK generation.
    /// Auto-zeroized when dropped.
    pub r: Zeroizing<SecretKey>,
    /// Per-row errors from `ksk_r_to_s`: `eᵢ` such that `d0ᵢ = eᵢ − sk·d1ᵢ + rᵢ·g`.
    pub errors_d0: Vec<Poly<NttShoup>>,
    /// Per-row errors from `ksk_s_to_r`: `eᵢ` such that `d2ᵢ = eᵢ + r·aᵢ + skᵢ·g`.
    pub errors_d2: Vec<Poly<NttShoup>>,
}

/// A party's additive contribution to threshold l-BFV relinearization-key
/// generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelinKeyShare {
    pub(crate) ksk_r_to_s: KeySwitchingKey,
    pub(crate) ksk_s_to_r: KeySwitchingKey,
    pub(crate) binding: Option<ContributionBinding>,
}

impl FheParametrized for RelinKeyShare {
    type Parameters = BfvParameters;
}

impl RelinKeyShare {
    /// Generate an unbound relinearization-key contribution from shared seeds.
    pub fn contribution<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        d1_seed: <ChaCha8Rng as SeedableRng>::Seed,
        a_seed: <ChaCha8Rng as SeedableRng>::Seed,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let (ksk_r_to_s, ksk_s_to_r) = LBFVRelinearizationKey::generate_components_with_seed(
            sk,
            d1_seed,
            a_seed,
            ciphertext_level,
            key_level,
            rng,
        )?;
        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
            binding: None,
        })
    }

    /// Generate a bound relinearization-key contribution from shared seeds.
    pub fn contribution_with_binding<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        d1_seed: <ChaCha8Rng as SeedableRng>::Seed,
        a_seed: <ChaCha8Rng as SeedableRng>::Seed,
        binding: ContributionBinding,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let mut share = Self::contribution(sk, d1_seed, a_seed, ciphertext_level, key_level, rng)?;
        share.binding = Some(binding);
        Ok(share)
    }

    /// Generate an unbound relinearization-key contribution from explicit
    /// URS/CRS polynomials.
    pub fn contribution_with_polys<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        d1_polys: Vec<Poly<NttShoup>>,
        a_polys: Vec<Poly<NttShoup>>,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let (ksk_r_to_s, ksk_s_to_r) = LBFVRelinearizationKey::generate_components_with_polys(
            sk,
            d1_polys,
            a_polys,
            ciphertext_level,
            key_level,
            rng,
        )?;
        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
            binding: None,
        })
    }

    /// Generate a bound relinearization-key contribution from explicit
    /// URS/CRS polynomials.
    pub fn contribution_with_polys_and_binding<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        d1_polys: Vec<Poly<NttShoup>>,
        a_polys: Vec<Poly<NttShoup>>,
        binding: ContributionBinding,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let mut share =
            Self::contribution_with_polys(sk, d1_polys, a_polys, ciphertext_level, key_level, rng)?;
        share.binding = Some(binding);
        Ok(share)
    }

    /// Generate an unbound relinearization-key contribution from shared CRP
    /// vectors.
    pub fn contribution_with_crp<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        crp_d1: &CommonRandomPolyVec,
        crp_a: &CommonRandomPolyVec,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let d1_polys: Vec<Poly<NttShoup>> = crp_d1
            .to_polys()
            .into_iter()
            .map(|p| p.into_ntt_shoup())
            .collect();
        let a_polys: Vec<Poly<NttShoup>> = crp_a
            .to_polys()
            .into_iter()
            .map(|p| p.into_ntt_shoup())
            .collect();

        let (mut ksk_r_to_s, mut ksk_s_to_r) =
            LBFVRelinearizationKey::generate_components_with_polys(
                sk,
                d1_polys,
                a_polys,
                ciphertext_level,
                key_level,
                rng,
            )?;

        // Preserve the CRP master seeds as KSK metadata when present.
        ksk_r_to_s.seed = crp_d1.seed();
        ksk_s_to_r.seed = crp_a.seed();

        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
            binding: None,
        })
    }

    /// Generate a bound relinearization-key contribution from shared CRP
    /// vectors.
    pub fn contribution_with_crp_and_binding<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        crp_d1: &CommonRandomPolyVec,
        crp_a: &CommonRandomPolyVec,
        binding: ContributionBinding,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let mut share =
            Self::contribution_with_crp(sk, crp_d1, crp_a, ciphertext_level, key_level, rng)?;
        share.binding = Some(binding);
        Ok(share)
    }

    /// Like [`contribution_with_crp`](Self::contribution_with_crp) but also
    /// returns an [`RlkWitness`] containing the ephemeral key `r` and the
    /// per-row error polynomials needed for ZK witness generation.
    pub fn contribution_with_crp_extended<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        crp_d1: &CommonRandomPolyVec,
        crp_a: &CommonRandomPolyVec,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<(Self, RlkWitness)> {
        let d1_polys: Vec<Poly<NttShoup>> = crp_d1
            .to_polys()
            .into_iter()
            .map(|p| p.into_ntt_shoup())
            .collect();
        let a_polys: Vec<Poly<NttShoup>> = crp_a
            .to_polys()
            .into_iter()
            .map(|p| p.into_ntt_shoup())
            .collect();

        let (mut ksk_r_to_s, mut ksk_s_to_r, r, errors_d0, errors_d2) =
            LBFVRelinearizationKey::generate_components_with_polys_extended(
                sk,
                d1_polys,
                a_polys,
                ciphertext_level,
                key_level,
                rng,
            )?;

        ksk_r_to_s.seed = crp_d1.seed();
        ksk_s_to_r.seed = crp_a.seed();

        Ok((
            Self {
                ksk_r_to_s,
                ksk_s_to_r,
                binding: None,
            },
            RlkWitness {
                r,
                errors_d0,
                errors_d2,
            },
        ))
    }

    /// Like [`contribution_with_crp_and_binding`](Self::contribution_with_crp_and_binding)
    /// but also returns an [`RlkWitness`] for ZK witness generation.
    pub fn contribution_with_crp_and_binding_extended<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        crp_d1: &CommonRandomPolyVec,
        crp_a: &CommonRandomPolyVec,
        binding: ContributionBinding,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<(Self, RlkWitness)> {
        let (mut share, witness) = Self::contribution_with_crp_extended(
            sk,
            crp_d1,
            crp_a,
            ciphertext_level,
            key_level,
            rng,
        )?;
        share.binding = Some(binding);
        Ok((share, witness))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::aggregate::AggregateIter;
    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};
    use crate::trlbfv::{
        AggregatedPublicKey, ContributionBinding, ParticipantSet, PublicKeyShare,
        aggregate_relinearization_key,
    };
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::{SeedableRng, rng};
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_distributed_relinearization() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let participant_set = ParticipantSet::new([1u8; 32], vec![1, 2])?;

        let sks = [
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
        ];

        let pk_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = [10u8; 32];
        // CRS binding: the RLK's a_seed must match the PK's seed.
        let a_seed = pk_seed;

        // 1. Create bound public-key shares and aggregate.
        let pk_shares: Vec<PublicKeyShare> = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = ContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                PublicKeyShare::new_with_seed_and_binding(sk, pk_seed, binding, &mut rng)
            })
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: AggregatedPublicKey = pk_shares.into_iter().aggregate()?;

        // 2. Create bound RLK shares and aggregate.
        let rlk_shares: Vec<RelinKeyShare> = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = ContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                RelinKeyShare::contribution_with_binding(
                    sk, d1_seed, a_seed, binding, 0, 0, &mut rng,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let relin_key = aggregate_relinearization_key(&rlk_shares, &aggregated_pk)?;

        // 3. Encrypt, multiply, relinearize, decrypt.
        let pt = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;
        let ct = aggregated_pk.operational().try_encrypt(&pt, &mut rng)?;
        let mut square = &ct * &ct;
        relin_key.relinearizes(&mut square)?;

        // Build joint secret key.
        let joint_coeffs: Vec<i64> = (0..params.degree())
            .map(|d| sks.iter().map(|sk| sk.coeffs[d]).sum())
            .collect();
        let joint_sk = SecretKey::new(joint_coeffs, &params);
        let decoded = Vec::<u64>::try_decode(&joint_sk.try_decrypt(&square)?, Encoding::poly())?;
        assert_eq!(decoded.first(), Some(&9));
        Ok(())
    }

    #[test]
    fn test_distributed_relinearization_large_participant_set() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let ids: Vec<u32> = (1..=5).collect();
        let participant_set = ParticipantSet::new([5u8; 32], ids.clone())?;

        let sks: Vec<SecretKey> = ids
            .iter()
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        let pk_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = [10u8; 32];
        let a_seed = pk_seed;

        let pk_shares: Vec<PublicKeyShare> = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = ContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                PublicKeyShare::new_with_seed_and_binding(sk, pk_seed, binding, &mut rng)
            })
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: AggregatedPublicKey = pk_shares.into_iter().aggregate()?;

        let rlk_shares: Vec<RelinKeyShare> = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = ContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                RelinKeyShare::contribution_with_binding(
                    sk, d1_seed, a_seed, binding, 0, 0, &mut rng,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let relin_key = aggregate_relinearization_key(&rlk_shares, &aggregated_pk)?;

        let pt = Plaintext::try_encode(&[2u64], Encoding::poly(), &params)?;
        let ct = aggregated_pk.operational().try_encrypt(&pt, &mut rng)?;
        let mut square = &ct * &ct;
        relin_key.relinearizes(&mut square)?;

        let joint_coeffs: Vec<i64> = (0..params.degree())
            .map(|d| sks.iter().map(|sk| sk.coeffs[d]).sum())
            .collect();
        let joint_sk = SecretKey::new(joint_coeffs, &params);
        let decoded = Vec::<u64>::try_decode(&joint_sk.try_decrypt(&square)?, Encoding::poly())?;
        assert_eq!(decoded.first(), Some(&4));
        Ok(())
    }

    #[test]
    fn rlk_aggregation_rejects_shares_from_different_session() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let ps1 = ParticipantSet::new([1u8; 32], vec![1, 2])?;
        let ps2 = ParticipantSet::new([2u8; 32], vec![1, 2])?; // Different session_id

        let sks = [
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
        ];

        let pk_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = [10u8; 32];
        let a_seed = pk_seed; // CRS must match for other checks to pass

        let pk_shares: Vec<PublicKeyShare> = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = ContributionBinding::new(ps1.clone(), (i + 1) as u32)?;
                PublicKeyShare::new_with_seed_and_binding(sk, pk_seed, binding, &mut rng)
            })
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: AggregatedPublicKey = pk_shares.into_iter().aggregate()?;

        // RLK share 1 uses ps1 (session [1u8;32]), RLK share 2 uses ps2 (session [2u8;32]).
        let rlk1 = RelinKeyShare::contribution_with_binding(
            &sks[0],
            d1_seed,
            a_seed,
            ContributionBinding::new(ps1.clone(), 1)?,
            0,
            0,
            &mut rng,
        )?;
        let rlk2 = RelinKeyShare::contribution_with_binding(
            &sks[1],
            d1_seed,
            a_seed,
            ContributionBinding::new(ps2, 2)?,
            0,
            0,
            &mut rng,
        )?;

        let result = aggregate_relinearization_key(&[rlk1, rlk2], &aggregated_pk);
        assert!(
            result.is_err(),
            "RLK aggregation must reject shares from different sessions"
        );
        Ok(())
    }

    #[test]
    fn rlk_aggregation_rejects_different_pk_participant_set() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);

        // PK uses participant set {1,2}, RLK uses {3,4}.
        let ps_pk = ParticipantSet::new([1u8; 32], vec![1, 2])?;
        let ps_rlk = ParticipantSet::new([1u8; 32], vec![3, 4])?;

        let sks = [
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
        ];

        let pk_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = [10u8; 32];
        let a_seed = pk_seed; // CRS must match for participant set check to trigger

        let pk_shares: Vec<PublicKeyShare> = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = ContributionBinding::new(ps_pk.clone(), (i + 1) as u32)?;
                PublicKeyShare::new_with_seed_and_binding(sk, pk_seed, binding, &mut rng)
            })
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: AggregatedPublicKey = pk_shares.into_iter().aggregate()?;

        let rlk_shares: Vec<RelinKeyShare> = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = ContributionBinding::new(ps_rlk.clone(), 3 + i as u32)?;
                RelinKeyShare::contribution_with_binding(
                    sk, d1_seed, a_seed, binding, 0, 0, &mut rng,
                )
            })
            .collect::<Result<Vec<_>>>()?;

        let result = aggregate_relinearization_key(&rlk_shares, &aggregated_pk);
        assert!(
            result.is_err(),
            "RLK aggregation must reject when RLK participant set differs from PK participant set"
        );
        Ok(())
    }

    #[test]
    fn aggregate_checks_participant_sets_and_component_linearity() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let participant_set = ParticipantSet::new([6u8; 32], vec![1, 2, 3])?;

        let sks = [
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
        ];
        let pk_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = [10u8; 32];
        let a_seed = pk_seed;

        // Aggregate public key.
        let pk_shares: Vec<PublicKeyShare> = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = ContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                PublicKeyShare::new_with_seed_and_binding(sk, pk_seed, binding, &mut rng)
            })
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: AggregatedPublicKey = pk_shares.into_iter().aggregate()?;
        assert_eq!(aggregated_pk.participant_set().participant_ids().len(), 3);

        // Aggregate relinearization keys.
        let rlk_shares: Vec<RelinKeyShare> = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = ContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                RelinKeyShare::contribution_with_binding(
                    sk, d1_seed, a_seed, binding, 0, 0, &mut rng,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let relin_key = aggregate_relinearization_key(&rlk_shares, &aggregated_pk)?;

        // Verify functionality.
        let pt = Plaintext::try_encode(&[5u64], Encoding::poly(), &params)?;
        let ct = aggregated_pk.operational().try_encrypt(&pt, &mut rng)?;
        let mut square = &ct * &ct;
        relin_key.relinearizes(&mut square)?;

        let joint_coeffs: Vec<i64> = (0..params.degree())
            .map(|d| sks.iter().map(|sk| sk.coeffs[d]).sum())
            .collect();
        let joint_sk = SecretKey::new(joint_coeffs, &params);
        let decoded = Vec::<u64>::try_decode(&joint_sk.try_decrypt(&square)?, Encoding::poly())?;
        assert_eq!(decoded.first(), Some(&25));
        Ok(())
    }
}

impl Serialize for RelinKeyShare {
    fn to_bytes(&self) -> Vec<u8> {
        let mut proto = LbfvRelinKeyShare {
            ksk_r_to_s: Some(KeySwitchingKeyProto::from(&self.ksk_r_to_s)),
            ksk_s_to_r: Some(KeySwitchingKeyProto::from(&self.ksk_s_to_r)),
            binding: None,
        };
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

impl DeserializeParametrized for RelinKeyShare {
    type Error = crate::Error;

    fn from_bytes(bytes: &[u8], params: &Arc<BfvParameters>) -> Result<Self> {
        let proto: LbfvRelinKeyShare = Message::decode(bytes).map_err(|e| {
            crate::Error::SerializationError(SerializationError::ProtobufError {
                message: e.to_string(),
            })
        })?;

        let ksk_r_to_s = proto
            .ksk_r_to_s
            .as_ref()
            .ok_or_else(|| {
                crate::Error::SerializationError(SerializationError::InvalidFormat {
                    reason: "Missing ksk_r_to_s in RelinKeyShare proto".to_string(),
                })
            })
            .and_then(|ksk| KeySwitchingKey::try_convert_from(ksk, params))?;
        let ksk_s_to_r = proto
            .ksk_s_to_r
            .as_ref()
            .ok_or_else(|| {
                crate::Error::SerializationError(SerializationError::InvalidFormat {
                    reason: "Missing ksk_s_to_r in RelinKeyShare proto".to_string(),
                })
            })
            .and_then(|ksk| KeySwitchingKey::try_convert_from(ksk, params))?;

        let binding = match proto.binding {
            Some(ref b) => {
                if b.aggregate {
                    return Err(crate::Error::SerializationError(
                        SerializationError::InvalidFormat {
                            reason:
                                "RelinKeyShare binding has aggregate=true; expected contribution binding"
                                    .to_string(),
                        },
                    ));
                }
                let session_id: [u8; 32] = b.session_id.as_slice().try_into().map_err(|_| {
                    crate::Error::SerializationError(SerializationError::InvalidFormat {
                        reason: "Invalid session_id length in RelinKeyShare binding".to_string(),
                    })
                })?;
                let participant_set =
                    super::ParticipantSet::new(session_id, b.participant_ids.clone())?;
                let contribution_binding =
                    super::ContributionBinding::new(participant_set, b.participant_id)?;
                Some(contribution_binding)
            }
            None => None,
        };

        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
            binding,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod proto_tests {
    use super::*;

    use crate::bfv::{BfvParameters, SecretKey};
    use crate::trlbfv::{ContributionBinding, ParticipantSet};
    use fhe_traits::{DeserializeParametrized, Serialize};
    use rand::SeedableRng;
    use rand::rng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn bound_rlk_share_roundtrip() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = <ChaCha8Rng as SeedableRng>::Seed::from([2u8; 32]);
        let participant_set = ParticipantSet::new([1u8; 32], vec![1, 2, 3])?;
        let binding = ContributionBinding::new(participant_set, 2)?;

        let share = RelinKeyShare::contribution_with_binding(
            &sk,
            d1_seed,
            a_seed,
            binding.clone(),
            0,
            0,
            &mut rng,
        )?;
        let bytes = share.to_bytes();
        let restored = RelinKeyShare::from_bytes(&bytes, &params)?;
        assert_eq!(restored.ksk_r_to_s, share.ksk_r_to_s);
        assert_eq!(restored.ksk_s_to_r, share.ksk_s_to_r);
        assert_eq!(restored.binding, Some(binding));
        Ok(())
    }

    #[test]
    fn unbound_rlk_share_roundtrip() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = <ChaCha8Rng as SeedableRng>::Seed::from([2u8; 32]);

        let share = RelinKeyShare::contribution(&sk, d1_seed, a_seed, 0, 0, &mut rng)?;
        let bytes = share.to_bytes();
        let restored = RelinKeyShare::from_bytes(&bytes, &params)?;
        assert_eq!(restored.ksk_r_to_s, share.ksk_r_to_s);
        assert_eq!(restored.ksk_s_to_r, share.ksk_s_to_r);
        assert_eq!(restored.binding, None);
        Ok(())
    }

    #[test]
    fn rlk_share_rejects_aggregate_binding() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = <ChaCha8Rng as SeedableRng>::Seed::from([2u8; 32]);
        let participant_set = ParticipantSet::new([1u8; 32], vec![1, 2])?;
        let binding = ContributionBinding::new(participant_set, 1)?;

        let share = RelinKeyShare::contribution_with_binding(
            &sk, d1_seed, a_seed, binding, 0, 0, &mut rng,
        )?;
        let proto = LbfvRelinKeyShare {
            ksk_r_to_s: Some(KeySwitchingKeyProto::from(&share.ksk_r_to_s)),
            ksk_s_to_r: Some(KeySwitchingKeyProto::from(&share.ksk_s_to_r)),
            binding: Some(LbfvBinding {
                session_id: vec![1u8; 32],
                participant_ids: vec![1, 2],
                participant_id: 0,
                aggregate: true,
            }),
        };
        let bytes = proto.encode_to_vec();
        assert!(
            RelinKeyShare::from_bytes(&bytes, &params).is_err(),
            "Deserialization must reject aggregate binding on a RelinKeyShare"
        );
        Ok(())
    }
}
