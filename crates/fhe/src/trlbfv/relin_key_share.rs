use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use zeroize::Zeroizing;

use crate::Result;
use crate::bfv::{BfvParameters, CommonRandomPolyVec, KeySwitchingKey, SecretKey};
use crate::lbfv::LBFVRelinearizationKey;
use fhe_math::rq::{NttShoup, Poly};
use fhe_traits::FheParametrized;

use crate::SerializationError;
use crate::bfv::traits::TryConvertFrom;
use crate::proto::bfv::KeySwitchingKey as KeySwitchingKeyProto;
use crate::proto::lbfv::LbfvRelinKeyShare;
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
    /// Per-row errors from `ksk_r_to_s`: `eᵢ` such that `d0ᵢ = eᵢ − sk·d1ᵢ + gᵢ·r`.
    pub errors_d0: Vec<Poly<NttShoup>>,
    /// Per-row errors from `ksk_s_to_r`: `eᵢ` such that `d2ᵢ = eᵢ + r·aᵢ + gᵢ·sk`.
    pub errors_d2: Vec<Poly<NttShoup>>,
}

/// A party's additive contribution to threshold l-BFV relinearization-key
/// generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelinKeyShare {
    pub(crate) ksk_r_to_s: KeySwitchingKey,
    pub(crate) ksk_s_to_r: KeySwitchingKey,
}

impl FheParametrized for RelinKeyShare {
    type Parameters = BfvParameters;
}

impl RelinKeyShare {
    /// Return the secret-dependent `d0` components in gadget-row order.
    ///
    /// Each [`Poly<NttShoup>`] contains all RNS limbs for one row. The slice is
    /// borrowed read-only from this share; the component fields remain private,
    /// so callers cannot mutate the key or bypass the validation performed by
    /// the share constructors and deserializer.
    #[must_use]
    pub fn d0_components(&self) -> &[Poly<NttShoup>] {
        &self.ksk_r_to_s.c0
    }

    /// Return the secret-dependent `d2` components in gadget-row order.
    ///
    /// Each [`Poly<NttShoup>`] contains all RNS limbs for one row. These rows
    /// use the positive-`a` convention `d2 = r*a + e2 + g*sk`. The slice is
    /// borrowed read-only from this share; the component fields remain private,
    /// so callers cannot mutate the key or bypass the validation performed by
    /// the share constructors and deserializer.
    #[must_use]
    pub fn d2_components(&self) -> &[Poly<NttShoup>] {
        &self.ksk_s_to_r.c0
    }

    /// Return the ciphertext level used by this relinearization-key share.
    #[must_use]
    pub const fn ciphertext_level(&self) -> usize {
        self.ksk_r_to_s.ciphertext_level
    }

    /// Return the key level used by this relinearization-key share.
    #[must_use]
    pub const fn key_level(&self) -> usize {
        self.ksk_r_to_s.ksk_level
    }

    /// Generate a relinearization-key contribution from shared seeds.
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
        })
    }

    /// Generate a relinearization-key contribution from explicit
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
        })
    }

    /// Generate a relinearization-key contribution from shared CRP
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
        })
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
            },
            RlkWitness {
                r,
                errors_d0,
                errors_d2,
            },
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::aggregate::AggregateIter;
    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};
    use crate::trlbfv::{LBFVPublicKey, PublicKeyShare, aggregate_relinearization_key};
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::{SeedableRng, rng};
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_distributed_relinearization() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);

        let sks = [
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
        ];

        let pk_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = [10u8; 32];
        // The RLK's a_seed must match the PK's CRS seed.
        let a_seed = pk_seed;

        let pk_shares: Vec<PublicKeyShare> = sks
            .iter()
            .map(|sk| PublicKeyShare::new_with_seed(sk, pk_seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: LBFVPublicKey = pk_shares.into_iter().aggregate()?;

        let rlk_shares: Vec<RelinKeyShare> = sks
            .iter()
            .map(|sk| RelinKeyShare::contribution(sk, d1_seed, a_seed, 0, 0, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let relin_key = aggregate_relinearization_key(&rlk_shares, &aggregated_pk)?;

        let pt = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;
        let ct = aggregated_pk.try_encrypt(&pt, &mut rng)?;
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
    fn test_distributed_relinearization_many_contributors() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);

        let sks: Vec<SecretKey> = (0..5)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        let pk_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = [10u8; 32];
        let a_seed = pk_seed;

        let pk_shares: Vec<PublicKeyShare> = sks
            .iter()
            .map(|sk| PublicKeyShare::new_with_seed(sk, pk_seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: LBFVPublicKey = pk_shares.into_iter().aggregate()?;

        let rlk_shares: Vec<RelinKeyShare> = sks
            .iter()
            .map(|sk| RelinKeyShare::contribution(sk, d1_seed, a_seed, 0, 0, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let relin_key = aggregate_relinearization_key(&rlk_shares, &aggregated_pk)?;

        let pt = Plaintext::try_encode(&[2u64], Encoding::poly(), &params)?;
        let ct = aggregated_pk.try_encrypt(&pt, &mut rng)?;
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
    fn rlk_aggregation_rejects_inconsistent_urs() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sks = [
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
        ];
        let pk_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = [10u8; 32];
        let mut other_d1_seed = d1_seed;
        other_d1_seed[0] ^= 1;
        let pk_shares = sks
            .iter()
            .map(|sk| PublicKeyShare::new_with_seed(sk, pk_seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: LBFVPublicKey = pk_shares.into_iter().aggregate()?;
        let rlk1 = RelinKeyShare::contribution(&sks[0], d1_seed, pk_seed, 0, 0, &mut rng)?;
        let rlk2 = RelinKeyShare::contribution(&sks[1], other_d1_seed, pk_seed, 0, 0, &mut rng)?;

        let result = aggregate_relinearization_key(&[rlk1, rlk2], &aggregated_pk);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn rlk_aggregation_rejects_public_key_crs_mismatch() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sks = [
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
        ];
        let pk_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = [10u8; 32];
        let mut rlk_a_seed = pk_seed;
        rlk_a_seed[0] ^= 1;
        let pk_shares = sks
            .iter()
            .map(|sk| PublicKeyShare::new_with_seed(sk, pk_seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: LBFVPublicKey = pk_shares.into_iter().aggregate()?;
        let rlk_shares = sks
            .iter()
            .map(|sk| RelinKeyShare::contribution(sk, d1_seed, rlk_a_seed, 0, 0, &mut rng))
            .collect::<Result<Vec<_>>>()?;

        let result = aggregate_relinearization_key(&rlk_shares, &aggregated_pk);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn rlk_aggregation_rejects_zero_shares() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let public_key = LBFVPublicKey::new(&sk, &mut rng)?;

        assert!(aggregate_relinearization_key(&[], &public_key).is_err());
        Ok(())
    }

    #[test]
    fn aggregation_is_functional_for_three_contributors() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
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
            .map(|sk| PublicKeyShare::new_with_seed(sk, pk_seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: LBFVPublicKey = pk_shares.into_iter().aggregate()?;

        // Aggregate relinearization keys.
        let rlk_shares: Vec<RelinKeyShare> = sks
            .iter()
            .map(|sk| RelinKeyShare::contribution(sk, d1_seed, a_seed, 0, 0, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let relin_key = aggregate_relinearization_key(&rlk_shares, &aggregated_pk)?;

        // Verify functionality.
        let pt = Plaintext::try_encode(&[5u64], Encoding::poly(), &params)?;
        let ct = aggregated_pk.try_encrypt(&pt, &mut rng)?;
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

    #[test]
    fn proof_components_roundtrip_preserves_rows_and_levels() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let crp_d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
        let crp_a = CommonRandomPolyVec::new(&params, &mut rng)?;

        let (share, witness) =
            RelinKeyShare::contribution_with_crp_extended(&sk, &crp_d1, &crp_a, 0, 0, &mut rng)?;

        assert_eq!(share.d0_components().len(), crp_d1.len());
        assert_eq!(share.d2_components().len(), crp_a.len());
        assert_eq!(witness.errors_d0.len(), crp_d1.len());
        assert_eq!(witness.errors_d2.len(), crp_a.len());
        assert_eq!(share.ciphertext_level(), 0);
        assert_eq!(share.key_level(), 0);
        assert_eq!(share.d0_components()[0].ctx().moduli(), params.moduli());
        assert_eq!(share.d2_components()[0].ctx().moduli(), params.moduli());

        let restored = RelinKeyShare::from_bytes(&share.to_bytes(), &params)?;
        assert_eq!(restored.d0_components(), share.d0_components());
        assert_eq!(restored.d2_components(), share.d2_components());
        assert_eq!(restored.ciphertext_level(), share.ciphertext_level());
        assert_eq!(restored.key_level(), share.key_level());
        Ok(())
    }
}

impl Serialize for RelinKeyShare {
    fn to_bytes(&self) -> Vec<u8> {
        LbfvRelinKeyShare {
            ksk_r_to_s: Some(KeySwitchingKeyProto::from(&self.ksk_r_to_s)),
            ksk_s_to_r: Some(KeySwitchingKeyProto::from(&self.ksk_s_to_r)),
        }
        .encode_to_vec()
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

        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod proto_tests {
    use super::*;

    use crate::bfv::{BfvParameters, SecretKey};
    use fhe_traits::{DeserializeParametrized, Serialize};
    use rand::SeedableRng;
    use rand::rng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn rlk_share_roundtrip() -> Result<()> {
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
        Ok(())
    }
}
