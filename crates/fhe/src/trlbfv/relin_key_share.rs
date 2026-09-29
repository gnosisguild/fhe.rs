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
use crate::proto::lbfv::{LbfvRelinKeyContribution, LbfvRelinKeyShare};
use fhe_traits::{DeserializeParametrized, Serialize};
use prost::Message;
use std::sync::Arc;

/// Witness material produced alongside a [`RelinKeyShare`] for ZK proof generation.
///
/// Holds the private values that a party must commit to in order to prove
/// correct construction of its relinearization-key contribution.  The witness
/// must be kept confidential and **zeroized after use**.
pub struct RelinKeyWitness {
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
    ///
    /// The URS seed `d1_seed` and the CRS seed `a_seed` must be distinct: the
    /// two reference strings must be generated independently, and identical
    /// seeds are rejected before any share material is produced.
    pub fn contribute_with_seed<R: RngCore + CryptoRng>(
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
    ///
    /// The CRS `a_polys` and URS `d1_polys` must be generated independently.
    /// Repeated rows within either vector and rows shared between the two
    /// vectors are rejected before any share material is produced. The checks
    /// compare concrete values only; they cannot certify independence of
    /// deliberately correlated but unequal randomness.
    pub fn contribute_with_polys<R: RngCore + CryptoRng>(
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
    ///
    /// The URS `crp_d1` and CRS `crp_a` vectors must be generated
    /// independently; identical seeds, repeated rows within a vector, and rows
    /// shared between the two vectors are rejected before any share material
    /// is produced.
    pub fn contribute_with_crp<R: RngCore + CryptoRng>(
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

    /// Like [`contribute_with_crp`](Self::contribute_with_crp) but also
    /// returns a [`RelinKeyWitness`] containing the ephemeral key `r` and the
    /// per-row error polynomials needed for ZK witness generation.
    pub fn contribute_with_crp_and_witness<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        crp_d1: &CommonRandomPolyVec,
        crp_a: &CommonRandomPolyVec,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<(Self, RelinKeyWitness)> {
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
            RelinKeyWitness {
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
    use crate::bfv::{Encoding, Plaintext, SecretKey};
    use crate::support::presets::insecure;
    use crate::trlbfv::{LBFVPublicKey, PublicKeyShare, aggregate_relinearization_key};
    use fhe_math::rq::Ntt;
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::{SeedableRng, rng};
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_distributed_relinearization() -> Result<()> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;

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
            .map(|sk| PublicKeyShare::contribute_with_seed(sk, pk_seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: LBFVPublicKey = pk_shares.into_iter().aggregate()?;

        let rlk_shares: Vec<RelinKeyShare> = sks
            .iter()
            .map(|sk| RelinKeyShare::contribute_with_seed(sk, d1_seed, a_seed, 0, 0, &mut rng))
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
        let params = insecure().unwrap().parameters;

        let sks: Vec<SecretKey> = (0..5)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        let pk_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = [10u8; 32];
        let a_seed = pk_seed;

        let pk_shares: Vec<PublicKeyShare> = sks
            .iter()
            .map(|sk| PublicKeyShare::contribute_with_seed(sk, pk_seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: LBFVPublicKey = pk_shares.into_iter().aggregate()?;

        let rlk_shares: Vec<RelinKeyShare> = sks
            .iter()
            .map(|sk| RelinKeyShare::contribute_with_seed(sk, d1_seed, a_seed, 0, 0, &mut rng))
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
        let params = insecure().unwrap().parameters;
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
            .map(|sk| PublicKeyShare::contribute_with_seed(sk, pk_seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: LBFVPublicKey = pk_shares.into_iter().aggregate()?;
        let rlk1 = RelinKeyShare::contribute_with_seed(&sks[0], d1_seed, pk_seed, 0, 0, &mut rng)?;
        let rlk2 =
            RelinKeyShare::contribute_with_seed(&sks[1], other_d1_seed, pk_seed, 0, 0, &mut rng)?;

        let result = aggregate_relinearization_key(&[rlk1, rlk2], &aggregated_pk);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn rlk_aggregation_rejects_public_key_crs_mismatch() -> Result<()> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
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
            .map(|sk| PublicKeyShare::contribute_with_seed(sk, pk_seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: LBFVPublicKey = pk_shares.into_iter().aggregate()?;
        let rlk_shares = sks
            .iter()
            .map(|sk| RelinKeyShare::contribute_with_seed(sk, d1_seed, rlk_a_seed, 0, 0, &mut rng))
            .collect::<Result<Vec<_>>>()?;

        let result = aggregate_relinearization_key(&rlk_shares, &aggregated_pk);
        assert!(result.is_err());
        Ok(())
    }

    /// The seeded contribution boundary validates the *generated* concrete
    /// rows before the share is returned, exactly like every other
    /// reference-string input.
    ///
    /// A genuine cross-seed row collision would require a ChaCha8 collision
    /// and cannot be produced through caller-controlled inputs, so the
    /// rejection branch of this gate is covered by the explicit-polynomial,
    /// serialization, and aggregation tests; this test pins the acceptance
    /// behaviour and the rows the gate runs on.
    #[test]
    fn seeded_contribution_validates_generated_rows() -> Result<()> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let ctx0 = params.context_at_level(0)?;

        let d1_seed: <ChaCha8Rng as SeedableRng>::Seed = [10u8; 32];
        let a_seed: <ChaCha8Rng as SeedableRng>::Seed = [11u8; 32];

        let share = RelinKeyShare::contribute_with_seed(&sk, d1_seed, a_seed, 0, 0, &mut rng)?;

        // The validated rows are exactly the seed-derived URS and CRS rows.
        let expected_d1 = KeySwitchingKey::c1_from_seed(ctx0, d1_seed, params.moduli().len());
        let expected_a = KeySwitchingKey::c1_from_seed(ctx0, a_seed, params.moduli().len());
        assert_eq!(share.ksk_r_to_s.c1.as_ref(), expected_d1.as_slice());
        assert_eq!(share.ksk_s_to_r.c1.as_ref(), expected_a.as_slice());

        // Control: the accepted seeded share still round-trips and aggregates
        // with an honest public key.
        let restored = RelinKeyShare::from_bytes(&share.to_bytes(), &params)?;
        assert_eq!(restored.ksk_r_to_s, share.ksk_r_to_s);
        assert_eq!(restored.ksk_s_to_r, share.ksk_s_to_r);
        Ok(())
    }

    #[test]
    fn rlk_aggregation_rejects_zero_shares() -> Result<()> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let public_key = LBFVPublicKey::new(&sk, &mut rng)?;

        assert!(aggregate_relinearization_key(&[], &public_key).is_err());
        Ok(())
    }

    /// Share constructors must reject reference strings that are observably
    /// reused: identical seeds, rows shared between the URS and CRS vectors,
    /// and rows repeated within a vector.
    #[test]
    fn contribute_rejects_reused_and_repeated_reference_strings() -> Result<()> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let ctx0 = params.context_at_level(0)?;

        let same_seed: <ChaCha8Rng as SeedableRng>::Seed = [33u8; 32];
        assert!(matches!(
            RelinKeyShare::contribute_with_seed(&sk, same_seed, same_seed, 0, 0, &mut rng),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::IdenticalReferenceStringSeeds
            ))
        ));

        // Independent CRS vector; URS vector colliding with it at a
        // cross-index position.
        let crp_a = CommonRandomPolyVec::new(&params, &mut rng)?;
        let mut colliding_polys =
            KeySwitchingKey::c1_from_seed(ctx0, [44u8; 32], params.moduli().len());
        colliding_polys[1] = crp_a.as_slice()[0].poly().clone().into_ntt_shoup();
        assert!(matches!(
            RelinKeyShare::contribute_with_polys(
                &sk,
                colliding_polys.clone(),
                crp_a
                    .to_polys()
                    .iter()
                    .map(|p| p.clone().into_ntt_shoup())
                    .collect(),
                0,
                0,
                &mut rng
            ),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::OverlappingReferenceStringRows {
                    crs_index: 0,
                    urs_index: 1,
                }
            ))
        ));

        // Repeated row inside the URS vector.
        let mut repeated = colliding_polys;
        repeated[1] = repeated[0].clone();
        assert!(matches!(
            RelinKeyShare::contribute_with_polys(
                &sk,
                repeated,
                crp_a
                    .to_polys()
                    .iter()
                    .map(|p| p.clone().into_ntt_shoup())
                    .collect(),
                0,
                0,
                &mut rng
            ),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::RepeatedReferenceStringRow {
                    role: crate::ReferenceStringRole::Urs,
                    first_index: 0,
                    second_index: 1,
                }
            ))
        ));

        // CRP-vector path: the URS vector shares row 0 with the CRS vector.
        let mut overlapping_polys: Vec<Poly<Ntt>> = (0..params.moduli().len())
            .map(|_| Poly::<Ntt>::random(ctx0, &mut rng))
            .collect();
        overlapping_polys[0] = crp_a.as_slice()[0].poly().clone();
        let crp_d1_overlapping = CommonRandomPolyVec::from_polys(&params, overlapping_polys, None)?;
        assert!(matches!(
            RelinKeyShare::contribute_with_crp(&sk, &crp_d1_overlapping, &crp_a, 0, 0, &mut rng),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::OverlappingReferenceStringRows {
                    crs_index: 0,
                    urs_index: 0,
                }
            ))
        ));
        assert!(matches!(
            RelinKeyShare::contribute_with_crp_and_witness(
                &sk,
                &crp_d1_overlapping,
                &crp_a,
                0,
                0,
                &mut rng
            ),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::OverlappingReferenceStringRows { .. }
            ))
        ));

        // Control: independent CRP vectors are accepted and produce a working
        // share (functional coverage lives in the aggregation tests).
        let crp_d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
        assert!(RelinKeyShare::contribute_with_crp(&sk, &crp_d1, &crp_a, 0, 0, &mut rng).is_ok());
        Ok(())
    }

    #[test]
    fn aggregation_is_functional_for_three_contributors() -> Result<()> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
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
            .map(|sk| PublicKeyShare::contribute_with_seed(sk, pk_seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let aggregated_pk: LBFVPublicKey = pk_shares.into_iter().aggregate()?;

        // Aggregate relinearization keys.
        let rlk_shares: Vec<RelinKeyShare> = sks
            .iter()
            .map(|sk| RelinKeyShare::contribute_with_seed(sk, d1_seed, a_seed, 0, 0, &mut rng))
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
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let crp_d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
        let crp_a = CommonRandomPolyVec::new(&params, &mut rng)?;

        let (share, witness): (RelinKeyShare, crate::trlbfv::RelinKeyWitness) =
            RelinKeyShare::contribute_with_crp_and_witness(&sk, &crp_d1, &crp_a, 0, 0, &mut rng)?;

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
            contribution: Some(LbfvRelinKeyContribution {
                ksk_r_to_s: Some(KeySwitchingKeyProto::from(&self.ksk_r_to_s)),
                ksk_s_to_r: Some(KeySwitchingKeyProto::from(&self.ksk_s_to_r)),
            }),
        }
        .encode_to_vec()
    }
}

impl DeserializeParametrized for RelinKeyShare {
    type Error = crate::Error;

    fn from_bytes(bytes: &[u8], params: &Arc<BfvParameters>) -> Result<Self> {
        let proto: LbfvRelinKeyShare =
            crate::serialization::decode(bytes, crate::SerializedObject::RelinearizationKeyShare)?;
        let contribution = proto.contribution.ok_or(crate::Error::SerializationError(
            SerializationError::MissingField {
                field: crate::SerializedField::RelinearizationKeyShareContribution,
            },
        ))?;

        let ksk_r_to_s = contribution
            .ksk_r_to_s
            .as_ref()
            .ok_or_else(|| {
                crate::Error::SerializationError(SerializationError::InvalidFormat {
                    reason: "Missing ksk_r_to_s in RelinKeyShare proto".to_string(),
                })
            })
            .and_then(|ksk| KeySwitchingKey::try_convert_from(ksk, params))?;
        let ksk_s_to_r = contribution
            .ksk_s_to_r
            .as_ref()
            .ok_or_else(|| {
                crate::Error::SerializationError(SerializationError::InvalidFormat {
                    reason: "Missing ksk_s_to_r in RelinKeyShare proto".to_string(),
                })
            })
            .and_then(|ksk| KeySwitchingKey::try_convert_from(ksk, params))?;

        // The two KSKs must describe one coherent contribution: matching
        // parameters, levels, contexts, and decomposition. Without this gate,
        // the URS and CRS rows would live in different contexts and could not
        // be compared meaningfully.
        if ksk_r_to_s.params != ksk_s_to_r.params {
            return Err(SerializationError::InvalidFormat {
                reason: "RelinKeyShare KSKs have mismatched parameters".to_string(),
            }
            .into());
        }
        if ksk_r_to_s.ciphertext_level != ksk_s_to_r.ciphertext_level
            || ksk_r_to_s.ksk_level != ksk_s_to_r.ksk_level
        {
            return Err(SerializationError::InvalidFormat {
                reason: "RelinKeyShare KSKs have mismatched levels".to_string(),
            }
            .into());
        }
        if ksk_r_to_s.ctx_ciphertext != ksk_s_to_r.ctx_ciphertext
            || ksk_r_to_s.ctx_ksk != ksk_s_to_r.ctx_ksk
        {
            return Err(SerializationError::InvalidFormat {
                reason: "RelinKeyShare KSKs have mismatched contexts".to_string(),
            }
            .into());
        }
        if ksk_r_to_s.log_base != ksk_s_to_r.log_base {
            return Err(SerializationError::InvalidFormat {
                reason: "RelinKeyShare KSKs have mismatched log_base".to_string(),
            }
            .into());
        }

        // Reference-string gate: the shared URS `d1` rows (ksk_r_to_s.c1) and
        // CRS `a` rows (ksk_s_to_r.c1) must be distinct within each vector and
        // disjoint across the two vectors. A serialized share built from
        // reused reference-string randomness is rejected instead of being
        // accepted into aggregation.
        crate::reference_string::validate_reference_string_pair(
            &ksk_r_to_s.ctx_ksk,
            &ksk_s_to_r.c1,
            &ksk_r_to_s.c1,
        )?;

        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod proto_tests {
    use super::*;

    use crate::bfv::SecretKey;
    use crate::lbfv::LBFVPublicKey;
    use crate::support::presets::insecure;
    use fhe_traits::{DeserializeParametrized, Serialize};
    use rand::SeedableRng;
    use rand::rng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn relin_key_share_envelope_has_stable_wire_fixture() {
        const FIXTURE: &[u8] = &[
            0x0a, 0x19, 0x0a, 0x0c, 0x0a, 0x01, 0xaa, 0x1a, 0x01, 0xcc, 0x20, 0x01, 0x28, 0x02,
            0x30, 0x03, 0x12, 0x09, 0x12, 0x01, 0xbb, 0x20, 0x04, 0x28, 0x05, 0x30, 0x06,
        ];
        let envelope = LbfvRelinKeyShare {
            contribution: Some(LbfvRelinKeyContribution {
                ksk_r_to_s: Some(KeySwitchingKeyProto {
                    c0: vec![vec![0xaa]],
                    c1: Vec::new(),
                    seed: vec![0xcc],
                    ciphertext_level: 1,
                    ksk_level: 2,
                    log_base: 3,
                }),
                ksk_s_to_r: Some(KeySwitchingKeyProto {
                    c0: Vec::new(),
                    c1: vec![vec![0xbb]],
                    seed: Vec::new(),
                    ciphertext_level: 4,
                    ksk_level: 5,
                    log_base: 6,
                }),
            }),
        };

        assert_eq!(envelope.encode_to_vec(), FIXTURE);
        assert_eq!(LbfvRelinKeyShare::decode(FIXTURE).unwrap(), envelope);
    }

    #[test]
    fn rlk_share_roundtrip() -> Result<()> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = <ChaCha8Rng as SeedableRng>::Seed::from([2u8; 32]);
        let share = RelinKeyShare::contribute_with_seed(&sk, d1_seed, a_seed, 0, 0, &mut rng)?;
        let bytes = share.to_bytes();
        let restored = RelinKeyShare::from_bytes(&bytes, &params)?;
        assert_eq!(restored.ksk_r_to_s, share.ksk_r_to_s);
        assert_eq!(restored.ksk_s_to_r, share.ksk_s_to_r);
        Ok(())
    }

    /// A serialized share whose URS rows collide with or repeat across its CRS
    /// rows must be rejected at deserialization time, and a share whose two
    /// KSKs describe incoherent levels must not decode.
    #[test]
    fn serialized_share_rejects_reused_rows_and_incoherent_ksks() -> Result<()> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);

        // Seedless CRP vectors so the KSK c1 rows serialize inline.
        let crp_a = CommonRandomPolyVec::new(&params, &mut rng)?;
        let crp_d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
        let share = RelinKeyShare::contribute_with_crp(&sk, &crp_d1, &crp_a, 0, 0, &mut rng)?;

        // Control: the honest payload round-trips.
        let restored = RelinKeyShare::from_bytes(&share.to_bytes(), &params)?;
        assert_eq!(restored.d0_components(), share.d0_components());
        assert_eq!(restored.d2_components(), share.d2_components());

        // Tamper: URS row 0 becomes a copy of CRS row 1.
        let proto: LbfvRelinKeyShare = LbfvRelinKeyShare::decode(share.to_bytes().as_slice())
            .expect("honest share payload decodes");
        let contribution = proto.contribution.expect("contribution");
        let mut tampered_rows = contribution.clone();
        let crs_row = tampered_rows.ksk_s_to_r.as_ref().expect("ksk_s_to_r").c1[1].clone();
        tampered_rows.ksk_r_to_s.as_mut().expect("ksk_r_to_s").c1[0] = crs_row;
        let bytes = LbfvRelinKeyShare {
            contribution: Some(tampered_rows),
        }
        .encode_to_vec();
        assert!(matches!(
            RelinKeyShare::from_bytes(&bytes, &params),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::OverlappingReferenceStringRows {
                    crs_index: 1,
                    urs_index: 0,
                }
            ))
        ));

        // Tamper: repeat a row within the URS vector.
        let mut repeated_rows = contribution.clone();
        let urs_row = repeated_rows.ksk_r_to_s.as_ref().expect("ksk_r_to_s").c1[0].clone();
        repeated_rows.ksk_r_to_s.as_mut().expect("ksk_r_to_s").c1[2] = urs_row;
        let bytes = LbfvRelinKeyShare {
            contribution: Some(repeated_rows),
        }
        .encode_to_vec();
        assert!(matches!(
            RelinKeyShare::from_bytes(&bytes, &params),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::RepeatedReferenceStringRow {
                    role: crate::ReferenceStringRole::Urs,
                    first_index: 0,
                    second_index: 2,
                }
            ))
        ));

        // Tamper: the two KSKs disagree on the key level; the share must not
        // decode because the URS/CRS rows could not be compared coherently.
        let mut mismatched_levels = contribution.clone();
        mismatched_levels
            .ksk_s_to_r
            .as_mut()
            .expect("ksk_s_to_r")
            .ksk_level = 1;
        let bytes = LbfvRelinKeyShare {
            contribution: Some(mismatched_levels),
        }
        .encode_to_vec();
        assert!(RelinKeyShare::from_bytes(&bytes, &params).is_err());

        Ok(())
    }

    #[test]
    fn contribution_and_operational_relin_key_wire_types_are_not_interchangeable() -> Result<()> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let d1_seed = <ChaCha8Rng as SeedableRng>::Seed::from([2u8; 32]);
        let public_key = LBFVPublicKey::new_with_seed(&sk, a_seed, &mut rng)?;
        let share = RelinKeyShare::contribute_with_seed(&sk, d1_seed, a_seed, 0, 0, &mut rng)?;
        let operational = LBFVRelinearizationKey::new(&sk, &public_key, Some(d1_seed), &mut rng)?;

        assert!(RelinKeyShare::from_bytes(&operational.to_bytes(), &params).is_err());
        assert!(LBFVRelinearizationKey::from_bytes(&share.to_bytes(), &params).is_err());
        Ok(())
    }
}
