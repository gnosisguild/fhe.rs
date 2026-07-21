//! Aggregation of threshold l-BFV key shares.
//!
//! Public-key aggregation validates the participant bindings and shared CRS,
//! then produces an [`AggregatedPublicKey`]. Relinearization-key aggregation
//! is performed by [`aggregate_relinearization_key`], which combines
//! [`RelinKeyShare`] values against the aggregated public key.

use crate::bfv::KeySwitchingKey;
use crate::lbfv::{LBFVPublicKey, LBFVRelinearizationKey};
use crate::mbfv::Aggregate;
use crate::{Error, Result};
use fhe_math::rq::{Ntt, NttShoup, Poly, Representation};

use super::binding::{ContributionBinding, ParticipantSet};
use super::public_key_share::PublicKeyShare;
use super::relin_key_share::RelinKeyShare;

/// An aggregated threshold l-BFV public key.
///
/// Wraps the operational single-party public key together with the participant
/// set that produced it.  The operational key can be extracted via
/// [`operational`](AggregatedPublicKey::operational) or
/// [`into_operational`](AggregatedPublicKey::into_operational).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedPublicKey {
    pub(crate) key: LBFVPublicKey,
    pub(crate) participant_set: ParticipantSet,
}

impl AggregatedPublicKey {
    /// Borrow the operational single-party public key.
    #[must_use]
    pub fn operational(&self) -> &LBFVPublicKey {
        &self.key
    }

    /// Consume this aggregated key and return the operational single-party
    /// public key.
    #[must_use]
    pub fn into_operational(self) -> LBFVPublicKey {
        self.key
    }

    /// The participant set that produced this aggregated key.
    #[must_use]
    pub fn participant_set(&self) -> &ParticipantSet {
        &self.participant_set
    }
}

impl Aggregate<PublicKeyShare> for AggregatedPublicKey {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = PublicKeyShare>,
    {
        let shares: Vec<PublicKeyShare> = iter.into_iter().collect();
        let (first, rest) = shares.split_first().ok_or_else(|| {
            Error::DefaultError("Cannot aggregate zero public-key shares".to_string())
        })?;

        // Require binding metadata on every share.
        let first_binding = first.binding.as_ref().ok_or_else(|| {
            Error::DefaultError("Public-key share is missing participant binding".to_string())
        })?;

        first.key.validate_structure()?;
        let participant_set = first_binding.participant_set().clone();

        // Validate parameter equality and binding consistency across all shares.
        let mut bindings: Vec<&ContributionBinding> = vec![first_binding];
        for share in rest {
            share.key.validate_structure()?;
            let binding = share.binding.as_ref().ok_or_else(|| {
                Error::DefaultError("Public-key share is missing participant binding".to_string())
            })?;
            if share.key.params != first.key.params {
                return Err(Error::DefaultError(
                    "Public-key shares have mismatched parameters".to_string(),
                ));
            }
            bindings.push(binding);
        }

        // Validate exact participant-set coverage.
        participant_set.validate_contributions(bindings)?;

        // Verify that the actual a_j (c[1]) polynomials match across all shares.
        // This is the concrete CRS check.
        for (j, first_ct) in first.key.c.iter().enumerate() {
            let a_first = first_ct.c.get(1).ok_or_else(|| {
                Error::DefaultError("LBFV public-key ciphertext is missing a".to_string())
            })?;
            for share in rest {
                let ct_j = share.key.c.get(j).ok_or_else(|| {
                    Error::DefaultError("LBFV public-key ciphertext count changed".to_string())
                })?;
                let a_other = ct_j.c.get(1).ok_or_else(|| {
                    Error::DefaultError("LBFV public-key ciphertext is missing a".to_string())
                })?;
                if a_first != a_other {
                    return Err(Error::DefaultError(
                        "LBFV public-key contributions use different CRS polynomials".to_string(),
                    ));
                }
            }
        }

        // Extract the shared a polynomials from the first share.
        let a_polys: Vec<Poly<Ntt>> = first
            .key
            .c
            .iter()
            .map(|ct| {
                ct.c.get(1).cloned().ok_or_else(|| {
                    Error::DefaultError("LBFV public-key ciphertext is missing a".to_string())
                })
            })
            .collect::<Result<_>>()?;

        // Sum b polynomials across all shares.
        let b_sums: Vec<Poly<Ntt>> = (0..first.key.c.len())
            .map(|j| {
                let mut sum = first
                    .key
                    .c
                    .get(j)
                    .and_then(|ct| ct.c.first())
                    .cloned()
                    .ok_or_else(|| {
                        Error::DefaultError("LBFV public-key ciphertext is missing b".to_string())
                    })?;
                for share in rest {
                    let b = share
                        .key
                        .c
                        .get(j)
                        .and_then(|ct| ct.c.first())
                        .ok_or_else(|| {
                            Error::DefaultError(
                                "LBFV public-key ciphertext is missing b".to_string(),
                            )
                        })?;
                    sum += b;
                }
                Ok(sum)
            })
            .collect::<Result<_>>()?;

        // Preserve seed only when all contributions have the same seed.
        let shared_seed = first
            .key
            .seed
            .filter(|seed| shares.iter().all(|share| share.key.seed == Some(*seed)));

        let aggregated_key =
            LBFVPublicKey::from_parts(b_sums, a_polys, first.key.params.clone(), shared_seed)?;

        Ok(AggregatedPublicKey {
            key: aggregated_key,
            participant_set,
        })
    }
}

// ---------------------------------------------------------------------------
// Relinearization-key aggregation
// ---------------------------------------------------------------------------

/// Sum the `c0` components of a set of key-switching keys, coordinate-wise over
/// the gadget dimension.
///
/// This is the additive aggregation `Σ d0_i` / `Σ d2_i`: each share's
/// secret-dependent part (`d0_i` for `ksk_r_to_s`, `d2_i` for `ksk_s_to_r`) is
/// stored as that key-switching key's `c0` component, so summing the `c0`s is
/// exactly summing the `d0_i` / `d2_i`. The shared `c1` (= `d1` / `a`) is not
/// summed — it is identical across shares and carried over by the caller.
///
/// Aggregation is a rare generation-time operation, so we pay the cost here:
/// convert each operand to `Ntt` (which supports addition), sum, and rebuild
/// the Shoup table once via `into_ntt_shoup` for the cheap-multiply property
/// to hold on the hot path.
fn sum_ksk_c0<'a>(
    ksks: impl Iterator<Item = &'a KeySwitchingKey>,
) -> Result<Box<[Poly<NttShoup>]>> {
    let mut acc: Vec<Option<Poly<Ntt>>> = Vec::new();
    for ksk in ksks {
        if acc.is_empty() {
            acc.resize_with(ksk.c0.len(), || None);
        } else if acc.len() != ksk.c0.len() {
            return Err(Error::DefaultError(
                "Relinearization key shares have mismatched gadget dimension".to_string(),
            ));
        }
        // Convert and sum in NTT.
        for (slot, c0_j) in acc.iter_mut().zip(ksk.c0.iter()) {
            let c0_j_ntt = c0_j.clone().into_ntt();
            match slot {
                Some(sum) => *sum += &c0_j_ntt,
                None => *slot = Some(c0_j_ntt),
            }
        }
    }
    if acc.is_empty() {
        return Err(Error::DefaultError(
            "Cannot sum an empty set of key-switching keys".to_string(),
        ));
    }
    // Convert again in NTTShoup.
    let out = acc
        .into_iter()
        .map(|p| {
            p.ok_or_else(|| Error::DefaultError("missing c0 component".to_string()))
                .map(Poly::<Ntt>::into_ntt_shoup)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(out.into_boxed_slice())
}

/// Aggregate threshold l-BFV relinearization-key contributions into an
/// operational [`LBFVRelinearizationKey`].
///
/// # Arguments
/// * `shares` - The relinearization-key shares from each participant.
/// * `public_key` - The aggregated public key used as the CRS reference.
///
/// # Validation
/// Rejects:
/// - empty share set,
/// - shares with missing bindings,
/// - bindings that do not cover or over-cover the participant set,
/// - KSKs with inconsistent parameters, levels, contexts, gadget dimensions,
///   or log_base,
/// - shares with differing concrete `d1` (URS) or `a` (CRS) polynomials,
/// - shares whose `a` polynomials do not match the aggregated public key's
///   concrete `a_j`.
pub fn aggregate_relinearization_key(
    shares: &[RelinKeyShare],
    public_key: &AggregatedPublicKey,
) -> Result<LBFVRelinearizationKey> {
    let (first, rest) = shares.split_first().ok_or_else(|| {
        Error::DefaultError("Cannot aggregate zero relinearization key shares".to_string())
    })?;

    // Validate public key structure.
    public_key.key.validate_structure()?;

    // Require binding metadata on every share and validate against participant set.
    let first_binding = first.binding.as_ref().ok_or_else(|| {
        Error::DefaultError("RelinKeyShare is missing participant binding".to_string())
    })?;
    let mut bindings: Vec<&ContributionBinding> = vec![first_binding];
    for share in rest {
        let binding = share.binding.as_ref().ok_or_else(|| {
            Error::DefaultError("RelinKeyShare is missing participant binding".to_string())
        })?;
        bindings.push(binding);
    }
    public_key
        .participant_set
        .validate_contributions(bindings)?;

    // Structural validation of every share's KSKs.
    for (i, share) in shares.iter().enumerate() {
        if share.ksk_r_to_s.params != first.ksk_r_to_s.params {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has different r->s parameters"
            )));
        }
        if i == 0 && share.ksk_r_to_s.params != public_key.key.params {
            return Err(Error::DefaultError(
                "Relinearization key share parameters do not match public key parameters"
                    .to_string(),
            ));
        }
        if share.ksk_r_to_s.c0.len() != share.ksk_r_to_s.c1.len()
            || share.ksk_s_to_r.c0.len() != share.ksk_s_to_r.c1.len()
        {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has mismatched c0/c1 dimensions"
            )));
        }
        if share.ksk_r_to_s.ciphertext_level != first.ksk_r_to_s.ciphertext_level
            || share.ksk_r_to_s.ksk_level != first.ksk_r_to_s.ksk_level
        {
            return Err(Error::DefaultError(
                "Relinearization key shares are inconsistent (differing r->s levels)".to_string(),
            ));
        }
        if share.ksk_r_to_s.ctx_ciphertext != first.ksk_r_to_s.ctx_ciphertext
            || share.ksk_r_to_s.ctx_ksk != first.ksk_r_to_s.ctx_ksk
        {
            return Err(Error::DefaultError(
                "Relinearization key shares are inconsistent (differing r->s contexts)".to_string(),
            ));
        }
        if share.ksk_s_to_r.params != first.ksk_s_to_r.params {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has different s->r parameters"
            )));
        }
        if share.ksk_s_to_r.ciphertext_level != first.ksk_s_to_r.ciphertext_level
            || share.ksk_s_to_r.ksk_level != first.ksk_s_to_r.ksk_level
        {
            return Err(Error::DefaultError(
                "Relinearization key shares are inconsistent (differing s->r levels)".to_string(),
            ));
        }
        if share.ksk_s_to_r.ctx_ciphertext != first.ksk_s_to_r.ctx_ciphertext
            || share.ksk_s_to_r.ctx_ksk != first.ksk_s_to_r.ctx_ksk
        {
            return Err(Error::DefaultError(
                "Relinearization key shares are inconsistent (differing s->r contexts)".to_string(),
            ));
        }
        if share.ksk_s_to_r.log_base != first.ksk_s_to_r.log_base {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has inconsistent s->r log_base"
            )));
        }
        if share.ksk_r_to_s.c0.len() != share.ksk_s_to_r.c0.len() {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has mismatched r->s/s->r c0 dimensions"
            )));
        }
        // Cross-KSK consistency.
        if share.ksk_r_to_s.params != share.ksk_s_to_r.params {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has mismatched r->s/s->r parameters"
            )));
        }
        if share.ksk_r_to_s.ciphertext_level != share.ksk_s_to_r.ciphertext_level {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has mismatched r->s/s->r ciphertext levels"
            )));
        }
        if share.ksk_r_to_s.ksk_level != share.ksk_s_to_r.ksk_level {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has mismatched r->s/s->r key levels"
            )));
        }
        if share.ksk_r_to_s.ctx_ciphertext != share.ksk_s_to_r.ctx_ciphertext {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has mismatched r->s/s->r ciphertext contexts"
            )));
        }
        if share.ksk_r_to_s.ctx_ksk != share.ksk_s_to_r.ctx_ksk {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has mismatched r->s/s->r key contexts"
            )));
        }
        if share.ksk_r_to_s.log_base != share.ksk_s_to_r.log_base {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has mismatched r->s/s->r log_base"
            )));
        }
    }

    // Verify the concrete d1 (URS) polynomials match across all shares.
    for s in rest {
        if s.ksk_r_to_s.c1 != first.ksk_r_to_s.c1 {
            return Err(Error::DefaultError(
                "Relinearization key shares have inconsistent d1 (URS) polynomials".to_string(),
            ));
        }
    }

    // Verify the concrete a (CRS) polynomials match across all shares.
    for s in rest {
        if s.ksk_s_to_r.c1 != first.ksk_s_to_r.c1 {
            return Err(Error::DefaultError(
                "Relinearization key shares have inconsistent a (CRS) polynomials".to_string(),
            ));
        }
    }

    // Determine whether all input KSKs share the same seeds.
    let seeds_match = shares
        .iter()
        .all(|s| s.ksk_r_to_s.seed == first.ksk_r_to_s.seed)
        && shares
            .iter()
            .all(|s| s.ksk_s_to_r.seed == first.ksk_s_to_r.seed);

    // CRS binding: the a polynomials in ksk_s_to_r.c1 must match the
    // public key's a_j ciphertext polynomials.
    let pk_ctx0 = public_key.key.params.context_at_level(0)?;
    let ksk_ctx = &first.ksk_s_to_r.ctx_ksk;
    if ksk_ctx != pk_ctx0 {
        return Err(Error::DefaultError(
            "Cannot verify CRS binding: RLK key context differs from public key level-0 context"
                .to_string(),
        ));
    }
    let new_l = public_key
        .key
        .l
        .checked_sub(first.ksk_r_to_s.ciphertext_level)
        .ok_or_else(|| {
            Error::DefaultError(
                "CRS binding failed: ciphertext_level exceeds public-key l".to_string(),
            )
        })?;
    if first.ksk_s_to_r.c1.len() != new_l {
        return Err(Error::DefaultError(
            "CRS binding failed: RLK's a polynomial count does not match expected l - ciphertext_level"
                .to_string(),
        ));
    }
    for (j, c1_j) in first.ksk_s_to_r.c1.iter().enumerate() {
        let mut a_ksk: Poly<Ntt> = c1_j.clone().into_ntt();
        a_ksk.disallow_variable_time_computations();
        let pk_a_j = public_key
            .key
            .c
            .get(j)
            .and_then(|ct| ct.c.get(1))
            .ok_or_else(|| {
                Error::DefaultError("Public key is missing its a_j polynomial".to_string())
            })?;
        if a_ksk != *pk_a_j {
            return Err(Error::DefaultError(
                "CRS binding failed: RLK's a_j does not match public key's a_j".to_string(),
            ));
        }
    }

    let ciphertext_level = first.ksk_r_to_s.ciphertext_level;
    let key_level = first.ksk_r_to_s.ksk_level;
    let b_vec = public_key.key.extract_b_polynomials(
        ciphertext_level,
        key_level,
        Representation::NttShoup,
    )?;

    let mut ksk_r_to_s = first.ksk_r_to_s.clone();
    ksk_r_to_s.c0 = sum_ksk_c0(shares.iter().map(|s| &s.ksk_r_to_s))?;

    let mut ksk_s_to_r = first.ksk_s_to_r.clone();
    ksk_s_to_r.c0 = sum_ksk_c0(shares.iter().map(|s| &s.ksk_s_to_r))?;

    if !seeds_match {
        ksk_r_to_s.seed = None;
        ksk_s_to_r.seed = None;
    }

    LBFVRelinearizationKey::from_components(ksk_r_to_s, ksk_s_to_r, b_vec)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

    use super::*;
    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};
    use crate::mbfv::AggregateIter;
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::{RngCore, SeedableRng, rng};
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn threshold_aggregation_keeps_binding_outside_lbfv_key() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let participant_set = ParticipantSet::new([11u8; 32], vec![1, 2])?;

        let secret_keys = [
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
        ];

        let a_seed = {
            let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill_bytes(&mut seed);
            seed
        };
        let d1_seed = {
            let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill_bytes(&mut seed);
            seed
        };

        let public_key_shares: Vec<PublicKeyShare> = secret_keys
            .iter()
            .enumerate()
            .map(|(index, sk)| {
                let b = ContributionBinding::new(participant_set.clone(), (index + 1) as u32)?;
                PublicKeyShare::new_with_seed_and_binding(sk, a_seed, b, &mut rng)
            })
            .collect::<Result<Vec<_>>>()?;

        let aggregated_pk: AggregatedPublicKey = public_key_shares.into_iter().aggregate()?;
        assert_eq!(aggregated_pk.participant_set(), &participant_set);

        let relin_key_shares: Vec<RelinKeyShare> = secret_keys
            .iter()
            .enumerate()
            .map(|(index, sk)| {
                let b = ContributionBinding::new(participant_set.clone(), (index + 1) as u32)?;
                RelinKeyShare::contribution_with_binding(sk, d1_seed, a_seed, b, 0, 0, &mut rng)
            })
            .collect::<Result<Vec<_>>>()?;

        let relin_key = aggregate_relinearization_key(&relin_key_shares, &aggregated_pk)?;

        let plaintext = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;
        let ct = aggregated_pk
            .operational()
            .try_encrypt(&plaintext, &mut rng)?;
        let mut square = &ct * &ct;
        relin_key.relinearizes(&mut square)?;

        let joint_coeffs: Vec<i64> = (0..params.degree())
            .map(|d| secret_keys.iter().map(|sk| sk.coeffs[d]).sum())
            .collect();
        let joint_sk = SecretKey::new(joint_coeffs, &params);
        let decoded = Vec::<u64>::try_decode(&joint_sk.try_decrypt(&square)?, Encoding::poly())?;
        assert_eq!(decoded.first(), Some(&9));
        Ok(())
    }
}

#[cfg(feature = "protobuf")]
mod protobuf {
    use super::*;
    use crate::SerializationError;
    use crate::bfv::BfvParameters;
    use crate::proto::bfv::{LbfvBinding, LbfvPublicKey as LbfvPublicKeyProto};
    use fhe_traits::FheParametrized;
    use fhe_traits::{DeserializeParametrized as DeserParam, Serialize};
    use prost::Message;
    use std::sync::Arc;

    impl Serialize for AggregatedPublicKey {
        fn to_bytes(&self) -> Vec<u8> {
            let mut proto: LbfvPublicKeyProto = LbfvPublicKeyProto::from(&self.key);
            proto.binding = Some(LbfvBinding {
                session_id: self.participant_set.session_id().to_vec(),
                participant_ids: self.participant_set.participant_ids().to_vec(),
                participant_id: 0,
                aggregate: true,
            });
            proto.encode_to_vec()
        }
    }

    impl DeserParam for AggregatedPublicKey {
        type Error = crate::Error;

        fn from_bytes(bytes: &[u8], params: &Arc<BfvParameters>) -> crate::Result<Self> {
            let proto: LbfvPublicKeyProto = Message::decode(bytes).map_err(|e| {
                crate::Error::SerializationError(SerializationError::ProtobufError {
                    message: e.to_string(),
                })
            })?;

            let binding = proto.binding.as_ref().ok_or_else(|| {
                crate::Error::SerializationError(SerializationError::InvalidFormat {
                    reason: "AggregatedPublicKey missing binding; expected aggregate=true"
                        .to_string(),
                })
            })?;

            if !binding.aggregate {
                return Err(crate::Error::SerializationError(
                    SerializationError::InvalidFormat {
                        reason: format!(
                            "AggregatedPublicKey binding has aggregate={}; expected true",
                            binding.aggregate
                        ),
                    },
                ));
            }

            let session_id: [u8; 32] = binding.session_id.as_slice().try_into().map_err(|_| {
                crate::Error::SerializationError(SerializationError::InvalidFormat {
                    reason: "Invalid session_id length in AggregatedPublicKey binding".to_string(),
                })
            })?;
            let participant_set = ParticipantSet::new(session_id, binding.participant_ids.clone())?;

            // Build the inner key from the proto, clearing the binding first.
            let mut key_proto = proto.clone();
            key_proto.binding = None;
            let key_bytes = key_proto.encode_to_vec();
            let key = LBFVPublicKey::from_bytes(&key_bytes, params)?;

            Ok(AggregatedPublicKey {
                key,
                participant_set,
            })
        }
    }

    impl FheParametrized for AggregatedPublicKey {
        type Parameters = BfvParameters;
    }

    #[cfg(test)]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    mod tests {
        use super::*;

        use crate::bfv::{BfvParameters, SecretKey};
        use crate::mbfv::AggregateIter;
        use crate::trlbfv::{ContributionBinding, ParticipantSet, PublicKeyShare};
        use fhe_traits::{DeserializeParametrized, Serialize};
        use rand::SeedableRng;
        use rand::rng;
        use rand_chacha::ChaCha8Rng;

        #[test]
        fn aggregated_public_key_roundtrip() -> crate::Result<()> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let participant_set = ParticipantSet::new([1u8; 32], vec![1, 2])?;

            let sk1 = SecretKey::random(&params, &mut rng);
            let sk2 = SecretKey::random(&params, &mut rng);

            let seed = <ChaCha8Rng as SeedableRng>::Seed::default();

            let shares: Vec<PublicKeyShare> = [(&sk1, 1u32), (&sk2, 2u32)]
                .iter()
                .map(|(sk, id)| {
                    let binding = ContributionBinding::new(participant_set.clone(), *id)?;
                    PublicKeyShare::new_with_seed_and_binding(sk, seed, binding, &mut rng)
                })
                .collect::<crate::Result<Vec<_>>>()?;

            let aggregated: AggregatedPublicKey = shares.into_iter().aggregate()?;
            let bytes = aggregated.to_bytes();
            let restored = AggregatedPublicKey::from_bytes(&bytes, &params)?;
            assert_eq!(restored.key, aggregated.key);
            assert_eq!(restored.participant_set, aggregated.participant_set);
            Ok(())
        }

        #[test]
        fn aggregated_pk_rejects_missing_binding() -> crate::Result<()> {
            let params = BfvParameters::default_arc(6, 8);

            // Serialize a plain LBFVPublicKey (no binding) and try to deser as AggregatedPublicKey.
            let mut rng = rng();
            let sk = SecretKey::random(&params, &mut rng);
            let pk = LBFVPublicKey::new(&sk, &mut rng)?;
            let bytes = pk.to_bytes();
            assert!(
                AggregatedPublicKey::from_bytes(&bytes, &params).is_err(),
                "Must reject a proto without a binding"
            );
            Ok(())
        }

        #[test]
        fn aggregated_pk_rejects_contribution_binding() -> crate::Result<()> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            let participant_set = ParticipantSet::new([1u8; 32], vec![1, 2])?;
            let binding = ContributionBinding::new(participant_set, 1)?;

            let share = PublicKeyShare::new_with_seed_and_binding(&sk, seed, binding, &mut rng)?;
            let bytes = share.to_bytes();
            assert!(
                AggregatedPublicKey::from_bytes(&bytes, &params).is_err(),
                "Must reject a contribution binding (aggregate=false) when deserializing AggregatedPublicKey"
            );
            Ok(())
        }
    }
}
