use std::sync::Arc;

use crate::bfv::{BfvParameters, Ciphertext, PublicKey, SecretKey};
use crate::identity::ContributionBinding;
use crate::{Error, Result};
use fhe_math::rq::{Ntt, Poly, PowerBasis, traits::TryConvertFrom};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;
//use serde::{Serialize, Deserialize};

use crate::bfv::CommonRandomPoly;

use super::Aggregate;
use super::consistency::{
    require_poly_context, require_same_parameters, validate_binding_coverage,
};

/// A party's share in public key generation protocol.
///
/// Each party uses the `PublicKeyShare` to generate their share of the public key and participate in the in the "Protocol 1: EncKeyGen", as detailed in [Multiparty BFV](https://eprint.iacr.org/2020/304.pdf) (p6). Use the [`Aggregate`] impl to combine the shares into a [`PublicKey`].
///
/// # Binding contract
///
/// Every share carries a required [`ContributionBinding`] identifying its
/// contributor within an exact N-out-of-N [`ParticipantSet`] for one
/// operation-specific [`crate::SessionId`]. Aggregation rejects duplicate,
/// missing, unknown, or cross-session/set contributions before any polynomial
/// arithmetic. Bindings provide consistency only; they do not authenticate a
/// contributor. All parties must use the same concrete level-zero CRP.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKeyShare {
    pub(crate) params: Arc<BfvParameters>,
    pub(crate) crp: CommonRandomPoly,
    pub(crate) p0_share: Poly<Ntt>,
    pub(crate) binding: ContributionBinding,
}

impl PublicKeyShare {
    /// Participate in a new EncKeyGen protocol.
    ///
    /// 1. *Private input*: BFV secret key share
    /// 2. *Public input*: common random polynomial
    /// 3. *Binding*: this party's [`ContributionBinding`] for the execution
    //
    // Implementation note: This is largely the same approach taken by fhe.rs, a
    // symmetric encryption of zero, the difference being that the crp is used
    // instead of a random poly. Might be possible to just pass a valid seed to
    // each party and basically take the SecretKey::try_encrypt implementation,
    // but with the hardcoded seed.
    ///
    /// # Errors
    ///
    /// Returns an error if the CRP is not at the parameters' level-zero
    /// context: collective public-key generation is a level-zero protocol by
    /// design, and a nonzero-level CRP is rejected rather than silently
    /// combined.
    pub fn new<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        crp: CommonRandomPoly,
        binding: ContributionBinding,
        rng: &mut R,
    ) -> Result<Self> {
        let params = sk_share.params.clone();
        let ctx = params.context_at_level(0)?;

        // Collective public-key generation is level zero by protocol design:
        // reject a nonzero-level CRP instead of silently combining it later.
        require_poly_context(crp.poly(), ctx)?;

        // Convert secret key to usable polynomial
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?
                .into_ntt()?,
        );

        // Sample error
        let e = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);
        // Create p0_i share
        let mut p0_share = -crp.poly.clone();
        p0_share.disallow_variable_time_computations();
        p0_share *= s.as_ref();
        p0_share += e.as_ref();
        unsafe { p0_share.allow_variable_time_computations() }

        Ok(Self {
            params,
            crp,
            p0_share,
            binding,
        })
    }

    /// Extended version of `new` that returns intermediate values for debugging/testing.
    ///
    /// Returns: (pk_0, pk_1, sk_poly, e)
    /// - pk_0: the p0_share (public key part 0 share) = -a*s + e
    /// - pk_1: the crp_poly (common random polynomial `a`, public key part 1)
    /// - sk_poly: the secret key polynomial in NTT form
    /// - e: the error polynomial
    #[allow(clippy::type_complexity)]
    pub fn new_extended<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        crp: CommonRandomPoly,
        rng: &mut R,
    ) -> Result<(Poly<Ntt>, Poly<Ntt>, Poly<Ntt>, Poly<Ntt>)> {
        let params = sk_share.params.clone();
        let ctx = params.context_at_level(0)?;

        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?
                .into_ntt()?,
        );
        let e = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);

        let mut pk_0 = -crp.poly.clone();
        pk_0.disallow_variable_time_computations();
        pk_0 *= s.as_ref();
        pk_0 += e.as_ref();
        unsafe { pk_0.allow_variable_time_computations() }

        let pk_1 = crp.poly.clone();

        Ok((pk_0, pk_1, (*s).clone(), (*e).clone()))
    }

    /// Convert this PublicKeyShare to an individual PublicKey without aggregation.
    ///
    /// This creates a PublicKey that can be used for individual encryption/decryption
    /// with the corresponding SecretKey. The resulting PublicKey is NOT suitable for
    /// threshold operations - use aggregation for that.
    // pub fn to_public_key(&self) -> Result<PublicKey> {
    //     Ok(PublicKey {
    //         c: Ciphertext::new(
    //             vec![self.p0_share.clone(), self.crp.poly.clone()],
    //             &self.params,
    //         )?,
    //         params: self.params.clone(),
    //     })
    // }
    pub fn to_public_key(&self) -> Result<PublicKey> {
        let mut p0 = self.p0_share.clone();
        let mut p1 = self.crp.poly.clone();

        p0.disallow_variable_time_computations();
        p1.disallow_variable_time_computations();

        Ok(PublicKey {
            c: Ciphertext::new(vec![p0, p1], &self.params)?,
            params: self.params.clone(),
        })
    }

    /// Get a reference to the underlying p0_share polynomial.
    #[must_use]
    pub fn p0_share(&self) -> &Poly<Ntt> {
        &self.p0_share
    }

    /// Get the underlying p0_share polynomial (consumes self).
    #[must_use]
    pub fn into_p0_share(self) -> Poly<Ntt> {
        self.p0_share
    }

    /// Borrow the contribution binding attached to this share.
    #[must_use]
    pub fn binding(&self) -> &ContributionBinding {
        &self.binding
    }
}

impl Aggregate<PublicKeyShare> for PublicKey {
    /// Aggregate public-key shares into the collective [`PublicKey`].
    ///
    /// # Errors
    ///
    /// Validates, immediately after the share list is collected and before
    /// any parameter, context, CRP, or polynomial access: exact one-per-member
    /// coverage of the shares' common [`crate::ParticipantSet`] (rejecting
    /// duplicate, missing, unknown, and cross-session/set contributions);
    /// then structural parameter equality, concrete equality of every share's
    /// CRP, and that all polynomials live at the parameters' level-zero
    /// context.
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = PublicKeyShare>,
    {
        let shares = iter.into_iter().collect::<Vec<_>>();
        let (first, rest) = shares.split_first().ok_or(Error::TooFewValues {
            actual: 0,
            minimum: 1,
        })?;

        // Exact N-out-of-N coverage of every share's binding, validated
        // before any parameter, context, CRP, or polynomial access.
        validate_binding_coverage(shares.iter().map(|share| &share.binding))?;

        let ctx = first.params.context_at_level(0)?;
        require_poly_context(first.crp.poly(), ctx)?;
        require_poly_context(&first.p0_share, ctx)?;

        for share in rest {
            require_same_parameters(&share.params, &first.params)?;
            if share.crp != first.crp {
                return Err(Error::Mbfv(crate::MbfvError::PublicInputMismatch {
                    reason: "public-key shares use different level-zero CRPs".to_string(),
                }));
            }
            require_poly_context(share.crp.poly(), ctx)?;
            require_poly_context(&share.p0_share, ctx)?;
        }

        // Only validated values are combined.
        let mut p0 = first.p0_share.clone();
        for sh in rest {
            p0 += &sh.p0_share;
        }

        Ok(PublicKey {
            c: Ciphertext::new(vec![p0, first.crp.poly.clone()], &first.params)?,
            params: first.params.clone(),
        })
    }
}

// impl From<&PublicKeyShare> for PublicKeyShare {
//     fn from(pks: &PublicKeyShare) -> Self {
//         PublicKeyShareProto {
//             c: Some(CiphertextProto::from(&p0_share.p0)),
//         }
//     }
// }

// impl DeserializeWithCRP for PublicKeyShare {
//     type Error = Error;

//     fn from_bytes(bytes: &[u8], params: &Arc<Self::Parameters>, crp:
// CommonRandomPoly) -> Result<Self> {         Ok(Self {
//             params: params.clone(),
//             crp: crp.clone(),
//             p0_share,
//         })
//     }
// }

#[cfg(feature = "protobuf")]
mod protobuf {
    use super::*;
    use crate::mbfv::wire;
    use crate::proto::bfv::{MbfvPublicKeySharePayload, mbfv_share_envelope};
    use fhe_traits::{DeserializeWithContext as _, Serialize};

    impl PublicKeyShare {
        /// Deserialize a bound `PublicKeyShare` from a versioned MBFV share
        /// envelope.
        ///
        /// The caller supplies the parameters and the common random polynomial;
        /// collective public-key generation is a level-zero protocol by design,
        /// so the deserializer validates that the supplied CRP lives at the
        /// parameters' level-zero context and that the envelope's serialized
        /// level is zero. It also validates the supported version, a well-formed
        /// contribution binding, and that the decoded share polynomial lives in
        /// the level-zero context. Old raw polynomial bytes are rejected: there
        /// is no unbound fallback.
        ///
        /// Serialized share bytes alone do not prove provenance; cross-share
        /// binding and concrete-CRP checks remain the aggregation boundary.
        pub fn deserialize(
            bytes: &[u8],
            par: &std::sync::Arc<BfvParameters>,
            crp: CommonRandomPoly,
        ) -> Result<Self> {
            let envelope = wire::decode_share(bytes)?;
            let payload = match envelope.payload {
                Some(mbfv_share_envelope::Payload::PublicKeyShare(payload)) => payload,
                _ => {
                    return Err(Error::Mbfv(crate::MbfvError::ShareShapeMismatch {
                        reason: "envelope does not carry a public-key share payload".to_string(),
                    }));
                }
            };
            let binding = wire::decode_binding(envelope.binding)?;

            if payload.level != 0 {
                return Err(Error::Mbfv(crate::MbfvError::LevelMismatch {
                    found: payload.level as usize,
                    expected: 0,
                }));
            }
            let ctx = par.context_at_level(0)?;
            // Collective public-key generation is level zero by protocol
            // design; reject a nonzero-level CRP instead of combining it later.
            require_poly_context(crp.poly(), ctx)?;
            let p0_share = Poly::<Ntt>::from_bytes(&payload.p0_share, ctx)?;

            Ok(Self {
                params: par.clone(),
                crp,
                p0_share,
                binding,
            })
        }
    }

    impl Serialize for PublicKeyShare {
        fn to_bytes(&self) -> Vec<u8> {
            wire::encode_share(
                &self.binding,
                mbfv_share_envelope::Payload::PublicKeyShare(MbfvPublicKeySharePayload {
                    p0_share: self.p0_share.to_bytes(),
                    // Collective public-key generation is a level-zero protocol.
                    level: 0,
                }),
            )
        }
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    mod tests {
        use super::*;
        use crate::identity::{ParticipantSet, SessionId};
        use prost::Message as _;
        use rand::rng;

        fn bound_share(params: &Arc<BfvParameters>) -> (CommonRandomPoly, PublicKeyShare) {
            let mut rng = rng();
            let crp = CommonRandomPoly::new(params, &mut rng).unwrap();
            let set = ParticipantSet::new(SessionId::new([91u8; 32]), vec![1, 2]).unwrap();
            let sk_share = SecretKey::random(params, &mut rng);
            let binding = ContributionBinding::new(set, 1).unwrap();
            let share = PublicKeyShare::new(&sk_share, crp.clone(), binding, &mut rng).unwrap();
            (crp, share)
        }

        #[test]
        fn round_trips_binding_metadata() -> Result<()> {
            let params = BfvParameters::default_arc(6, 32);
            let (crp, share) = bound_share(&params);

            let restored = PublicKeyShare::deserialize(&share.to_bytes(), &params, crp.clone())?;
            assert_eq!(restored, share);
            assert_eq!(restored.binding().participant_id(), 1);
            assert_eq!(
                restored.binding().participant_set().session_id(),
                SessionId::new([91u8; 32])
            );
            assert_eq!(restored.crp, crp);
            Ok(())
        }

        #[test]
        fn rejects_wrong_level_payload_and_invalid_crp_context() -> Result<()> {
            let params = BfvParameters::default_arc(6, 32);
            let (crp, share) = bound_share(&params);

            // A nonzero serialized level is rejected even though EncKeyGen is
            // always level zero: decode the envelope, set the public-key
            // payload's declared level to one, and re-serialize.
            let mut envelope =
                crate::proto::bfv::MbfvShareEnvelope::decode(share.to_bytes().as_slice()).unwrap();
            assert!(
                matches!(
                    envelope.payload,
                    Some(crate::proto::bfv::mbfv_share_envelope::Payload::PublicKeyShare(_))
                ),
                "envelope does not carry a public-key payload"
            );
            if let Some(crate::proto::bfv::mbfv_share_envelope::Payload::PublicKeyShare(payload)) =
                envelope.payload.as_mut()
            {
                payload.level = 1;
            }
            let err = PublicKeyShare::deserialize(&envelope.encode_to_vec(), &params, crp.clone());
            assert!(
                matches!(
                    err,
                    Err(Error::Mbfv(crate::MbfvError::LevelMismatch {
                        found: 1,
                        expected: 0
                    }))
                ),
                "unexpected error: {err:?}"
            );

            // A nonzero-level CRP is rejected by the level-zero protocol.
            let leveled_crp = CommonRandomPoly::new_leveled(&params, 1, &mut rng())?;
            let err = PublicKeyShare::deserialize(&share.to_bytes(), &params, leveled_crp);
            assert!(
                matches!(err, Err(Error::Mbfv(crate::MbfvError::InvalidContext))),
                "unexpected error: {err:?}"
            );
            Ok(())
        }

        #[test]
        fn rejects_old_raw_bytes_and_malformed_metadata() -> Result<()> {
            let params = BfvParameters::default_arc(6, 32);
            let (crp, share) = bound_share(&params);

            // Old raw polynomial bytes have no version/binding metadata.
            let raw = share.p0_share().to_bytes();
            let err = PublicKeyShare::deserialize(&raw, &params, crp.clone());
            assert!(err.is_err(), "old raw bytes must be rejected");

            // A malformed session id inside an otherwise valid envelope.
            let mut envelope =
                crate::proto::bfv::MbfvShareEnvelope::decode(share.to_bytes().as_slice()).unwrap();
            envelope.binding.as_mut().unwrap().session_id = vec![7u8; 31];
            let err = PublicKeyShare::deserialize(&envelope.encode_to_vec(), &params, crp.clone());
            assert!(err.is_err(), "malformed session id must be rejected");
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use fhe_traits::{FheEncoder, FheEncrypter};
    use rand::rng;

    use crate::{
        bfv::{BfvParameters, CommonRandomPoly, Encoding, Plaintext, PublicKey, SecretKey},
        identity::{ContributionBinding, ParticipantSet, SessionId},
        mbfv::Aggregate as _,
    };

    use super::PublicKeyShare;

    const NUM_PARTIES: usize = 11;

    fn participant_set() -> ParticipantSet {
        ParticipantSet::new(
            SessionId::new([7u8; 32]),
            (1..=NUM_PARTIES as u32).collect(),
        )
        .unwrap()
    }

    fn bound_pk_share(
        params: &std::sync::Arc<BfvParameters>,
        set: &ParticipantSet,
        id: u32,
        crp: &CommonRandomPoly,
    ) -> PublicKeyShare {
        let sk_share = SecretKey::random(params, &mut rng());
        let binding = ContributionBinding::new(set.clone(), id).unwrap();
        PublicKeyShare::new(&sk_share, crp.clone(), binding, &mut rng()).unwrap()
    }

    #[test]
    // This just makes sure the public key creation is successful, and arbitrary
    // encryptions complete without error. See a full encrypt->decrypt test in
    // `secret_key_switch`.
    fn protocol_creates_valid_pk() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 32),
        ] {
            for level in 0..=params.max_level() {
                for _ in 0..20 {
                    let crp = CommonRandomPoly::new(&params, &mut rng)?;
                    let set = participant_set();

                    let mut pk_shares: Vec<PublicKeyShare> = vec![];

                    // Parties collectively generate public key
                    for i in 1..=NUM_PARTIES as u32 {
                        let sk_share = SecretKey::random(&params, &mut rng);
                        let binding = ContributionBinding::new(set.clone(), i)?;
                        let pk_share =
                            PublicKeyShare::new(&sk_share, crp.clone(), binding, &mut rng)?;
                        pk_shares.push(pk_share);
                    }
                    let public_key = PublicKey::from_shares(pk_shares)?;

                    // Use it to encrypt a random polynomial
                    let pt = Plaintext::try_encode(
                        &fhe_math::zq::Modulus::new(params.try_plaintext()?)
                            .unwrap()
                            .random_vec(params.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &params,
                    )
                    .unwrap();
                    let _ct = public_key.try_encrypt(&pt, &mut rng).unwrap();
                }
            }
        }
        Ok(())
    }

    #[test]
    fn aggregation_accepts_reordered_shares_and_reports_binding() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();
        // Exactly four contributors for this execution.
        let set = ParticipantSet::new(SessionId::new([7u8; 32]), vec![1, 2, 3, 4]).unwrap();

        let mut shares: Vec<PublicKeyShare> = (1..=4)
            .map(|i| bound_pk_share(&params, &set, i, &crp))
            .collect();
        shares.reverse();

        let pk = PublicKey::from_shares(shares.clone()).unwrap();
        assert_eq!(pk.params, params);

        // Every share carries its contribution binding.
        assert_eq!(shares.first().unwrap().binding().participant_id(), 4);
        assert_eq!(shares.first().unwrap().binding().participant_set(), &set);
    }

    #[test]
    fn aggregation_rejects_duplicate_participant_id() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();
        let set = ParticipantSet::new(SessionId::new([7u8; 32]), vec![1, 2]).unwrap();

        let one = bound_pk_share(&params, &set, 1, &crp);
        let duplicate_one = bound_pk_share(&params, &set, 1, &crp);

        let err = PublicKey::from_shares(vec![one, duplicate_one]).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Threshold(crate::ThresholdError::DuplicateContribution {
                    participant_id: 1
                })
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_missing_participant_contribution() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();
        // Set declares two members but only party 1 contributes.
        let set = ParticipantSet::new(SessionId::new([7u8; 32]), vec![1, 2]).unwrap();
        let one = bound_pk_share(&params, &set, 1, &crp);

        let err = PublicKey::from_shares(vec![one]).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Threshold(crate::ThresholdError::MissingContribution)
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_cross_session_shares() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();
        let set_a = ParticipantSet::new(SessionId::new([7u8; 32]), vec![1, 2]).unwrap();
        let set_b = ParticipantSet::new(SessionId::new([9u8; 32]), vec![1, 2]).unwrap();

        let a1 = bound_pk_share(&params, &set_a, 1, &crp);
        let b2 = bound_pk_share(&params, &set_b, 2, &crp);

        let err = PublicKey::from_shares(vec![a1, b2]).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Threshold(crate::ThresholdError::ContributionSetMismatch)
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_different_crps() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let crp_a = CommonRandomPoly::new(&params, &mut rng).unwrap();
        let crp_b = CommonRandomPoly::new(&params, &mut rng).unwrap();
        let set = ParticipantSet::new(SessionId::new([7u8; 32]), vec![1, 2]).unwrap();

        let a1 = bound_pk_share(&params, &set, 1, &crp_a);
        let b2 = bound_pk_share(&params, &set, 2, &crp_b);

        let err = PublicKey::from_shares(vec![a1, b2]).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Mbfv(crate::MbfvError::PublicInputMismatch { .. })
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_parameter_mismatch() {
        let mut rng = rng();
        let params_small = BfvParameters::default_arc(1, 16);
        let params_large = BfvParameters::default_arc(6, 32);
        let crp_small = CommonRandomPoly::new(&params_small, &mut rng).unwrap();
        let crp_large = CommonRandomPoly::new(&params_large, &mut rng).unwrap();
        let set = ParticipantSet::new(SessionId::new([7u8; 32]), vec![1, 2]).unwrap();

        let small = bound_pk_share(&params_small, &set, 1, &crp_small);
        let large = bound_pk_share(&params_large, &set, 2, &crp_large);

        let err = PublicKey::from_shares(vec![small, large]).unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(crate::MbfvError::ParameterMismatch)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn constructor_rejects_nonzero_level_crp() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let leveled_crp = CommonRandomPoly::new_leveled(&params, 1, &mut rng).unwrap();
        let set = ParticipantSet::new(SessionId::new([7u8; 32]), vec![1]).unwrap();
        let sk_share = SecretKey::random(&params, &mut rng);
        let binding = ContributionBinding::new(set, 1).unwrap();

        let err = PublicKeyShare::new(&sk_share, leveled_crp, binding, &mut rng).unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(crate::MbfvError::InvalidContext)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_wrong_share_context() {
        use fhe_math::rq::{Ntt, Poly};

        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();
        let set = ParticipantSet::new(SessionId::new([7u8; 32]), vec![1, 2]).unwrap();

        let good = bound_pk_share(&params, &set, 1, &crp);

        // Fabricate a share whose p0_share lives at another level's context,
        // bound to the set's other member so coverage stays exact.
        let ctx_other = params.context_at_level(1).unwrap();
        let mut bad = good.clone();
        bad.binding = ContributionBinding::new(set.clone(), 2).unwrap();
        bad.p0_share = Poly::<Ntt>::random(ctx_other, &mut rng);

        let err = PublicKey::from_shares(vec![good.clone(), bad]).unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(crate::MbfvError::InvalidContext)),
            "unexpected error: {err}"
        );

        // Sanity: the same pair without the fabricated context still aggregates.
        let other = bound_pk_share(&params, &set, 2, &crp);
        assert!(PublicKey::from_shares(vec![good, other]).is_ok());
    }

    #[test]
    fn test_new_extended() {
        let mut rng = rng();

        // Test with different parameter configurations
        for params in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            let sk_share = SecretKey::random(&params, &mut rng);
            let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();

            // Call new_extended
            let (pk_0, pk_1, s, e) =
                PublicKeyShare::new_extended(&sk_share, crp.clone(), &mut rng).unwrap();

            // Verify pk_1 is the same as crp polynomial
            assert_eq!(pk_1, crp.poly, "pk_1 should be the same as crp polynomial");

            // Verify the relationship: pk_0 = -a*s + e
            // Compute -a*s + e and compare with pk_0
            let mut expected = -crp.poly.clone();
            expected.disallow_variable_time_computations();
            expected *= &s;
            expected += &e;
            unsafe { expected.allow_variable_time_computations() }

            assert_eq!(pk_0, expected, "pk_0 should equal -a*s + e");

            assert_eq!(s.representation(), fhe_math::rq::Representation::Ntt);
            assert_eq!(e.representation(), fhe_math::rq::Representation::Ntt);
            assert_eq!(pk_0.representation(), fhe_math::rq::Representation::Ntt);
        }
    }

    #[test]
    fn test_new_extended_multiple_parties() {
        let mut rng = rng();
        const NUM_PARTIES: usize = 5;

        let params = BfvParameters::default_arc(1, 8);
        let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();

        // Generate extended data for multiple parties
        let mut extended_data = vec![];
        for _ in 0..NUM_PARTIES {
            let sk_share = SecretKey::random(&params, &mut rng);
            let (pk_0, pk_1, s, e) =
                PublicKeyShare::new_extended(&sk_share, crp.clone(), &mut rng).unwrap();
            extended_data.push((pk_0, pk_1, s, e));
        }

        // Verify all parties have the same pk_1 (crp)
        for (_, pk_1, _, _) in &extended_data {
            assert_eq!(
                *pk_1, crp.poly,
                "All parties should have the same pk_1 (crp)"
            );
        }

        // Verify the mathematical relationship holds for each party
        for (pk_0, pk_1, s, e) in &extended_data {
            let mut expected = -pk_1.clone();
            expected.disallow_variable_time_computations();
            expected *= s;
            expected += e;
            unsafe { expected.allow_variable_time_computations() }
            assert_eq!(*pk_0, expected, "pk_0 should equal -a*s + e for each party");
        }
    }

    #[test]
    fn test_new_extended_consistency_with_new() {
        let mut rng = rng();

        let params = BfvParameters::default_arc(1, 8);
        let sk_share = SecretKey::random(&params, &mut rng);
        let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();
        let set = ParticipantSet::new(SessionId::new([7u8; 32]), vec![1]).unwrap();

        // Create PublicKeyShare using original new()
        let pks = PublicKeyShare::new(
            &sk_share,
            crp.clone(),
            ContributionBinding::new(set, 1).unwrap(),
            &mut rng,
        )
        .unwrap();

        // Verify that new_extended produces pk_1 that matches the crp
        let (_pk_0, pk_1, _s, _e) =
            PublicKeyShare::new_extended(&sk_share, crp.clone(), &mut rng).unwrap();

        assert_eq!(
            pk_1, pks.crp.poly,
            "pk_1 from new_extended should match crp from PublicKeyShare"
        );
        assert_eq!(pk_1, crp.poly, "pk_1 should be the crp polynomial");
    }
}
