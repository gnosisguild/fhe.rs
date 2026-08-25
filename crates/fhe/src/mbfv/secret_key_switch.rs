use std::sync::Arc;

use fhe_math::rq::{Ntt, Poly, PowerBasis, traits::TryConvertFrom};
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::bfv::{BfvParameters, Ciphertext, Plaintext, PlaintextValues, SecretKey};
use crate::identity::ContributionBinding;
use crate::{Error, MbfvError, Result};

use super::Aggregate;
use super::consistency::{
    require_poly_context, require_same_ciphertext_input, require_same_parameters,
    validate_binding_coverage,
};

/// A party's share in the secret key switch protocol.
///
/// Each party uses the `SecretKeySwitchShare` to generate their share of the
/// new ciphertext and participate in the "Protocol 3: KeySwitch" protocol
/// detailed in [Multiparty BFV](https://eprint.iacr.org/2020/304.pdf) (p7). Use the [`Aggregate`] impl to combine the
/// shares into a [`Ciphertext`].
///
/// # Binding contract
///
/// Every share carries a required [`ContributionBinding`] identifying its
/// contributor within an exact N-out-of-N [`crate::ParticipantSet`] for one
/// operation-specific [`crate::SessionId`]. Aggregation rejects duplicate,
/// missing, unknown, or cross-session/set contributions, and verifies that
/// every share was generated for the same concrete input ciphertext (equal
/// parameters, level, component count, contexts, and polynomial values),
/// before any arithmetic. Bindings provide consistency only; they do not
/// authenticate a contributor or prove correct share formation. This protocol
/// assumes the output key is split into the same number of parties as the
/// input key, and remains semi-honest N-out-of-N.
#[derive(Debug, Clone)]
pub struct SecretKeySwitchShare {
    pub(crate) params: Arc<BfvParameters>,
    /// The original input ciphertext
    // Probably doesn't need to be Arc in real usage but w/e
    pub(crate) ct: Arc<Ciphertext>,
    pub(crate) h_share: Poly<Ntt>,
    pub(crate) binding: ContributionBinding,
}

impl SecretKeySwitchShare {
    /// Participate in a new KeySwitch protocol
    ///
    /// 1. *Private input*: BFV input secret key share
    /// 2. *Private input*: BFV output secret key share
    /// 3. *Public input*: Input ciphertext to keyswitch
    /// 4. *Binding*: this party's [`ContributionBinding`] for the execution
    ///
    /// The ciphertext may live at any supported level; the share records the
    /// ciphertext's actual level/context and all local conversion and error
    /// sampling use it.
    ///
    /// # Errors
    ///
    /// Returns an error if the shares and ciphertext use different BFV
    /// parameters, the ciphertext does not have the supported two-component
    /// shape, or the declared ciphertext level does not resolve to a context
    /// containing every ciphertext component.
    pub fn new<R: RngCore + CryptoRng>(
        sk_input_share: &SecretKey,
        sk_output_share: &SecretKey,
        ct: Arc<Ciphertext>,
        binding: ContributionBinding,
        rng: &mut R,
    ) -> Result<Self> {
        if sk_input_share.params != sk_output_share.params || sk_output_share.params != ct.params {
            return Err(Error::Mbfv(MbfvError::ParameterMismatch));
        }
        // Note: M-BFV implementation only supports ciphertext of length 2
        if ct.len() != 2 {
            return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: format!(
                    "MBFV key switching supports only two-component ciphertexts; found {}",
                    ct.len()
                ),
            }));
        }

        let params = sk_input_share.params.clone();
        // Resolve the working context from the ciphertext's *declared* level
        // and validate every ciphertext component against it. This is the
        // same contract the wire deserialization path enforces.
        let ctx = params.context_at_level(ct.level)?.clone();
        for component in ct.iter() {
            require_poly_context(component, &ctx)?;
        }
        // Length was validated as exactly two above.
        let Some(ct1) = ct.get(1) else {
            return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: "ciphertext lost its second component".to_string(),
            }));
        };

        let s_in = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_input_share.coeffs.as_ref(), &ctx, false)?
                .into_ntt()?,
        );
        let s_out = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_output_share.coeffs.as_ref(), &ctx, false)?
                .into_ntt()?,
        );

        // Sample error
        // TODO this should be exponential in ciphertext noise!
        let e = Zeroizing::new(Poly::<Ntt>::small(&ctx, params.variance, rng)?);

        // Create h_i share
        let mut h_share = s_in.as_ref() - s_out.as_ref();
        h_share.disallow_variable_time_computations();
        h_share *= ct1;
        h_share += e.as_ref();

        Ok(Self {
            params,
            ct,
            h_share,
            binding,
        })
    }

    /// Borrow the contribution binding attached to this share.
    #[must_use]
    pub fn binding(&self) -> &ContributionBinding {
        &self.binding
    }
}

impl Aggregate<SecretKeySwitchShare> for Ciphertext {
    /// Aggregate secret-key-switch shares into the switched [`Ciphertext`].
    ///
    /// # Errors
    ///
    /// Validates, before any polynomial arithmetic: exact one-per-member
    /// coverage of the shares' common [`crate::ParticipantSet`] (rejecting
    /// duplicate, missing, unknown, unbound, and cross-session/set
    /// contributions immediately after the share list is collected),
    /// structural equality of every share's input ciphertext (parameters,
    /// declared level, component count, contexts, and concrete polynomial
    /// values), a context resolved from the declared level that contains
    /// every ciphertext component, and that every `h` share lives in that
    /// context. The output retains the validated input level.
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = SecretKeySwitchShare>,
    {
        let shares = iter.into_iter().collect::<Vec<_>>();
        let (first, rest) = shares.split_first().ok_or(Error::TooFewValues {
            actual: 0,
            minimum: 1,
        })?;

        // Exact N-out-of-N coverage of every share's binding, validated
        // before any parameter, context, ciphertext-component, or polynomial
        // access.
        validate_binding_coverage(shares.iter().map(|share| &share.binding))?;

        require_same_parameters(&first.params, &first.ct.params)?;
        if first.ct.len() != 2 {
            return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: format!(
                    "MBFV key switching supports only two-component ciphertexts; found {}",
                    first.ct.len()
                ),
            }));
        }
        // Resolve the expected context from the declared ciphertext level and
        // validate every ciphertext component and share polynomial against
        // it, mirroring the wire deserialization contract.
        let ctx = first.params.context_at_level(first.ct.level)?.clone();
        for component in first.ct.iter() {
            require_poly_context(component, &ctx)?;
        }
        require_poly_context(&first.h_share, &ctx)?;
        for sh in rest {
            require_same_parameters(&sh.params, &first.params)?;
            require_same_ciphertext_input(&sh.ct, &first.ct)?;
            require_poly_context(&sh.h_share, &ctx)?;
        }

        let mut h = first.h_share.clone();
        for sh in rest {
            h += &sh.h_share;
        }

        // Lengths validated above; access remains fallible.
        let ct0 = first
            .ct
            .first()
            .ok_or(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: "ciphertext lost its first component".to_string(),
            }))?;
        let ct1 = first
            .ct
            .get(1)
            .ok_or(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: "ciphertext lost its second component".to_string(),
            }))?;
        let c0 = ct0 + &h;
        let c1 = ct1.clone();

        Ciphertext::new(vec![c0, c1], &first.params)
    }
}

/// A party's share in the decryption protocol.
///
/// Each party uses the `DecryptionShare` to generate their share of the
/// plaintext output. Note that this is a special case of the "Protocol 3:
/// KeySwitch" protocol detailed in [Multiparty BFV](https://eprint.iacr.org/2020/304.pdf) (p7), using an output key of zero. Use the
/// [`Aggregate`] impl to combine the shares into a [`Plaintext`].
pub struct DecryptionShare {
    pub(crate) sks_share: SecretKeySwitchShare,
}

impl DecryptionShare {
    /// Participate in a new Decryption protocol.
    ///
    /// 1. *Private input*: BFV input secret key share
    /// 2. *Public input*: Ciphertext to decrypt
    /// 3. *Binding*: this party's [`ContributionBinding`] for the execution
    ///
    /// # Errors
    ///
    /// Delegates the parameter, shape, level, and binding contract of
    /// [`SecretKeySwitchShare::new`].
    pub fn new<R: RngCore + CryptoRng>(
        sk_input_share: &SecretKey,
        ct: &Arc<Ciphertext>,
        binding: ContributionBinding,
        rng: &mut R,
    ) -> Result<Self> {
        let params = &sk_input_share.params;
        let zero = SecretKey::new(vec![0; params.degree()], params);
        let sks_share = SecretKeySwitchShare::new(sk_input_share, &zero, ct.clone(), binding, rng)?;
        Ok(DecryptionShare { sks_share })
    }
}

impl Aggregate<DecryptionShare> for Plaintext {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = DecryptionShare>,
    {
        let sks_shares = iter.into_iter().map(|s| s.sks_share);
        let ct = Ciphertext::from_shares(sks_shares)?;

        // Note: during SKS, the second component times the secret key has
        // already been added to the first component.
        let c0_poly = ct
            .first()
            .ok_or(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: "aggregated ciphertext lost its first component".to_string(),
            }))?;
        let mut c = Zeroizing::new(c0_poly.clone());
        c.disallow_variable_time_computations();
        let ctx = c.ctx().clone();
        let c_inner = std::mem::replace(c.as_mut(), Poly::<Ntt>::zero(&ctx));
        let c = c_inner.into_power_basis()?;

        // The true decryption part is done during SKS; all that is left is to scale
        let ctx_lvl = ct.params.context_level_at(ct.level)?;
        let d = Zeroizing::new(c.scale(&ctx_lvl.cipher_plain_context.scaler)?);

        let v: Vec<BigUint> = Vec::<BigUint>::try_from(d.as_ref())?
            .into_iter()
            .map(|vi| vi + ct.params.plaintext_big())
            .collect_vec();

        let degree = ct.params.degree();
        let Some(mut w) = v.get(..degree).map(<[BigUint]>::to_vec) else {
            return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: format!("scaled decryption produced {degree} values",),
            }));
        };
        let q_poly = d.as_ref().ctx().modulus();
        w.iter_mut().for_each(|wi| *wi %= q_poly);

        ct.params.plaintext.reduce_vec(&mut w);

        let poly = Poly::<PowerBasis>::try_convert_from(w.as_slice(), &ctx, false)?.into_ntt()?;

        let value = match ct.params.plaintext {
            crate::bfv::PlaintextModulus::Small { .. } => PlaintextValues::Small(
                w.iter()
                    .map(|x| x.to_u64().unwrap())
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
            crate::bfv::PlaintextModulus::Large(_) => PlaintextValues::Large(w.into_boxed_slice()),
        };

        let pt = Plaintext {
            params: ct.params.clone(),
            value,
            encoding: None,
            poly_ntt: poly,
            level: ct.level,
        };

        Ok(pt)
    }
}

#[cfg(feature = "protobuf")]
mod protobuf {
    use super::*;
    use crate::mbfv::wire;
    use crate::proto::bfv::{MbfvSecretKeySwitchSharePayload, mbfv_share_envelope};
    use fhe_traits::{DeserializeWithContext as _, Serialize};

    impl SecretKeySwitchShare {
        /// Deserialize a bound `SecretKeySwitchShare` from a versioned MBFV
        /// share envelope.
        ///
        /// The caller supplies the parameters and the input ciphertext; the
        /// polynomial context is derived from the ciphertext's level (not
        /// unconditionally from level zero). Deserialization validates that
        /// the envelope carries the supported version and a well-formed
        /// binding, that the serialized level equals the supplied ciphertext
        /// level, that the ciphertext has the supported two-component shape at
        /// the supplied parameters, and that every ciphertext component lives
        /// in the derived context. Old raw polynomial bytes are rejected:
        /// there is no unbound fallback.
        ///
        /// Serialized share bytes alone do not prove provenance; cross-share
        /// binding and concrete-input checks remain the aggregation boundary.
        pub fn deserialize(
            bytes: &[u8],
            par: &std::sync::Arc<BfvParameters>,
            ct: std::sync::Arc<Ciphertext>,
        ) -> Result<Self> {
            let envelope = wire::decode_share(bytes)?;
            let payload = match envelope.payload {
                Some(mbfv_share_envelope::Payload::SecretKeySwitchShare(payload)) => payload,
                _ => {
                    return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                        reason: "envelope does not carry a secret-key-switch share payload"
                            .to_string(),
                    }));
                }
            };
            let binding = wire::decode_binding(envelope.binding)?;

            require_same_parameters(&ct.params, par)?;
            if ct.len() != 2 {
                return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                    reason: format!(
                        "MBFV key switching supports only two-component ciphertexts; found {}",
                        ct.len()
                    ),
                }));
            }
            let expected_level = ct.level;
            if payload.level as usize != expected_level {
                return Err(Error::Mbfv(MbfvError::LevelMismatch {
                    found: payload.level as usize,
                    expected: expected_level,
                }));
            }
            let ctx = par.context_at_level(expected_level)?;
            for component in ct.iter() {
                require_poly_context(component, ctx)?;
            }
            let h_share = Poly::<Ntt>::from_bytes(&payload.h_share, ctx)?;

            Ok(Self {
                params: par.clone(),
                ct,
                h_share,
                binding,
            })
        }
    }

    impl Serialize for SecretKeySwitchShare {
        fn to_bytes(&self) -> Vec<u8> {
            wire::encode_share(
                &self.binding,
                mbfv_share_envelope::Payload::SecretKeySwitchShare(
                    MbfvSecretKeySwitchSharePayload {
                        h_share: self.h_share.to_bytes(),
                        level: self.ct.level as u32,
                    },
                ),
            )
        }
    }

    impl DecryptionShare {
        /// Deserialize a bound `DecryptionShare` from a versioned MBFV share
        /// envelope.
        ///
        /// Delegates the level-aware validation contract of
        /// [`SecretKeySwitchShare::deserialize`] with the caller-supplied
        /// parameters and ciphertext.
        pub fn deserialize(
            bytes: &[u8],
            par: &std::sync::Arc<BfvParameters>,
            ct: std::sync::Arc<Ciphertext>,
        ) -> Result<Self> {
            Ok(Self {
                sks_share: SecretKeySwitchShare::deserialize(bytes, par, ct)?,
            })
        }
    }

    impl Serialize for DecryptionShare {
        fn to_bytes(&self) -> Vec<u8> {
            self.sks_share.to_bytes()
        }
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    mod tests {
        use super::*;
        use crate::bfv::{CommonRandomPoly, Encoding, PublicKey};
        use crate::identity::{ParticipantSet, SessionId};
        use crate::mbfv::PublicKeyShare;
        use fhe_traits::{FheEncoder as _, FheEncrypter as _};
        use prost::Message as _;
        use rand::rng;

        const NUM_PARTIES: usize = 3;

        fn participant_set(session: u8) -> ParticipantSet {
            ParticipantSet::new(
                SessionId::new([session; 32]),
                (1..=NUM_PARTIES as u32).collect(),
            )
            .unwrap()
        }

        /// Collective key generation plus an encryption at `level`; returns
        /// the parties' secret-key shares and the ciphertext.
        fn setup(
            params: &Arc<BfvParameters>,
            set: &ParticipantSet,
            level: usize,
        ) -> Vec<(SecretKey, Arc<Ciphertext>)> {
            let mut rng = rng();
            let crp = CommonRandomPoly::new(params, &mut rng).unwrap();
            let mut sk_shares: Vec<SecretKey> = Vec::with_capacity(NUM_PARTIES);
            let mut pk_shares: Vec<PublicKeyShare> = Vec::with_capacity(NUM_PARTIES);
            for i in 1..=NUM_PARTIES as u32 {
                let sk_share = SecretKey::random(params, &mut rng);
                let binding = ContributionBinding::new(set.clone(), i).unwrap();
                pk_shares
                    .push(PublicKeyShare::new(&sk_share, crp.clone(), binding, &mut rng).unwrap());
                sk_shares.push(sk_share);
            }
            let public_key: PublicKey = Aggregate::from_shares(pk_shares).unwrap();
            let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
            let pt = Plaintext::try_encode(
                &q.random_vec(params.degree(), &mut rng),
                Encoding::poly_at_level(level),
                params,
            )
            .unwrap();
            let ct = Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap());
            assert_eq!(ct.level, level);
            sk_shares.into_iter().map(|sk| (sk, ct.clone())).collect()
        }

        #[test]
        fn round_trip_at_level_zero_and_nonzero_levels() -> Result<()> {
            for params in [BfvParameters::default_arc(6, 32)] {
                for level in 0..=params.max_level() {
                    let set = participant_set(92);
                    let parties = setup(&params, &set, level);

                    // Serialize each decryption share and deserialize it
                    // against a fresh copy of the ciphertext; the aggregate
                    // must retain the original level.
                    let mut restored: Vec<DecryptionShare> = Vec::new();
                    for (i, (sk, ct)) in parties.iter().enumerate() {
                        let binding = ContributionBinding::new(set.clone(), i as u32 + 1)?;
                        let share = DecryptionShare::new(sk, ct, binding, &mut rng())?;
                        let bytes = share.to_bytes();
                        restored.push(DecryptionShare::deserialize(&bytes, &params, ct.clone())?);
                    }
                    let pt: Plaintext =
                        <Plaintext as Aggregate<DecryptionShare>>::from_shares(restored)?;
                    assert_eq!(pt.level, level);
                }
            }
            Ok(())
        }

        #[test]
        fn rejects_serialized_level_mismatching_ciphertext() -> Result<()> {
            let params = BfvParameters::default_arc(6, 32);
            let set = participant_set(93);
            let parties = setup(&params, &set, 0);

            let (sk, ct_l0) = &parties[0];
            let binding = ContributionBinding::new(set, 1)?;
            let share = DecryptionShare::new(sk, ct_l0, binding, &mut rng())?;
            let bytes = share.to_bytes();

            // Deserialize against a switched-down ciphertext of the same
            // parameters: the serialized level no longer matches.
            let mut ct_l1 = (**ct_l0).clone();
            ct_l1.switch_down()?;
            assert_ne!(ct_l0.level, ct_l1.level);
            let err = SecretKeySwitchShare::deserialize(&bytes, &params, Arc::new(ct_l1.clone()));
            assert!(
                matches!(
                    err,
                    Err(Error::Mbfv(MbfvError::LevelMismatch {
                        found: 0,
                        expected: 1
                    }))
                ),
                "unexpected error: {err:?}"
            );

            // The matching ciphertext still deserializes.
            assert!(DecryptionShare::deserialize(&bytes, &params, ct_l0.clone()).is_ok());
            Ok(())
        }

        #[test]
        fn rejects_old_raw_bytes_bad_versions_and_malformed_metadata() -> Result<()> {
            let params = BfvParameters::default_arc(6, 32);
            let set = participant_set(94);
            let parties = setup(&params, &set, 0);

            let (sk, ct) = &parties[0];
            let binding = ContributionBinding::new(set, 1)?;
            let share = SecretKeySwitchShare::new(
                sk,
                &SecretKey::new(vec![0i64; params.degree()], &params),
                ct.clone(),
                binding,
                &mut rng(),
            )?;
            let bytes = share.to_bytes();

            // Old wire format was the bare polynomial payload; it carries no
            // envelope version or binding metadata.
            let old_bytes = share.h_share_bytes_only();
            assert!(
                SecretKeySwitchShare::deserialize(&old_bytes, &params, ct.clone()).is_err(),
                "old raw bytes must be rejected"
            );
            // Random bytes must not parse either.
            assert!(
                SecretKeySwitchShare::deserialize(&vec![0xaau8; 512], &params, ct.clone()).is_err()
            );

            // An unsupported explicit version is rejected.
            let mut envelope =
                crate::proto::bfv::MbfvShareEnvelope::decode(bytes.as_slice()).unwrap();
            envelope.version = 2;
            let err =
                SecretKeySwitchShare::deserialize(&envelope.encode_to_vec(), &params, ct.clone());
            assert!(
                matches!(
                    err,
                    Err(Error::Mbfv(MbfvError::UnsupportedVersion {
                        found: 2,
                        expected: 1
                    }))
                ),
                "unexpected error: {err:?}"
            );

            // A malformed session ID inside the envelope is rejected.
            let mut envelope =
                crate::proto::bfv::MbfvShareEnvelope::decode(bytes.as_slice()).unwrap();
            envelope.binding.as_mut().unwrap().session_id = vec![1u8; 31];
            assert!(
                SecretKeySwitchShare::deserialize(&envelope.encode_to_vec(), &params, ct.clone())
                    .is_err()
            );

            // Duplicate participant IDs in the canonical list are rejected.
            let mut envelope =
                crate::proto::bfv::MbfvShareEnvelope::decode(bytes.as_slice()).unwrap();
            envelope.binding.as_mut().unwrap().participant_ids = vec![1, 1];
            assert!(
                SecretKeySwitchShare::deserialize(&envelope.encode_to_vec(), &params, ct.clone())
                    .is_err()
            );
            Ok(())
        }

        impl SecretKeySwitchShare {
            /// The pre-envelope wire format: only the polynomial payload.
            fn h_share_bytes_only(&self) -> Vec<u8> {
                self.h_share.to_bytes()
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use std::sync::Arc;

    use fhe_math::rq::Ntt;
    use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
    use rand::rng;

    use crate::{
        MbfvError,
        bfv::{
            BfvParameters, Ciphertext, CommonRandomPoly, Encoding, Plaintext, PublicKey, SecretKey,
        },
        identity::{ContributionBinding, ParticipantSet, SessionId},
        mbfv::{Aggregate, AggregateIter, DecryptionShare, PublicKeyShare, SecretKeySwitchShare},
    };

    const NUM_PARTIES: usize = 11;

    struct Party {
        sk_share: SecretKey,
        pk_share: PublicKeyShare,
    }

    fn participant_set(session: u8) -> ParticipantSet {
        ParticipantSet::new(
            SessionId::new([session; 32]),
            (1..=NUM_PARTIES as u32).collect(),
        )
        .unwrap()
    }

    /// Generate collective public-key shares for every member of the given
    /// participant set.
    fn generate_parties(params: &Arc<BfvParameters>, set: &ParticipantSet) -> Vec<Party> {
        let mut rng = rng();
        let crp = CommonRandomPoly::new(params, &mut rng).unwrap();
        set.participant_ids()
            .iter()
            .map(|&i| {
                let sk_share = SecretKey::random(params, &mut rng);
                let binding = ContributionBinding::new(set.clone(), i).unwrap();
                let pk_share =
                    PublicKeyShare::new(&sk_share, crp.clone(), binding, &mut rng).unwrap();
                Party { sk_share, pk_share }
            })
            .collect()
    }

    #[test]
    fn encrypt_decrypt() {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 32),
        ] {
            for level in 0..=params.max_level() {
                for _ in 0..20 {
                    let set = participant_set(11);
                    let parties = generate_parties(&params, &set);

                    let public_key: PublicKey = parties
                        .iter()
                        .map(|p| p.pk_share.clone())
                        .aggregate()
                        .unwrap();

                    // Use it to encrypt a random polynomial
                    let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
                    let pt1 = Plaintext::try_encode(
                        &q.random_vec(params.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &params,
                    )
                    .unwrap();
                    let ct = Arc::new(public_key.try_encrypt(&pt1, &mut rng).unwrap());

                    // Parties perform a collective decryption
                    let decryption_shares = parties.iter().enumerate().map(|(i, p)| {
                        DecryptionShare::new(
                            &p.sk_share,
                            &ct,
                            ContributionBinding::new(set.clone(), i as u32 + 1).unwrap(),
                            &mut rng,
                        )
                    });
                    let pt2 = Plaintext::from_shares(decryption_shares).unwrap();

                    assert_eq!(pt1, pt2);
                }
            }
        }
    }

    #[test]
    fn encrypt_keyswitch_decrypt() {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 32),
        ] {
            for level in 0..=params.max_level() {
                for _ in 0..20 {
                    // Parties collectively generate public key
                    let in_set = participant_set(21);
                    let parties = generate_parties(&params, &in_set);

                    let public_key: PublicKey = parties
                        .iter()
                        .map(|p| p.pk_share.clone())
                        .aggregate()
                        .unwrap();

                    // Use it to encrypt a random polynomial ct1
                    let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
                    let pt1 = Plaintext::try_encode(
                        &q.random_vec(params.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &params,
                    )
                    .unwrap();
                    let ct1 = Arc::new(public_key.try_encrypt(&pt1, &mut rng).unwrap());

                    // Key switch ct1 to a different set of parties
                    let out_set = participant_set(22);
                    let out_parties = generate_parties(&params, &out_set);
                    let ct2: Ciphertext = parties
                        .iter()
                        .zip(out_parties.iter())
                        .enumerate()
                        .map(|(i, (ip, op))| {
                            SecretKeySwitchShare::new(
                                &ip.sk_share,
                                &op.sk_share,
                                ct1.clone(),
                                ContributionBinding::new(in_set.clone(), i as u32 + 1).unwrap(),
                                &mut rng,
                            )
                        })
                        .aggregate()
                        .unwrap();
                    assert_eq!(ct2.level, ct1.level);
                    let ct2 = Arc::new(ct2);

                    // The second set of parties then does a collective decryption
                    let pt2 = out_parties
                        .iter()
                        .enumerate()
                        .map(|(i, p)| {
                            DecryptionShare::new(
                                &p.sk_share,
                                &ct2,
                                ContributionBinding::new(out_set.clone(), i as u32 + 1).unwrap(),
                                &mut rng,
                            )
                        })
                        .aggregate()
                        .unwrap();

                    assert_eq!(pt1, pt2);
                }
            }
        }
    }

    #[test]
    fn collective_keys_enable_homomorphic_addition() {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 32),
        ] {
            for level in 0..=params.max_level() {
                for _ in 0..20 {
                    let set = participant_set(31);
                    let parties = generate_parties(&params, &set);
                    let public_key: PublicKey = parties
                        .iter()
                        .map(|p| p.pk_share.clone())
                        .aggregate()
                        .unwrap();

                    // Parties encrypt two plaintexts
                    let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
                    let a = q.random_vec(params.degree(), &mut rng);
                    let b = q.random_vec(params.degree(), &mut rng);
                    let mut expected = a.clone();
                    q.add_vec(&mut expected, &b);

                    let pt_a =
                        Plaintext::try_encode(&a, Encoding::poly_at_level(level), &params).unwrap();
                    let pt_b =
                        Plaintext::try_encode(&b, Encoding::poly_at_level(level), &params).unwrap();
                    let ct_a = public_key.try_encrypt(&pt_a, &mut rng).unwrap();
                    let ct_b = public_key.try_encrypt(&pt_b, &mut rng).unwrap();

                    // and add them together
                    let ct = Arc::new(&ct_a + &ct_b);

                    // Parties perform a collective decryption
                    let pt = parties
                        .iter()
                        .enumerate()
                        .map(|(i, p)| {
                            DecryptionShare::new(
                                &p.sk_share,
                                &ct,
                                ContributionBinding::new(set.clone(), i as u32 + 1).unwrap(),
                                &mut rng,
                            )
                        })
                        .aggregate()
                        .unwrap();

                    assert_eq!(
                        Vec::<u64>::try_decode(&pt, Encoding::poly_at_level(level)).unwrap(),
                        expected
                    );
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Aggregation rejection matrix (#89)
    // -----------------------------------------------------------------------

    /// Build one secret-key-switch share against ciphertext `ct`, bound to
    /// `binding`.
    fn sks_share_for(
        params: &Arc<BfvParameters>,
        ct: &Arc<Ciphertext>,
        binding: ContributionBinding,
    ) -> SecretKeySwitchShare {
        let mut rng = rng();
        let sk_in = SecretKey::random(params, &mut rng);
        let sk_out = SecretKey::random(params, &mut rng);
        SecretKeySwitchShare::new(&sk_in, &sk_out, ct.clone(), binding, &mut rng).unwrap()
    }

    #[test]
    fn one_share_aggregate_is_valid_for_single_member_set() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();
        let set = ParticipantSet::new(SessionId::new([41u8; 32]), vec![7]).unwrap();

        let mut parties: Vec<Party> = vec![];
        let sk_share = SecretKey::random(&params, &mut rng);
        let pk_share = PublicKeyShare::new(
            &sk_share,
            crp.clone(),
            ContributionBinding::new(set.clone(), 7).unwrap(),
            &mut rng,
        )
        .unwrap();
        parties.push(Party { sk_share, pk_share });
        let public_key: PublicKey = parties
            .iter()
            .map(|p| p.pk_share.clone())
            .aggregate()
            .unwrap();
        let pt1 = Plaintext::try_encode(&[0u64; 32], Encoding::poly_at_level(0), &params).unwrap();
        let ct = Arc::new(public_key.try_encrypt(&pt1, &mut rng).unwrap());

        let share = DecryptionShare::new(
            &parties[0].sk_share,
            &ct,
            ContributionBinding::new(set.clone(), 7).unwrap(),
            &mut rng,
        )
        .unwrap();
        let pt2 = Plaintext::from_shares(vec![share]).unwrap();
        assert_eq!(pt1, pt2);
    }

    #[test]
    fn aggregation_rejects_different_input_ciphertexts_same_level() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        // Exact two-member set; one contribution is tampered below.
        let set = ParticipantSet::new(SessionId::new([42u8; 32]), vec![1, 2]).unwrap();
        let parties = generate_parties(&params, &set);
        let public_key: PublicKey = parties
            .iter()
            .map(|p| p.pk_share.clone())
            .aggregate()
            .unwrap();

        let pt = Plaintext::try_encode(&[1u64; 32], Encoding::poly_at_level(0), &params).unwrap();
        let ct_a = Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap());
        let ct_b = Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap());
        assert_ne!(ct_a[0], ct_b[0], "fresh encryptions must differ");

        let shares = vec![
            sks_share_for(
                &params,
                &ct_a,
                ContributionBinding::new(set.clone(), 1).unwrap(),
            ),
            sks_share_for(
                &params,
                &ct_b,
                ContributionBinding::new(set.clone(), 2).unwrap(),
            ),
        ];
        let err = <Ciphertext as Aggregate<SecretKeySwitchShare>>::from_shares(shares).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Mbfv(MbfvError::PublicInputMismatch { .. })
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn constructor_rejects_parameter_mismatch() {
        let mut rng = rng();
        let params_big = BfvParameters::default_arc(6, 32);
        let params_small = BfvParameters::default_arc(1, 16);
        let set = participant_set(43);

        // The constructor rejects secret keys and ciphertext built under
        // different parameters before any polynomial is formed.
        let ct_params_big = Arc::new({
            let ctx = params_big.context_at_level(0).unwrap();
            Ciphertext::new(
                vec![
                    fhe_math::rq::Poly::<Ntt>::random(ctx, &mut rng),
                    fhe_math::rq::Poly::<Ntt>::random(ctx, &mut rng),
                ],
                &params_big,
            )
            .unwrap()
        });
        let err = SecretKeySwitchShare::new(
            &SecretKey::random(&params_small, &mut rng),
            &SecretKey::random(&params_small, &mut rng),
            ct_params_big,
            ContributionBinding::new(set.clone(), 1).unwrap(),
            &mut rng,
        )
        .unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::ParameterMismatch)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_parameter_mismatch() {
        let mut rng = rng();
        let params_big = BfvParameters::default_arc(6, 32);
        let params_small = BfvParameters::default_arc(1, 16);
        // Exact two-member set; the second share carries tampered parameters.
        let set = ParticipantSet::new(SessionId::new([43u8; 32]), vec![1, 2]).unwrap();
        let parties = generate_parties(&params_big, &set);
        let public_key: PublicKey = parties
            .iter()
            .map(|p| p.pk_share.clone())
            .aggregate()
            .unwrap();
        let pt =
            Plaintext::try_encode(&[2u64; 32], Encoding::poly_at_level(0), &params_big).unwrap();
        let ct = Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap());

        let good = sks_share_for(
            &params_big,
            &ct,
            ContributionBinding::new(set.clone(), 1).unwrap(),
        );
        // A deserialized or assembled share could carry inconsistent
        // parameters; aggregation must still reject it.
        let mut bad = sks_share_for(
            &params_big,
            &ct,
            ContributionBinding::new(set.clone(), 2).unwrap(),
        );
        bad.params = params_small;
        let err = <Ciphertext as Aggregate<SecretKeySwitchShare>>::from_shares(vec![good, bad])
            .unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::ParameterMismatch)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_wrong_h_share_context() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        // Exact two-member set; the second h share carries a foreign context.
        let set = ParticipantSet::new(SessionId::new([44u8; 32]), vec![1, 2]).unwrap();
        let parties = generate_parties(&params, &set);
        let public_key: PublicKey = parties
            .iter()
            .map(|p| p.pk_share.clone())
            .aggregate()
            .unwrap();
        let pt = Plaintext::try_encode(&[3u64; 32], Encoding::poly_at_level(0), &params).unwrap();
        let ct = Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap());

        let good = sks_share_for(
            &params,
            &ct,
            ContributionBinding::new(set.clone(), 1).unwrap(),
        );
        let mut bad = sks_share_for(
            &params,
            &ct,
            ContributionBinding::new(set.clone(), 2).unwrap(),
        );
        bad.h_share =
            fhe_math::rq::Poly::<Ntt>::random(params.context_at_level(1).unwrap(), &mut rng);

        let err = <Ciphertext as Aggregate<SecretKeySwitchShare>>::from_shares(vec![good, bad])
            .unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::InvalidContext)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_mixed_levels() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        // Exact two-member set; the second share was generated at level 1.
        let set = ParticipantSet::new(SessionId::new([45u8; 32]), vec![1, 2]).unwrap();
        let parties = generate_parties(&params, &set);
        let public_key: PublicKey = parties
            .iter()
            .map(|p| p.pk_share.clone())
            .aggregate()
            .unwrap();
        let pt = Plaintext::try_encode(&[4u64; 32], Encoding::poly_at_level(0), &params).unwrap();
        let ct_l0 = Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap());
        let mut ct_l1 = (*ct_l0).clone();
        ct_l1.switch_down().unwrap();
        let ct_l1 = Arc::new(ct_l1);
        assert_ne!(ct_l0.level, ct_l1.level);

        let good = sks_share_for(
            &params,
            &ct_l0,
            ContributionBinding::new(set.clone(), 1).unwrap(),
        );
        let bad = sks_share_for(
            &params,
            &ct_l1,
            ContributionBinding::new(set.clone(), 2).unwrap(),
        );

        let err = <Ciphertext as Aggregate<SecretKeySwitchShare>>::from_shares(vec![good, bad])
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Mbfv(MbfvError::LevelMismatch {
                    found: 1,
                    expected: 0
                })
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn constructor_rejects_level_inconsistent_with_component_contexts() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let set = ParticipantSet::new(SessionId::new([52u8; 32]), vec![1]).unwrap();
        let parties = generate_parties(&params, &set);
        let public_key: PublicKey = parties
            .iter()
            .map(|p| p.pk_share.clone())
            .aggregate()
            .unwrap();
        let pt = Plaintext::try_encode(&[8u64; 32], Encoding::poly_at_level(0), &params).unwrap();
        let ct_l0 = Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap());

        // A fabricated or assembled ciphertext that declares level 1 while
        // its components still live in the level-zero context must be
        // rejected rather than trusted.
        let mut lying_ct: Ciphertext = (*ct_l0).clone();
        assert_ne!(
            params.context_at_level(0).unwrap(),
            params.context_at_level(1).unwrap()
        );
        lying_ct.level = 1;

        let err = SecretKeySwitchShare::new(
            &parties[0].sk_share,
            &SecretKey::new(vec![0i64; params.degree()], &params),
            Arc::new(lying_ct),
            ContributionBinding::new(set, 1).unwrap(),
            &mut rng,
        )
        .unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::InvalidContext)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_declared_level_inconsistent_with_context() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let set = ParticipantSet::new(SessionId::new([53u8; 32]), vec![1]).unwrap();
        let parties = generate_parties(&params, &set);
        let public_key: PublicKey = parties
            .iter()
            .map(|p| p.pk_share.clone())
            .aggregate()
            .unwrap();
        let pt = Plaintext::try_encode(&[9u64; 32], Encoding::poly_at_level(0), &params).unwrap();
        let ct_l0 = Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap());

        // Build an honestly bound share, then forge its stored ciphertext's
        // declared level; aggregation resolves contexts from the declared
        // level and must reject the mismatch.
        let share = sks_share_for(&params, &ct_l0, ContributionBinding::new(set, 1).unwrap());
        let mut forged = share.clone();
        let mut lying_ct: Ciphertext = (*ct_l0).clone();
        lying_ct.level = 1;
        forged.ct = Arc::new(lying_ct);

        let err =
            <Ciphertext as Aggregate<SecretKeySwitchShare>>::from_shares(vec![forged]).unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::InvalidContext)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_non_two_component_ciphertext() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let set = participant_set(46);

        let ctx = params.context_at_level(0).unwrap();
        let polys = vec![
            fhe_math::rq::Poly::<Ntt>::random(ctx, &mut rng),
            fhe_math::rq::Poly::<Ntt>::random(ctx, &mut rng),
            fhe_math::rq::Poly::<Ntt>::random(ctx, &mut rng),
        ];
        let three_component = Arc::new(Ciphertext::new(polys, &params).unwrap());

        let err = SecretKeySwitchShare::new(
            &SecretKey::random(&params, &mut rng),
            &SecretKey::random(&params, &mut rng),
            three_component.clone(),
            ContributionBinding::new(set, 1).unwrap(),
            &mut rng,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Mbfv(MbfvError::ShareShapeMismatch { .. })
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_cross_session_duplicate_unknown_and_missing_ids() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let set_a = participant_set(47);
        let set_b = participant_set(48);
        let parties = generate_parties(&params, &set_a);
        let public_key: PublicKey = parties
            .iter()
            .map(|p| p.pk_share.clone())
            .aggregate()
            .unwrap();
        let pt = Plaintext::try_encode(&[5u64; 32], Encoding::poly_at_level(0), &params).unwrap();
        let ct = Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap());

        // Cross-session shares.
        let a1 = sks_share_for(
            &params,
            &ct,
            ContributionBinding::new(set_a.clone(), 1).unwrap(),
        );
        let b2 = sks_share_for(&params, &ct, ContributionBinding::new(set_b, 2).unwrap());
        let err =
            <Ciphertext as Aggregate<SecretKeySwitchShare>>::from_shares(vec![a1, b2]).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Threshold(crate::ThresholdError::ContributionSetMismatch)
            ),
            "unexpected error: {err}"
        );

        // Duplicate contributor.
        let set_c = participant_set(49);
        let one = sks_share_for(
            &params,
            &ct,
            ContributionBinding::new(set_c.clone(), 1).unwrap(),
        );
        let one_again = sks_share_for(
            &params,
            &ct,
            ContributionBinding::new(set_c.clone(), 1).unwrap(),
        );
        let err =
            <Ciphertext as Aggregate<SecretKeySwitchShare>>::from_shares(vec![one, one_again])
                .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Threshold(crate::ThresholdError::DuplicateContribution {
                    participant_id: 1
                })
            ),
            "unexpected error: {err}"
        );

        // Unknown contributor (not part of the declared set).
        let two_of_three = ParticipantSet::new(SessionId::new([50u8; 32]), vec![1, 2]).unwrap();
        let unknown = sks_share_for(
            &params,
            &ct,
            // A binding for an ID outside the declared set cannot be created;
            // emulate an "unknown" contribution with mismatched sets instead.
            ContributionBinding::new(
                ParticipantSet::new(SessionId::new([51u8; 32]), vec![3]).unwrap(),
                3,
            )
            .unwrap(),
        );
        let member = sks_share_for(
            &params,
            &ct,
            ContributionBinding::new(two_of_three.clone(), 1).unwrap(),
        );
        let err =
            <Ciphertext as Aggregate<SecretKeySwitchShare>>::from_shares(vec![member, unknown])
                .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Threshold(crate::ThresholdError::ContributionSetMismatch)
            ),
            "unexpected error: {err}"
        );

        // Missing contribution: set declares {1, 2}, only 1 contributes.
        let only_one = sks_share_for(
            &params,
            &ct,
            ContributionBinding::new(two_of_three.clone(), 1).unwrap(),
        );
        let err = <Ciphertext as Aggregate<SecretKeySwitchShare>>::from_shares(vec![only_one])
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Threshold(crate::ThresholdError::MissingContribution)
            ),
            "unexpected error: {err}"
        );

        // Empty share list remains fallible.
        let err = <Ciphertext as Aggregate<SecretKeySwitchShare>>::from_shares(Vec::<
            SecretKeySwitchShare,
        >::new())
        .unwrap_err();
        assert!(matches!(err, crate::Error::TooFewValues { .. }));
    }
}
