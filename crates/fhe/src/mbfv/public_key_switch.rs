use std::sync::Arc;

use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::rq::{Ntt, Poly, PowerBasis};

use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::bfv::{BfvParameters, Ciphertext, PublicKey, SecretKey};
use crate::identity::ContributionBinding;
use crate::{Error, MbfvError, Result};

use super::Aggregate;
use super::consistency::{
    require_poly_context, require_same_ciphertext_input, require_same_parameters,
    require_same_poly_vector, validate_binding_coverage,
};

/// A party's share in the public key switch protocol.
///
/// Each party uses the `PublicKeySwitchShare` to generate their share of the
/// new ciphertext and participate in the "Protocol 4: PubKeySwitch" protocol detailed in as detailed in [Multiparty BFV](https://eprint.iacr.org/2020/304.pdf) (p7). Use the [`Aggregate`] impl to combine the shares into a [`Ciphertext`].
///
/// # Binding contract
///
/// Every share carries a required [`ContributionBinding`] identifying its
/// contributor within an exact N-out-of-N [`crate::ParticipantSet`] for one
/// operation-specific [`crate::SessionId`], plus a structural record of the
/// complete public inputs used to form it: the full input ciphertext (all
/// components, level, and contexts) and the target public-key components at
/// the input's level. Aggregation rejects duplicate, missing, unknown, or
/// cross-session/set contributions and any disagreement on those public
/// inputs before any polynomial arithmetic. Bindings provide consistency
/// only; they do not authenticate a contributor or prove correct share
/// formation.
#[derive(Debug, Clone)]
pub struct PublicKeySwitchShare {
    pub(crate) params: Arc<BfvParameters>,
    /// The complete input ciphertext this share was generated for.
    pub(crate) input_ct: Arc<Ciphertext>,
    /// The target public-key components switched to the input ciphertext's
    /// level; these are the polynomials used to produce `h0_share`/`h1_share`.
    pub(crate) target_pk: Box<[Poly<Ntt>]>,
    pub(crate) h0_share: Poly<Ntt>,
    pub(crate) h1_share: Poly<Ntt>,
    pub(crate) binding: ContributionBinding,
}

impl PublicKeySwitchShare {
    /// Participate in a new PubKeySwitch protocol.
    ///
    /// 1. *Private input*: BFV secret key share
    /// 2. *Public input*: BFV output public key
    /// 3. *Public input*: Ciphertext
    /// 4. *Binding*: this party's [`ContributionBinding`] for the execution
    ///
    /// # Errors
    ///
    /// Returns an error if the secret-key share, output public key, and
    /// ciphertext do not share structurally equal BFV parameters; if the
    /// input ciphertext or the target public key does not have exactly two
    /// components; if a component does not live in the context resolved from
    /// the declared ciphertext level; or if the target public key is already
    /// deeper than the input ciphertext (a target key can only be leveled
    /// down toward the ciphertext, never up).
    pub fn new<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        public_key: &PublicKey,
        ct: &Ciphertext,
        binding: ContributionBinding,
        rng: &mut R,
    ) -> Result<Self> {
        if sk_share.params != public_key.params || public_key.params != ct.params {
            return Err(Error::Mbfv(MbfvError::ParameterMismatch));
        }
        let params = sk_share.params.clone();

        // MBFV public-key switching consumes exactly the first two ciphertext
        // components; anything else changes the switch semantics and is
        // rejected instead of silently ignored.
        if ct.len() != 2 {
            return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: format!(
                    "public-key switching requires exactly two input ciphertext components; found {}",
                    ct.len()
                ),
            }));
        }
        // Validate the input ciphertext against its declared level's context.
        let ctx = params.context_at_level(ct.level)?;
        for component in ct.iter() {
            require_poly_context(component, ctx)?;
        }
        let Some(ct1) = ct.get(1) else {
            return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: "input ciphertext lost its second component".to_string(),
            }));
        };

        // The target key must also be a two-component public key; components
        // beyond the second would be dropped from the structural descriptor.
        if public_key.c.len() != 2 {
            return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: format!(
                    "public-key switching requires exactly two target public-key components; found {}",
                    public_key.c.len()
                ),
            }));
        }

        // Get appropriate target public key at the input ciphertext's level.
        // Fallible leveled access: a target key already deeper than the
        // input cannot be leveled up, and leveling stops at the maximum
        // level, so an equality loop could otherwise never converge.
        let mut pk_ct = public_key.c.clone();
        pk_ct.switch_to_level(ct.level)?;
        let Some(pk0) = pk_ct.first().cloned() else {
            return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: "target public key lost its first component".to_string(),
            }));
        };
        let Some(pk1) = pk_ct.get(1).cloned() else {
            return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: "target public key lost its second component".to_string(),
            }));
        };
        for component in [&pk0, &pk1] {
            require_poly_context(component, ctx)?;
        }

        let mut s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?
                .into_ntt()?,
        );
        s.disallow_variable_time_computations();

        let u = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);
        // TODO this should be exponential in ciphertext noise!
        let e0 = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);
        let e1 = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);

        let mut h0 = pk0.clone();
        h0.disallow_variable_time_computations();
        h0 *= u.as_ref();
        *s.as_mut() *= ct1;
        h0 += s.as_ref();
        h0 += e0.as_ref();

        let mut h1 = pk1.clone();
        h1.disallow_variable_time_computations();
        h1 *= u.as_ref();
        h1 += e1.as_ref();

        unsafe {
            h0.allow_variable_time_computations();
            h1.allow_variable_time_computations();
        }

        Ok(Self {
            params,
            input_ct: Arc::new(ct.clone()),
            target_pk: Box::new([pk0, pk1]),
            h0_share: h0,
            h1_share: h1,
            binding,
        })
    }

    /// Borrow the contribution binding attached to this share.
    #[must_use]
    pub fn binding(&self) -> &ContributionBinding {
        &self.binding
    }
}

impl Aggregate<PublicKeySwitchShare> for Ciphertext {
    /// Aggregate public-key-switch shares into the switched [`Ciphertext`].
    ///
    /// # Errors
    ///
    /// Validates, before any polynomial arithmetic: exact one-per-member
    /// coverage of the shares' common [`crate::ParticipantSet`] (rejecting
    /// duplicate, missing, unknown, unbound, and cross-session/set
    /// contributions immediately after the share list is collected);
    /// structural equality of every share's complete input ciphertext
    /// (parameters, level, exactly two components, contexts, and concrete
    /// polynomial values); a two-component target public-key descriptor,
    /// structurally equal across shares; and that all `h0`/`h1` shares agree
    /// on context, level, and shape.
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = PublicKeySwitchShare>,
    {
        let shares = iter.into_iter().collect::<Vec<_>>();
        let (first, rest) = shares.split_first().ok_or(Error::TooFewValues {
            actual: 0,
            minimum: 1,
        })?;

        // Exact N-out-of-N coverage of every share's binding, validated
        // before any parameter, context, ciphertext-component, target-key, or
        // polynomial access.
        validate_binding_coverage(shares.iter().map(|share| &share.binding))?;

        require_same_parameters(&first.params, &first.input_ct.params)?;
        if first.input_ct.len() != 2 {
            return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: format!(
                    "public-key switching requires exactly two input ciphertext components; found {}",
                    first.input_ct.len()
                ),
            }));
        }
        if first.target_pk.len() != 2 {
            return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: format!(
                    "public-key switching requires exactly two target public-key components; found {}",
                    first.target_pk.len()
                ),
            }));
        }
        let ctx = first.h0_share.ctx().clone();
        require_poly_context(&first.h1_share, &ctx)?;
        for component in first.input_ct.iter() {
            require_poly_context(component, &ctx)?;
        }
        for component in first.target_pk.iter() {
            require_poly_context(component, &ctx)?;
        }
        for sh in rest {
            require_same_parameters(&sh.params, &first.params)?;
            require_same_ciphertext_input(&sh.input_ct, &first.input_ct)?;
            if sh.target_pk.len() != 2 {
                return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                    reason: format!(
                        "public-key switching requires exactly two target public-key components; found {}",
                        sh.target_pk.len()
                    ),
                }));
            }
            require_same_poly_vector(&sh.target_pk, &first.target_pk, "target public key")?;
            require_poly_context(&sh.h0_share, &ctx)?;
            require_poly_context(&sh.h1_share, &ctx)?;
        }

        let mut h0 = first.h0_share.clone();
        let mut h1 = first.h1_share.clone();
        for sh in rest {
            h0 += &sh.h0_share;
            h1 += &sh.h1_share;
        }

        // Length validated above; access remains fallible.
        let c00 = first
            .input_ct
            .first()
            .ok_or(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: "input ciphertext lost its first component".to_string(),
            }))?;
        let c0 = c00 + &h0;

        Ciphertext::new(vec![c0, h1], &first.params)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use std::sync::Arc;

    use fhe_math::rq::{Ntt, Poly};
    use fhe_traits::{FheDecrypter, FheEncoder, FheEncrypter};
    use rand::rng;

    use crate::{
        MbfvError,
        bfv::{
            BfvParameters, Ciphertext, CommonRandomPoly, Encoding, Plaintext, PublicKey, SecretKey,
        },
        identity::{ContributionBinding, ParticipantSet, SessionId},
        mbfv::{Aggregate, AggregateIter, PublicKeyShare, PublicKeySwitchShare},
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
    fn encrypt_keyswitch_decrypt() {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 32),
        ] {
            for level in 0..=params.max_level() {
                for _ in 0..20 {
                    let set = participant_set(61);
                    let parties = generate_parties(&params, &set);

                    let public_key: PublicKey = parties
                        .iter()
                        .map(|p| p.pk_share.clone())
                        .aggregate()
                        .unwrap();

                    // Use it to encrypt a random polynomial ct1
                    let pt1 = Plaintext::try_encode(
                        &fhe_math::zq::Modulus::new(params.plaintext())
                            .unwrap()
                            .random_vec(params.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &params,
                    )
                    .unwrap();
                    let ct1 = Arc::new(public_key.try_encrypt(&pt1, &mut rng).unwrap());

                    // Key switch ct1 to a new keypair
                    let sk_out = SecretKey::random(&params, &mut rng);
                    let pk_out = PublicKey::new(&sk_out, &mut rng);
                    let ct2: Ciphertext = parties
                        .iter()
                        .enumerate()
                        .map(|(i, p)| {
                            PublicKeySwitchShare::new(
                                &p.sk_share,
                                &pk_out,
                                &ct1,
                                ContributionBinding::new(set.clone(), i as u32 + 1).unwrap(),
                                &mut rng,
                            )
                        })
                        .aggregate()
                        .unwrap();
                    assert_eq!(ct2.level, ct1.level);

                    let pt2 = sk_out.try_decrypt(&ct2).unwrap();
                    assert_eq!(pt1, pt2);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Aggregation rejection matrix (#89)
    // -----------------------------------------------------------------------

    fn setup(session: u8) -> (Arc<BfvParameters>, Vec<Party>, Arc<Ciphertext>, PublicKey) {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let set = participant_set(session);
        let parties = generate_parties(&params, &set);
        let public_key: PublicKey = parties
            .iter()
            .map(|p| p.pk_share.clone())
            .aggregate()
            .unwrap();
        let pt = Plaintext::try_encode(
            &fhe_math::zq::Modulus::new(params.plaintext())
                .unwrap()
                .random_vec(params.degree(), &mut rng),
            Encoding::poly_at_level(0),
            &params,
        )
        .unwrap();
        let ct = Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap());
        (params, parties, ct, public_key)
    }

    fn pks_share_for(
        party: &Party,
        pk_out: &PublicKey,
        ct: &Arc<Ciphertext>,
        binding: ContributionBinding,
    ) -> PublicKeySwitchShare {
        PublicKeySwitchShare::new(&party.sk_share, pk_out, ct, binding, &mut rng()).unwrap()
    }

    #[test]
    fn aggregation_rejects_different_input_ciphertexts() {
        // Exact two-member set; one contribution is tampered below.
        let two_set = || ParticipantSet::new(SessionId::new([62u8; 32]), vec![1, 2]).unwrap();
        let (params, parties, ct_a, _pk) = {
            let params = BfvParameters::default_arc(6, 32);
            let parties = generate_parties(&params, &two_set());
            let public_key: PublicKey = parties
                .iter()
                .map(|p| p.pk_share.clone())
                .aggregate()
                .unwrap();
            let mut rng = rng();
            let pt = Plaintext::try_encode(
                &fhe_math::zq::Modulus::new(params.plaintext())
                    .unwrap()
                    .random_vec(params.degree(), &mut rng),
                Encoding::poly_at_level(0),
                &params,
            )
            .unwrap();
            (
                params,
                parties,
                Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap()),
                public_key,
            )
        };
        let mut rng = rng();
        let pt_b = Plaintext::try_encode(
            &fhe_math::zq::Modulus::new(params.plaintext())
                .unwrap()
                .random_vec(params.degree(), &mut rng),
            Encoding::poly_at_level(0),
            &params,
        )
        .unwrap();
        let ct_b = Arc::new(_pk.try_encrypt(&pt_b, &mut rng).unwrap());
        let sk_out = SecretKey::random(&params, &mut rng);
        let pk_out = PublicKey::new(&sk_out, &mut rng);
        let set = two_set();

        let good = pks_share_for(
            &parties[0],
            &pk_out,
            &ct_a,
            ContributionBinding::new(set.clone(), 1).unwrap(),
        );
        let bad = pks_share_for(
            &parties[1],
            &pk_out,
            &ct_b,
            ContributionBinding::new(set.clone(), 2).unwrap(),
        );
        let err = <Ciphertext as Aggregate<PublicKeySwitchShare>>::from_shares(vec![good, bad])
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Mbfv(MbfvError::PublicInputMismatch { .. })
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_different_target_public_keys() {
        // Exact two-member set; one contribution targets a different key.
        let set = ParticipantSet::new(SessionId::new([63u8; 32]), vec![1, 2]).unwrap();
        let (params, parties, ct, _pk) = {
            let params = BfvParameters::default_arc(6, 32);
            let parties = generate_parties(&params, &set);
            let public_key: PublicKey = parties
                .iter()
                .map(|p| p.pk_share.clone())
                .aggregate()
                .unwrap();
            let mut rng = rng();
            let pt = Plaintext::try_encode(
                &fhe_math::zq::Modulus::new(params.plaintext())
                    .unwrap()
                    .random_vec(params.degree(), &mut rng),
                Encoding::poly_at_level(0),
                &params,
            )
            .unwrap();
            (
                params,
                parties,
                Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap()),
                public_key,
            )
        };
        let mut rng = rng();
        let sk_out_a = SecretKey::random(&params, &mut rng);
        let pk_out_a = PublicKey::new(&sk_out_a, &mut rng);
        let sk_out_b = SecretKey::random(&params, &mut rng);
        let pk_out_b = PublicKey::new(&sk_out_b, &mut rng);

        let good = pks_share_for(
            &parties[0],
            &pk_out_a,
            &ct,
            ContributionBinding::new(set.clone(), 1).unwrap(),
        );
        let bad = pks_share_for(
            &parties[1],
            &pk_out_b,
            &ct,
            ContributionBinding::new(set.clone(), 2).unwrap(),
        );
        let err = <Ciphertext as Aggregate<PublicKeySwitchShare>>::from_shares(vec![good, bad])
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Mbfv(MbfvError::PublicInputMismatch { .. })
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_parameter_mismatch_and_wrong_contexts() {
        // Exact two-member set; one contribution is tampered in each section.
        let set = ParticipantSet::new(SessionId::new([64u8; 32]), vec![1, 2]).unwrap();
        let (params, parties, ct, _pk) = {
            let params = BfvParameters::default_arc(6, 32);
            let parties = generate_parties(&params, &set);
            let public_key: PublicKey = parties
                .iter()
                .map(|p| p.pk_share.clone())
                .aggregate()
                .unwrap();
            let mut rng = rng();
            let pt = Plaintext::try_encode(
                &fhe_math::zq::Modulus::new(params.plaintext())
                    .unwrap()
                    .random_vec(params.degree(), &mut rng),
                Encoding::poly_at_level(0),
                &params,
            )
            .unwrap();
            (
                params,
                parties,
                Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap()),
                public_key,
            )
        };
        let mut rng = rng();
        let other_params = BfvParameters::default_arc(1, 16);
        let sk_out = SecretKey::random(&params, &mut rng);
        let pk_out = PublicKey::new(&sk_out, &mut rng);

        let good = pks_share_for(
            &parties[0],
            &pk_out,
            &ct,
            ContributionBinding::new(set.clone(), 1).unwrap(),
        );

        // Parameter mismatch between shares.
        let mut bad = good.clone();
        bad.params = other_params.clone();
        bad.binding = ContributionBinding::new(set.clone(), 2).unwrap();
        let err =
            <Ciphertext as Aggregate<PublicKeySwitchShare>>::from_shares(vec![good.clone(), bad])
                .unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::ParameterMismatch)),
            "unexpected error: {err}"
        );

        // Wrong h-share context on the second contribution.
        let mut bad_ctx = good.clone();
        bad_ctx.binding = ContributionBinding::new(set, 2).unwrap();
        bad_ctx.h0_share = Poly::<Ntt>::random(other_params.context_at_level(0).unwrap(), &mut rng);
        let err = <Ciphertext as Aggregate<PublicKeySwitchShare>>::from_shares(vec![good, bad_ctx])
            .unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::InvalidContext)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aggregation_rejects_cross_session_duplicate_and_missing_ids() {
        let (params, parties, ct, _pk) = setup(65);
        let mut rng = rng();
        let set_a = participant_set(65);
        let set_b = participant_set(66);
        let sk_out = SecretKey::random(&params, &mut rng);
        let pk_out = PublicKey::new(&sk_out, &mut rng);

        // Cross-session.
        let a1 = pks_share_for(
            &parties[0],
            &pk_out,
            &ct,
            ContributionBinding::new(set_a.clone(), 1).unwrap(),
        );
        let b2 = pks_share_for(
            &parties[1],
            &pk_out,
            &ct,
            ContributionBinding::new(set_b, 2).unwrap(),
        );
        let err =
            <Ciphertext as Aggregate<PublicKeySwitchShare>>::from_shares(vec![a1, b2]).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Threshold(crate::ThresholdError::ContributionSetMismatch)
            ),
            "unexpected error: {err}"
        );

        // Duplicate contributor.
        let one = pks_share_for(
            &parties[0],
            &pk_out,
            &ct,
            ContributionBinding::new(set_a.clone(), 1).unwrap(),
        );
        let one_again = pks_share_for(
            &parties[1],
            &pk_out,
            &ct,
            ContributionBinding::new(set_a.clone(), 1).unwrap(),
        );
        let err =
            <Ciphertext as Aggregate<PublicKeySwitchShare>>::from_shares(vec![one, one_again])
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

        // Missing contributor: declared {1, 2}, only party 1 contributes.
        let two_set = ParticipantSet::new(SessionId::new([67u8; 32]), vec![1, 2]).unwrap();
        let only_one = pks_share_for(
            &parties[0],
            &pk_out,
            &ct,
            ContributionBinding::new(two_set, 1).unwrap(),
        );
        let err = <Ciphertext as Aggregate<PublicKeySwitchShare>>::from_shares(vec![only_one])
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Threshold(crate::ThresholdError::MissingContribution)
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn constructor_rejects_non_two_component_input_ciphertexts() {
        let mut rng = rng();
        let (params, parties, ct, _pk) = setup(86);
        let set = participant_set(86);
        let sk_out = SecretKey::random(&params, &mut rng);
        let pk_out = PublicKey::new(&sk_out, &mut rng);
        let binding = ContributionBinding::new(set, 1).unwrap();
        let ctx0 = params.context_at_level(0).unwrap();

        // Zero-component input ciphertext: must be a typed error, no unwind.
        let empty_ct = Ciphertext::zero(&params);
        let err = PublicKeySwitchShare::new(
            &parties[0].sk_share,
            &pk_out,
            &empty_ct,
            binding.clone(),
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

        // One-component input ciphertext.
        let one_component = Ciphertext {
            params: params.clone(),
            seed: None,
            c: vec![ct.first().unwrap().clone()],
            level: 0,
        };
        let err = PublicKeySwitchShare::new(
            &parties[0].sk_share,
            &pk_out,
            &one_component,
            binding.clone(),
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

        // Three-component (unrelinearized) input ciphertext: the extra
        // component must not be silently ignored.
        let three_component = Ciphertext {
            params: params.clone(),
            seed: None,
            c: vec![
                ct.first().unwrap().clone(),
                ct.get(1).unwrap().clone(),
                Poly::<Ntt>::random(ctx0, &mut rng),
            ],
            level: 0,
        };
        let err = PublicKeySwitchShare::new(
            &parties[0].sk_share,
            &pk_out,
            &three_component,
            binding,
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
    fn constructor_rejects_non_two_component_target_public_keys() {
        let mut rng = rng();
        let (params, parties, ct, _pk) = setup(87);
        let set = participant_set(87);
        let ctx0 = params.context_at_level(0).unwrap();

        // Target public key with only one component.
        let sk_one = SecretKey::random(&params, &mut rng);
        let mut pk_one_component = PublicKey::new(&sk_one, &mut rng);
        pk_one_component.c.c.truncate(1);
        let err = PublicKeySwitchShare::new(
            &parties[0].sk_share,
            &pk_one_component,
            &ct,
            ContributionBinding::new(set.clone(), 1).unwrap(),
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

        // Target public key with three components: components beyond the
        // second change the switch semantics and must not be dropped.
        let sk_three = SecretKey::random(&params, &mut rng);
        let mut pk_three_components = PublicKey::new(&sk_three, &mut rng);
        pk_three_components
            .c
            .c
            .push(Poly::<Ntt>::random(ctx0, &mut rng));
        let err = PublicKeySwitchShare::new(
            &parties[0].sk_share,
            &pk_three_components,
            &ct,
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
    fn aggregation_rejects_non_two_component_target_descriptor() {
        let mut rng = rng();
        // Exact two-member set; one contribution carries a truncated target.
        let set = ParticipantSet::new(SessionId::new([88u8; 32]), vec![1, 2]).unwrap();
        let (params, parties, ct, _pk) = {
            let params = BfvParameters::default_arc(6, 32);
            let parties = generate_parties(&params, &set);
            let public_key: PublicKey = parties
                .iter()
                .map(|p| p.pk_share.clone())
                .aggregate()
                .unwrap();
            let pt = Plaintext::try_encode(
                &fhe_math::zq::Modulus::new(params.plaintext())
                    .unwrap()
                    .random_vec(params.degree(), &mut rng),
                Encoding::poly_at_level(0),
                &params,
            )
            .unwrap();
            (
                params,
                parties,
                Arc::new(public_key.try_encrypt(&pt, &mut rng).unwrap()),
                public_key,
            )
        };
        let sk_out = SecretKey::random(&params, &mut rng);
        let pk_out = PublicKey::new(&sk_out, &mut rng);

        let good = pks_share_for(
            &parties[0],
            &pk_out,
            &ct,
            ContributionBinding::new(set.clone(), 1).unwrap(),
        );
        // An assembled share whose target-key descriptor lost a component is
        // rejected instead of being treated as identical to complete targets.
        let mut bad = good.clone();
        bad.binding = ContributionBinding::new(set, 2).unwrap();
        bad.target_pk = Box::new([bad.target_pk.first().unwrap().clone()]);

        let err = <Ciphertext as Aggregate<PublicKeySwitchShare>>::from_shares(vec![good, bad])
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
    fn constructor_rejects_target_deeper_than_input() {
        // A target public key already switched deeper (level 1) than the
        // input ciphertext (level 0) can never be leveled down to match;
        // construction must fail with a typed error instead of looping.
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 32);
        let set = ParticipantSet::new(SessionId::new([89u8; 32]), vec![1, 2]).unwrap();
        let parties = generate_parties(&params, &set);
        let public_key: PublicKey = parties
            .iter()
            .map(|p| p.pk_share.clone())
            .aggregate()
            .unwrap();
        let pt = Plaintext::try_encode(
            &fhe_math::zq::Modulus::new(params.plaintext())
                .unwrap()
                .random_vec(params.degree(), &mut rng),
            Encoding::poly_at_level(0),
            &params,
        )
        .unwrap();
        let ct = public_key.try_encrypt(&pt, &mut rng).unwrap();
        assert_eq!(ct.level, 0);

        let sk_out = SecretKey::random(&params, &mut rng);
        let mut deep_pk_out = PublicKey::new(&sk_out, &mut rng);
        deep_pk_out.c.switch_down().unwrap();
        assert_eq!(deep_pk_out.c.level, 1);

        let outcome = PublicKeySwitchShare::new(
            &parties[0].sk_share,
            &deep_pk_out,
            &ct,
            ContributionBinding::new(set, 1).unwrap(),
            &mut rng,
        );
        assert!(
            matches!(outcome, Err(crate::Error::InvalidLevel { .. })),
            "unexpected outcome: {outcome:?}"
        );
    }

    #[test]
    fn leveled_switch_still_works_after_rejections() {
        // A valid switch of a leveled (switched-down) ciphertext must remain
        // functional end-to-end.
        let (params, parties, ct, _pk) = setup(68);
        let mut rng = rng();
        let mut ct_leveled = (*ct).clone();
        ct_leveled.switch_down().unwrap();
        let ct_leveled = Arc::new(ct_leveled);
        let set = participant_set(68);
        let sk_out = SecretKey::random(&params, &mut rng);
        let pk_out = PublicKey::new(&sk_out, &mut rng);

        let ct2: Ciphertext = parties
            .iter()
            .enumerate()
            .map(|(i, p)| {
                pks_share_for(
                    p,
                    &pk_out,
                    &ct_leveled,
                    ContributionBinding::new(set.clone(), i as u32 + 1).unwrap(),
                )
            })
            .aggregate()
            .unwrap();
        assert_eq!(ct2.level, ct_leveled.level);
    }
}
