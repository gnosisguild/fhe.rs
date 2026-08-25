use std::marker::PhantomData;
use std::sync::Arc;

use crate::Error;
use crate::MbfvError;
use crate::Result;
use crate::bfv::{BfvParameters, KeySwitchingKey, RelinearizationKey, SecretKey};
use crate::identity::{ContributionBinding, ParticipantSet};
use fhe_math::rns::RnsContext;
use fhe_math::rq::{Ntt, NttShoup, Poly, PowerBasis, traits::TryConvertFrom};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::bfv::{CommonRandomPoly, CommonRandomPolyVec};

use super::Aggregate;
use super::consistency::{
    require_anchored_poly_vector, require_poly_context, require_same_parameters,
    require_same_poly_vector, validate_all_bindings,
};
use super::round::{R1, R1Aggregated, R2, Round};

/// A party's share in the relinearization key generation protocol.
/// Use the [`RelinKeyGenerator`] to create these shares.
///
/// # Binding contract
///
/// Round-1 and round-2 shares each carry a required [`ContributionBinding`]
/// for one operation-specific [`crate::SessionId`] and an exact N-out-of-N
/// [`crate::ParticipantSet`]. The round-1 aggregate retains the validated
/// participant set, session, CRP descriptor, and vector dimensions; it is not
/// represented as a fake single-party binding. Round-2 shares reference the
/// round-1 aggregate they were derived from, and the final aggregation
/// verifies that every share references one structurally identical validated
/// aggregate before any polynomial arithmetic. Bindings provide consistency
/// only; they do not authenticate a contributor or prove correct share
/// formation. Relin key generation remains a level-zero protocol.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RelinKeyShare<R: Round = R1> {
    pub(crate) params: Arc<BfvParameters>,
    pub(crate) h0: Box<[Poly<Ntt>]>,
    pub(crate) h1: Box<[Poly<Ntt>]>,
    /// This party's contribution binding (round-1 and round-2 shares only).
    pub(crate) binding: Option<ContributionBinding>,
    /// The common level-zero CRP vector descriptor (round-1 shares and the
    /// round-1 aggregate). Concrete polynomials are authoritative; seed
    /// metadata is ignored by equality.
    pub(crate) crp: Option<CommonRandomPolyVec>,
    /// The validated exact participant set (round-1 aggregate only).
    pub(crate) participant_set: Option<ParticipantSet>,
    last_round: Option<Arc<RelinKeyShare<R1Aggregated>>>,
    _phantom_data: PhantomData<R>,
}

impl<R: Round> RelinKeyShare<R> {
    /// Borrow this share's contribution binding, if one is attached.
    ///
    /// Round-1 and round-2 shares always carry a binding; the round-1
    /// aggregate instead retains the validated [`ParticipantSet`].
    #[must_use]
    pub fn binding(&self) -> Option<&ContributionBinding> {
        self.binding.as_ref()
    }

    /// Borrow the validated participant set (round-1 aggregates only).
    #[must_use]
    pub fn participant_set(&self) -> Option<&ParticipantSet> {
        self.participant_set.as_ref()
    }
}

/// A builder for creating relinearization key generation shares per party.
///
/// Each party uses the `RelinKeyGenerator` to generate their shares and
/// participate in the "Protocol 2: RelinKeyGen" protocol detailed in
/// [Multiparty BFV](https://eprint.iacr.org/2020/304.pdf) (p6). The shares need to be aggregated between
/// rounds:
///
/// ```rust
/// use std::sync::Arc;
/// use fhe::bfv::{BfvParametersBuilder, CommonRandomPolyVec, RelinearizationKey, SecretKey};
/// use fhe::identity::{ContributionBinding, ParticipantSet, SessionId};
/// use fhe::mbfv::{Aggregate, RelinKeyGenerator, RelinKeyShare, round::*};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let parameters = BfvParametersBuilder::new()
///         .set_degree(4096)
///         .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
///         .set_plaintext_modulus(1 << 10)
///         .build_arc()?;
///
/// // All parties agree on one operation-specific session and exact
/// // participant set; each party binds its own 1-based participant ID.
/// let participant_set = ParticipantSet::new(SessionId::new([42u8; 32]), vec![1])?;
/// let binding = ContributionBinding::new(participant_set, 1)?;
///
/// // Party perspective
/// let mut rng = rand::rng();
/// let sk_share = SecretKey::random(&parameters, &mut rng);
/// let crp = CommonRandomPolyVec::new(&parameters, &mut rng)?;
/// let rlk_generator = RelinKeyGenerator::new(&sk_share, &crp, binding, &mut rng)?;
/// let rlk_r1_share = rlk_generator.round_1(&mut rng)?;
///
/// // Aggregator perspective
/// let r1_shares = vec![rlk_r1_share]; // all party shares go here
/// let rlk_r1_aggregated = RelinKeyShare::<R1Aggregated>::from_shares(r1_shares)?;
///
/// // Party perspective
/// let rlk_r2_share = rlk_generator.round_2(&Arc::new(rlk_r1_aggregated), &mut rng)?;
///
/// // Aggregator perspective
/// let r2_shares = vec![rlk_r2_share]; // all party shares go here
/// let rlk = RelinearizationKey::from_shares(r2_shares)?;
/// # Ok(())
/// # }
/// ```
pub struct RelinKeyGenerator<'a, 'b> {
    sk_share: &'a SecretKey,
    crp: &'b CommonRandomPolyVec,
    u: Zeroizing<Poly<Ntt>>,
    binding: ContributionBinding,
}

impl<'a, 'b> RelinKeyGenerator<'a, 'b> {
    /// Create a new relin key generator for a given party.
    ///
    /// 1. *Private input*: BFV secret key share
    /// 2. *Public input*: common random polynomial vector
    /// 3. *Binding*: this party's [`ContributionBinding`] for the execution
    ///
    /// # Errors
    ///
    /// Returns an error if these parameters do not support key switching
    /// (a single modulus), if the CRP vector length differs from the number
    /// of ciphertext moduli, or if a CRP component is not at the level-zero
    /// context: relinearization key generation is a level-zero protocol.
    pub fn new<R: RngCore + CryptoRng>(
        sk_share: &'a SecretKey,
        crp: &'b CommonRandomPolyVec,
        binding: ContributionBinding,
        rng: &mut R,
    ) -> Result<Self> {
        let params = sk_share.params.clone();
        let ctx = params.context_at_level(0)?;
        if ctx.moduli().len() == 1 {
            Err(Error::DefaultError(
                "These parameters do not support key switching".to_string(),
            ))
        } else if crp.len() != ctx.moduli().len() {
            Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason:
                    "The size of the CRP polynomial vector must equal the number of ciphertext moduli."
                        .to_string(),
            }))
        } else {
            for component in crp.as_slice() {
                require_poly_context(component.poly(), ctx)?;
            }
            let u = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);
            Ok(Self {
                sk_share,
                crp,
                u,
                binding,
            })
        }
    }

    /// Generate share for round 1
    ///
    /// The returned share carries this party's contribution binding and the
    /// concrete CRP vector descriptor used to form it.
    pub fn round_1<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<RelinKeyShare<R1>> {
        <RelinKeyShare<R1>>::new(self.sk_share, self.crp, &self.u, &self.binding, rng)
    }

    /// Generate share for round 2
    ///
    /// The returned share carries its own contribution binding and retains a
    /// reference to the validated round-1 aggregate it was generated from.
    ///
    /// # Errors
    ///
    /// Returns an error if the round-1 aggregate is inconsistent with this
    /// party's own execution: different participant set or session, different
    /// parameters, a different concrete CRP vector, or dimensions that do not
    /// match the generator's level-zero CRP length. A party may only derive
    /// its round-2 share from an aggregate of exactly the same public inputs.
    pub fn round_2<R: RngCore + CryptoRng>(
        &self,
        r1: &Arc<RelinKeyShare<R1Aggregated>>,
        rng: &mut R,
    ) -> Result<RelinKeyShare<R2>> {
        // A party's own round-2 contribution must belong to the same
        // execution as the aggregate it references.
        match (&r1.participant_set, self.binding.participant_set()) {
            (Some(aggregate_set), own_set) if aggregate_set == own_set => {}
            _ => return Err(Error::Mbfv(MbfvError::RoundReferenceMismatch)),
        }
        // The aggregate must have been produced under this generator's
        // parameters and against this generator's concrete CRP vector; a
        // shared session label alone never legitimizes different public
        // inputs.
        require_same_parameters(&r1.params, &self.sk_share.params)?;
        let Some(r1_crp) = r1.crp.as_ref() else {
            return Err(Error::Mbfv(MbfvError::RoundReferenceMismatch));
        };
        if r1_crp != self.crp {
            return Err(Error::Mbfv(MbfvError::RoundReferenceMismatch));
        }
        // Anchor dimensions and level-zero contexts to this generator's CRP:
        // one h0/h1 entry per RNS modulus at level zero, all in that context.
        let ctx = self.sk_share.params.context_at_level(0)?;
        let expected_len = ctx.moduli().len();
        for component in self.crp.as_slice() {
            require_poly_context(component.poly(), ctx)?;
        }
        require_anchored_poly_vector(&r1.h0, ctx, expected_len, "round-1 aggregate h0")?;
        require_anchored_poly_vector(&r1.h1, ctx, expected_len, "round-1 aggregate h1")?;
        <RelinKeyShare<R2>>::new(self.sk_share, &self.u, r1, &self.binding, rng)
    }
}

impl RelinKeyShare<R1> {
    fn new<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        crp: &CommonRandomPolyVec,
        u: &Zeroizing<Poly<Ntt>>,
        binding: &ContributionBinding,
        rng: &mut R,
    ) -> Result<Self> {
        let params = sk_share.params.clone();

        if crp.len() != params.context_at_level(0)?.moduli().len() {
            Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason:
                    "The size of the CRP polynomial vector must equal the number of ciphertext moduli."
                        .to_string(),
            }))
        } else {
            let h0 = Self::generate_h0(sk_share, crp.as_slice(), u, rng)?;
            let h1 = Self::generate_h1(sk_share, crp.as_slice(), rng)?;
            Ok(Self {
                params,
                h0,
                h1,
                binding: Some(binding.clone()),
                crp: Some(crp.clone()),
                participant_set: None,
                last_round: None,
                _phantom_data: PhantomData,
            })
        }
    }

    fn generate_h0<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        crp: &[CommonRandomPoly],
        u: &Zeroizing<Poly<Ntt>>,
        rng: &mut R,
    ) -> Result<Box<[Poly<Ntt>]>> {
        let params = sk_share.params.clone();
        let ctx = params.context_at_level(0)?;

        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?
                .into_ntt()?,
        );
        let moduli = sk_share.params.moduli.get(..crp.len()).ok_or(Error::Mbfv(
            MbfvError::ShareShapeMismatch {
                reason: format!(
                    "CRP length {} exceeds the available RNS moduli {}",
                    crp.len(),
                    sk_share.params.moduli.len()
                ),
            },
        ))?;
        let rns = RnsContext::new(moduli)?;
        let h0 = crp
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let w = rns.get_garner(i).ok_or(Error::DefaultError(
                    "Unable to retrieve Garner auxiliary modulus".to_string(),
                ))?;
                let w_s = Zeroizing::new(w * s.as_ref());

                let e = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);

                let mut h = -a.poly.clone();
                h.disallow_variable_time_computations();
                h *= u.as_ref();
                h += w_s.as_ref();
                h += e.as_ref();
                Ok(h)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(h0.into_boxed_slice())
    }

    fn generate_h1<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        crp: &[CommonRandomPoly],
        rng: &mut R,
    ) -> Result<Box<[Poly<Ntt>]>> {
        let params = sk_share.params.clone();
        let ctx = params.context_at_level(0)?;
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?
                .into_ntt()?,
        );

        let h1 = crp
            .iter()
            .map(|a| {
                let mut h = a.poly.clone();
                h.disallow_variable_time_computations();
                let e = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);
                h *= s.as_ref();
                h += e.as_ref();
                Ok(h)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(h1.into_boxed_slice())
    }
}

impl Aggregate<RelinKeyShare<R1>> for RelinKeyShare<R1Aggregated> {
    /// Aggregate round-1 relin-key shares into the validated round-1
    /// aggregate.
    ///
    /// # Errors
    ///
    /// Validates, immediately after the share list is collected and before
    /// any parameter, context, CRP, or polynomial access: every share carries
    /// exactly one contribution binding (unbound shares are rejected, never
    /// skipped) and the bindings achieve exact one-per-member coverage of the
    /// common [`crate::ParticipantSet`] (rejecting duplicate, missing,
    /// unknown, and cross-session/set contributions); then structural
    /// parameter equality, concrete equality of every share's level-zero CRP
    /// vector, and that all `h0`/`h1` vectors agree on length and context.
    /// The aggregate retains the validated participant set, session, CRP
    /// descriptor, and dimensions.
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = RelinKeyShare<R1>>,
    {
        let shares = iter.into_iter().collect::<Vec<_>>();
        let (first, rest) = shares.split_first().ok_or(Error::TooFewValues {
            actual: 0,
            minimum: 1,
        })?;

        // Exact N-out-of-N coverage of every share's binding, validated
        // before any parameter, context, CRP, or polynomial access. A share
        // without a binding is rejected outright.
        let participant_set = validate_all_bindings(shares.iter().map(|share| &share.binding))?;

        let ctx = first.params.context_at_level(0)?.clone();
        // All relin arithmetic is anchored to the level-zero context: every
        // vector has exactly one entry per level-zero modulus and every
        // component lives in that context. Internal consistency between
        // shares alone never substitutes for this anchor.
        let expected_len = ctx.moduli().len();
        let first_crp = first
            .crp
            .as_ref()
            .ok_or(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: "round-1 share lacks its CRP descriptor".to_string(),
            }))?;
        if first_crp.len() != expected_len {
            return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
                reason: format!(
                    "round-1 CRP vector has {} components instead of the expected {expected_len}",
                    first_crp.len()
                ),
            }));
        }
        for component in first_crp.as_slice() {
            require_poly_context(component.poly(), &ctx)?;
        }
        require_anchored_poly_vector(&first.h0, &ctx, expected_len, "round-1 h0")?;
        require_anchored_poly_vector(&first.h1, &ctx, expected_len, "round-1 h1")?;
        for sh in rest {
            require_same_parameters(&sh.params, &first.params)?;
            let sh_crp = sh
                .crp
                .as_ref()
                .ok_or(Error::Mbfv(MbfvError::ShareShapeMismatch {
                    reason: "round-1 share lacks its CRP descriptor".to_string(),
                }))?;
            if sh_crp != first_crp {
                return Err(Error::Mbfv(MbfvError::PublicInputMismatch {
                    reason: "round-1 shares use different CRP vectors".to_string(),
                }));
            }
            require_anchored_poly_vector(&sh.h0, &ctx, expected_len, "round-1 h0")?;
            require_anchored_poly_vector(&sh.h1, &ctx, expected_len, "round-1 h1")?;
        }

        // Coordinate-wise additions over checked equal lengths.
        let mut h0 = first.h0.clone();
        let mut h1 = first.h1.clone();
        for sh in rest {
            for (dst, src) in h0.iter_mut().zip(sh.h0.iter()) {
                *dst += src;
            }
            for (dst, src) in h1.iter_mut().zip(sh.h1.iter()) {
                *dst += src;
            }
        }

        Ok(RelinKeyShare {
            params: first.params.clone(),
            h0,
            h1,
            binding: None,
            crp: Some(first_crp.clone()),
            participant_set: Some(participant_set),
            last_round: None,
            _phantom_data: PhantomData,
        })
    }
}

/// Require two round-1 aggregates to be structurally identical: parameters,
/// retained participant set/session, CRP descriptor, dimensions, contexts,
/// and every concrete aggregate polynomial value.
fn require_same_r1_aggregate(
    found: &RelinKeyShare<R1Aggregated>,
    expected: &RelinKeyShare<R1Aggregated>,
) -> Result<()> {
    require_same_parameters(&found.params, &expected.params)?;
    if found.participant_set != expected.participant_set
        || found.crp != expected.crp
        || found.h0.len() != expected.h0.len()
        || found.h1.len() != expected.h1.len()
    {
        return Err(Error::Mbfv(MbfvError::RoundReferenceMismatch));
    }
    require_same_poly_vector(&found.h0, &expected.h0, "round-1 aggregate h0")?;
    require_same_poly_vector(&found.h1, &expected.h1, "round-1 aggregate h1")?;
    Ok(())
}

impl RelinKeyShare<R2> {
    fn new<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        u: &Zeroizing<Poly<Ntt>>,
        r1: &Arc<RelinKeyShare<R1Aggregated>>,
        binding: &ContributionBinding,
        rng: &mut R,
    ) -> Result<Self> {
        let params = sk_share.params.clone();
        let h0 = Self::generate_h0(sk_share, &r1.h0, rng)?;
        let h1 = Self::generate_h1(sk_share, u, &r1.h1, rng)?;
        Ok(Self {
            params,
            h0,
            h1,
            binding: Some(binding.clone()),
            crp: None,
            participant_set: None,
            last_round: Some(Arc::clone(r1)),
            _phantom_data: PhantomData,
        })
    }

    fn generate_h0<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        r1_h0: &[Poly<Ntt>],
        rng: &mut R,
    ) -> Result<Box<[Poly<Ntt>]>> {
        let params = sk_share.params.clone();
        let ctx = params.context_at_level(0)?;

        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?
                .into_ntt()?,
        );
        let h0 = r1_h0
            .iter()
            .map(|h| {
                let e = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);

                let mut h_prime = h.clone();
                h_prime.disallow_variable_time_computations();
                h_prime *= s.as_ref();

                h_prime += e.as_ref();
                Ok(h_prime)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(h0.into_boxed_slice())
    }

    fn generate_h1<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        u: &Zeroizing<Poly<Ntt>>,
        r1_h1: &[Poly<Ntt>],
        rng: &mut R,
    ) -> Result<Box<[Poly<Ntt>]>> {
        let params = sk_share.params.clone();
        let ctx = params.context_at_level(0)?;
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?
                .into_ntt()?,
        );

        let u_s = Zeroizing::new(u.as_ref() - s.as_ref());

        let h1 = r1_h1
            .iter()
            .map(|h| {
                let mut h_prime = h.clone();
                h_prime.disallow_variable_time_computations();
                let e = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);
                h_prime *= u_s.as_ref();
                h_prime += e.as_ref();
                Ok(h_prime)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(h1.into_boxed_slice())
    }
}

impl Aggregate<RelinKeyShare<R2>> for RelinearizationKey {
    /// Aggregate round-2 relin-key shares into the collective
    /// [`RelinearizationKey`].
    ///
    /// # Errors
    ///
    /// Validates, immediately after the share list is collected and before
    /// any parameter, context, round-1-reference, or polynomial access:
    /// every share carries exactly one contribution binding (unbound shares
    /// are rejected, never skipped) and the bindings achieve exact
    /// one-per-member coverage of the common [`crate::ParticipantSet`]; that
    /// every share references one structurally identical, concretely equal
    /// validated round-1 aggregate (rejecting missing or mismatched round-1
    /// references); structural parameter equality across shares; and that all
    /// `h0`/`h1` vectors agree on length and context. Final coordinate-wise
    /// additions run over checked equal lengths; mismatched lengths are
    /// rejected instead of silently truncated.
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = RelinKeyShare<R2>>,
    {
        let shares = iter.into_iter().collect::<Vec<_>>();
        let (first, rest) = shares.split_first().ok_or(Error::TooFewValues {
            actual: 0,
            minimum: 1,
        })?;

        // Exact N-out-of-N coverage of every share's binding across both
        // rounds' contributors, validated before any parameter, context,
        // round-1-reference, or polynomial access.
        let r2_participant_set = validate_all_bindings(shares.iter().map(|share| &share.binding))?;

        let params = first.params.clone();
        let ctx = params.context_at_level(0)?.clone();
        let expected_len = ctx.moduli().len();
        let r1 = first
            .last_round
            .clone()
            .ok_or(Error::Mbfv(MbfvError::RoundReferenceMismatch))?;
        require_same_parameters(&r1.params, &params)?;
        // The referencing execution must be the aggregate's own execution: a
        // differently-labelled share set may not reuse another session's
        // aggregate even when every polynomial happens to coincide.
        if r1.participant_set.as_ref() != Some(&r2_participant_set) {
            return Err(Error::Mbfv(MbfvError::RoundReferenceMismatch));
        }

        // Anchor every retained reference and share vector to the level-zero
        // context with exactly one entry per level-zero modulus.
        require_anchored_poly_vector(&r1.h0, &ctx, expected_len, "round-1 aggregate h0")?;
        require_anchored_poly_vector(&r1.h1, &ctx, expected_len, "round-1 aggregate h1")?;
        require_anchored_poly_vector(&first.h0, &ctx, expected_len, "round-2 h0")?;
        require_anchored_poly_vector(&first.h1, &ctx, expected_len, "round-2 h1")?;
        for sh in rest {
            require_same_parameters(&sh.params, &params)?;
            let sh_r1 = sh
                .last_round
                .clone()
                .ok_or(Error::Mbfv(MbfvError::RoundReferenceMismatch))?;
            require_same_r1_aggregate(&sh_r1, &r1)?;
            require_anchored_poly_vector(&sh.h0, &ctx, expected_len, "round-2 h0")?;
            require_anchored_poly_vector(&sh.h1, &ctx, expected_len, "round-2 h1")?;
        }

        // Checked coordinate-wise additions over validated equal lengths.
        let mut h0 = first.h0.clone();
        let mut h1 = first.h1.clone();
        for sh in rest {
            for (dst, src) in h0.iter_mut().zip(sh.h0.iter()) {
                *dst += src;
            }
            for (dst, src) in h1.iter_mut().zip(sh.h1.iter()) {
                *dst += src;
            }
        }

        // h0 and h1 were validated to have equal lengths above.
        let mut c0 = Vec::from(h0);
        for (c0i, h1i) in c0.iter_mut().zip(h1.iter()) {
            *c0i += h1i;
        }
        let c0 = c0
            .into_iter()
            .map(|p| Poly::<Ntt>::into_ntt_shoup(p).map_err(Error::MathError))
            .collect::<Result<Vec<Poly<NttShoup>>>>()?
            .into_boxed_slice();

        let c1 = r1
            .h1
            .iter()
            .cloned()
            .map(|p| Poly::<Ntt>::into_ntt_shoup(p).map_err(Error::MathError))
            .collect::<Result<Vec<Poly<NttShoup>>>>()?
            .into_boxed_slice();

        let ksk = KeySwitchingKey {
            params,
            c0,
            c1,
            seed: None,
            ciphertext_level: 0,
            ctx_ciphertext: ctx.clone(),
            ksk_level: 0,
            ctx_ksk: ctx.clone(),
            log_base: 0,
        };
        Ok(RelinearizationKey::new_from_ksk(ksk))
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
            BfvParameters, CommonRandomPoly, CommonRandomPolyVec, Encoding, Multiplicator,
            Plaintext, PublicKey, RelinearizationKey, SecretKey,
        },
        identity::{ContributionBinding, ParticipantSet, SessionId},
        mbfv::round::{R1, R1Aggregated, R2},
        mbfv::{
            Aggregate, AggregateIter, DecryptionShare, PublicKeyShare, RelinKeyGenerator,
            RelinKeyShare,
        },
    };

    const NUM_PARTIES: usize = 5;

    fn participant_set(session: u8) -> ParticipantSet {
        ParticipantSet::new(
            SessionId::new([session; 32]),
            (1..=NUM_PARTIES as u32).collect(),
        )
        .unwrap()
    }

    #[test]
    fn relinearization_works() {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(3, 16),
            BfvParameters::default_arc(6, 32),
        ] {
            // Just support level 0 for now.
            let level = 0;
            for _ in 0..10 {
                let crp = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

                let mut party_sks: Vec<SecretKey> = vec![];
                let mut party_pks: Vec<PublicKeyShare> = vec![];
                let mut party_rlks: Vec<RelinKeyGenerator> = vec![];

                let pk_set = participant_set(71);
                let rlk_set = participant_set(72);

                // Parties undergo round 1
                for _ in 0..NUM_PARTIES {
                    let sk_share = SecretKey::random(&params, &mut rng);
                    party_sks.push(sk_share);
                }
                let crp_pk = CommonRandomPoly::new(&params, &mut rng).unwrap();
                for (i, sk) in party_sks.iter().enumerate() {
                    let pk_share = PublicKeyShare::new(
                        sk,
                        crp_pk.clone(),
                        ContributionBinding::new(pk_set.clone(), i as u32 + 1).unwrap(),
                        &mut rng,
                    )
                    .unwrap();
                    let rlk_generator = RelinKeyGenerator::new(
                        sk,
                        &crp,
                        ContributionBinding::new(rlk_set.clone(), i as u32 + 1).unwrap(),
                        &mut rng,
                    )
                    .unwrap();
                    party_pks.push(pk_share);
                    party_rlks.push(rlk_generator);
                }

                // Aggregate pk shares into public key
                let public_key = PublicKey::from_shares(party_pks).unwrap();

                // Aggregate rlk r1 shares
                let rlk_r1 = Arc::new(
                    party_rlks
                        .iter()
                        .enumerate()
                        .map(|(i, g)| {
                            g.round_1(&mut rng).inspect(|share| {
                                assert_eq!(
                                    share.binding().map(|b| b.participant_id()),
                                    Some(i as u32 + 1)
                                );
                            })
                        })
                        .aggregate()
                        .unwrap(),
                );
                // Aggregate rlk r2 shares into relin key
                let rlk: RelinearizationKey = party_rlks
                    .iter()
                    .map(|g| g.round_2(&rlk_r1, &mut rng))
                    .aggregate()
                    .unwrap();

                // Create a couple random encrypted polynomials
                let v1 = fhe_math::zq::Modulus::new(params.plaintext())
                    .unwrap()
                    .random_vec(params.degree(), &mut rng);
                let v2 = fhe_math::zq::Modulus::new(params.plaintext())
                    .unwrap()
                    .random_vec(params.degree(), &mut rng);
                let pt1 =
                    Plaintext::try_encode(&v1, Encoding::simd_at_level(level), &params).unwrap();
                let pt2 =
                    Plaintext::try_encode(&v2, Encoding::simd_at_level(level), &params).unwrap();
                let ct1 = public_key.try_encrypt(&pt1, &mut rng).unwrap();
                let ct2 = public_key.try_encrypt(&pt2, &mut rng).unwrap();

                // Multiply them
                let mut multiplicator = Multiplicator::default(&rlk).unwrap();
                if params.moduli().len() > 1 {
                    multiplicator.enable_mod_switching().unwrap();
                }
                let ct = Arc::new(multiplicator.multiply(&ct1, &ct2).unwrap());
                assert_eq!(ct.len(), 2);

                // Parties perform a collective decryption
                let pt = party_sks
                    .iter()
                    .enumerate()
                    .map(|(i, s)| {
                        DecryptionShare::new(
                            s,
                            &ct,
                            ContributionBinding::new(pk_set.clone(), i as u32 + 1).unwrap(),
                            &mut rng,
                        )
                    })
                    .aggregate()
                    .unwrap();

                let mut expected = v1.clone();
                fhe_math::zq::Modulus::new(params.plaintext())
                    .unwrap()
                    .mul_vec(&mut expected, &v2);
                assert_eq!(
                    Vec::<u64>::try_decode(&pt, Encoding::simd_at_level(pt.level)).unwrap(),
                    expected
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Aggregation rejection matrix (#89)
    // -----------------------------------------------------------------------

    /// Generate bound round-1 shares for all parties against `crp`.
    fn generate_round1(
        params: &Arc<BfvParameters>,
        crp: &CommonRandomPolyVec,
        set: &ParticipantSet,
    ) -> Vec<RelinKeyShare<R1>> {
        let mut rng = rng();
        (1..=NUM_PARTIES as u32)
            .map(|i| {
                let sk_share = SecretKey::random(params, &mut rng);
                let generator = RelinKeyGenerator::new(
                    &sk_share,
                    crp,
                    ContributionBinding::new(set.clone(), i).unwrap(),
                    &mut rng,
                )
                .unwrap();
                generator.round_1(&mut rng).unwrap()
            })
            .collect()
    }

    #[test]
    fn r1_aggregation_rejects_different_crp_vectors_and_participants() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let set = participant_set(73);
        let crp_a = CommonRandomPolyVec::new(&params, &mut rng).unwrap();
        let crp_b = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

        // Different CRP vectors under complete exact coverage: party 5's
        // contribution was generated against a foreign CRP.
        let mut shares = generate_round1(&params, &crp_a, &set);
        shares.remove(NUM_PARTIES - 1);
        let stray = generate_round1(&params, &crp_b, &set).remove(NUM_PARTIES - 1);
        shares.push(stray);
        let err =
            <RelinKeyShare<R1Aggregated> as Aggregate<RelinKeyShare<R1>>>::from_shares(shares)
                .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Mbfv(MbfvError::PublicInputMismatch { .. })
            ),
            "unexpected error: {err}"
        );

        // Duplicate participant.
        let mut shares = generate_round1(&params, &crp_a, &set);
        shares.truncate(2);
        shares[1].binding = Some(ContributionBinding::new(set.clone(), 1).unwrap());
        let err =
            <RelinKeyShare<R1Aggregated> as Aggregate<RelinKeyShare<R1>>>::from_shares(shares)
                .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Threshold(crate::ThresholdError::DuplicateContribution { .. })
            ),
            "unexpected error: {err}"
        );

        // Missing participant: declare more members than contributions.
        let bigger_set = ParticipantSet::new(
            SessionId::new([74u8; 32]),
            (1..=(NUM_PARTIES as u32 + 1)).collect(),
        )
        .unwrap();
        let shares = generate_round1(&params, &crp_a, &bigger_set);
        let err =
            <RelinKeyShare<R1Aggregated> as Aggregate<RelinKeyShare<R1>>>::from_shares(shares)
                .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Threshold(crate::ThresholdError::MissingContribution)
            ),
            "unexpected error: {err}"
        );

        // Cross-session shares.
        let other_set = participant_set(75);
        let mut shares = generate_round1(&params, &crp_a, &set);
        let stranger = generate_round1(&params, &crp_a, &other_set).remove(0);
        shares.push(stranger);
        let err =
            <RelinKeyShare<R1Aggregated> as Aggregate<RelinKeyShare<R1>>>::from_shares(shares)
                .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Threshold(crate::ThresholdError::ContributionSetMismatch)
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn r1_aggregation_rejects_length_and_context_mismatches() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let set = participant_set(76);
        let crp = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

        let mut shares = generate_round1(&params, &crp, &set);

        // Truncated h0 on one share: previously silently ignored by izip!.
        let mut short = shares.remove(1);
        short.h0 = short.h0[..short.h0.len() - 1].to_vec().into_boxed_slice();
        shares.push(short);
        let err = <RelinKeyShare<R1Aggregated> as Aggregate<RelinKeyShare<R1>>>::from_shares(
            shares.clone(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Mbfv(MbfvError::ShareShapeMismatch { .. })
            ),
            "unexpected error: {err}"
        );

        // Wrong-context component.
        let mut shares = generate_round1(&params, &crp, &set);
        let mut wrong_ctx = shares.remove(1);
        let leveled_ctx = params.context_at_level(1).unwrap();
        wrong_ctx.h0[0] = fhe_math::rq::Poly::<Ntt>::random(leveled_ctx, &mut rng);
        shares.push(wrong_ctx);
        let err =
            <RelinKeyShare<R1Aggregated> as Aggregate<RelinKeyShare<R1>>>::from_shares(shares)
                .unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::InvalidContext)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn r2_aggregation_rejects_missing_and_mismatched_r1_references() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let set = participant_set(77);
        let crp = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

        // Generators borrow their party secret keys; create keys first.
        let party_sks: Vec<SecretKey> = (0..NUM_PARTIES)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let generators: Vec<RelinKeyGenerator> = party_sks
            .iter()
            .enumerate()
            .map(|(i, sk_share)| {
                RelinKeyGenerator::new(
                    sk_share,
                    &crp,
                    ContributionBinding::new(set.clone(), i as u32 + 1).unwrap(),
                    &mut rng,
                )
                .unwrap()
            })
            .collect();

        let r1: Arc<RelinKeyShare<R1Aggregated>> = Arc::new(
            generators
                .iter()
                .map(|g| g.round_1(&mut rng))
                .aggregate()
                .unwrap(),
        );
        let r1_other = Arc::new(RelinKeyShare::<R1Aggregated> {
            params: r1.params.clone(),
            h0: r1.h0.clone(),
            h1: r1.h1.clone(),
            binding: None,
            crp: r1.crp.clone(),
            participant_set: Some(participant_set(78)),
            last_round: None,
            _phantom_data: std::marker::PhantomData,
        });

        // Missing round-1 reference.
        let mut shares: Vec<RelinKeyShare<R2>> = generators
            .iter()
            .take(NUM_PARTIES - 1)
            .map(|g| g.round_2(&r1, &mut rng).unwrap())
            .collect();
        let orphan = {
            let sk_share = SecretKey::random(&params, &mut rng);
            let generator = RelinKeyGenerator::new(
                &sk_share,
                &crp,
                ContributionBinding::new(set.clone(), NUM_PARTIES as u32).unwrap(),
                &mut rng,
            )
            .unwrap();
            let mut share = generator.round_2(&r1, &mut rng).unwrap();
            share.last_round = None;
            share
        };
        shares.push(orphan);
        let err =
            <RelinearizationKey as Aggregate<RelinKeyShare<R2>>>::from_shares(shares).unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::RoundReferenceMismatch)),
            "unexpected error: {err}"
        );

        // Mismatched round-1 reference (same shape, different metadata).
        let mut shares: Vec<RelinKeyShare<R2>> = generators
            .iter()
            .take(NUM_PARTIES - 1)
            .map(|g| g.round_2(&r1, &mut rng).unwrap())
            .collect();
        let mut deviant = generators[NUM_PARTIES - 1].round_2(&r1, &mut rng).unwrap();
        deviant.last_round = Some(Arc::clone(&r1_other));
        shares.push(deviant);
        let err =
            <RelinearizationKey as Aggregate<RelinKeyShare<R2>>>::from_shares(shares).unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::RoundReferenceMismatch)),
            "unexpected error: {err}"
        );

        // A valid full two-round aggregation still succeeds.
        let shares: Vec<RelinKeyShare<R2>> = generators
            .iter()
            .map(|g| g.round_2(&r1, &mut rng).unwrap())
            .collect();
        assert!(RelinearizationKey::from_shares(shares).is_ok());
    }

    #[test]
    fn r2_aggregation_rejects_truncated_vectors_previously_hidden_by_izip() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let set = participant_set(79);
        let crp = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

        // Generators borrow their party secret keys; create keys first.
        let party_sks: Vec<SecretKey> = (0..NUM_PARTIES)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let generators: Vec<RelinKeyGenerator> = party_sks
            .iter()
            .enumerate()
            .map(|(i, sk_share)| {
                RelinKeyGenerator::new(
                    sk_share,
                    &crp,
                    ContributionBinding::new(set.clone(), i as u32 + 1).unwrap(),
                    &mut rng,
                )
                .unwrap()
            })
            .collect();
        let r1 = Arc::new(
            generators
                .iter()
                .map(|g| g.round_1(&mut rng))
                .aggregate()
                .unwrap(),
        );

        // One share's h0 is shorter than the others: old izip! silently
        // truncated; the aggregation must now reject the shape mismatch.
        let mut shares: Vec<RelinKeyShare<R2>> = generators
            .iter()
            .map(|g| g.round_2(&r1, &mut rng).unwrap())
            .collect();
        let mut short = shares.remove(2);
        short.h0 = short.h0[..short.h0.len() - 1].to_vec().into_boxed_slice();
        shares.push(short);
        let err =
            <RelinearizationKey as Aggregate<RelinKeyShare<R2>>>::from_shares(shares).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Mbfv(MbfvError::ShareShapeMismatch { .. })
            ),
            "unexpected error: {err}"
        );

        // Duplicate participant at round 2.
        let mut shares: Vec<RelinKeyShare<R2>> = generators
            .iter()
            .map(|g| g.round_2(&r1, &mut rng).unwrap())
            .collect();
        shares[1].binding = shares[0].binding.clone();
        let err =
            <RelinearizationKey as Aggregate<RelinKeyShare<R2>>>::from_shares(shares).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Threshold(crate::ThresholdError::DuplicateContribution { .. })
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn r1_aggregation_rejects_unbound_share_among_valid_shares() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let set = participant_set(82);
        let crp = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

        // The full exactly-covering bound set plus one APPENDED unbound
        // share: coverage alone would succeed on the bound set while the
        // extra polynomial would previously be summed silently. The whole
        // list must be rejected with MissingBinding.
        let mut shares = generate_round1(&params, &crp, &set);
        let mut unbound = shares.first().unwrap().clone();
        unbound.binding = None;
        shares.push(unbound);
        let err =
            <RelinKeyShare<R1Aggregated> as Aggregate<RelinKeyShare<R1>>>::from_shares(shares)
                .unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::MissingBinding)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn r1_aggregation_rejects_foreign_context_h_vectors() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let set = participant_set(90);
        let crp = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

        // Every h vector consistently moved to a non-level-zero context:
        // internal consistency among shares must not substitute for the
        // level-zero anchor.
        let mut shares = generate_round1(&params, &crp, &set);
        let foreign_ctx = params.context_at_level(1).unwrap();
        for share in &mut shares {
            for h in share.h0.iter_mut().chain(share.h1.iter_mut()) {
                *h = fhe_math::rq::Poly::<Ntt>::random(foreign_ctx, &mut rng);
            }
        }
        let err =
            <RelinKeyShare<R1Aggregated> as Aggregate<RelinKeyShare<R1>>>::from_shares(shares)
                .unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::InvalidContext)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn r1_aggregation_rejects_empty_h_vectors() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let set = participant_set(91);
        let crp = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

        // All h vectors emptied: vacuous shape agreement must not pass.
        let mut shares = generate_round1(&params, &crp, &set);
        for share in &mut shares {
            share.h0 = Vec::new().into_boxed_slice();
            share.h1 = Vec::new().into_boxed_slice();
        }
        let err =
            <RelinKeyShare<R1Aggregated> as Aggregate<RelinKeyShare<R1>>>::from_shares(shares)
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
    fn round_2_and_r2_aggregation_reject_foreign_context_round1_reference() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let set = participant_set(92);
        let crp = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

        // Generators borrow their party secret keys; create keys first.
        let party_sks: Vec<SecretKey> = (0..NUM_PARTIES)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let generators: Vec<RelinKeyGenerator> = party_sks
            .iter()
            .enumerate()
            .map(|(i, sk_share)| {
                RelinKeyGenerator::new(
                    sk_share,
                    &crp,
                    ContributionBinding::new(set.clone(), i as u32 + 1).unwrap(),
                    &mut rng,
                )
                .unwrap()
            })
            .collect();

        let r1: Arc<RelinKeyShare<R1Aggregated>> = Arc::new(
            generators
                .iter()
                .map(|g| g.round_1(&mut rng))
                .aggregate()
                .unwrap(),
        );

        // Forge a round-1 aggregate whose retained h vectors live at level
        // one but whose metadata (set/session/CRP/lengths) is intact.
        let mut forged_r1 = (*r1).clone();
        let foreign_ctx = params.context_at_level(1).unwrap();
        for h in forged_r1.h0.iter_mut().chain(forged_r1.h1.iter_mut()) {
            *h = fhe_math::rq::Poly::<Ntt>::random(foreign_ctx, &mut rng);
        }
        let forged_r1 = Arc::new(forged_r1);

        // The generator path must refuse to derive round-2 material from it.
        let err = generators[0].round_2(&forged_r1, &mut rng).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::Mbfv(MbfvError::InvalidContext)
                    | crate::Error::Mbfv(MbfvError::RoundReferenceMismatch)
            ),
            "unexpected error: {err}"
        );

        // Crate-assembled round-2 shares referencing the forged aggregate are
        // equally rejected at aggregation time.
        let mut shares: Vec<RelinKeyShare<R2>> = generators
            .iter()
            .map(|g| g.round_2(&r1, &mut rng).unwrap())
            .collect();
        for share in &mut shares {
            share.last_round = Some(Arc::clone(&forged_r1));
            for h in share.h0.iter_mut().chain(share.h1.iter_mut()) {
                *h = fhe_math::rq::Poly::<Ntt>::random(foreign_ctx, &mut rng);
            }
        }
        let err =
            <RelinearizationKey as Aggregate<RelinKeyShare<R2>>>::from_shares(shares).unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::InvalidContext)),
            "unexpected error: {err}"
        );

        // The honest protocol still completes.
        let shares: Vec<RelinKeyShare<R2>> = generators
            .iter()
            .map(|g| g.round_2(&r1, &mut rng).unwrap())
            .collect();
        assert!(RelinearizationKey::from_shares(shares).is_ok());
    }

    #[test]
    fn r2_aggregation_rejects_foreign_session_r2_set_referencing_valid_r1() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let set_a = ParticipantSet::new(
            SessionId::new([93u8; 32]),
            (1..=NUM_PARTIES as u32).collect(),
        )
        .unwrap();
        // Same IDs, different session.
        let set_b = ParticipantSet::new(
            SessionId::new([94u8; 32]),
            (1..=NUM_PARTIES as u32).collect(),
        )
        .unwrap();
        let crp = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

        // Generators borrow their party secret keys; create keys first.
        let party_sks: Vec<SecretKey> = (0..NUM_PARTIES)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let generators: Vec<RelinKeyGenerator> = party_sks
            .iter()
            .enumerate()
            .map(|(i, sk_share)| {
                RelinKeyGenerator::new(
                    sk_share,
                    &crp,
                    ContributionBinding::new(set_a.clone(), i as u32 + 1).unwrap(),
                    &mut rng,
                )
                .unwrap()
            })
            .collect();

        let r1: Arc<RelinKeyShare<R1Aggregated>> = Arc::new(
            generators
                .iter()
                .map(|g| g.round_1(&mut rng))
                .aggregate()
                .unwrap(),
        );

        // Re-label an otherwise valid round-2 contribution set with another
        // session's exact participant set, keeping references to the original
        // aggregate. The relabelled coverage is exact, but the executions
        // differ and the aggregation must refuse.
        let mut shares: Vec<RelinKeyShare<R2>> = generators
            .iter()
            .map(|g| g.round_2(&r1, &mut rng).unwrap())
            .collect();
        for (i, share) in shares.iter_mut().enumerate() {
            share.binding = Some(ContributionBinding::new(set_b.clone(), i as u32 + 1).unwrap());
        }
        let err =
            <RelinearizationKey as Aggregate<RelinKeyShare<R2>>>::from_shares(shares).unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::RoundReferenceMismatch)),
            "unexpected error: {err}"
        );

        // The honestly-labelled aggregation still succeeds.
        let shares: Vec<RelinKeyShare<R2>> = generators
            .iter()
            .map(|g| g.round_2(&r1, &mut rng).unwrap())
            .collect();
        assert!(RelinearizationKey::from_shares(shares).is_ok());
    }

    #[test]
    fn r2_aggregation_rejects_unbound_share_among_valid_shares() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let set = participant_set(83);
        let crp = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

        // Generators borrow their party secret keys; create keys first.
        let party_sks: Vec<SecretKey> = (0..NUM_PARTIES)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let generators: Vec<RelinKeyGenerator> = party_sks
            .iter()
            .enumerate()
            .map(|(i, sk_share)| {
                RelinKeyGenerator::new(
                    sk_share,
                    &crp,
                    ContributionBinding::new(set.clone(), i as u32 + 1).unwrap(),
                    &mut rng,
                )
                .unwrap()
            })
            .collect();
        let r1 = Arc::new(
            generators
                .iter()
                .map(|g| g.round_1(&mut rng))
                .aggregate()
                .unwrap(),
        );

        // Full bound round-2 set plus an APPENDED unbound copy of a valid
        // share; the aggregation must reject rather than sum the extra.
        let mut shares: Vec<RelinKeyShare<R2>> = generators
            .iter()
            .map(|g| g.round_2(&r1, &mut rng).unwrap())
            .collect();
        let mut unbound = shares.first().unwrap().clone();
        unbound.binding = None;
        shares.push(unbound);
        let err =
            <RelinearizationKey as Aggregate<RelinKeyShare<R2>>>::from_shares(shares).unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::MissingBinding)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn round_2_rejects_same_session_with_foreign_crp() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        // Same session and participant set for both executions; only the
        // concrete CRP vector differs.
        let set = ParticipantSet::new(SessionId::new([84u8; 32]), vec![1]).unwrap();
        let crp_a = CommonRandomPolyVec::new(&params, &mut rng).unwrap();
        let crp_b = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

        // Aggregate from an execution over CRP A.
        let sk_share_a = SecretKey::random(&params, &mut rng);
        let generator_a = RelinKeyGenerator::new(
            &sk_share_a,
            &crp_a,
            ContributionBinding::new(set.clone(), 1).unwrap(),
            &mut rng,
        )
        .unwrap();
        let r1 = Arc::new(
            vec![generator_a.round_1(&mut rng).unwrap()]
                .into_iter()
                .aggregate::<RelinKeyShare<R1Aggregated>>()
                .unwrap(),
        );

        // A party whose generator uses CRP B must not derive round-2
        // material from the CRP-A aggregate under the same session label.
        let sk_share_b = SecretKey::random(&params, &mut rng);
        let generator_b = RelinKeyGenerator::new(
            &sk_share_b,
            &crp_b,
            ContributionBinding::new(set.clone(), 1).unwrap(),
            &mut rng,
        )
        .unwrap();
        let err = generator_b.round_2(&r1, &mut rng).unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::RoundReferenceMismatch)),
            "unexpected error: {err}"
        );

        // The matching-CRP generator still works.
        assert!(generator_a.round_2(&r1, &mut rng).is_ok());
    }

    #[test]
    fn generator_rejects_mismatched_binding_for_round2_reference() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        // Single-member sets keep the one-party round-1 aggregation exact.
        let set = ParticipantSet::new(SessionId::new([80u8; 32]), vec![1]).unwrap();
        let other_set = ParticipantSet::new(SessionId::new([81u8; 32]), vec![2]).unwrap();
        let crp = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

        let sk_share = SecretKey::random(&params, &mut rng);
        let generator = RelinKeyGenerator::new(
            &sk_share,
            &crp,
            ContributionBinding::new(set.clone(), 1).unwrap(),
            &mut rng,
        )
        .unwrap();
        let r1 = Arc::new(
            vec![generator.round_1(&mut rng).unwrap()]
                .into_iter()
                .aggregate::<RelinKeyShare<R1Aggregated>>()
                .unwrap(),
        );

        // The same party cannot derive round-2 material from an aggregate of
        // another execution (different participant set/session).
        let other_sk = SecretKey::random(&params, &mut rng);
        let mismatched_generator = RelinKeyGenerator::new(
            &other_sk,
            &crp,
            ContributionBinding::new(other_set, 2).unwrap(),
            &mut rng,
        )
        .unwrap();
        let err = mismatched_generator.round_2(&r1, &mut rng).unwrap_err();
        assert!(
            matches!(err, crate::Error::Mbfv(MbfvError::RoundReferenceMismatch)),
            "unexpected error: {err}"
        );
    }
}
