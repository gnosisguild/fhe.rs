use std::marker::PhantomData;
use std::sync::Arc;

use crate::bfv::{BfvParameters, KeySwitchingKey, RelinearizationKey, SecretKey};
use crate::{MultipartyError, Result};
use fhe_math::rns::RnsContext;
use fhe_math::rq::{Ntt, NttShoup, Poly, PowerBasis, traits::TryConvertFrom};
use itertools::izip;
use rand::{CryptoRng, Rng as RngCore};
use zeroize::Zeroizing;

use crate::bfv::{CommonRandomPoly, CommonRandomPolyVec};

use super::Aggregate;
use super::round::{R1, R1Aggregated, R2, Round};
use super::validate::{same_params, same_polys};

/// A party's share in the relinearization key generation protocol.
/// Use the [`RelinKeyGenerator`] to create these shares.
/// Round-one shares retain their concrete CRP vector so aggregation can reject
/// contributions generated from different reference polynomials.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RelinKeyShare<R: Round = R1> {
    pub(crate) params: Arc<BfvParameters>,
    pub(crate) h0: Box<[Poly<Ntt>]>,
    pub(crate) h1: Box<[Poly<Ntt>]>,
    // Retain the concrete round-one reference string for aggregation checks.
    crp: Option<CommonRandomPolyVec>,
    last_round: Option<Arc<RelinKeyShare<R1Aggregated>>>,
    _phantom_data: PhantomData<R>,
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
/// use fhe::mbfv::{Aggregate, RelinKeyGenerator, RelinKeyShare, round::*};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let parameters = BfvParametersBuilder::new()
///         .set_degree(4096)
///         .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
///         .set_plaintext_modulus(1 << 10)
///         .build_arc()?;
///
/// // Party perspective
/// let mut rng = rand::rng();
/// let sk_share = SecretKey::random(&parameters, &mut rng);
/// let crp = CommonRandomPolyVec::new(&parameters, &mut rng)?;
/// let rlk_generator = RelinKeyGenerator::new(&sk_share, &crp, &mut rng)?;
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
}

impl<'a, 'b> RelinKeyGenerator<'a, 'b> {
    /// Create a new relin key generator for a given party.
    ///
    /// 1. *Private input*: BFV secret key share
    /// 2. *Public input*: common random polynomial vector
    pub fn new<R: RngCore + CryptoRng>(
        sk_share: &'a SecretKey,
        crp: &'b CommonRandomPolyVec,
        rng: &mut R,
    ) -> Result<Self> {
        let params = sk_share.params.clone();
        let ctx = params.context_at_level(0)?;
        if ctx.moduli().len() == 1 {
            Err(crate::EvaluationKeyError::KeySwitchingNotSupported.into())
        } else if crp.len() != ctx.moduli().len() {
            Err(crate::MultipartyError::InvalidCommonRandomPolynomialCount {
                actual: crp.len(),
                expected: ctx.moduli().len(),
            }
            .into())
        } else if crp.as_slice().iter().any(|p| p.poly().ctx() != ctx) {
            Err(MultipartyError::IncompatibleShares {
                reason: "relinearization CRP context does not match secret-key parameters",
            }
            .into())
        } else {
            let u = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);
            Ok(Self { sk_share, crp, u })
        }
    }

    /// Generate share for round 1
    pub fn round_1<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<RelinKeyShare<R1>> {
        <RelinKeyShare<R1>>::new(self.sk_share, self.crp, &self.u, rng)
    }

    /// Generate share for round 2
    pub fn round_2<R: RngCore + CryptoRng>(
        &self,
        r1: &Arc<RelinKeyShare<R1Aggregated>>,
        rng: &mut R,
    ) -> Result<RelinKeyShare<R2>> {
        <RelinKeyShare<R2>>::new(self.sk_share, &self.u, r1, rng)
    }
}

impl RelinKeyShare<R1> {
    fn new<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        crp: &CommonRandomPolyVec,
        u: &Zeroizing<Poly<Ntt>>,
        rng: &mut R,
    ) -> Result<Self> {
        let params = sk_share.params.clone();

        let expected_crp_count = params.context_at_level(0)?.moduli().len();
        if crp.len() != expected_crp_count {
            Err(crate::MultipartyError::InvalidCommonRandomPolynomialCount {
                actual: crp.len(),
                expected: expected_crp_count,
            }
            .into())
        } else {
            let h0 = Self::generate_h0(sk_share, crp.as_slice(), u, rng)?;
            let h1 = Self::generate_h1(sk_share, crp.as_slice(), rng)?;
            Ok(Self {
                params,
                h0,
                h1,
                crp: Some(crp.clone()),
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
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?.into_ntt(),
        );
        let rns = RnsContext::new(&sk_share.params.moduli[..crp.len()])?;
        let h0 = crp
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let w = rns.get_garner(i).unwrap();
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
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?.into_ntt(),
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
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = RelinKeyShare<R1>>,
    {
        let mut shares = iter.into_iter();
        let share = shares.next().ok_or(crate::MultipartyError::NoShares)?;
        let expected = share.params.moduli().len();
        same_polys(&share.h0, expected, "round-one h0", &share.params)?;
        same_polys(&share.h1, expected, "round-one h1", &share.params)?;
        let crp = share
            .crp
            .as_ref()
            .ok_or(MultipartyError::IncompatibleShares {
                reason: "missing round-one CRP",
            })?;
        let ctx = share.params.context_at_level(0)?;
        if crp.len() != expected || crp.as_slice().iter().any(|p| p.poly().ctx() != ctx) {
            return Err(MultipartyError::IncompatibleShares {
                reason: "invalid round-one CRP",
            }
            .into());
        }
        let mut h0 = share.h0;
        let mut h1 = share.h1;
        for sh in shares {
            same_params(&share.params, &sh.params)?;
            same_polys(&sh.h0, expected, "round-one h0", &sh.params)?;
            same_polys(&sh.h1, expected, "round-one h1", &sh.params)?;
            if sh.crp.as_ref() != Some(crp) {
                return Err(MultipartyError::IncompatibleShares {
                    reason: "different relinearization CRP polynomials",
                }
                .into());
            }
            izip!(h0.iter_mut(), sh.h0.iter()).for_each(|(h0i, sh_h0i)| *h0i += sh_h0i);
            izip!(h1.iter_mut(), sh.h1.iter()).for_each(|(h1i, sh_h1i)| *h1i += sh_h1i);
        }

        Ok(RelinKeyShare {
            params: share.params,
            h0,
            h1,
            crp: share.crp,
            last_round: None,
            _phantom_data: PhantomData,
        })
    }
}

impl RelinKeyShare<R2> {
    fn new<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        u: &Zeroizing<Poly<Ntt>>,
        r1: &Arc<RelinKeyShare<R1Aggregated>>,
        rng: &mut R,
    ) -> Result<Self> {
        let params = sk_share.params.clone();
        same_params(&params, &r1.params)?;
        let expected = params.moduli().len();
        same_polys(&r1.h0, expected, "aggregated round-one h0", &params)?;
        same_polys(&r1.h1, expected, "aggregated round-one h1", &params)?;
        let h0 = Self::generate_h0(sk_share, &r1.h0, rng)?;
        let h1 = Self::generate_h1(sk_share, u, &r1.h1, rng)?;
        Ok(Self {
            params,
            h0,
            h1,
            crp: None,
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
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?.into_ntt(),
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
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?.into_ntt(),
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
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = RelinKeyShare<R2>>,
    {
        let mut shares = iter.into_iter();
        let share = shares.next().ok_or(crate::MultipartyError::NoShares)?;
        let params = share.params.clone();
        let expected = params.moduli().len();
        same_polys(&share.h0, expected, "round-two h0", &params)?;
        same_polys(&share.h1, expected, "round-two h1", &params)?;
        let ctx = params.context_at_level(0)?.clone();
        let r1 = share
            .last_round
            .ok_or(crate::MultipartyError::MissingRelinearizationRoundOneShare)?;
        same_params(&params, &r1.params)?;
        same_polys(&r1.h0, expected, "aggregated round-one h0", &params)?;
        same_polys(&r1.h1, expected, "aggregated round-one h1", &params)?;

        let mut h0 = share.h0;
        let mut h1 = share.h1;
        for sh in shares {
            same_params(&params, &sh.params)?;
            same_polys(&sh.h0, expected, "round-two h0", &params)?;
            same_polys(&sh.h1, expected, "round-two h1", &params)?;
            if sh.last_round.as_deref() != Some(r1.as_ref()) {
                return Err(MultipartyError::IncompatibleShares {
                    reason: "round-two shares reference different round-one aggregations",
                }
                .into());
            }
            izip!(h0.iter_mut(), h1.iter_mut(), sh.h0.iter(), sh.h1.iter()).for_each(
                |(h0, h1, h0i, h1i)| {
                    *h0 += h0i;
                    *h1 += h1i;
                },
            );
        }

        let mut c0 = Vec::from(h0);
        izip!(c0.iter_mut(), h1.iter()).for_each(|(c0, h1)| *c0 += h1);
        let c0 = c0
            .into_iter()
            .map(Poly::<Ntt>::into_ntt_shoup)
            .collect::<Vec<Poly<NttShoup>>>()
            .into_boxed_slice();

        let c1 = r1
            .h1
            .iter()
            .cloned()
            .map(Poly::<Ntt>::into_ntt_shoup)
            .collect::<Vec<Poly<NttShoup>>>()
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
mod tests {
    use std::sync::Arc;

    use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
    use rand::rng;

    use crate::{
        bfv::{
            BfvParameters, CommonRandomPoly, CommonRandomPolyVec, Encoding, Multiplicator,
            Plaintext, PublicKey, RelinearizationKey, SecretKey,
        },
        mbfv::{Aggregate as _, AggregateIter, DecryptionShare, PublicKeyShare, RelinKeyGenerator},
    };

    const NUM_PARTIES: usize = 5;

    #[test]
    fn aggregation_rejects_mismatched_relinearization_crps_rows_and_rounds() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let crp = CommonRandomPolyVec::new(&params, &mut rng).unwrap();
        let other_crp = CommonRandomPolyVec::new(&params, &mut rng).unwrap();
        let generator = RelinKeyGenerator::new(&sk, &crp, &mut rng).unwrap();
        let other_generator = RelinKeyGenerator::new(&sk, &other_crp, &mut rng).unwrap();
        let other_params = BfvParameters::default_arc(6, 16);
        let other_params_crp = CommonRandomPolyVec::new(&other_params, &mut rng).unwrap();
        assert!(RelinKeyGenerator::new(&sk, &other_params_crp, &mut rng).is_err());
        let first = generator.round_1(&mut rng).unwrap();
        let different_crp = other_generator.round_1(&mut rng).unwrap();
        assert!(
            crate::mbfv::RelinKeyShare::<crate::mbfv::round::R1Aggregated>::from_shares([
                first.clone(),
                generator.round_1(&mut rng).unwrap(),
            ])
            .is_ok()
        );
        assert!(matches!(
            crate::mbfv::RelinKeyShare::<crate::mbfv::round::R1Aggregated>::from_shares([
                first.clone(),
                different_crp
            ]),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::IncompatibleShares { .. }
            ))
        ));

        let mut short = generator.round_1(&mut rng).unwrap();
        short.h0 = Vec::new().into_boxed_slice();
        assert!(matches!(
            crate::mbfv::RelinKeyShare::<crate::mbfv::round::R1Aggregated>::from_shares([
                first.clone(),
                short
            ]),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::SharePolynomialCountMismatch { .. }
            ))
        ));

        let r1a = Arc::new(
            crate::mbfv::RelinKeyShare::<crate::mbfv::round::R1Aggregated>::from_shares([
                first.clone()
            ])
            .unwrap(),
        );
        let r1b = Arc::new(
            crate::mbfv::RelinKeyShare::<crate::mbfv::round::R1Aggregated>::from_shares([
                generator.round_1(&mut rng).unwrap(),
            ])
            .unwrap(),
        );
        let first_r2 = generator.round_2(&r1a, &mut rng).unwrap();
        let different_round = generator.round_2(&r1b, &mut rng).unwrap();
        assert!(matches!(
            RelinearizationKey::from_shares([first_r2.clone(), different_round]),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::IncompatibleShares { .. }
            ))
        ));

        let mut short_r2 = generator.round_2(&r1a, &mut rng).unwrap();
        short_r2.h1 = Vec::new().into_boxed_slice();
        assert!(matches!(
            RelinearizationKey::from_shares([first_r2, short_r2]),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::SharePolynomialCountMismatch { .. }
            ))
        ));

        let same_round = generator.round_2(&r1a, &mut rng).unwrap();
        let another_same_round = generator.round_2(&r1a, &mut rng).unwrap();
        assert!(RelinearizationKey::from_shares([same_round, another_same_round]).is_ok());

        let other_sk = SecretKey::random(&other_params, &mut rng);
        let other_generator =
            RelinKeyGenerator::new(&other_sk, &other_params_crp, &mut rng).unwrap();
        let other_r1 = Arc::new(
            crate::mbfv::RelinKeyShare::<crate::mbfv::round::R1Aggregated>::from_shares([
                other_generator.round_1(&mut rng).unwrap(),
            ])
            .unwrap(),
        );
        assert!(generator.round_2(&other_r1, &mut rng).is_err());
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

                // Parties undergo round 1
                for _ in 0..NUM_PARTIES {
                    let sk_share = SecretKey::random(&params, &mut rng);
                    party_sks.push(sk_share);
                }
                let crp_pk = CommonRandomPoly::new(&params, &mut rng).unwrap();
                (0..NUM_PARTIES).for_each(|i| {
                    let pk_share =
                        PublicKeyShare::new(&party_sks[i], crp_pk.clone(), &mut rng).unwrap();
                    let rlk_generator =
                        RelinKeyGenerator::new(&party_sks[i], &crp, &mut rng).unwrap();
                    party_pks.push(pk_share);
                    party_rlks.push(rlk_generator);
                });

                // Aggregate pk shares into public key
                let public_key = PublicKey::from_shares(party_pks).unwrap();

                // Aggregate rlk r1 shares
                let rlk_r1 = Arc::new(
                    party_rlks
                        .iter()
                        .map(|g| g.round_1(&mut rng))
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
                    .map(|s| DecryptionShare::new(s, &ct, &mut rng))
                    .aggregate()
                    .unwrap();

                let mut expected = v1.clone();
                fhe_math::zq::Modulus::new(params.plaintext())
                    .unwrap()
                    .mul_vec(&mut expected, &v2);
                assert_eq!(
                    Vec::<u64>::try_decode(&pt, Encoding::simd_at_level(pt.level())).unwrap(),
                    expected
                );
            }
        }
    }
}
