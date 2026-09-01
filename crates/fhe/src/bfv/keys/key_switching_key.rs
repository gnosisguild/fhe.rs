//! Key-switching keys for the BFV encryption scheme. Implements the
//! Brakerski-Vaikuntanathan key switching through decomposition technique
//! adapted to RNS as described in the HPS optimization paper (https://eprint.iacr.org/2018/117)

use crate::bfv::{BfvParameters, SecretKey, traits::TryConvertFrom as BfvTryConvertFrom};
use crate::proto::bfv::KeySwitchingKey as KeySwitchingKeyProto;
use crate::{Error, Result, SerializationError};
use fhe_math::rq::Context;
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::{
    rns::RnsContext,
    rq::{Ntt, NttShoup, Poly, PowerBasis},
};
use fhe_traits::{DeserializeWithContext, Serialize};
use itertools::{Itertools, izip};
use num_bigint::BigUint;
use rand::{CryptoRng, Rng, Rng as RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Key switching key for the BFV encryption scheme.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeySwitchingKey {
    /// BFV encryption scheme parameters.
    pub params: Arc<BfvParameters>,

    /// Seed used to generate c1 polynomials.
    pub seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,

    /// The key switching elements c0.
    pub(crate) c0: Box<[Poly<NttShoup>]>,

    /// The key switching elements c1.
    pub(crate) c1: Box<[Poly<NttShoup>]>,

    /// Max level and context of polynomials that can be key switched. This
    /// defines the decomposition basis of the key switching key.
    pub ciphertext_level: usize,

    /// Context of the ciphertext being key switched.
    pub ctx_ciphertext: Arc<Context>,

    /// Level and context of the key switching key polynomials. These can be
    /// mod switched down to be multiplied during keyswitching with a ciphertext
    /// that is of a different level.
    pub ksk_level: usize,

    /// Context of the key switching key polynomials.
    pub ctx_ksk: Arc<Context>,

    /// For level with only one modulus, we will use basis.
    pub log_base: usize,
}

impl KeySwitchingKey {
    fn permits_variable_time_with(&self, p: &Poly<PowerBasis>) -> bool {
        p.allows_variable_time_computations()
            && self
                .c0
                .iter()
                .chain(self.c1.iter())
                .all(Poly::allows_variable_time_computations)
    }

    fn configure_accumulators(&self, p: &Poly<PowerBasis>, c0: &mut Poly<Ntt>, c1: &mut Poly<Ntt>) {
        if self.permits_variable_time_with(p) {
            let variable_time =
                fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
            c0.allow_variable_time_computations(variable_time);
            c1.allow_variable_time_computations(variable_time);
        } else {
            c0.disallow_variable_time_computations();
            c1.disallow_variable_time_computations();
        }
    }

    /// Generate a [`KeySwitchingKey`] to this [`SecretKey`] from a polynomial
    /// `from` using a random seed for generating c1 values.
    pub fn new<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly<PowerBasis>,
        ciphertext_level: usize,
        ksk_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);

        Self::new_with_seed(sk, from, seed, ciphertext_level, ksk_level, rng)
    }

    /// Generate a [`KeySwitchingKey`] with a provided seed for generating c1
    /// values.
    pub fn new_with_seed<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly<PowerBasis>,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        ciphertext_level: usize,
        ksk_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        if ciphertext_level < ksk_level {
            return Err(crate::EvaluationKeyError::InvalidLevelOrder {
                ciphertext_level,
                key_level: ksk_level,
            }
            .into());
        }

        let params = sk.params.clone();
        let ctx_ksk = params.context_at_level(ksk_level)?.clone();
        let ctx_ciphertext = params.context_at_level(ciphertext_level)?.clone();

        if from.ctx() != &ctx_ksk {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::KeySwitchingKey,
            });
        }

        if ctx_ksk.moduli().len() == 1 {
            let modulus = ctx_ksk
                .moduli()
                .first()
                .ok_or(fhe_math::Error::EmptyModuli)?;
            let log_modulus = modulus.next_power_of_two().ilog2() as usize;
            let log_base = log_modulus / 2;
            let c1 = Self::c1_from_seed(&ctx_ksk, seed, log_modulus.div_ceil(log_base));
            let c0 = Self::generate_c0_decomposition(sk, from, &c1, rng, log_base)?;
            Ok(Self {
                params,
                seed: Some(seed),
                c0: c0.into_boxed_slice(),
                c1: c1.into_boxed_slice(),
                ciphertext_level,
                ctx_ciphertext,
                ksk_level,
                ctx_ksk,
                log_base,
            })
        } else {
            let c1 = Self::c1_from_seed(&ctx_ksk, seed, ctx_ciphertext.moduli().len());
            let c0 = Self::generate_c0(sk, from, &c1, rng)?;
            Ok(Self {
                params,
                seed: Some(seed),
                c0: c0.into_boxed_slice(),
                c1: c1.into_boxed_slice(),
                ciphertext_level,
                ctx_ciphertext,
                ksk_level,
                ctx_ksk,
                log_base: 0,
            })
        }
    }

    /// Generate a [`KeySwitchingKey`] with explicit `c1` polynomials.
    ///
    /// This is the on-chain URS path: the caller provides `c1` directly
    /// (as `NttShoup` polynomials) rather than a seed. No seed is stored;
    /// deserialization will embed the `c1` bytes inline.
    pub fn new_with_c1<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly<PowerBasis>,
        c1: Vec<Poly<NttShoup>>,
        ciphertext_level: usize,
        ksk_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        if ciphertext_level < ksk_level {
            return Err(crate::EvaluationKeyError::InvalidLevelOrder {
                ciphertext_level,
                key_level: ksk_level,
            }
            .into());
        }

        let params = sk.params.clone();
        let ctx_ksk = params.context_at_level(ksk_level)?.clone();
        let ctx_ciphertext = params.context_at_level(ciphertext_level)?.clone();

        if from.ctx() != &ctx_ksk {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::KeySwitchingKey,
            });
        }

        // Validate every supplied c1 polynomial uses ctx_ksk
        for c1i in &c1 {
            if c1i.ctx().as_ref() != ctx_ksk.as_ref() {
                return Err(Error::ParameterMismatch {
                    left: crate::ParameterSource::Polynomial,
                    right: crate::ParameterSource::KeySwitchingKey,
                });
            }
        }

        if ctx_ksk.moduli().len() == 1 {
            let modulus = ctx_ksk
                .moduli()
                .first()
                .ok_or(fhe_math::Error::EmptyModuli)?;
            let log_modulus = modulus.next_power_of_two().ilog2() as usize;
            let log_base = log_modulus / 2;
            let expected_len = log_modulus.div_ceil(log_base);
            if c1.len() != expected_len {
                return Err(crate::EvaluationKeyError::InvalidDecompositionLength {
                    actual: c1.len(),
                    expected: expected_len,
                }
                .into());
            }
            let c0 = Self::generate_c0_decomposition(sk, from, &c1, rng, log_base)?;
            Ok(Self {
                params,
                seed: None,
                c0: c0.into_boxed_slice(),
                c1: c1.into_boxed_slice(),
                ciphertext_level,
                ctx_ciphertext,
                ksk_level,
                ctx_ksk,
                log_base,
            })
        } else {
            let expected_len = ctx_ciphertext.moduli().len();
            if c1.len() != expected_len {
                return Err(crate::EvaluationKeyError::InvalidDecompositionLength {
                    actual: c1.len(),
                    expected: expected_len,
                }
                .into());
            }
            let c0 = Self::generate_c0(sk, from, &c1, rng)?;
            Ok(Self {
                params,
                seed: None,
                c0: c0.into_boxed_slice(),
                c1: c1.into_boxed_slice(),
                ciphertext_level,
                ctx_ciphertext,
                ksk_level,
                ctx_ksk,
                log_base: 0,
            })
        }
    }

    /// Like [`new_with_c1`](Self::new_with_c1) but also returns the per-row error
    /// polynomials sampled during `c0` generation.
    ///
    /// Each `errors[i]` is the small error `eᵢ` such that
    /// `c0[i] = eᵢ − c1[i]·sk + gᵢ·from` (paper notation: `d0ᵢ = eᵢ − sk·d1ᵢ + gᵢ·r`).  The errors are returned in
    /// `NttShoup` form for consistency with `c0`.  They are needed by ZK
    /// witness-generation routines that must prove knowledge of the noise.
    pub fn new_with_c1_extended<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly<PowerBasis>,
        c1: Vec<Poly<NttShoup>>,
        ciphertext_level: usize,
        ksk_level: usize,
        rng: &mut R,
    ) -> Result<(Self, Vec<Poly<NttShoup>>)> {
        if ciphertext_level < ksk_level {
            return Err(crate::EvaluationKeyError::InvalidLevelOrder {
                ciphertext_level,
                key_level: ksk_level,
            }
            .into());
        }

        let params = sk.params.clone();
        let ctx_ksk = params.context_at_level(ksk_level)?.clone();
        let ctx_ciphertext = params.context_at_level(ciphertext_level)?.clone();

        if from.ctx() != &ctx_ksk {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::KeySwitchingKey,
            });
        }

        for c1i in &c1 {
            if c1i.ctx().as_ref() != ctx_ksk.as_ref() {
                return Err(Error::ParameterMismatch {
                    left: crate::ParameterSource::Polynomial,
                    right: crate::ParameterSource::KeySwitchingKey,
                });
            }
        }

        if ctx_ksk.moduli().len() == 1 {
            let modulus = ctx_ksk
                .moduli()
                .first()
                .ok_or(fhe_math::Error::EmptyModuli)?;
            let log_modulus = modulus.next_power_of_two().ilog2() as usize;
            let log_base = log_modulus / 2;
            let expected_len = log_modulus.div_ceil(log_base);
            if c1.len() != expected_len {
                return Err(crate::EvaluationKeyError::InvalidDecompositionLength {
                    actual: c1.len(),
                    expected: expected_len,
                }
                .into());
            }
            let (c0, errors) =
                Self::generate_c0_decomposition_with_errors(sk, from, &c1, rng, log_base)?;
            Ok((
                Self {
                    params,
                    seed: None,
                    c0: c0.into_boxed_slice(),
                    c1: c1.into_boxed_slice(),
                    ciphertext_level,
                    ctx_ciphertext,
                    ksk_level,
                    ctx_ksk,
                    log_base,
                },
                errors,
            ))
        } else {
            let expected_len = ctx_ciphertext.moduli().len();
            if c1.len() != expected_len {
                return Err(crate::EvaluationKeyError::InvalidDecompositionLength {
                    actual: c1.len(),
                    expected: expected_len,
                }
                .into());
            }
            let (c0, errors) = Self::generate_c0_with_errors(sk, from, &c1, rng)?;
            Ok((
                Self {
                    params,
                    seed: None,
                    c0: c0.into_boxed_slice(),
                    c1: c1.into_boxed_slice(),
                    ciphertext_level,
                    ctx_ciphertext,
                    ksk_level,
                    ctx_ksk,
                    log_base: 0,
                },
                errors,
            ))
        }
    }

    /// Deterministically generate `c1` polynomials from a seed and context.
    ///
    /// This is the reusable helper for sharing `d1`/`a` material across
    /// distributed key-generation participants without exposing the full KSK
    /// generation. The context defines the polynomial domain; `size` determines
    /// how many `NttShoup` polynomials are produced.
    pub(crate) fn c1_from_seed(
        ctx: &Arc<Context>,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        size: usize,
    ) -> Vec<Poly<NttShoup>> {
        Self::generate_c1(ctx, seed, size)
    }

    /// Generate the c1's from the seed. The context is used to define the
    /// number of RNS moduli that the polynomials are represented by. When key
    /// switching, there is a multiplication between the decomposed polynomial
    /// for each RNS modulus up to 'size' and the c1's which occurs between
    /// polynomials. These polynomials should be of the same context even
    /// though the decomposition 'size' may be different.
    fn generate_c1(
        ctx: &Arc<Context>,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        size: usize,
    ) -> Vec<Poly<NttShoup>> {
        let mut c1 = Vec::with_capacity(size);
        let mut rng = ChaCha8Rng::from_seed(seed);
        let variable_time = fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
        (0..size).for_each(|_| {
            let mut seed_i = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut seed_i);
            let mut a = Poly::<NttShoup>::random_from_seed(ctx, seed_i);
            a.allow_variable_time_computations(variable_time);
            c1.push(a);
        });
        c1
    }

    /// Generate the c0 component of the key switching key (KSK) using the
    /// Brakerski-Vaikuntanathan key switching through decomposition
    /// technique adapted to RNS as described in the HPS optimization paper (https://eprint.iacr.org/2018/117).
    fn generate_c0<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly<PowerBasis>,
        c1: &[Poly<NttShoup>],
        rng: &mut R,
    ) -> Result<Vec<Poly<NttShoup>>> {
        let ctx0 = c1
            .first()
            .ok_or(crate::EvaluationKeyError::EmptyKeySwitchingComponents)?
            .ctx();
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx0, false)?.into_ntt(),
        );

        let moduli_slice = sk.params.moduli.get(..c1.len()).ok_or(
            crate::EvaluationKeyError::InvalidDecompositionLength {
                actual: c1.len(),
                expected: sk.params.moduli.len(),
            },
        )?;
        let rns = RnsContext::new(moduli_slice)?;

        let c0 = c1
            .iter()
            .enumerate()
            .map(|(i, c1i)| {
                let mut a_s = Zeroizing::new(c1i.clone().into_ntt());
                a_s.disallow_variable_time_computations();
                *a_s.as_mut() *= s.as_ref();
                let ctx = a_s.ctx().clone();
                let a_s_inner = std::mem::replace(a_s.as_mut(), Poly::<Ntt>::zero(&ctx));
                let a_s_pb = Zeroizing::new(a_s_inner.into_power_basis());

                let mut b = Poly::<PowerBasis>::small(a_s_pb.ctx(), sk.params.variance, rng)?;
                b -= a_s_pb.as_ref();

                let gi = rns
                    .get_garner(i)
                    .ok_or(crate::EvaluationKeyError::MissingGarnerCoefficient { index: i })?;
                let g_i_from = Zeroizing::new(gi * from);

                b += &g_i_from;

                // It is now safe to enable variable time computations.
                b.allow_variable_time_computations(fhe_traits::VariableTime::new(
                    fhe_traits::PublicData::assert_public(),
                ));
                Ok(b.into_ntt_shoup())
            })
            .collect::<Result<Vec<Poly<NttShoup>>>>()?;

        Ok(c0)
    }

    /// Generate the c0's from the c1's, the secret key, and the 'from' secret
    /// key polynomial.
    fn generate_c0_decomposition<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly<PowerBasis>,
        c1: &[Poly<NttShoup>],
        rng: &mut R,
        log_base: usize,
    ) -> Result<Vec<Poly<NttShoup>>> {
        let ctx0 = c1
            .first()
            .ok_or(crate::EvaluationKeyError::EmptyKeySwitchingComponents)?
            .ctx();
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx0, false)?.into_ntt(),
        );

        let c0 = c1
            .iter()
            .enumerate()
            .map(|(i, c1i)| {
                let mut a_s = Zeroizing::new(c1i.clone().into_ntt());
                a_s.disallow_variable_time_computations();
                *a_s.as_mut() *= s.as_ref();
                let ctx = a_s.ctx().clone();
                let a_s_inner = std::mem::replace(a_s.as_mut(), Poly::<Ntt>::zero(&ctx));
                let a_s_pb = Zeroizing::new(a_s_inner.into_power_basis());

                let mut b = Poly::<PowerBasis>::small(a_s_pb.ctx(), sk.params.variance, rng)?;
                b -= a_s_pb.as_ref();

                let power = BigUint::from(1u64 << (i * log_base));
                let from_power = Zeroizing::new(from * &power);
                b += from_power.as_ref();

                // It is now safe to enable variable time computations.
                b.allow_variable_time_computations(fhe_traits::VariableTime::new(
                    fhe_traits::PublicData::assert_public(),
                ));
                Ok(b.into_ntt_shoup())
            })
            .collect::<Result<Vec<Poly<NttShoup>>>>()?;

        Ok(c0)
    }

    /// Like [`generate_c0`](Self::generate_c0) but also returns the per-row
    /// error polynomials `eᵢ` captured before they are folded into `c0`.
    #[allow(clippy::type_complexity)]
    fn generate_c0_with_errors<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly<PowerBasis>,
        c1: &[Poly<NttShoup>],
        rng: &mut R,
    ) -> Result<(Vec<Poly<NttShoup>>, Vec<Poly<NttShoup>>)> {
        let ctx0 = c1
            .first()
            .ok_or(crate::EvaluationKeyError::EmptyKeySwitchingComponents)?
            .ctx();
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx0, false)?.into_ntt(),
        );

        let moduli_slice = sk.params.moduli.get(..c1.len()).ok_or(
            crate::EvaluationKeyError::InvalidDecompositionLength {
                actual: c1.len(),
                expected: sk.params.moduli.len(),
            },
        )?;
        let rns = RnsContext::new(moduli_slice)?;

        let pairs: Vec<(Poly<NttShoup>, Poly<NttShoup>)> = c1
            .iter()
            .enumerate()
            .map(|(i, c1i)| {
                let mut a_s = Zeroizing::new(c1i.clone().into_ntt());
                a_s.disallow_variable_time_computations();
                *a_s.as_mut() *= s.as_ref();
                let ctx = a_s.ctx().clone();
                let a_s_inner = std::mem::replace(a_s.as_mut(), Poly::<Ntt>::zero(&ctx));
                let a_s_pb = Zeroizing::new(a_s_inner.into_power_basis());

                let mut b = Poly::<PowerBasis>::small(a_s_pb.ctx(), sk.params.variance, rng)?;

                let mut error_i = b.clone();
                error_i.allow_variable_time_computations(fhe_traits::VariableTime::new(
                    fhe_traits::PublicData::assert_public(),
                ));
                let error_ntt = error_i.into_ntt_shoup();

                b -= a_s_pb.as_ref();

                let gi = rns
                    .get_garner(i)
                    .ok_or(crate::EvaluationKeyError::MissingGarnerCoefficient { index: i })?;
                let g_i_from = Zeroizing::new(gi * from);
                b += &g_i_from;

                b.allow_variable_time_computations(fhe_traits::VariableTime::new(
                    fhe_traits::PublicData::assert_public(),
                ));
                Ok((b.into_ntt_shoup(), error_ntt))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(pairs.into_iter().unzip())
    }

    /// Like [`generate_c0_decomposition`](Self::generate_c0_decomposition) but
    /// also returns per-row errors.
    #[allow(clippy::type_complexity)]
    fn generate_c0_decomposition_with_errors<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly<PowerBasis>,
        c1: &[Poly<NttShoup>],
        rng: &mut R,
        log_base: usize,
    ) -> Result<(Vec<Poly<NttShoup>>, Vec<Poly<NttShoup>>)> {
        let ctx0 = c1
            .first()
            .ok_or(crate::EvaluationKeyError::EmptyKeySwitchingComponents)?
            .ctx();
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx0, false)?.into_ntt(),
        );

        let pairs: Vec<(Poly<NttShoup>, Poly<NttShoup>)> = c1
            .iter()
            .enumerate()
            .map(|(i, c1i)| {
                let mut a_s = Zeroizing::new(c1i.clone().into_ntt());
                a_s.disallow_variable_time_computations();
                *a_s.as_mut() *= s.as_ref();
                let ctx = a_s.ctx().clone();
                let a_s_inner = std::mem::replace(a_s.as_mut(), Poly::<Ntt>::zero(&ctx));
                let a_s_pb = Zeroizing::new(a_s_inner.into_power_basis());

                let mut b = Poly::<PowerBasis>::small(a_s_pb.ctx(), sk.params.variance, rng)?;

                let mut error_i = b.clone();
                error_i.allow_variable_time_computations(fhe_traits::VariableTime::new(
                    fhe_traits::PublicData::assert_public(),
                ));
                let error_ntt = error_i.into_ntt_shoup();

                b -= a_s_pb.as_ref();

                let power = BigUint::from(1u64 << (i * log_base));
                let from_power = Zeroizing::new(from * &power);
                b += from_power.as_ref();

                b.allow_variable_time_computations(fhe_traits::VariableTime::new(
                    fhe_traits::PublicData::assert_public(),
                ));
                Ok((b.into_ntt_shoup(), error_ntt))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(pairs.into_iter().unzip())
    }

    /// Key switch a polynomial.
    pub fn key_switch(&self, p: &Poly<PowerBasis>) -> Result<(Poly<Ntt>, Poly<Ntt>)> {
        if self.log_base != 0 {
            return self.key_switch_decomposition(p);
        }

        if p.ctx().as_ref() != self.ctx_ciphertext.as_ref() {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::KeySwitchingKey,
            });
        }
        let mut c0 = Poly::<Ntt>::zero(&self.ctx_ksk);
        let mut c1 = Poly::<Ntt>::zero(&self.ctx_ksk);
        self.configure_accumulators(p, &mut c0, &mut c1);
        let p_coefficients = p.coefficients();
        for (c2_i_coefficients, c0_i, c1_i) in
            izip!(p_coefficients.outer_iter(), self.c0.iter(), self.c1.iter())
        {
            let mut c2_i =
                Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                    c2_i_coefficients
                        .as_slice()
                        .ok_or(fhe_math::Error::NonContiguousCoefficients)?,
                    &self.ctx_ksk,
                    fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public()),
                );
            c0 += &(&c2_i * c0_i);

            c2_i *= c1_i;
            c1 += &c2_i;
        }
        Ok((c0, c1))
    }

    /// Key switch a polynomial, writing the result in-place.
    pub fn key_switch_assign(
        &self,
        p: &Poly<PowerBasis>,
        c0: &mut Poly<Ntt>,
        c1: &mut Poly<Ntt>,
    ) -> Result<()> {
        if self.log_base != 0 {
            let (k0, k1) = self.key_switch_decomposition(p)?;
            *c0 = k0;
            *c1 = k1;
            return Ok(());
        }

        if p.ctx().as_ref() != self.ctx_ciphertext.as_ref() {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::KeySwitchingKey,
            });
        }
        if c0.ctx().as_ref() != self.ctx_ksk.as_ref() {
            *c0 = Poly::<Ntt>::zero(&self.ctx_ksk);
        } else {
            c0.zeroize();
        }

        if c1.ctx().as_ref() != self.ctx_ksk.as_ref() {
            *c1 = Poly::<Ntt>::zero(&self.ctx_ksk);
        } else {
            c1.zeroize();
        }
        self.configure_accumulators(p, c0, c1);

        let p_coefficients = p.coefficients();
        for (c2_i_coefficients, c0_i, c1_i) in
            izip!(p_coefficients.outer_iter(), self.c0.iter(), self.c1.iter())
        {
            let mut c2_i =
                Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                    c2_i_coefficients
                        .as_slice()
                        .ok_or(fhe_math::Error::NonContiguousCoefficients)?,
                    &self.ctx_ksk,
                    fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public()),
                );
            *c0 += &(&c2_i * c0_i);
            c2_i *= c1_i;
            *c1 += &c2_i;
        }
        Ok(())
    }

    /// Key switch a polynomial using base decomposition.
    fn key_switch_decomposition(&self, p: &Poly<PowerBasis>) -> Result<(Poly<Ntt>, Poly<Ntt>)> {
        if p.ctx().as_ref() != self.ctx_ciphertext.as_ref() {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::KeySwitchingKey,
            });
        }

        let log_modulus = p
            .ctx()
            .moduli()
            .first()
            .ok_or(fhe_math::Error::EmptyModuli)?
            .next_power_of_two()
            .ilog2() as usize;

        let mut coefficients = p
            .coefficients()
            .to_slice()
            .ok_or(fhe_math::Error::NonContiguousCoefficients)?
            .to_vec();
        let mut c2i = vec![];
        let mask = (1u64 << self.log_base) - 1;
        (0..log_modulus.div_ceil(self.log_base)).for_each(|_| {
            c2i.push(coefficients.iter().map(|c| c & mask).collect_vec());
            coefficients.iter_mut().for_each(|c| *c >>= self.log_base);
        });

        let mut c0 = Poly::<Ntt>::zero(&self.ctx_ksk);
        let mut c1 = Poly::<Ntt>::zero(&self.ctx_ksk);
        self.configure_accumulators(p, &mut c0, &mut c1);
        for (c2_i_coefficients, c0_i, c1_i) in izip!(c2i.iter(), self.c0.iter(), self.c1.iter()) {
            let mut c2_i =
                Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                    c2_i_coefficients.as_slice(),
                    &self.ctx_ksk,
                    fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public()),
                );
            c0 += &(&c2_i * c0_i);
            c2_i *= c1_i;
            c1 += &c2_i;
        }
        Ok((c0, c1))
    }
}

impl From<&KeySwitchingKey> for KeySwitchingKeyProto {
    fn from(value: &KeySwitchingKey) -> Self {
        let mut ksk = KeySwitchingKeyProto::default();
        if let Some(seed) = value.seed.as_ref() {
            ksk.seed = seed.to_vec();
        } else {
            ksk.c1.reserve_exact(value.c1.len());
            for c1 in value.c1.iter() {
                ksk.c1.push(c1.to_bytes())
            }
        }
        ksk.c0.reserve_exact(value.c0.len());
        for c0 in value.c0.iter() {
            ksk.c0.push(c0.to_bytes())
        }
        ksk.ciphertext_level = value.ciphertext_level as u32;
        ksk.ksk_level = value.ksk_level as u32;
        ksk.log_base = value.log_base as u32;
        ksk
    }
}

impl BfvTryConvertFrom<&KeySwitchingKeyProto> for KeySwitchingKey {
    fn try_convert_from(value: &KeySwitchingKeyProto, params: &Arc<BfvParameters>) -> Result<Self> {
        let ciphertext_level = value.ciphertext_level as usize;
        let ksk_level = value.ksk_level as usize;
        let ctx_ksk = params.context_at_level(ksk_level)?.clone();
        let ctx_ciphertext = params.context_at_level(ciphertext_level)?.clone();

        let c0_size: usize;
        let log_base = value.log_base as usize;
        if log_base != 0 {
            if ksk_level != params.max_level() || ciphertext_level != params.max_level() {
                return Err(Error::SerializationError(
                    SerializationError::InvalidKeySwitchingDecompositionLevels {
                        ciphertext_level,
                        key_level: ksk_level,
                        expected: params.max_level(),
                    },
                ));
            } else {
                let log_modulus: usize =
                    params.moduli().first().unwrap().next_power_of_two().ilog2() as usize;
                c0_size = log_modulus.div_ceil(log_base);
            }
        } else {
            c0_size = ctx_ciphertext.moduli().len();
        }
        if value.c0.len() != c0_size {
            return Err(Error::SerializationError(
                SerializationError::WrongPolynomialCount {
                    component: crate::SerializedPolynomialComponent::KeySwitchingKeyC0,
                    expected: c0_size,
                    actual: value.c0.len(),
                },
            ));
        }

        let seed = if value.seed.is_empty() {
            if value.c1.len() != c0_size {
                return Err(Error::SerializationError(
                    SerializationError::WrongPolynomialCount {
                        component: crate::SerializedPolynomialComponent::KeySwitchingKeyC1,
                        expected: c0_size,
                        actual: value.c1.len(),
                    },
                ));
            }
            None
        } else {
            Some(
                <ChaCha8Rng as SeedableRng>::Seed::try_from(value.seed.clone()).map_err(|_| {
                    Error::SerializationError(SerializationError::InvalidKeySwitchingSeedLength {
                        actual: value.seed.len(),
                        expected: std::mem::size_of::<<ChaCha8Rng as SeedableRng>::Seed>(),
                    })
                })?,
            )
        };

        let mut c1 = if let Some(seed) = seed {
            Self::generate_c1(&ctx_ksk, seed, value.c0.len())
        } else {
            value
                .c1
                .iter()
                .map(|c1i| Poly::<NttShoup>::from_bytes(c1i, &ctx_ksk).map_err(Error::MathError))
                .collect::<Result<Vec<Poly<NttShoup>>>>()?
        };

        let mut c0 = value
            .c0
            .iter()
            .map(|c0i| Poly::<NttShoup>::from_bytes(c0i, &ctx_ksk).map_err(Error::MathError))
            .collect::<Result<Vec<Poly<NttShoup>>>>()?;

        // Key-switching keys are public cryptographic material. Grant timing
        // permission at this trusted type boundary; the polynomial wire flag
        // itself remains ignored.
        let variable_time = fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
        c0.iter_mut()
            .chain(c1.iter_mut())
            .for_each(|poly| poly.allow_variable_time_computations(variable_time));

        Ok(Self {
            params: params.clone(),
            seed,
            c0: c0.into_boxed_slice(),
            c1: c1.into_boxed_slice(),
            ciphertext_level,
            ctx_ciphertext,
            ksk_level,
            ctx_ksk,
            log_base: value.log_base as usize,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use crate::bfv::{
        BfvParameters, SecretKey, keys::key_switching_key::KeySwitchingKey, traits::TryConvertFrom,
    };
    use crate::proto::bfv::KeySwitchingKey as KeySwitchingKeyProto;
    use fhe_math::{
        rns::RnsContext,
        rq::{Ntt, NttShoup, Poly, PowerBasis, traits::TryConvertFrom as TryConvertFromPoly},
    };
    use num_bigint::BigUint;
    use rand::rng;
    use std::error::Error;

    #[test]
    fn constructor() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(6, 16),
            BfvParameters::default_arc(3, 16),
        ] {
            let sk = SecretKey::random(&params, &mut rng);
            let ctx = params.context_at_level(0)?;
            let p = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
            let ksk = KeySwitchingKey::new(&sk, &p, 0, 0, &mut rng);
            assert!(ksk.is_ok());
        }
        Ok(())
    }

    #[test]
    fn constructor_last_level() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(6, 16),
            BfvParameters::default_arc(3, 16),
        ] {
            let level = params.moduli().len() - 1;
            let sk = SecretKey::random(&params, &mut rng);
            let ctx = params.context_at_level(level)?;
            let p = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
            let ksk = KeySwitchingKey::new(&sk, &p, level, level, &mut rng);
            assert!(ksk.is_ok());
        }
        Ok(())
    }

    #[test]
    fn key_switch() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [BfvParameters::default_arc(6, 16)] {
            for _ in 0..100 {
                let sk = SecretKey::random(&params, &mut rng);
                let ctx = params.context_at_level(0)?;
                let p = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
                let ksk = KeySwitchingKey::new(&sk, &p, 0, 0, &mut rng)?;
                let s = Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx, false)
                    .map_err(crate::Error::MathError)?
                    .into_ntt();

                let input = Poly::<PowerBasis>::random(ctx, &mut rng);
                let (c0, c1) = ksk.key_switch(&input)?;

                let c2 = (&c0 + &(&c1 * &s)).into_power_basis();

                let input_ntt = input.into_ntt();
                let p_ntt = p.into_ntt();
                let c3 = (&input_ntt * &p_ntt).into_power_basis();

                let rns = RnsContext::new(&params.moduli)?;
                Vec::<BigUint>::from(&(&c2 - &c3)).iter().for_each(|b| {
                    assert!(std::cmp::min(b.bits(), (rns.modulus() - b).bits()) <= 70)
                });
            }
        }
        Ok(())
    }

    #[test]
    fn key_switch_assign_matches() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        {
            let params = BfvParameters::default_arc(6, 16);
            let sk = SecretKey::random(&params, &mut rng);
            let ctx = params.context_at_level(0)?;
            let p = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
            let ksk = KeySwitchingKey::new(&sk, &p, 0, 0, &mut rng)?;
            let mut input = Poly::<PowerBasis>::random(ctx, &mut rng);
            input.allow_variable_time_computations(fhe_traits::VariableTime::new(
                fhe_traits::PublicData::assert_public(),
            ));

            let (c0, c1) = ksk.key_switch(&input)?;

            let mut a0 = Poly::<Ntt>::zero(&ksk.ctx_ksk);
            let mut a1 = Poly::<Ntt>::zero(&ksk.ctx_ksk);
            ksk.key_switch_assign(&input, &mut a0, &mut a1)?;

            assert_eq!(c0, a0);
            assert_eq!(c1, a1);
            assert!(c0.allows_variable_time_computations());
            assert!(c1.allows_variable_time_computations());

            input.disallow_variable_time_computations();
            ksk.key_switch_assign(&input, &mut a0, &mut a1)?;
            assert!(!a0.allows_variable_time_computations());
            assert!(!a1.allows_variable_time_computations());
        }
        Ok(())
    }

    #[test]
    fn key_switch_decomposition() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [BfvParameters::default_arc(6, 16)] {
            for _ in 0..100 {
                let sk = SecretKey::random(&params, &mut rng);
                let ctx = params.context_at_level(5)?;
                let p = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
                let ksk = KeySwitchingKey::new(&sk, &p, 5, 5, &mut rng)?;
                let s = Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx, false)
                    .map_err(crate::Error::MathError)?
                    .into_ntt();

                let input = Poly::<PowerBasis>::random(ctx, &mut rng);
                let (c0, c1) = ksk.key_switch(&input)?;

                let c2 = (&c0 + &(&c1 * &s)).into_power_basis();

                let input_ntt = input.into_ntt();
                let p_ntt = p.into_ntt();
                let c3 = (&input_ntt * &p_ntt).into_power_basis();

                let rns = RnsContext::new(ctx.moduli())?;
                Vec::<BigUint>::from(&(&c2 - &c3)).iter().for_each(|b| {
                    assert!(
                        std::cmp::min(b.bits(), (rns.modulus() - b).bits())
                            <= (rns.modulus().bits() / 2) + 10
                    )
                });
            }
        }
        Ok(())
    }

    #[test]
    fn proto_conversion() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(6, 16),
            BfvParameters::default_arc(3, 16),
        ] {
            let sk = SecretKey::random(&params, &mut rng);
            let ctx = params.context_at_level(0)?;
            let p = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
            let ksk = KeySwitchingKey::new(&sk, &p, 0, 0, &mut rng)?;
            let ksk_proto = KeySwitchingKeyProto::from(&ksk);
            let decoded = KeySwitchingKey::try_convert_from(&ksk_proto, &params)?;
            assert_eq!(ksk, decoded);
            assert!(
                decoded
                    .c0
                    .iter()
                    .chain(decoded.c1.iter())
                    .all(Poly::allows_variable_time_computations)
            );
        }
        Ok(())
    }

    #[test]
    fn compare_constructors() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [BfvParameters::default_arc(6, 8)] {
            let sk = SecretKey::random(&params, &mut rng);
            let ctx = params.context_at_level(0)?;
            let p = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;

            let ksk1 = KeySwitchingKey::new(&sk, &p, 0, 0, &mut rng)?;
            let seed = ksk1.seed.expect("Key should have a seed");
            let ksk2 = KeySwitchingKey::new_with_seed(&sk, &p, seed, 0, 0, &mut rng)?;

            assert_eq!(ksk1.c1.len(), ksk2.c1.len());
            for (c1_1, c1_2) in ksk1.c1.iter().zip(ksk2.c1.iter()) {
                assert_eq!(c1_1, c1_2);
            }
        }
        Ok(())
    }

    /// Verify `c0[i] + c1[i]·sk = eᵢ + gᵢ·from` (paper: `d0ᵢ = eᵢ − sk·d1ᵢ + gᵢ·r`).
    #[test]
    fn new_with_c1_extended_witness_equations() -> Result<(), Box<dyn Error>> {
        use fhe_math::rns::RnsContext;
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0)?;
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;

        let c1 = KeySwitchingKey::c1_from_seed(ctx, [42u8; 32], params.moduli().len());
        let (ksk, errors) = KeySwitchingKey::new_with_c1_extended(&sk, &from, c1, 0, 0, &mut rng)?;

        let sk_ntt = Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx, false)
            .map_err(crate::Error::MathError)?
            .into_ntt();
        let rns = RnsContext::new(&params.moduli)?;

        for (i, ((c0_i, c1_i), e_i)) in ksk
            .c0
            .iter()
            .zip(ksk.c1.iter())
            .zip(errors.iter())
            .enumerate()
        {
            let lhs = (&c0_i.clone().into_ntt() + &(&c1_i.clone().into_ntt() * &sk_ntt))
                .into_power_basis();
            let gi = rns.get_garner(i).expect("garner");
            let rhs = (&e_i.clone().into_ntt() + &(gi * &from).into_ntt()).into_power_basis();
            assert_eq!(lhs, rhs, "witness equation failed at row {i}");
        }
        Ok(())
    }

    #[test]
    fn c1_from_seed_matches_seeded_constructor() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let context = params.context_at_level(0)?;
        let from = Poly::<PowerBasis>::small(context, 10, &mut rng)?;
        let seed = [13u8; 32];

        let key = KeySwitchingKey::new_with_seed(&sk, &from, seed, 0, 0, &mut rng)?;
        let explicit = KeySwitchingKey::c1_from_seed(context, seed, params.moduli().len());

        assert_eq!(key.c1.as_ref(), explicit.as_slice());
        Ok(())
    }

    // --- Finding 1: new_with_c1 validation ---

    #[test]
    fn new_with_c1_rejects_wrong_c1_context() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx_ksk = params.context_at_level(0)?;
        let from = Poly::<PowerBasis>::small(ctx_ksk, 10, &mut rng)?;

        // Build a c1 vector with polynomials from a different context
        let other_ctx = params.context_at_level(1)?;
        let c1: Vec<_> = (0..params.moduli().len())
            .map(|_| Poly::<NttShoup>::random_from_seed(other_ctx, [42u8; 32]))
            .collect();

        let result = KeySwitchingKey::new_with_c1(&sk, &from, c1, 0, 0, &mut rng);
        assert!(matches!(
            result,
            Err(crate::Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::KeySwitchingKey,
            })
        ));
        Ok(())
    }

    #[test]
    fn new_with_c1_rejects_ciphertext_level_lt_ksk_level() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);

        // Choose levels where the ciphertext moduli length happens to match
        // the cardinality of the c1 vector we supply, so the length check
        // does not catch it before the explicit level-ordering check.
        let ciphertext_level = 1usize;
        let ksk_level = 2usize;
        let ctx_ciphertext = params.context_at_level(ciphertext_level)?;
        let ctx_ksk = params.context_at_level(ksk_level)?;
        let from = Poly::<PowerBasis>::small(ctx_ksk, 10, &mut rng)?;

        // Generate c1 with the same element count as ctx_ciphertext.moduli().len(),
        // so the length check in new_with_c1 passes.
        let c1 = KeySwitchingKey::c1_from_seed(ctx_ksk, [7u8; 32], ctx_ciphertext.moduli().len());

        // ciphertext_level(1) < ksk_level(2) → must be rejected by level ordering
        let result =
            KeySwitchingKey::new_with_c1(&sk, &from, c1, ciphertext_level, ksk_level, &mut rng);
        assert!(matches!(
            result,
            Err(crate::Error::EvaluationKey(
                crate::EvaluationKeyError::InvalidLevelOrder {
                    ciphertext_level: 1,
                    key_level: 2,
                }
            ))
        ));
        Ok(())
    }

    // --- Finding 2: protobuf log_base validation ---
}
