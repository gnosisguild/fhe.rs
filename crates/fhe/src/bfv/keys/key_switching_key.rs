//! Key-switching keys for the BFV encryption scheme. Implements the
//! Brakerski-Vaikuntanathan key switching through decomposition technique
//! adapted to RNS as described in the HPS optimization paper
//! (<https://eprint.iacr.org/2018/117>)

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

    /// For a single-modulus key-switching context, the logarithm of the
    /// decomposition base (`log_modulus / 2`); zero denotes the standard RNS
    /// decomposition used with a multi-modulus key context. Deserialization
    /// only accepts these constructor-produced values.
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
    ///
    /// The errors are secret-dependent, so each row is handed to the caller
    /// as a wipe-on-drop [`Zeroizing`] owner: ownership is transferred to the
    /// caller, every row keeps variable-time computations disabled (the
    /// error sampling and conversion run in constant time), and dropping a
    /// row — normally, on an early error, or during an unwind — wipes its
    /// coefficients and Shoup tables. The public `c0` rows of the returned
    /// key keep their public time policy.
    ///
    /// # Keeping the witness rows guarded
    ///
    /// Keep every error row inside its [`Zeroizing`] owner. Cloning a row
    /// yields a new guarded copy, but moving the inner polynomial out of a
    /// guard (for example with [`std::mem::replace`]) creates an unguarded
    /// secret copy that Rust will drop without wiping; zeroize any extracted
    /// value before it drops.
    ///
    /// Wiping coverage inside this constructor is likewise not absolute: the
    /// sampler's internal partial buffer (for example when the RNG panics
    /// mid-sample) and the brief move-based conversion intervals are not
    /// guaranteed wiped without `fhe-math` changes.
    pub fn new_with_c1_extended<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly<PowerBasis>,
        c1: Vec<Poly<NttShoup>>,
        ciphertext_level: usize,
        ksk_level: usize,
        rng: &mut R,
    ) -> Result<(Self, Vec<Zeroizing<Poly<NttShoup>>>)> {
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

    /// Attach `seed` to this key after verifying the seed expansion against
    /// the concrete `c1` rows the key carries.
    ///
    /// Seed metadata is compression, not authority: serialization omits the
    /// concrete `c1` rows whenever a seed is present, and deserialization
    /// regenerates them from the seed, so attaching an unverified seed would
    /// silently replace the stored rows across a round-trip. The seed is
    /// stored only when it reproduces every `c1` row; otherwise the first
    /// mismatching row is reported and the key keeps its explicit, seedless
    /// representation.
    pub(crate) fn attach_verified_seed(
        &mut self,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
    ) -> Result<()> {
        let expanded = Self::generate_c1(&self.ctx_ksk, seed, self.c1.len());
        if let Some(index) = expanded
            .iter()
            .zip(self.c1.iter())
            .position(|(expanded, stored)| expanded != stored)
        {
            return Err(Error::DefaultError(format!(
                "Seed metadata does not reproduce key-switching row {index}; refusing to attach an inconsistent seed"
            )));
        }
        self.seed = Some(seed);
        Ok(())
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
    ///
    /// The errors are secret-dependent: each row is placed under a
    /// [`Zeroizing`] guard immediately after sampling, keeps variable-time
    /// computations disabled, and is wiped whenever its guard is dropped.
    /// Wiping coverage is not absolute: the sampler's internal partial
    /// buffer and the brief move-based conversion intervals (clone into a
    /// guard, guard release) are not guaranteed wiped without `fhe-math`
    /// changes.
    #[allow(clippy::type_complexity)]
    fn generate_c0_with_errors<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly<PowerBasis>,
        c1: &[Poly<NttShoup>],
        rng: &mut R,
    ) -> Result<(Vec<Poly<NttShoup>>, Vec<Zeroizing<Poly<NttShoup>>>)> {
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

        let pairs: Vec<(Poly<NttShoup>, Zeroizing<Poly<NttShoup>>)> = c1
            .iter()
            .enumerate()
            .map(|(i, c1i)| {
                let mut a_s = Zeroizing::new(c1i.clone().into_ntt());
                a_s.disallow_variable_time_computations();
                *a_s.as_mut() *= s.as_ref();
                let ctx = a_s.ctx().clone();
                let a_s_inner = std::mem::replace(a_s.as_mut(), Poly::<Ntt>::zero(&ctx));
                let a_s_pb = Zeroizing::new(a_s_inner.into_power_basis());

                // The freshly sampled error is secret: guard it before any
                // fallible operation, so an early error or unwind cannot drop
                // it un-wiped.
                let mut b = Zeroizing::new(Poly::<PowerBasis>::small(
                    a_s_pb.ctx(),
                    sk.params.variance,
                    rng,
                )?);

                // Capture the error row before it is folded into `c0`. The
                // clone lives under its own `Zeroizing` guard, and the row
                // keeps its variable-time flag false; dropping a guard —
                // normally, on an early error, or during an unwind — wipes
                // the row.
                let mut error_i = Zeroizing::new(b.as_ref().clone());
                let error_ctx = error_i.ctx().clone();
                let error_ntt = Zeroizing::new(
                    std::mem::replace(error_i.as_mut(), Poly::<PowerBasis>::zero(&error_ctx))
                        .into_ntt_shoup(),
                );

                *b.as_mut() -= a_s_pb.as_ref();

                let gi = rns
                    .get_garner(i)
                    .ok_or(crate::EvaluationKeyError::MissingGarnerCoefficient { index: i })?;
                let g_i_from = Zeroizing::new(gi * from);
                *b.as_mut() += g_i_from.as_ref();

                // The row is now the public `c0` component: mark it public
                // and only then release it from its guard.
                b.allow_variable_time_computations(fhe_traits::VariableTime::new(
                    fhe_traits::PublicData::assert_public(),
                ));
                let b_ctx = b.ctx().clone();
                let b_inner = std::mem::replace(b.as_mut(), Poly::<PowerBasis>::zero(&b_ctx));
                Ok((b_inner.into_ntt_shoup(), error_ntt))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(pairs.into_iter().unzip())
    }

    /// Like [`generate_c0_decomposition`](Self::generate_c0_decomposition) but
    /// also returns per-row errors.
    ///
    /// The errors are secret-dependent: each row is placed under a
    /// [`Zeroizing`] guard immediately after sampling, keeps variable-time
    /// computations disabled, and is wiped whenever its guard is dropped.
    /// Wiping coverage is not absolute: the sampler's internal partial
    /// buffer and the brief move-based conversion intervals (clone into a
    /// guard, guard release) are not guaranteed wiped without `fhe-math`
    /// changes.
    #[allow(clippy::type_complexity)]
    fn generate_c0_decomposition_with_errors<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly<PowerBasis>,
        c1: &[Poly<NttShoup>],
        rng: &mut R,
        log_base: usize,
    ) -> Result<(Vec<Poly<NttShoup>>, Vec<Zeroizing<Poly<NttShoup>>>)> {
        let ctx0 = c1
            .first()
            .ok_or(crate::EvaluationKeyError::EmptyKeySwitchingComponents)?
            .ctx();
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx0, false)?.into_ntt(),
        );

        let pairs: Vec<(Poly<NttShoup>, Zeroizing<Poly<NttShoup>>)> = c1
            .iter()
            .enumerate()
            .map(|(i, c1i)| {
                let mut a_s = Zeroizing::new(c1i.clone().into_ntt());
                a_s.disallow_variable_time_computations();
                *a_s.as_mut() *= s.as_ref();
                let ctx = a_s.ctx().clone();
                let a_s_inner = std::mem::replace(a_s.as_mut(), Poly::<Ntt>::zero(&ctx));
                let a_s_pb = Zeroizing::new(a_s_inner.into_power_basis());

                // The freshly sampled error is secret: guard it before any
                // fallible operation, so an early error or unwind cannot drop
                // it un-wiped.
                let mut b = Zeroizing::new(Poly::<PowerBasis>::small(
                    a_s_pb.ctx(),
                    sk.params.variance,
                    rng,
                )?);

                // Capture the error row before it is folded into `c0`. The
                // clone lives under its own `Zeroizing` guard, and the row
                // keeps its variable-time flag false; dropping a guard —
                // normally, on an early error, or during an unwind — wipes
                // the row.
                let mut error_i = Zeroizing::new(b.as_ref().clone());
                let error_ctx = error_i.ctx().clone();
                let error_ntt = Zeroizing::new(
                    std::mem::replace(error_i.as_mut(), Poly::<PowerBasis>::zero(&error_ctx))
                        .into_ntt_shoup(),
                );

                *b.as_mut() -= a_s_pb.as_ref();

                let power = BigUint::from(1u64 << (i * log_base));
                let from_power = Zeroizing::new(from * &power);
                *b.as_mut() += from_power.as_ref();

                // The row is now the public `c0` component: mark it public
                // and only then release it from its guard.
                b.allow_variable_time_computations(fhe_traits::VariableTime::new(
                    fhe_traits::PublicData::assert_public(),
                ));
                let b_ctx = b.ctx().clone();
                let b_inner = std::mem::replace(b.as_mut(), Poly::<PowerBasis>::zero(&b_ctx));
                Ok((b_inner.into_ntt_shoup(), error_ntt))
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

/// Parameter-implied shape of a serialized key-switching key.
pub(crate) struct KeySwitchingKeyWireShape {
    /// Number of `c0` rows (and of `c1` rows when no seed is present) that
    /// the constructors produce for the declared levels and decomposition
    /// base.
    pub(crate) row_count: usize,
    /// Exact length in bytes of the packed coefficient payload of one row at
    /// the key-switching key context.
    pub(crate) row_bytes: usize,
}

/// The decomposition base the [`KeySwitchingKey`] constructors produce for a
/// key-switching key context: the standard RNS decomposition (base 0)
/// over a multi-modulus context, or the base-2^(log_modulus/2) decomposition
/// over a single-modulus one.
///
/// This lets request-based decoding derive the expected wire shape locally,
/// from validated parameters and levels, instead of trusting the base
/// declared on the wire.
pub(crate) fn constructor_log_base(moduli: &[u64]) -> Result<usize> {
    if moduli.len() != 1 {
        return Ok(0);
    }
    let qi = moduli.first().ok_or(fhe_math::Error::EmptyModuli)?;
    Ok(qi.next_power_of_two().ilog2() as usize / 2)
}

/// Compute the shape the [`KeySwitchingKey`] constructors produce for a
/// serialized key-switching key with the declared levels and decomposition
/// base.
///
/// This is the single source of truth shared by
/// [`KeySwitchingKey::try_convert_from`] (post-decode validation) and the
/// evaluation-key wire preflight, so both reject the same malformed shapes
/// with the same typed errors, in the same precedence order.
pub(crate) fn expected_wire_shape(
    params: &Arc<BfvParameters>,
    ciphertext_level: usize,
    ksk_level: usize,
    log_base: usize,
) -> Result<KeySwitchingKeyWireShape> {
    // The constructors reject an inverted level ordering before any key
    // material is produced, so the decoder must reject it too instead of
    // deferring the failure to `key_switch`.
    if ciphertext_level < ksk_level {
        return Err(Error::SerializationError(
            SerializationError::InvalidKeySwitchingLevelOrder {
                ciphertext_level,
                key_level: ksk_level,
            },
        ));
    }

    let ctx_ksk = params.context_at_level(ksk_level)?;
    let ctx_ciphertext = params.context_at_level(ciphertext_level)?;

    // The decomposition base must match what the constructors produce for
    // this key context: the standard RNS decomposition (`log_base = 0`) over
    // a multi-modulus key context, or the base-2^(log_modulus/2)
    // decomposition over a single-modulus key context (which the
    // constructors only produce at the maximal ciphertext and key levels).
    let single_modulus_key_context = ctx_ksk.moduli().len() == 1;
    let expected_log_base = constructor_log_base(ctx_ksk.moduli())?;
    if log_base != expected_log_base || (single_modulus_key_context && log_base == 0) {
        return Err(Error::SerializationError(
            SerializationError::InvalidKeySwitchingLogBase {
                log_base,
                expected_log_base,
            },
        ));
    }

    let row_count = if log_base == 0 {
        ctx_ciphertext.moduli().len()
    } else {
        if ksk_level != params.max_level() || ciphertext_level != params.max_level() {
            return Err(Error::SerializationError(
                SerializationError::InvalidKeySwitchingDecompositionLevels {
                    ciphertext_level,
                    key_level: ksk_level,
                    expected: params.max_level(),
                },
            ));
        }
        let log_modulus: usize = ctx_ksk
            .moduli()
            .first()
            .ok_or(fhe_math::Error::EmptyModuli)?
            .next_power_of_two()
            .ilog2() as usize;
        log_modulus.div_ceil(log_base)
    };

    // Checked so a derived resource bound can never wrap: the encoded row
    // size this function reports feeds the request-based decoder's byte
    // bound (see `EvaluationKeyDecodeRequest::wire_bound`).
    let mut row_bytes: usize = 0;
    for &qi in ctx_ksk.moduli() {
        let length = fhe_math::zq::Modulus::new(qi)?
            .checked_serialization_length(params.degree())
            .ok_or(SerializationError::WireBoundOverflow)?;
        row_bytes = row_bytes
            .checked_add(length)
            .ok_or(SerializationError::WireBoundOverflow)?;
    }

    Ok(KeySwitchingKeyWireShape {
        row_count,
        row_bytes,
    })
}

impl BfvTryConvertFrom<&KeySwitchingKeyProto> for KeySwitchingKey {
    fn try_convert_from(value: &KeySwitchingKeyProto, params: &Arc<BfvParameters>) -> Result<Self> {
        let ciphertext_level = value.ciphertext_level as usize;
        let ksk_level = value.ksk_level as usize;

        // The decomposition base and the row count must match what the
        // constructors produce for this key context; the shared helper applies
        // the same checks, in the same order, as the wire preflight.
        let shape =
            expected_wire_shape(params, ciphertext_level, ksk_level, value.log_base as usize)?;

        let ctx_ksk = params.context_at_level(ksk_level)?.clone();
        let ctx_ciphertext = params.context_at_level(ciphertext_level)?.clone();

        if value.c0.len() != shape.row_count {
            return Err(Error::SerializationError(
                SerializationError::WrongPolynomialCount {
                    component: crate::SerializedPolynomialComponent::KeySwitchingKeyC0,
                    expected: shape.row_count,
                    actual: value.c0.len(),
                },
            ));
        }

        if !value.seed.is_empty() && !value.c1.is_empty() {
            return Err(Error::SerializationError(
                SerializationError::InvalidFormat {
                    reason:
                        "Key-switching key cannot contain both a seed and explicit c1 polynomials"
                            .to_string(),
                },
            ));
        }

        let seed = if value.seed.is_empty() {
            if value.c1.len() != shape.row_count {
                return Err(Error::SerializationError(
                    SerializationError::WrongPolynomialCount {
                        component: crate::SerializedPolynomialComponent::KeySwitchingKeyC1,
                        expected: shape.row_count,
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
    use fhe_traits::Serialize;
    use num_bigint::BigUint;
    use rand::{CryptoRng, RngCore, rng};
    use std::error::Error;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use zeroize::{Zeroize, Zeroizing};

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
                Vec::<BigUint>::try_from(&(&c2 - &c3))?
                    .iter()
                    .for_each(|b| {
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
                Vec::<BigUint>::try_from(&(&c2 - &c3))?
                    .iter()
                    .for_each(|b| {
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
    fn proto_conversion_rejects_seed_with_explicit_c1() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0)?;
        let p = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
        let ksk = KeySwitchingKey::new(&sk, &p, 0, 0, &mut rng)?;
        let mut proto = KeySwitchingKeyProto::from(&ksk);

        proto.c1.push(ksk.c1[0].to_bytes());

        assert!(KeySwitchingKey::try_convert_from(&proto, &params).is_err());
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

    /// `attach_verified_seed` must reject a master seed that does not expand
    /// to the stored `c1` rows: the mismatch is an error, the key stays
    /// seedless, and the rows are untouched. The seed the rows were derived
    /// from attaches and changes no rows.
    #[test]
    fn attach_verified_seed_rejects_mismatched_seed() -> Result<(), Box<dyn Error>> {
        use rand::SeedableRng;
        use rand_chacha::ChaCha8Rng;

        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0)?;
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;

        // Seedless key carrying explicit rows derived from `urs_seed`.
        let urs_seed: <ChaCha8Rng as SeedableRng>::Seed = [42u8; 32];
        let c1 = KeySwitchingKey::c1_from_seed(ctx, urs_seed, params.moduli().len());
        let mut ksk = KeySwitchingKey::new_with_c1(&sk, &from, c1, 0, 0, &mut rng)?;
        assert!(ksk.seed.is_none());
        let rows_before = ksk.c1.to_vec();

        // A different master seed does not expand to the stored rows.
        let wrong_seed: <ChaCha8Rng as SeedableRng>::Seed = [43u8; 32];
        assert!(matches!(
            ksk.attach_verified_seed(wrong_seed),
            Err(crate::Error::DefaultError(_))
        ));
        assert!(ksk.seed.is_none(), "a rejected seed must not be stored");
        assert_eq!(ksk.c1.as_ref(), rows_before.as_slice());

        // Control: the master seed the rows were derived from attaches.
        ksk.attach_verified_seed(urs_seed)?;
        assert_eq!(ksk.seed, Some(urs_seed));
        assert_eq!(ksk.c1.as_ref(), rows_before.as_slice());
        Ok(())
    }

    /// Verify `c0[i] + c1[i]·sk = eᵢ + gᵢ·from` (paper: `d0ᵢ = eᵢ − sk·d1ᵢ + gᵢ·r`)
    /// on the multi-modulus path, with the exported errors guarded and secret.
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

        // The exported error rows are wipe-on-drop owners.
        let errors: &Vec<Zeroizing<Poly<NttShoup>>> = &errors;
        assert_eq!(errors.len(), ksk.c0.len());

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
            let rhs =
                (&e_i.as_ref().clone().into_ntt() + &(gi * &from).into_ntt()).into_power_basis();
            assert_eq!(lhs, rhs, "witness equation failed at row {i}");
        }
        Ok(())
    }

    /// Same witness equations on the single-modulus decomposition path:
    /// `c0[i] + c1[i]·sk = eᵢ + from·2^(i·log_base)`, with the exported
    /// errors guarded and secret.
    #[test]
    fn new_with_c1_extended_witness_equations_decomposition() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0)?;
        assert_eq!(ctx.moduli().len(), 1);
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;

        let modulus = ctx.moduli().first().expect("single modulus");
        let log_modulus = modulus.next_power_of_two().ilog2() as usize;
        let log_base = log_modulus / 2;
        let expected_len = log_modulus.div_ceil(log_base);

        let c1 = KeySwitchingKey::c1_from_seed(ctx, [42u8; 32], expected_len);
        let (ksk, errors) = KeySwitchingKey::new_with_c1_extended(&sk, &from, c1, 0, 0, &mut rng)?;

        // The exported error rows are wipe-on-drop owners.
        let errors: &Vec<Zeroizing<Poly<NttShoup>>> = &errors;
        assert_eq!(errors.len(), expected_len);

        let sk_ntt = Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx, false)
            .map_err(crate::Error::MathError)?
            .into_ntt();

        for (i, ((c0_i, c1_i), e_i)) in ksk
            .c0
            .iter()
            .zip(ksk.c1.iter())
            .zip(errors.iter())
            .enumerate()
        {
            let lhs = (&c0_i.clone().into_ntt() + &(&c1_i.clone().into_ntt() * &sk_ntt))
                .into_power_basis();
            let power = BigUint::from(1u64 << (i * log_base));
            let rhs = (&e_i.as_ref().clone().into_ntt() + &(&from * &power).into_ntt())
                .into_power_basis();
            assert_eq!(lhs, rhs, "witness equation failed at row {i}");
        }
        Ok(())
    }

    /// Witness error rows must stay secret in time policy (no variable-time
    /// computations) on both error-generation branches, while the public key
    /// components keep their public marking.
    #[test]
    fn extended_witness_errors_stay_secret_and_public_components_public()
    -> Result<(), Box<dyn Error>> {
        let mut rng = rng();

        // Multi-modulus path (generate_c0_with_errors).
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0)?;
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
        let c1 = KeySwitchingKey::c1_from_seed(ctx, [42u8; 32], params.moduli().len());
        let (ksk, errors) = KeySwitchingKey::new_with_c1_extended(&sk, &from, c1, 0, 0, &mut rng)?;
        assert!(
            errors
                .iter()
                .all(|e| !e.allows_variable_time_computations())
        );
        assert!(
            ksk.c0
                .iter()
                .chain(ksk.c1.iter())
                .all(Poly::allows_variable_time_computations)
        );

        // Single-modulus decomposition path
        // (generate_c0_decomposition_with_errors).
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0)?;
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
        let modulus = ctx.moduli().first().expect("single modulus");
        let log_modulus = modulus.next_power_of_two().ilog2() as usize;
        let expected_len = log_modulus.div_ceil(log_modulus / 2);
        let c1 = KeySwitchingKey::c1_from_seed(ctx, [42u8; 32], expected_len);
        let (ksk, errors) = KeySwitchingKey::new_with_c1_extended(&sk, &from, c1, 0, 0, &mut rng)?;
        assert!(
            errors
                .iter()
                .all(|e| !e.allows_variable_time_computations())
        );
        assert!(
            ksk.c0
                .iter()
                .chain(ksk.c1.iter())
                .all(Poly::allows_variable_time_computations)
        );
        Ok(())
    }

    /// `Poly::zeroize` — the implementation `Zeroizing` invokes on drop —
    /// must erase the coefficient table (the Shoup table is erased by the
    /// same element-wise pass inside `fhe-math`). This checks the zeroize
    /// implementation on a live value; the drop-time behavior of the guard
    /// itself is observed by [`zeroizing_drops_zeroize_the_guarded_value`],
    /// and the guarded error-row types make reading freed memory impossible.
    #[test]
    fn poly_zeroize_erases_coefficients() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let ctx = params.context_at_level(0)?;

        let mut poly = Poly::<NttShoup>::random(ctx, &mut rng);
        assert!(poly.coefficients().iter().any(|&c| c != 0));
        poly.zeroize();
        assert!(poly.coefficients().iter().all(|&c| c == 0));

        // The exported error rows are `Zeroizing` owners holding non-zero
        // rows, so dropping them (normally, on an early error, or during an
        // unwind) runs the zeroization verified above.
        let sk = SecretKey::random(&params, &mut rng);
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
        let c1 = KeySwitchingKey::c1_from_seed(ctx, [42u8; 32], params.moduli().len());
        let (_ksk, errors) = KeySwitchingKey::new_with_c1_extended(&sk, &from, c1, 0, 0, &mut rng)?;
        for e in errors {
            assert!(e.as_ref().coefficients().iter().any(|&c| c != 0));
            drop(e);
        }
        Ok(())
    }

    /// Test-only probe recording that its guard ran `Zeroize::zeroize` on it.
    struct WipeProbe(Arc<AtomicBool>);

    impl Zeroize for WipeProbe {
        fn zeroize(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Drop a guarded probe through an unwind.
    #[expect(clippy::panic, reason = "test-only unwind probe")]
    fn unwind_with_guarded_probe(probe: Zeroizing<WipeProbe>) {
        let _probe = probe;
        panic!("probe unwind");
    }

    /// Safe drop-time observation of the guard mechanism the witness error
    /// rows rely on: `Zeroizing` runs `Zeroize::zeroize` on its contents when
    /// dropped, on both the ordinary and the unwind path. The production rows
    /// cannot be instrumented from outside the constructor, so this probe
    /// substitutes for a direct observation; combined with
    /// [`poly_zeroize_erases_coefficients`] (what `Poly::zeroize` erases) and
    /// the guarded return/field types, it establishes — without reading freed
    /// memory — that dropped error rows are wiped.
    #[test]
    fn zeroizing_drops_zeroize_the_guarded_value() {
        // Ordinary drop.
        let wiped = Arc::new(AtomicBool::new(false));
        let probe = Zeroizing::new(WipeProbe(Arc::clone(&wiped)));
        assert!(!wiped.load(Ordering::SeqCst));
        drop(probe);
        assert!(wiped.load(Ordering::SeqCst));

        // Drop during an unwind.
        let wiped = Arc::new(AtomicBool::new(false));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            unwind_with_guarded_probe(Zeroizing::new(WipeProbe(Arc::clone(&wiped))));
        }));
        assert!(result.is_err());
        assert!(wiped.load(Ordering::SeqCst));
    }

    /// An RNG that succeeds for a fixed number of draws and then panics,
    /// simulating a mid-generation RNG failure after earlier error rows were
    /// already sampled.
    struct PanickingAfterDraws {
        draws: usize,
        fail_after: usize,
    }

    impl RngCore for PanickingAfterDraws {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.draws += 1;
            #[expect(
                clippy::panic,
                reason = "test-only RNG simulating a mid-generation RNG failure"
            )]
            if self.draws > self.fail_after {
                panic!("simulated RNG failure after earlier error rows were sampled");
            }
            u64::from_le_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    impl CryptoRng for PanickingAfterDraws {}

    /// A failing RNG that unwinds mid-generation after row 0 was fully
    /// sampled. This test exercises the unwind path and proves unwind safety;
    /// it cannot directly observe the dropped rows (the rows live inside the
    /// constructor, so their guards cannot be instrumented from here).
    /// Wiping follows indirectly: the rows under construction are
    /// `Vec<Zeroizing<Poly<NttShoup>>>` (pinned at compile time by the return
    /// type), and [`zeroizing_drops_zeroize_the_guarded_value`] shows a
    /// `Zeroizing` guard zeroizes its contents when dropped during an unwind.
    #[test]
    fn extended_ksk_rng_failure_after_sampled_rows_unwinds_safely() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0).unwrap();
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng).unwrap();
        let c1 = KeySwitchingKey::c1_from_seed(ctx, [42u8; 32], params.moduli().len());

        // Variance 10 uses the CBD sampler, which bit-packs draws: a
        // degree-8 row consumes 6 draws, so failing after 9 draws means row 0
        // completed and row 1 was mid-sampling when the RNG failed.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut failing = PanickingAfterDraws {
                draws: 0,
                fail_after: 9,
            };
            KeySwitchingKey::new_with_c1_extended(&sk, &from, c1, 0, 0, &mut failing)
        }));

        let payload = result.expect_err("generation must unwind when the RNG fails");
        assert_eq!(
            payload.downcast_ref::<&'static str>().copied(),
            Some("simulated RNG failure after earlier error rows were sampled")
        );
    }

    /// Same unwind-safety property on the single-modulus decomposition path,
    /// with the same limits on what this test can directly observe.
    #[test]
    fn extended_ksk_rng_failure_decomposition_unwinds_safely() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0).unwrap();
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng).unwrap();
        let modulus = ctx.moduli().first().unwrap();
        let log_modulus = modulus.next_power_of_two().ilog2() as usize;
        let expected_len = log_modulus.div_ceil(log_modulus / 2);
        let c1 = KeySwitchingKey::c1_from_seed(ctx, [42u8; 32], expected_len);

        // A degree-8, variance-10 CBD row consumes 6 draws, so failing after
        // 9 draws lands inside row 1 with row 0 fully sampled.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut failing = PanickingAfterDraws {
                draws: 0,
                fail_after: 9,
            };
            KeySwitchingKey::new_with_c1_extended(&sk, &from, c1, 0, 0, &mut failing)
        }));

        let payload = result.expect_err("generation must unwind when the RNG fails");
        assert!(payload.downcast_ref::<&'static str>().is_some());
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

    /// The decoder must reject an inverted level ordering — no constructor
    /// produces `ciphertext_level < ksk_level`, and the runtime check lives
    /// in `key_switch`, so accepting it at decode would defer the failure to
    /// operation time.
    #[test]
    fn proto_conversion_rejects_ciphertext_level_below_ksk_level() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx_ksk = params.context_at_level(1)?;
        let from = Poly::<PowerBasis>::small(ctx_ksk, 10, &mut rng)?;
        let ksk = KeySwitchingKey::new(&sk, &from, 1, 1, &mut rng)?;
        let mut proto = KeySwitchingKeyProto::from(&ksk);

        // Tamper: ciphertext level drops below the key level.
        proto.ciphertext_level = 0;
        assert!(matches!(
            KeySwitchingKey::try_convert_from(&proto, &params),
            Err(crate::Error::SerializationError(
                crate::SerializationError::InvalidKeySwitchingLevelOrder {
                    ciphertext_level: 0,
                    key_level: 1,
                }
            ))
        ));
        Ok(())
    }

    /// A nonzero `log_base` on a multi-modulus key context is a layout no
    /// constructor produces (the constructors only set `log_base` on the
    /// single-modulus decomposition path), including arbitrary oversized
    /// values that would corrupt the runtime decomposition.
    #[test]
    fn proto_conversion_rejects_unsupported_log_base_for_multi_modulus_context()
    -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0)?;
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
        let ksk = KeySwitchingKey::new(&sk, &from, 0, 0, &mut rng)?;
        assert_eq!(ksk.log_base, 0);

        for tampered_log_base in [3usize, 70] {
            let mut proto = KeySwitchingKeyProto::from(&ksk);
            proto.log_base = tampered_log_base as u32;
            assert!(matches!(
                KeySwitchingKey::try_convert_from(&proto, &params),
                Err(crate::Error::SerializationError(
                    crate::SerializationError::InvalidKeySwitchingLogBase {
                        log_base,
                        expected_log_base: 0,
                    }
                )) if log_base == tampered_log_base
            ));
        }
        Ok(())
    }

    /// A single-modulus key context only supports the base-2^(log_modulus/2)
    /// decomposition; `log_base = 0` and any other value are layouts no
    /// constructor produces. The honest decomposition key round-trips as a
    /// control.
    #[test]
    fn proto_conversion_rejects_non_constructor_log_base_for_decomposition_context()
    -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0)?;
        assert_eq!(ctx.moduli().len(), 1);
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
        let ksk = KeySwitchingKey::new(&sk, &from, 0, 0, &mut rng)?;

        let modulus = ctx.moduli().first().expect("single modulus");
        let log_modulus = modulus.next_power_of_two().ilog2() as usize;
        let expected_log_base = log_modulus / 2;
        assert!(expected_log_base > 0);
        assert_eq!(ksk.log_base, expected_log_base);

        // Control: the honest payload round-trips.
        let decoded =
            KeySwitchingKey::try_convert_from(&KeySwitchingKeyProto::from(&ksk), &params)?;
        assert_eq!(decoded, ksk);

        // Tamper: log_base zeroed out...
        let mut zeroed = KeySwitchingKeyProto::from(&ksk);
        zeroed.log_base = 0;
        assert_eq!(expected_log_base, 31); // 62-bit modulus → 62 / 2
        assert!(matches!(
            KeySwitchingKey::try_convert_from(&zeroed, &params),
            Err(crate::Error::SerializationError(
                crate::SerializationError::InvalidKeySwitchingLogBase {
                    log_base: 0,
                    expected_log_base: 31,
                }
            ))
        ));

        // ...and both a plausible and an oversized wrong base.
        for tampered_log_base in [expected_log_base - 1, expected_log_base + 1, 70] {
            let mut proto = KeySwitchingKeyProto::from(&ksk);
            proto.log_base = tampered_log_base as u32;
            assert!(matches!(
                KeySwitchingKey::try_convert_from(&proto, &params),
                Err(crate::Error::SerializationError(
                    crate::SerializationError::InvalidKeySwitchingLogBase {
                        log_base,
                        expected_log_base: 31,
                    }
                )) if log_base == tampered_log_base
            ));
        }
        Ok(())
    }

    /// The decoder must enforce the constructor row counts in both
    /// representations: the seeded representation derives `c1` from the seed,
    /// the explicit representation embeds `c1`, and neither may carry a
    /// different number of gadget rows than the constructors produce.
    #[test]
    fn proto_conversion_rejects_wrong_row_count() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0)?;
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
        let expected_rows = params.moduli().len();

        // Seeded representation: truncate and extend c0.
        let seeded = KeySwitchingKey::new(&sk, &from, 0, 0, &mut rng)?;
        let mut truncated = KeySwitchingKeyProto::from(&seeded);
        truncated.c0.pop();
        assert!(matches!(
            KeySwitchingKey::try_convert_from(&truncated, &params),
            Err(crate::Error::SerializationError(
                crate::SerializationError::WrongPolynomialCount {
                    component: crate::SerializedPolynomialComponent::KeySwitchingKeyC0,
                    expected: 6,
                    actual: 5,
                }
            ))
        ));
        let mut extended = KeySwitchingKeyProto::from(&seeded);
        extended.c0.push(extended.c0.first().expect("row").clone());
        assert!(KeySwitchingKey::try_convert_from(&extended, &params).is_err());

        // Explicit representation: truncate and extend c1.
        let c1 = KeySwitchingKey::c1_from_seed(ctx, [43u8; 32], expected_rows);
        let explicit = KeySwitchingKey::new_with_c1(&sk, &from, c1, 0, 0, &mut rng)?;
        let mut truncated_c1 = KeySwitchingKeyProto::from(&explicit);
        truncated_c1.c1.pop();
        assert!(matches!(
            KeySwitchingKey::try_convert_from(&truncated_c1, &params),
            Err(crate::Error::SerializationError(
                crate::SerializationError::WrongPolynomialCount {
                    component: crate::SerializedPolynomialComponent::KeySwitchingKeyC1,
                    expected: 6,
                    actual: 5,
                }
            ))
        ));
        let mut extended_c1 = KeySwitchingKeyProto::from(&explicit);
        extended_c1
            .c1
            .push(extended_c1.c1.first().expect("row").clone());
        assert!(KeySwitchingKey::try_convert_from(&extended_c1, &params).is_err());

        // Same row-count enforcement on the decomposition path.
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0)?;
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
        let decomposition = KeySwitchingKey::new(&sk, &from, 0, 0, &mut rng)?;
        let mut truncated_rows = KeySwitchingKeyProto::from(&decomposition);
        truncated_rows.c0.pop();
        assert!(matches!(
            KeySwitchingKey::try_convert_from(&truncated_rows, &params),
            Err(crate::Error::SerializationError(
                crate::SerializationError::WrongPolynomialCount {
                    component: crate::SerializedPolynomialComponent::KeySwitchingKeyC0,
                    ..
                }
            ))
        ));
        Ok(())
    }

    /// Round-trip for the explicit (seedless) representation on both the
    /// standard RNS and the single-modulus decomposition layouts.
    #[test]
    fn proto_conversion_explicit_c1_roundtrip() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        // Standard RNS layout over a multi-modulus context.
        let params = BfvParameters::default_arc(6, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0)?;
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
        let c1 = KeySwitchingKey::c1_from_seed(ctx, [44u8; 32], params.moduli().len());
        let explicit = KeySwitchingKey::new_with_c1(&sk, &from, c1, 0, 0, &mut rng)?;
        assert!(explicit.seed.is_none());
        let decoded =
            KeySwitchingKey::try_convert_from(&KeySwitchingKeyProto::from(&explicit), &params)?;
        assert_eq!(decoded, explicit);
        assert!(decoded.seed.is_none());

        // Single-modulus decomposition layout at the maximal level.
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0)?;
        let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;
        let modulus = ctx.moduli().first().expect("single modulus");
        let log_modulus = modulus.next_power_of_two().ilog2() as usize;
        let expected_rows = log_modulus.div_ceil(log_modulus / 2);
        let c1 = KeySwitchingKey::c1_from_seed(ctx, [45u8; 32], expected_rows);
        let explicit = KeySwitchingKey::new_with_c1(&sk, &from, c1, 0, 0, &mut rng)?;
        assert_eq!(explicit.log_base, log_modulus / 2);
        let decoded =
            KeySwitchingKey::try_convert_from(&KeySwitchingKeyProto::from(&explicit), &params)?;
        assert_eq!(decoded, explicit);
        Ok(())
    }

    /// Round-trip for seeded keys at nonzero (constructor-compatible)
    /// levels, on both the standard RNS layout and the single-modulus
    /// decomposition layout.
    #[test]
    fn proto_conversion_nonzero_level_roundtrip() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 16);
        let sk = SecretKey::random(&params, &mut rng);

        // Ciphertext level 1 with the key at level 0: 5 gadget rows.
        let ctx_ksk = params.context_at_level(0)?;
        let from = Poly::<PowerBasis>::small(ctx_ksk, 10, &mut rng)?;
        let leveled = KeySwitchingKey::new(&sk, &from, 1, 0, &mut rng)?;
        assert_eq!(leveled.c0.len(), params.context_at_level(1)?.moduli().len());
        let decoded =
            KeySwitchingKey::try_convert_from(&KeySwitchingKeyProto::from(&leveled), &params)?;
        assert_eq!(decoded, leveled);

        // Ciphertext level 2 with the key at level 1.
        let ctx_ksk = params.context_at_level(1)?;
        let from = Poly::<PowerBasis>::small(ctx_ksk, 10, &mut rng)?;
        let leveled = KeySwitchingKey::new(&sk, &from, 2, 1, &mut rng)?;
        let decoded =
            KeySwitchingKey::try_convert_from(&KeySwitchingKeyProto::from(&leveled), &params)?;
        assert_eq!(decoded, leveled);

        // The maximal level is the single-modulus decomposition layout.
        let max_level = params.max_level();
        let ctx_ksk = params.context_at_level(max_level)?;
        let from = Poly::<PowerBasis>::small(ctx_ksk, 10, &mut rng)?;
        let decomposition = KeySwitchingKey::new(&sk, &from, max_level, max_level, &mut rng)?;
        assert!(decomposition.log_base > 0);
        let decoded = KeySwitchingKey::try_convert_from(
            &KeySwitchingKeyProto::from(&decomposition),
            &params,
        )?;
        assert_eq!(decoded, decomposition);
        Ok(())
    }
}
