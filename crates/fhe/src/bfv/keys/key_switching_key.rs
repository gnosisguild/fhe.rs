//! Key-switching keys for the BFV encryption scheme. Implements the
//! Brakerski-Vaikuntanathan key switching through decomposition technique
//! adapted to RNS as described in the HPS optimization paper (https://eprint.iacr.org/2018/117)

use crate::bfv::{BfvParameters, SecretKey};
use crate::{Error, Result};
use fhe_math::rq::Context;
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::{
    rns::RnsContext,
    rq::{Ntt, NttShoup, Poly, PowerBasis},
};
use itertools::{Itertools, izip};
use num_bigint::BigUint;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
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
            return Err(Error::DefaultError(format!(
                "ciphertext_level ({ciphertext_level}) must be >= ksk_level ({ksk_level})"
            )));
        }

        let params = sk.params.clone();
        let ctx_ksk = params.context_at_level(ksk_level)?.clone();
        let ctx_ciphertext = params.context_at_level(ciphertext_level)?.clone();

        if from.ctx() != &ctx_ksk {
            return Err(Error::DefaultError(
                "Incorrect context for polynomial from".to_string(),
            ));
        }

        if ctx_ksk.moduli().len() == 1 {
            let modulus = ctx_ksk
                .moduli()
                .first()
                .ok_or_else(|| Error::DefaultError("Empty modulus list in ctx_ksk".to_string()))?;
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
            return Err(Error::DefaultError(format!(
                "ciphertext_level ({ciphertext_level}) must be >= ksk_level ({ksk_level})"
            )));
        }

        let params = sk.params.clone();
        let ctx_ksk = params.context_at_level(ksk_level)?.clone();
        let ctx_ciphertext = params.context_at_level(ciphertext_level)?.clone();

        if from.ctx() != &ctx_ksk {
            return Err(Error::DefaultError(
                "Incorrect context for polynomial from".to_string(),
            ));
        }

        // Validate every supplied c1 polynomial uses ctx_ksk
        for (i, c1i) in c1.iter().enumerate() {
            if c1i.ctx().as_ref() != ctx_ksk.as_ref() {
                return Err(Error::DefaultError(format!(
                    "c1[{i}] has wrong context: expected ksk-level context"
                )));
            }
        }

        if ctx_ksk.moduli().len() == 1 {
            let modulus = ctx_ksk
                .moduli()
                .first()
                .ok_or_else(|| Error::DefaultError("Empty modulus list in ctx_ksk".to_string()))?;
            let log_modulus = modulus.next_power_of_two().ilog2() as usize;
            let log_base = log_modulus / 2;
            let expected_len = log_modulus.div_ceil(log_base);
            if c1.len() != expected_len {
                return Err(Error::DefaultError(format!(
                    "Expected {expected_len} c1 polynomials for single-modulus context, got {}",
                    c1.len()
                )));
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
                return Err(Error::DefaultError(format!(
                    "Expected {expected_len} c1 polynomials, got {}",
                    c1.len()
                )));
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
            return Err(Error::DefaultError(format!(
                "ciphertext_level ({ciphertext_level}) must be >= ksk_level ({ksk_level})"
            )));
        }

        let params = sk.params.clone();
        let ctx_ksk = params.context_at_level(ksk_level)?.clone();
        let ctx_ciphertext = params.context_at_level(ciphertext_level)?.clone();

        if from.ctx() != &ctx_ksk {
            return Err(Error::DefaultError(
                "Incorrect context for polynomial from".to_string(),
            ));
        }

        for (i, c1i) in c1.iter().enumerate() {
            if c1i.ctx().as_ref() != ctx_ksk.as_ref() {
                return Err(Error::DefaultError(format!(
                    "c1[{i}] has wrong context: expected ksk-level context"
                )));
            }
        }

        if ctx_ksk.moduli().len() == 1 {
            let modulus = ctx_ksk
                .moduli()
                .first()
                .ok_or_else(|| Error::DefaultError("Empty modulus list in ctx_ksk".to_string()))?;
            let log_modulus = modulus.next_power_of_two().ilog2() as usize;
            let log_base = log_modulus / 2;
            let expected_len = log_modulus.div_ceil(log_base);
            if c1.len() != expected_len {
                return Err(Error::DefaultError(format!(
                    "Expected {expected_len} c1 polynomials for single-modulus context, got {}",
                    c1.len()
                )));
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
                return Err(Error::DefaultError(format!(
                    "Expected {expected_len} c1 polynomials, got {}",
                    c1.len()
                )));
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
        (0..size).for_each(|_| {
            let mut seed_i = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut seed_i);
            let mut a = Poly::<NttShoup>::random_from_seed(ctx, seed_i);
            unsafe { a.allow_variable_time_computations() }
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
            .ok_or_else(|| Error::DefaultError("Empty number of c1's".to_string()))?
            .ctx();
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx0, false)?.into_ntt(),
        );

        let moduli_slice =
            sk.params.moduli.get(..c1.len()).ok_or_else(|| {
                Error::DefaultError("c1 length exceeds modulus count".to_string())
            })?;
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

                let gi = rns.get_garner(i).ok_or_else(|| {
                    Error::DefaultError(format!("Garner coefficient {i} not found"))
                })?;
                let g_i_from = Zeroizing::new(gi * from);

                b += &g_i_from;

                unsafe { b.allow_variable_time_computations() }
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
            .ok_or_else(|| Error::DefaultError("Empty number of c1's".to_string()))?
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

                unsafe { b.allow_variable_time_computations() }
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
            .ok_or_else(|| Error::DefaultError("Empty number of c1's".to_string()))?
            .ctx();
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx0, false)?.into_ntt(),
        );

        let moduli_slice =
            sk.params.moduli.get(..c1.len()).ok_or_else(|| {
                Error::DefaultError("c1 length exceeds modulus count".to_string())
            })?;
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
                unsafe { error_i.allow_variable_time_computations() }
                let error_ntt = error_i.into_ntt_shoup();

                b -= a_s_pb.as_ref();

                let gi = rns.get_garner(i).ok_or_else(|| {
                    Error::DefaultError(format!("Garner coefficient {i} not found"))
                })?;
                let g_i_from = Zeroizing::new(gi * from);
                b += &g_i_from;

                unsafe { b.allow_variable_time_computations() }
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
            .ok_or_else(|| Error::DefaultError("Empty number of c1's".to_string()))?
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
                unsafe { error_i.allow_variable_time_computations() }
                let error_ntt = error_i.into_ntt_shoup();

                b -= a_s_pb.as_ref();

                let power = BigUint::from(1u64 << (i * log_base));
                let from_power = Zeroizing::new(from * &power);
                b += from_power.as_ref();

                unsafe { b.allow_variable_time_computations() }
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
            return Err(Error::DefaultError(
                "The input polynomial does not have the correct context. Its RNS representation needs to match that of the key switching key decomposition context, or in other words, the key switching key ciphertext context.".to_string(),
            ));
        }
        let mut c0 = Poly::<Ntt>::zero(&self.ctx_ksk);
        let mut c1 = Poly::<Ntt>::zero(&self.ctx_ksk);
        let p_coefficients = p.coefficients();
        for (c2_i_coefficients, c0_i, c1_i) in
            izip!(p_coefficients.outer_iter(), self.c0.iter(), self.c1.iter())
        {
            let mut c2_i = unsafe {
                Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                    c2_i_coefficients.as_slice().ok_or_else(|| {
                        Error::DefaultError(
                            "Non-contiguous coefficient array in key_switch".to_string(),
                        )
                    })?,
                    &self.ctx_ksk,
                )
            };
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
            return Err(Error::DefaultError(
                "The input polynomial does not have the correct context.".to_string(),
            ));
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

        let p_coefficients = p.coefficients();
        for (c2_i_coefficients, c0_i, c1_i) in
            izip!(p_coefficients.outer_iter(), self.c0.iter(), self.c1.iter())
        {
            let mut c2_i = unsafe {
                Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                    c2_i_coefficients.as_slice().ok_or_else(|| {
                        Error::DefaultError(
                            "Non-contiguous coefficient array in key_switch_assign".to_string(),
                        )
                    })?,
                    &self.ctx_ksk,
                )
            };
            *c0 += &(&c2_i * c0_i);
            c2_i *= c1_i;
            *c1 += &c2_i;
        }
        Ok(())
    }

    /// Key switch a polynomial using base decomposition.
    fn key_switch_decomposition(&self, p: &Poly<PowerBasis>) -> Result<(Poly<Ntt>, Poly<Ntt>)> {
        if p.ctx().as_ref() != self.ctx_ciphertext.as_ref() {
            return Err(Error::DefaultError(
                "The input polynomial does not have the correct context.".to_string(),
            ));
        }

        let log_modulus = p
            .ctx()
            .moduli()
            .first()
            .ok_or_else(|| {
                Error::DefaultError("Empty modulus list in key_switch_decomposition".to_string())
            })?
            .next_power_of_two()
            .ilog2() as usize;

        let mut coefficients = p
            .coefficients()
            .to_slice()
            .ok_or_else(|| {
                Error::DefaultError(
                    "Non-contiguous coefficient array in key_switch_decomposition".to_string(),
                )
            })?
            .to_vec();
        let mut c2i = vec![];
        let mask = (1u64 << self.log_base) - 1;
        (0..log_modulus.div_ceil(self.log_base)).for_each(|_| {
            c2i.push(coefficients.iter().map(|c| c & mask).collect_vec());
            coefficients.iter_mut().for_each(|c| *c >>= self.log_base);
        });

        let mut c0 = Poly::<Ntt>::zero(&self.ctx_ksk);
        let mut c1 = Poly::<Ntt>::zero(&self.ctx_ksk);
        for (c2_i_coefficients, c0_i, c1_i) in izip!(c2i.iter(), self.c0.iter(), self.c1.iter()) {
            let mut c2_i = unsafe {
                Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                    c2_i_coefficients.as_slice(),
                    &self.ctx_ksk,
                )
            };
            c0 += &(&c2_i * c0_i);
            c2_i *= c1_i;
            c1 += &c2_i;
        }
        Ok((c0, c1))
    }
}

#[cfg(feature = "protobuf")]
mod protobuf {
    use super::*;
    use crate::bfv::traits::TryConvertFrom as BfvTryConvertFrom;
    use crate::proto::bfv::KeySwitchingKey as KeySwitchingKeyProto;
    use fhe_traits::{DeserializeWithContext, Serialize};

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
        fn try_convert_from(
            value: &KeySwitchingKeyProto,
            par: &Arc<BfvParameters>,
        ) -> Result<Self> {
            let ciphertext_level = value.ciphertext_level as usize;
            let ksk_level = value.ksk_level as usize;

            // Validate level ordering — the key-switching decomposition requires
            // ciphertext_level >= ksk_level. Malformed serialized KSKs with
            // reversed levels must be rejected.
            if ciphertext_level < ksk_level {
                return Err(Error::DefaultError(format!(
                    "ciphertext_level ({ciphertext_level}) must be >= ksk_level ({ksk_level})"
                )));
            }

            let ctx_ksk = par.context_at_level(ksk_level)?.clone();
            let ctx_ciphertext = par.context_at_level(ciphertext_level)?.clone();

            let log_base = value.log_base as usize;

            // Validate log_base before any c0/c1 allocation or parsing.
            let c0_size: usize = if log_base != 0 {
                if ksk_level != par.max_level() || ciphertext_level != par.max_level() {
                    return Err(Error::DefaultError(
                        "A decomposition size is specified but the levels are not maximal"
                            .to_string(),
                    ));
                }

                // log_base must be < 64 to keep 1u64 << log_base safe
                if log_base > 63 {
                    return Err(Error::DefaultError(format!(
                        "log_base {log_base} is too large (max 63)"
                    )));
                }

                let log_modulus: usize = par
                    .moduli()
                    .first()
                    .ok_or_else(|| {
                        Error::DefaultError("Empty modulus list in parameters".to_string())
                    })?
                    .next_power_of_two()
                    .ilog2() as usize;

                // log_base must not exceed log_modulus
                if log_base > log_modulus {
                    return Err(Error::DefaultError(format!(
                        "log_base {log_base} exceeds log_modulus {log_modulus}"
                    )));
                }

                log_modulus.div_ceil(log_base)
            } else {
                ctx_ciphertext.moduli().len()
            };

            if value.c0.len() != c0_size {
                return Err(Error::DefaultError(
                    "Incorrect number of values in c0".to_string(),
                ));
            }

            let seed = if value.seed.is_empty() {
                if value.c1.len() != c0_size {
                    return Err(Error::DefaultError(
                        "Incorrect number of values in c1".to_string(),
                    ));
                }
                None
            } else {
                let seed = <ChaCha8Rng as SeedableRng>::Seed::try_from(value.seed.clone())
                    .map_err(|_| Error::DefaultError("Invalid seed".to_string()))?;
                Some(seed)
            };

            let c1 = if let Some(seed) = seed {
                let regenerated = KeySwitchingKey::c1_from_seed(&ctx_ksk, seed, value.c0.len());
                // If the serialized form also carries inline c1 polynomials,
                // they must match the seed-based regeneration exactly.
                // Contradictory encodings (seed != inline c1) are rejected.
                if !value.c1.is_empty() {
                    if value.c1.len() != c0_size {
                        return Err(Error::DefaultError(
                            "Incorrect number of values in c1".to_string(),
                        ));
                    }
                    let parsed: Vec<Poly<NttShoup>> = value
                        .c1
                        .iter()
                        .map(|c1i| {
                            Poly::<NttShoup>::from_bytes(c1i, &ctx_ksk).map_err(Error::MathError)
                        })
                        .collect::<Result<_>>()?;
                    if parsed != regenerated {
                        return Err(Error::DefaultError(
                            "Contradictory KSK protobuf: inline c1 polynomials \
                             do not match seed-derived c1"
                                .to_string(),
                        ));
                    }
                }
                regenerated
            } else {
                value
                    .c1
                    .iter()
                    .map(|c1i| {
                        Poly::<NttShoup>::from_bytes(c1i, &ctx_ksk).map_err(Error::MathError)
                    })
                    .collect::<Result<Vec<Poly<NttShoup>>>>()?
            };

            let c0 = value
                .c0
                .iter()
                .map(|c0i| Poly::<NttShoup>::from_bytes(c0i, &ctx_ksk).map_err(Error::MathError))
                .collect::<Result<Vec<Poly<NttShoup>>>>()?;

            Ok(Self {
                params: par.clone(),
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
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    #[cfg(feature = "protobuf")]
    use crate::bfv::traits::TryConvertFrom;
    use crate::bfv::{BfvParameters, SecretKey, keys::key_switching_key::KeySwitchingKey};
    #[cfg(feature = "protobuf")]
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
            let input = Poly::<PowerBasis>::random(ctx, &mut rng);

            let (c0, c1) = ksk.key_switch(&input)?;

            let mut a0 = Poly::<Ntt>::zero(&ksk.ctx_ksk);
            let mut a1 = Poly::<Ntt>::zero(&ksk.ctx_ksk);
            ksk.key_switch_assign(&input, &mut a0, &mut a1)?;

            assert_eq!(c0, a0);
            assert_eq!(c1, a1);
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

    #[cfg(feature = "protobuf")]
    mod protobuf {
        use super::*;
        use crate::bfv::traits::TryConvertFrom;
        use crate::proto::bfv::KeySwitchingKey as KeySwitchingKeyProto;
        use fhe_traits::Serialize;

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
                assert_eq!(ksk, KeySwitchingKey::try_convert_from(&ksk_proto, &params)?);
            }
            Ok(())
        }

        /// A KSK proto with both a seed and contradictory inline c1 polynomials
        /// must be rejected during deserialization.
        #[test]
        fn proto_rejects_seed_contradicting_c1() -> Result<(), Box<dyn Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let ctx = params.context_at_level(0)?;
            let from = Poly::<PowerBasis>::small(ctx, 10, &mut rng)?;

            // Build a valid KSK with a known seed.
            let honest_seed = [17u8; 32];
            let ksk = KeySwitchingKey::new_with_seed(&sk, &from, honest_seed, 0, 0, &mut rng)?;

            // Serialize → proto carries seed, no inline c1.
            let mut proto = KeySwitchingKeyProto::from(&ksk);

            // Inject c1 polynomials that were generated from a *different* seed.
            let wrong_seed = [99u8; 32];
            let wrong_c1 = KeySwitchingKey::c1_from_seed(&ksk.ctx_ksk, wrong_seed, ksk.c0.len());
            proto.c1 = wrong_c1.iter().map(|p| p.to_bytes()).collect();

            // Deserialization must detect the contradiction and reject.
            let result = KeySwitchingKey::try_convert_from(&proto, &params);
            assert!(
                result.is_err(),
                "Protobuf deserialization should reject KSK with seed contradicting inline c1"
            );

            // Sanity check: the same proto without the malicious c1 is valid.
            proto.c1.clear();
            assert!(
                KeySwitchingKey::try_convert_from(&proto, &params).is_ok(),
                "Protobuf deserialization of honest KSK should succeed"
            );

            Ok(())
        }
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
        assert!(result.is_err());
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
        assert!(result.is_err());
        Ok(())
    }

    // --- Finding 2: protobuf log_base validation ---

    #[cfg(feature = "protobuf")]
    #[test]
    fn proto_rejects_malformed_log_base_too_large() -> Result<(), Box<dyn Error>> {
        let params = BfvParameters::default_arc(6, 8);
        let max_level = params.max_level();

        // Build a proto whose levels are valid but log_base is >= 64,
        // which would overflow the shift operations in key_switch_decomposition.
        let proto = KeySwitchingKeyProto {
            ciphertext_level: max_level as u32,
            ksk_level: max_level as u32,
            log_base: 64,
            ..Default::default()
        };

        // The fix must reject this with a log_base-specific error before it
        // hits the c0-size check. Today it fails on "Incorrect number of
        // values in c0", which is the wrong reason.
        let err = KeySwitchingKey::try_convert_from(&proto, &params).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("log_base") || msg.contains("log base"),
            "Expected log_base validation error, got: {err}"
        );
        Ok(())
    }

    #[cfg(feature = "protobuf")]
    #[test]
    fn proto_rejects_malformed_log_base_gt_log_modulus() -> Result<(), Box<dyn Error>> {
        let params = BfvParameters::default_arc(6, 8);
        let max_level = params.max_level();
        let log_modulus = params
            .moduli()
            .first()
            .expect("params must have moduli")
            .next_power_of_two()
            .ilog2() as usize;

        // log_base larger than log_modulus is nonsensical.
        let proto = KeySwitchingKeyProto {
            ciphertext_level: max_level as u32,
            ksk_level: max_level as u32,
            log_base: (log_modulus + 1) as u32,
            ..Default::default()
        };

        // Must be rejected with a log_base-specific error, not the
        // c0-count check.
        let err = KeySwitchingKey::try_convert_from(&proto, &params).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("log_base") || msg.contains("log base"),
            "Expected log_base validation error, got: {err}"
        );
        Ok(())
    }

    #[cfg(feature = "protobuf")]
    #[test]
    fn proto_rejects_malformed_log_base_nonzero_not_max_level() -> Result<(), Box<dyn Error>> {
        let params = BfvParameters::default_arc(6, 8);

        let mut proto = KeySwitchingKeyProto {
            ciphertext_level: 0u32,
            ksk_level: 0u32,
            log_base: 8, // non-zero at non-max level is invalid
            ..Default::default()
        };
        proto.c0.push(vec![0u8; 1]);

        let result = KeySwitchingKey::try_convert_from(&proto, &params);
        assert!(result.is_err());
        Ok(())
    }
}
