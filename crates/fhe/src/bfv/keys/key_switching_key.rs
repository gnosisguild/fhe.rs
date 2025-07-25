//! Key-switching keys for the BFV encryption scheme. Implements the
//! Brakerski-Vaikuntanathan key switching through decomposition technique
//! adapted to RNS as described in the HPS optimization paper (https://eprint.iacr.org/2018/117)

use crate::bfv::{traits::TryConvertFrom as BfvTryConvertFrom, BfvParameters, SecretKey};
use crate::proto::bfv::KeySwitchingKey as KeySwitchingKeyProto;
use crate::{Error, Result};
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::rq::Context;
use fhe_math::{
    rns::RnsContext,
    rq::{Poly, Representation},
};
use fhe_traits::{DeserializeWithContext, Serialize};
use itertools::{izip, Itertools};
use num_bigint::BigUint;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Key switching key for the BFV encryption scheme.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeySwitchingKey {
    /// BFV encryption scheme parameters.
    pub par: Arc<BfvParameters>,

    /// Seed used to generate c1 polynomials.
    pub seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,

    /// Key switching elements c0.
    pub c0: Box<[Poly]>,

    /// Key switching elements c1.
    pub c1: Box<[Poly]>,

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
        from: &Poly,
        ciphertext_level: usize,
        ksk_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);

        Self::new_with_seed(sk, from, seed, ciphertext_level, ksk_level, rng)
    }

    /// Generate a [`KeySwitchingKey`] with a provided seed for generating c1
    /// values
    pub fn new_with_seed<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        ciphertext_level: usize,
        ksk_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let ctx_ksk = sk.par.ctx_at_level(ksk_level)?;
        let ctx_ciphertext = sk.par.ctx_at_level(ciphertext_level)?;

        if from.ctx() != ctx_ksk {
            return Err(Error::DefaultError(
                "Incorrect context for polynomial from".to_string(),
            ));
        }

        if ctx_ksk.moduli().len() == 1 {
            let modulus = ctx_ksk.moduli().first().unwrap();
            let log_modulus = modulus.next_power_of_two().ilog2() as usize;
            let log_base = log_modulus / 2;

            let c1 = Self::generate_c1(ctx_ksk, seed, log_modulus.div_ceil(log_base));
            let c0 = Self::generate_c0_decomposition(sk, from, &c1, rng, log_base)?;

            Ok(Self {
                par: sk.par.clone(),
                seed: Some(seed),
                c0: c0.into_boxed_slice(),
                c1: c1.into_boxed_slice(),
                ciphertext_level,
                ctx_ciphertext: ctx_ciphertext.clone(),
                ksk_level,
                ctx_ksk: ctx_ksk.clone(),
                log_base,
            })
        } else {
            let c1 = Self::generate_c1(ctx_ksk, seed, ctx_ciphertext.moduli().len());
            let c0 = Self::generate_c0(sk, from, &c1, rng)?;

            Ok(Self {
                par: sk.par.clone(),
                seed: Some(seed),
                c0: c0.into_boxed_slice(),
                c1: c1.into_boxed_slice(),
                ciphertext_level,
                ctx_ciphertext: ctx_ciphertext.clone(),
                ksk_level,
                ctx_ksk: ctx_ksk.clone(),
                log_base: 0,
            })
        }
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
    ) -> Vec<Poly> {
        let mut c1 = Vec::with_capacity(size);
        let mut rng = ChaCha8Rng::from_seed(seed);
        (0..size).for_each(|_| {
            let mut seed_i = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut seed_i);
            let mut a = Poly::random_from_seed(ctx, Representation::NttShoup, seed_i);
            unsafe { a.allow_variable_time_computations() }
            c1.push(a);
        });
        c1
    }

    /// Generate the c0 component of the key switching key (KSK) using the
    /// Brakerski-Vaikuntanathan key switching through decomposition
    /// technique adapted to RNS as described in the HPS optimization paper (https://eprint.iacr.org/2018/117).
    ///
    /// A key switching key consists of two components (c0,c1) = (KS_0, KS_1).
    /// This function generates the KS_0 component while KS_1 is generated
    /// separately as random polynomials.
    ///
    /// For each RNS modulus q_i in the basis, KS_0[i] is computed as:
    /// KS_0[i] = [e_i - a_i·s + p·g_i]_{Q}
    /// where:
    /// - e_i is a small error polynomial in RNS
    /// - a_i is the i-th random polynomial from KS_1 in RNS
    /// - s is the secret key in RNS
    /// - p is the input polynomial in RNS
    /// - g_i is the RNS basis conversion factor (q̃_i · q*_i) for the current
    ///   modulus q_i
    ///
    /// The size of the KS_0 vector is the same as the number of RNS moduli in
    /// the ciphertext context, meaning polynomials, when they are key switched,
    /// are decomposed by each modulus in the ciphertext context. This key
    /// already has the basis of the decomposition that the deocmposed
    /// polynomials then dot-product with to perform the key switching.
    ///
    /// Each element of KS_0 therefore corresponds to operations performed in
    /// RNS, with its own error polynomial e_i and random polynomial a_i,
    /// resulting in a collection of RNS polynomials that form the complete
    /// KS_0 component. Each element of KS_0 is a polynomial with context equal
    /// to the key switching key context.
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key
    /// * `from` - The original key to switch from (in RNS representation).
    /// * `c1` - The KS_1 polynomials (containing a_i for i in 0..k-1)
    /// * `rng` - Random number generator
    ///
    /// # Returns
    ///
    /// * `Result<Vec<Poly>>` - The generated KS_0 polynomials, where each
    ///   element corresponds to an RNS polynomial
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The c1 vector is empty
    /// * The `from` polynomial is not in power basis representation
    fn generate_c0<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly,
        c1: &[Poly],
        rng: &mut R,
    ) -> Result<Vec<Poly>> {
        if c1.is_empty() {
            return Err(Error::DefaultError("Empty number of c1's".to_string()));
        }
        if from.representation() != &Representation::PowerBasis {
            return Err(Error::DefaultError(
                "Unexpected representation for from".to_string(),
            ));
        }

        let mut s = Zeroizing::new(Poly::try_convert_from(
            sk.coeffs.as_ref(),
            c1[0].ctx(),
            false,
            Representation::PowerBasis,
        )?);
        s.change_representation(Representation::Ntt);

        // Up to size because that is the decomposition basis set by c1. We only need
        // the garner coefficients for the moduli we are using (g₁, ..., g_size).
        let rns = RnsContext::new(&sk.par.moduli[..c1.len()])?;

        // For each of the RNS moduli qi, we compute the following:
        // a_s = a*s
        // b = e - a*s
        // gi = qi_tilde * qi_star
        // g_i_from = poly * qi_tilde * qi_star
        // b = poly * qi_tilde * qi_star - a*s + e
        let c0 = c1
            .iter()
            .enumerate()
            .map(|(i, c1i)| {
                // a_s = a*s
                let mut a_s = Zeroizing::new(c1i.clone());
                a_s.disallow_variable_time_computations();
                a_s.change_representation(Representation::Ntt);
                *a_s.as_mut() *= s.as_ref();
                a_s.change_representation(Representation::PowerBasis);

                // b = e - a*s
                let mut b =
                    Poly::small(a_s.ctx(), Representation::PowerBasis, sk.par.variance, rng)?;
                b -= &a_s;

                // gi = qi_tilde * qi_star
                let gi = rns.get_garner(i).unwrap();

                // g_i_from = poly * qi_tilde * qi_star
                // We expect that every RNS component of g_i_from has all zero coefficients
                // except for the i-th RNS component
                let g_i_from = Zeroizing::new(gi * from);

                // b = poly * qi_tilde * qi_star - a*s + e
                b += &g_i_from;

                // It is now safe to enable variable time computations.
                unsafe { b.allow_variable_time_computations() }
                b.change_representation(Representation::NttShoup);
                Ok(b)
            })
            .collect::<Result<Vec<Poly>>>()?;

        Ok(c0)
    }

    /// Generate the c0's from the c1's, the secret key, and the 'from' secret
    /// key polynomial.
    fn generate_c0_decomposition<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        from: &Poly,
        c1: &[Poly],
        rng: &mut R,
        log_base: usize,
    ) -> Result<Vec<Poly>> {
        if c1.is_empty() {
            return Err(Error::DefaultError("Empty number of c1's".to_string()));
        }

        if from.representation() != &Representation::PowerBasis {
            return Err(Error::DefaultError(
                "Unexpected representation for from".to_string(),
            ));
        }

        let mut s = Zeroizing::new(Poly::try_convert_from(
            sk.coeffs.as_ref(),
            c1[0].ctx(),
            false,
            Representation::PowerBasis,
        )?);
        s.change_representation(Representation::Ntt);

        let c0 = c1
            .iter()
            .enumerate()
            .map(|(i, c1i)| {
                let mut a_s = Zeroizing::new(c1i.clone());
                a_s.disallow_variable_time_computations();
                a_s.change_representation(Representation::Ntt);
                *a_s.as_mut() *= s.as_ref();
                a_s.change_representation(Representation::PowerBasis);

                let mut b =
                    Poly::small(a_s.ctx(), Representation::PowerBasis, sk.par.variance, rng)?;
                b -= &a_s;

                let power = BigUint::from(1u64 << (i * log_base));
                b += &(from * &power);

                // It is now safe to enable variable time computations.
                unsafe { b.allow_variable_time_computations() }
                b.change_representation(Representation::NttShoup);
                Ok(b)
            })
            .collect::<Result<Vec<Poly>>>()?;

        Ok(c0)
    }

    /// Key switch a polynomial from one secret key to another using the
    /// Brakerski-Vaikuntanathan key switching through decomposition
    /// technique adapted to RNS as described in the HPS optimization paper (https://eprint.iacr.org/2018/117).
    ///
    /// This function performs key switching on a polynomial `p` encrypted under
    /// one secret key to obtain a ciphertext encrypted under a different
    /// secret key. Unlike key switching a full ciphertext, this function
    /// only handles the switching of a single polynomial (typically C1 of a
    /// ciphertext) and does not add any existing C0 term to the result.
    /// This makes it more flexible for use in various homomorphic
    /// operations where different handling of the C0 term may be desired.
    ///
    /// The function supports two modes of operation:
    /// - When `log_base = 0`: Direct key switching without decomposition
    ///   (hybrid key switching)
    /// - When `log_base > 0`: Key switching with base-2^log_base decomposition
    ///   (RNS decomposition key switching)
    ///
    /// # Arguments
    ///
    /// * `p` - The input polynomial to key switch, must be in power basis
    ///   representation
    ///
    /// # Returns
    ///
    /// * `Result<(Poly, Poly)>` - A tuple containing (C0, C1) of the key
    ///   switched result
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The input polynomial's context doesn't match the expected ciphertext
    ///   context
    /// * The input polynomial is not in power basis representation
    pub fn key_switch(&self, p: &Poly) -> Result<(Poly, Poly)> {
        if self.log_base != 0 {
            return self.key_switch_decomposition(p);
        }

        if p.ctx().as_ref() != self.ctx_ciphertext.as_ref() {
            return Err(Error::DefaultError(
                "The input polynomial does not have the correct context. Its RNS representation needs to match that of the key switching key decomposition context, or in other words, the key switching key ciphertext context.".to_string(),
            ));
        }
        if p.representation() != &Representation::PowerBasis {
            return Err(Error::DefaultError("Incorrect representation".to_string()));
        }

        let mut c0 = Poly::zero(&self.ctx_ksk, Representation::Ntt);
        let mut c1 = Poly::zero(&self.ctx_ksk, Representation::Ntt);
        for (c2_i_coefficients, c0_i, c1_i) in izip!(
            p.coefficients().outer_iter(),
            self.c0.iter(),
            self.c1.iter()
        ) {
            // Takes the coefficients of [p]_{qi} and converts them to an RNS representation
            // by taking [[p]_qi]_qj for every RNS basis qj!
            let mut c2_i = unsafe {
                Poly::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                    c2_i_coefficients.as_slice().unwrap(),
                    &self.ctx_ksk,
                )
            };
            c0 += &(&c2_i * c0_i);

            c2_i *= c1_i; // Re-uses memory, is faster
            c1 += &c2_i;
        }
        Ok((c0, c1))
    }

    /// Key switch a polynomial.
    fn key_switch_decomposition(&self, p: &Poly) -> Result<(Poly, Poly)> {
        if p.ctx().as_ref() != self.ctx_ciphertext.as_ref() {
            return Err(Error::DefaultError(
                "The input polynomial does not have the correct context.".to_string(),
            ));
        }
        if p.representation() != &Representation::PowerBasis {
            return Err(Error::DefaultError("Incorrect representation".to_string()));
        }

        let log_modulus = p
            .ctx()
            .moduli()
            .first()
            .unwrap()
            .next_power_of_two()
            .ilog2() as usize;

        let mut coefficients = p.coefficients().to_slice().unwrap().to_vec();
        let mut c2i = vec![];
        let mask = (1u64 << self.log_base) - 1;
        (0..log_modulus.div_ceil(self.log_base)).for_each(|_| {
            c2i.push(coefficients.iter().map(|c| c & mask).collect_vec());
            coefficients.iter_mut().for_each(|c| *c >>= self.log_base);
        });

        let mut c0 = Poly::zero(&self.ctx_ksk, Representation::Ntt);
        let mut c1 = Poly::zero(&self.ctx_ksk, Representation::Ntt);
        for (c2_i_coefficients, c0_i, c1_i) in izip!(c2i.iter(), self.c0.iter(), self.c1.iter()) {
            let mut c2_i = unsafe {
                Poly::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
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
    fn try_convert_from(value: &KeySwitchingKeyProto, par: &Arc<BfvParameters>) -> Result<Self> {
        let ciphertext_level = value.ciphertext_level as usize;
        let ksk_level = value.ksk_level as usize;
        let ctx_ksk = par.ctx_at_level(ksk_level)?;
        let ctx_ciphertext = par.ctx_at_level(ciphertext_level)?;

        let c0_size: usize;
        let log_base = value.log_base as usize;
        if log_base != 0 {
            if ksk_level != par.max_level() || ciphertext_level != par.max_level() {
                return Err(Error::DefaultError(
                    "A decomposition size is specified but the levels are not maximal".to_string(),
                ));
            } else {
                let log_modulus: usize =
                    par.moduli().first().unwrap().next_power_of_two().ilog2() as usize;
                c0_size = log_modulus.div_ceil(log_base);
            }
        } else {
            c0_size = ctx_ciphertext.moduli().len();
        }

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
            let unwrapped = <ChaCha8Rng as SeedableRng>::Seed::try_from(value.seed.clone());
            if unwrapped.is_err() {
                return Err(Error::DefaultError("Invalid seed".to_string()));
            }
            Some(unwrapped.unwrap())
        };

        let c1 = if let Some(seed) = seed {
            Self::generate_c1(ctx_ksk, seed, value.c0.len())
        } else {
            value
                .c1
                .iter()
                .map(|c1i| Poly::from_bytes(c1i, ctx_ksk).map_err(Error::MathError))
                .collect::<Result<Vec<Poly>>>()?
        };

        let c0 = value
            .c0
            .iter()
            .map(|c0i| Poly::from_bytes(c0i, ctx_ksk).map_err(Error::MathError))
            .collect::<Result<Vec<Poly>>>()?;

        Ok(Self {
            par: par.clone(),
            seed,
            c0: c0.into_boxed_slice(),
            c1: c1.into_boxed_slice(),
            ciphertext_level,
            ctx_ciphertext: ctx_ciphertext.clone(),
            ksk_level,
            ctx_ksk: ctx_ksk.clone(),
            log_base: value.log_base as usize,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::bfv::{
        keys::key_switching_key::KeySwitchingKey, traits::TryConvertFrom, BfvParameters, SecretKey,
    };
    use crate::proto::bfv::KeySwitchingKey as KeySwitchingKeyProto;
    use fhe_math::{
        rns::RnsContext,
        rq::{traits::TryConvertFrom as TryConvertFromPoly, Poly, Representation},
    };
    use num_bigint::BigUint;
    use rand::thread_rng;
    use std::error::Error;

    #[test]
    fn constructor() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        for params in [
            BfvParameters::default_arc(6, 8),
            BfvParameters::default_arc(3, 8),
        ] {
            let sk = SecretKey::random(&params, &mut rng);
            let ctx = params.ctx_at_level(0)?;
            let p = Poly::small(ctx, Representation::PowerBasis, 10, &mut rng)?;
            let ksk = KeySwitchingKey::new(&sk, &p, 0, 0, &mut rng);
            assert!(ksk.is_ok());
        }
        Ok(())
    }

    #[test]
    fn constructor_last_level() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        for params in [
            BfvParameters::default_arc(6, 8),
            BfvParameters::default_arc(3, 8),
        ] {
            let level = params.moduli().len() - 1;
            let sk = SecretKey::random(&params, &mut rng);
            let ctx = params.ctx_at_level(level)?;
            let p = Poly::small(ctx, Representation::PowerBasis, 10, &mut rng)?;
            let ksk = KeySwitchingKey::new(&sk, &p, level, level, &mut rng);
            assert!(ksk.is_ok());
        }
        Ok(())
    }

    #[test]
    fn key_switch() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        for params in [BfvParameters::default_arc(6, 8)] {
            for _ in 0..100 {
                let sk = SecretKey::random(&params, &mut rng);
                let ctx = params.ctx_at_level(0)?;
                let mut p = Poly::small(ctx, Representation::PowerBasis, 10, &mut rng)?;
                let ksk = KeySwitchingKey::new(&sk, &p, 0, 0, &mut rng)?;
                let mut s = Poly::try_convert_from(
                    sk.coeffs.as_ref(),
                    ctx,
                    false,
                    Representation::PowerBasis,
                )
                .map_err(crate::Error::MathError)?;
                s.change_representation(Representation::Ntt);

                let mut input = Poly::random(ctx, Representation::PowerBasis, &mut rng);
                let (c0, c1) = ksk.key_switch(&input)?;

                let mut c2 = &c0 + &(&c1 * &s);
                c2.change_representation(Representation::PowerBasis);

                input.change_representation(Representation::Ntt);
                p.change_representation(Representation::Ntt);
                let mut c3 = &input * &p;
                c3.change_representation(Representation::PowerBasis);

                let rns = RnsContext::new(&params.moduli)?;
                Vec::<BigUint>::from(&(&c2 - &c3)).iter().for_each(|b| {
                    assert!(std::cmp::min(b.bits(), (rns.modulus() - b).bits()) <= 70)
                });
            }
        }
        Ok(())
    }

    #[test]
    fn key_switch_decomposition() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        for params in [BfvParameters::default_arc(6, 8)] {
            for _ in 0..100 {
                let sk = SecretKey::random(&params, &mut rng);
                let ctx = params.ctx_at_level(5)?;
                let mut p = Poly::small(ctx, Representation::PowerBasis, 10, &mut rng)?;
                let ksk = KeySwitchingKey::new(&sk, &p, 5, 5, &mut rng)?;
                let mut s = Poly::try_convert_from(
                    sk.coeffs.as_ref(),
                    ctx,
                    false,
                    Representation::PowerBasis,
                )
                .map_err(crate::Error::MathError)?;
                s.change_representation(Representation::Ntt);

                let mut input = Poly::random(ctx, Representation::PowerBasis, &mut rng);
                let (c0, c1) = ksk.key_switch(&input)?;

                let mut c2 = &c0 + &(&c1 * &s);
                c2.change_representation(Representation::PowerBasis);

                input.change_representation(Representation::Ntt);
                p.change_representation(Representation::Ntt);
                let mut c3 = &input * &p;
                c3.change_representation(Representation::PowerBasis);

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
        let mut rng = thread_rng();
        for params in [
            BfvParameters::default_arc(6, 8),
            BfvParameters::default_arc(3, 8),
        ] {
            let sk = SecretKey::random(&params, &mut rng);
            let ctx = params.ctx_at_level(0)?;
            let p = Poly::small(ctx, Representation::PowerBasis, 10, &mut rng)?;
            let ksk = KeySwitchingKey::new(&sk, &p, 0, 0, &mut rng)?;
            let ksk_proto = KeySwitchingKeyProto::from(&ksk);
            assert_eq!(ksk, KeySwitchingKey::try_convert_from(&ksk_proto, &params)?);
        }
        Ok(())
    }

    #[test]
    fn compare_constructors() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        for params in [BfvParameters::default_arc(6, 8)] {
            let sk = SecretKey::random(&params, &mut rng);
            let ctx = params.ctx_at_level(0)?;
            let p = Poly::small(ctx, Representation::PowerBasis, 10, &mut rng)?;

            // Create first key with new()
            let ksk1 = KeySwitchingKey::new(&sk, &p, 0, 0, &mut rng)?;

            // Get the seed from the first key
            let seed = ksk1.seed.expect("Key should have a seed");

            // Create second key with new_with_seed() using the same seed
            let ksk2 = KeySwitchingKey::new_with_seed(&sk, &p, seed, 0, 0, &mut rng)?;

            // Compare c1 values
            assert_eq!(ksk1.c1.len(), ksk2.c1.len());
            for (c1_1, c1_2) in ksk1.c1.iter().zip(ksk2.c1.iter()) {
                assert_eq!(c1_1, c1_2);
            }
        }
        Ok(())
    }
}
