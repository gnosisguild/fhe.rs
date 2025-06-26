use std::sync::Arc;

use fhe_math::{
    rns::ScalingFactor,
    rq::{scaler::Scaler, Context, Representation},
    zq::primes::generate_prime,
};
use num_bigint::BigUint;

use crate::{
    bfv::{traits::GenericRelinearizationKey, BfvParameters, Ciphertext},
    Error, Result,
};

/// Multiplicator that implements a strategy for multiplying. In particular, the
/// following information can be specified:
/// - Whether `lhs` must be scaled;
/// - Whether `rhs` must be scaled;
/// - The basis at which the multiplication will occur;
/// - The scaling factor after multiplication;
/// - Whether relinearization should be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multiplicator {
    par: Arc<BfvParameters>,
    pub(crate) extender_lhs: Scaler,
    pub(crate) extender_rhs: Scaler,
    pub(crate) down_scaler: Scaler,
    pub(crate) base_ctx: Arc<Context>,
    pub(crate) mul_ctx: Arc<Context>,
    rk: Option<GenericRelinearizationKey>,
    mod_switch: bool,
    level: usize,
}

impl Multiplicator {
    /// Construct a multiplicator using custom scaling factors and extended
    /// basis.
    pub fn new(
        lhs_scaling_factor: ScalingFactor,
        rhs_scaling_factor: ScalingFactor,
        extended_basis: &[u64],
        post_mul_scaling_factor: ScalingFactor,
        par: &Arc<BfvParameters>,
    ) -> Result<Self> {
        Self::new_leveled_internal(
            lhs_scaling_factor,
            rhs_scaling_factor,
            extended_basis,
            post_mul_scaling_factor,
            0,
            par,
        )
    }

    /// Construct a multiplicator using custom scaling factors and extended
    /// basis at a given level.
    pub fn new_leveled(
        lhs_scaling_factor: ScalingFactor,
        rhs_scaling_factor: ScalingFactor,
        extended_basis: &[u64],
        post_mul_scaling_factor: ScalingFactor,
        level: usize,
        par: &Arc<BfvParameters>,
    ) -> Result<Self> {
        Self::new_leveled_internal(
            lhs_scaling_factor,
            rhs_scaling_factor,
            extended_basis,
            post_mul_scaling_factor,
            level,
            par,
        )
    }

    fn new_leveled_internal(
        lhs_scaling_factor: ScalingFactor,
        rhs_scaling_factor: ScalingFactor,
        extended_basis: &[u64],
        post_mul_scaling_factor: ScalingFactor,
        level: usize,
        par: &Arc<BfvParameters>,
    ) -> Result<Self> {
        let base_ctx = par.ctx_at_level(level)?;
        let mul_ctx = Arc::new(Context::new(extended_basis, par.degree())?);
        let extender_lhs = Scaler::new(base_ctx, &mul_ctx, lhs_scaling_factor)?;
        let extender_rhs = Scaler::new(base_ctx, &mul_ctx, rhs_scaling_factor)?;
        let down_scaler = Scaler::new(&mul_ctx, base_ctx, post_mul_scaling_factor)?;
        Ok(Self {
            par: par.clone(),
            extender_lhs,
            extender_rhs,
            down_scaler,
            base_ctx: base_ctx.clone(),
            mul_ctx,
            rk: None,
            mod_switch: false,
            level,
        })
    }

    /// Default multiplication strategy using relinearization.
    pub fn default<RK>(rk: &RK) -> Result<Self>
    where
        for<'a> &'a RK: Into<GenericRelinearizationKey>,
    {
        let rk: GenericRelinearizationKey = rk.into();
        let par = rk.parameters();
        let ctx = par.ctx_at_level(rk.ciphertext_level())?;

        let modulus_size = par.moduli_sizes()[..ctx.moduli().len()]
            .iter()
            .sum::<usize>();
        let n_moduli = (modulus_size + 60).div_ceil(62);

        let mut extended_basis = Vec::with_capacity(ctx.moduli().len() + n_moduli);
        extended_basis.append(&mut ctx.moduli().to_vec());
        let mut upper_bound = 1 << 62;
        while extended_basis.len() != ctx.moduli().len() + n_moduli {
            upper_bound = generate_prime(62, 2 * par.degree() as u64, upper_bound).unwrap();
            if !extended_basis.contains(&upper_bound) && !ctx.moduli().contains(&upper_bound) {
                extended_basis.push(upper_bound)
            }
        }

        let mut multiplicator = Self::new_leveled_internal(
            ScalingFactor::one(),
            ScalingFactor::one(),
            &extended_basis,
            ScalingFactor::new(&BigUint::from(par.plaintext.modulus()), ctx.modulus()),
            rk.ciphertext_level(),
            &par,
        )?;

        multiplicator.enable_relinearization_with_key(rk)?;
        Ok(multiplicator)
    }

    /// Takes a reference, clones internally (for external users)
    pub fn enable_relinearization<RK>(&mut self, rk: &RK) -> Result<()>
    where
        for<'a> &'a RK: Into<GenericRelinearizationKey>,
    {
        let rk = rk.into();
        self.enable_relinearization_with_key(rk)
    }

    /// Takes ownership, no clone
    fn enable_relinearization_with_key(&mut self, rk: GenericRelinearizationKey) -> Result<()> {
        let rk_ctx = self.par.ctx_at_level(rk.ciphertext_level())?;
        if rk_ctx != &self.base_ctx {
            return Err(Error::DefaultError(
                "Invalid relinearization key context".to_string(),
            ));
        }
        self.rk = Some(rk);
        Ok(())
    }

    /// Enable modulus switching after multiplication (and relinearization, if
    /// applicable).
    pub fn enable_mod_switching(&mut self) -> Result<()> {
        if self.par.ctx_at_level(self.par.max_level())? == &self.base_ctx {
            Err(Error::DefaultError(
                "Cannot modulo switch as this is already the last level".to_string(),
            ))
        } else {
            self.mod_switch = true;
            Ok(())
        }
    }

    /// Multiply two ciphertexts using the defined multiplication strategy.
    pub fn multiply(&self, lhs: &Ciphertext, rhs: &Ciphertext) -> Result<Ciphertext> {
        if lhs.par != self.par || rhs.par != self.par {
            return Err(Error::DefaultError(
                "Ciphertexts do not have the same parameters".to_string(),
            ));
        }
        if lhs.level != self.level || rhs.level != self.level {
            return Err(Error::DefaultError(format!(
                "Ciphertexts are not at expected level. lhs: {}, rhs: {}, expected: {}",
                lhs.level, rhs.level, self.level
            )));
        }
        if lhs.c.len() != 2 || rhs.c.len() != 2 {
            return Err(Error::DefaultError(
                "Multiplication can only be performed on ciphertexts of size 2".to_string(),
            ));
        }

        // Extend
        let c00 = lhs.c[0].scale(&self.extender_lhs)?;
        let c01 = lhs.c[1].scale(&self.extender_lhs)?;
        let c10 = rhs.c[0].scale(&self.extender_rhs)?;
        let c11 = rhs.c[1].scale(&self.extender_rhs)?;

        // Multiply
        let c0 = &c00 * &c10;
        let mut c1 = &c00 * &c11;
        c1 += &(&c01 * &c10);
        let c2 = &c01 * &c11;

        // Scale
        let mut c = vec![c0, c1, c2];
        for p in c.iter_mut() {
            p.change_representation(Representation::PowerBasis);
            *p = p.scale(&self.down_scaler)?;
            p.change_representation(Representation::Ntt)
        }

        // Create a ciphertext
        let mut ct = Ciphertext::new(c, &self.par)?;

        // Relinearize
        if let Some(rk) = self.rk.as_ref() {
            rk.relinearizes(&mut ct)?;
        }

        // Reduce by one modulus to control noise growth
        if self.mod_switch {
            ct.mod_switch_to_next_level()?;
        }

        Ok(ct)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::bfv::{
        BfvParameters, Ciphertext, Encoding, Plaintext, RelinearizationKey, SecretKey,
    };
    use crate::lbfv::keys::LBFVRelinearizationKey;
    use crate::lbfv::LBFVPublicKey;
    use fhe_math::{
        rns::{RnsContext, ScalingFactor},
        zq::primes::generate_prime,
    };
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use num_bigint::BigUint;
    use rand::rngs::OsRng;
    use rand::{thread_rng, CryptoRng, RngCore};
    use std::error::Error;

    use super::Multiplicator;

    // Feature flag to control LBFV tests
    const RUN_LBFV_TESTS: bool = true;
    // const RUN_LBFV_TESTS: bool = false;

    #[test]
    fn mul() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let par = BfvParameters::default_arc(3, 8);

        // Standard BFV tests
        for _ in 0..15 {
            run_mul_test(par.clone(), false, &mut rng)?;
        }

        // LBFV tests (conditionally)
        if RUN_LBFV_TESTS {
            for _ in 0..15 {
                run_mul_test(par.clone(), true, &mut rng)?;
            }
        }

        Ok(())
    }

    fn run_mul_test<R: RngCore + CryptoRng>(
        par: Arc<BfvParameters>,
        use_lbfv: bool,
        rng: &mut R,
    ) -> Result<(), Box<dyn Error>> {
        // We will encode `values` in an Simd format, and check that the product is
        // computed correctly.
        let values = par.plaintext.random_vec(par.degree(), rng);
        let mut expected = values.clone();
        par.plaintext.mul_vec(&mut expected, &values);

        let sk = SecretKey::random(&par, rng);
        let pt = Plaintext::try_encode(&values, Encoding::simd(), &par)?;
        let ct1 = sk.try_encrypt(&pt, rng)?;
        let ct2 = sk.try_encrypt(&pt, rng)?;

        let mut multiplicator = if use_lbfv {
            let pk = LBFVPublicKey::new(&sk, rng);
            let rk = LBFVRelinearizationKey::new(&sk, &pk, None, rng)?;
            Multiplicator::default(&rk)?
        } else {
            let rk = RelinearizationKey::new(&sk, rng)?;
            Multiplicator::default(&rk)?
        };

        let ct3 = multiplicator.multiply(&ct1, &ct2)?;
        println!(
            "Noise ({}) : {}",
            if use_lbfv { "LBFV" } else { "BFV" },
            unsafe { sk.measure_noise(&ct3)? }
        );
        let pt = sk.try_decrypt(&ct3)?;
        assert_eq!(Vec::<u64>::try_decode(&pt, Encoding::simd())?, expected);

        multiplicator.enable_mod_switching()?;
        let ct3 = multiplicator.multiply(&ct1, &ct2)?;
        assert_eq!(ct3.level, 1);
        println!(
            "Noise ({} with mod switch): {}",
            if use_lbfv { "LBFV" } else { "BFV" },
            unsafe { sk.measure_noise(&ct3)? }
        );
        let pt = sk.try_decrypt(&ct3)?;
        assert_eq!(Vec::<u64>::try_decode(&pt, Encoding::simd())?, expected);

        Ok(())
    }

    #[test]
    fn mul_at_level() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let num_moduli = 6;
        let par = BfvParameters::default_arc(num_moduli, 8);

        // Standard BFV tests
        for _ in 0..5 {
            for level in 0..num_moduli - 1 {
                run_mul_at_level_test(&par, level, false, &mut rng)?;
            }
        }

        // LBFV tests (conditionally)
        if RUN_LBFV_TESTS {
            for _ in 0..5 {
                for level in 0..num_moduli - 1 {
                    run_mul_at_level_test(&par, level, true, &mut rng)?;
                }
            }
        }

        Ok(())
    }

    fn run_mul_at_level_test<R: RngCore + CryptoRng>(
        par: &Arc<BfvParameters>,
        level: usize,
        use_lbfv: bool,
        rng: &mut R,
    ) -> Result<(), Box<dyn Error>> {
        let values: Vec<u64> = par.plaintext.random_vec(par.degree(), rng);
        let mut expected = values.clone();
        par.plaintext.mul_vec(&mut expected, &values);

        let sk = SecretKey::random(par, rng);
        let pt = Plaintext::try_encode(&values, Encoding::simd_at_level(level), par)?;
        let ct1: Ciphertext = sk.try_encrypt(&pt, rng)?;
        let ct2: Ciphertext = sk.try_encrypt(&pt, rng)?;
        assert_eq!(ct1.level, level);
        assert_eq!(ct2.level, level);

        let mut multiplicator = if use_lbfv {
            let pk = LBFVPublicKey::new(&sk, rng);
            let rk = LBFVRelinearizationKey::new_leveled(&sk, &pk, None, level, 0, rng)?;
            assert_eq!(rk.ciphertext_level(), level);
            assert_eq!(rk.key_level(), 0);
            assert_eq!(rk.l()?, pk.l - level);
            Multiplicator::default(&rk)?
        } else {
            let rk = RelinearizationKey::new_leveled(&sk, level, level, rng)?;
            Multiplicator::default(&rk)?
        };

        let ct3 = multiplicator.multiply(&ct1, &ct2)?;
        println!(
            "Noise ({} at level {}): {}",
            if use_lbfv { "LBFV" } else { "BFV" },
            level,
            unsafe { sk.measure_noise(&ct3)? }
        );
        let pt = sk.try_decrypt(&ct3)?;
        assert_eq!(Vec::<u64>::try_decode(&pt, Encoding::simd())?, expected);

        multiplicator.enable_mod_switching()?;
        let ct3 = multiplicator.multiply(&ct1, &ct2)?;
        assert_eq!(ct3.level, level + 1);
        println!(
            "Noise ({} at level {} with mod switch): {}",
            if use_lbfv { "LBFV" } else { "BFV" },
            level,
            unsafe { sk.measure_noise(&ct3)? }
        );
        let pt = sk.try_decrypt(&ct3)?;
        assert_eq!(Vec::<u64>::try_decode(&pt, Encoding::simd())?, expected);

        Ok(())
    }

    #[test]
    fn mul_no_relin() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let par = BfvParameters::default_arc(6, 8);
        for _ in 0..30 {
            // We will encode `values` in an Simd format, and check that the product is
            // computed correctly.
            let values = par.plaintext.random_vec(par.degree(), &mut rng);
            let mut expected = values.clone();
            par.plaintext.mul_vec(&mut expected, &values);

            let sk = SecretKey::random(&par, &mut OsRng);
            let rk = RelinearizationKey::new(&sk, &mut rng)?;
            let pt = Plaintext::try_encode(&values, Encoding::simd(), &par)?;
            let ct1 = sk.try_encrypt(&pt, &mut rng)?;
            let ct2 = sk.try_encrypt(&pt, &mut rng)?;

            let mut multiplicator = Multiplicator::default(&rk)?;
            // Remove the relinearization key.
            multiplicator.rk = None;
            let ct3 = multiplicator.multiply(&ct1, &ct2)?;
            println!("Noise: {}", unsafe { sk.measure_noise(&ct3)? });
            let pt = sk.try_decrypt(&ct3)?;
            assert_eq!(Vec::<u64>::try_decode(&pt, Encoding::simd())?, expected);

            multiplicator.enable_mod_switching()?;
            let ct3 = multiplicator.multiply(&ct1, &ct2)?;
            assert_eq!(ct3.level, 1);
            println!("Noise: {}", unsafe { sk.measure_noise(&ct3)? });
            let pt = sk.try_decrypt(&ct3)?;
            assert_eq!(Vec::<u64>::try_decode(&pt, Encoding::simd())?, expected);
        }
        Ok(())
    }

    #[test]
    fn different_mul_strategy() -> Result<(), Box<dyn Error>> {
        // Implement the second multiplication strategy from <https://eprint.iacr.org/2021/204>

        let mut rng = thread_rng();
        let par = BfvParameters::default_arc(3, 8);
        let mut extended_basis = par.moduli().to_vec();
        extended_basis
            .push(generate_prime(62, 2 * par.degree() as u64, extended_basis[2]).unwrap());
        extended_basis
            .push(generate_prime(62, 2 * par.degree() as u64, extended_basis[3]).unwrap());
        extended_basis
            .push(generate_prime(62, 2 * par.degree() as u64, extended_basis[4]).unwrap());
        let rns = RnsContext::new(&extended_basis[3..])?;

        for _ in 0..30 {
            // We will encode `values` in an Simd format, and check that the product is
            // computed correctly.
            let values = par.plaintext.random_vec(par.degree(), &mut rng);
            let mut expected = values.clone();
            par.plaintext.mul_vec(&mut expected, &values);

            let sk = SecretKey::random(&par, &mut OsRng);
            let pt = Plaintext::try_encode(&values, Encoding::simd(), &par)?;
            let ct1 = sk.try_encrypt(&pt, &mut rng)?;
            let ct2 = sk.try_encrypt(&pt, &mut rng)?;

            let mut multiplicator = Multiplicator::new(
                ScalingFactor::one(),
                ScalingFactor::new(rns.modulus(), par.ctx[0].modulus()),
                &extended_basis,
                ScalingFactor::new(&BigUint::from(par.plaintext()), rns.modulus()),
                &par,
            )?;

            let ct3 = multiplicator.multiply(&ct1, &ct2)?;
            println!("Noise: {}", unsafe { sk.measure_noise(&ct3)? });
            let pt = sk.try_decrypt(&ct3)?;
            assert_eq!(Vec::<u64>::try_decode(&pt, Encoding::simd())?, expected);

            multiplicator.enable_mod_switching()?;
            let ct3 = multiplicator.multiply(&ct1, &ct2)?;
            assert_eq!(ct3.level, 1);
            println!("Noise: {}", unsafe { sk.measure_noise(&ct3)? });
            let pt = sk.try_decrypt(&ct3)?;
            assert_eq!(Vec::<u64>::try_decode(&pt, Encoding::simd())?, expected);
        }

        Ok(())
    }

    #[test]
    fn multiply_three_times_with_level_changes() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        // Run test for both standard BFV and LBFV
        run_multiply_three_times_test(false, &mut rng)?;

        if RUN_LBFV_TESTS {
            run_multiply_three_times_test(true, &mut rng)?;
        }

        Ok(())
    }

    fn run_multiply_three_times_test<R: RngCore + CryptoRng>(
        use_lbfv: bool,
        rng: &mut R,
    ) -> Result<(), Box<dyn Error>> {
        const DEGREE: usize = 8;
        let params = BfvParameters::default_arc(6, DEGREE);
        let sk = SecretKey::random(&params, rng);
        let key_level = 0;
        let num_multiplications = 3;

        // Encrypt initial value (2)
        let pt = Plaintext::try_encode(&[2u64; DEGREE], Encoding::simd(), &params)?;
        let mut ct: Ciphertext = sk.try_encrypt(&pt, rng)?;
        println!(
            "Initial noise ({}): {}",
            if use_lbfv { "LBFV" } else { "BFV" },
            unsafe { sk.measure_noise(&ct)? }
        );

        // Expected values after each multiplication: 2 -> 4 -> 16 -> 256
        let mut expected_value = 2u64;

        // Perform multiplications
        for i in 0..num_multiplications {
            // Create relinearization key for current level
            let mut multiplicator = if use_lbfv {
                let pk = LBFVPublicKey::new(&sk, rng);
                let rk = LBFVRelinearizationKey::new_leveled(&sk, &pk, None, i, key_level, rng)?;
                Multiplicator::default(&rk)?
            } else {
                let rk = RelinearizationKey::new_leveled(&sk, i, key_level, rng)?;
                Multiplicator::default(&rk)?
            };

            // Enable modulus switching and multiply
            multiplicator.enable_mod_switching()?;
            ct = multiplicator.multiply(&ct, &ct)?;

            // Update expected value and verify
            expected_value = expected_value * expected_value;
            println!(
                "Mul #{} ({}): level={}, noise={}",
                i + 1,
                if use_lbfv { "LBFV" } else { "BFV" },
                ct.level,
                unsafe { sk.measure_noise(&ct)? }
            );

            // Decrypt and verify
            let pt = sk.try_decrypt(&ct)?;
            let result = Vec::<u64>::try_decode(&pt, Encoding::simd())?;
            assert_eq!(result, vec![expected_value; DEGREE]);
        }

        Ok(())
    }
}
