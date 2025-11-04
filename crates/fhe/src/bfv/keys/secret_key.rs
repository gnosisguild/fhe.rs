//! Secret keys for the BFV encryption scheme

use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::{Error, Result};
use fhe_math::{
    rq::{traits::TryConvertFrom, Poly, Representation},
    zq::Modulus,
};
use fhe_traits::{FheDecrypter, FheEncrypter, FheParametrized};
use fhe_util::sample_vec_cbd_f32;
use itertools::Itertools;
use num_bigint::BigUint;
use rand::{thread_rng, CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Secret key for the BFV encryption scheme.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SecretKey {
    /// The BFV parameters
    pub(crate) par: Arc<BfvParameters>,
    /// The secret key coefficients
    pub coeffs: Box<[i64]>,
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl SecretKey {
    /// The variance used for secret key sampling
    pub const SK_VARIANCE: f32 = 0.5;

    /// Get the secret key bound (2 * variance).
    pub fn sk_bound() -> f32 {
        2.0 * Self::SK_VARIANCE
    }
    /// Generate a random [`SecretKey`].
    pub fn random<R: RngCore + CryptoRng>(par: &Arc<BfvParameters>, rng: &mut R) -> Self {
        let s_coefficients = sample_vec_cbd_f32(par.degree(), Self::SK_VARIANCE, rng).unwrap();
        Self::new(s_coefficients, par)
    }

    /// Generate a [`SecretKey`] from its coefficients.
    pub fn new(coeffs: Vec<i64>, par: &Arc<BfvParameters>) -> Self {
        Self {
            par: par.clone(),
            coeffs: coeffs.into_boxed_slice(),
        }
    }

    /// Measure the noise in a [`Ciphertext`].
    ///
    /// # Safety
    ///
    /// This operations may run in a variable time depending on the value of the
    /// noise.
    pub unsafe fn measure_noise(&self, ct: &Ciphertext) -> Result<usize> {
        let plaintext = Zeroizing::new(self.try_decrypt(ct)?);
        let m = Zeroizing::new(plaintext.to_poly());

        // Let's create a secret key with the ciphertext context
        let mut s = Zeroizing::new(Poly::try_convert_from(
            self.coeffs.as_ref(),
            ct.c[0].ctx(),
            false,
            Representation::PowerBasis,
        )?);
        s.change_representation(Representation::Ntt);
        let mut si = s.clone();

        // Let's disable variable time computations
        let mut c = Zeroizing::new(ct.c[0].clone());
        c.disallow_variable_time_computations();

        for i in 1..ct.c.len() {
            let mut cis = Zeroizing::new(ct.c[i].clone());
            cis.disallow_variable_time_computations();
            *cis.as_mut() *= si.as_ref();
            *c.as_mut() += &cis;
            *si.as_mut() *= s.as_ref();
        }
        *c.as_mut() -= &m;
        c.change_representation(Representation::PowerBasis);

        let ciphertext_modulus = ct.c[0].ctx().modulus();
        let mut noise = 0usize;
        for coeff in Vec::<BigUint>::from(c.as_ref()) {
            noise = std::cmp::max(
                noise,
                std::cmp::min(coeff.bits(), (ciphertext_modulus - &coeff).bits()) as usize,
            )
        }

        Ok(noise)
    }

    /// Encrypt a plaintext using a provided seed for deterministic generation
    /// of random polynomials aᵢ.
    pub(crate) fn encrypt_poly_with_seed<R: RngCore + CryptoRng>(
        &self,
        p: &Poly,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Result<Ciphertext> {
        assert_eq!(p.representation(), &Representation::Ntt);

        let level = self.par.level_of_ctx(p.ctx())?;

        // Let's create a secret key with the ciphertext context
        let mut s = Zeroizing::new(Poly::try_convert_from(
            self.coeffs.as_ref(),
            p.ctx(),
            false,
            Representation::PowerBasis,
        )?);
        s.change_representation(Representation::Ntt);

        let mut a = Poly::random_from_seed(p.ctx(), Representation::Ntt, seed);
        let a_s = Zeroizing::new(&a * s.as_ref());

        let mut b = Poly::small(p.ctx(), Representation::Ntt, self.par.variance, rng)
            .map_err(Error::MathError)?;
        b -= &a_s;
        b += p;

        // It is now safe to enable variable time computations.
        unsafe {
            a.allow_variable_time_computations();
            b.allow_variable_time_computations()
        }

        Ok(Ciphertext {
            par: self.par.clone(),
            seed: Some(seed),
            c: vec![b, a],
            level,
        })
    }
    /// Encrypt a plaintext using a provided seed for deterministic generation
    /// of random polynomials aᵢ. Returns the ciphertext and the error polynomial.
    pub(crate) fn encrypt_poly_with_seed_extended<R: RngCore + CryptoRng>(
        &self,
        p: &Poly,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Result<(Ciphertext, Poly, Poly)> {
        assert_eq!(p.representation(), &Representation::Ntt);

        let level = self.par.level_of_ctx(p.ctx())?;

        let mut s = Zeroizing::new(Poly::try_convert_from(
            self.coeffs.as_ref(),
            p.ctx(),
            false,
            Representation::PowerBasis,
        )?);
        s.change_representation(Representation::Ntt);

        let mut a = Poly::random_from_seed(p.ctx(), Representation::Ntt, seed);
        let a_s = Zeroizing::new(&a * s.as_ref());

        let e = Poly::small(p.ctx(), Representation::Ntt, self.par.variance, rng)
            .map_err(Error::MathError)?;

        // Clone BEFORE enabling variable time to preserve restricted copies
        let a_copy = a.clone();
        let e_copy = e.clone();

        let mut b = e.clone();
        b -= &a_s;
        b += p;

        // Enable variable time only for the ciphertext components
        unsafe {
            a.allow_variable_time_computations();
            b.allow_variable_time_computations()
        }

        let ct = Ciphertext {
            par: self.par.clone(),
            seed: Some(seed),
            c: vec![b, a],
            level,
        };

        // Return ciphertext and the restricted copies of a and e
        Ok((ct, a_copy, e_copy))
    }

    /// Encrypt a plaintext using a random seed for deterministic generation
    /// of random polynomials aᵢ.
    pub(crate) fn encrypt_poly<R: RngCore + CryptoRng>(
        &self,
        p: &Poly,
        rng: &mut R,
    ) -> Result<Ciphertext> {
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        thread_rng().fill(&mut seed);

        self.encrypt_poly_with_seed(p, seed, rng)
    }
    /// Encrypt a plaintext using a random seed and return the error
    pub(crate) fn encrypt_poly_extended<R: RngCore + CryptoRng>(
        &self,
        p: &Poly,
        rng: &mut R,
    ) -> Result<(Ciphertext, Poly, Poly)> {
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        thread_rng().fill(&mut seed);

        self.encrypt_poly_with_seed_extended(p, seed, rng)
    }

    /// Encrypt a plaintext using a provided seed for deterministic generation
    /// of random polynomials
    pub fn try_encrypt_with_seed<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Result<Ciphertext> {
        assert_eq!(self.par, pt.par);
        let m = Zeroizing::new(pt.to_poly());
        self.encrypt_poly_with_seed(m.as_ref(), seed, rng)
    }
}

impl FheParametrized for SecretKey {
    type Parameters = BfvParameters;
}

impl FheEncrypter<Plaintext, Ciphertext> for SecretKey {
    type Error = Error;

    fn try_encrypt<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<Ciphertext> {
        assert_eq!(self.par, pt.par);
        let m = Zeroizing::new(pt.to_poly());
        self.encrypt_poly(m.as_ref(), rng)
    }
}

impl FheDecrypter<Plaintext, Ciphertext> for SecretKey {
    type Error = Error;

    fn try_decrypt(&self, ct: &Ciphertext) -> Result<Plaintext> {
        if self.par != ct.par {
            Err(Error::DefaultError(
                "Incompatible BFV parameters".to_string(),
            ))
        } else {
            // Let's create a secret key with the ciphertext context
            let mut s = Zeroizing::new(Poly::try_convert_from(
                self.coeffs.as_ref(),
                ct.c[0].ctx(),
                false,
                Representation::PowerBasis,
            )?);
            s.change_representation(Representation::Ntt);
            let mut si = s.clone();

            let mut c = Zeroizing::new(ct.c[0].clone());
            c.disallow_variable_time_computations();

            for i in 1..ct.c.len() {
                let mut cis = Zeroizing::new(ct.c[i].clone());
                cis.disallow_variable_time_computations();
                *cis.as_mut() *= si.as_ref();
                *c.as_mut() += &cis;
                *si.as_mut() *= s.as_ref();
            }
            c.change_representation(Representation::PowerBasis);

            let d = Zeroizing::new(c.scale(&self.par.scalers[ct.level])?);

            // TODO: Can we handle plaintext moduli that are BigUint?
            let v = Zeroizing::new(
                Vec::<u64>::from(d.as_ref())
                    .iter_mut()
                    .map(|vi| *vi + self.par.plaintext.modulus())
                    .collect_vec(),
            );
            let mut w = v[..self.par.degree()].to_vec();
            let q = Modulus::new(self.par.moduli[0]).map_err(Error::MathError)?;
            q.reduce_vec(&mut w);
            self.par.plaintext.reduce_vec(&mut w);

            let mut poly =
                Poly::try_convert_from(&w, ct.c[0].ctx(), false, Representation::PowerBasis)?;
            poly.change_representation(Representation::Ntt);

            let pt = Plaintext {
                par: self.par.clone(),
                value: w.into_boxed_slice(),
                encoding: None,
                poly_ntt: poly,
                level: ct.level,
            };

            Ok(pt)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SecretKey;
    use crate::bfv::{parameters::BfvParameters, Encoding, Plaintext};
    use fhe_traits::{FheDecrypter, FheEncoder, FheEncrypter};
    use rand::{thread_rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use std::error::Error;

    #[test]
    fn keygen() {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        assert_eq!(sk.par, params);

        sk.coeffs.iter().for_each(|ci: &i64| {
            // Check that this is a small polynomial
            let sk_variance = params.variance as f32 / 20.0;
            assert!((*ci).abs() as f32 <= 2.0 * sk_variance)
        })
    }

    #[test]
    fn encrypt_decrypt() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        for params in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            for level in 0..params.max_level() {
                for _ in 0..20 {
                    let sk = SecretKey::random(&params, &mut rng);

                    let pt = Plaintext::try_encode(
                        &params.plaintext.random_vec(params.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &params,
                    )?;
                    let ct = sk.try_encrypt(&pt, &mut rng)?;
                    let pt2 = sk.try_decrypt(&ct)?;

                    println!("Noise: {}", unsafe { sk.measure_noise(&ct)? });
                    assert_eq!(pt2, pt);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn test_deterministic_encryption() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);

        // Create a test plaintext
        let pt = Plaintext::try_encode(
            &params.plaintext.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;

        // Create a fixed seed
        let seed = <ChaCha8Rng as SeedableRng>::Seed::default();

        // Encrypt the same plaintext twice with the same seed
        let ct1 = sk.try_encrypt_with_seed(&pt, seed, &mut rng)?;
        let ct2 = sk.try_encrypt_with_seed(&pt, seed, &mut rng)?;

        // The ciphertexts should be identical except for the error terms
        assert_eq!(ct1.c[1], ct2.c[1]); // The 'a' polynomials should be identical
        assert_ne!(ct1.c[0], ct2.c[0]); // The 'b' polynomials should differ due to random error

        // Both should decrypt to the same plaintext
        let pt1 = sk.try_decrypt(&ct1)?;
        let pt2 = sk.try_decrypt(&ct2)?;
        assert_eq!(pt1, pt2);
        assert_eq!(pt1, pt);

        Ok(())
    }
}
