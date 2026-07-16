//! Operations over ciphertexts

mod dot_product;
pub use dot_product::dot_product_scalar;

mod mul;
pub use mul::Multiplicator;

use super::{Ciphertext, Plaintext};
use crate::{Error, Result};
use fhe_math::rq::{Ntt, Poly};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::sync::Arc;

impl Add<&Ciphertext> for &Ciphertext {
    type Output = Result<Ciphertext>;

    fn add(self, rhs: &Ciphertext) -> Self::Output {
        self.try_add(rhs)
    }
}

impl Add<&Ciphertext> for Ciphertext {
    type Output = Result<Ciphertext>;

    fn add(mut self, rhs: &Ciphertext) -> Self::Output {
        self.try_add_assign(rhs)?;
        Ok(self)
    }
}

impl Ciphertext {
    /// Add another ciphertext, treating missing higher-degree components as
    /// zero. The result has the larger input length. Returns an error if the
    /// parameters or levels are incompatible.
    pub fn try_add(&self, rhs: &Self) -> Result<Self> {
        let mut result = self.clone();
        result.try_add_assign(rhs)?;
        Ok(result)
    }

    /// Add another ciphertext in place, treating missing higher-degree
    /// components as zero. Returns an error without changing `self` if the
    /// parameters or levels are incompatible.
    pub fn try_add_assign(&mut self, rhs: &Self) -> Result<()> {
        if !Arc::ptr_eq(&self.par, &rhs.par) {
            return Err(Error::context_mismatch(&rhs.par, &self.par));
        }
        if self.is_empty() {
            *self = rhs.clone();
            return Ok(());
        }
        if rhs.is_empty() {
            return Ok(());
        }
        if self.level != rhs.level {
            return Err(Error::InvalidLevel {
                level: rhs.level,
                min_level: self.level,
                max_level: self.level,
            });
        }

        self.iter_mut()
            .zip(rhs.iter())
            .for_each(|(lhs, rhs)| *lhs += rhs);
        if rhs.len() > self.len() {
            self.c.extend(rhs.iter().skip(self.len()).cloned());
        }
        self.seed = None;
        Ok(())
    }
}

impl Add<&Plaintext> for &Ciphertext {
    type Output = Ciphertext;

    fn add(self, rhs: &Plaintext) -> Ciphertext {
        let mut self_clone = self.clone();
        self_clone += rhs;
        self_clone
    }
}

impl Add<&Ciphertext> for &Plaintext {
    type Output = Ciphertext;

    fn add(self, rhs: &Ciphertext) -> Ciphertext {
        rhs + self
    }
}

impl AddAssign<&Plaintext> for Ciphertext {
    fn add_assign(&mut self, rhs: &Plaintext) {
        assert!(Arc::ptr_eq(&self.par, &rhs.par));
        assert!(!self.is_empty());
        assert_eq!(self.level, rhs.level);

        let poly = rhs.to_poly();
        self[0] += &poly;
        self.seed = None
    }
}

impl Add<&Plaintext> for Ciphertext {
    type Output = Ciphertext;

    fn add(mut self, rhs: &Plaintext) -> Ciphertext {
        self += rhs;
        self
    }
}

impl Sub<&Ciphertext> for &Ciphertext {
    type Output = Result<Ciphertext>;

    fn sub(self, rhs: &Ciphertext) -> Self::Output {
        self.try_sub(rhs)
    }
}

impl Sub<&Ciphertext> for Ciphertext {
    type Output = Result<Ciphertext>;

    fn sub(mut self, rhs: &Ciphertext) -> Self::Output {
        self.try_sub_assign(rhs)?;
        Ok(self)
    }
}

impl Ciphertext {
    /// Subtract another ciphertext, treating missing higher-degree components
    /// as zero. The result has the larger input length. Returns an error if the
    /// parameters or levels are incompatible.
    pub fn try_sub(&self, rhs: &Self) -> Result<Self> {
        let mut result = self.clone();
        result.try_sub_assign(rhs)?;
        Ok(result)
    }

    /// Subtract another ciphertext in place, treating missing higher-degree
    /// components as zero. Returns an error without changing `self` if the
    /// parameters or levels are incompatible.
    pub fn try_sub_assign(&mut self, rhs: &Self) -> Result<()> {
        if !Arc::ptr_eq(&self.par, &rhs.par) {
            return Err(Error::context_mismatch(&rhs.par, &self.par));
        }
        if self.is_empty() {
            *self = -rhs;
            return Ok(());
        }
        if rhs.is_empty() {
            return Ok(());
        }
        if self.level != rhs.level {
            return Err(Error::InvalidLevel {
                level: rhs.level,
                min_level: self.level,
                max_level: self.level,
            });
        }

        self.iter_mut()
            .zip(rhs.iter())
            .for_each(|(lhs, rhs)| *lhs -= rhs);
        if rhs.len() > self.len() {
            self.c.extend(rhs.iter().skip(self.len()).map(Neg::neg));
        }
        self.seed = None;
        Ok(())
    }
}

impl Sub<&Plaintext> for &Ciphertext {
    type Output = Ciphertext;

    fn sub(self, rhs: &Plaintext) -> Ciphertext {
        let mut self_clone = self.clone();
        self_clone -= rhs;
        self_clone
    }
}

impl Sub<&Ciphertext> for &Plaintext {
    type Output = Ciphertext;

    fn sub(self, rhs: &Ciphertext) -> Ciphertext {
        -(rhs - self)
    }
}

impl SubAssign<&Plaintext> for Ciphertext {
    fn sub_assign(&mut self, rhs: &Plaintext) {
        assert!(Arc::ptr_eq(&self.par, &rhs.par));
        assert!(!self.is_empty());
        assert_eq!(self.level, rhs.level);

        let poly = rhs.to_poly();
        self.c[0] -= &poly;
        self.seed = None
    }
}

impl Sub<&Plaintext> for Ciphertext {
    type Output = Ciphertext;

    fn sub(mut self, rhs: &Plaintext) -> Ciphertext {
        self -= rhs;
        self
    }
}

impl Neg for &Ciphertext {
    type Output = Ciphertext;

    fn neg(self) -> Ciphertext {
        let c = self.iter().map(|c1i| -c1i).collect::<Vec<_>>();
        Ciphertext {
            par: self.par.clone(),
            seed: None,
            c,
            level: self.level,
        }
    }
}

impl Neg for Ciphertext {
    type Output = Ciphertext;

    fn neg(mut self) -> Ciphertext {
        self.iter_mut().for_each(|c1i| *c1i = -&*c1i);
        self.seed = None;
        self
    }
}

impl MulAssign<&Plaintext> for Ciphertext {
    fn mul_assign(&mut self, rhs: &Plaintext) {
        assert!(Arc::ptr_eq(&self.par, &rhs.par));
        if !self.is_empty() {
            assert_eq!(self.level, rhs.level);
            self.iter_mut().for_each(|ci| *ci *= &rhs.poly_ntt);
        }
        self.seed = None
    }
}

impl Mul<&Plaintext> for &Ciphertext {
    type Output = Ciphertext;

    fn mul(self, rhs: &Plaintext) -> Ciphertext {
        let mut self_clone = self.clone();
        self_clone *= rhs;
        self_clone
    }
}

impl Mul<&Plaintext> for Ciphertext {
    type Output = Ciphertext;

    fn mul(mut self, rhs: &Plaintext) -> Ciphertext {
        self *= rhs;
        self
    }
}

impl Mul<&Ciphertext> for &Ciphertext {
    type Output = Ciphertext;

    fn mul(self, rhs: &Ciphertext) -> Ciphertext {
        if self.is_empty() {
            return self.clone();
        }

        if rhs == self {
            // Squaring operation
            let ctx_lvl = self.par.context_level_at(self.level).unwrap();
            let mp = ctx_lvl.mul_params();

            // Scale all ciphertexts
            let self_c = self
                .iter()
                .map(|ci| ci.scale(&mp.extender).map_err(Error::MathError))
                .collect::<Result<Vec<Poly<Ntt>>>>()
                .unwrap();

            // Multiply
            let mut c = vec![Poly::<Ntt>::zero(&mp.to); 2 * self_c.len() - 1];
            for i in 0..self_c.len() {
                for j in 0..self_c.len() {
                    c[i + j] += &(&self_c[i] * &self_c[j])
                }
            }

            // Scale
            let c = c
                .iter_mut()
                .map(|ci| ci.scale(&mp.down_scaler).map_err(Error::MathError))
                .collect::<Result<Vec<Poly<Ntt>>>>()
                .unwrap();

            Ciphertext {
                par: self.par.clone(),
                seed: None,
                c,
                level: rhs.level,
            }
        } else {
            assert!(Arc::ptr_eq(&self.par, &rhs.par));
            assert_eq!(self.level, rhs.level);

            let ctx_lvl = self.par.context_level_at(self.level).unwrap();
            let mp = ctx_lvl.mul_params();

            // Scale all ciphertexts
            let self_c = self
                .iter()
                .map(|ci| ci.scale(&mp.extender).map_err(Error::MathError))
                .collect::<Result<Vec<Poly<Ntt>>>>()
                .unwrap();
            let other_c = rhs
                .iter()
                .map(|ci| ci.scale(&mp.extender).map_err(Error::MathError))
                .collect::<Result<Vec<Poly<Ntt>>>>()
                .unwrap();

            // Multiply
            let mut c = vec![Poly::<Ntt>::zero(&mp.to); self_c.len() + other_c.len() - 1];
            for i in 0..self_c.len() {
                for j in 0..other_c.len() {
                    c[i + j] += &(&self_c[i] * &other_c[j])
                }
            }

            // Scale
            let c = c
                .iter_mut()
                .map(|ci| ci.scale(&mp.down_scaler).map_err(Error::MathError))
                .collect::<Result<Vec<Poly<Ntt>>>>()
                .unwrap();

            Ciphertext {
                par: self.par.clone(),
                seed: None,
                c,
                level: rhs.level,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::bfv::{
        BfvParameters, Ciphertext, Encoding, Plaintext, SecretKey, encoding::EncodingEnum,
    };
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::rng;
    use std::error::Error;

    #[test]
    fn add() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();

        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 16),
        ] {
            let zero = Ciphertext::zero(&params);
            let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
            for _ in 0..50 {
                let a = q.random_vec(params.degree(), &mut rng);
                let b = q.random_vec(params.degree(), &mut rng);
                let mut c = a.clone();
                q.add_vec(&mut c, &b);

                let sk = SecretKey::random(&params, &mut rng);

                for encoding in [Encoding::poly(), Encoding::simd()] {
                    let pt_a = Plaintext::try_encode(&a, encoding.clone(), &params)?;
                    let pt_b = Plaintext::try_encode(&b, encoding.clone(), &params)?;

                    let mut ct_a: Ciphertext = sk.try_encrypt(&pt_a, &mut rng)?;
                    assert_eq!(ct_a, (&ct_a + &zero)?);
                    assert_eq!(ct_a, (&zero + &ct_a)?);
                    let ct_b: Ciphertext = sk.try_encrypt(&pt_b, &mut rng)?;
                    let ct_c = (&ct_a + &ct_b)?;
                    let ct_c_owned = (ct_a.clone() + &ct_b)?;
                    ct_a.try_add_assign(&ct_b)?;

                    let pt_c = sk.try_decrypt(&ct_c)?;
                    assert_eq!(Vec::<u64>::try_decode(&pt_c, encoding.clone())?, c);
                    assert_eq!(ct_c_owned, ct_c);
                    let pt_c = sk.try_decrypt(&ct_a)?;
                    assert_eq!(Vec::<u64>::try_decode(&pt_c, encoding.clone())?, c);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn checked_add_sub_support_mixed_sizes_and_reject_incompatible_inputs()
    -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let pt = Plaintext::try_encode(&[3_u64], Encoding::poly(), &params)?;
        let ct: Ciphertext = sk.try_encrypt(&pt, &mut rng)?;
        let product = &ct * &ct;

        let sum = ct.try_add(&product)?;
        assert_eq!(sum.len(), product.len());
        let recovered_ct = sum.try_sub(&product)?;
        assert_eq!(sk.try_decrypt(&recovered_ct)?, sk.try_decrypt(&ct)?);
        let recovered_product = product.try_sub(&ct)?.try_add(&ct)?;
        assert_eq!(
            sk.try_decrypt(&recovered_product)?,
            sk.try_decrypt(&product)?
        );
        let short_minus_long = (&ct - &product)?;
        assert_eq!(short_minus_long.len(), product.len());
        assert_eq!(
            sk.try_decrypt(&short_minus_long.try_add(&product)?)?,
            sk.try_decrypt(&ct)?
        );

        let mut switched = ct.clone();
        switched.switch_down()?;
        let original = ct.clone();
        let mut accumulator = ct.clone();
        assert!(matches!(
            accumulator.try_add_assign(&switched),
            Err(crate::Error::InvalidLevel { .. })
        ));
        assert_eq!(accumulator, original);
        assert!(matches!(
            accumulator.try_sub_assign(&switched),
            Err(crate::Error::InvalidLevel { .. })
        ));
        assert_eq!(accumulator, original);

        let other_params = BfvParameters::default_arc(6, 16);
        let other_sk = SecretKey::random(&other_params, &mut rng);
        let other_pt = Plaintext::try_encode(&[3_u64], Encoding::poly(), &other_params)?;
        let other_ct: Ciphertext = other_sk.try_encrypt(&other_pt, &mut rng)?;
        assert!(matches!(
            accumulator.try_add_assign(&other_ct),
            Err(crate::Error::ContextMismatch { .. })
        ));
        assert_eq!(accumulator, original);
        assert!(matches!(
            accumulator.try_sub_assign(&other_ct),
            Err(crate::Error::ContextMismatch { .. })
        ));
        assert_eq!(accumulator, original);

        Ok(())
    }

    #[test]
    fn add_scalar() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();

        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 16),
        ] {
            let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
            for _ in 0..50 {
                let a = q.random_vec(params.degree(), &mut rng);
                let b = q.random_vec(params.degree(), &mut rng);
                let mut c = a.clone();
                q.add_vec(&mut c, &b);

                let sk = SecretKey::random(&params, &mut rng);

                for encoding in [Encoding::poly(), Encoding::simd()] {
                    let zero = Plaintext::zero(encoding.clone(), &params)?;
                    let pt_a = Plaintext::try_encode(&a, encoding.clone(), &params)?;
                    let pt_b = Plaintext::try_encode(&b, encoding.clone(), &params)?;

                    let mut ct_a: Ciphertext = sk.try_encrypt(&pt_a, &mut rng)?;
                    assert_eq!(
                        Vec::<u64>::try_decode(
                            &sk.try_decrypt(&(&ct_a + &zero))?,
                            encoding.clone()
                        )?,
                        a
                    );
                    assert_eq!(
                        Vec::<u64>::try_decode(
                            &sk.try_decrypt(&(&zero + &ct_a))?,
                            encoding.clone()
                        )?,
                        a
                    );
                    let ct_c = &ct_a + &pt_b;
                    let ct_c_owned = ct_a.clone() + &pt_b;
                    ct_a += &pt_b;

                    let pt_c = sk.try_decrypt(&ct_c)?;
                    assert_eq!(Vec::<u64>::try_decode(&pt_c, encoding.clone())?, c);
                    assert_eq!(ct_c_owned, ct_c);
                    let pt_c = sk.try_decrypt(&ct_a)?;
                    assert_eq!(Vec::<u64>::try_decode(&pt_c, encoding.clone())?, c);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn sub() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 16),
        ] {
            let zero = Ciphertext::zero(&params);
            let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
            for _ in 0..50 {
                let a = q.random_vec(params.degree(), &mut rng);
                let mut a_neg = a.clone();
                q.neg_vec(&mut a_neg);
                let b = q.random_vec(params.degree(), &mut rng);
                let mut c = a.clone();
                q.sub_vec(&mut c, &b);

                let sk = SecretKey::random(&params, &mut rng);

                for encoding in [Encoding::poly(), Encoding::simd()] {
                    let pt_a = Plaintext::try_encode(&a, encoding.clone(), &params)?;
                    let pt_b = Plaintext::try_encode(&b, encoding.clone(), &params)?;

                    let mut ct_a: Ciphertext = sk.try_encrypt(&pt_a, &mut rng)?;
                    assert_eq!(ct_a, (&ct_a - &zero)?);
                    assert_eq!(
                        Vec::<u64>::try_decode(
                            &sk.try_decrypt(&(&zero - &ct_a)?)?,
                            encoding.clone()
                        )?,
                        a_neg
                    );
                    let ct_b: Ciphertext = sk.try_encrypt(&pt_b, &mut rng)?;
                    let ct_c = (&ct_a - &ct_b)?;
                    let ct_c_owned = (ct_a.clone() - &ct_b)?;
                    ct_a.try_sub_assign(&ct_b)?;

                    let pt_c = sk.try_decrypt(&ct_c)?;
                    assert_eq!(Vec::<u64>::try_decode(&pt_c, encoding.clone())?, c);
                    assert_eq!(ct_c_owned, ct_c);
                    let pt_c = sk.try_decrypt(&ct_a)?;
                    assert_eq!(Vec::<u64>::try_decode(&pt_c, encoding.clone())?, c);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn sub_scalar() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 16),
        ] {
            let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
            for _ in 0..50 {
                let a = q.random_vec(params.degree(), &mut rng);
                let mut a_neg = a.clone();
                q.neg_vec(&mut a_neg);
                let b = q.random_vec(params.degree(), &mut rng);
                let mut c = a.clone();
                q.sub_vec(&mut c, &b);

                let sk = SecretKey::random(&params, &mut rng);

                for encoding in [Encoding::poly(), Encoding::simd()] {
                    let zero = Plaintext::zero(encoding.clone(), &params)?;
                    let pt_a = Plaintext::try_encode(&a, encoding.clone(), &params)?;
                    let pt_b = Plaintext::try_encode(&b, encoding.clone(), &params)?;

                    let mut ct_a: Ciphertext = sk.try_encrypt(&pt_a, &mut rng)?;
                    assert_eq!(
                        Vec::<u64>::try_decode(
                            &sk.try_decrypt(&(&ct_a - &zero))?,
                            encoding.clone()
                        )?,
                        a
                    );
                    assert_eq!(
                        Vec::<u64>::try_decode(
                            &sk.try_decrypt(&(&zero - &ct_a))?,
                            encoding.clone()
                        )?,
                        a_neg
                    );
                    let ct_c = &ct_a - &pt_b;
                    let ct_c_owned = ct_a.clone() - &pt_b;
                    ct_a -= &pt_b;

                    let pt_c = sk.try_decrypt(&ct_c)?;
                    assert_eq!(Vec::<u64>::try_decode(&pt_c, encoding.clone())?, c);
                    assert_eq!(ct_c_owned, ct_c);
                    let pt_c = sk.try_decrypt(&ct_a)?;
                    assert_eq!(Vec::<u64>::try_decode(&pt_c, encoding.clone())?, c);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn neg() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 16),
        ] {
            let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
            for _ in 0..50 {
                let a = q.random_vec(params.degree(), &mut rng);
                let mut c = a.clone();
                q.neg_vec(&mut c);

                let sk = SecretKey::random(&params, &mut rng);
                for encoding in [Encoding::poly(), Encoding::simd()] {
                    let pt_a = Plaintext::try_encode(&a, encoding.clone(), &params)?;

                    let ct_a: Ciphertext = sk.try_encrypt(&pt_a, &mut rng)?;

                    let ct_c = -&ct_a;
                    let pt_c = sk.try_decrypt(&ct_c)?;
                    assert_eq!(Vec::<u64>::try_decode(&pt_c, encoding.clone())?, c);

                    let ct_c = -ct_a;
                    let pt_c = sk.try_decrypt(&ct_c)?;
                    assert_eq!(Vec::<u64>::try_decode(&pt_c, encoding.clone())?, c);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn mul_scalar() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();

        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 16),
        ] {
            let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
            for _ in 0..50 {
                let a = q.random_vec(params.degree(), &mut rng);
                let b = q.random_vec(params.degree(), &mut rng);

                let sk = SecretKey::random(&params, &mut rng);
                for encoding in [Encoding::poly(), Encoding::simd()] {
                    let mut c = vec![0u64; params.degree()];
                    match encoding.encoding {
                        EncodingEnum::Poly => {
                            for i in 0..params.degree() {
                                for j in 0..params.degree() {
                                    if i + j >= params.degree() {
                                        c[(i + j) % params.degree()] =
                                            q.sub(c[(i + j) % params.degree()], q.mul(a[i], b[j]));
                                    } else {
                                        c[i + j] = q.add(c[i + j], q.mul(a[i], b[j]));
                                    }
                                }
                            }
                        }
                        EncodingEnum::Simd => {
                            c.clone_from(&a);
                            q.mul_vec(&mut c, &b);
                        }
                    }

                    let pt_a = Plaintext::try_encode(&a, encoding.clone(), &params)?;
                    let pt_b = Plaintext::try_encode(&b, encoding.clone(), &params)?;

                    let mut ct_a: Ciphertext = sk.try_encrypt(&pt_a, &mut rng)?;
                    let ct_c = &ct_a * &pt_b;
                    let ct_c_owned = ct_a.clone() * &pt_b;
                    ct_a *= &pt_b;

                    let pt_c = sk.try_decrypt(&ct_c)?;
                    assert_eq!(Vec::<u64>::try_decode(&pt_c, encoding.clone())?, c);
                    assert_eq!(ct_c_owned, ct_c);
                    let pt_c = sk.try_decrypt(&ct_a)?;
                    assert_eq!(Vec::<u64>::try_decode(&pt_c, encoding.clone())?, c);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn mul() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for par in [
            BfvParameters::default_arc(2, 16),
            BfvParameters::default_arc(8, 16),
        ] {
            let q = fhe_math::zq::Modulus::new(par.plaintext()).unwrap();
            for _ in 0..1 {
                // We will encode `values` in an Simd format, and check that the product is
                // computed correctly.
                let v1 = q.random_vec(par.degree(), &mut rng);
                let v2 = q.random_vec(par.degree(), &mut rng);
                let mut expected = v1.clone();
                q.mul_vec(&mut expected, &v2);

                let sk = SecretKey::random(&par, &mut rng);
                let pt1 = Plaintext::try_encode(&v1, Encoding::simd(), &par)?;
                let pt2 = Plaintext::try_encode(&v2, Encoding::simd(), &par)?;

                let ct1: Ciphertext = sk.try_encrypt(&pt1, &mut rng)?;
                let ct2: Ciphertext = sk.try_encrypt(&pt2, &mut rng)?;
                let ct3 = &ct1 * &ct2;
                let ct4 = &ct3 * &ct3;

                println!("Noise: {}", unsafe { sk.measure_noise(&ct3)? });
                let pt = sk.try_decrypt(&ct3)?;
                assert_eq!(Vec::<u64>::try_decode(&pt, Encoding::simd())?, expected);

                let e = expected.clone();
                q.mul_vec(&mut expected, &e);
                println!("Noise: {}", unsafe { sk.measure_noise(&ct4)? });
                let pt = sk.try_decrypt(&ct4)?;
                assert_eq!(Vec::<u64>::try_decode(&pt, Encoding::simd())?, expected);
            }
        }
        Ok(())
    }

    #[test]
    fn square() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let par = BfvParameters::default_arc(6, 16);
        let q = fhe_math::zq::Modulus::new(par.plaintext()).unwrap();
        for _ in 0..20 {
            // We will encode `values` in an Simd format, and check that the product is
            // computed correctly.
            let v = q.random_vec(par.degree(), &mut rng);
            let mut expected = v.clone();
            q.mul_vec(&mut expected, &v);

            let sk = SecretKey::random(&par, &mut rng);
            let pt = Plaintext::try_encode(&v, Encoding::simd(), &par)?;

            let ct1: Ciphertext = sk.try_encrypt(&pt, &mut rng)?;
            let ct2 = &ct1 * &ct1;

            println!("Noise: {}", unsafe { sk.measure_noise(&ct2)? });
            let pt = sk.try_decrypt(&ct2)?;
            assert_eq!(Vec::<u64>::try_decode(&pt, Encoding::simd())?, expected);
        }
        Ok(())
    }
}
