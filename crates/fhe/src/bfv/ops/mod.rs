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

impl Ciphertext {
    /// Materialize the empty accumulator as a ciphertext containing a plaintext.
    fn assign_plaintext(&mut self, plaintext: &Plaintext) -> Result<()> {
        let c0 = plaintext.to_poly()?;
        let c1 = Poly::<Ntt>::zero(c0.ctx());
        self.c = vec![c0, c1];
        self.level = plaintext.level();
        self.seed = None;
        Ok(())
    }

    /// Add a plaintext, returning a typed error for incompatible parameters,
    /// levels, or a level whose ciphertext modulus cannot encode plaintexts.
    /// Use this method instead of `+=` when the inputs are not trusted.
    pub fn try_add_plaintext(&mut self, rhs: &Plaintext) -> Result<()> {
        rhs.validate_for(&self.params)?;
        if self.is_empty() {
            return self.assign_plaintext(rhs);
        }
        if self.level != rhs.level() {
            return Err(Error::InvalidLevel {
                level: rhs.level(),
                min_level: self.level,
                max_level: self.level,
            });
        }
        self.validate_for(&self.params)?;
        let poly = rhs.to_poly()?;
        self[0] += &poly;
        self.seed = None;
        Ok(())
    }

    /// Subtract a plaintext with the same checks as [`Self::try_add_plaintext`].
    pub fn try_sub_plaintext(&mut self, rhs: &Plaintext) -> Result<()> {
        rhs.validate_for(&self.params)?;
        if self.is_empty() {
            self.assign_plaintext(rhs)?;
            self.c[0] = -&self.c[0];
            return Ok(());
        }
        if self.level != rhs.level() {
            return Err(Error::InvalidLevel {
                level: rhs.level(),
                min_level: self.level,
                max_level: self.level,
            });
        }
        self.validate_for(&self.params)?;
        let poly = rhs.to_poly()?;
        self.c[0] -= &poly;
        self.seed = None;
        Ok(())
    }

    /// Multiply a ciphertext by a plaintext, returning a typed error for
    /// incompatible parameters, levels, or a level whose ciphertext modulus
    /// cannot encode plaintexts. Use this method instead of `*=` when the
    /// inputs are not trusted.
    ///
    /// Unlike [`Self::try_add_plaintext`] and [`Self::try_sub_plaintext`], an
    /// empty accumulator is not materialized: a validated multiplication
    /// leaves it empty.
    pub fn try_mul_plaintext(&mut self, rhs: &Plaintext) -> Result<()> {
        rhs.validate_for(&self.params)?;
        if self.is_empty() {
            return Ok(());
        }
        if self.level != rhs.level() {
            return Err(Error::InvalidLevel {
                level: rhs.level(),
                min_level: self.level,
                max_level: self.level,
            });
        }
        self.validate_for(&self.params)?;
        self.iter_mut().for_each(|ci| *ci *= &rhs.poly_ntt);
        self.seed = None;
        Ok(())
    }
}

impl Add<&Ciphertext> for &Ciphertext {
    type Output = Ciphertext;

    fn add(self, rhs: &Ciphertext) -> Ciphertext {
        assert!(Arc::ptr_eq(&self.params, &rhs.params));

        if self.is_empty() {
            return rhs.clone();
        }
        if rhs.is_empty() {
            return self.clone();
        }

        assert_eq!(self.level, rhs.level);
        assert_eq!(self.len(), rhs.len());

        let c = self
            .iter()
            .zip(rhs.iter())
            .map(|(c1i, c2i)| c1i + c2i)
            .collect::<Vec<_>>();
        Ciphertext {
            params: self.params.clone(),
            seed: None,
            c,
            level: self.level,
        }
    }
}

impl Add<&Ciphertext> for Ciphertext {
    type Output = Ciphertext;

    fn add(mut self, rhs: &Ciphertext) -> Ciphertext {
        self += rhs;
        self
    }
}

impl AddAssign<&Ciphertext> for Ciphertext {
    fn add_assign(&mut self, rhs: &Ciphertext) {
        assert!(Arc::ptr_eq(&self.params, &rhs.params));

        if self.is_empty() {
            *self = rhs.clone()
        } else if !rhs.is_empty() {
            assert_eq!(self.level, rhs.level);
            assert_eq!(self.len(), rhs.len());
            self.iter_mut()
                .zip(rhs.iter())
                .for_each(|(c1i, c2i)| *c1i += c2i);
            self.seed = None
        }
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
    #[expect(
        clippy::expect_used,
        reason = "the AddAssign trait is infallible; use try_add_plaintext for a typed error"
    )]
    fn add_assign(&mut self, rhs: &Plaintext) {
        self.try_add_plaintext(rhs).expect(
            "ciphertext/plaintext addition requires matching parameters and supported levels; use try_add_plaintext for a typed error",
        );
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
    type Output = Ciphertext;

    fn sub(self, rhs: &Ciphertext) -> Ciphertext {
        assert!(Arc::ptr_eq(&self.params, &rhs.params));

        if self.is_empty() {
            return -rhs.clone();
        }
        if rhs.is_empty() {
            return self.clone();
        }

        assert_eq!(self.level, rhs.level);
        assert_eq!(self.len(), rhs.len());

        let c = self
            .iter()
            .zip(rhs.iter())
            .map(|(c1i, c2i)| c1i - c2i)
            .collect::<Vec<_>>();
        Ciphertext {
            params: self.params.clone(),
            seed: None,
            c,
            level: self.level,
        }
    }
}

impl Sub<&Ciphertext> for Ciphertext {
    type Output = Ciphertext;

    fn sub(mut self, rhs: &Ciphertext) -> Ciphertext {
        self -= rhs;
        self
    }
}

impl SubAssign<&Ciphertext> for Ciphertext {
    fn sub_assign(&mut self, rhs: &Ciphertext) {
        assert!(Arc::ptr_eq(&self.params, &rhs.params));

        if self.is_empty() {
            *self = -rhs
        } else if !rhs.is_empty() {
            assert_eq!(self.level, rhs.level);
            assert_eq!(self.len(), rhs.len());
            self.iter_mut()
                .zip(rhs.iter())
                .for_each(|(c1i, c2i)| *c1i -= c2i);
            self.seed = None
        }
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
    #[expect(
        clippy::expect_used,
        reason = "the SubAssign trait is infallible; use try_sub_plaintext for a typed error"
    )]
    fn sub_assign(&mut self, rhs: &Plaintext) {
        self.try_sub_plaintext(rhs).expect(
            "ciphertext/plaintext subtraction requires matching parameters and supported levels; use try_sub_plaintext for a typed error",
        );
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
            params: self.params.clone(),
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
    #[expect(
        clippy::expect_used,
        reason = "the MulAssign trait is infallible; use try_mul_plaintext for a typed error"
    )]
    fn mul_assign(&mut self, rhs: &Plaintext) {
        self.try_mul_plaintext(rhs).expect(
            "ciphertext/plaintext multiplication requires matching parameters and supported levels; use try_mul_plaintext for a typed error",
        );
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
        assert!(Arc::ptr_eq(&self.params, &rhs.params));
        if self.is_empty() || rhs.is_empty() {
            return Ciphertext::zero(&self.params);
        }

        if rhs == self {
            // Squaring operation
            let ctx_lvl = self.params.context_level_at(self.level).unwrap();
            let mp = ctx_lvl.mul_params();

            // Scale all ciphertexts
            let self_c = self
                .iter()
                .map(|ci| ci.scale(&mp.extender).map_err(Error::MathError))
                .collect::<Result<Vec<Poly<Ntt>>>>()
                .unwrap();

            // Multiply
            let mut c = vec![Poly::<Ntt>::zero(&mp.to); 2 * self_c.len() - 1];
            if self_c.iter().all(Poly::allows_variable_time_computations) {
                let variable_time =
                    fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
                c.iter_mut()
                    .for_each(|ci| ci.allow_variable_time_computations(variable_time));
            }
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
                params: self.params.clone(),
                seed: None,
                c,
                level: rhs.level,
            }
        } else {
            assert_eq!(self.level, rhs.level);

            let ctx_lvl = self.params.context_level_at(self.level).unwrap();
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
            if self_c
                .iter()
                .chain(other_c.iter())
                .all(Poly::allows_variable_time_computations)
            {
                let variable_time =
                    fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
                c.iter_mut()
                    .for_each(|ci| ci.allow_variable_time_computations(variable_time));
            }
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
                params: self.params.clone(),
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
        BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey,
        encoding::EncodingEnum,
    };
    use crate::{Error as FheError, PlaintextError};
    use fhe_math::rq::{Ntt, Poly};
    use fhe_traits::{
        DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
    };
    use num_bigint::BigUint;
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
                    assert_eq!(ct_a, &ct_a + &zero);
                    assert_eq!(ct_a, &zero + &ct_a);
                    let ct_b: Ciphertext = sk.try_encrypt(&pt_b, &mut rng)?;
                    let ct_c = &ct_a + &ct_b;
                    let ct_c_owned = ct_a.clone() + &ct_b;
                    ct_a += &ct_b;

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
    fn empty_accumulator_materializes_plaintext_at_its_level() -> Result<(), Box<dyn Error>> {
        let params = BfvParameters::default_arc(2, 16);
        let sk = SecretKey::random(&params, &mut rng());
        let mut values = vec![0u64; params.degree()];
        values[0] = 1;
        values[1] = 2;

        for level in 0..=1 {
            let encoding = Encoding::poly_at_level(level);
            let pt = Plaintext::try_encode(&values, encoding.clone(), &params)?;
            let zero = Ciphertext::zero(&params);

            let mut multiplied = zero.clone();
            multiplied *= &pt;
            assert_eq!(multiplied, zero);
            assert!(Ciphertext::from_bytes(&zero.to_bytes(), &params).is_err());

            let mut added = zero.clone();
            added += &pt;
            assert_eq!(added, &zero + &pt);
            assert_eq!(added, &pt + &zero);
            assert_eq!(added.len(), 2);
            assert_eq!(added.level, level);
            assert_eq!(
                Vec::<u64>::try_decode(&sk.try_decrypt(&added)?, encoding.clone())?,
                values
            );

            let mut subtracted = zero.clone();
            subtracted -= &pt;
            assert_eq!(subtracted, &zero - &pt);
            assert_eq!(subtracted.len(), 2);
            assert_eq!(subtracted.level, level);
            let mut negated = values.clone();
            fhe_math::zq::Modulus::new(params.plaintext())?.neg_vec(&mut negated);
            assert_eq!(
                Vec::<u64>::try_decode(&sk.try_decrypt(&subtracted)?, encoding.clone())?,
                negated
            );
            assert_eq!(
                Vec::<u64>::try_decode(&sk.try_decrypt(&(&pt - &zero))?, encoding)?,
                values
            );
        }
        Ok(())
    }

    #[test]
    fn checked_plaintext_arithmetic_reports_typed_errors() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();

        // t = 4099 exceeds the single-modulus level's q0 = 1153, so level 1
        // keeps a valid polynomial context but cannot encode plaintexts.
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(4099)
            .set_moduli(&[1153, 12289])
            .build_arc()?;
        let sk = SecretKey::random(&params, &mut rng);
        let values = vec![7u64; params.degree()];
        let valid = Plaintext::try_encode(&values, Encoding::poly(), &params)?;
        let unsupported_plaintext = Plaintext {
            params: params.clone(),
            encoding: Some(Encoding::poly_at_level(1)),
            poly_ntt: Poly::<Ntt>::zero(params.context_at_level(1)?),
        };
        let unsupported = FheError::Plaintext(PlaintextError::UnsupportedCiphertextLevel {
            level: 1,
            ciphertext_modulus: BigUint::from(1153u64),
            plaintext_modulus: BigUint::from(4099u64),
        });

        // The empty-accumulator path rejects the level without materializing.
        let mut empty = Ciphertext::zero(&params);
        assert_eq!(
            empty.try_add_plaintext(&unsupported_plaintext).unwrap_err(),
            unsupported
        );
        assert!(empty.is_empty());
        assert_eq!(
            empty.try_sub_plaintext(&unsupported_plaintext).unwrap_err(),
            unsupported
        );
        assert!(empty.is_empty());

        // The non-empty path rejects the level before touching the ciphertext.
        let mut ct: Ciphertext = sk.try_encrypt(&valid, &mut rng)?;
        assert_eq!(ct.level, 0);
        assert_eq!(
            ct.try_add_plaintext(&unsupported_plaintext).unwrap_err(),
            unsupported
        );
        assert_eq!(
            ct.try_sub_plaintext(&unsupported_plaintext).unwrap_err(),
            unsupported
        );

        // Level mismatches are typed even when both levels are supported.
        let two_level_params = BfvParameters::default_arc(2, 16);
        let two_level_sk = SecretKey::random(&two_level_params, &mut rng);
        let low = Plaintext::try_encode(&values, Encoding::poly_at_level(0), &two_level_params)?;
        let high = Plaintext::try_encode(&values, Encoding::poly_at_level(1), &two_level_params)?;
        let mut high_ct: Ciphertext = two_level_sk.try_encrypt(&high, &mut rng)?;
        assert_eq!(high_ct.level, 1);
        let mismatch = FheError::InvalidLevel {
            level: 0,
            min_level: 1,
            max_level: 1,
        };
        assert_eq!(high_ct.try_add_plaintext(&low).unwrap_err(), mismatch);
        assert_eq!(high_ct.try_sub_plaintext(&low).unwrap_err(), mismatch);

        // Parameter mismatches are typed as well.
        let other_params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(4099)
            .set_moduli(&[1153, 12289])
            .build_arc()?;
        let other_plaintext = Plaintext::try_encode(&values, Encoding::poly(), &other_params)?;
        assert!(matches!(
            ct.try_add_plaintext(&other_plaintext),
            Err(FheError::ParameterMismatch { .. })
        ));
        assert!(matches!(
            ct.try_sub_plaintext(&other_plaintext),
            Err(FheError::ParameterMismatch { .. })
        ));

        // Supported-level arithmetic via the checked APIs stays correct.
        let mut sum = ct.clone();
        sum.try_add_plaintext(&valid)?;
        sum.try_sub_plaintext(&valid)?;
        assert_eq!(
            Vec::<u64>::try_decode(&sk.try_decrypt(&sum)?, Encoding::poly())?,
            values
        );

        Ok(())
    }

    #[test]
    fn checked_plaintext_multiplication_reports_typed_errors() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();

        // t = 4099 exceeds the single-modulus level's q0 = 1153, so level 1
        // keeps a valid polynomial context but cannot encode plaintexts.
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(4099)
            .set_moduli(&[1153, 12289])
            .build_arc()?;
        let sk = SecretKey::random(&params, &mut rng);
        let values = vec![7u64; params.degree()];
        let valid = Plaintext::try_encode(&values, Encoding::poly(), &params)?;
        let unsupported_plaintext = Plaintext {
            params: params.clone(),
            encoding: Some(Encoding::poly_at_level(1)),
            poly_ntt: Poly::<Ntt>::zero(params.context_at_level(1)?),
        };
        let unsupported = FheError::Plaintext(PlaintextError::UnsupportedCiphertextLevel {
            level: 1,
            ciphertext_modulus: BigUint::from(1153u64),
            plaintext_modulus: BigUint::from(4099u64),
        });

        // The empty accumulator rejects the level (it used to skip every
        // plaintext check) and stays empty.
        let mut empty = Ciphertext::zero(&params);
        assert_eq!(
            empty.try_mul_plaintext(&unsupported_plaintext).unwrap_err(),
            unsupported
        );
        assert!(empty.is_empty());

        // The empty accumulator rejects mismatched parameters as well.
        let other_params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(4099)
            .set_moduli(&[1153, 12289])
            .build_arc()?;
        let other_plaintext = Plaintext::try_encode(&values, Encoding::poly(), &other_params)?;
        let mut empty = Ciphertext::zero(&params);
        assert!(matches!(
            empty.try_mul_plaintext(&other_plaintext),
            Err(FheError::ParameterMismatch { .. })
        ));
        assert!(empty.is_empty());

        // A switched ciphertext rejects the level before any mutation; the
        // multiplication used to silently proceed at Q <= t.
        let mut ct: Ciphertext = sk.try_encrypt(&valid, &mut rng)?;
        assert_eq!(ct.level, 0);
        let mut switched = ct.clone();
        switched.switch_down()?;
        assert_eq!(switched.level, 1);
        let untouched = switched.clone();
        assert_eq!(
            switched
                .try_mul_plaintext(&unsupported_plaintext)
                .unwrap_err(),
            unsupported
        );
        assert_eq!(switched, untouched);

        // A supported-level ciphertext rejects the plaintext's level too: the
        // rhs check precedes the level comparison.
        let untouched = ct.clone();
        assert_eq!(
            ct.try_mul_plaintext(&unsupported_plaintext).unwrap_err(),
            unsupported
        );
        assert_eq!(ct, untouched);

        // Level mismatches are typed before any mutation.
        let two_level_params = BfvParameters::default_arc(2, 16);
        let two_level_sk = SecretKey::random(&two_level_params, &mut rng);
        let high = Plaintext::try_encode(&values, Encoding::poly_at_level(1), &two_level_params)?;
        let low = Plaintext::try_encode(&values, Encoding::poly_at_level(0), &two_level_params)?;
        let mut high_ct: Ciphertext = two_level_sk.try_encrypt(&high, &mut rng)?;
        assert_eq!(high_ct.level, 1);
        let untouched = high_ct.clone();
        let mismatch = FheError::InvalidLevel {
            level: 0,
            min_level: 1,
            max_level: 1,
        };
        assert_eq!(high_ct.try_mul_plaintext(&low).unwrap_err(), mismatch);
        assert_eq!(high_ct, untouched);

        // Parameter mismatches are typed before any mutation as well.
        let untouched = ct.clone();
        assert!(matches!(
            ct.try_mul_plaintext(&other_plaintext),
            Err(FheError::ParameterMismatch { .. })
        ));
        assert_eq!(ct, untouched);

        Ok(())
    }

    #[test]
    fn checked_plaintext_multiplication_matches_infallible_operator() -> Result<(), Box<dyn Error>>
    {
        let mut rng = rng();
        let params = BfvParameters::default_arc(2, 16);
        let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
        let sk = SecretKey::random(&params, &mut rng);

        let a = q.random_vec(params.degree(), &mut rng);
        let b = q.random_vec(params.degree(), &mut rng);
        let mut expected = vec![0u64; params.degree()];
        for i in 0..params.degree() {
            for j in 0..params.degree() {
                if i + j >= params.degree() {
                    expected[(i + j) % params.degree()] =
                        q.sub(expected[(i + j) % params.degree()], q.mul(a[i], b[j]));
                } else {
                    expected[i + j] = q.add(expected[i + j], q.mul(a[i], b[j]));
                }
            }
        }

        let pt_a = Plaintext::try_encode(&a, Encoding::poly(), &params)?;
        let pt_b = Plaintext::try_encode(&b, Encoding::poly(), &params)?;
        let ct: Ciphertext = sk.try_encrypt(&pt_a, &mut rng)?;

        let mut checked = ct.clone();
        checked.try_mul_plaintext(&pt_b)?;
        let pt_c = sk.try_decrypt(&checked)?;
        assert_eq!(Vec::<u64>::try_decode(&pt_c, Encoding::poly())?, expected);

        // The infallible operator delegates to the checked API.
        let mut delegated = ct.clone();
        delegated *= &pt_b;
        assert_eq!(delegated, checked);

        // A validated multiplication leaves the empty accumulator empty.
        let mut empty = Ciphertext::zero(&params);
        empty.try_mul_plaintext(&pt_b)?;
        assert_eq!(empty, Ciphertext::zero(&params));

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
                    assert_eq!(ct_a, &ct_a - &zero);
                    assert_eq!(
                        Vec::<u64>::try_decode(
                            &sk.try_decrypt(&(&zero - &ct_a))?,
                            encoding.clone()
                        )?,
                        a_neg
                    );
                    let ct_b: Ciphertext = sk.try_encrypt(&pt_b, &mut rng)?;
                    let ct_c = &ct_a - &ct_b;
                    let ct_c_owned = ct_a.clone() - &ct_b;
                    ct_a -= &ct_b;

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
        for params in [
            BfvParameters::default_arc(2, 16),
            BfvParameters::default_arc(8, 16),
        ] {
            let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
            for _ in 0..1 {
                // We will encode `values` in an Simd format, and check that the product is
                // computed correctly.
                let v1 = q.random_vec(params.degree(), &mut rng);
                let v2 = q.random_vec(params.degree(), &mut rng);
                let mut expected = v1.clone();
                q.mul_vec(&mut expected, &v2);

                let sk = SecretKey::random(&params, &mut rng);
                let pt1 = Plaintext::try_encode(&v1, Encoding::simd(), &params)?;
                let pt2 = Plaintext::try_encode(&v2, Encoding::simd(), &params)?;

                let ct1: Ciphertext = sk.try_encrypt(&pt1, &mut rng)?;
                let ct2: Ciphertext = sk.try_encrypt(&pt2, &mut rng)?;
                let ct3 = &ct1 * &ct2;
                let ct4 = &ct3 * &ct3;
                assert!(
                    ct3.iter()
                        .chain(ct4.iter())
                        .all(|poly| poly.allows_variable_time_computations())
                );

                let mut mixed = ct2.clone();
                mixed[0].disallow_variable_time_computations();
                let mixed_product = &ct1 * &mixed;
                assert!(
                    mixed_product
                        .iter()
                        .all(|poly| !poly.allows_variable_time_computations())
                );

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
    fn empty_accumulator_absorbs_ciphertext_multiplication_in_both_orders()
    -> Result<(), Box<dyn Error>> {
        let params = BfvParameters::default_arc(2, 16);
        let sk = SecretKey::random(&params, &mut rng());
        let zero = Ciphertext::zero(&params);

        for level in 0..=1 {
            let pt = Plaintext::try_encode(&[1u64][..], Encoding::poly_at_level(level), &params)?;
            let ct: Ciphertext = sk.try_encrypt(&pt, &mut rng())?;
            // The unmaterialized result has no context; its level is a placeholder.
            assert_eq!(&zero * &ct, zero);
            assert_eq!(&ct * &zero, zero);
            assert_eq!(&zero * &zero, zero);
        }
        Ok(())
    }

    #[test]
    fn empty_accumulator_multiplication_checks_parameter_identity() {
        let params = BfvParameters::default_arc(1, 16);
        let other_params = BfvParameters::default_arc(1, 16);
        assert_eq!(params, other_params);
        assert!(!std::sync::Arc::ptr_eq(&params, &other_params));
        let sk = SecretKey::random(&other_params, &mut rng());
        let pt = Plaintext::try_encode(&[1u64][..], Encoding::poly(), &other_params).unwrap();
        let ct: Ciphertext = sk.try_encrypt(&pt, &mut rng()).unwrap();
        assert!(std::panic::catch_unwind(|| &Ciphertext::zero(&params) * &ct).is_err());
        assert!(std::panic::catch_unwind(|| &ct * &Ciphertext::zero(&params)).is_err());
    }

    #[test]
    fn square() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 16);
        let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();
        for _ in 0..20 {
            // We will encode `values` in an Simd format, and check that the product is
            // computed correctly.
            let v = q.random_vec(params.degree(), &mut rng);
            let mut expected = v.clone();
            q.mul_vec(&mut expected, &v);

            let sk = SecretKey::random(&params, &mut rng);
            let pt = Plaintext::try_encode(&v, Encoding::simd(), &params)?;

            let ct1: Ciphertext = sk.try_encrypt(&pt, &mut rng)?;
            let ct2 = &ct1 * &ct1;

            println!("Noise: {}", unsafe { sk.measure_noise(&ct2)? });
            let pt = sk.try_decrypt(&ct2)?;
            assert_eq!(Vec::<u64>::try_decode(&pt, Encoding::simd())?, expected);
        }
        Ok(())
    }
}
