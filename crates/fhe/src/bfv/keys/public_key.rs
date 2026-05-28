//! Public keys for the BFV encryption scheme

use crate::bfv::traits::TryConvertFrom;
use crate::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext};
use crate::proto::bfv::{Ciphertext as CiphertextProto, PublicKey as PublicKeyProto};
use crate::{Error, Result, SerializationError};
use fhe_math::rq::{
    Ntt, Poly, PowerBasis, Representation, traits::TryConvertFrom as PolyTryConvertFrom,
};
use fhe_traits::{DeserializeParametrized, FheEncrypter, FheParametrized, Serialize};
use fhe_util::sample_vec_cbd_f32;
use prost::Message;
use rand::{CryptoRng, RngCore};
use std::borrow::Cow;
use std::sync::Arc;
use zeroize::Zeroizing;

use super::SecretKey;

/// Public key for the BFV encryption scheme.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKey {
    /// The BFV parameters
    pub par: Arc<BfvParameters>,
    /// The public key ciphertext
    pub c: Ciphertext,
}

impl PublicKey {
    /// Generate a new [`PublicKey`] from a [`SecretKey`].
    pub fn new<R: RngCore + CryptoRng>(sk: &SecretKey, rng: &mut R) -> Self {
        let zero = Plaintext::zero(Encoding::poly(), &sk.par).unwrap();
        let mut c: Ciphertext = sk.try_encrypt(&zero, rng).unwrap();
        // The polynomials of a public key should not allow for variable time
        // computation.
        c.iter_mut()
            .for_each(|p| p.disallow_variable_time_computations());
        Self {
            par: sk.par.clone(),
            c,
        }
    }

    /// Generate a new [`PublicKey`] and return all components for testing.
    ///
    /// Returns: (public_key, a, s, e)
    /// where:
    /// - `a` is the random polynomial
    /// - `s` is the secret key as a polynomial in NTT representation
    /// - `e` is the error polynomial
    pub fn new_extended<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        rng: &mut R,
    ) -> Result<(Self, Poly<Ntt>, Poly<Ntt>, Poly<Ntt>)> {
        let zero = Plaintext::zero(Encoding::poly(), &sk.par)?;
        let zero_poly = Zeroizing::new(zero.to_poly());

        let (mut c, a, e) = sk.encrypt_poly_extended(zero_poly.as_ref(), rng)?;

        let s =
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), c[0].ctx(), false)?.into_ntt();

        c.iter_mut()
            .for_each(|p| p.disallow_variable_time_computations());

        let pk = Self {
            par: sk.par.clone(),
            c,
        };

        Ok((pk, a, s, e))
    }

    /// Encrypt a plaintext with the public key and return the noise polynomials.
    ///
    /// This extended version returns the noise polynomials (u, e1, e2) used during encryption,
    /// which can be useful for debugging or verification purposes.
    pub fn try_encrypt_extended<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<(Ciphertext, Poly<Ntt>, Poly<Ntt>, Poly<Ntt>)> {
        let mut ct = self.c.clone();
        while ct.level != pt.level {
            ct.switch_down()?;
        }

        let ctx = self.par.context_at_level(ct.level)?.clone();

        let u_coefficients = Zeroizing::new(
            sample_vec_cbd_f32(ctx.degree, SecretKey::SK_VARIANCE, rng)
                .map_err(|e| Error::UnspecifiedInput(e.to_string()))?,
        );
        let u = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(u_coefficients.as_ref() as &[i64], &ctx, false)?
                .into_ntt(),
        );

        let e2 = Zeroizing::new(Poly::<Ntt>::small(&ctx, self.par.variance, rng)?);
        let e1 = Zeroizing::new(Poly::<Ntt>::error_1(
            &ctx,
            Representation::Ntt,
            &self.par.error1_variance,
            rng,
        )?);

        let m = Zeroizing::new(pt.to_poly());

        let u_copy = u.as_ref().clone();
        let e1_copy = e1.as_ref().clone();
        let e2_copy = e2.as_ref().clone();

        let mut c0 = u.as_ref() * &ct[0];
        c0 += e1.as_ref();
        c0 += &m;
        let mut c1 = u.as_ref() * &ct[1];
        c1 += e2.as_ref();

        unsafe {
            c0.allow_variable_time_computations();
            c1.allow_variable_time_computations()
        }

        let ciphertext = Ciphertext {
            par: self.par.clone(),
            seed: None,
            c: vec![c0, c1],
            level: ct.level,
        };

        Ok((ciphertext, u_copy, e1_copy, e2_copy))
    }
}

impl FheParametrized for PublicKey {
    type Parameters = BfvParameters;
}

impl FheEncrypter<Plaintext, Ciphertext> for PublicKey {
    type Error = Error;

    /// Encrypt a plaintext using the public key.
    ///
    /// This method uses the configured error1_variance for the e1 noise term,
    /// which allows it to support both standard BFV (when error1_variance = variance)
    /// and threshold BFV (when error1_variance is set to a larger value).
    fn try_encrypt<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<Ciphertext> {
        let needs_switch = self.c.level != pt.level;
        let ct: Cow<'_, Ciphertext> = if needs_switch {
            let mut owned = self.c.clone();
            while owned.level != pt.level {
                owned.switch_down()?;
            }
            Cow::Owned(owned)
        } else {
            Cow::Borrowed(&self.c)
        };

        let ctx = self.par.context_at_level(ct.level)?.clone();

        let u_coefficients = Zeroizing::new(
            sample_vec_cbd_f32(ctx.degree, SecretKey::SK_VARIANCE, rng)
                .map_err(|e| Error::UnspecifiedInput(e.to_string()))?,
        );
        let u = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(u_coefficients.as_ref() as &[i64], &ctx, false)?
                .into_ntt(),
        );

        let e2 = Zeroizing::new(Poly::<Ntt>::small(&ctx, self.par.variance, rng)?);
        let e1 = Zeroizing::new(Poly::<Ntt>::error_1(
            &ctx,
            Representation::Ntt,
            &self.par.error1_variance,
            rng,
        )?);

        let m = Zeroizing::new(pt.to_poly());
        let mut c0 = u.as_ref() * &ct[0];
        c0 += e1.as_ref();
        c0 += &m;
        let mut c1 = u.as_ref() * &ct[1];
        c1 += e2.as_ref();

        unsafe {
            c0.allow_variable_time_computations();
            c1.allow_variable_time_computations()
        }

        Ok(Ciphertext {
            par: self.par.clone(),
            seed: None,
            c: vec![c0, c1],
            level: ct.level,
        })
    }
}

impl From<&PublicKey> for PublicKeyProto {
    fn from(pk: &PublicKey) -> Self {
        PublicKeyProto {
            c: Some(CiphertextProto::from(&pk.c)),
        }
    }
}

impl Serialize for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        PublicKeyProto::from(self).encode_to_vec()
    }
}

impl DeserializeParametrized for PublicKey {
    type Error = Error;

    fn from_bytes(bytes: &[u8], par: &Arc<Self::Parameters>) -> Result<Self> {
        let proto: PublicKeyProto = Message::decode(bytes).map_err(|_| {
            Error::SerializationError(SerializationError::ProtobufError {
                message: "PublicKey decode".into(),
            })
        })?;
        if let Some(proto_c) = &proto.c {
            let mut c = Ciphertext::try_convert_from(proto_c, par)?;
            if c.level != 0 {
                Err(Error::SerializationError(
                    SerializationError::InvalidFormat {
                        reason: "ciphertext level must be 0".into(),
                    },
                ))
            } else {
                c.iter_mut()
                    .for_each(|p| p.disallow_variable_time_computations());
                Ok(Self {
                    par: par.clone(),
                    c,
                })
            }
        } else {
            Err(Error::SerializationError(
                SerializationError::MissingField {
                    field_name: "c".into(),
                },
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PublicKey;
    use crate::bfv::{
        Encoding, Plaintext, SecretKey,
        parameters::{BfvParameters, BfvParametersBuilder},
    };
    use fhe_math::rq::{Poly, PowerBasis, traits::TryConvertFrom};
    use fhe_traits::{DeserializeParametrized, FheDecrypter, FheEncoder, FheEncrypter, Serialize};
    use num_bigint::BigUint;
    use rand::rng;
    use std::error::Error;

    #[test]
    fn keygen() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        assert_eq!(pk.par, params);
        assert_eq!(
            sk.try_decrypt(&pk.c)?,
            Plaintext::zero(Encoding::poly(), &params)?
        );
        Ok(())
    }

    #[test]
    fn encrypt_decrypt() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 16),
        ] {
            for level in 0..params.max_level() {
                for _ in 0..20 {
                    let sk = SecretKey::random(&params, &mut rng);
                    let pk = PublicKey::new(&sk, &mut rng);

                    let pt = Plaintext::try_encode(
                        &fhe_math::zq::Modulus::new(params.plaintext())
                            .unwrap()
                            .random_vec(params.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &params,
                    )?;
                    let ct = pk.try_encrypt(&pt, &mut rng)?;
                    let pt2 = sk.try_decrypt(&ct)?;

                    println!("Noise: {}", unsafe { sk.measure_noise(&ct)? });
                    assert_eq!(pt2, pt);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn test_serialize() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 16),
        ] {
            let sk = SecretKey::random(&params, &mut rng);
            let pk = PublicKey::new(&sk, &mut rng);
            let bytes = pk.to_bytes();
            assert_eq!(pk, PublicKey::from_bytes(&bytes, &params)?);
        }
        Ok(())
    }

    #[test]
    fn encrypt_decrypt_default_variance() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let q = fhe_math::zq::Modulus::new(params.plaintext())?;

        let pt = Plaintext::try_encode(
            &q.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;

        let ct = pk.try_encrypt(&pt, &mut rng)?;
        let pt2 = sk.try_decrypt(&ct)?;

        println!("Noise (default variance): {}", unsafe {
            sk.measure_noise(&ct)?
        });
        assert_eq!(pt2, pt);
        assert_eq!(
            params.get_error1_variance(),
            &BigUint::from(params.variance())
        );

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_custom_error1_variance() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();

        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62usize; 1])
            .set_variance(10)
            .set_error1_variance_usize(15)
            .build_arc()?;

        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let q = fhe_math::zq::Modulus::new(params.plaintext())?;

        let pt = Plaintext::try_encode(
            &q.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;

        let ct = pk.try_encrypt(&pt, &mut rng)?;
        let pt2 = sk.try_decrypt(&ct)?;

        println!("Noise (custom error1_variance): {}", unsafe {
            sk.measure_noise(&ct)?
        });
        assert_eq!(pt2, pt);
        assert_eq!(params.get_error1_variance(), &BigUint::from(15u32));
        assert_eq!(params.variance(), 10);

        Ok(())
    }

    #[test]
    fn extended_encrypt_returns_noise_polynomials() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let q = fhe_math::zq::Modulus::new(params.plaintext())?;

        let pt = Plaintext::try_encode(
            &q.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;

        let (ct, _u, _e1, _e2) = pk.try_encrypt_extended(&pt, &mut rng)?;
        let pt2 = sk.try_decrypt(&ct)?;

        println!("Extended encryption - noise polynomials returned successfully");
        assert_eq!(pt2, pt);

        Ok(())
    }

    #[test]
    fn threshold_bfv_with_large_error1_variance() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();

        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62usize; 1])
            .set_variance(10)
            .set_error1_variance_usize(20)
            .build_arc()?;

        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let q = fhe_math::zq::Modulus::new(params.plaintext())?;

        let pt = Plaintext::try_encode(
            &q.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;

        let ct = pk.try_encrypt(&pt, &mut rng)?;
        let pt2 = sk.try_decrypt(&ct)?;

        println!("Threshold BFV with large error1_variance: {}", unsafe {
            sk.measure_noise(&ct)?
        });
        assert_eq!(pt2, pt);
        assert_eq!(params.get_error1_variance(), &BigUint::from(20u32));

        Ok(())
    }

    #[test]
    fn standard_vs_threshold_bfv() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();

        let params_standard = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62usize; 1])
            .set_variance(10)
            .build_arc()?;

        let params_threshold = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62usize; 1])
            .set_variance(10)
            .set_error1_variance_usize(15)
            .build_arc()?;

        assert_eq!(
            params_standard.get_error1_variance(),
            &BigUint::from(params_standard.variance())
        );

        assert_eq!(
            params_threshold.get_error1_variance(),
            &BigUint::from(15u32)
        );
        assert_eq!(params_threshold.variance(), 10);
        assert_ne!(
            params_threshold.get_error1_variance(),
            &BigUint::from(params_threshold.variance())
        );

        for params in [params_standard, params_threshold] {
            let sk = SecretKey::random(&params, &mut rng);
            let pk = PublicKey::new(&sk, &mut rng);
            let q = fhe_math::zq::Modulus::new(params.plaintext())?;

            let pt = Plaintext::try_encode(
                &q.random_vec(params.degree(), &mut rng),
                Encoding::poly(),
                &params,
            )?;

            let ct = pk.try_encrypt(&pt, &mut rng)?;
            let pt2 = sk.try_decrypt(&ct)?;

            assert_eq!(pt2, pt);
        }

        Ok(())
    }

    #[test]
    fn test_new_extended() -> Result<(), Box<dyn Error>> {
        use fhe_math::rq::Representation;

        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);

        let sk = SecretKey::random(&params, &mut rng);

        let (pk, a, s, e) = PublicKey::new_extended(&sk, &mut rng)?;

        assert_eq!(pk.par, params);
        assert_eq!(pk.c.par, params);
        assert_eq!(pk.c.len(), 2);
        assert_eq!(pk.c[1].coefficients(), a.coefficients());
        assert_eq!(pk.c[1].ctx(), a.ctx());
        assert_eq!(s.representation(), Representation::Ntt);

        let b = &pk.c[0];
        let mut a_s = a.clone();
        a_s *= &s;
        let mut expected_b = e.clone();
        expected_b -= &a_s;

        assert_eq!(
            b.coefficients(),
            expected_b.coefficients(),
            "Public key equation b = e - a*s should hold"
        );

        let plaintext = Plaintext::zero(Encoding::poly(), &params)?;
        let ciphertext = pk.try_encrypt(&plaintext, &mut rng)?;
        let pt2 = sk.try_decrypt(&ciphertext)?;
        assert_eq!(pt2, plaintext);

        assert_eq!(e.representation(), Representation::Ntt);
        assert_eq!(a.representation(), Representation::Ntt);

        let s_check =
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), b.ctx(), false)?.into_ntt();
        assert_eq!(
            s.coefficients(),
            s_check.coefficients(),
            "Returned secret key polynomial should match original"
        );

        Ok(())
    }

    #[test]
    fn test_new_vs_new_extended_consistency() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);

        let sk = SecretKey::random(&params, &mut rng);

        let pk1 = PublicKey::new(&sk, &mut rng);
        let (pk2, _, _, _) = PublicKey::new_extended(&sk, &mut rng)?;

        assert_eq!(pk1.par, pk2.par);
        assert_eq!(pk1.c.len(), 2);
        assert_eq!(pk2.c.len(), 2);

        let plaintext = Plaintext::zero(Encoding::poly(), &params)?;

        let ct1 = pk1.try_encrypt(&plaintext, &mut rng)?;
        let ct2 = pk2.try_encrypt(&plaintext, &mut rng)?;

        let dec1 = sk.try_decrypt(&ct1)?;
        let dec2 = sk.try_decrypt(&ct2)?;

        assert_eq!(dec1, plaintext);
        assert_eq!(dec2, plaintext);

        Ok(())
    }

    #[test]
    fn test_new_extended_security_properties() -> Result<(), Box<dyn Error>> {
        use fhe_math::rq::Representation;

        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);

        let (_pk, a, s, e) = PublicKey::new_extended(&sk, &mut rng)?;

        assert_eq!(a.representation(), Representation::Ntt);
        assert_eq!(s.representation(), Representation::Ntt);
        assert_eq!(e.representation(), Representation::Ntt);

        let mut s_squared = s.clone();
        s_squared *= &s;
        assert_eq!(s_squared.representation(), Representation::Ntt);

        Ok(())
    }
}
