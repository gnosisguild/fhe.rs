//! Public keys for the BFV encryption scheme

use crate::bfv::traits::TryConvertFrom;
use crate::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext};
use crate::proto::bfv::{Ciphertext as CiphertextProto, PublicKey as PublicKeyProto};
use crate::{Error, Result};
use fhe_math::rq::traits::TryConvertFrom as TCF;
use fhe_math::rq::{Poly, Representation};
use fhe_traits::{DeserializeParametrized, FheEncrypter, FheParametrized, Serialize};
use prost::Message;
use rand::{CryptoRng, RngCore};
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
        c.c.iter_mut()
            .for_each(|p| p.disallow_variable_time_computations());
        Self {
            par: sk.par.clone(),
            c,
        }
    }
    /// Generate a new [`PublicKey`] and return all components.
    ///
    /// Returns: (public_key, a, secret_key_clone, e)
    pub fn new_extended<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        rng: &mut R,
    ) -> (Self, Poly, SecretKey, Poly) {
        let zero = Plaintext::zero(Encoding::poly(), &sk.par).unwrap();
        let zero_poly = Zeroizing::new(zero.to_poly());

        let (mut c, a, e) = sk.encrypt_poly_extended(zero_poly.as_ref(), rng).unwrap();

        // Disallow variable time computations for public key (same as new())
        c.c.iter_mut()
            .for_each(|p| p.disallow_variable_time_computations());

        let pk = Self {
            par: sk.par.clone(),
            c,
        };

        // a and e are already restricted (cloned before variable time was enabled)
        (pk, a, sk.clone(), e)
    }

    /// Encrypt a plaintext with the public key.
    /// The encryption is done in the same level as the plaintext.
    /// Returns the ciphertext and the noise polynomials.
    ///
    /// This extended version returns the noise polynomials (u, e1, e2) used during encryption,
    /// which can be useful for debugging or verification purposes.
    pub fn try_encrypt_extended<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<(Ciphertext, Poly, Poly, Poly)> {
        let mut ct = self.c.clone();
        while ct.level != pt.level {
            ct.mod_switch_to_next_level()?;
        }

        let ctx = self.par.ctx_at_level(ct.level)?;

        // Standard variance for u and e1
        let u = Poly::small(ctx, Representation::Ntt, self.par.variance, rng)?;
        let e1 = Poly::small(ctx, Representation::Ntt, self.par.variance, rng)?;

        // error2_variance for e2 (supports both standard and threshold BFV)
        let e2 = Poly::error_2(ctx, Representation::Ntt, &self.par.error2_variance, rng)?;

        let m = Zeroizing::new(pt.to_poly());
        let mut c0 = &u * &ct.c[0];
        c0 += &e1;
        c0 += &m;
        let mut c1 = &u * &ct.c[1];
        c1 += &e2;

        // It is now safe to enable variable time computations.
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

        Ok((ciphertext, u, e1, e2))
    }
}

impl FheParametrized for PublicKey {
    type Parameters = BfvParameters;
}

impl FheEncrypter<Plaintext, Ciphertext> for PublicKey {
    type Error = Error;

    /// Encrypt a plaintext using the public key.
    ///
    /// This method uses the configured error2_variance for the e2 noise term,
    /// which allows it to support both standard BFV (when error2_variance = variance)
    /// and threshold BFV (when error2_variance is set to a larger value).
    ///
    /// For standard BFV: Set only `variance` in parameters (error2_variance will match automatically)
    /// For threshold BFV: Explicitly set both `variance` and `error2_variance` in parameters
    fn try_encrypt<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<Ciphertext> {
        let mut ct = self.c.clone();
        while ct.level != pt.level {
            ct.mod_switch_to_next_level()?;
        }

        let ctx = self.par.ctx_at_level(ct.level)?;

        // Standard variance for u and e1
        let u = Zeroizing::new(Poly::small(
            ctx,
            Representation::Ntt,
            self.par.variance,
            rng,
        )?);
        let e1 = Zeroizing::new(Poly::small(
            ctx,
            Representation::Ntt,
            self.par.variance,
            rng,
        )?);

        // error2_variance for e2 (supports both standard and threshold BFV)
        let e2 = Zeroizing::new(Poly::error_2(
            ctx,
            Representation::Ntt,
            &self.par.error2_variance,
            rng,
        )?);

        let m = Zeroizing::new(pt.to_poly());
        let mut c0 = u.as_ref() * &ct.c[0];
        c0 += &e1;
        c0 += &m;
        let mut c1 = u.as_ref() * &ct.c[1];
        c1 += &e2;

        // It is now safe to enable variable time computations.
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
        let proto: PublicKeyProto =
            Message::decode(bytes).map_err(|_| Error::SerializationError)?;
        if proto.c.is_some() {
            let mut c = Ciphertext::try_convert_from(&proto.c.unwrap(), par)?;
            if c.level != 0 {
                Err(Error::SerializationError)
            } else {
                // The polynomials of a public key should not allow for variable time
                // computation.
                c.c.iter_mut()
                    .for_each(|p| p.disallow_variable_time_computations());
                Ok(Self {
                    par: par.clone(),
                    c,
                })
            }
        } else {
            Err(Error::SerializationError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PublicKey;
    use crate::bfv::{
        parameters::BfvParameters, parameters::BfvParametersBuilder, Encoding, Plaintext, SecretKey,
    };
    use fhe_math::rq::traits::TryConvertFrom;
    use fhe_traits::{DeserializeParametrized, FheDecrypter, FheEncoder, FheEncrypter, Serialize};
    use num_bigint::BigUint;
    use rand::thread_rng;
    use std::error::Error;

    #[test]
    fn keygen() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(1, 8);
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
        let mut rng = thread_rng();
        for params in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            for level in 0..params.max_level() {
                for _ in 0..20 {
                    let sk = SecretKey::random(&params, &mut rng);
                    let pk = PublicKey::new(&sk, &mut rng);

                    let pt = Plaintext::try_encode(
                        &params.plaintext.random_vec(params.degree(), &mut rng),
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
        let mut rng = thread_rng();
        for params in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
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
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let pt = Plaintext::try_encode(
            &params.plaintext.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;

        // Test with default error2_variance (should be same as variance)
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        let pt2 = sk.try_decrypt(&ct)?;

        println!("Noise (default variance): {}", unsafe {
            sk.measure_noise(&ct)?
        });
        assert_eq!(pt2, pt);
        // Verify that error2_variance matches variance by default
        assert_eq!(
            params.get_error2_variance(),
            &BigUint::from(params.variance())
        );

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_custom_error2_variance() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        // Create parameters with custom error2_variance for threshold BFV
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62usize; 1])
            .set_variance(10)
            .set_error2_variance_usize(15)
            .build_arc()?;

        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let pt = Plaintext::try_encode(
            &params.plaintext.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;

        // This should use the configured error2_variance (15)
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        let pt2 = sk.try_decrypt(&ct)?;

        println!("Noise (custom error2_variance): {}", unsafe {
            sk.measure_noise(&ct)?
        });
        assert_eq!(pt2, pt);
        assert_eq!(params.get_error2_variance(), &BigUint::from(15u32));
        assert_eq!(params.variance(), 10); // Original variance unchanged

        Ok(())
    }

    #[test]
    fn extended_encrypt_returns_noise_polynomials() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let pt = Plaintext::try_encode(
            &params.plaintext.random_vec(params.degree(), &mut rng),
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
    fn threshold_bfv_with_large_error2_variance() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        // Test with error2_variance >= 16 to trigger uniform distribution
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62usize; 1])
            .set_moduli_sizes(&[62usize; 1])
            .set_variance(10)
            .set_error2_variance_usize(20) // >= 16, will use uniform distribution
            .build_arc()?;

        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let pt = Plaintext::try_encode(
            &params.plaintext.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;

        // This should use uniform distribution for e2
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        let pt2 = sk.try_decrypt(&ct)?;

        println!("Threshold BFV with large error2_variance: {}", unsafe {
            sk.measure_noise(&ct)?
        });
        assert_eq!(pt2, pt);
        assert_eq!(params.get_error2_variance(), &BigUint::from(20u32));

        Ok(())
    }

    #[test]
    fn standard_vs_threshold_bfv() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        // Standard BFV: only set variance
        let params_standard = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62usize; 1])
            .set_variance(10)
            .build_arc()?;

        // Threshold BFV: explicitly set different error2_variance
        let params_threshold = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62usize; 1])
            .set_variance(10)
            .set_error2_variance_usize(15)
            .build_arc()?;

        // Verify standard BFV has matching variances
        assert_eq!(
            params_standard.get_error2_variance(),
            &BigUint::from(params_standard.variance())
        );

        // Verify threshold BFV has different variances
        assert_eq!(
            params_threshold.get_error2_variance(),
            &BigUint::from(15u32)
        );
        assert_eq!(params_threshold.variance(), 10);
        assert_ne!(
            params_threshold.get_error2_variance(),
            &BigUint::from(params_threshold.variance())
        );

        // Both should encrypt and decrypt correctly
        for params in [params_standard, params_threshold] {
            let sk = SecretKey::random(&params, &mut rng);
            let pk = PublicKey::new(&sk, &mut rng);

            let pt = Plaintext::try_encode(
                &params.plaintext.random_vec(params.degree(), &mut rng),
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
        use fhe_math::rq::{Poly, Representation};

        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(1, 8);

        let sk = SecretKey::random(&params, &mut rng);

        // Call new_extended
        let (pk, a, sk_returned, e) = PublicKey::new_extended(&sk, &mut rng);

        // Test 1: Verify the public key has correct parameters
        assert_eq!(pk.par, params);
        assert_eq!(pk.c.par, params);

        // Test 2: Verify the ciphertext has 2 components [b, a]
        assert_eq!(pk.c.c.len(), 2);

        // Test 3: Verify that second component matches `a` (compare coefficients using method)
        assert_eq!(pk.c.c[1].coefficients(), a.coefficients());
        assert_eq!(pk.c.c[1].ctx(), a.ctx());
        assert_eq!(pk.c.c[1].representation(), a.representation());

        // Test 4: Verify secret key is correctly cloned
        assert_eq!(sk_returned.coeffs, sk.coeffs);
        assert_eq!(sk_returned.par, sk.par);

        // Test 5: Verify that b = e - a*s (the core encryption equation)
        let b = &pk.c.c[0];

        // Create secret key in NTT representation
        let mut s = Poly::try_convert_from(
            sk.coeffs.as_ref(),
            b.ctx(),
            false,
            Representation::PowerBasis,
        )?;
        s.change_representation(Representation::Ntt);

        // Compute a * s
        let mut a_s = a.clone();
        a_s *= &s;

        // Compute e - a*s
        let mut expected_b = e.clone();
        expected_b -= &a_s;

        // Compare coefficients using method (semantic equality)
        assert_eq!(
            b.coefficients(),
            expected_b.coefficients(),
            "Public key equation b = e - a*s should hold"
        );

        // Test 6: Verify the public key can actually encrypt
        let plaintext = Plaintext::zero(Encoding::poly(), &params)?;
        let ciphertext = pk.try_encrypt(&plaintext, &mut rng)?;

        // Test 7: Verify decryption works with the secret key
        let pt2 = sk.try_decrypt(&ciphertext)?;
        assert_eq!(pt2, plaintext);

        // Test 8: Verify error polynomial has correct representation
        assert_eq!(e.representation(), &Representation::Ntt);

        // Test 9: Verify `a` has correct representation
        assert_eq!(a.representation(), &Representation::Ntt);

        // Note: We cannot directly test allow_variable_time_computations flag
        // as it's a private field without a getter method. However, the implementation
        // maintains the security properties as documented.

        println!("✓ All tests passed!");
        println!("  - Public key generated successfully");
        println!("  - Extracted components: a, sk, e");
        println!("  - Verified encryption equation: b = e - a*s");
        println!("  - Encryption/decryption working correctly");

        Ok(())
    }

    #[test]
    fn test_new_vs_new_extended_consistency() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(1, 8);

        let sk = SecretKey::random(&params, &mut rng);

        // Generate using both methods
        let pk1 = PublicKey::new(&sk, &mut rng);
        let (pk2, _, _, _) = PublicKey::new_extended(&sk, &mut rng);

        // Both should have same parameters
        assert_eq!(pk1.par, pk2.par);

        // Both should produce valid ciphertexts with 2 components
        assert_eq!(pk1.c.c.len(), 2);
        assert_eq!(pk2.c.c.len(), 2);

        // Both should be able to encrypt
        let plaintext = Plaintext::zero(Encoding::poly(), &params)?;

        let ct1 = pk1.try_encrypt(&plaintext, &mut rng)?;
        let ct2 = pk2.try_encrypt(&plaintext, &mut rng)?;

        // Both ciphertexts should decrypt correctly
        let dec1 = sk.try_decrypt(&ct1)?;
        let dec2 = sk.try_decrypt(&ct2)?;

        assert_eq!(dec1, plaintext);
        assert_eq!(dec2, plaintext);

        println!("✓ Consistency test passed!");
        println!("  - new() and new_extended() produce compatible keys");

        Ok(())
    }
}
