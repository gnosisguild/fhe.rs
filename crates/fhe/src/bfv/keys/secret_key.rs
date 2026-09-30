//! Secret keys for the BFV encryption scheme

use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::proto::bfv::SecretKey as SecretKeyProto;
use crate::{Error, Result, SerializationError};
use fhe_math::{
    rq::{Ntt, Poly, PowerBasis, traits::TryConvertFrom},
    zq::Modulus,
};
use fhe_traits::{DeserializeParametrized, FheDecrypter, FheEncrypter, FheParametrized, Serialize};
use fhe_util::sample_vec_cbd_f32;
use itertools::Itertools;
use num_bigint::BigUint;
use prost::Message;
use rand::{CryptoRng, Rng as RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Secret key for the BFV encryption scheme.
#[derive(PartialEq, Eq, Clone)]
pub struct SecretKey {
    /// The BFV parameters
    pub(crate) params: Arc<BfvParameters>,
    /// The secret key coefficients. Operations validate that the length still
    /// matches the parameter degree after caller mutation.
    pub coeffs: Box<[i64]>,
}

// Redacted `Debug` so that `{:?}` never leaks the secret coefficients.
impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("params", &self.params)
            .field("coeffs", &"<redacted>")
            .finish()
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SecretKey {
    /// The variance used for secret key sampling
    pub const SK_VARIANCE: f32 = 0.5;

    /// Get the secret key bound (2 * variance).
    #[must_use]
    pub fn sk_bound() -> f32 {
        2.0 * Self::SK_VARIANCE
    }

    /// Generate a random [`SecretKey`].
    #[must_use]
    pub fn random<R: RngCore + CryptoRng>(params: &Arc<BfvParameters>, rng: &mut R) -> Self {
        let s_coefficients = sample_vec_cbd_f32(params.degree(), Self::SK_VARIANCE, rng).unwrap();
        Self::new(s_coefficients, params).unwrap()
    }

    /// Construct a secret key with exactly one coefficient per ring degree.
    ///
    /// # Errors
    /// Returns [`crate::SecretKeyError::InvalidCoefficientCount`] for a wrong
    /// length. Rejected coefficients are wiped before being dropped.
    ///
    /// # Security
    /// Coefficient magnitudes are not restricted: aggregated keys need not be
    /// ternary. The caller must ensure their distribution and bounds satisfy
    /// the security assumptions and noise budget of the chosen parameters.
    pub fn new(coeffs: Vec<i64>, params: &Arc<BfvParameters>) -> Result<Self> {
        let mut coeffs = Zeroizing::new(coeffs);
        Self::validate_coefficient_count(coeffs.len(), params.degree())?;
        // Boxing can shrink an overallocated vector and free an unwiped
        // buffer. In that case, copy into the final owner and wipe the input.
        let coeffs = if coeffs.capacity() == coeffs.len() {
            std::mem::take(&mut *coeffs).into_boxed_slice()
        } else {
            Box::from(coeffs.as_slice())
        };
        Ok(Self {
            params: params.to_owned(),
            coeffs,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        Self::validate_coefficient_count(self.coeffs.len(), self.params.degree())
    }

    fn validate_coefficient_count(actual: usize, expected: usize) -> Result<()> {
        if actual != expected {
            return Err(crate::SecretKeyError::InvalidCoefficientCount { actual, expected }.into());
        }
        Ok(())
    }

    /// Measure the noise in a [`Ciphertext`].
    ///
    /// # Safety
    ///
    /// This operations may run in a variable time depending on the value of the
    /// noise.
    pub unsafe fn measure_noise(&self, ct: &Ciphertext) -> Result<usize> {
        self.validate()?;
        let plaintext = Zeroizing::new(self.try_decrypt(ct)?);
        let m = Zeroizing::new(plaintext.to_poly()?);

        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(self.coeffs.as_ref(), ct[0].ctx(), false)?
                .into_ntt(),
        );
        let mut si = s.clone();

        let mut c = Zeroizing::new(ct[0].clone());
        c.disallow_variable_time_computations();

        for i in 1..ct.len() {
            let mut cis = Zeroizing::new(ct[i].clone());
            cis.disallow_variable_time_computations();
            *cis.as_mut() *= si.as_ref();
            *c.as_mut() += &cis;
            *si.as_mut() *= s.as_ref();
        }
        *c.as_mut() -= &m;
        let ctx = c.ctx().clone();
        let c_inner = std::mem::replace(c.as_mut(), Poly::<Ntt>::zero(&ctx));
        let c = Zeroizing::new(c_inner.into_power_basis());

        let ciphertext_modulus = ct[0].ctx().modulus();
        let mut noise = 0usize;
        for coeff in Vec::<BigUint>::try_from(c.as_ref())? {
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
        p: &Poly<Ntt>,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Result<Ciphertext> {
        self.validate()?;
        let level = self.params.level_of_context(p.ctx())?;

        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(self.coeffs.as_ref(), p.ctx(), false)?.into_ntt(),
        );

        let mut a = Poly::<Ntt>::random_from_seed(p.ctx(), seed);
        let a_s = Zeroizing::new(&a * s.as_ref());

        let mut b =
            Poly::<Ntt>::small(p.ctx(), self.params.variance, rng).map_err(Error::MathError)?;
        b -= &a_s;
        b += p;

        // It is now safe to enable variable time computations.
        let variable_time = fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
        a.allow_variable_time_computations(variable_time);
        b.allow_variable_time_computations(variable_time);

        Ok(Ciphertext {
            params: self.params.clone(),
            seed: Some(seed),
            c: vec![b, a],
            level,
        })
    }

    /// Encrypt a plaintext using a provided seed and return zeroizing `a` and `e` intermediates.
    #[allow(clippy::type_complexity)]
    pub(crate) fn encrypt_poly_with_seed_extended<R: RngCore + CryptoRng>(
        &self,
        p: &Poly<Ntt>,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Result<(Ciphertext, Zeroizing<Poly<Ntt>>, Zeroizing<Poly<Ntt>>)> {
        self.validate()?;
        let level = self.params.level_of_context(p.ctx())?;

        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(self.coeffs.as_ref(), p.ctx(), false)?.into_ntt(),
        );

        let mut a = Poly::<Ntt>::random_from_seed(p.ctx(), seed);
        let a_s = Zeroizing::new(&a * s.as_ref());

        let e = Zeroizing::new(
            Poly::<Ntt>::small(p.ctx(), self.params.variance, rng).map_err(Error::MathError)?,
        );

        let a_copy = Zeroizing::new(a.clone());

        let mut b = e.as_ref().clone();
        b -= &a_s;
        b += p;

        let variable_time = fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
        a.allow_variable_time_computations(variable_time);
        b.allow_variable_time_computations(variable_time);

        let ct = Ciphertext {
            params: self.params.clone(),
            seed: Some(seed),
            c: vec![b, a],
            level,
        };

        Ok((ct, a_copy, e))
    }

    /// Encrypt a plaintext using a random seed for deterministic generation
    /// of random polynomials aᵢ.
    pub(crate) fn encrypt_poly<R: RngCore + CryptoRng>(
        &self,
        p: &Poly<Ntt>,
        rng: &mut R,
    ) -> Result<Ciphertext> {
        self.validate()?;
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);

        self.encrypt_poly_with_seed(p, seed, rng)
    }

    /// Encrypt a plaintext using a random seed and return zeroizing `a` and `e` intermediates.
    #[allow(clippy::type_complexity)]
    pub(crate) fn encrypt_poly_extended<R: RngCore + CryptoRng>(
        &self,
        p: &Poly<Ntt>,
        rng: &mut R,
    ) -> Result<(Ciphertext, Zeroizing<Poly<Ntt>>, Zeroizing<Poly<Ntt>>)> {
        self.validate()?;
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);

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
        pt.validate_for(&self.params)?;
        let m = Zeroizing::new(pt.to_poly()?);
        self.encrypt_poly_with_seed(m.as_ref(), seed, rng)
    }
}

impl From<&SecretKey> for SecretKeyProto {
    fn from(sk: &SecretKey) -> Self {
        Self {
            coeffs: sk.coeffs.to_vec(),
        }
    }
}

impl Serialize for SecretKey {
    fn to_bytes(&self) -> Vec<u8> {
        SecretKeyProto::from(self).encode_to_vec()
    }
}

impl DeserializeParametrized for SecretKey {
    type Error = Error;

    /// Decode a secret key. Wrong coefficient counts are reported as
    /// [`SerializationError::InvalidSecretKeyCoefficientCount`] at this wire
    /// boundary; [`SecretKey::new`] and in-memory validation instead use
    /// [`crate::SecretKeyError::InvalidCoefficientCount`].
    fn from_bytes(bytes: &[u8], params: &Arc<Self::Parameters>) -> Result<Self> {
        let proto: SecretKeyProto =
            crate::serialization::decode(bytes, crate::SerializedObject::SecretKey)?;

        if proto.coeffs.len() != params.degree() {
            return Err(Error::SerializationError(
                SerializationError::InvalidSecretKeyCoefficientCount {
                    actual: proto.coeffs.len(),
                    expected: params.degree(),
                },
            ));
        }

        Ok(Self {
            params: params.clone(),
            coeffs: proto.coeffs.into_boxed_slice(),
        })
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
        pt.validate_for(&self.params)?;
        let m = Zeroizing::new(pt.to_poly()?);
        self.encrypt_poly(m.as_ref(), rng)
    }
}

impl FheDecrypter<Plaintext, Ciphertext> for SecretKey {
    type Error = Error;

    fn try_decrypt(&self, ct: &Ciphertext) -> Result<Plaintext> {
        self.validate()?;
        ct.validate_for(&self.params)?;
        self.params.validate_plaintext_level(ct.level)?;
        // Let's create a secret key with the ciphertext context
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(self.coeffs.as_ref(), ct[0].ctx(), false)?
                .into_ntt(),
        );
        let mut si = s.clone();

        let mut c = Zeroizing::new(ct[0].clone());
        c.disallow_variable_time_computations();

        // Compute the phase c0 + c1*s + c2*s^2 + ... where the secret power
        // s^k is computed on-the-fly
        for i in 1..ct.len() {
            let mut cis = Zeroizing::new(ct[i].clone());
            cis.disallow_variable_time_computations();
            *cis.as_mut() *= si.as_ref();
            *c.as_mut() += &cis;
            if i + 1 < ct.len() {
                *si.as_mut() *= s.as_ref();
            }
        }
        let ctx_lvl = self.params.context_level_at(ct.level)?;
        let ctx = c.ctx().clone();
        let c_inner = std::mem::replace(c.as_mut(), Poly::<Ntt>::zero(&ctx));
        let c_pb = Zeroizing::new(c_inner.into_power_basis());
        let d = Zeroizing::new(c_pb.as_ref().scale(&ctx_lvl.cipher_plain_context.scaler)?);

        let poly = match self.params.plaintext.small() {
            Some(plaintext_modulus) if self.params.u64_decrypt_fast_path_is_exact() => {
                let mut v = Vec::<u64>::try_from(d.as_ref())?;
                v.iter_mut().for_each(|vi| *vi += **plaintext_modulus);
                let mut w = v[..self.params.degree()].to_vec();

                let q = Modulus::new(self.params.moduli[0]).map_err(Error::MathError)?;
                q.reduce_vec(&mut w);
                plaintext_modulus.reduce_vec(&mut w);
                Poly::<PowerBasis>::try_convert_from(w.as_slice(), ct[0].ctx(), false)?.into_ntt()
            }
            _ => {
                // Reducing through q_0 is only exact for 2t <= q_0. Otherwise
                // (a small t above q_0 / 2 at a valid multi-modulus level)
                // reducing through q_0 loses information; lift through the
                // full plaintext context before reducing mod t.
                let v: Vec<BigUint> = Vec::<BigUint>::try_from(d.as_ref())?
                    .into_iter()
                    .map(|vi| vi + self.params.plaintext_big())
                    .collect_vec();

                let mut w = v[..self.params.degree()].to_vec();
                let q_poly = d.as_ref().ctx().modulus();
                w.iter_mut().for_each(|wi| *wi %= q_poly);

                self.params.plaintext.reduce_vec(&mut w);
                Poly::<PowerBasis>::try_convert_from(w.as_slice(), ct[0].ctx(), false)?.into_ntt()
            }
        };

        let pt = Plaintext {
            params: self.params.clone(),
            encoding: None,
            poly_ntt: poly,
        };

        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::SecretKey;
    use crate::bfv::{
        Ciphertext, Encoding, Plaintext, PublicKey,
        parameters::{BfvParameters, BfvParametersBuilder},
    };
    use crate::proto::bfv::SecretKey as SecretKeyProto;
    use fhe_traits::{
        DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
    };
    use prost::Message;
    use rand::{SeedableRng, rng};
    use rand_chacha::ChaCha8Rng;
    use std::error::Error;
    use zeroize::Zeroize;

    #[test]
    fn decrypt_lifts_through_plaintext_context_when_q0_below_2t() -> Result<(), Box<dyn Error>> {
        let mut rng = crate::support::presets::rng(239);

        // q0 = 1153 lies in (t, 2t) for t = 769: plaintext values near t wrap
        // when the scaled phase is reduced through q0 alone, so decryption must
        // lift through the plaintext context. The boundary complement keeps
        // 2t <= q0 and exercises the u64 fast path with a value near t.
        let wrap_params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(769)
            .set_moduli(&[1153, 12289])
            .build_arc()?;
        assert!(!wrap_params.u64_decrypt_fast_path_is_exact());
        let fast_params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(521)
            .set_moduli(&[1153, 12289])
            .build_arc()?;
        assert!(fast_params.u64_decrypt_fast_path_is_exact());
        // Common parameter shapes keep the fast path.
        assert!(BfvParameters::default_arc(1, 16).u64_decrypt_fast_path_is_exact());
        assert!(BfvParameters::default_arc(6, 16).u64_decrypt_fast_path_is_exact());

        for (params, values) in [
            (&wrap_params, vec![768u64; wrap_params.degree()]),
            (&fast_params, vec![520u64; fast_params.degree()]),
        ] {
            let sk = SecretKey::random(params, &mut rng);
            let pk = PublicKey::new(&sk, &mut rng)?;
            let pt = Plaintext::try_encode(&values, Encoding::poly(), params)?;
            let sk_ct: Ciphertext = sk.try_encrypt(&pt, &mut rng)?;
            assert_eq!(sk_ct.level, 0);
            assert_eq!(
                Vec::<u64>::try_decode(&sk.try_decrypt(&sk_ct)?, Encoding::poly())?,
                values
            );
            let pk_ct = pk.try_encrypt(&pt, &mut rng)?;
            assert_eq!(
                Vec::<u64>::try_decode(&sk.try_decrypt(&pk_ct)?, Encoding::poly())?,
                values
            );
        }

        Ok(())
    }

    #[test]
    fn extended_encryption_returns_zeroizing_intermediates() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let plaintext = Plaintext::zero(Encoding::poly(), &params)?;
        let (ct, mut a, mut e) = sk.encrypt_poly_extended(&plaintext.to_poly()?, &mut rng)?;

        assert_eq!(ct[1].coefficients(), a.coefficients());
        a.zeroize();
        e.zeroize();
        assert!(a.coefficients().iter().all(|&coefficient| coefficient == 0));
        assert!(e.coefficients().iter().all(|&coefficient| coefficient == 0));
        Ok(())
    }

    #[test]
    fn keygen() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 16);
        let sk = SecretKey::random(&params, &mut rng);
        assert_eq!(sk.params, params);

        sk.coeffs.iter().for_each(|ci: &i64| {
            let sk_variance = params.variance as f32 / 20.0;
            assert!((*ci).abs() as f32 <= 2.0 * sk_variance)
        })
    }

    #[test]
    fn debug_does_not_leak_coefficients() {
        // Use a distinctive sentinel value that will not appear in the params.
        let params = BfvParameters::default_arc(1, 16);
        let sk = SecretKey::new(vec![987654321i64; params.degree()], &params).unwrap();
        let debug = format!("{sk:?}");
        assert!(debug.contains("<redacted>"));
        assert!(
            !debug.contains("987654321"),
            "debug output leaked coefficients: {debug}"
        );
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
                    let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();

                    let pt = Plaintext::try_encode(
                        &q.random_vec(params.degree(), &mut rng),
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
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let q = fhe_math::zq::Modulus::new(params.plaintext())?;

        let pt = Plaintext::try_encode(
            &q.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;

        let seed = <ChaCha8Rng as SeedableRng>::Seed::default();

        let ct1 = sk.try_encrypt_with_seed(&pt, seed, &mut rng)?;
        let ct2 = sk.try_encrypt_with_seed(&pt, seed, &mut rng)?;

        assert_eq!(ct1[1], ct2[1]);
        assert_ne!(ct1[0], ct2[0]);

        let pt1 = sk.try_decrypt(&ct1)?;
        let pt2 = sk.try_decrypt(&ct2)?;
        assert_eq!(pt1, pt2);
        assert_eq!(pt1, pt);

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_reject_invalid_inputs() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 16);
        let other_params = BfvParameters::default_arc(1, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let other_pt = Plaintext::try_encode(&[1u64][..], Encoding::poly(), &other_params)?;
        let encrypted: crate::Result<crate::bfv::Ciphertext> = sk.try_encrypt(&other_pt, &mut rng);

        assert!(encrypted.is_err());
        assert!(matches!(
            sk.try_decrypt(&crate::bfv::Ciphertext::zero(&params)),
            Err(crate::Error::Ciphertext(_))
        ));
        Ok(())
    }

    #[test]
    fn measure_noise_within_modulus_bits() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let q = fhe_math::zq::Modulus::new(params.plaintext()).unwrap();

        let pt = Plaintext::try_encode(
            &q.random_vec(params.degree(), &mut rng),
            Encoding::poly_at_level(0),
            &params,
        )?;
        let ct = sk.try_encrypt(&pt, &mut rng)?;
        let noise = unsafe { sk.measure_noise(&ct)? };

        let modulus_bits = ct[0].ctx().modulus().bits() as usize;
        assert!(noise <= modulus_bits);

        Ok(())
    }

    #[test]
    fn measure_noise_rejects_invalid_secret_key_before_ciphertext_processing()
    -> Result<(), Box<dyn Error>> {
        let mut rng = crate::support::presets::rng(242);
        let params = BfvParameters::default_arc(1, 16);
        let mut sk = SecretKey::random(&params, &mut rng);
        let pt = Plaintext::zero(Encoding::poly(), &params)?;
        let ciphertext = sk.try_encrypt(&pt, &mut rng)?;
        let empty_ciphertext = Ciphertext::zero(&params);

        for actual in [0, params.degree() - 1, params.degree() + 1] {
            sk.coeffs = vec![0; actual].into_boxed_slice();
            for ct in [&ciphertext, &empty_ciphertext] {
                assert_eq!(
                    unsafe { sk.measure_noise(ct) }.unwrap_err(),
                    crate::Error::SecretKey(crate::SecretKeyError::InvalidCoefficientCount {
                        actual,
                        expected: params.degree(),
                    })
                );
            }
        }
        Ok(())
    }

    #[test]
    fn serialize_roundtrip() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(2, 16);
        let sk = SecretKey::random(&params, &mut rng);

        let bytes = sk.to_bytes();
        let decoded = SecretKey::from_bytes(&bytes, &params)?;

        assert_eq!(decoded, sk);
        Ok(())
    }

    #[test]
    fn coefficient_count_errors_distinguish_serialized_and_in_memory_keys() {
        let params = BfvParameters::default_arc(1, 16);
        let mut sk = SecretKey::new(vec![0; params.degree()], &params).unwrap();
        for actual in [0, params.degree() - 1, params.degree() + 1] {
            let proto = SecretKeyProto {
                coeffs: vec![0; actual],
            };
            let error = crate::Error::SecretKey(crate::SecretKeyError::InvalidCoefficientCount {
                actual,
                expected: params.degree(),
            });
            assert_eq!(
                SecretKey::new(proto.coeffs.clone(), &params).unwrap_err(),
                error
            );
            sk.coeffs = proto.coeffs.clone().into_boxed_slice();
            assert_eq!(sk.validate().unwrap_err(), error);
            assert_eq!(
                SecretKey::from_bytes(&proto.encode_to_vec(), &params).unwrap_err(),
                crate::Error::SerializationError(
                    crate::SerializationError::InvalidSecretKeyCoefficientCount {
                        actual,
                        expected: params.degree(),
                    }
                )
            );
        }
    }
}
