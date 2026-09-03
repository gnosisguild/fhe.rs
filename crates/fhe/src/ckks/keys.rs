//! Secret and public keys for the CKKS encryption scheme.

use crate::ckks::{CkksCiphertext, CkksParameters, CkksPlaintext};
use crate::proto::ckks::{PublicKey as PublicKeyProto, SecretKey as SecretKeyProto};
use crate::{Error, Result, SerializationError};
use fhe_math::rq::{Ntt, Poly, PowerBasis, traits::TryConvertFrom};
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, FheParametrized, Serialize};
use fhe_util::sample_vec_cbd_f32;
use prost::Message;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Secret key for the CKKS encryption scheme.
#[derive(PartialEq, Clone)]
pub struct CkksSecretKey {
    /// The CKKS parameters.
    pub(crate) par: Arc<CkksParameters>,
    /// The secret key coefficients (small, ternary-like from CBD sampling).
    pub coeffs: Box<[i64]>,
}

impl std::fmt::Debug for CkksSecretKey {
    /// Manual impl: NEVER print the secret coefficients (a derived Debug
    /// would leak the key into logs and error messages).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksSecretKey")
            .field("par", &self.par)
            .field("coeffs", &"<redacted>")
            .finish()
    }
}

impl Zeroize for CkksSecretKey {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

impl Drop for CkksSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl CkksSecretKey {
    /// The variance used for secret key sampling (matches BFV).
    pub const SK_VARIANCE: f32 = 0.5;

    /// Get the secret key bound (2 * variance).
    #[must_use]
    pub fn sk_bound() -> f32 {
        2.0 * Self::SK_VARIANCE
    }

    /// Generate a random [`CkksSecretKey`].
    #[must_use]
    pub fn random<R: RngCore + CryptoRng>(par: &Arc<CkksParameters>, rng: &mut R) -> Self {
        let coeffs = sample_vec_cbd_f32(par.degree(), Self::SK_VARIANCE, rng).unwrap();
        Self::new(coeffs, par)
    }

    /// Generate a [`CkksSecretKey`] from its coefficients.
    #[must_use]
    pub fn new(coeffs: Vec<i64>, par: &Arc<CkksParameters>) -> Self {
        Self {
            par: par.to_owned(),
            coeffs: coeffs.into_boxed_slice(),
        }
    }

    /// The secret key as a polynomial in NTT representation at the
    /// ciphertext's context.
    fn s_poly(&self, ct_ctx: &Arc<fhe_math::rq::Context>) -> Result<Poly<Ntt>> {
        Ok(Poly::<PowerBasis>::try_convert_from(self.coeffs.as_ref(), ct_ctx, false)?.into_ntt())
    }

    /// Decrypt a ciphertext.
    ///
    /// Returns the plaintext `c0 + c1*s (+ c2*s^2 + ...)`, which equals
    /// `delta*m + e` for a fresh ciphertext: the caller decodes it with
    /// [`crate::ckks::CkksEncoder::decode`], dividing by the carried scale.
    /// Decryption is approximate; the noise `e` remains in the result.
    pub fn try_decrypt(&self, ct: &CkksCiphertext) -> Result<CkksPlaintext> {
        if self.par != ct.par {
            return Err(Error::DefaultError(
                "Incompatible CKKS parameters".to_string(),
            ));
        }
        let s = Zeroizing::new(self.s_poly(ct[0].ctx())?);
        let mut si = s.clone();

        let mut c = Zeroizing::new(ct[0].clone());
        c.disallow_variable_time_computations();

        for i in 1..ct.len() {
            let mut cis = Zeroizing::new(ct[i].clone());
            cis.disallow_variable_time_computations();
            *cis.as_mut() *= si.as_ref();
            *c.as_mut() += &cis;
            if i + 1 < ct.len() {
                *si.as_mut() *= s.as_ref();
            }
        }

        let ctx = c.ctx().clone();
        let poly = std::mem::replace(c.as_mut(), Poly::<Ntt>::zero(&ctx));

        Ok(CkksPlaintext {
            par: self.par.clone(),
            poly,
            scale: ct.scale,
            level: ct.level,
        })
    }
}

/// Public key for the CKKS encryption scheme.
///
/// The key is a pair `(pk0, pk1) = (-a*s + e, a)`, i.e. an encryption of
/// zero under the secret key.
#[derive(Debug, PartialEq, Clone)]
pub struct CkksPublicKey {
    /// The CKKS parameters.
    pub par: Arc<CkksParameters>,
    /// The public key polynomials `(pk0, pk1)`.
    pub c: Vec<Poly<Ntt>>,
}

impl CkksPublicKey {
    /// Generate a new [`CkksPublicKey`] from a [`CkksSecretKey`].
    pub fn new<R: RngCore + CryptoRng>(sk: &CkksSecretKey, rng: &mut R) -> Result<Self> {
        let ctx = sk.par.context_at_level(0)?;

        let s = Zeroizing::new(sk.s_poly(ctx)?);
        let a = Poly::<Ntt>::random(ctx, rng);
        let a_s = Zeroizing::new(&a * s.as_ref());

        let e = Zeroizing::new(
            Poly::<Ntt>::small(ctx, sk.par.variance, rng).map_err(Error::MathError)?,
        );

        let mut pk0 = e.as_ref().clone();
        pk0 -= &a_s;

        let mut c = vec![pk0, a];
        c.iter_mut()
            .for_each(|p| p.disallow_variable_time_computations());

        Ok(Self {
            par: sk.par.clone(),
            c,
        })
    }

    /// Encrypt a plaintext with the public key.
    ///
    /// `ct = (pk0*u + e0 + pt, pk1*u + e1)`, matching the relation proven by
    /// Greco-style encryption circuits (without BFV's `k1*k0i` term, since
    /// the scaled message enters the ciphertext directly).
    pub fn try_encrypt<R: RngCore + CryptoRng>(
        &self,
        pt: &CkksPlaintext,
        rng: &mut R,
    ) -> Result<CkksCiphertext> {
        let (ct, _, _, _) = self.try_encrypt_extended(pt, rng)?;
        Ok(ct)
    }

    /// Encrypt a plaintext and return the encryption randomness.
    ///
    /// Returns `(ct, u, e0, e1)` where `ct = (pk0*u + e0 + pt, pk1*u + e1)`.
    /// The randomness polynomials are the witnesses needed by proof-of-correct-
    /// encryption circuits (Greco-style).
    #[allow(clippy::type_complexity)]
    pub fn try_encrypt_extended<R: RngCore + CryptoRng>(
        &self,
        pt: &CkksPlaintext,
        rng: &mut R,
    ) -> Result<(CkksCiphertext, Poly<Ntt>, Poly<Ntt>, Poly<Ntt>)> {
        if self.par != pt.par {
            return Err(Error::DefaultError(
                "Incompatible CKKS parameters".to_string(),
            ));
        }
        if pt.level != 0 {
            return Err(Error::InvalidPlaintext {
                reason: "public-key encryption requires a level-0 plaintext".to_string(),
            });
        }
        let ctx = self.par.context_at_level(0)?;

        let u_coefficients = Zeroizing::new(
            sample_vec_cbd_f32(ctx.degree, CkksSecretKey::SK_VARIANCE, rng)
                .map_err(|e| Error::UnspecifiedInput(e.to_string()))?,
        );
        let u = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(u_coefficients.as_ref() as &[i64], ctx, false)?
                .into_ntt(),
        );

        let e0 = Zeroizing::new(
            Poly::<Ntt>::small(ctx, self.par.variance, rng).map_err(Error::MathError)?,
        );
        let e1 = Zeroizing::new(
            Poly::<Ntt>::small(ctx, self.par.variance, rng).map_err(Error::MathError)?,
        );

        let u_copy = u.as_ref().clone();
        let e0_copy = e0.as_ref().clone();
        let e1_copy = e1.as_ref().clone();

        let mut c0 = u.as_ref() * &self.c[0];
        c0 += e0.as_ref();
        c0 += &pt.poly;
        let mut c1 = u.as_ref() * &self.c[1];
        c1 += e1.as_ref();

        unsafe {
            c0.allow_variable_time_computations();
            c1.allow_variable_time_computations();
        }

        let ct = CkksCiphertext {
            par: self.par.clone(),
            c: vec![c0, c1],
            level: 0,
            scale: pt.scale,
        };

        Ok((ct, u_copy, e0_copy, e1_copy))
    }
}

impl FheParametrized for CkksSecretKey {
    type Parameters = CkksParameters;
}

impl FheParametrized for CkksPublicKey {
    type Parameters = CkksParameters;
}

impl From<&CkksSecretKey> for SecretKeyProto {
    fn from(sk: &CkksSecretKey) -> Self {
        Self {
            coeffs: sk.coeffs.to_vec(),
        }
    }
}

impl Serialize for CkksSecretKey {
    fn to_bytes(&self) -> Vec<u8> {
        SecretKeyProto::from(self).encode_to_vec()
    }
}

impl DeserializeParametrized for CkksSecretKey {
    type Error = Error;

    fn from_bytes(bytes: &[u8], par: &Arc<CkksParameters>) -> Result<Self> {
        let proto: SecretKeyProto = Message::decode(bytes).map_err(|_| {
            Error::SerializationError(SerializationError::ProtobufError {
                message: "CkksSecretKey decode".into(),
            })
        })?;
        if proto.coeffs.len() != par.degree() {
            return Err(Error::SerializationError(
                SerializationError::InvalidFormat {
                    reason: "CkksSecretKey coeffs length and parameters degree mismatch".into(),
                },
            ));
        }
        Ok(Self {
            par: par.clone(),
            coeffs: proto.coeffs.into_boxed_slice(),
        })
    }
}

impl From<&CkksPublicKey> for PublicKeyProto {
    fn from(pk: &CkksPublicKey) -> Self {
        Self {
            c: pk.c.iter().map(|p| p.to_bytes()).collect(),
        }
    }
}

impl Serialize for CkksPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        PublicKeyProto::from(self).encode_to_vec()
    }
}

impl DeserializeParametrized for CkksPublicKey {
    type Error = Error;

    fn from_bytes(bytes: &[u8], par: &Arc<CkksParameters>) -> Result<Self> {
        let proto: PublicKeyProto = Message::decode(bytes).map_err(|_| {
            Error::SerializationError(SerializationError::ProtobufError {
                message: "CkksPublicKey decode".into(),
            })
        })?;
        if proto.c.len() != 2 {
            return Err(Error::SerializationError(
                SerializationError::InvalidFormat {
                    reason: format!(
                        "CkksPublicKey must have 2 polynomials, got {}",
                        proto.c.len()
                    ),
                },
            ));
        }
        let ctx = par.context_at_level(0)?;
        let mut c = proto
            .c
            .iter()
            .map(|b| Poly::<Ntt>::from_bytes(b, ctx).map_err(Error::MathError))
            .collect::<Result<Vec<_>>>()?;
        c.iter_mut()
            .for_each(|p| p.disallow_variable_time_computations());
        Ok(Self {
            par: par.clone(),
            c,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{CkksPublicKey, CkksSecretKey};
    use crate::ckks::{CkksEncoder, CkksParametersBuilder};
    use rand::rng;
    use std::error::Error;

    fn test_params() -> std::sync::Arc<crate::ckks::CkksParameters> {
        CkksParametersBuilder::new()
            .set_degree(32)
            .set_moduli_sizes(&[54, 45])
            .set_scale(2f64.powi(30))
            .build_arc()
            .unwrap()
    }

    #[test]
    fn keygen() {
        let mut rng = rng();
        let params = test_params();
        let sk = CkksSecretKey::random(&params, &mut rng);
        assert_eq!(sk.par, params);
        for ci in sk.coeffs.iter() {
            assert!(ci.abs() as f32 <= CkksSecretKey::sk_bound());
        }
        let pk = CkksPublicKey::new(&sk, &mut rng).unwrap();
        assert_eq!(pk.c.len(), 2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = test_params();
        let encoder = CkksEncoder::new(&params);
        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng)?;

        let values = vec![1.25, -3.5, 0.125, 2.75];
        let pt = encoder.encode(&values, 0)?;
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        let pt2 = sk.try_decrypt(&ct)?;
        let decoded = encoder.decode(&pt2)?;

        // Approximate: noise ~ variance-scale / delta = 2^-30-ish per slot.
        for (v, d) in values.iter().zip(decoded.iter()) {
            assert!(
                (v - d).abs() < 1e-3,
                "decryption error too large: {v} vs {d}"
            );
        }
        Ok(())
    }

    #[test]
    fn extended_encrypt_satisfies_equations() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = test_params();
        let encoder = CkksEncoder::new(&params);
        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng)?;

        let values = vec![7.5, -1.0];
        let pt = encoder.encode(&values, 0)?;
        let (ct, u, e0, e1) = pk.try_encrypt_extended(&pt, &mut rng)?;

        // ct0 == pk0*u + e0 + pt
        let mut expected_c0 = &pk.c[0] * &u;
        expected_c0 += &e0;
        expected_c0 += &pt.poly;

        // ct1 == pk1*u + e1
        let mut expected_c1 = &pk.c[1] * &u;
        expected_c1 += &e1;

        // The ciphertext polynomials allow variable-time computations;
        // align the flag so PartialEq compares coefficients only.
        unsafe {
            expected_c0.allow_variable_time_computations();
            expected_c1.allow_variable_time_computations();
        }
        assert_eq!(ct[0], expected_c0);
        assert_eq!(ct[1], expected_c1);

        // And it still decrypts correctly.
        let decoded = encoder.decode(&sk.try_decrypt(&ct)?)?;
        assert!((decoded[0] - 7.5).abs() < 1e-3);
        assert!((decoded[1] + 1.0).abs() < 1e-3);
        Ok(())
    }

    #[test]
    fn incompatible_parameters_rejected() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params_a = test_params();
        // Structurally different parameters (different scale): encryption
        // must be rejected. Note equal-valued parameters in distinct Arcs
        // ARE compatible (structural equality, not pointer identity).
        let params_b = CkksParametersBuilder::new()
            .set_degree(params_a.degree())
            .set_moduli(params_a.moduli())
            .set_scale(params_a.scale() * 2.0)
            .build_arc()?;
        let encoder_b = CkksEncoder::new(&params_b);
        let sk_a = CkksSecretKey::random(&params_a, &mut rng);
        let pk_a = CkksPublicKey::new(&sk_a, &mut rng)?;

        let pt_b = encoder_b.encode(&[1.0], 0)?;
        assert!(pk_a.try_encrypt(&pt_b, &mut rng).is_err());
        Ok(())
    }

    #[test]
    fn serialize_roundtrip() -> Result<(), Box<dyn Error>> {
        use fhe_traits::{DeserializeParametrized, Serialize};

        let mut rng = rng();
        let params = test_params();
        let encoder = CkksEncoder::new(&params);
        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng)?;

        // Secret key roundtrip.
        let sk2 = CkksSecretKey::from_bytes(&sk.to_bytes(), &params)?;
        assert_eq!(sk.coeffs, sk2.coeffs);

        // Public key roundtrip.
        let pk2 = CkksPublicKey::from_bytes(&pk.to_bytes(), &params)?;
        assert_eq!(pk, pk2);

        // Ciphertext roundtrip, and the deserialized ciphertext still
        // decrypts to the same values.
        let values = vec![2.5, -0.75];
        let pt = encoder.encode(&values, 0)?;
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        let ct2 = crate::ckks::CkksCiphertext::from_bytes(&ct.to_bytes(), &params)?;
        assert_eq!(ct.level, ct2.level);
        assert_eq!(ct.scale, ct2.scale);
        let decoded = encoder.decode(&sk.try_decrypt(&ct2)?)?;
        assert!((decoded[0] - 2.5).abs() < 1e-3);
        assert!((decoded[1] + 0.75).abs() < 1e-3);
        Ok(())
    }

    #[test]
    fn deserialize_invalid_secret_key_length() {
        use fhe_traits::DeserializeParametrized;
        use prost::Message;

        let params = test_params();
        let proto = crate::proto::ckks::SecretKey {
            coeffs: vec![0; params.degree() - 1],
        };
        let bytes = proto.encode_to_vec();
        assert!(CkksSecretKey::from_bytes(&bytes, &params).is_err());
    }
}
