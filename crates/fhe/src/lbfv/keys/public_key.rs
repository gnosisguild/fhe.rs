/*!
 * This module contains the public key for the l-BFV encryption scheme.
 */

use crate::{Error, Result, SerializationError};
use std::sync::Arc;

use prost::Message;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use zeroize::Zeroizing;

use crate::bfv::{
    BfvParameters, Ciphertext, Encoding, Plaintext, SecretKey, traits::TryConvertFrom,
};
use crate::proto::bfv::Ciphertext as CiphertextProto;
use crate::proto::lbfv::LbfvPublicKey as LBFVPublicKeyProto;
use fhe_math::rq::{Ntt, NttShoup, Poly, Representation, switcher::Switcher};
use fhe_traits::{DeserializeParametrized, FheEncrypter, FheParametrized, Serialize};

/// Public key for the L-BFV encryption scheme.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LBFVPublicKey {
    /// The BFV parameters
    pub par: Arc<BfvParameters>,
    /// The public key ciphertexts, one for each RNS modulus
    pub c: Vec<Ciphertext>,
    /// The decomposition size which is the number of RNS moduli (the l in lBFV).
    /// Note while l in https://eprint.iacr.org/2024/1285.pdf is equal to the size
    /// chosen of the Gadget vector, here it is equal the number of RNS moduli
    /// as the library uses the optimization of https://eprint.iacr.org/2018/117.pdf
    pub l: usize,
    /// The seed used to generate all ciphertexts deterministically
    pub seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
}

impl LBFVPublicKey {
    /// Generate a new [`LBFVPublicKey`] from a [`SecretKey`] using a provided
    /// seed. The seed is used to generate l seeds for the ciphertexts which are
    /// used to generate the random polynomials aᵢ for each ciphertext
    /// deterministically.
    pub fn new_with_seed<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Self {
        let zero = Plaintext::zero(Encoding::poly(), &sk.params).unwrap();
        let mut c: Vec<Ciphertext> = Vec::with_capacity(sk.params.moduli().len());
        let mut seed_rng = ChaCha8Rng::from_seed(seed); // This is used to generate the seeds for the ciphertexts by creating a new
        // ChaCha8Rng from the input seed

        // Create a vector of ciphertexts, each encrypting zero, for each RNS modulus
        // [(b₁, a₁), ..., (bₗ, aₗ)].
        for _ in 0..sk.params.moduli().len() {
            let mut seed_i = <ChaCha8Rng as SeedableRng>::Seed::default();
            seed_rng.fill(&mut seed_i);
            let mut ct = sk.try_encrypt_with_seed(&zero, seed_i, rng).unwrap();
            // The polynomials of a public key should not allow for variable time
            // computation.
            ct.c.iter_mut()
                .for_each(|p| p.disallow_variable_time_computations());
            c.push(ct);
        }

        Self {
            par: sk.params.clone(),
            c,
            l: sk.params.moduli().len(),
            seed: Some(seed),
        }
    }

    /// Generate a new [`LBFVPublicKey`] from a [`SecretKey`] using a random
    /// seed.
    pub fn new<R: RngCore + CryptoRng>(sk: &SecretKey, rng: &mut R) -> Result<Self> {
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);
        Ok(Self::new_with_seed(sk, seed, rng))
    }

    /// Encrypt a plaintext with the public key.
    /// The encryption is done in the same level as the plaintext.
    /// Returns the ciphertext and the noise polynomials.
    #[allow(clippy::indexing_slicing, clippy::type_complexity)] // ct.c always has exactly 2 components (BFV invariant)
    pub fn try_encrypt_extended<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<(Ciphertext, Poly<Ntt>, Poly<Ntt>, Poly<Ntt>)> {
        if self.c.is_empty() {
            return Err(crate::EvaluationKeyError::EmptyPublicKey.into());
        }

        // Use only the first ciphertext from the array
        let mut ct = self.c[0].clone();
        while ct.level != pt.level() {
            ct.switch_down()?;
        }

        let ctx = self.par.context_at_level(ct.level)?;
        let u = Poly::<Ntt>::small(ctx, self.par.variance, rng)?;
        let e1 = Poly::<Ntt>::error_1(
            ctx,
            Representation::Ntt,
            &self.par.error1_variance,
            rng,
        )?;
        let e2 = Poly::<Ntt>::small(ctx, self.par.variance, rng)?;

        let m = Zeroizing::new(pt.to_poly());
        let mut c0 = u.as_ref() * &ct.c[0];
        c0 += &e1;
        c0 += &m;
        let mut c1 = u.as_ref() * &ct.c[1];
        c1 += &e2;

        // It is now safe to enable variable time computations.
        let variable_time = fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
        c0.allow_variable_time_computations(variable_time);
        c1.allow_variable_time_computations(variable_time);

        let ciphertext = Ciphertext {
            params: self.par.clone(),
            seed: None,
            c: vec![c0, c1],
            level: ct.level,
        };

        Ok((ciphertext, u, e1, e2))
    }

    /// Extract the b polynomials from the ciphertexts in the public key at a specified key level and representation.
    ///
    /// This method extracts the first l = # moduli - ciphertext level, c[0] components from each ciphertext in the public key,
    /// mod switches them to the key level, and converts them to the specified representation.
    ///
    /// # Arguments
    /// * `ciphertext_level` - The level of the ciphertext that will use these polynomials
    /// * `key_level` - The level of the key that will be used (currently must be 0)
    /// * `rep` - The desired representation for the output polynomials
    ///
    /// # Returns
    /// * `Ok(Vec<Poly>)` - A vector of polynomials in the specified representation at the target level
    /// * `Err` if:
    ///   - The requested ciphertext level is greater than the maximum level
    ///   - The key level is not 0 (current limitation)
    ///   - The public key is not at level 0
    ///   - Any polynomial operations fail during mod switching or representation changes
    // self.c[0..new_l] is always valid (self.c has self.l elements, new_l <= self.l)
    #[allow(clippy::indexing_slicing)]
    pub fn extract_b_polynomials(
        &self,
        ciphertext_level: usize,
        key_level: usize,
        rep: Representation,
    ) -> Result<Vec<Poly<NttShoup>>> {
        // Necessary checks
        if ciphertext_level > self.par.max_level() {
            return Err(Error::InvalidLevel {
                level: ciphertext_level,
                min_level: 0,
                max_level: self.par.max_level(),
            });
        }

        // Note: this may seem redundant, but it's because in the future, we want to experiment with different key levels
        // for the public key.
        if key_level != 0 {
            return Err(Error::InvalidLevel {
                level: key_level,
                min_level: 0,
                max_level: 0,
            });
        }

        let key_ctx = self.par.context_at_level(key_level)?;
        if self.c[0].c[0].ctx() != key_ctx {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::PublicKey,
                right: crate::ParameterSource::Parameters,
            });
        }

        // Note: key switching is redundant for now.
        // Create switcher to mod switch from initial to final context (for when public key is at different level than ciphertext)
        let ciphertext_ctx = self.par.context_at_level(ciphertext_level)?;
        let switcher = Switcher::new(ciphertext_ctx, key_ctx)?;

        // Extract (l - level) b polynomials and change representation accordingly
        let new_l = self.l - ciphertext_level;
        let mut b_polynomials = Vec::with_capacity(new_l);
        for i in 0..new_l {
            let mut poly = self.c[i].c[0].clone();
            if poly.ctx() != key_ctx {
                poly = poly.switch(&switcher)?;
            }
            let poly = match rep {
                Representation::NttShoup => poly.into_ntt_shoup(),
                Representation::PowerBasis | Representation::Ntt => {
                    return Err(crate::EvaluationKeyError::UnsupportedRepresentation {
                        found: format!("{rep:?}"),
                    }
                    .into());
                }
            };
            b_polynomials.push(poly);
        }
        Ok(b_polynomials)
    }
}

impl FheParametrized for LBFVPublicKey {
    type Parameters = BfvParameters;
}

impl FheEncrypter<Plaintext, Ciphertext> for LBFVPublicKey {
    type Error = Error;

    /// Encrypt a plaintext using the public key.
    ///
    /// This method samples the `e1` noise term from the configured
    /// `error1_variance`, while `u` and `e2` use the standard `variance`.
    #[allow(clippy::indexing_slicing)] // ct.c always has exactly 2 components (BFV invariant)
    fn try_encrypt<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<Ciphertext> {
        if self.c.is_empty() {
            return Err(crate::EvaluationKeyError::EmptyPublicKey.into());
        }

        // Use only the first ciphertext from the array
        let mut ct = self.c[0].clone();
        while ct.level != pt.level() {
            ct.switch_down()?;
        }

        let ctx = self.par.context_at_level(ct.level)?;
        let u = Zeroizing::new(Poly::<Ntt>::small(ctx, self.par.variance, rng)?);
        let e1 = Zeroizing::new(Poly::<Ntt>::error_1(
            ctx,
            Representation::Ntt,
            &self.par.error1_variance,
            rng,
        )?);
        let e2 = Zeroizing::new(Poly::<Ntt>::small(ctx, self.par.variance, rng)?);

        let m = Zeroizing::new(pt.to_poly());
        let mut c0 = u.as_ref() * &ct.c[0];
        c0 += &e1;
        c0 += &m;
        let mut c1 = u.as_ref() * &ct.c[1];
        c1 += &e2;

        // It is now safe to enable variable time computations.
        let variable_time = fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
        c0.allow_variable_time_computations(variable_time);
        c1.allow_variable_time_computations(variable_time);

        Ok(Ciphertext {
            params: self.par.clone(),
            seed: None,
            c: vec![c0, c1],
            level: ct.level,
        })
    }
}

impl From<&LBFVPublicKey> for LBFVPublicKeyProto {
    fn from(pk: &LBFVPublicKey) -> Self {
        LBFVPublicKeyProto {
            c: pk.c.iter().map(CiphertextProto::from).collect(),
            l: pk.l as u32,
            seed: pk.seed.map_or_else(Vec::new, |s| s.to_vec()),
        }
    }
}

impl Serialize for LBFVPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        LBFVPublicKeyProto::from(self).encode_to_vec()
    }
}

impl DeserializeParametrized for LBFVPublicKey {
    type Error = Error;

    fn from_bytes(bytes: &[u8], par: &Arc<Self::Parameters>) -> Result<Self> {
        let proto: LBFVPublicKeyProto = Message::decode(bytes).map_err(|_| {
            Error::SerializationError(SerializationError::Decode {
                object: crate::SerializedObject::PublicKey,
            })
        })?;

        if proto.c.is_empty() {
            return Err(Error::SerializationError(
                SerializationError::MissingField {
                    field: crate::SerializedField::PublicKeyCiphertext,
                },
            ));
        }

        let mut c: Vec<Ciphertext> = Vec::with_capacity(proto.c.len());
        for ct_proto in proto.c {
            let mut ct = Ciphertext::try_convert_from(&ct_proto, par)?;
            if ct.level != 0 {
                return Err(SerializationError::InvalidPublicKeyLevel {
                    actual: ct.level,
                    expected: 0,
                }
                .into());
            }
            // The polynomials of a public key should not allow for variable time
            // computation.
            ct.c.iter_mut()
                .for_each(|p| p.disallow_variable_time_computations());
            c.push(ct);
        }

        // Import the seed if it exists
        let seed = if !proto.seed.is_empty() {
            let mut seed_array = <ChaCha8Rng as SeedableRng>::Seed::default();
            if proto.seed.len() != seed_array.len() {
                return Err(SerializationError::InvalidPublicKeySeedLength {
                    actual: proto.seed.len(),
                    expected: seed_array.len(),
                }
                .into());
            }
            seed_array.copy_from_slice(&proto.seed);
            Some(seed_array)
        } else {
            None
        };

        Ok(Self {
            par: par.clone(),
            c,
            l: proto.l as usize,
            seed,
        })
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::LBFVPublicKey;
    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};
    use fhe_math::zq::Modulus;
    use fhe_traits::{DeserializeParametrized, FheDecrypter, FheEncoder, FheEncrypter, Serialize};
    use rand::{SeedableRng, rng};
    use rand_chacha::ChaCha8Rng;
    use std::error::Error;

    #[test]
    fn keygen() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng).unwrap();
        assert_eq!(pk.par, params);
        // Check that l matches number of moduli
        assert_eq!(pk.l, params.moduli().len());
        // Check that all ciphertexts decrypt to zero
        for ct in pk.c.iter() {
            assert_eq!(
                sk.try_decrypt(ct)?,
                Plaintext::zero(Encoding::poly(), &params)?
            );
        }
        Ok(())
    }

    #[test]
    fn encrypt_decrypt() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            for level in 0..params.max_level() {
                for _ in 0..20 {
                    let sk = SecretKey::random(&params, &mut rng);
                    let pk = LBFVPublicKey::new(&sk, &mut rng).unwrap();

                    let pt = Plaintext::try_encode(
                        &Modulus::new(params.plaintext())?.random_vec(params.degree(), &mut rng),
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

    /// `try_encrypt` and `try_encrypt_extended` must sample `e1` from the
    /// configured `error1_variance`, independently of `variance` (used for
    /// `u` and `e2`), mirroring `bfv::PublicKey`.
    #[test]
    fn encrypt_decrypt_custom_error1_variance() -> Result<(), Box<dyn Error>> {
        use crate::bfv::BfvParametersBuilder;
        use num_bigint::BigUint;

        let mut rng = rng();

        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62usize; 3])
            .set_variance(10)
            .set_error1_variance_usize(15)
            .build_arc()?;

        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;

        let pt = Plaintext::try_encode(
            &Modulus::new(params.plaintext())?.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;

        let ct = pk.try_encrypt(&pt, &mut rng)?;
        let pt2 = sk.try_decrypt(&ct)?;
        assert_eq!(pt2, pt);
        assert_eq!(params.get_error1_variance(), &BigUint::from(15u32));
        assert_eq!(params.variance(), 10);

        let (ct_ext, _u, _e1, _e2) = pk.try_encrypt_extended(&pt, &mut rng)?;
        let pt2_ext = sk.try_decrypt(&ct_ext)?;
        assert_eq!(pt2_ext, pt);

        Ok(())
    }

    /// `try_encrypt_extended` witness equations: `c0 = u·b + e1 + m` and
    /// `c1 = u·a + e2`, per `.rules/witness.md`.
    #[test]
    fn extended_encrypt_witness_equations() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;

        let pt = Plaintext::try_encode(
            &Modulus::new(params.plaintext())?.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;

        let (ct, u, e1, e2) = pk.try_encrypt_extended(&pt, &mut rng)?;

        let b = pk.c[0].c[0].clone();
        let a = pk.c[0].c[1].clone();
        let m = pt.to_poly()?;

        let mut expected_c0 = &u * &b;
        expected_c0 += &e1;
        expected_c0 += &m;
        let mut expected_c1 = &u * &a;
        expected_c1 += &e2;

        assert_eq!(ct.c[0].coefficients(), expected_c0.coefficients());
        assert_eq!(ct.c[1].coefficients(), expected_c1.coefficients());

        Ok(())
    }

    #[cfg(feature = "protobuf")]
    mod protobuf {
        use super::*;
        use crate::proto::bfv::LbfvPublicKey as LBFVPublicKeyProto;
        use fhe_traits::{DeserializeParametrized, Serialize};
        use prost::Message;

        #[test]
        fn test_serialize() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            for params in [
                BfvParameters::default_arc(1, 8),
                BfvParameters::default_arc(6, 8),
            ] {
                let sk = SecretKey::random(&params, &mut rng);
                let pk = LBFVPublicKey::new(&sk, &mut rng)?;
                let bytes = pk.to_bytes();
                assert_eq!(pk, LBFVPublicKey::from_bytes(&bytes, &params)?);
            }
            Ok(())
        }

        #[test]
        fn test_malformed_l_rejected() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let pk = LBFVPublicKey::new(&sk, &mut rng)?;

            let mut proto: LBFVPublicKeyProto = LBFVPublicKeyProto::from(&pk);
            proto.l = 1; // Malformed: l should be the number of moduli
            let bytes = proto.encode_to_vec();
            assert!(LBFVPublicKey::from_bytes(&bytes, &params).is_err());

            // Also test: l doesn't match ciphertext count
            let mut proto2: LBFVPublicKeyProto = LBFVPublicKeyProto::from(&pk);
            proto2.c.pop(); // Remove one ciphertext but leave l unchanged
            let bytes2 = proto2.encode_to_vec();
            assert!(LBFVPublicKey::from_bytes(&bytes2, &params).is_err());

            Ok(())
        }

        /// A serialized public key with a tampered seed that does not match the
        /// concrete `a` polynomials must be rejected during deserialization.
        #[test]
        fn test_tampered_seed_rejected() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let pk = LBFVPublicKey::new(&sk, &mut rng)?;

            // Serialize the valid PK to proto, then replace the seed with a
            // different one that does not reproduce the concrete a_j.
            let mut proto: LBFVPublicKeyProto = LBFVPublicKeyProto::from(&pk);
            proto.seed = vec![0u8; 32]; // A seed that does not match the a_j

            let bytes = proto.encode_to_vec();
            assert!(
                LBFVPublicKey::from_bytes(&bytes, &params).is_err(),
                "PK deserialization must reject a tampered seed"
            );

            // A seedless PK with no seed must still be accepted.
            let mut seedless_proto = LBFVPublicKeyProto::from(&pk);
            seedless_proto.seed.clear();
            let seedless_bytes = seedless_proto.encode_to_vec();
            let seedless_pk = LBFVPublicKey::from_bytes(&seedless_bytes, &params)?;
            assert!(seedless_pk.seed.is_none(), "Seedless PK must carry no seed");

            Ok(())
        }

        /// A serialized PK carrying a binding must be rejected — single-party
        /// LBFVPublicKey does not carry bindings.
        #[test]
        fn test_binding_rejected() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let pk = LBFVPublicKey::new(&sk, &mut rng)?;

            let mut proto: LBFVPublicKeyProto = LBFVPublicKeyProto::from(&pk);
            // Inject a binding field (any non-empty binding should be rejected).
            proto.binding = Some(Default::default());

            let bytes = proto.encode_to_vec();
            assert!(
                LBFVPublicKey::from_bytes(&bytes, &params).is_err(),
                "PK deserialization must reject a binding field"
            );

            Ok(())
        }
    }
    #[test]
    fn test_serialize() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            let sk = SecretKey::random(&params, &mut rng);
            let pk = LBFVPublicKey::new(&sk, &mut rng).unwrap();
            let bytes = pk.to_bytes();
            assert_eq!(pk, LBFVPublicKey::from_bytes(&bytes, &params)?);
        }
        Ok(())
    }

    #[test]
    fn test_deterministic_public_key() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);

        // Create a fixed seed
        let seed = <ChaCha8Rng as SeedableRng>::Seed::default();

        // Create two public keys with the same seed
        let pk1 = LBFVPublicKey::new_with_seed(&sk, seed, &mut rng);
        let pk2 = LBFVPublicKey::new_with_seed(&sk, seed, &mut rng);

        // Verify that both public keys have the same seed
        assert_eq!(pk1.seed, pk2.seed);
        assert_eq!(pk1.seed, Some(seed));

        // Verify that all ciphertexts have the same c[1] components
        assert_eq!(pk1.c.len(), pk2.c.len());
        for (ct1, ct2) in pk1.c.iter().zip(pk2.c.iter()) {
            assert_eq!(ct1.c[1], ct2.c[1]); // The 'a' polynomials should be identical
            assert_ne!(ct1.c[0], ct2.c[0]); // The 'b' polynomials should differ due to random error

            // Verify both decrypt to zero
            let pt1 = sk.try_decrypt(ct1)?;
            let pt2 = sk.try_decrypt(ct2)?;
            assert_eq!(pt1, Plaintext::zero(Encoding::poly(), &params)?);
            assert_eq!(pt2, Plaintext::zero(Encoding::poly(), &params)?);
        }

        Ok(())
    }
}
