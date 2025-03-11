//! Public keys for the l-BFV encryption scheme

use crate::bfv::traits::TryConvertFrom;
use crate::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, SecretKey};
use crate::proto::bfv::{Ciphertext as CiphertextProto, LbfvPublicKey as LBFVPublicKeyProto};
use crate::{Error, Result};
use fhe_math::rq::{Poly, Representation};
use fhe_traits::{DeserializeParametrized, FheEncrypter, FheParametrized, Serialize};
use prost::Message;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Public key for the L-BFV encryption scheme.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LBFVPublicKey {
    /// The BFV parameters
    pub par: Arc<BfvParameters>,
    /// The public key ciphertexts, one for each RNS modulus
    pub c: Vec<Ciphertext>,
    /// The decomposition size which is the number of RNS moduli (the l in lBFV)
    pub l: usize,
    /// The seed used to generate all ciphertexts deterministically
    pub seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
}

impl LBFVPublicKey {
    /// Generate a new [`LBFVPublicKey`] from a [`SecretKey`] using a provided
    /// seed.
    pub fn new_with_seed<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Self {
        let zero = Plaintext::zero(Encoding::poly(), &sk.par).unwrap();
        let mut c: Vec<Ciphertext> = Vec::with_capacity(sk.par.moduli().len());
        let mut seed_rng = ChaCha8Rng::from_seed(seed);

        // Create a ciphertext for each RNS modulus
        for _ in 0..sk.par.moduli().len() {
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
            par: sk.par.clone(),
            c,
            l: sk.par.moduli().len(),
            seed: Some(seed),
        }
    }

    /// Generate a new [`LBFVPublicKey`] from a [`SecretKey`] using a random
    /// seed.
    pub fn new<R: RngCore + CryptoRng>(sk: &SecretKey, rng: &mut R) -> Self {
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);
        Self::new_with_seed(sk, seed, rng)
    }

    /// Encrypt a plaintext with the public key.
    /// The encryption is done in the same level as the plaintext.
    /// Returns the ciphertext and the noise polynomials.
    pub fn try_encrypt_extended<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<(Ciphertext, Poly, Poly, Poly)> {
        if self.c.is_empty() {
            return Err(Error::DefaultError(
                "Public key has no ciphertexts available".to_string(),
            ));
        }

        // Use only the first ciphertext from the array
        let mut ct = self.c[0].clone();
        while ct.level != pt.level {
            ct.mod_switch_to_next_level()?;
        }

        let ctx = self.par.ctx_at_level(ct.level)?;
        let u = Poly::small(ctx, Representation::Ntt, self.par.variance, rng)?;
        let e1 = Poly::small(ctx, Representation::Ntt, self.par.variance, rng)?;
        let e2 = Poly::small(ctx, Representation::Ntt, self.par.variance, rng)?;

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

        let ciphertext = Ciphertext {
            par: self.par.clone(),
            seed: None,
            c: vec![c0, c1],
            level: ct.level,
        };

        Ok((ciphertext, u, e1, e2))
    }
}

impl FheParametrized for LBFVPublicKey {
    type Parameters = BfvParameters;
}

impl FheEncrypter<Plaintext, Ciphertext> for LBFVPublicKey {
    type Error = Error;

    fn try_encrypt<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<Ciphertext> {
        if self.c.is_empty() {
            return Err(Error::DefaultError(
                "Public key has no ciphertexts available".to_string(),
            ));
        }

        // Use only the first ciphertext from the array
        let mut ct = self.c[0].clone();
        while ct.level != pt.level {
            ct.mod_switch_to_next_level()?;
        }

        let ctx = self.par.ctx_at_level(ct.level)?;
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
        let e2 = Zeroizing::new(Poly::small(
            ctx,
            Representation::Ntt,
            self.par.variance,
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

impl From<&LBFVPublicKey> for LBFVPublicKeyProto {
    fn from(pk: &LBFVPublicKey) -> Self {
        LBFVPublicKeyProto {
            c: pk.c.iter().map(CiphertextProto::from).collect(),
            l: pk.l as u32,
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
        let proto: LBFVPublicKeyProto =
            Message::decode(bytes).map_err(|_| Error::SerializationError)?;

        if proto.c.is_empty() {
            return Err(Error::SerializationError);
        }

        let mut c: Vec<Ciphertext> = Vec::with_capacity(proto.c.len());
        for ct_proto in proto.c {
            let mut ct = Ciphertext::try_convert_from(&ct_proto, par)?;
            if ct.level != 0 {
                return Err(Error::SerializationError);
            }
            // The polynomials of a public key should not allow for variable time
            // computation.
            ct.c.iter_mut()
                .for_each(|p| p.disallow_variable_time_computations());
            c.push(ct);
        }

        Ok(Self {
            par: par.clone(),
            c,
            l: proto.l as usize,
            seed: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::LBFVPublicKey;
    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};
    use fhe_math::rq::{Poly, Representation};
    use fhe_traits::{DeserializeParametrized, FheDecrypter, FheEncoder, FheEncrypter, Serialize};
    use rand::{thread_rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use std::error::Error;

    #[test]
    fn keygen() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng);
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
        let mut rng = thread_rng();
        for params in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            for level in 0..params.max_level() {
                for _ in 0..20 {
                    let sk = SecretKey::random(&params, &mut rng);
                    let pk = LBFVPublicKey::new(&sk, &mut rng);

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
            let pk = LBFVPublicKey::new(&sk, &mut rng);
            let bytes = pk.to_bytes();
            assert_eq!(pk, LBFVPublicKey::from_bytes(&bytes, &params)?);
        }
        Ok(())
    }

    #[test]
    fn test_deterministic_public_key() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
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
