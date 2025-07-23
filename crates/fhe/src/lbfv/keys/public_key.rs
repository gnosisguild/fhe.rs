/*!
 * This module contains the public key for the l-BFV encryption scheme.
 */

use crate::{Error, Result};
use std::sync::Arc;

use prost::Message;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use zeroize::Zeroizing;

use crate::bfv::{
    traits::TryConvertFrom, BfvParameters, Ciphertext, Encoding, Plaintext, SecretKey,
};
use crate::proto::bfv::{Ciphertext as CiphertextProto, LbfvPublicKey as LBFVPublicKeyProto};
use fhe_math::rq::{switcher::Switcher, Poly, Representation};
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
        let zero = Plaintext::zero(Encoding::poly(), &sk.par).unwrap();
        let mut c: Vec<Ciphertext> = Vec::with_capacity(sk.par.moduli().len());
        let mut seed_rng = ChaCha8Rng::from_seed(seed); // This is used to generate the seeds for the ciphertexts by creating a new
                                                        // ChaCha8Rng from the input seed

        // Create a vector of ciphertexts, each encrypting zero, for each RNS modulus
        // [(b₁, a₁), ..., (bₗ, aₗ)].
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
    pub fn extract_b_polynomials(
        &self,
        ciphertext_level: usize,
        key_level: usize,
        rep: Representation,
    ) -> Result<Vec<Poly>> {
        // Necessary checks
        if ciphertext_level > self.par.max_level() {
            return Err(Error::DefaultError(
                "Level is greater than the maximum level".to_string(),
            ));
        }

        // Note: this may seem redundant, but it's because in the future, we want to experiment with different key levels
        // for the public key.
        if key_level != 0 {
            return Err(Error::DefaultError("Key level must be 0".to_string()));
        }

        let key_ctx = self.par.ctx_at_level(key_level)?;
        if self.c[0].c[0].ctx() != key_ctx {
            return Err(Error::DefaultError(
                "Public key is not at level 0".to_string(),
            ));
        }

        // Note: key switching is redundant for now.
        // Create switcher to mod switch from initial to final context (for when public key is at different level than ciphertext)
        let ciphertext_ctx = self.par.ctx_at_level(ciphertext_level)?;
        let switcher = Switcher::new(ciphertext_ctx, key_ctx)?;

        // Extract (l - level) b polynomials and change representation accordingly
        let new_l = self.l - ciphertext_level;
        let mut b_polynomials = Vec::with_capacity(new_l);
        for i in 0..new_l {
            let mut poly = self.c[i].c[0].clone();
            if poly.ctx() != key_ctx {
                println!("Switching from level {ciphertext_level} to level {key_level}");
                poly.change_representation(Representation::PowerBasis);
                poly = poly.mod_switch_to(&switcher)?;
            }
            poly.change_representation(rep.clone());
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

        // Import the seed if it exists
        let seed = if !proto.seed.is_empty() {
            let mut seed_array = <ChaCha8Rng as SeedableRng>::Seed::default();
            if proto.seed.len() != seed_array.len() {
                return Err(Error::SerializationError);
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
mod tests {
    use super::LBFVPublicKey;
    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};
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
