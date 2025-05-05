/*!
 * Implementation of the l-BFV relinearization algorithm as described in
 * [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
 *
 * This module contains the relinearization key for the l-BFV scheme, along with the relinearization key 
 * relinearization algorithm.
 */

use crate::bfv::traits::TryConvertFrom;
use crate::bfv::{BfvParameters, Ciphertext, SecretKey, KeySwitchingKey};
use crate::proto::bfv::{
    KeySwitchingKey as KeySwitchingKeyProto,
    LbfvRelinearizationKey as LBFVRelinearizationKeyProto
};
use fhe_math::rq::{
    switcher::Switcher, traits::TryConvertFrom as TryConvertFromPoly, Poly, Representation, Context
};
use fhe_traits::{
    DeserializeParametrized, DeserializeWithContext, FheParametrized, Serialize,
};
use itertools::izip;
use prost::Message;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;
use crate::{Error, Result};

use super::LBFVPublicKey;

/// A relinearization key for the l-BFV scheme, consisting of two key switching
/// keys: one from r to s and another from s to r. This enables single-round
/// relinearization of ciphertexts after homomorphic multiplication.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LBFVRelinearizationKey {
    /// Key switching key that transforms ciphertexts encrypted under r to
    /// ciphertexts encrypted under s ((d0, d1), where d0 is the c0 component,
    /// and d1 is the c1 component of the key switch key). Mathematically,
    /// this is equivalent to (-sk*d1 + e + r*g, d1).
    ksk_r_to_s: KeySwitchingKey,
    /// Key switching key that transforms ciphertexts encrypted under s to
    /// ciphertexts encrypted under r ((d2, -a), where d2 is the c0 component,
    /// and -a is the c1 component of the key switch key). Note that we
    /// negate 'r' to counteract the effects of a positive 'a' since we do
    /// not want to go into the code and negate 'a' itself. We are using c0
    /// of this key switching key anyways so a positive 'a' is not a big
    /// deal. We get (r*a + e + sk*g, a).
    ksk_s_to_r: KeySwitchingKey,
    /// The polynomial b_vec used in the relinearization process. This is the
    /// l-BFV public key b-values associated with the secret key.
    b_vec: Vec<Poly>,
}

impl LBFVRelinearizationKey {
    /// Generate a new relinearization key. This relinearization key is
    /// generated using the key switching keys from r to s and s to r, following
    /// the l-BFV relinearization algorithm in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
    /// The first key switching key is generated using the seed `d1_seed` and
    /// the second key switching key is generated using the seed `a_seed`. If
    /// `d1_seed` is not provided, a new seed is generated. The key in the paper
    /// follows (d0,d1,d2). In our implementation, (d0,d1) is the key switching
    /// key from r to s and (d2, a) is the key switching key from s to r. Note,
    /// it should be (d2, -a), but we negate 'r' to counteract the effects of
    /// a positive 'a' since we do not want to go into the code and negate 'a'
    /// itself. We only use d2  anyways so a not used positive 'a' is not a big
    /// deal. We get (r*a + e + sk*g, a).
    ///
    /// # Arguments
    /// * `sk` - The secret key to use for key generation
    /// * `a_seed` - The seed for the key switching key from s to r
    /// * `d1_seed` - The seed for the key switching key from r to s
    /// * `ciphertext_level` - The level of the ciphertext to relinearize
    /// * `key_level` - The level of the key to use for relinearization
    /// * `rng` - The random number generator to use for key generation
    pub fn new_leveled<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        pk: &LBFVPublicKey,
        d1_seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let ctx_relin_key = sk.par.ctx_at_level(key_level)?;
        let ctx_ciphertext = sk.par.ctx_at_level(ciphertext_level)?;
        let switcher_up = Switcher::new(ctx_ciphertext, ctx_relin_key)?;

        if ciphertext_level < key_level {
            return Err(Error::DefaultError(
                "Ciphertext level must be greater than or equal to key level".to_string(),
            ));
        }

        if ctx_relin_key.moduli().len() == 1 {
            return Err(Error::DefaultError(
                "These parameters do not support key switching".to_string(),
            ));
        }

        if ctx_ciphertext.moduli().len() == 1 {
            return Err(Error::DefaultError(
                "These parameters do not support key switching".to_string(),
            )); 
        }

        // Generate random polynomial 'r' from the key distribution
        let r: SecretKey = SecretKey::random(&sk.par, rng);
        let r_poly = Poly::try_convert_from( 
            r.coeffs.as_ref(),
            ctx_ciphertext,
            false,
            Representation::PowerBasis,
        )?;
        let r_switched_up = r_poly.mod_switch_to(&switcher_up)?;

        // Convert 'sk' coefficients to polynomial
        let sk_poly = Poly::try_convert_from(
            sk.coeffs.as_ref(),
            ctx_ciphertext,
            false,
            Representation::PowerBasis,
        )?;
        let sk_switched_up = sk_poly.mod_switch_to(&switcher_up)?;

        // Create key switching key from r to s using d1_seed if provided, otherwise
        // generate new seed (-sk*d1 + e + r*g, d1) = (d0, d1)
        let d1_seed = d1_seed.unwrap_or_else(|| {
            let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut seed);
            seed
        });
        let ksk_r_to_s = KeySwitchingKey::new_with_seed(
            sk,
            &r_switched_up,
            d1_seed,
            ciphertext_level,
            key_level,
            rng,
        )?;

        // Create key switching key from s to r using -a_seed. Note, we negate 'r' to
        // counteract the effects of a positive 'a' since we do not want to go into the
        // code and negate 'a' itself. We are using c0 of this key switching key
        // anyways so a positive 'a' is not a big deal. We get (r*a + e + sk*g, a).
        let mut neg_r = r.clone();
        neg_r.coeffs.iter_mut().for_each(|x| *x = x.wrapping_neg());
        let ksk_s_to_r = KeySwitchingKey::new_with_seed(
            &neg_r,
            &sk_switched_up,
            pk.seed
                .ok_or_else(|| Error::DefaultError("Public key is missing its seed".to_string()))?,
            ciphertext_level,
            key_level,
            rng,
        )?;

        // Extract b_vec from pk.c[i][0] at the ciphertext level
        // TODO: we are not switching to the key level here, but since the ciphertext 
        // level defines l (the number of ciphertexts in the public key), this may be fine.
        // We should probably think about this more carefully.
        let b_vec = pk.extract_b_polynomials(ciphertext_level, key_level, Representation::NttShoup)?;

        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
            b_vec,
        })
    }

    /// Get "l" in "l-BFV" based on members of the [`LBFVRelinearizationKey`] struct, 
    /// which is equal to the number of ciphertexts in the public key.
    /// 
    /// # Returns
    /// * `Ok(usize)` - The number of ciphertexts in the public key
    /// * `Err` if the number of moduli in the ciphertext context is not equal 
    /// to the number of polynomials in `b_vec`, which should be equal to "l".
    pub fn l(&self) -> Result<usize> {
        if self.ksk_r_to_s.par.max_level() + 1 - self.ciphertext_level() != self.b_vec.len() {
            return Err(Error::DefaultError("'l' is not consistent.".to_string()));
        }
        Ok(self.b_vec.len())
    }

    /// Generate a new relinearization key. This relinearization key is
    /// generated using the key switching keys from r to s and s to r, following
    /// the l-BFV relinearization algorithm in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
    /// The first key switching key is generated using the seed `d1_seed` and
    /// the second key switching key is generated using the seed `a_seed`. If
    /// `d1_seed` is not provided, a new seed is generated.
    pub fn new<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        pk: &LBFVPublicKey,
        d1_seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
        rng: &mut R,
    ) -> Result<Self> {
        Self::new_leveled(sk, pk, d1_seed, 0, 0, rng)
    }   

    /// Relinearizes a ciphertext of degree 2 to degree 1 using the l-BFV relinearization algorithm.
    /// 
    /// This function implements the relinearization algorithm from [Robust Multiparty Computation from 
    /// Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
    /// 
    /// Note: Key switching operations are done in the key switching key context, not the ciphertext context.
    /// When necesary, the ciphertext is converted to the key switching key context. Then, it is converted back
    /// to the ciphertext context to perform necessary mathematical operations.
    ///
    /// # Arguments
    /// * `ct` - The ciphertext to relinearize. Must have exactly 3 parts (degree 2).
    ///
    /// # Returns
    /// * `Ok(())` - If relinearization succeeds. The input ciphertext is modified in-place to have 2 parts (degree 1).
    /// * `Err` - If the ciphertext does not have exactly 3 parts or is at the wrong level.
    pub fn relinearizes(&self, ct: &mut Ciphertext) -> Result<()> {
        if ct.c.len() != 3 {
            Err(Error::DefaultError(
                "Only supports relinearization of ciphertext with 3 parts".to_string(),
            ))
        } else if ct.level != self.ciphertext_level()
        {
            Err(Error::DefaultError(
                "Ciphertext has incorrect level".to_string(),
            ))
        } else {
            let ciphertext_ctx = self.ciphertext_ctx();
            let mut c2_hat = ct.c[2].clone();
            c2_hat.change_representation(Representation::PowerBasis);

            // Step 3: c2_prime = < D_Q(c2_hat), b_vec >
            let mut c2_prime = self.decompose_poly_and_product_sum(&c2_hat, &self.b_vec)?;
            c2_prime.change_representation(Representation::PowerBasis);
            if c2_prime.ctx() != &ciphertext_ctx {
                c2_prime.mod_switch_down_to(&ciphertext_ctx)?;
            }

            // Step 4
            let (mut c0_prime, mut c1_prime) = self.ksk_r_to_s.key_switch(&c2_prime)?;
            if c0_prime.ctx() != &ciphertext_ctx || c1_prime.ctx() != &ciphertext_ctx {
                c0_prime.change_representation(Representation::PowerBasis);
                c1_prime.change_representation(Representation::PowerBasis);
                c0_prime.mod_switch_down_to(&ciphertext_ctx)?;
                c1_prime.mod_switch_down_to(&ciphertext_ctx)?;
                c0_prime.change_representation(Representation::Ntt);
                c1_prime.change_representation(Representation::Ntt);
            }
            ct.c[0] += &c0_prime;
            ct.c[1] += &c1_prime;

            // Step 5
            let mut c1_double_prime =
                self.decompose_poly_and_product_sum(&c2_hat, &self.ksk_s_to_r.c0)?;
            if c1_double_prime.ctx() != &ciphertext_ctx {
                c1_double_prime.change_representation(Representation::PowerBasis);
                c1_double_prime.mod_switch_down_to(&ciphertext_ctx)?;
                c1_double_prime.change_representation(Representation::Ntt);
            }
            ct.c[1] += &c1_double_prime;

            // Remove unnecessary third element
            ct.c.truncate(2);
            Ok(())
        }
    }

    /// Get the ciphertext level of the relinearization key.
    /// 
    /// # Returns
    /// * `usize` - The ciphertext level of the relinearization key which is the same 
    /// as the ciphertext level of the key switching key. 
    pub fn ciphertext_level(&self) -> usize {
        self.ksk_r_to_s.ciphertext_level
    }

    /// Get the ciphertext context of the relinearization key.
    /// 
    /// # Returns
    /// * `Arc<Context>` - The ciphertext context of the relinearization key which is the same 
    /// as the ciphertext context of the key switching key. 
    pub fn ciphertext_ctx(&self) -> Arc<Context> {
        self.ksk_r_to_s.ctx_ciphertext.clone()
    }

    /// Get the key level of the relinearization key.
    /// 
    /// # Returns
    /// * `usize` - The key level of the relinearization key which is the same 
    /// as the key level of the key switching key. 
    pub fn key_level(&self) -> usize {  
        self.ksk_r_to_s.ksk_level
    }

    /// Get the key context of the relinearization key.
    /// 
    /// # Returns
    /// * `Arc<Context>` - The key context of the relinearization key which is the same 
    /// as the key context of the key switching key. 
    pub fn key_ctx(&self) -> Arc<Context> {
        self.ksk_r_to_s.ctx_ksk.clone()
    }

    /// Get the BFV parameters of the relinearization key.
    /// 
    /// # Returns
    /// * `Arc<BfvParameters>` - The BFV parameters of the relinearization key which is the same 
    /// as the BFV parameters of the key switching key. 
    pub fn parameters(&self) -> Arc<BfvParameters> {
        self.ksk_r_to_s.par.clone()
    }

    /// Decomposes a polynomial into its RNS components and computes the product-sum with an array of polynomials.
    ///
    /// This function takes a polynomial in power basis representation and an array of polynomials in NTT-Shoup representation.
    /// It decomposes the input polynomial into its RNS components and computes the sum of products between each component
    /// and the corresponding polynomial in the array.
    /// 
    /// The input polynomial should be in the context of the ciphertext being relinearized and the array of polynomials should be in 
    /// the context of the key.
    ///
    /// # Arguments
    /// * `poly` - The polynomial to decompose, must be in power basis representation
    /// * `arr` - Array of polynomials to multiply with the decomposed components, must be in NTT-Shoup representation
    ///
    /// # Returns
    /// * `Ok(Poly)` - The resulting polynomial in NTT representation
    /// * `Err` if:
    ///   - The input polynomial is not in the correct context
    ///   - The input polynomial is not in power basis representation
    ///   - Any polynomial in the array is not in the correct context
    ///   - Any polynomial in the array is not in NTT-Shoup representation
    ///
    /// # Implementation Details
    /// For each coefficient p in the input polynomial and corresponding polynomial a in the array:
    /// 1. Takes [p]_{qi} and converts it to [[p]_{qi}]_{qj} for every RNS basis qj
    /// 2. Multiplies this with a and accumulates the result
    fn decompose_poly_and_product_sum(&self, poly: &Poly, arr: &[Poly]) -> Result<Poly> {
        let ciphertext_ctx = self.ciphertext_ctx();
        let ksk_ctx = self.key_ctx();

        // Validate equal context and representation
        if poly.ctx() != &ciphertext_ctx {
            return Err(Error::DefaultError(
                "The input polynomial does not have the correct context.".to_string(),
            ));
        }
        if arr.len() != ciphertext_ctx.moduli().len() {
            return Err(Error::DefaultError(
                "The input array of polynomials does not have the correct length.".to_string(),
            ));
        }
        if poly.representation() != &Representation::PowerBasis {
            return Err(Error::DefaultError("Incorrect representation".to_string()));
        }

        // Product-sum of decomposed polynomial and array of polynomials
        let mut out = Poly::zero(&ksk_ctx, Representation::Ntt);
        for (poly_i_coefficients, arr_i) in izip!(poly.coefficients().outer_iter(), arr.iter()) {
            if arr_i.representation() != &Representation::NttShoup {
                return Err(Error::DefaultError("Incorrect representation".to_string()));
            }
            if arr_i.ctx() != &ksk_ctx {
                return Err(Error::DefaultError(
                    "The input array of polynomials does not have the correct context.".to_string(),
                ));
            }

            // Takes the coefficients of [p]_{qi} and converts them to an RNS representation
            // by taking [[p]_qi]_qj for every RNS basis qj
            let poly_i = unsafe {
                Poly::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                    poly_i_coefficients.as_slice().unwrap(),
                    &ksk_ctx,
                )
            };
            out += &(&poly_i * arr_i);
        }
        Ok(out)
    }
}

/// Converts a [`LBFVRelinearizationKey`] into its protobuf representation
impl From<&LBFVRelinearizationKey> for LBFVRelinearizationKeyProto {
    fn from(value: &LBFVRelinearizationKey) -> Self {
        LBFVRelinearizationKeyProto {
            ksk_r_to_s: Some(KeySwitchingKeyProto::from(&value.ksk_r_to_s)),
            ksk_s_to_r: Some(KeySwitchingKeyProto::from(&value.ksk_s_to_r)),
            b_vec: value.b_vec.iter().map(|p| p.to_bytes()).collect(),
        }
    }
}

/// Attempts to convert a protobuf representation back into a
/// [`LBFVRelinearizationKey`]
///
/// # Arguments
/// * `value` - The protobuf representation to convert
/// * `par` - The BFV parameters to use for the conversion
///
/// # Returns
/// * `Ok(LBFVRelinearizationKey)` if conversion succeeds
/// * `Err` if the protobuf is invalid or conversion fails
impl TryConvertFrom<&LBFVRelinearizationKeyProto> for LBFVRelinearizationKey {
    fn try_convert_from(value: &LBFVRelinearizationKeyProto, par: &Arc<BfvParameters>) -> Result<Self> {
        if value.ksk_r_to_s.is_none() || value.ksk_s_to_r.is_none() {
            return Err(Error::DefaultError("Invalid serialization: missing key switching keys".to_string()));
        }
        
        let ksk_r_to_s = KeySwitchingKey::try_convert_from(value.ksk_r_to_s.as_ref().unwrap(), par)?;
        let ksk_s_to_r = KeySwitchingKey::try_convert_from(value.ksk_s_to_r.as_ref().unwrap(), par)?;
        
        // Deserialize b_vec
        let key_ctx = ksk_r_to_s.ctx_ksk.clone();
        let mut b_vec = Vec::with_capacity(value.b_vec.len());
        for poly_bytes in &value.b_vec {
            let poly = Poly::from_bytes(poly_bytes, &key_ctx)?;
            b_vec.push(poly);
        }
        
        Ok(LBFVRelinearizationKey {
            ksk_r_to_s,
            ksk_s_to_r,
            b_vec,
        })
    }
}

/// Serializes the [`LBFVRelinearizationKey`] into a byte vector
impl Serialize for LBFVRelinearizationKey {
    fn to_bytes(&self) -> Vec<u8> {
        LBFVRelinearizationKeyProto::from(self).encode_to_vec()
    }
}

/// Associates the [`LBFVRelinearizationKey`] with BFV parameters
impl FheParametrized for LBFVRelinearizationKey {
    type Parameters = BfvParameters;
}

/// Deserializes a [`LBFVRelinearizationKey`] from bytes using the provided
/// parameters
///
/// # Arguments
/// * `bytes` - The serialized relinearization key
/// * `par` - The BFV parameters to use for deserialization
///
/// # Returns
/// * `Ok(LBFVRelinearizationKey)` if deserialization succeeds
/// * `Err` if the bytes are invalid or deserialization fails
impl DeserializeParametrized for LBFVRelinearizationKey {
    type Error = Error;

    fn from_bytes(bytes: &[u8], par: &Arc<Self::Parameters>) -> Result<Self> {
        let rk = Message::decode(bytes);
        if let Ok(rk) = rk {
            LBFVRelinearizationKey::try_convert_from(&rk, par)
        } else {
            Err(Error::DefaultError("Invalid serialization".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfv::{Encoding, Plaintext};
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::thread_rng;
    use std::error::Error;
    use std::result::Result;

    #[test]
    fn test_serialize_deserialize() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng);
        
        // Create relinearization key
        let relin_key = LBFVRelinearizationKey::new(&sk, &pk, None, &mut rng)?;
        
        // Serialize and deserialize
        let bytes = relin_key.to_bytes();
        let deserialized_key = LBFVRelinearizationKey::from_bytes(&bytes, &params)?;
        
        // Test that the deserialized key works correctly
        let pt = Plaintext::try_encode(&[2u64], Encoding::poly(), &params)?;
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        let mut ct_squared = &ct.clone() * &ct;
        
        // Relinearize with original key
        let mut ct_squared_original = ct_squared.clone();
        relin_key.relinearizes(&mut ct_squared_original)?;
        
        // Relinearize with deserialized key
        deserialized_key.relinearizes(&mut ct_squared)?;
        
        // Decrypt and verify both give the same result
        let pt_original = sk.try_decrypt(&ct_squared_original)?;
        let pt_deserialized = sk.try_decrypt(&ct_squared)?;
        
        assert_eq!(pt_original, pt_deserialized);
        
        let result = Vec::<u64>::try_decode(&pt_deserialized, Encoding::poly())?;
        assert_eq!(result[0], 4);
        
        Ok(())
    }

    #[test]
    fn test_multiplication() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng);
        
        // Create relinearization key
        let relin_key = LBFVRelinearizationKey::new(&sk, &pk, None, &mut rng)?;
        
        // Test multiplication with different encodings
        for encoding in [Encoding::poly(), Encoding::simd()] {
            // Encode and encrypt values
            let pt1 = Plaintext::try_encode(&[3u64], encoding.clone(), &params)?;
            let pt2 = Plaintext::try_encode(&[5u64], encoding.clone(), &params)?;
            let ct1 = pk.try_encrypt(&pt1, &mut rng)?;
            let ct2 = pk.try_encrypt(&pt2, &mut rng)?;
            
            // Multiply ciphertexts
            let mut ct_product = &ct1 * &ct2;
            
            // Relinearize
            relin_key.relinearizes(&mut ct_product)?;
            
            // Decrypt and verify
            let pt_result = sk.try_decrypt(&ct_product)?;
            let result = Vec::<u64>::try_decode(&pt_result, encoding.clone())?;
            
            // Check result (3 * 5 = 15)
            assert_eq!(result[0], 15);
        }
        
        Ok(())
    }
}
