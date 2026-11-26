/*!
 * Implementation of the l-BFV relinearization algorithm as described in
 * Robust Multiparty Computation from Threshold Encryption Based on RLWE
 * [1](https://eprint.iacr.org/2024/1285.pdf).
 *
 * This module contains the relinearization key for the l-BFV scheme, along with the relinearization key
 * relinearization algorithm.
 */

use crate::bfv::traits::TryConvertFrom;
use crate::bfv::{BfvParameters, Ciphertext, CommonRandomPolyVec, KeySwitchingKey, SecretKey};
use crate::proto::bfv::KeySwitchingKey as KeySwitchingKeyProto;
use crate::proto::lbfv::LbfvRelinearizationKey as LBFVRelinearizationKeyProto;
use crate::{Error, Result, SerializationError};
use fhe_math::rq::{Context, Ntt, NttShoup, Poly, PowerBasis};
use fhe_traits::{
    DeserializeParametrized, DeserializeWithContext, FheParametrized, PublicData, Serialize,
    VariableTime,
};
use itertools::izip;
use prost::Message;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;

use super::LBFVPublicKey;
use super::components::{Components, KeyRows, RelinInputs, row_count};

/// A relinearization key for the l-BFV scheme, consisting of two key switching
/// keys: one from r to s and another from s to r. This enables single-round
/// relinearization of ciphertexts after homomorphic multiplication.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LBFVRelinearizationKey {
    /// Key switching key that transforms ciphertexts encrypted under r to
    /// ciphertexts encrypted under s ((d0, d1), where d0 is the c0 component,
    /// and d1 is the c1 component of the key switch key). Mathematically,
    /// this is equivalent to (-sk*d1 + e + r*g, d1).
    /// This key serves us while performing Step 4 from Algorithm 1 of [1](https://eprint.iacr.org/2024/1285.pdf)
    ksk_r_to_s: KeySwitchingKey,
    /// Key switching key that transforms ciphertexts encrypted under s to
    /// ciphertexts encrypted under r ((d2, -a), where d2 is the c0 component,
    /// and -a is the c1 component of the key switch key). Note that we
    /// negate 'r' to counteract the effects of a positive 'a' since we do
    /// not want to go into the code and negate 'a' itself. We are using c0
    /// of this key switching key anyways so a positive 'a' is not a big
    /// deal. We get (r*a + e + sk*g, a).
    /// This key serves us while performing Step 5 from Algorithm 1 of [1](https://eprint.iacr.org/2024/1285.pdf)
    ksk_s_to_r: KeySwitchingKey,
    /// The polynomial b_vec used in the relinearization process. This is the
    /// l-BFV public key b-values associated with the secret key.
    b_vec: Vec<Poly<NttShoup>>,
}

impl LBFVRelinearizationKey {
    /// Generate a new relinearization key. This relinearization key is
    /// generated using the key switching keys from r to s and s to r, following
    /// the l-BFV relinearization algorithm in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
    /// The first key switching key is generated using the seed `d1_seed` and
    /// the second uses the concrete `a` rows in `pk` (with or without a seed). If
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
    /// * `pk` - The l-BFV public key for the same secret
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
        sk.validate_coefficient_count()?;
        let count = row_count(&sk.params, ciphertext_level, key_level)?;
        // 0.6 sampled r before drawing an optional d1 seed. Keep its RNG stream.
        let r = SecretKey::random(&sk.params, rng);
        let d1_seed = d1_seed.unwrap_or_else(|| {
            let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut seed);
            seed
        });
        let d1 = KeyRows::seeded(sk.params.context_at_level(0)?, count, d1_seed);
        let a = KeyRows::from_public_key(pk, &sk.params, count, &d1)?;
        let parts = RelinInputs::new(&sk.params, ciphertext_level, d1, a)?.generate(sk, &r, rng)?;
        Self::from_components(parts, pk.b_prefix(count))
    }

    /// Generate a leveled key from explicit `d1` rows and the public key's concrete `a` rows.
    pub fn new_leveled_with_polys<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        pk: &LBFVPublicKey,
        d1: Vec<Poly<NttShoup>>,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let count = row_count(&sk.params, ciphertext_level, key_level)?;
        Self::with_rows(
            sk,
            pk,
            KeyRows::explicit(d1, sk.params.context_at_level(0)?)?,
            count,
            ciphertext_level,
            rng,
        )
    }

    /// Use the `#moduli - ciphertext_level` leading rows of a shared URS vector.
    pub fn new_leveled_with_crp<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        pk: &LBFVPublicKey,
        d1: &CommonRandomPolyVec,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let count = row_count(&sk.params, ciphertext_level, key_level)?;
        let rows = KeyRows::from_crp(d1, sk.params.context_at_level(0)?, count)?;
        Self::with_rows(sk, pk, rows, count, ciphertext_level, rng)
    }

    /// Generate a level-zero key using a shared URS vector.
    pub fn new_with_crp<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        pk: &LBFVPublicKey,
        d1: &CommonRandomPolyVec,
        rng: &mut R,
    ) -> Result<Self> {
        Self::new_leveled_with_crp(sk, pk, d1, 0, 0, rng)
    }

    fn with_rows<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        pk: &LBFVPublicKey,
        d1: KeyRows,
        count: usize,
        level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        sk.validate_coefficient_count()?;
        let a = KeyRows::from_public_key(pk, &sk.params, count, &d1)?;
        let inputs = RelinInputs::new(&sk.params, level, d1, a)?;
        let parts = inputs.generate(sk, &SecretKey::random(&sk.params, rng), rng)?;
        Self::from_components(parts, pk.b_prefix(count))
    }

    pub(crate) fn from_components(parts: Components, b_vec: Vec<Poly<NttShoup>>) -> Result<Self> {
        if b_vec.len() != parts.r_to_s.c0.len()
            || b_vec
                .iter()
                .any(|b| b.ctx() != &parts.r_to_s.ctx_ksk || !b.has_canonical_coefficients())
        {
            return Err(crate::EvaluationKeyError::InvalidLbfvLayout {
                reason: "b rows do not match the relinearization key",
            }
            .into());
        }
        Ok(Self {
            ksk_r_to_s: parts.r_to_s,
            ksk_s_to_r: parts.s_to_r,
            b_vec,
        })
    }

    /// Get "l" in "l-BFV" based on members of the [`LBFVRelinearizationKey`] struct,
    /// which is equal to the number of ciphertexts in the public key.
    ///
    /// # Returns
    /// * `Ok(usize)` - The number of ciphertexts in the public key
    /// * `Err` if the number of moduli in the ciphertext context is not equal
    ///   to the number of polynomials in `b_vec`, which should be equal to "l".
    pub fn l(&self) -> Result<usize> {
        let expected = self.ksk_r_to_s.params.max_level() + 1 - self.ciphertext_level();
        if expected != self.b_vec.len() {
            return Err(crate::EvaluationKeyError::InvalidDecompositionLength {
                actual: self.b_vec.len(),
                expected,
            }
            .into());
        }
        Ok(self.b_vec.len())
    }

    /// Generate a new relinearization key. This relinearization key is
    /// generated using the key switching keys from r to s and s to r, following
    /// the l-BFV relinearization algorithm in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
    /// The first key switching key is generated using the seed `d1_seed` and
    /// the second uses the concrete `a` rows in `pk` (with or without a seed). If
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
    /// When necessary, the ciphertext is converted to the key switching key context. Then, it is converted back
    /// to the ciphertext context to perform necessary mathematical operations.
    ///
    /// # Arguments
    /// * `ct` - The ciphertext to relinearize. Must have exactly 3 parts (degree 2).
    ///
    /// # Returns
    /// * `Ok(())` - If relinearization succeeds. The input ciphertext is modified in-place to have 2 parts (degree 1).
    /// * `Err` - If the ciphertext does not have exactly 3 parts or is at the wrong level.
    #[allow(clippy::indexing_slicing)] // ct.c checked to have exactly 3 elements above; c[0..1] always valid BFV invariant
    pub fn relinearizes(&self, ct: &mut Ciphertext) -> Result<()> {
        if ct.c.len() != 3 {
            Err(crate::CiphertextError::InvalidPolynomialCount {
                operation: crate::CiphertextOperation::Relinearization,
                actual: ct.c.len(),
                expected: 3,
            }
            .into())
        } else if ct.level != self.ciphertext_level() {
            Err(Error::InvalidLevel {
                level: ct.level,
                min_level: self.ciphertext_level(),
                max_level: self.ciphertext_level(),
            })
        } else {
            let ciphertext_ctx = self.ciphertext_ctx();
            if ct.params != self.ksk_r_to_s.params {
                return Err(Error::ParameterMismatch {
                    left: crate::ParameterSource::Ciphertext,
                    right: crate::ParameterSource::RelinearizationKey,
                });
            }
            ct.validate_for_context(&ct.params, self.ciphertext_level(), &ciphertext_ctx)?;
            if !ct.c.iter().all(Poly::has_canonical_coefficients) {
                return Err(crate::EvaluationKeyError::InvalidLbfvLayout {
                    reason: "relinearization requires canonical ciphertext components",
                }
                .into());
            }
            let c2_hat = ct.c[2].clone().into_power_basis();

            let mut c2_prime = self.decompose_poly_and_product_sum(&c2_hat, &self.b_vec)?;
            if c2_prime.ctx() != &ciphertext_ctx {
                let mut pb = c2_prime.into_power_basis();
                pb.switch_down_to(&ciphertext_ctx)?;
                c2_prime = pb.into_ntt();
            }

            let c2_pb = c2_prime.into_power_basis();
            let (mut c0_prime, mut c1_prime) = self.ksk_r_to_s.key_switch(&c2_pb)?;
            if c0_prime.ctx() != &ciphertext_ctx || c1_prime.ctx() != &ciphertext_ctx {
                let mut c0_pb = c0_prime.into_power_basis();
                let mut c1_pb = c1_prime.into_power_basis();
                c0_pb.switch_down_to(&ciphertext_ctx)?;
                c1_pb.switch_down_to(&ciphertext_ctx)?;
                c0_prime = c0_pb.into_ntt();
                c1_prime = c1_pb.into_ntt();
            }
            ct.c[0] += &c0_prime;
            ct.c[1] += &c1_prime;

            let mut c1_double_prime =
                self.decompose_poly_and_product_sum(&c2_hat, &self.ksk_s_to_r.c0)?;
            if c1_double_prime.ctx() != &ciphertext_ctx {
                let mut pb = c1_double_prime.into_power_basis();
                pb.switch_down_to(&ciphertext_ctx)?;
                c1_double_prime = pb.into_ntt();
            }
            ct.c[1] += &c1_double_prime;

            // Remove unnecessary third element
            ct.c.truncate(2);
            ct.seed = None;
            Ok(())
        }
    }

    /// Get the ciphertext level of the relinearization key.
    ///
    /// # Returns
    /// * `usize` - The ciphertext level of the relinearization key which is the same
    ///   as the ciphertext level of the key switching key.
    #[must_use]
    pub fn ciphertext_level(&self) -> usize {
        self.ksk_r_to_s.ciphertext_level
    }

    /// Get the ciphertext context of the relinearization key.
    ///
    /// # Returns
    /// * `Arc<Context>` - The ciphertext context of the relinearization key which is the same
    ///   as the ciphertext context of the key switching key.
    #[must_use]
    pub fn ciphertext_ctx(&self) -> Arc<Context> {
        self.ksk_r_to_s.ctx_ciphertext.clone()
    }

    /// Get the key level of the relinearization key.
    ///
    /// # Returns
    /// * `usize` - The key level of the relinearization key which is the same
    ///   as the key level of the key switching key.
    #[must_use]
    pub fn key_level(&self) -> usize {
        self.ksk_r_to_s.ksk_level
    }

    /// Get the key context of the relinearization key.
    ///
    /// # Returns
    /// * `Arc<Context>` - The key context of the relinearization key which is the same
    ///   as the key context of the key switching key.
    #[must_use]
    pub fn key_ctx(&self) -> Arc<Context> {
        self.ksk_r_to_s.ctx_ksk.clone()
    }

    /// Get the BFV parameters of the relinearization key.
    ///
    /// # Returns
    /// * `Arc<BfvParameters>` - The BFV parameters of the relinearization key which is the same
    ///   as the BFV parameters of the key switching key.
    #[must_use]
    pub fn parameters(&self) -> Arc<BfvParameters> {
        self.ksk_r_to_s.params.clone()
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
    /// 1. Takes `[p]_{qi}` and converts it to `[[p]_{qi}]_{qj}` for every RNS basis `qj`
    /// 2. Multiplies this with a and accumulates the result
    fn decompose_poly_and_product_sum(
        &self,
        poly: &Poly<PowerBasis>,
        arr: &[Poly<NttShoup>],
    ) -> Result<Poly<Ntt>> {
        let ciphertext_ctx = self.ciphertext_ctx();
        let ksk_ctx = self.key_ctx();

        // Validate equal context and representation
        if poly.ctx() != &ciphertext_ctx {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::Polynomial,
                right: crate::ParameterSource::RelinearizationKey,
            });
        }
        if arr.len() != ciphertext_ctx.moduli().len() {
            return Err(crate::EvaluationKeyError::InvalidDecompositionLength {
                actual: arr.len(),
                expected: ciphertext_ctx.moduli().len(),
            }
            .into());
        }
        // Product-sum of decomposed polynomial and array of polynomials
        let mut out = Poly::<Ntt>::zero(&ksk_ctx);
        for (poly_i_coefficients, arr_i) in izip!(poly.coefficients().outer_iter(), arr.iter()) {
            if arr_i.ctx() != &ksk_ctx {
                return Err(Error::ParameterMismatch {
                    left: crate::ParameterSource::Polynomial,
                    right: crate::ParameterSource::KeySwitchingKey,
                });
            }

            let poly_i =
                Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                    poly_i_coefficients.as_slice().unwrap(),
                    &ksk_ctx,
                    VariableTime::new(PublicData::assert_public()),
                );
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
    fn try_convert_from(
        value: &LBFVRelinearizationKeyProto,
        par: &Arc<BfvParameters>,
    ) -> Result<Self> {
        let parts =
            Components::from_protos(value.ksk_r_to_s.as_ref(), value.ksk_s_to_r.as_ref(), par)?;
        if value.b_vec.len() != parts.r_to_s.c0.len() {
            return Err(crate::EvaluationKeyError::InvalidDecompositionLength {
                actual: value.b_vec.len(),
                expected: parts.r_to_s.c0.len(),
            }
            .into());
        }

        // Deserialize b_vec
        let key_ctx = parts.r_to_s.ctx_ksk.clone();
        let mut b_vec = Vec::with_capacity(value.b_vec.len());
        for poly_bytes in &value.b_vec {
            let poly = Poly::<NttShoup>::from_bytes(poly_bytes, &key_ctx)?;
            b_vec.push(poly);
        }

        Self::from_components(parts, b_vec)
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
            Err(SerializationError::Decode {
                object: crate::SerializedObject::RelinearizationKey,
            }
            .into())
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::bfv::{Encoding, Plaintext};
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::rng;
    use std::error::Error;
    use std::result::Result;

    #[test]
    fn test_serialize_deserialize() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng).unwrap();

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
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng).unwrap();

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
