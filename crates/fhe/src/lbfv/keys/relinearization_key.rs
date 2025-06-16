/*!
 * Implementation of the l-BFV relinearization algorithm as described in
 * [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
 *
 * The l-BFV (linear BFV) relinearization algorithm provides several key
 * advantages over traditional relinearization approaches:
 *
 * 1. Linear Communication: The protocol achieves linear communication
 *    complexity, making it more efficient than quadratic alternatives.
 *
 * 2. Single Round: Unlike traditional approaches that require two rounds of
 *    communication, l-BFV completes relinearization in a single round,
 *    significantly reducing latency and network overhead.
 *
 * 3. Enhanced Robustness: The single-round nature of the protocol
 *    inherently provides robustness in the threshold setting.
 */

use crate::bfv::keys::key_switching_key::KeySwitchingKey;
use crate::bfv::{Ciphertext, SecretKey};
use crate::{Error, Result};
use fhe_math::rq::{
    switcher::Switcher, traits::TryConvertFrom as TryConvertFromPoly, Poly, Representation,
};
use itertools::izip;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use zeroize::Zeroizing;

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
    pub(crate) ksk_r_to_s: KeySwitchingKey,
    /// Key switching key that transforms ciphertexts encrypted under s to
    /// ciphertexts encrypted under r ((d2, -a), where d2 is the c0 component,
    /// and -a is the c1 component of the key switch key). Note that we
    /// negate 'r' to counteract the effects of a positive 'a' since we do
    /// not want to go into the code and negate 'a' itself. We are using c0
    /// of this key switching key anyways so a positive 'a' is not a big
    /// deal. We get (r*a + e + sk*g, a).
    pub(crate) ksk_s_to_r: KeySwitchingKey,
    /// The polynomial b_vec used in the relinearization process. This is the
    /// l-BFV public key b-values associated with the secret key.
    pub(crate) b_vec: Vec<Poly>,
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
    pub fn new<R: RngCore + CryptoRng>(
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

        if ctx_relin_key.moduli().len() == 1 {
            return Err(Error::DefaultError(
                "These parameters do not support key switching".to_string(),
            ));
        }

        // Generate random polynomial 'r' from the key distribution
        let r: SecretKey = SecretKey::random(&sk.par, rng);
        let r_poly = Zeroizing::new(Poly::try_convert_from(
            r.coeffs.as_ref(),
            ctx_ciphertext,
            false,
            Representation::PowerBasis,
        )?);
        let r_switched_up = Zeroizing::new(r_poly.mod_switch_to(&switcher_up)?);

        // Convert 'sk' coefficients to polynomial
        let sk_poly = Zeroizing::new(Poly::try_convert_from(
            sk.coeffs.as_ref(),
            ctx_ciphertext,
            false,
            Representation::PowerBasis,
        )?);
        let sk_switched_up = Zeroizing::new(sk_poly.mod_switch_to(&switcher_up)?);

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

        // Extract b_vec from pk.c[i][0]
        let b_vec = pk.extract_b_polynomials_ntt_shoup()?;

        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
            b_vec,
        })
    }

    pub fn relinearizes(&self, ct: &mut Ciphertext) -> Result<()> {
        if ct.c.len() != 3 {
            Err(Error::DefaultError(
                "Only supports relinearization of ciphertext with 3 parts".to_string(),
            ))
        } else if ct.level != self.ksk_r_to_s.ciphertext_level
            || ct.level != self.ksk_s_to_r.ciphertext_level
        {
            Err(Error::DefaultError(
                "Ciphertext has incorrect level".to_string(),
            ))
        } else {
            let mut c2_hat = ct.c[2].clone();
            c2_hat.change_representation(Representation::PowerBasis);

            // Step 3: c2_prime = < D_Q(c2_hat), b_vec >
            let mut c2_prime = self.decompose_poly_and_product_sum(&c2_hat, &self.b_vec)?;
            c2_prime.change_representation(Representation::PowerBasis);
            if c2_prime.ctx() != ct.c[0].ctx() {
                c2_prime.mod_switch_down_to(ct.c[0].ctx())?;
            }

            // Step 4
            let (mut c0_prime, mut c1_prime) = self.ksk_r_to_s.key_switch(&c2_prime)?;
            if c0_prime.ctx() != ct.c[0].ctx() || c1_prime.ctx() != ct.c[1].ctx() {
                c0_prime.change_representation(Representation::PowerBasis);
                c1_prime.change_representation(Representation::PowerBasis);
                c0_prime.mod_switch_down_to(ct.c[0].ctx())?;
                c1_prime.mod_switch_down_to(ct.c[1].ctx())?;
                c0_prime.change_representation(Representation::Ntt);
                c1_prime.change_representation(Representation::Ntt);
            }
            ct.c[0] += &c0_prime;
            ct.c[1] += &c1_prime;

            // Step 5
            let mut c1_double_prime =
                self.decompose_poly_and_product_sum(&c2_hat, &self.ksk_s_to_r.c0)?;
            if c1_double_prime.ctx() != ct.c[1].ctx() {
                c1_double_prime.change_representation(Representation::PowerBasis);
                c1_double_prime.mod_switch_down_to(ct.c[1].ctx())?;
                c1_double_prime.change_representation(Representation::Ntt);
            }
            ct.c[1] += &c1_double_prime;

            // Remove unnecessary third element
            ct.c.truncate(2);
            Ok(())
        }
    }

    fn decompose_poly_and_product_sum(&self, poly: &Poly, arr: &[Poly]) -> Result<Poly> {
        // Validate equal context and representation
        if poly.ctx().as_ref() != self.ksk_r_to_s.ctx_ciphertext.as_ref() {
            return Err(Error::DefaultError(
                "The input polynomial does not have the correct context.".to_string(),
            ));
        }
        if poly.representation() != &Representation::PowerBasis {
            return Err(Error::DefaultError("Incorrect representation".to_string()));
        }

        // Product-sum of decomposed polynomial and array of polynomials
        let mut out = Poly::zero(&self.ksk_r_to_s.ctx_ksk, Representation::Ntt);
        for (poly_i_coefficients, arr_i) in izip!(poly.coefficients().outer_iter(), arr.iter()) {
            // Validate equal context and representation
            if arr_i.ctx().as_ref() != self.ksk_r_to_s.ctx_ciphertext.as_ref() {
                return Err(Error::DefaultError(
                    "A polynomial in the array does not have the correct context.".to_string(),
                ));
            }
            if arr_i.representation() != &Representation::NttShoup {
                return Err(Error::DefaultError("Incorrect representation".to_string()));
            }

            // Takes the coefficients of [p]_{qi} and converts them to an RNS representation
            // by taking [[p]_qi]_qj for every RNS basis qj
            let poly_i = unsafe {
                Poly::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                    poly_i_coefficients.as_slice().unwrap(),
                    &self.ksk_r_to_s.ctx_ksk,
                )
            };
            out += &(&poly_i * arr_i);
        }
        Ok(out)
    }
}

/// Converts a [`RelinearizationKey`] into its protobuf representation
// impl From<&RelinearizationKey> for RelinearizationKeyProto {
//     fn from(value: &RelinearizationKey) -> Self {
//         RelinearizationKeyProto {
//             ksk: Some(KeySwitchingKeyProto::from(&value.ksk)),
//         }
//     }
// }

/// Attempts to convert a protobuf representation back into a
/// [`RelinearizationKey`]
///
/// # Arguments
/// * `value` - The protobuf representation to convert
/// * `par` - The BFV parameters to use for the conversion
///
/// # Returns
/// * `Ok(RelinearizationKey)` if conversion succeeds
/// * `Err` if the protobuf is invalid or conversion fails
// impl TryConvertFrom<&RelinearizationKeyProto> for RelinearizationKey {
//     fn try_convert_from(value: &RelinearizationKeyProto, par: &Arc<BfvParameters>) ->
// Result<Self> {         if value.ksk.is_some() {
//             Ok(RelinearizationKey {
//                 ksk: KeySwitchingKey::try_convert_from(value.ksk.as_ref().unwrap(), par)?,
//             })
//         } else {
//             Err(Error::DefaultError("Invalid serialization".to_string()))
//         }
//     }
// }

/// Serializes the [`RelinearizationKey`] into a byte vector
// impl Serialize for RelinearizationKey {
//     fn to_bytes(&self) -> Vec<u8> {
//         RelinearizationKeyProto::from(self).encode_to_vec()
//     }
// }

/// Associates the [`RelinearizationKey`] with BFV parameters
// impl FheParametrized for RelinearizationKey {
//     type Parameters = BfvParameters;
// }

/// Deserializes a [`RelinearizationKey`] from bytes using the provided
/// parameters
///
/// # Arguments
/// * `bytes` - The serialized relinearization key
/// * `par` - The BFV parameters to use for deserialization
///
/// # Returns
/// * `Ok(RelinearizationKey)` if deserialization succeeds
/// * `Err` if the bytes are invalid or deserialization fails
// impl DeserializeParametrized for RelinearizationKey {
//     type Error = Error;

//     fn from_bytes(bytes: &[u8], par: &Arc<Self::Parameters>) -> Result<Self> {
//         let rk = Message::decode(bytes);
//         if let Ok(rk) = rk {
//             RelinearizationKey::try_convert_from(&rk, par)
//         } else {
//             Err(Error::DefaultError("Invalid serialization".to_string()))
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use super::LBFVRelinearizationKey;
    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};
    use crate::lbfv::keys::LBFVPublicKey;
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::thread_rng;
    use std::error::Error;

    #[test]
    fn test_relinearization_after_multiplication() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng);

        // Create relinearization key
        let relin_key = LBFVRelinearizationKey::new(
            &sk, &pk, None, // Use random d1_seed
            0,    // ciphertext level
            0,    // key level
            &mut rng,
        )?;

        // Create a plaintext with value 2
        let pt = Plaintext::try_encode(&[2u64], Encoding::poly(), &params)?;

        // Encrypt the plaintext
        let ct = pk.try_encrypt(&pt, &mut rng)?;

        // Multiply the ciphertext with itself (this creates a 3-part ciphertext)
        let mut ct_squared = &ct.clone() * &ct;

        // Relinearize the squared ciphertext
        relin_key.relinearizes(&mut ct_squared)?;

        // Decrypt and verify the result is 4 (2 * 2)
        let pt_result = sk.try_decrypt(&ct_squared)?;
        let result = Vec::<u64>::try_decode(&pt_result, Encoding::poly())?;
        assert_eq!(result[0], 4);

        Ok(())
    }
}
