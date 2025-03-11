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

use std::sync::Arc;

use crate::bfv::keys::key_switching_key::KeySwitchingKey;
use crate::bfv::{traits::TryConvertFrom, BfvParameters, Ciphertext, SecretKey};
use crate::proto::bfv::{
    KeySwitchingKey as KeySwitchingKeyProto, RelinearizationKey as RelinearizationKeyProto,
};
use crate::{Error, Result};
use fhe_math::rq::{
    switcher::Switcher, traits::TryConvertFrom as TryConvertFromPoly, Poly, Representation,
};
use fhe_traits::{DeserializeParametrized, FheParametrized, Serialize};
use prost::Message;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use zeroize::Zeroizing;

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
}

impl LBFVRelinearizationKey {
    /// Generate a new relinearization key
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
        a_seed: <ChaCha8Rng as SeedableRng>::Seed,
        d1_seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let ctx_relin_key = sk.par.ctx_at_level(key_level)?;
        let ctx_ciphertext = sk.par.ctx_at_level(ciphertext_level)?;

        if ctx_relin_key.moduli().len() == 1 {
            return Err(Error::DefaultError(
                "These parameters do not support key switching".to_string(),
            ));
        }

        // Generate random polynomial 'r' from the key distribution
        let r: SecretKey = SecretKey::random(&sk.par, rng);
        let mut r_poly = Zeroizing::new(Poly::try_convert_from(
            r.coeffs.as_ref(),
            ctx_ciphertext,
            false,
            Representation::PowerBasis,
        )?);
        r_poly.change_representation(Representation::Ntt);

        // Convert 'sk' coefficients to polynomial
        let mut sk_poly = Zeroizing::new(Poly::try_convert_from(
            sk.coeffs.as_ref(),
            ctx_ciphertext,
            false,
            Representation::PowerBasis,
        )?);
        sk_poly.change_representation(Representation::Ntt);

        // Create key switching key from r to s using d1_seed if provided, otherwise
        // generate new seed (-sk*d1 + e + r*g, d1)
        let d1_seed = d1_seed.unwrap_or_else(|| {
            let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut seed);
            seed
        });
        let ksk_r_to_s = KeySwitchingKey::new_with_seed(
            sk,
            r_poly.as_ref(),
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
            sk_poly.as_ref(),
            a_seed,
            ciphertext_level,
            key_level,
            rng,
        )?;

        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
        })
    }

    /// Relinearize an "extended" ciphertext (c₀, c₁, c₂) into a [`Ciphertext`]
    ///
    /// This method transforms a degree-2 ciphertext with three components
    /// (c₀, c₁, c₂) into a regular degree-1 ciphertext with two components
    /// (c₀', c₁').
    /// This process is necessary after homomorphic multiplication, which
    /// produces ciphertexts containing terms encrypted under s², not s, thus
    /// expanding the size of the ciphertext.
    ///
    /// A degree-2 ciphertext can be decrypted by computing
    /// c₀ + c₁·s + c₂·s² = m + e, where e is the noise. During
    /// relinearization, we want to make c₀' + c₁'·s = m + e', where e' is
    /// the new noise, so we need to find a way to make the following
    /// approximate equality:
    /// c₀ + c₁·s + c₂·s² ≈ c₀' + c₁'·s = m + e'. We can do this by
    /// setting c₀' = c₀ + c₂·s². Thus, we can add an encryption of s² * c₂, a
    /// polynomial that we get from the key switch operation between c₂ and
    /// a key switch key s² → s.
    ///
    /// # Process
    /// 1. Takes the c₂ component and converts it to power basis
    /// 2. Uses the key switching key to transform c₂ into (d₀, d₁) = c₂ * s²,
    ///    encrypted under s
    /// 3. Adds d₀ to c₀ and d₁ to c₁ to produce the final relinearized
    ///    ciphertext (c₀', c₁') such that c₀' + c₁'·s = m + e'.
    ///
    /// # Arguments
    /// * `ct` - A mutable reference to a [`Ciphertext`] with three components
    ///
    /// # Returns
    /// * `Ok(())` if relinearization succeeds
    /// * `Err` if the ciphertext doesn't have exactly 3 components or is at
    ///   wrong level
    ///
    /// # Note
    /// The input ciphertext must be at the same level as specified during key
    /// generation
    pub fn relinearizes(&self, ct: &mut Ciphertext) -> Result<()> {
        // TODO: Implement this
        Ok(())
    }

    /// Same operation as [`relinearizes`] but for relinearizing a polynomial
    /// rather than a full ciphertext. Takes a polynomial representing c₂
    /// and returns the relinearized components (d₀, d₁) = c₂·s², encrypted
    /// under s.
    ///
    /// # Arguments
    /// * `c2` - The polynomial to relinearize, representing the c₂ component
    ///
    /// # Returns
    /// * `Ok((d₀, d₁))` - The relinearized components encrypted under s
    /// * `Err` if the key switching operation fails
    pub(crate) fn relinearizes_poly(&self, c2: &Poly) -> Result<(Poly, Poly)> {
        // TODO: Implement this
        Ok((
            Poly::zero(c2.ctx(), Representation::Ntt),
            Poly::zero(c2.ctx(), Representation::Ntt),
        ))
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
    use crate::bfv::{traits::TryConvertFrom, BfvParameters, Ciphertext, Encoding, SecretKey};
    use crate::proto::bfv::RelinearizationKey as RelinearizationKeyProto;
    use fhe_math::rq::{traits::TryConvertFrom as TryConvertFromPoly, Poly, Representation};
    use fhe_traits::{FheDecoder, FheDecrypter};
    use rand::thread_rng;
    use std::error::Error;

    // #[test]
    // fn relinearization() -> Result<(), Box<dyn Error>> {
    //     let mut rng = thread_rng();
    //     for params in [BfvParameters::default_arc(6, 8)] {
    //         for _ in 0..100 {
    //             let sk = SecretKey::random(&params, &mut rng);
    //             let rk = RelinearizationKey::new(&sk, &mut rng)?;

    //             let ctx = params.ctx_at_level(0)?;
    //             let mut s = Poly::try_convert_from(
    //                 sk.coeffs.as_ref(),
    //                 ctx,
    //                 false,
    //                 Representation::PowerBasis,
    //             )
    //             .map_err(crate::Error::MathError)?;
    //             s.change_representation(Representation::Ntt);
    //             let s2 = &s * &s;

    //             // Let's generate manually an "extended" ciphertext (c₀ = e -
    // c₁·s - c₂·s²,             // c₁, c₂) encrypting 0.
    //             let mut c2 = Poly::random(ctx, Representation::Ntt, &mut
    // rng);             let c1 = Poly::random(ctx, Representation::Ntt,
    // &mut rng);             let mut c0 = Poly::small(ctx,
    // Representation::PowerBasis, 16, &mut rng)?;
    // c0.change_representation(Representation::Ntt);             c0 -=
    // &(&c1 * &s);             c0 -= &(&c2 * &s2);
    //             let mut ct = Ciphertext::new(vec![c0.clone(), c1.clone(),
    // c2.clone()], &params)?;

    //             // Relinearize the extended ciphertext!
    //             rk.relinearizes(&mut ct)?;
    //             assert_eq!(ct.c.len(), 2);

    //             // Check that the relinearization by polynomials works the
    // same way
    // c2.change_representation(Representation::PowerBasis);             let
    // (mut c0r, mut c1r) = rk.relinearizes_poly(&c2)?;
    // c0r.change_representation(Representation::PowerBasis);
    // c0r.mod_switch_down_to(c0.ctx())?;
    // c1r.change_representation(Representation::PowerBasis);
    // c1r.mod_switch_down_to(c1.ctx())?;
    // c0r.change_representation(Representation::Ntt);
    // c1r.change_representation(Representation::Ntt);
    // assert_eq!(ct, Ciphertext::new(vec![&c0 + &c0r, &c1 + &c1r], &params)?);

    //             // Print the noise and decrypt
    //             println!("Noise: {}", unsafe { sk.measure_noise(&ct)? });
    //             let pt = sk.try_decrypt(&ct)?;
    //             let w = Vec::<u64>::try_decode(&pt, Encoding::poly())?;
    //             assert_eq!(w, &[0u64; 8]);
    //         }
    //     }
    //     Ok(())
    // }

    // #[test]
    // fn relinearization_leveled() -> Result<(), Box<dyn Error>> {
    //     let mut rng = thread_rng();
    //     for params in [BfvParameters::default_arc(5, 8)] {
    //         for ciphertext_level in 0..params.max_level() {
    //             for key_level in 0..=ciphertext_level {
    //                 for _ in 0..10 {
    //                     let sk = SecretKey::random(&params, &mut rng);
    //                     let rk = RelinearizationKey::new_leveled(
    //                         &sk,
    //                         ciphertext_level,
    //                         key_level,
    //                         &mut rng,
    //                     )?;

    //                     let ctx = params.ctx_at_level(ciphertext_level)?;
    //                     let mut s = Poly::try_convert_from(
    //                         sk.coeffs.as_ref(),
    //                         ctx,
    //                         false,
    //                         Representation::PowerBasis,
    //                     )
    //                     .map_err(crate::Error::MathError)?;
    //                     s.change_representation(Representation::Ntt);
    //                     let s2 = &s * &s;
    //                     // Let's generate manually an "extended" ciphertext
    // (c₀ = e - c₁·s - c₂·s²,                     // c₁, c₂) encrypting 0.
    //                     let mut c2 = Poly::random(ctx, Representation::Ntt,
    // &mut rng);                     let c1 = Poly::random(ctx,
    // Representation::Ntt, &mut rng);                     let mut c0 =
    // Poly::small(ctx, Representation::PowerBasis, 16, &mut rng)?;
    //                     c0.change_representation(Representation::Ntt);
    //                     c0 -= &(&c1 * &s);
    //                     c0 -= &(&c2 * &s2);
    //                     let mut ct =
    //                         Ciphertext::new(vec![c0.clone(), c1.clone(),
    // c2.clone()], &params)?;

    //                     // Relinearize the extended ciphertext!
    //                     rk.relinearizes(&mut ct)?;
    //                     assert_eq!(ct.c.len(), 2);

    //                     // Check that the relinearization by polynomials
    // works the same way
    // c2.change_representation(Representation::PowerBasis);
    // let (mut c0r, mut c1r) = rk.relinearizes_poly(&c2)?;
    // c0r.change_representation(Representation::PowerBasis);
    // c0r.mod_switch_down_to(c0.ctx())?;
    // c1r.change_representation(Representation::PowerBasis);
    // c1r.mod_switch_down_to(c1.ctx())?;
    // c0r.change_representation(Representation::Ntt);
    // c1r.change_representation(Representation::Ntt);
    // assert_eq!(ct, Ciphertext::new(vec![&c0 + &c0r, &c1 + &c1r], &params)?);

    //                     // Print the noise and decrypt
    //                     println!("Noise: {}", unsafe { sk.measure_noise(&ct)?
    // });                     let pt = sk.try_decrypt(&ct)?;
    //                     let w = Vec::<u64>::try_decode(&pt,
    // Encoding::poly())?;                     assert_eq!(w, &[0u64; 8]);
    //                 }
    //             }
    //         }
    //     }
    //     Ok(())
    // }

    // #[test]
    // fn proto_conversion() -> Result<(), Box<dyn Error>> {
    //     let mut rng = thread_rng();
    //     for params in [
    //         BfvParameters::default_arc(6, 8),
    //         BfvParameters::default_arc(3, 8),
    //     ] {
    //         let sk = SecretKey::random(&params, &mut rng);
    //         let rk = RelinearizationKey::new(&sk, &mut rng)?;
    //         let proto = RelinearizationKeyProto::from(&rk);
    //         assert_eq!(rk, RelinearizationKey::try_convert_from(&proto,
    // &params)?);     }
    //     Ok(())
    // }
}
