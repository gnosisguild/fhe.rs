//! Relinearization for the BFV encryption scheme
//!
//! This module implements relinearization keys and the relinearization
//! operation for the RNS flavour of the BFV homomorphic encryption scheme.
//! Relinearization is a crucial operation that transforms degree-2 ciphertexts
//! (result of multiplication) back to degree-1 ciphertexts to manage noise
//! growth and ciphertext size.
//!
//! The implementation follows the decomposition technique in RNS for
//! key-switching as described in Halevi, Polyakov, and Shoup's paper "An
//! Improved RNS Variant of the BFV Homomorphic Encryption Scheme" (CT-RSA 2019)
//! <https://eprint.iacr.org/2018/117.pdf>. The technique involves:
//!
//! 1. Decomposing high-degree terms into smaller components using the chinese
//!    remainder theorem
//! 2. Using precomputed key-switching keys to transform these components
//! 3. Recombining the transformed components to obtain a degree-1 ciphertext
//!
//! This approach provides efficient relinearization while maintaining
//! controlled noise growth in the RNS representation.

use std::sync::Arc;

use crate::bfv::traits::TryConvertFrom;
use crate::bfv::{BfvParameters, Ciphertext, KeySwitchingKey, SecretKey};
use crate::proto::bfv::{
    KeySwitchingKey as KeySwitchingKeyProto, RelinearizationKey as RelinearizationKeyProto,
};
use crate::{Error, Result};
use fhe_math::rq::{
    switcher::Switcher, traits::TryConvertFrom as TryConvertFromPoly, Poly, Representation,
};
use fhe_traits::{DeserializeParametrized, FheParametrized, Serialize};
use prost::Message;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// A relinearization key in the BFV encryption scheme is fundamentally a key
/// switching key that transforms ciphertext terms encrypted under s² to terms
/// encrypted under s.
///
/// While this may seem counterintuitive, the mathematical construction ensures
/// that when this key is applied to a quadratic ciphertext (containing s² terms
/// from multiplication), the s² terms are eliminated through the key switching
/// process, resulting in a ciphertext that is linear in s. This transformation
/// is crucial for managing the growth of noise and ciphertext size after
/// homomorphic multiplication operations.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RelinearizationKey {
    pub(crate) ksk: KeySwitchingKey,
}

impl RelinearizationKey {
    /// Generate a [`RelinearizationKey`] from a [`SecretKey`].
    pub fn new<R: RngCore + CryptoRng>(sk: &SecretKey, rng: &mut R) -> Result<Self> {
        Self::new_leveled_internal(sk, 0, 0, rng)
    }

    /// Generate a [`RelinearizationKey`] from a [`SecretKey`].
    pub fn new_leveled<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        Self::new_leveled_internal(sk, ciphertext_level, key_level, rng)
    }

    /// Creates a relinearization key by:
    /// 1. Computing s² by converting the secret key s to NTT form and
    ///    multiplying it by itself
    /// 2. Converting s² back to power basis representation
    /// 3. Switching s² up to the key level context if needed
    /// 4. Creating a key switching key that transforms encryptions under s² to
    ///    encryptions under s
    ///
    /// The resulting key enables relinearization of quadratic ciphertexts
    /// (containing s² terms from multiplication) back to linear ciphertexts
    /// encrypted under s. This is done by:
    /// - Taking the c₂ component of a quadratic ciphertext (c₀, c₁, c₂)
    /// - Using the key switching key to transform it into (d₀, d₁) encrypted
    ///   under s
    /// - Adding d₀ to c₀ and d₁ to c₁ to get the final relinearized ciphertext
    ///
    /// This process is crucial for managing noise growth and keeping
    /// ciphertexts compact after homomorphic multiplication operations.
    fn new_leveled_internal<R: RngCore + CryptoRng>(
        sk: &SecretKey,
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

        let mut s = Zeroizing::new(Poly::try_convert_from(
            sk.coeffs.as_ref(),
            ctx_ciphertext,
            false,
            Representation::PowerBasis,
        )?);
        s.change_representation(Representation::Ntt);
        let mut s2 = Zeroizing::new(s.as_ref() * s.as_ref());
        s2.change_representation(Representation::PowerBasis);
        let switcher_up = Switcher::new(ctx_ciphertext, ctx_relin_key)?;
        let s2_switched_up = Zeroizing::new(s2.mod_switch_to(&switcher_up)?);
        let ksk = KeySwitchingKey::new(sk, &s2_switched_up, ciphertext_level, key_level, rng)?;
        Ok(Self { ksk })
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
        if ct.c.len() != 3 {
            Err(Error::DefaultError(
                "Only supports relinearization of ciphertext with 3 parts".to_string(),
            ))
        } else if ct.level != self.ksk.ciphertext_level {
            Err(Error::DefaultError(
                "Ciphertext has incorrect level".to_string(),
            ))
        } else {
            let mut c2 = ct.c[2].clone();
            c2.change_representation(Representation::PowerBasis);

            #[allow(unused_mut)]
            let (mut c0, mut c1) = self.relinearizes_poly(&c2)?;

            if c0.ctx() != ct.c[0].ctx() {
                c0.change_representation(Representation::PowerBasis);
                c1.change_representation(Representation::PowerBasis);
                c0.mod_switch_down_to(ct.c[0].ctx())?;
                c1.mod_switch_down_to(ct.c[1].ctx())?;
                c0.change_representation(Representation::Ntt);
                c1.change_representation(Representation::Ntt);
            }

            ct.c[0] += &c0;
            ct.c[1] += &c1;
            ct.c.truncate(2);
            Ok(())
        }
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
        self.ksk.key_switch(c2)
    }
}

/// Converts a [`RelinearizationKey`] into its protobuf representation
impl From<&RelinearizationKey> for RelinearizationKeyProto {
    fn from(value: &RelinearizationKey) -> Self {
        RelinearizationKeyProto {
            ksk: Some(KeySwitchingKeyProto::from(&value.ksk)),
        }
    }
}

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
impl TryConvertFrom<&RelinearizationKeyProto> for RelinearizationKey {
    fn try_convert_from(value: &RelinearizationKeyProto, par: &Arc<BfvParameters>) -> Result<Self> {
        if value.ksk.is_some() {
            Ok(RelinearizationKey {
                ksk: KeySwitchingKey::try_convert_from(value.ksk.as_ref().unwrap(), par)?,
            })
        } else {
            Err(Error::DefaultError("Invalid serialization".to_string()))
        }
    }
}

/// Serializes the [`RelinearizationKey`] into a byte vector
impl Serialize for RelinearizationKey {
    fn to_bytes(&self) -> Vec<u8> {
        RelinearizationKeyProto::from(self).encode_to_vec()
    }
}

/// Associates the [`RelinearizationKey`] with BFV parameters
impl FheParametrized for RelinearizationKey {
    type Parameters = BfvParameters;
}

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
impl DeserializeParametrized for RelinearizationKey {
    type Error = Error;

    fn from_bytes(bytes: &[u8], par: &Arc<Self::Parameters>) -> Result<Self> {
        let rk = Message::decode(bytes);
        if let Ok(rk) = rk {
            RelinearizationKey::try_convert_from(&rk, par)
        } else {
            Err(Error::DefaultError("Invalid serialization".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RelinearizationKey;
    use crate::bfv::{traits::TryConvertFrom, BfvParameters, Ciphertext, Encoding, SecretKey};
    use crate::proto::bfv::RelinearizationKey as RelinearizationKeyProto;
    use fhe_math::rq::{traits::TryConvertFrom as TryConvertFromPoly, Poly, Representation};
    use fhe_traits::{FheDecoder, FheDecrypter};
    use rand::thread_rng;
    use std::error::Error;

    #[test]
    fn relinearization() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        for params in [BfvParameters::default_arc(6, 8)] {
            for _ in 0..100 {
                let sk = SecretKey::random(&params, &mut rng);
                let rk = RelinearizationKey::new(&sk, &mut rng)?;

                let ctx = params.ctx_at_level(0)?;
                let mut s = Poly::try_convert_from(
                    sk.coeffs.as_ref(),
                    ctx,
                    false,
                    Representation::PowerBasis,
                )
                .map_err(crate::Error::MathError)?;
                s.change_representation(Representation::Ntt);
                let s2 = &s * &s;

                // Let's generate manually an "extended" ciphertext (c₀ = e - c₁·s - c₂·s²,
                // c₁, c₂) encrypting 0.
                let mut c2 = Poly::random(ctx, Representation::Ntt, &mut rng);
                let c1 = Poly::random(ctx, Representation::Ntt, &mut rng);
                let mut c0 = Poly::small(ctx, Representation::PowerBasis, 16, &mut rng)?;
                c0.change_representation(Representation::Ntt);
                c0 -= &(&c1 * &s);
                c0 -= &(&c2 * &s2);
                let mut ct = Ciphertext::new(vec![c0.clone(), c1.clone(), c2.clone()], &params)?;

                // Relinearize the extended ciphertext!
                rk.relinearizes(&mut ct)?;
                assert_eq!(ct.c.len(), 2);

                // Check that the relinearization by polynomials works the same way
                c2.change_representation(Representation::PowerBasis);
                let (mut c0r, mut c1r) = rk.relinearizes_poly(&c2)?;
                c0r.change_representation(Representation::PowerBasis);
                c0r.mod_switch_down_to(c0.ctx())?;
                c1r.change_representation(Representation::PowerBasis);
                c1r.mod_switch_down_to(c1.ctx())?;
                c0r.change_representation(Representation::Ntt);
                c1r.change_representation(Representation::Ntt);
                assert_eq!(ct, Ciphertext::new(vec![&c0 + &c0r, &c1 + &c1r], &params)?);

                // Print the noise and decrypt
                println!("Noise: {}", unsafe { sk.measure_noise(&ct)? });
                let pt = sk.try_decrypt(&ct)?;
                let w = Vec::<u64>::try_decode(&pt, Encoding::poly())?;
                assert_eq!(w, &[0u64; 8]);
            }
        }
        Ok(())
    }

    #[test]
    fn relinearization_leveled() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        for params in [BfvParameters::default_arc(5, 8)] {
            for ciphertext_level in 0..params.max_level() {
                for key_level in 0..=ciphertext_level {
                    for _ in 0..10 {
                        let sk = SecretKey::random(&params, &mut rng);
                        let rk = RelinearizationKey::new_leveled(
                            &sk,
                            ciphertext_level,
                            key_level,
                            &mut rng,
                        )?;

                        let ctx = params.ctx_at_level(ciphertext_level)?;
                        let mut s = Poly::try_convert_from(
                            sk.coeffs.as_ref(),
                            ctx,
                            false,
                            Representation::PowerBasis,
                        )
                        .map_err(crate::Error::MathError)?;
                        s.change_representation(Representation::Ntt);
                        let s2 = &s * &s;
                        // Let's generate manually an "extended" ciphertext (c₀ = e - c₁·s - c₂·s²,
                        // c₁, c₂) encrypting 0.
                        let mut c2 = Poly::random(ctx, Representation::Ntt, &mut rng);
                        let c1 = Poly::random(ctx, Representation::Ntt, &mut rng);
                        let mut c0 = Poly::small(ctx, Representation::PowerBasis, 16, &mut rng)?;
                        c0.change_representation(Representation::Ntt);
                        c0 -= &(&c1 * &s);
                        c0 -= &(&c2 * &s2);
                        let mut ct =
                            Ciphertext::new(vec![c0.clone(), c1.clone(), c2.clone()], &params)?;

                        // Relinearize the extended ciphertext!
                        rk.relinearizes(&mut ct)?;
                        assert_eq!(ct.c.len(), 2);

                        // Check that the relinearization by polynomials works the same way
                        c2.change_representation(Representation::PowerBasis);
                        let (mut c0r, mut c1r) = rk.relinearizes_poly(&c2)?;
                        c0r.change_representation(Representation::PowerBasis);
                        c0r.mod_switch_down_to(c0.ctx())?;
                        c1r.change_representation(Representation::PowerBasis);
                        c1r.mod_switch_down_to(c1.ctx())?;
                        c0r.change_representation(Representation::Ntt);
                        c1r.change_representation(Representation::Ntt);
                        assert_eq!(ct, Ciphertext::new(vec![&c0 + &c0r, &c1 + &c1r], &params)?);

                        // Print the noise and decrypt
                        println!("Noise: {}", unsafe { sk.measure_noise(&ct)? });
                        let pt = sk.try_decrypt(&ct)?;
                        let w = Vec::<u64>::try_decode(&pt, Encoding::poly())?;
                        assert_eq!(w, &[0u64; 8]);
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn proto_conversion() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        for params in [
            BfvParameters::default_arc(6, 8),
            BfvParameters::default_arc(3, 8),
        ] {
            let sk = SecretKey::random(&params, &mut rng);
            let rk = RelinearizationKey::new(&sk, &mut rng)?;
            let proto = RelinearizationKeyProto::from(&rk);
            assert_eq!(rk, RelinearizationKey::try_convert_from(&proto, &params)?);
        }
        Ok(())
    }
}
