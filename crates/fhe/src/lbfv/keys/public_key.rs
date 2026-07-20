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
use crate::proto::bfv::{Ciphertext as CiphertextProto, LbfvPublicKey as LBFVPublicKeyProto};
use fhe_math::rq::{
    Ntt, NttShoup, Poly, PowerBasis, Representation, switcher::Switcher,
    traits::TryConvertFrom as RqTryConvertFrom,
};
use fhe_traits::{DeserializeParametrized, FheEncrypter, FheParametrized, Serialize};

/// Public key for the L-BFV encryption scheme.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LBFVPublicKey {
    /// The BFV parameters
    pub params: Arc<BfvParameters>,
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
            params: sk.params.clone(),
            c,
            l: sk.params.moduli().len(),
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

    /// Build an [`LBFVPublicKey`] from explicit `b` and `a` polynomials.
    ///
    /// This is the on-chain URS constructor: the caller supplies the
    /// polynomials directly rather than deriving them from a seed.
    ///
    /// # Arguments
    /// * `b_polynomials` - The `l` b-polynomials `(b₀, …, bₗ₋₁)` where
    ///   `bⱼ = -aⱼ·sk + eⱼ`.
    /// * `a_polynomials` - The `l` shared CRS polynomials `(a₀, …, aₗ₋₁)`.
    ///   These are the *concrete* shared-input polynomials whose equality must
    ///   be verifiable across all contributions and between the public key and
    ///   the relinearization key. Must be at the same context as the
    ///   `b_polynomials`.
    /// * `seed` - Optional CRS seed for backwards compatibility. When `None`,
    ///   the key carries no seed and polynomial-level comparisons are the sole
    ///   consistency check.
    pub fn from_parts(
        b_polynomials: Vec<Poly<Ntt>>,
        a_polynomials: Vec<Poly<Ntt>>,
        params: Arc<BfvParameters>,
        seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
    ) -> Result<Self> {
        if b_polynomials.len() != a_polynomials.len() {
            return Err(Error::DefaultError(
                "b and a polynomial vectors have different lengths".to_string(),
            ));
        }
        let l = b_polynomials.len();
        if l != params.moduli().len() {
            return Err(Error::DefaultError(format!(
                "Expected {} polynomial pairs (one per modulus), got {l}",
                params.moduli().len()
            )));
        }

        let ctx0 = params.context_at_level(0)?;
        let mut c: Vec<Ciphertext> = Vec::with_capacity(l);
        for (b_poly, a_poly) in b_polynomials.into_iter().zip(a_polynomials.into_iter()) {
            if b_poly.ctx() != ctx0 || a_poly.ctx() != ctx0 {
                return Err(Error::DefaultError(
                    "Public-key polynomials must be at level 0".to_string(),
                ));
            }
            let mut ct = Ciphertext {
                params: params.clone(),
                seed: None,
                c: vec![b_poly, a_poly],
                level: 0,
            };
            ct.c.iter_mut()
                .for_each(|p| p.disallow_variable_time_computations());
            c.push(ct);
        }

        Ok(Self { params, c, l, seed })
    }

    /// Compute one party's public-key contribution using explicit CRS
    /// polynomials `a_j` from the on-chain URS.
    ///
    /// Each party encrypts zero under their `sk_i` using the shared `a_j`:
    /// `b_j = -a_j·sk_i + e_j`, producing `l` ciphertexts `(b_j, a_j)`.
    /// The result is an [`LBFVPublicKey`] contribution meant to be fed into
    /// [`aggregate`](Self::aggregate).
    ///
    /// This mirrors [`new_with_seed`](Self::new_with_seed) but uses explicit
    /// polynomials instead of a seed, so `seed` is `None`.
    pub fn contribute<R: RngCore + CryptoRng>(
        sk_i: &SecretKey,
        a_polynomials: &[Poly<Ntt>],
        rng: &mut R,
    ) -> Result<Self> {
        let l = sk_i.params.moduli().len();
        if a_polynomials.len() != l {
            return Err(Error::DefaultError(format!(
                "Expected {l} a_polynomials (one per modulus), got {}",
                a_polynomials.len()
            )));
        }

        let ctx = sk_i.params.context_at_level(0)?;
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_i.coeffs.as_ref(), ctx, false)?.into_ntt(),
        );

        let mut c: Vec<Ciphertext> = Vec::with_capacity(l);
        for a_j in a_polynomials {
            if a_j.ctx() != ctx {
                return Err(Error::DefaultError(
                    "a polynomial has incorrect context".to_string(),
                ));
            }

            let a_s = Zeroizing::new(a_j * s.as_ref());
            let mut b = Poly::<Ntt>::small(ctx, sk_i.params.variance, rng)?;
            b -= a_s.as_ref();

            let mut ct = Ciphertext {
                params: sk_i.params.clone(),
                seed: None,
                c: vec![b, a_j.clone()],
                level: 0,
            };
            ct.c.iter_mut()
                .for_each(|p| p.disallow_variable_time_computations());
            c.push(ct);
        }

        Ok(Self {
            params: sk_i.params.clone(),
            c,
            l,
            seed: None,
        })
    }

    /// Aggregate per-node public-key contributions into the threshold public key
    /// (DKG aggregation, Eq. (3) of §5.1 of
    /// [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf)).
    ///
    /// Each contribution is itself an [`LBFVPublicKey`] built by a single node
    /// from its secret-key contribution `sk_i` and the common CRS seed, i.e.
    /// `LBFVPublicKey::new_with_seed(sk_i, shared_seed, rng)`. A contribution is
    /// therefore `l` encryptions of zero `(b_{i,j}, a_j) = (-a_j·sk_i + e_{i,j},
    /// a_j)`, all sharing the CRS `a_j` derived from `shared_seed`.
    ///
    /// Aggregation sums the `b` components coordinate-wise and keeps the shared
    /// `a`:
    /// ```text
    ///   b_j = Σ_i b_{i,j} = -a_j·(Σ_i sk_i) + Σ_i e_{i,j} = -a_j·sk + e_j
    /// ```
    /// so the result is `l` encryptions of zero under the joint key
    /// `sk = Σ_i sk_i`, sharing the same CRS `a`. Component `[0]` doubles as the
    /// encryption key `(b_0, a_0)`, while the `b`-polynomials of all `l`
    /// components form the relinearization `b_vec` (via
    /// [`extract_b_polynomials`](Self::extract_b_polynomials)). Crucially, `sk`
    /// is never assembled: each node only ever holds its own `sk_i`.
    ///
    /// The shared seed is carried over to the result, so the same CRS `a` is
    /// reused when building the relinearization key's `d2` (it must match! see
    /// [`LBFVRelinKeyShare`](super::LBFVRelinKeyShare)).
    ///
    /// # Errors
    /// Returns an error if `contributions` is empty, or if the contributions are
    /// inconsistent (differing seed, `l`, parameters, or number of ciphertexts),
    /// which would mean they do not share a common CRS `a` and cannot be summed.
    #[allow(clippy::indexing_slicing)] // each ct.c has exactly 2 components (BFV invariant)
    pub fn aggregate(contributions: &[LBFVPublicKey]) -> Result<Self> {
        let (first, rest) = contributions.split_first().ok_or_else(|| {
            Error::DefaultError("Cannot aggregate zero public-key contributions".to_string())
        })?;

        for pk in rest {
            if pk.seed != first.seed
                || pk.l != first.l
                || pk.params != first.params
                || pk.c.len() != first.c.len()
            {
                return Err(Error::DefaultError(
                    "Public-key contributions are inconsistent (differing seed, l, or parameters)"
                        .to_string(),
                ));
            }
        }

        // Verify that the actual a_j (c[1]) polynomials match across all
        // contributions.  This is the concrete CRS check that seed equality
        // alone cannot guarantee (e.g. seedless deserialized keys).
        for j in 0..first.c.len() {
            let a_first = &first.c[j].c[1];
            for pk in rest {
                if a_first != &pk.c[j].c[1] {
                    return Err(Error::DefaultError(
                        "Public-key contributions have inconsistent CRS polynomials (a_j differ)"
                            .to_string(),
                    ));
                }
            }
        }

        let mut c: Vec<Ciphertext> = Vec::with_capacity(first.c.len());
        for (j, first_ct) in first.c.iter().enumerate() {
            let mut b = first_ct.c[0].clone();
            for pk in rest {
                b += &pk.c[j].c[0];
            }

            let a = first_ct.c[1].clone();
            let mut ct = Ciphertext {
                params: first.params.clone(),
                seed: None,
                c: vec![b, a],
                level: first_ct.level,
            };
            ct.c.iter_mut()
                .for_each(|p| p.disallow_variable_time_computations());
            c.push(ct);
        }

        Ok(Self {
            params: first.params.clone(),
            c,
            l: first.l,
            seed: first.seed,
        })
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

        let ctx = self.params.context_at_level(ct.level)?;
        let u = Poly::<Ntt>::small(ctx, self.params.variance, rng)?;
        let e1 = Poly::<Ntt>::small(ctx, self.params.variance, rng)?;
        let e2 = Poly::<Ntt>::small(ctx, self.params.variance, rng)?;

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
            params: self.params.clone(),
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
        if ciphertext_level > self.params.max_level() {
            return Err(Error::InvalidLevel {
                level: ciphertext_level,
                min_level: 0,
                max_level: self.params.max_level(),
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

        let key_ctx = self.params.context_at_level(key_level)?;
        if self.c[0].c[0].ctx() != key_ctx {
            return Err(Error::ParameterMismatch {
                left: crate::ParameterSource::PublicKey,
                right: crate::ParameterSource::Parameters,
            });
        }

        // Note: key switching is redundant for now.
        // Create switcher to mod switch from initial to final context (for when public key is at different level than ciphertext)
        let ciphertext_ctx = self.params.context_at_level(ciphertext_level)?;
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

        let ctx = self.params.context_at_level(ct.level)?;
        let u = Zeroizing::new(Poly::<Ntt>::small(ctx, self.params.variance, rng)?);
        let e1 = Zeroizing::new(Poly::<Ntt>::small(ctx, self.params.variance, rng)?);
        let e2 = Zeroizing::new(Poly::<Ntt>::small(ctx, self.params.variance, rng)?);

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
            params: self.params.clone(),
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

    fn from_bytes(bytes: &[u8], params: &Arc<Self::Parameters>) -> Result<Self> {
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
            let mut ct = Ciphertext::try_convert_from(&ct_proto, params)?;
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
            params: params.clone(),
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
    use fhe_math::rq::{Ntt, Poly};
    use fhe_math::zq::Modulus;
    use fhe_traits::{DeserializeParametrized, FheDecrypter, FheEncoder, FheEncrypter, Serialize};
    use rand::{Rng, SeedableRng, rng};
    use rand_chacha::ChaCha8Rng;
    use std::error::Error;

    #[test]
    fn test_aggregate_public_key() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let n = 3;

        // Common CRS seed shared by all nodes.
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);

        // Per-node secret-key contributions, and the matching public-key
        // contributions (l zero-encryptions under sk_i with the shared seed).
        let sk_shares: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let contributions: Vec<LBFVPublicKey> = sk_shares
            .iter()
            .map(|sk_i| LBFVPublicKey::new_with_seed(sk_i, seed, &mut rng))
            .collect();

        // Joint secret key, assembled only to check decryption in this test.
        let mut sum_coeffs = vec![0i64; params.degree()];
        for sk in &sk_shares {
            for (acc, c) in sum_coeffs.iter_mut().zip(sk.coeffs.iter()) {
                *acc = acc.wrapping_add(*c);
            }
        }
        let sk_joint = SecretKey::new(sum_coeffs, &params);

        let pk = LBFVPublicKey::aggregate(&contributions)?;

        // The aggregated key carries the shared CRS seed and the right l.
        assert_eq!(pk.seed, Some(seed));
        assert_eq!(pk.l, params.moduli().len());
        assert_eq!(pk.c.len(), params.moduli().len());

        // All l zero-encryptions decrypt to zero under the joint key.
        for ct in pk.c.iter() {
            assert_eq!(
                sk_joint.try_decrypt(ct)?,
                Plaintext::zero(Encoding::poly(), &params)?
            );
        }

        // Encrypt/decrypt roundtrip under the aggregated public key.
        let pt = Plaintext::try_encode(
            &Modulus::new(params.plaintext())?.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        assert_eq!(sk_joint.try_decrypt(&ct)?, pt);

        // A contribution under a different CRS seed must be rejected.
        let mut other_seed = seed;
        other_seed[0] ^= 0xff;
        let bad = LBFVPublicKey::new_with_seed(&sk_shares[0], other_seed, &mut rng);
        assert!(LBFVPublicKey::aggregate(&[contributions[0].clone(), bad]).is_err());

        Ok(())
    }

    #[test]
    fn keygen() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng);
        assert_eq!(pk.params, params);
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
                    let pk = LBFVPublicKey::new(&sk, &mut rng);

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

    #[test]
    fn test_serialize() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
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
    fn test_from_parts_roundtrip() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);

        let pk_seeded = LBFVPublicKey::new(&sk, &mut rng);
        let b_polys: Vec<Poly<Ntt>> = pk_seeded.c.iter().map(|ct| ct.c[0].clone()).collect();
        let a_polys: Vec<Poly<Ntt>> = pk_seeded.c.iter().map(|ct| ct.c[1].clone()).collect();
        let pk_from_parts =
            LBFVPublicKey::from_parts(b_polys, a_polys, params.clone(), pk_seeded.seed)?;

        // Roundtrip encrypt/decrypt under the from_parts key.
        let pt = Plaintext::try_encode(&[42u64], Encoding::poly(), &params)?;
        let ct = pk_from_parts.try_encrypt(&pt, &mut rng)?;
        assert_eq!(sk.try_decrypt(&ct)?, pt);

        // All l zero-encryptions decrypt to zero.
        for ct in pk_from_parts.c.iter() {
            assert_eq!(
                sk.try_decrypt(ct)?,
                Plaintext::zero(Encoding::poly(), &params)?
            );
        }

        Ok(())
    }

    #[test]
    fn test_contribute_and_aggregate() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let n = 3;

        // Generate shared CRS a polynomials from a seed (simulating on-chain URS).
        let a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let pk_ref =
            LBFVPublicKey::new_with_seed(&SecretKey::random(&params, &mut rng), a_seed, &mut rng);
        let a_polys: Vec<Poly<Ntt>> = pk_ref.c.iter().map(|ct| ct.c[1].clone()).collect();

        // Each party contributes using the shared a_polys.
        let sk_shares: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let contributions: Vec<LBFVPublicKey> = sk_shares
            .iter()
            .map(|sk_i| LBFVPublicKey::contribute(sk_i, &a_polys, &mut rng).unwrap())
            .collect();

        let pk = LBFVPublicKey::aggregate(&contributions)?;

        // Verify: seed is None (from explicit polynomials) and a_j match the reference.
        assert!(pk.seed.is_none());
        for (j, ct) in pk.c.iter().enumerate() {
            assert_eq!(ct.c[1], a_polys[j]);
        }

        // Joint secret key for decryption.
        let mut sum_coeffs = vec![0i64; params.degree()];
        for sk in &sk_shares {
            for (acc, c) in sum_coeffs.iter_mut().zip(sk.coeffs.iter()) {
                *acc = acc.wrapping_add(*c);
            }
        }
        let sk_joint = SecretKey::new(sum_coeffs, &params);

        let pt = Plaintext::try_encode(&[7u64], Encoding::poly(), &params)?;
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        assert_eq!(sk_joint.try_decrypt(&ct)?, pt);

        Ok(())
    }

    #[test]
    fn test_aggregate_rejects_inconsistent_a_polys() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);

        let a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let pk_ref =
            LBFVPublicKey::new_with_seed(&SecretKey::random(&params, &mut rng), a_seed, &mut rng);
        let a_polys: Vec<Poly<Ntt>> = pk_ref.c.iter().map(|ct| ct.c[1].clone()).collect();

        let sk = SecretKey::random(&params, &mut rng);
        let c1 = LBFVPublicKey::contribute(&sk, &a_polys, &mut rng)?;

        // Create a contribution with a tampered a polynomial.
        let mut bad_a = a_polys.to_vec();
        let ctx0 = params.context_at_level(0)?;
        bad_a[0] = Poly::<Ntt>::small(ctx0, params.variance, &mut rng)?; // random replacement
        let mut bad_cts = c1.c.clone();
        bad_cts[0].c[1] = bad_a[0].clone();
        let c_bad = LBFVPublicKey::from_parts(
            bad_cts.iter().map(|ct| ct.c[0].clone()).collect(),
            bad_a,
            params.clone(),
            None,
        )?;

        assert!(LBFVPublicKey::aggregate(&[c1, c_bad]).is_err());

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
