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
    BfvParameters, Ciphertext, CommonRandomPolyVec, Encoding, EncryptionIntermediates, Plaintext,
    SecretKey, traits::TryConvertFrom,
};
use crate::proto::bfv::Ciphertext as CiphertextProto;
use crate::proto::lbfv::LbfvPublicKey as LBFVPublicKeyProto;
use crate::reference_string::{same_concrete_values, validate_no_repeated_rows};
use crate::{EvaluationKeyError, MultipartyError, ReferenceStringRole};
use fhe_math::rq::{
    Ntt, NttShoup, Poly, PowerBasis, Representation, traits::TryConvertFrom as TryConvertPoly,
};
use fhe_traits::{DeserializeParametrized, FheEncrypter, FheParametrized, Serialize};

/// Public key for the L-BFV encryption scheme.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LBFVPublicKey {
    /// The BFV parameters
    pub par: Arc<BfvParameters>,
    /// The public key ciphertexts, one for each RNS modulus
    pub c: Vec<Ciphertext>,
    /// The decomposition size: the number of RNS moduli (the `l` in l-BFV).
    /// The [threshold-encryption construction](https://eprint.iacr.org/2024/1285.pdf)
    /// uses the gadget-vector length; here RNS decomposition follows the
    /// [HPS optimization](https://eprint.iacr.org/2018/117.pdf).
    pub l: usize,
    /// Seed for the public random polynomials, not for the fresh encryption errors.
    pub seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
}

impl LBFVPublicKey {
    /// Generate a new [`LBFVPublicKey`] from a [`SecretKey`] using a provided
    /// seed. The seed is used to generate l seeds for the ciphertexts which are
    /// used to generate the random polynomials aᵢ for each ciphertext
    /// deterministically.
    ///
    /// This legacy constructor panics on invalid inputs. Use
    /// [`Self::try_new_with_seed`] for fallible contribution generation.
    #[expect(
        clippy::expect_used,
        reason = "preserve the infallible 0.6 constructor"
    )]
    pub fn new_with_seed<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Self {
        Self::seeded(sk, seed, rng).expect("invalid l-BFV key-generation input")
    }

    /// Fallible seeded key generation for callers supplying a secret contribution.
    pub fn try_new_with_seed<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        seed: [u8; 32],
        rng: &mut R,
    ) -> Result<Self> {
        sk.validate_coefficient_count()?;
        Self::seeded(sk, seed, rng)
    }

    fn seeded<R: RngCore + CryptoRng>(sk: &SecretKey, seed: [u8; 32], rng: &mut R) -> Result<Self> {
        let zero = Plaintext::zero(Encoding::poly(), &sk.params)?;
        let mut c: Vec<Ciphertext> = Vec::with_capacity(sk.params.moduli().len());

        // Create a vector of ciphertexts, each encrypting zero, for each RNS modulus
        // [(b₁, a₁), ..., (bₗ, aₗ)].
        for seed_i in Self::row_seeds(seed).take(sk.params.moduli().len()) {
            let mut ct = sk.try_encrypt_with_seed(&zero, seed_i, rng)?;
            // The polynomials of a public key should not allow for variable time
            // computation.
            ct.c.iter_mut()
                .for_each(|p| p.disallow_variable_time_computations());
            c.push(ct);
        }

        validate_no_repeated_rows(
            ReferenceStringRole::Crs,
            c.iter().filter_map(|row| row.c.get(1)),
        )?;
        Ok(Self {
            par: sk.params.clone(),
            c,
            l: sk.params.moduli().len(),
            seed: Some(seed),
        })
    }

    /// Generate a new [`LBFVPublicKey`] from a [`SecretKey`] using a random
    /// seed.
    pub fn new<R: RngCore + CryptoRng>(sk: &SecretKey, rng: &mut R) -> Result<Self> {
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);
        Self::seeded(sk, seed, rng)
    }

    fn row_seeds(seed: [u8; 32]) -> impl Iterator<Item = [u8; 32]> {
        let mut rng = ChaCha8Rng::from_seed(seed);
        std::iter::repeat_with(move || {
            let mut row = [0; 32];
            rng.fill(&mut row);
            row
        })
    }

    /// Generate a key using the supplied level-zero public randomness.
    pub fn new_with_crp<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        crp: &CommonRandomPolyVec,
        rng: &mut R,
    ) -> Result<Self> {
        Self::from_crs(sk, crp.to_polys(), crp.seed(), rng)
    }

    pub(crate) fn from_crs<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        a: Vec<Poly<Ntt>>,
        seed: Option<[u8; 32]>,
        rng: &mut R,
    ) -> Result<Self> {
        sk.validate_coefficient_count()?;
        Self::validate_crs(&a, &sk.params, seed)?;
        let ctx = sk.params.context_at_level(0)?;
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx, false)?.into_ntt(),
        );
        let b = a
            .iter()
            .map(|a| {
                let product = Zeroizing::new(a * s.as_ref());
                let mut b = Poly::<Ntt>::small(ctx, sk.params.variance(), rng)?;
                b -= product.as_ref();
                Ok(b)
            })
            .collect::<Result<Vec<_>>>()?;
        Self::assemble(b, a, sk.params.clone(), seed)
    }

    /// Construct an operational key from ordered `(b, a)` rows. A supplied
    /// master seed must reproduce every concrete `a` polynomial.
    pub fn from_parts(
        b: Vec<Poly<Ntt>>,
        a: Vec<Poly<Ntt>>,
        params: Arc<BfvParameters>,
        seed: Option<[u8; 32]>,
    ) -> Result<Self> {
        Self::validate_crs(&a, &params, seed)?;
        Self::assemble(b, a, params, seed)
    }

    fn validate_crs(
        a: &[Poly<Ntt>],
        params: &Arc<BfvParameters>,
        seed: Option<[u8; 32]>,
    ) -> Result<()> {
        let ctx = params.context_at_level(0)?;
        if a.len() != params.moduli().len() {
            return Err(EvaluationKeyError::InvalidDecompositionLength {
                actual: a.len(),
                expected: params.moduli().len(),
            }
            .into());
        }
        let mut seeds = seed.map(Self::row_seeds);
        for (index, row) in a.iter().enumerate() {
            if row.ctx() != ctx || !row.has_canonical_coefficients() {
                return Err(EvaluationKeyError::InvalidLbfvLayout {
                    reason: "CRS rows must be canonical level-zero polynomials",
                }
                .into());
            }
            if let Some(seed) = seeds.as_mut().and_then(Iterator::next)
                && !same_concrete_values(row, &Poly::<Ntt>::random_from_seed(ctx, seed))
            {
                return Err(MultipartyError::CommonRandomPolynomialSeedMismatch { index }.into());
            }
        }
        validate_no_repeated_rows(ReferenceStringRole::Crs, a)
    }

    fn assemble(
        b: Vec<Poly<Ntt>>,
        a: Vec<Poly<Ntt>>,
        par: Arc<BfvParameters>,
        seed: Option<[u8; 32]>,
    ) -> Result<Self> {
        let l = a.len();
        if b.len() != l {
            return Err(EvaluationKeyError::InvalidDecompositionLength {
                actual: b.len(),
                expected: l,
            }
            .into());
        }
        let ctx = par.context_at_level(0)?;
        let mut seeds = seed.map(Self::row_seeds);
        let c = b
            .into_iter()
            .zip(a)
            .map(|(mut b, mut a)| {
                if b.ctx() != ctx || !b.has_canonical_coefficients() {
                    return Err(EvaluationKeyError::InvalidLbfvLayout {
                        reason: "public-key b rows must be canonical level-zero polynomials",
                    }
                    .into());
                }
                a.disallow_variable_time_computations();
                b.disallow_variable_time_computations();
                Ok(Ciphertext {
                    params: par.clone(),
                    c: vec![b, a],
                    level: 0,
                    seed: seeds.as_mut().and_then(Iterator::next),
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self { par, c, l, seed })
    }

    /// Public fields and per-ciphertext seed metadata can be mutated by a
    /// 0.6 caller. Check them before using an operational key in a key ceremony.
    pub(crate) fn validate_rows(&self) -> Result<()> {
        let expected = self.par.moduli().len();
        if self.l != expected || self.c.len() != expected {
            return Err(EvaluationKeyError::InvalidLbfvLayout {
                reason: "public-key row count and l must match the modulus count",
            }
            .into());
        }
        let ctx = self.par.context_at_level(0)?;
        let mut seeds = self.seed.map(Self::row_seeds);
        let mut rows = Vec::with_capacity(expected);
        for (index, row) in self.c.iter().enumerate() {
            row.validate_for_context(&self.par, 0, ctx)?;
            let [b, a] = row.c.as_slice() else {
                return Err(EvaluationKeyError::InvalidLbfvLayout {
                    reason: "public-key rows must contain exactly (b, a)",
                }
                .into());
            };
            if !b.has_canonical_coefficients() || !a.has_canonical_coefficients() {
                return Err(EvaluationKeyError::InvalidLbfvLayout {
                    reason: "public-key rows must be canonical",
                }
                .into());
            }
            let derived = seeds.as_mut().and_then(Iterator::next);
            if let Some(seed) = derived.or(row.seed)
                && (row.seed.is_some_and(|actual| actual != seed)
                    || !same_concrete_values(a, &Poly::<Ntt>::random_from_seed(ctx, seed)))
            {
                return Err(MultipartyError::CommonRandomPolynomialSeedMismatch { index }.into());
            }
            rows.push(a);
        }
        validate_no_repeated_rows(ReferenceStringRole::Crs, rows)
    }

    /// Encrypt a plaintext and return the randomness and errors used to construct it.
    ///
    /// The intermediates zeroize their polynomials when dropped.
    #[allow(clippy::indexing_slicing)] // ct.c always has exactly 2 components (BFV invariant)
    pub fn try_encrypt_with_intermediates<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<(Ciphertext, EncryptionIntermediates)> {
        let ct = self.encryption_key_at_level(pt)?;

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
        c0 += e1.as_ref();
        c0 += &m;
        let mut c1 = u.as_ref() * &ct.c[1];
        c1 += e2.as_ref();

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

        Ok((ciphertext, EncryptionIntermediates::new(u, e1, e2)))
    }

    fn encryption_key_at_level(&self, pt: &Plaintext) -> Result<Ciphertext> {
        let key = self
            .c
            .first()
            .ok_or(crate::EvaluationKeyError::EmptyPublicKey)?;
        pt.validate_for(&self.par)?;
        key.validate_for(&self.par)?;
        if key.c.len() != 2 || !key.c.iter().all(Poly::has_canonical_coefficients) {
            return Err(EvaluationKeyError::InvalidLbfvLayout {
                reason: "encryption requires a canonical two-component public-key row",
            }
            .into());
        }

        let plaintext_level = pt.level();
        if plaintext_level < key.level {
            return Err(Error::InvalidLevel {
                level: plaintext_level,
                min_level: key.level,
                max_level: self.par.max_level(),
            });
        }

        let mut ct = key.clone();
        while ct.level != plaintext_level {
            ct.switch_down()?;
        }
        Ok(ct)
    }

    /// Extract the public-key `b` polynomials in NTT-Shoup representation at key level zero.
    ///
    /// Extracts the `c[0]` component of each of the first
    /// `l - ciphertext_level` public-key ciphertexts and converts the result to
    /// [`Representation::NttShoup`].
    ///
    /// # Arguments
    /// * `ciphertext_level` - The level of the ciphertext that will use these polynomials
    /// * `key_level` - The level of the key that will be used (currently must be 0)
    /// * `rep` - Must be [`Representation::NttShoup`]
    ///
    /// # Returns
    /// * `Ok(Vec<Poly>)` - A vector of polynomials in the specified representation at the target level
    /// * `Err` if:
    ///   - The requested ciphertext level is greater than the maximum level
    ///   - The key level is not 0 (current limitation)
    ///   - The public key is not at level 0
    ///   - The requested representation is not NTT-Shoup
    ///   - The public key has inconsistent rows or seed metadata
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

        if key_level != 0 {
            return Err(Error::InvalidLevel {
                level: key_level,
                min_level: 0,
                max_level: 0,
            });
        }

        if rep != Representation::NttShoup {
            return Err(EvaluationKeyError::UnsupportedRepresentation {
                found: format!("{rep:?}"),
            }
            .into());
        }
        self.validate_rows()?;
        Ok(self.b_prefix(self.l - ciphertext_level))
    }

    pub(crate) fn b_prefix(&self, count: usize) -> Vec<Poly<NttShoup>> {
        self.c
            .iter()
            .take(count)
            .filter_map(|row| row.first())
            .cloned()
            .map(Poly::<Ntt>::into_ntt_shoup)
            .collect()
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
        let ct = self.encryption_key_at_level(pt)?;

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

        Self::from_proto(proto, par)
    }
}

impl LBFVPublicKey {
    pub(crate) fn from_proto(proto: LBFVPublicKeyProto, par: &Arc<BfvParameters>) -> Result<Self> {
        if proto.c.is_empty() {
            return Err(Error::SerializationError(
                SerializationError::MissingField {
                    field: crate::SerializedField::PublicKeyCiphertext,
                },
            ));
        }

        if proto.l as usize != par.moduli().len() || proto.c.len() != proto.l as usize {
            return Err(EvaluationKeyError::InvalidLbfvLayout {
                reason: "serialized public-key row count or l does not match the parameters",
            }
            .into());
        }
        let mut c: Vec<Ciphertext> = Vec::with_capacity(proto.c.len());
        for ct_proto in proto.c {
            if ct_proto.c.len() != if ct_proto.seed.is_empty() { 2 } else { 1 } {
                return Err(SerializationError::InvalidCiphertextPolynomialCount {
                    actual: ct_proto.c.len(),
                    seed_present: !ct_proto.seed.is_empty(),
                }
                .into());
            }
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

        let key = Self {
            par: par.clone(),
            c,
            l: proto.l as usize,
            seed,
        };
        key.validate_rows()?;
        Ok(key)
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

    #[test]
    fn encryption_rejects_mismatched_parameters_and_invalid_level() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(2, 16);
        let other_params = BfvParameters::default_arc(2, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let mut pk = LBFVPublicKey::new(&sk, &mut rng)?;
        let mismatched_pt = Plaintext::try_encode(&[1u64], Encoding::poly(), &other_params)?;
        assert!(
            pk.try_encrypt_with_intermediates(&mismatched_pt, &mut rng)
                .is_err()
        );
        assert!(pk.try_encrypt(&mismatched_pt, &mut rng).is_err());

        let pt = Plaintext::try_encode(&[1u64], Encoding::poly(), &params)?;
        pk.c[0].params = other_params;
        assert!(pk.try_encrypt_with_intermediates(&pt, &mut rng).is_err());
        assert!(pk.try_encrypt(&pt, &mut rng).is_err());
        pk.c[0].params = params.clone();

        pk.c[0].switch_down()?;
        assert!(matches!(
            pk.try_encrypt_with_intermediates(&pt, &mut rng),
            Err(crate::Error::InvalidLevel {
                level: 0,
                min_level: 1,
                ..
            })
        ));
        assert!(matches!(
            pk.try_encrypt(&pt, &mut rng),
            Err(crate::Error::InvalidLevel {
                level: 0,
                min_level: 1,
                ..
            })
        ));
        Ok(())
    }

    /// `try_encrypt` and `try_encrypt_with_intermediates` must sample `e1` from the
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

        let (ct_ext, _intermediates) = pk.try_encrypt_with_intermediates(&pt, &mut rng)?;
        let pt2_ext = sk.try_decrypt(&ct_ext)?;
        assert_eq!(pt2_ext, pt);

        Ok(())
    }

    /// `try_encrypt_with_intermediates` equations: `c0 = u·b + e1 + m` and
    /// `c1 = u·a + e2`.
    #[test]
    fn extended_encrypt_intermediates_equations() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;

        let pt = Plaintext::try_encode(
            &Modulus::new(params.plaintext())?.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;

        let (ct, intermediates) = pk.try_encrypt_with_intermediates(&pt, &mut rng)?;

        let b = pk.c[0].c[0].clone();
        let a = pk.c[0].c[1].clone();
        let m = pt.to_poly();

        let mut expected_c0 = intermediates.randomness() * &b;
        expected_c0 += intermediates.error_0();
        expected_c0 += &m;
        let mut expected_c1 = intermediates.randomness() * &a;
        expected_c1 += intermediates.error_1();

        assert_eq!(ct.c[0].coefficients(), expected_c0.coefficients());
        assert_eq!(ct.c[1].coefficients(), expected_c1.coefficients());

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
