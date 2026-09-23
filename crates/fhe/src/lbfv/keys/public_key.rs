/*!
 * Public key for the l-BFV encryption scheme.
 *
 * # Concrete vs. seed-derived polynomials
 *
 * Every public key holds `l` ciphertexts `(b_j, a_j)`.  The **concrete**
 * `a_j` polynomials are the authoritative shared reference string (CRS):
 * equality checks compare the actual polynomial coefficients, never seeds alone.
 *
 * The value returned by [`seed`](LBFVPublicKey::seed) is optional compression
 * metadata: it records the seed that *would* regenerate the same `a_j`
 * polynomials, making serialization smaller.  When present, it is
 * verified against the concrete polynomials at construction and
 * deserialization time (see [`from_parts`](LBFVPublicKey::from_parts)).
 * A seed that contradicts the concrete polynomials is rejected.
 *
 * # Wire representations
 *
 * Seeded keys serialize only the secret-dependent `b_j` rows and one CRS seed;
 * deserialization regenerates every concrete `a_j`. Seedless keys serialize
 * every explicit `(b_j, a_j)` row. The decoder requires exactly one of these
 * representation fields, so mixed or missing encodings are not accepted.
 * Payloads produced by the older flat `c`/`l`/`seed` schema are intentionally
 * rejected.
 *
 * The seed is compression metadata, not protocol authentication. Applications
 * must bind the expected CRS seed to their authenticated protocol context.
 *
 * # Single-party operational key
 *
 * This module provides a strictly single-party operational public key.
 * There is no distributed aggregation or threshold construction. All
 * threshold/multiparty utilities live in [`crate::trlbfv`]; use
 * [`crate::trlbfv::PublicKeyShare`] for distributed-key workflows.
 */

use crate::{Error, Result};
use std::sync::Arc;

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use zeroize::Zeroizing;

use crate::bfv::{BfvParameters, Ciphertext, CommonRandomPolyVec, Encoding, Plaintext, SecretKey};
use fhe_math::rq::{
    Ntt, NttShoup, Poly, PowerBasis, Representation, switcher::Switcher, traits::TryConvertFrom,
};
use fhe_traits::{FheEncrypter, FheParametrized};

/// Public key for the L-BFV encryption scheme.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LBFVPublicKey {
    /// The BFV parameters
    pub(crate) params: Arc<BfvParameters>,
    /// The public key ciphertexts, one for each RNS modulus
    pub(crate) c: Vec<Ciphertext>,
    /// The decomposition size which is the number of RNS moduli (the l in lBFV).
    /// Note while l in https://eprint.iacr.org/2024/1285.pdf is equal to the size
    /// chosen of the Gadget vector, here it is equal the number of RNS moduli
    /// as the library uses the optimization of https://eprint.iacr.org/2018/117.pdf
    pub(crate) l: usize,
    /// Optional compression metadata: the seed that generates the same
    /// concrete `a_j` CRS polynomials as those stored in `c`. When absent
    /// (e.g. seedless deserialized or contributed keys), polynomial-level
    /// comparison is the sole consistency mechanism. When present, it is
    /// verified against the concrete polynomials at construction time.
    pub(crate) seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
}

impl LBFVPublicKey {
    /// Return the validated public-key rows in gadget-row order.
    ///
    /// Each row is a two-component ciphertext `(b, a)`. Constructors and
    /// deserialization validate that the row count and ciphertext structure
    /// match the key parameters.
    #[must_use]
    pub fn rows(&self) -> &[Ciphertext] {
        &self.c
    }

    /// Return the number of gadget rows in this public key.
    #[must_use]
    pub const fn row_count(&self) -> usize {
        self.l
    }

    /// Return the BFV parameters for this public key.
    #[must_use]
    pub fn parameters(&self) -> &BfvParameters {
        &self.params
    }

    /// Return the seed that reproduces the concrete CRS polynomials, if stored.
    #[must_use]
    pub const fn seed(&self) -> Option<<ChaCha8Rng as SeedableRng>::Seed> {
        self.seed
    }

    /// Generate a new [`LBFVPublicKey`] from a [`SecretKey`] using a provided
    /// seed. The seed is used to generate l seeds for the ciphertexts which are
    /// used to generate the random polynomials aᵢ for each ciphertext
    /// deterministically.
    pub fn new_with_seed<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Result<Self> {
        Self::new_with_seed_inner(sk, seed, rng)
    }

    /// Fallible version of [`new_with_seed`](Self::new_with_seed).
    ///
    /// Validates that the secret key's coefficient count matches the parameter
    /// degree before delegating.  Callers that should never panic (e.g.
    /// bound distributed-construction paths) must use this instead of the
    /// infallible [`new_with_seed`](Self::new_with_seed).
    fn new_with_seed_inner<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Result<Self> {
        if sk.coeffs.len() != sk.params.degree() {
            return Err(Error::DefaultError(format!(
                "Secret key has {} coefficients, expected {}",
                sk.coeffs.len(),
                sk.params.degree()
            )));
        }

        let zero = Plaintext::zero(Encoding::poly(), &sk.params)?;
        let row_seeds = Self::derive_crs_row_seeds(&sk.params, seed);
        let mut c: Vec<Ciphertext> = Vec::with_capacity(row_seeds.len());

        // Create a vector of ciphertexts, each encrypting zero, for each RNS modulus
        // [(b₁, a₁), ..., (bₗ, aₗ)].
        for seed_i in row_seeds {
            let mut ct = sk.try_encrypt_with_seed(&zero, seed_i, rng)?;
            // The polynomials of a public key should not allow for variable time
            // computation.
            ct.c.iter_mut()
                .for_each(|p| p.disallow_variable_time_computations());
            c.push(ct);
        }

        Ok(Self {
            params: sk.params.clone(),
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
        Self::new_with_seed(sk, seed, rng)
    }

    /// Build a public key from a [`SecretKey`] and explicit CRS polynomials `a_j`.
    ///
    /// This is the core operational constructor: the caller supplies the shared
    /// `a_j` CRS polynomials (as a slice of NTT polynomials) and an optional
    /// compression seed, and the helper computes `b_j = -a_j·sk + e_j` for each
    /// `j`, then delegates to [`from_parts`](Self::from_parts).
    ///
    /// # Arguments
    /// * `sk` - The secret key.
    /// * `a_polynomials` - The `l` shared CRS polynomials `a_j`.
    /// * `seed` - Optional compression metadata seed. When `None`, the key
    ///   carries no seed.
    /// * `rng` - RNG for sampling the error polynomials `e_j`.
    pub(crate) fn from_crs<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        a_polynomials: &[Poly<Ntt>],
        seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
        rng: &mut R,
    ) -> Result<Self> {
        if sk.coeffs.len() != sk.params.degree() {
            return Err(Error::DefaultError(format!(
                "Secret key has {} coefficients, expected {}",
                sk.coeffs.len(),
                sk.params.degree()
            )));
        }

        let l = sk.params.moduli().len();
        if a_polynomials.len() != l {
            return Err(Error::DefaultError(format!(
                "Expected {l} a_polynomials (one per modulus), got {}",
                a_polynomials.len()
            )));
        }

        let ctx = sk.params.context_at_level(0)?;
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx, false)?.into_ntt(),
        );

        let mut b_polys: Vec<Poly<Ntt>> = Vec::with_capacity(l);
        for a_j in a_polynomials {
            if a_j.ctx() != ctx {
                return Err(Error::DefaultError(
                    "a polynomial has incorrect context".to_string(),
                ));
            }

            let a_s = Zeroizing::new(a_j * s.as_ref());
            let mut b = Poly::<Ntt>::small(ctx, sk.params.variance, rng)?;
            b -= a_s.as_ref();
            b_polys.push(b);
        }

        Self::from_parts(b_polys, a_polynomials.to_vec(), sk.params.clone(), seed)
    }

    /// Generate a new [`LBFVPublicKey`] from a [`SecretKey`] using explicit
    /// CRS polynomials supplied as a [`CommonRandomPolyVec`].
    ///
    /// The concrete `a_j` polynomials are extracted from `crp` and used as the
    /// shared CRS; the optional seed is copied into the key as compression
    /// metadata.
    pub fn new_with_crp<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        crp: &CommonRandomPolyVec,
        rng: &mut R,
    ) -> Result<Self> {
        Self::from_crs(sk, &crp.to_polys(), crp.seed(), rng)
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
        for (b_poly, a_poly) in b_polynomials.into_iter().zip(a_polynomials) {
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

        // When a seed is provided, verify that the supplied a polynomials
        // match the concrete polynomials the seed would produce. Preserve each
        // derived row seed as compression metadata on its ciphertext.
        if let Some(seed) = seed {
            let derived_crs = Self::derive_crs_rows(&params, seed)?;
            for (j, (ct, (seed_j, expected_a))) in c.iter_mut().zip(derived_crs).enumerate() {
                let actual_a = ct.c.get(1).ok_or_else(|| {
                    Error::DefaultError("Ciphertext is missing a component".to_string())
                })?;
                if expected_a != *actual_a {
                    return Err(Error::DefaultError(format!(
                        "Supplied seed does not match the concrete a polynomial at index {j}"
                    )));
                }
                ct.seed = Some(seed_j);
            }
        }

        Ok(Self { params, c, l, seed })
    }

    fn derive_crs_rows(
        params: &Arc<BfvParameters>,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
    ) -> Result<Vec<(<ChaCha8Rng as SeedableRng>::Seed, Poly<Ntt>)>> {
        let ctx0 = params.context_at_level(0)?;
        Ok(Self::derive_crs_row_seeds(params, seed)
            .into_iter()
            .map(|row_seed| (row_seed, Poly::<Ntt>::random_from_seed(ctx0, row_seed)))
            .collect())
    }

    fn derive_crs_row_seeds(
        params: &BfvParameters,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
    ) -> Vec<<ChaCha8Rng as SeedableRng>::Seed> {
        let mut seed_rng = ChaCha8Rng::from_seed(seed);
        (0..params.moduli().len())
            .map(|_| {
                let mut row_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
                seed_rng.fill(&mut row_seed);
                row_seed
            })
            .collect()
    }

    // ---------------------------------------------------------------------------
    // Structural validation and safe accessors
    // ---------------------------------------------------------------------------

    /// Validate that the public-key structure is consistent: `l` matches the
    /// parameter modulus count, every ciphertext has exactly two components at
    /// level 0, and all polynomial contexts match the parameter's level-0 context.
    pub(crate) fn validate_structure(&self) -> Result<()> {
        let expected_l = self.params.moduli().len();
        if self.l != expected_l {
            return Err(Error::DefaultError(
                "LBFV public-key l does not match the parameter modulus count".to_string(),
            ));
        }
        if self.c.len() != expected_l {
            return Err(Error::DefaultError(
                "LBFV public-key ciphertext count does not match l".to_string(),
            ));
        }

        let ctx0 = self.params.context_at_level(0)?;
        for (index, ciphertext) in self.c.iter().enumerate() {
            if ciphertext.params != self.params {
                return Err(Error::DefaultError(format!(
                    "LBFV public-key ciphertext {index} has incompatible parameters"
                )));
            }
            if ciphertext.level != 0 {
                return Err(Error::DefaultError(format!(
                    "LBFV public-key ciphertext {index} is not at level 0"
                )));
            }
            if ciphertext.c.len() != 2 {
                return Err(Error::DefaultError(format!(
                    "LBFV public-key ciphertext {index} must have exactly two components"
                )));
            }
            for polynomial in &ciphertext.c {
                if polynomial.ctx() != ctx0 {
                    return Err(Error::DefaultError(format!(
                        "LBFV public-key ciphertext {index} has an incorrect polynomial context"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Extract the `a` polynomials from the first `ciphertext_level` ciphertexts
    /// for use as explicit CRS material.
    ///
    /// Currently requires `key_level == 0`.
    pub(crate) fn a_polynomials_for_level(
        &self,
        ciphertext_level: usize,
        key_level: usize,
    ) -> Result<Vec<Poly<NttShoup>>> {
        self.validate_structure()?;

        if key_level != 0 {
            return Err(Error::DefaultError(
                "Explicit l-BFV CRS extraction currently requires key level 0".to_string(),
            ));
        }
        if ciphertext_level > self.params.max_level() {
            return Err(Error::InvalidLevel {
                level: ciphertext_level,
                min_level: 0,
                max_level: self.params.max_level(),
            });
        }

        let count = self
            .l
            .checked_sub(ciphertext_level)
            .ok_or_else(|| Error::DefaultError("Invalid l-BFV ciphertext level".to_string()))?;

        self.c
            .iter()
            .take(count)
            .map(|ciphertext| {
                ciphertext
                    .c
                    .get(1)
                    .cloned()
                    .map(Poly::<Ntt>::into_ntt_shoup)
                    .ok_or_else(|| {
                        Error::DefaultError(
                            "LBFV public-key ciphertext is missing its a polynomial".to_string(),
                        )
                    })
            })
            .collect()
    }

    /// Encrypt a plaintext with the public key.
    /// The encryption is done in the same level as the plaintext.
    /// Returns the ciphertext and the noise polynomials.
    #[allow(clippy::type_complexity)]
    #[cfg(test)]
    pub fn try_encrypt_extended<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<(Ciphertext, Poly<Ntt>, Poly<Ntt>, Poly<Ntt>)> {
        // Validate public-key structure before using it for encryption.
        self.validate_structure()?;

        // Use only the first ciphertext from the array
        let mut ct = self.c.first().cloned().ok_or_else(|| {
            Error::DefaultError("Public key has no ciphertexts available".to_string())
        })?;
        while ct.level != pt.level() {
            ct.switch_down()?;
        }

        let ctx = self.params.context_at_level(ct.level)?;
        let u = Poly::<Ntt>::small(ctx, self.params.variance, rng)?;
        let e1 = Poly::<Ntt>::error_1(ctx, Representation::Ntt, &self.params.error1_variance, rng)?;
        let e2 = Poly::<Ntt>::small(ctx, self.params.variance, rng)?;

        let m = Zeroizing::new(pt.to_poly());
        let b = ct
            .c
            .first()
            .ok_or_else(|| Error::DefaultError("Ciphertext is missing b component".to_string()))?;
        let a = ct
            .c
            .get(1)
            .ok_or_else(|| Error::DefaultError("Ciphertext is missing a component".to_string()))?;
        let mut c0 = u.as_ref() * b;
        c0 += &e1;
        c0 += &m;
        let mut c1 = u.as_ref() * a;
        c1 += &e2;

        // It is now safe to enable variable time computations.
        c0.allow_variable_time_computations(fhe_traits::VariableTime::new(
            fhe_traits::PublicData::assert_public(),
        ));
        c1.allow_variable_time_computations(fhe_traits::VariableTime::new(
            fhe_traits::PublicData::assert_public(),
        ));

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
    pub fn extract_b_polynomials(
        &self,
        ciphertext_level: usize,
        key_level: usize,
        rep: Representation,
    ) -> Result<Vec<Poly<NttShoup>>> {
        // Validate public-key structure before accessing ciphertexts.
        self.validate_structure()?;

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
        let first_ct = self
            .c
            .first()
            .ok_or_else(|| Error::DefaultError("Public key has no ciphertexts".to_string()))?;
        let first_b = first_ct.c.first().ok_or_else(|| {
            Error::DefaultError("Public-key ciphertext is missing b component".to_string())
        })?;
        if first_b.ctx() != key_ctx {
            return Err(Error::DefaultError(
                "Public key is not at level 0".to_string(),
            ));
        }

        // Note: key switching is redundant for now.
        // Create switcher to mod switch from initial to final context (for when public key is at different level than ciphertext)
        let ciphertext_ctx = self.params.context_at_level(ciphertext_level)?;
        let switcher = Switcher::new(ciphertext_ctx, key_ctx)?;

        // Extract (l - level) b polynomials and change representation accordingly
        let new_l = self
            .l
            .checked_sub(ciphertext_level)
            .ok_or_else(|| Error::DefaultError("Invalid l-BFV ciphertext level".to_string()))?;
        let mut b_polynomials = Vec::with_capacity(new_l);
        for i in 0..new_l {
            let ct = self.c.get(i).ok_or_else(|| {
                Error::DefaultError("Public-key ciphertext index out of bounds".to_string())
            })?;
            let mut poly = ct.c.first().cloned().ok_or_else(|| {
                Error::DefaultError("Public-key ciphertext is missing b component".to_string())
            })?;
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
    /// This method uses the configured `error1_variance` for the `e1` noise
    /// term, mirroring `bfv::PublicKey::try_encrypt`: standard l-BFV keeps
    /// `error1_variance == variance`, while threshold l-BFV can set a larger
    /// `error1_variance` for the same reason threshold BFV does.
    fn try_encrypt<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<Ciphertext> {
        // Validate public-key structure before using it for encryption.
        self.validate_structure()?;

        // Use only the first ciphertext from the array
        let mut ct = self.c.first().cloned().ok_or_else(|| {
            Error::DefaultError("Public key has no ciphertexts available".to_string())
        })?;
        while ct.level != pt.level() {
            ct.switch_down()?;
        }

        let ctx = self.params.context_at_level(ct.level)?;
        let u = Zeroizing::new(Poly::<Ntt>::small(ctx, self.params.variance, rng)?);
        let e1 = Zeroizing::new(Poly::<Ntt>::error_1(
            ctx,
            Representation::Ntt,
            &self.params.error1_variance,
            rng,
        )?);
        let e2 = Zeroizing::new(Poly::<Ntt>::small(ctx, self.params.variance, rng)?);

        let m = Zeroizing::new(pt.to_poly());
        let b = ct
            .c
            .first()
            .ok_or_else(|| Error::DefaultError("Ciphertext is missing b component".to_string()))?;
        let a = ct
            .c
            .get(1)
            .ok_or_else(|| Error::DefaultError("Ciphertext is missing a component".to_string()))?;
        let mut c0 = u.as_ref() * b;
        c0 += &e1;
        c0 += &m;
        let mut c1 = u.as_ref() * a;
        c1 += &e2;

        // It is now safe to enable variable time computations.
        c0.allow_variable_time_computations(fhe_traits::VariableTime::new(
            fhe_traits::PublicData::assert_public(),
        ));
        c1.allow_variable_time_computations(fhe_traits::VariableTime::new(
            fhe_traits::PublicData::assert_public(),
        ));

        Ok(Ciphertext {
            params: self.params.clone(),
            seed: None,
            c: vec![c0, c1],
            level: ct.level,
        })
    }
}

use crate::SerializationError;
use crate::bfv::traits::TryConvertFrom as BfvTryConvertFrom;
use crate::proto::bfv::Ciphertext as CiphertextProto;
use crate::proto::lbfv::{
    LbfvPublicKey as LBFVPublicKeyProto, LbfvPublicKeyExplicit, LbfvPublicKeySeeded,
};
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, Serialize};
use prost::Message;

impl From<&LBFVPublicKey> for LBFVPublicKeyProto {
    fn from(pk: &LBFVPublicKey) -> Self {
        debug_assert!(
            pk.validate_structure().is_ok(),
            "LBFV public keys must be structurally valid before serialization"
        );
        let (explicit, seeded) = match pk.seed {
            Some(seed) => (
                None,
                Some(LbfvPublicKeySeeded {
                    b: pk
                        .c
                        .iter()
                        .map(|ciphertext| {
                            ciphertext
                                .c
                                .first()
                                .map_or_else(Vec::new, fhe_traits::Serialize::to_bytes)
                        })
                        .collect(),
                    seed: seed.to_vec(),
                }),
            ),
            None => (
                Some(LbfvPublicKeyExplicit {
                    c: pk.c.iter().map(CiphertextProto::from).collect(),
                }),
                None,
            ),
        };
        LBFVPublicKeyProto {
            l: pk.l as u32,
            explicit,
            seeded,
        }
    }
}

impl Serialize for LBFVPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        LBFVPublicKeyProto::from(self).encode_to_vec()
    }
}

impl LBFVPublicKey {
    pub(crate) fn from_proto(
        proto: LBFVPublicKeyProto,
        params: &Arc<BfvParameters>,
    ) -> Result<Self> {
        let proto_l = proto.l as usize;
        let expected_l = params.moduli().len();

        // Validate that l matches the parameter modulus count
        if proto_l != expected_l {
            return Err(Error::SerializationError(
                SerializationError::InvalidFormat {
                    reason: format!(
                        "LBFV public-key l={proto_l} does not match the parameter modulus count={expected_l}"
                    ),
                },
            ));
        }

        match (proto.explicit, proto.seeded) {
            (Some(explicit), None) => Self::from_explicit_proto(explicit, proto_l, params),
            (None, Some(seeded)) => Self::from_seeded_proto(seeded, proto_l, params),
            (None, None) => Err(SerializationError::MissingField {
                field: crate::SerializedField::LbfvPublicKeyRepresentation,
            }
            .into()),
            (Some(_), Some(_)) => Err(SerializationError::InvalidFormat {
                reason: "LBFV public key contains both explicit and seeded representations"
                    .to_string(),
            }
            .into()),
        }
    }

    fn from_explicit_proto(
        explicit: LbfvPublicKeyExplicit,
        expected_l: usize,
        params: &Arc<BfvParameters>,
    ) -> Result<Self> {
        if explicit.c.is_empty() {
            return Err(SerializationError::MissingField {
                field: crate::SerializedField::PublicKeyCiphertext,
            }
            .into());
        }
        if explicit.c.len() != expected_l {
            return Err(SerializationError::InvalidFormat {
                reason: format!(
                    "LBFV public-key l={expected_l} does not match the explicit ciphertext count={}",
                    explicit.c.len()
                ),
            }
            .into());
        }

        let mut ciphertexts = Vec::with_capacity(explicit.c.len());
        for ciphertext_proto in explicit.c {
            if !ciphertext_proto.seed.is_empty() {
                return Err(SerializationError::InvalidFormat {
                    reason: "Explicit LBFV public-key rows must contain concrete a polynomials"
                        .to_string(),
                }
                .into());
            }
            let mut ciphertext = Ciphertext::try_convert_from(&ciphertext_proto, params)?;
            if ciphertext.level != 0 {
                return Err(SerializationError::InvalidPublicKeyLevel {
                    actual: ciphertext.level,
                    expected: 0,
                }
                .into());
            }
            ciphertext
                .c
                .iter_mut()
                .for_each(|polynomial| polynomial.disallow_variable_time_computations());
            ciphertexts.push(ciphertext);
        }

        let key = Self {
            params: params.clone(),
            c: ciphertexts,
            l: expected_l,
            seed: None,
        };
        key.validate_structure()?;
        Ok(key)
    }

    fn from_seeded_proto(
        seeded: LbfvPublicKeySeeded,
        expected_l: usize,
        params: &Arc<BfvParameters>,
    ) -> Result<Self> {
        if seeded.b.len() != expected_l {
            return Err(SerializationError::InvalidFormat {
                reason: format!(
                    "LBFV public-key l={expected_l} does not match the seeded b-row count={}",
                    seeded.b.len()
                ),
            }
            .into());
        }

        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        if seeded.seed.len() != seed.len() {
            return Err(SerializationError::InvalidPublicKeySeedLength {
                actual: seeded.seed.len(),
                expected: seed.len(),
            }
            .into());
        }
        seed.copy_from_slice(&seeded.seed);

        let ctx0 = params.context_at_level(0)?;
        let b_polynomials = seeded
            .b
            .iter()
            .map(|bytes| Poly::<Ntt>::from_bytes(bytes, ctx0).map_err(Error::from))
            .collect::<Result<Vec<_>>>()?;
        let a_polynomials = Self::derive_crs_rows(params, seed)?
            .into_iter()
            .map(|(_, polynomial)| polynomial)
            .collect();
        Self::from_parts(b_polynomials, a_polynomials, params.clone(), Some(seed))
    }
}

impl DeserializeParametrized for LBFVPublicKey {
    type Error = Error;

    fn from_bytes(bytes: &[u8], params: &Arc<Self::Parameters>) -> Result<Self> {
        let proto = crate::serialization::decode(bytes, crate::SerializedObject::LbfvPublicKey)?;
        Self::from_proto(proto, params)
    }
}
#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::LBFVPublicKey;
    use crate::bfv::{BfvParameters, CommonRandomPolyVec, Encoding, Plaintext, SecretKey};
    use crate::support::presets::insecure;
    use fhe_math::rq::{Ntt, Poly, Representation};
    use fhe_math::zq::Modulus;
    use fhe_traits::{FheDecrypter, FheEncoder, FheEncrypter};
    use rand::{Rng, SeedableRng, rng};
    use rand_chacha::ChaCha8Rng;
    use std::error::Error;

    #[test]
    fn keygen() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;
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
    fn encrypt_decrypt() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 8),
            insecure().unwrap().parameters,
        ] {
            for level in 0..params.max_level() {
                for _ in 0..20 {
                    let sk = SecretKey::random(&params, &mut rng);
                    let pk = LBFVPublicKey::new(&sk, &mut rng)?;

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

    use crate::proto::lbfv::{LbfvPublicKey as LBFVPublicKeyProto, LbfvPublicKeyExplicit};
    use fhe_traits::{DeserializeParametrized, Serialize};
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    struct LegacyLbfvPublicKey {
        #[prost(message, repeated, tag = "1")]
        c: Vec<crate::proto::bfv::Ciphertext>,
        #[prost(uint32, tag = "2")]
        l: u32,
        #[prost(bytes = "vec", tag = "3")]
        seed: Vec<u8>,
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

    /// `try_encrypt_extended` witness equations: `c0 = u*b + e1 + m` and
    /// `c1 = u*a + e2`.
    #[test]
    fn extended_encrypt_witness_equations() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
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
        let m = pt.to_poly();

        let mut expected_c0 = &u * &b;
        expected_c0 += &e1;
        expected_c0 += &m;
        let mut expected_c1 = &u * &a;
        expected_c1 += &e2;

        assert_eq!(ct.c[0].coefficients(), expected_c0.coefficients());
        assert_eq!(ct.c[1].coefficients(), expected_c1.coefficients());

        Ok(())
    }

    #[test]
    fn test_serialize() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 8),
            insecure().unwrap().parameters,
        ] {
            let sk = SecretKey::random(&params, &mut rng);
            let pk = LBFVPublicKey::new(&sk, &mut rng)?;
            let bytes = pk.to_bytes();
            assert_eq!(pk, LBFVPublicKey::from_bytes(&bytes, &params)?);
        }
        Ok(())
    }

    #[test]
    fn test_malformed_l_rejected() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;

        let mut proto: LBFVPublicKeyProto = LBFVPublicKeyProto::from(&pk);
        proto.l = 1; // Malformed: l should be the number of moduli
        let bytes = proto.encode_to_vec();
        assert!(LBFVPublicKey::from_bytes(&bytes, &params).is_err());

        // Also test: l doesn't match the seeded b-row count.
        let mut proto2: LBFVPublicKeyProto = LBFVPublicKeyProto::from(&pk);
        let Some(seeded) = proto2.seeded.as_mut() else {
            return Err("expected seeded public-key representation".into());
        };
        seeded.b.pop();
        let bytes2 = proto2.encode_to_vec();
        assert!(LBFVPublicKey::from_bytes(&bytes2, &params).is_err());

        Ok(())
    }

    /// Seeded and explicit representations must both round-trip. The seeded
    /// representation must omit the concrete `a` rows and therefore be smaller.
    #[test]
    fn seeded_and_explicit_serialization_roundtrip() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let seeded = LBFVPublicKey::new(&sk, &mut rng)?;
        let seeded_bytes = seeded.to_bytes();
        assert_eq!(LBFVPublicKey::from_bytes(&seeded_bytes, &params)?, seeded);

        let b_polynomials = seeded.c.iter().map(|ct| ct.c[0].clone()).collect();
        let a_polynomials = seeded.c.iter().map(|ct| ct.c[1].clone()).collect();
        let explicit =
            LBFVPublicKey::from_parts(b_polynomials, a_polynomials, params.clone(), None)?;
        let explicit_bytes = explicit.to_bytes();
        assert_eq!(
            LBFVPublicKey::from_bytes(&explicit_bytes, &params)?,
            explicit
        );
        assert!(seeded_bytes.len() < explicit_bytes.len());
        Ok(())
    }

    #[test]
    fn malformed_seeded_representation_is_rejected() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;
        let mut proto = LBFVPublicKeyProto::from(&pk);
        let Some(seeded) = proto.seeded.as_mut() else {
            return Err("expected seeded public-key representation".into());
        };
        seeded.seed.pop();

        let bytes = proto.encode_to_vec();
        assert!(LBFVPublicKey::from_bytes(&bytes, &params).is_err());
        Ok(())
    }

    #[test]
    fn ambiguous_public_key_representation_is_rejected() -> std::result::Result<(), Box<dyn Error>>
    {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let mut proto = LBFVPublicKeyProto::from(&LBFVPublicKey::new(&sk, &mut rng)?);
        proto.explicit = Some(LbfvPublicKeyExplicit::default());

        assert!(LBFVPublicKey::from_bytes(&proto.encode_to_vec(), &params).is_err());
        Ok(())
    }

    #[test]
    fn explicit_representation_rejects_seeded_rows() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let seeded = LBFVPublicKey::new(&sk, &mut rng)?;
        let explicit = LBFVPublicKey::from_parts(
            seeded.c.iter().map(|ct| ct.c[0].clone()).collect(),
            seeded.c.iter().map(|ct| ct.c[1].clone()).collect(),
            params.clone(),
            None,
        )?;
        let mut proto = LBFVPublicKeyProto::from(&explicit);
        let Some(first_row) = proto
            .explicit
            .as_mut()
            .and_then(|representation| representation.c.first_mut())
        else {
            return Err("expected explicit public-key row".into());
        };
        first_row.c.pop();
        first_row.seed = vec![0x55; 32];

        assert!(LBFVPublicKey::from_bytes(&proto.encode_to_vec(), &params).is_err());
        Ok(())
    }

    #[test]
    fn legacy_flat_public_key_payload_is_rejected() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;
        let legacy = LegacyLbfvPublicKey {
            c: pk
                .c
                .iter()
                .map(crate::proto::bfv::Ciphertext::from)
                .collect(),
            l: pk.l as u32,
            seed: pk.seed.map_or_else(Vec::new, |seed| seed.to_vec()),
        };

        assert!(LBFVPublicKey::from_bytes(&legacy.encode_to_vec(), &params).is_err());
        Ok(())
    }

    #[test]
    fn test_from_parts_roundtrip() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);

        let pk_seeded = LBFVPublicKey::new(&sk, &mut rng)?;
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

    /// `from_parts` must reject a seed that does not reproduce the concrete `a`
    /// polynomials — a mismatched seed breaks CRS consistency downstream.
    #[test]
    fn from_parts_rejects_inconsistent_seed() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);

        let pk_seeded = LBFVPublicKey::new(&sk, &mut rng)?;
        let b_polys: Vec<Poly<Ntt>> = pk_seeded.c.iter().map(|ct| ct.c[0].clone()).collect();
        let a_polys: Vec<Poly<Ntt>> = pk_seeded.c.iter().map(|ct| ct.c[1].clone()).collect();

        // A seed different from the one that produced those a_polys.
        let mut bad_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut bad_seed);
        // Ensure it's actually different.
        if Some(bad_seed) == pk_seeded.seed {
            bad_seed[0] ^= 0xff;
        }

        let result = LBFVPublicKey::from_parts(b_polys, a_polys, params.clone(), Some(bad_seed));
        assert!(
            result.is_err(),
            "from_parts must reject a seed that is inconsistent with the concrete a polynomials"
        );

        // The correct seed must still be accepted.
        assert!(
            LBFVPublicKey::from_parts(
                pk_seeded.c.iter().map(|ct| ct.c[0].clone()).collect(),
                pk_seeded.c.iter().map(|ct| ct.c[1].clone()).collect(),
                params,
                pk_seeded.seed,
            )
            .is_ok()
        );

        Ok(())
    }

    #[test]
    fn test_deterministic_public_key() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);

        // Create a fixed seed
        let seed = <ChaCha8Rng as SeedableRng>::Seed::default();

        // Create two public keys with the same seed
        let pk1 = LBFVPublicKey::new_with_seed(&sk, seed, &mut rng)?;
        let pk2 = LBFVPublicKey::new_with_seed(&sk, seed, &mut rng)?;

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

    /// Malformed in-memory public keys must be rejected by `try_encrypt`,
    /// `try_encrypt_extended`, and `extract_b_polynomials`.
    #[test]
    fn malformed_pk_rejected_by_encryption_and_extraction()
    -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;

        let pt = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;

        // Normal operations succeed.
        let _ct = pk.try_encrypt(&pt, &mut rng)?;
        let (_ct, _u, _e1, _e2) = pk.try_encrypt_extended(&pt, &mut rng)?;
        let _b = pk.extract_b_polynomials(0, 0, Representation::NttShoup)?;

        // Malformed PK: wrong l value.
        let mut bad_pk = pk.clone();
        bad_pk.l = 1;
        assert!(
            bad_pk.try_encrypt(&pt, &mut rng).is_err(),
            "try_encrypt must reject a malformed PK (wrong l)"
        );
        assert!(
            bad_pk.try_encrypt_extended(&pt, &mut rng).is_err(),
            "try_encrypt_extended must reject a malformed PK (wrong l)"
        );
        assert!(
            bad_pk
                .extract_b_polynomials(0, 0, Representation::NttShoup)
                .is_err(),
            "extract_b_polynomials must reject a malformed PK (wrong l)"
        );

        // Malformed PK: truncated ciphertexts.
        let mut truncated_pk = pk.clone();
        truncated_pk.c.pop();
        assert!(
            truncated_pk.try_encrypt(&pt, &mut rng).is_err(),
            "try_encrypt must reject a PK with truncated ciphertexts"
        );
        assert!(
            truncated_pk.try_encrypt_extended(&pt, &mut rng).is_err(),
            "try_encrypt_extended must reject a PK with truncated ciphertexts"
        );
        assert!(
            truncated_pk
                .extract_b_polynomials(0, 0, Representation::NttShoup)
                .is_err(),
            "extract_b_polynomials must reject a PK with truncated ciphertexts"
        );

        Ok(())
    }

    /// `new_with_crp` uses the supplied concrete `a` polynomials from a
    /// seedless CRP vector, and the resulting key carries no seed.
    #[test]
    fn new_with_crp_uses_concrete_a_from_seedless_vector() -> std::result::Result<(), Box<dyn Error>>
    {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);

        let crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        assert!(crp.seed().is_none());

        let pk = LBFVPublicKey::new_with_crp(&sk, &crp, &mut rng)?;

        // The seed should be absent (seedless CRP).
        assert!(pk.seed.is_none());

        // The concrete a polynomials must match the CRP.
        let expected_a = crp.to_polys();
        for (j, ct) in pk.c.iter().enumerate() {
            assert_eq!(ct.c[1], expected_a[j]);
        }

        // Encrypt/decrypt roundtrip works.
        let pt = Plaintext::try_encode(&[42u64], Encoding::poly(), &params)?;
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        assert_eq!(sk.try_decrypt(&ct)?, pt);

        Ok(())
    }
}
