/*!
 * Single-party l-BFV relinearization key.
 *
 * This module provides an operational relinearization key built from a
 * single-party secret key.  The key consists of two key-switching keys and
 * a `b_vec` extracted from the public key, following the l-BFV relinearization
 * algorithm from
 * [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
 *
 * # Operational construction
 *
 * [`LBFVRelinearizationKey::new_leveled`](LBFVRelinearizationKey::new_leveled)
 * and [`LBFVRelinearizationKey::new_leveled_with_polys`](LBFVRelinearizationKey::new_leveled_with_polys)
 * build a key directly from a secret key and public key.  There is no
 * distributed aggregation — all threshold/multiparty utilities live in
 * [`crate::trlbfv`].
 */

use crate::bfv::{BfvParameters, Ciphertext, KeySwitchingKey, SecretKey};
use crate::{Error, Result};
use fhe_math::rq::{
    Context, Ntt, NttShoup, Poly, PowerBasis, Representation, switcher::Switcher,
    traits::TryConvertFrom as TryConvertFromPoly,
};
use fhe_traits::FheParametrized;
use itertools::izip;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;
use zeroize::Zeroizing;

use super::LBFVPublicKey;
use crate::bfv::CommonRandomPolyVec;

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
    /// Generate the two key-switching-key components from a secret key using
    /// provided seeds for `d1` (URS) and `a` (CRS).
    ///
    /// Returns `(ksk_r_to_s, ksk_s_to_r)` — the two KSKs that together with
    /// a `b_vec` form a complete relinearization key.
    pub(crate) fn generate_components_with_seed<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        d1_seed: <ChaCha8Rng as SeedableRng>::Seed,
        a_seed: <ChaCha8Rng as SeedableRng>::Seed,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<(KeySwitchingKey, KeySwitchingKey)> {
        let ctx_relin_key = sk.params.context_at_level(key_level)?;
        let ctx_ciphertext = sk.params.context_at_level(ciphertext_level)?;
        let switcher_up = Switcher::new(ctx_ciphertext, ctx_relin_key)?;

        if ciphertext_level < key_level {
            return Err(Error::DefaultError(
                "Ciphertext level must be greater than or equal to key level".to_string(),
            ));
        }
        if ctx_relin_key.moduli().len() == 1 || ctx_ciphertext.moduli().len() == 1 {
            return Err(Error::DefaultError(
                "These parameters do not support key switching".to_string(),
            ));
        }

        let r = Zeroizing::new(SecretKey::random(&sk.params, rng));
        let r_poly = Zeroizing::new(Poly::<PowerBasis>::try_convert_from(
            r.coeffs.as_ref(),
            ctx_ciphertext,
            false,
        )?);
        let r_switched_up = Zeroizing::new(r_poly.switch(&switcher_up)?);

        let sk_poly = Zeroizing::new(Poly::<PowerBasis>::try_convert_from(
            sk.coeffs.as_ref(),
            ctx_ciphertext,
            false,
        )?);
        let sk_switched_up = Zeroizing::new(sk_poly.switch(&switcher_up)?);

        // (d0, d1) = (-sk·d1 + e0 + r·g, d1)
        let ksk_r_to_s = KeySwitchingKey::new_with_seed(
            sk,
            &r_switched_up,
            d1_seed,
            ciphertext_level,
            key_level,
            rng,
        )?;

        // (d2, a) = (r·a + e2 + sk·g, a), obtained by encrypting sk under -r
        let mut neg_r = Zeroizing::new((*r).clone());
        neg_r
            .coeffs
            .iter_mut()
            .for_each(|coefficient| *coefficient = coefficient.wrapping_neg());
        let ksk_s_to_r = KeySwitchingKey::new_with_seed(
            &neg_r,
            &sk_switched_up,
            a_seed,
            ciphertext_level,
            key_level,
            rng,
        )?;

        Ok((ksk_r_to_s, ksk_s_to_r))
    }

    /// Generate the two key-switching-key components from a secret key using
    /// explicit URS/CRS polynomials instead of seeds.
    ///
    /// Returns `(ksk_r_to_s, ksk_s_to_r)` — the two KSKs that together with
    /// a `b_vec` form a complete relinearization key.
    pub(crate) fn generate_components_with_polys<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        d1_polys: Vec<Poly<NttShoup>>,
        a_polys: Vec<Poly<NttShoup>>,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<(KeySwitchingKey, KeySwitchingKey)> {
        let ctx_relin_key = sk.params.context_at_level(key_level)?;
        let ctx_ciphertext = sk.params.context_at_level(ciphertext_level)?;
        let switcher_up = Switcher::new(ctx_ciphertext, ctx_relin_key)?;

        if ciphertext_level < key_level {
            return Err(Error::DefaultError(
                "Ciphertext level must be greater than or equal to key level".to_string(),
            ));
        }
        if ctx_relin_key.moduli().len() == 1 || ctx_ciphertext.moduli().len() == 1 {
            return Err(Error::DefaultError(
                "These parameters do not support key switching".to_string(),
            ));
        }

        let r = Zeroizing::new(SecretKey::random(&sk.params, rng));
        let r_poly = Zeroizing::new(Poly::<PowerBasis>::try_convert_from(
            r.coeffs.as_ref(),
            ctx_ciphertext,
            false,
        )?);
        let r_switched_up = Zeroizing::new(r_poly.switch(&switcher_up)?);

        let sk_poly = Zeroizing::new(Poly::<PowerBasis>::try_convert_from(
            sk.coeffs.as_ref(),
            ctx_ciphertext,
            false,
        )?);
        let sk_switched_up = Zeroizing::new(sk_poly.switch(&switcher_up)?);

        // (d0, d1) = (-sk·d1 + e0 + r·g, d1)
        let ksk_r_to_s = KeySwitchingKey::new_with_c1(
            sk,
            &r_switched_up,
            d1_polys,
            ciphertext_level,
            key_level,
            rng,
        )?;

        // (d2, a) = (r·a + e2 + sk·g, a)
        let mut neg_r = Zeroizing::new((*r).clone());
        neg_r
            .coeffs
            .iter_mut()
            .for_each(|coefficient| *coefficient = coefficient.wrapping_neg());
        let ksk_s_to_r = KeySwitchingKey::new_with_c1(
            &neg_r,
            &sk_switched_up,
            a_polys,
            ciphertext_level,
            key_level,
            rng,
        )?;

        Ok((ksk_r_to_s, ksk_s_to_r))
    }

    /// Like [`generate_components_with_polys`](Self::generate_components_with_polys)
    /// but also returns the ephemeral key `r` and the per-row error polynomials
    /// from both KSKs — needed for ZK witness generation.
    ///
    /// Returns `(ksk_r_to_s, ksk_s_to_r, r, errors_d0, errors_d2)` where:
    /// - `r` is the ephemeral `SecretKey`; auto-zeroized when dropped.
    /// - `errors_d0[i]` is the small error `eᵢ` such that `d0ᵢ = eᵢ − sk·d1ᵢ + rᵢ·g`.
    /// - `errors_d2[i]` is the small error `eᵢ` such that `d2ᵢ = eᵢ + r·aᵢ + skᵢ·g`.
    #[allow(clippy::type_complexity)]
    pub(crate) fn generate_components_with_polys_extended<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        d1_polys: Vec<Poly<NttShoup>>,
        a_polys: Vec<Poly<NttShoup>>,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<(
        KeySwitchingKey,
        KeySwitchingKey,
        Zeroizing<SecretKey>,
        Vec<Poly<NttShoup>>,
        Vec<Poly<NttShoup>>,
    )> {
        let ctx_relin_key = sk.params.context_at_level(key_level)?;
        let ctx_ciphertext = sk.params.context_at_level(ciphertext_level)?;
        let switcher_up = Switcher::new(ctx_ciphertext, ctx_relin_key)?;

        if ciphertext_level < key_level {
            return Err(Error::DefaultError(
                "Ciphertext level must be greater than or equal to key level".to_string(),
            ));
        }
        if ctx_relin_key.moduli().len() == 1 || ctx_ciphertext.moduli().len() == 1 {
            return Err(Error::DefaultError(
                "These parameters do not support key switching".to_string(),
            ));
        }

        let r = Zeroizing::new(SecretKey::random(&sk.params, rng));
        let r_poly = Zeroizing::new(Poly::<PowerBasis>::try_convert_from(
            r.coeffs.as_ref(),
            ctx_ciphertext,
            false,
        )?);
        let r_switched_up = Zeroizing::new(r_poly.switch(&switcher_up)?);

        let sk_poly = Zeroizing::new(Poly::<PowerBasis>::try_convert_from(
            sk.coeffs.as_ref(),
            ctx_ciphertext,
            false,
        )?);
        let sk_switched_up = Zeroizing::new(sk_poly.switch(&switcher_up)?);

        let (ksk_r_to_s, errors_d0) = KeySwitchingKey::new_with_c1_extended(
            sk,
            &r_switched_up,
            d1_polys,
            ciphertext_level,
            key_level,
            rng,
        )?;

        let mut neg_r = Zeroizing::new((*r).clone());
        neg_r
            .coeffs
            .iter_mut()
            .for_each(|coefficient| *coefficient = coefficient.wrapping_neg());
        let (ksk_s_to_r, errors_d2) = KeySwitchingKey::new_with_c1_extended(
            &neg_r,
            &sk_switched_up,
            a_polys,
            ciphertext_level,
            key_level,
            rng,
        )?;

        Ok((ksk_r_to_s, ksk_s_to_r, r, errors_d0, errors_d2))
    }

    /// Build a relinearization key from pre-computed components.
    ///
    /// Validates that the two KSKs are structurally consistent and that
    /// `b_vec` has the correct length. The resulting key is operational
    /// (single-party, no participant bindings).
    pub(crate) fn from_components(
        ksk_r_to_s: KeySwitchingKey,
        ksk_s_to_r: KeySwitchingKey,
        b_vec: Vec<Poly<NttShoup>>,
    ) -> Result<Self> {
        if ksk_r_to_s.params != ksk_s_to_r.params {
            return Err(Error::DefaultError(
                "RLK KSKs have mismatched parameters".to_string(),
            ));
        }
        if ksk_r_to_s.ciphertext_level != ksk_s_to_r.ciphertext_level {
            return Err(Error::DefaultError(
                "RLK KSKs have mismatched ciphertext levels".to_string(),
            ));
        }
        if ksk_r_to_s.ksk_level != ksk_s_to_r.ksk_level {
            return Err(Error::DefaultError(
                "RLK KSKs have mismatched key levels".to_string(),
            ));
        }
        if ksk_r_to_s.c0.len() != ksk_r_to_s.c1.len() {
            return Err(Error::DefaultError(
                "ksk_r_to_s has mismatched c0/c1 dimensions".to_string(),
            ));
        }
        if ksk_s_to_r.c0.len() != ksk_s_to_r.c1.len() {
            return Err(Error::DefaultError(
                "ksk_s_to_r has mismatched c0/c1 dimensions".to_string(),
            ));
        }
        if ksk_r_to_s.log_base != ksk_s_to_r.log_base {
            return Err(Error::DefaultError(
                "RLK KSKs have mismatched log_base".to_string(),
            ));
        }

        let expected_b_vec_len = ksk_r_to_s
            .params
            .moduli()
            .len()
            .checked_sub(ksk_r_to_s.ciphertext_level)
            .ok_or_else(|| {
                Error::DefaultError("ciphertext_level exceeds modulus count".to_string())
            })?;
        if b_vec.len() != expected_b_vec_len {
            return Err(Error::DefaultError(format!(
                "b_vec length mismatch: expected {expected_b_vec_len}, got {}",
                b_vec.len()
            )));
        }

        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
            b_vec,
        })
    }

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
        let d1_seed = d1_seed.unwrap_or_else(|| {
            let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut seed);
            seed
        });

        let (ksk_r_to_s, ksk_s_to_r) = match pk.seed {
            Some(a_seed) => {
                // Validate that the concrete a_j stored in the PK actually
                // match the seed. A tampered PK (c[1] changed but seed left
                // alone) must be rejected immediately, not silently fixed.
                let ctx0 = pk.params.context_at_level(key_level)?;
                let mut seed_rng = ChaCha8Rng::from_seed(a_seed);
                let new_l = pk.l.checked_sub(ciphertext_level).ok_or_else(|| {
                    Error::DefaultError("ciphertext_level exceeds public-key l".to_string())
                })?;
                for j in 0..new_l {
                    let mut seed_j = <ChaCha8Rng as SeedableRng>::Seed::default();
                    seed_rng.fill(&mut seed_j);
                    let expected_a = Poly::<Ntt>::random_from_seed(ctx0, seed_j);
                    let actual_a = pk.c.get(j).and_then(|ct| ct.c.get(1)).ok_or_else(|| {
                        Error::DefaultError("Public key is missing its a_j polynomial".to_string())
                    })?;
                    if expected_a != *actual_a {
                        return Err(Error::DefaultError(format!(
                            "Public-key a_j at index {j} does not match its stored seed"
                        )));
                    }
                }
                // Seed matches — use the fast seed-only path.
                Self::generate_components_with_seed(
                    sk,
                    d1_seed,
                    a_seed,
                    ciphertext_level,
                    key_level,
                    rng,
                )?
            }
            None => {
                // Seedless PK — extract concrete a from the PK and build
                // explicit d1 polynomials from the d1 seed.
                let a_polys = pk.a_polynomials_for_level(ciphertext_level, key_level)?;
                let d1_context = pk.params.context_at_level(key_level)?;
                let d1_polys = KeySwitchingKey::c1_from_seed(d1_context, d1_seed, a_polys.len());

                Self::generate_components_with_polys(
                    sk,
                    d1_polys,
                    a_polys,
                    ciphertext_level,
                    key_level,
                    rng,
                )?
            }
        };

        let b_vec =
            pk.extract_b_polynomials(ciphertext_level, key_level, Representation::NttShoup)?;
        Self::from_components(ksk_r_to_s, ksk_s_to_r, b_vec)
    }

    /// Generate a new leveled relinearization key using explicit d1 polynomials.
    ///
    /// This is the explicit URS path: the caller provides the `d1` polynomials
    /// directly and the `a` (CRS) polynomials are extracted from the public key's
    /// concrete ciphertext polynomials. The caller cannot supply an unrelated `a`.
    ///
    /// # Arguments
    /// * `sk` - The secret key to use for key generation.
    /// * `pk` - The l-BFV public key whose concrete `a` polynomials are used as
    ///   CRS material.
    /// * `d1_polys` - The explicit URS `d1` polynomials (in `NttShoup` form).
    /// * `ciphertext_level` / `key_level` - Levels (currently restricted to 0).
    /// * `rng` - RNG for ephemeral `r` and the errors.
    pub fn new_leveled_with_polys<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        pk: &LBFVPublicKey,
        d1_polys: Vec<Poly<NttShoup>>,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let a_polys = pk.a_polynomials_for_level(ciphertext_level, key_level)?;
        let (ksk_r_to_s, ksk_s_to_r) = Self::generate_components_with_polys(
            sk,
            d1_polys,
            a_polys,
            ciphertext_level,
            key_level,
            rng,
        )?;
        let b_vec =
            pk.extract_b_polynomials(ciphertext_level, key_level, Representation::NttShoup)?;
        Self::from_components(ksk_r_to_s, ksk_s_to_r, b_vec)
    }

    /// Generate a new leveled relinearization key using a [`CommonRandomPolyVec`]
    /// for the URS `d1` polynomials.
    ///
    /// This is the CRP-vector variant of [`new_leveled_with_polys`](Self::new_leveled_with_polys).
    /// The `d1` polynomials are extracted from `crp_d1` and converted to
    /// `NttShoup`; the `a` (CRS) polynomials are extracted from the public key
    /// as usual.
    ///
    /// # Arguments
    /// * `sk` - The secret key for key generation.
    /// * `pk` - The l-BFV public key whose concrete `a` polynomials are used as
    ///   CRS material.
    /// * `crp_d1` - A [`CommonRandomPolyVec`] providing the URS `d1` polynomials.
    /// * `ciphertext_level` / `key_level` - Levels (currently restricted to 0).
    /// * `rng` - RNG for ephemeral `r` and the errors.
    pub fn new_leveled_with_crp<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        pk: &LBFVPublicKey,
        crp_d1: &CommonRandomPolyVec,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let d1_polys: Vec<Poly<NttShoup>> = crp_d1
            .to_polys()
            .into_iter()
            .map(|p| p.into_ntt_shoup())
            .collect();
        Self::new_leveled_with_polys(sk, pk, d1_polys, ciphertext_level, key_level, rng)
    }

    /// Generate a new relinearization key using a [`CommonRandomPolyVec`] for the
    /// URS `d1` at level 0.
    ///
    /// Convenience wrapper around [`new_leveled_with_crp`](Self::new_leveled_with_crp).
    pub fn new_with_crp<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        pk: &LBFVPublicKey,
        crp_d1: &CommonRandomPolyVec,
        rng: &mut R,
    ) -> Result<Self> {
        Self::new_leveled_with_crp(sk, pk, crp_d1, 0, 0, rng)
    }

    /// Get "l" in "l-BFV" based on members of the [`LBFVRelinearizationKey`] struct,
    /// which is equal to the number of ciphertexts in the public key.
    ///
    /// # Returns
    /// * `Ok(usize)` - The number of ciphertexts in the public key
    /// * `Err` if the number of moduli in the ciphertext context is not equal
    ///   to the number of polynomials in `b_vec`, which should be equal to "l".
    pub fn l(&self) -> Result<usize> {
        if self.ksk_r_to_s.params.max_level() + 1 - self.ciphertext_level() != self.b_vec.len() {
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
            Err(Error::DefaultError(
                "Only supports relinearization of ciphertext with 3 parts".to_string(),
            ))
        } else if ct.level != self.ciphertext_level() {
            Err(Error::DefaultError(
                "Ciphertext has incorrect level".to_string(),
            ))
        } else {
            let ciphertext_ctx = self.ciphertext_ctx();
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
    /// 1. Takes [p]_{qi} and converts it to [[p]_{qi}]_{qj} for every RNS basis qj
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
            return Err(Error::DefaultError(
                "The input polynomial does not have the correct context.".to_string(),
            ));
        }
        if arr.len() != ciphertext_ctx.moduli().len() {
            return Err(Error::DefaultError(
                "The input array of polynomials does not have the correct length.".to_string(),
            ));
        }
        // Product-sum of decomposed polynomial and array of polynomials
        let mut out = Poly::<Ntt>::zero(&ksk_ctx);
        for (poly_i_coefficients, arr_i) in izip!(poly.coefficients().outer_iter(), arr.iter()) {
            if arr_i.ctx() != &ksk_ctx {
                return Err(Error::DefaultError(
                    "The input array of polynomials does not have the correct context.".to_string(),
                ));
            }

            let poly_i =
                Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                    poly_i_coefficients.as_slice().ok_or_else(|| {
                        Error::DefaultError(
                            "Non-contiguous coefficient array in decompose_poly_and_product_sum"
                                .to_string(),
                        )
                    })?,
                    &ksk_ctx,
                    fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public()),
                );
            out += &(&poly_i * arr_i);
        }
        Ok(out)
    }
}

/// Associates the [`LBFVRelinearizationKey`] with BFV parameters
impl FheParametrized for LBFVRelinearizationKey {
    type Parameters = BfvParameters;
}

use crate::bfv::traits::TryConvertFrom;
use crate::proto::bfv::KeySwitchingKey as KeySwitchingKeyProto;
use crate::proto::lbfv::LbfvRelinearizationKey as LBFVRelinearizationKeyProto;
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, Serialize};
use prost::Message;

impl From<&LBFVRelinearizationKey> for LBFVRelinearizationKeyProto {
    fn from(value: &LBFVRelinearizationKey) -> Self {
        LBFVRelinearizationKeyProto {
            ksk_r_to_s: Some(KeySwitchingKeyProto::from(&value.ksk_r_to_s)),
            ksk_s_to_r: Some(KeySwitchingKeyProto::from(&value.ksk_s_to_r)),
            b_vec: value.b_vec.iter().map(|p| p.to_bytes()).collect(),
            binding: None,
        }
    }
}

impl TryConvertFrom<&LBFVRelinearizationKeyProto> for LBFVRelinearizationKey {
    fn try_convert_from(
        value: &LBFVRelinearizationKeyProto,
        params: &Arc<BfvParameters>,
    ) -> Result<Self> {
        let ksk_r_to_s = value
            .ksk_r_to_s
            .as_ref()
            .ok_or_else(|| {
                Error::DefaultError("Invalid serialization: missing ksk_r_to_s".to_string())
            })
            .and_then(|ksk| KeySwitchingKey::try_convert_from(ksk, params))?;
        let ksk_s_to_r = value
            .ksk_s_to_r
            .as_ref()
            .ok_or_else(|| {
                Error::DefaultError("Invalid serialization: missing ksk_s_to_r".to_string())
            })
            .and_then(|ksk| KeySwitchingKey::try_convert_from(ksk, params))?;

        // Reject protos that carry a binding — callers should use trlbfv instead.
        if value.binding.is_some() {
            return Err(Error::SerializationError(
                crate::SerializationError::InvalidFormat {
                    reason: "LBFV RLK carries a binding field; use trlbfv instead".to_string(),
                },
            ));
        }

        // --- Cross-KSK structural validation ---
        if ksk_s_to_r.params != ksk_r_to_s.params {
            return Err(Error::DefaultError(
                "RLK KSKs have mismatched parameters".to_string(),
            ));
        }
        if ksk_s_to_r.ciphertext_level != ksk_r_to_s.ciphertext_level {
            return Err(Error::DefaultError(
                "RLK KSKs have mismatched ciphertext levels".to_string(),
            ));
        }
        if ksk_s_to_r.ksk_level != ksk_r_to_s.ksk_level {
            return Err(Error::DefaultError(
                "RLK KSKs have mismatched key levels".to_string(),
            ));
        }
        if ksk_s_to_r.ctx_ciphertext != ksk_r_to_s.ctx_ciphertext {
            return Err(Error::DefaultError(
                "RLK KSKs have mismatched ciphertext contexts".to_string(),
            ));
        }
        if ksk_s_to_r.ctx_ksk != ksk_r_to_s.ctx_ksk {
            return Err(Error::DefaultError(
                "RLK KSKs have mismatched key contexts".to_string(),
            ));
        }
        if ksk_s_to_r.log_base != ksk_r_to_s.log_base {
            return Err(Error::DefaultError(
                "RLK KSKs have mismatched log_base".to_string(),
            ));
        }
        // Validate c0/c1 dimensions in each KSK
        if ksk_r_to_s.c0.len() != ksk_r_to_s.c1.len() {
            return Err(Error::DefaultError(
                "ksk_r_to_s has mismatched c0/c1 dimensions".to_string(),
            ));
        }
        if ksk_s_to_r.c0.len() != ksk_s_to_r.c1.len() {
            return Err(Error::DefaultError(
                "ksk_s_to_r has mismatched c0/c1 dimensions".to_string(),
            ));
        }

        // --- b_vec validation ---
        let expected_b_vec_len = params
            .moduli()
            .len()
            .checked_sub(ksk_r_to_s.ciphertext_level)
            .ok_or_else(|| {
                Error::DefaultError(
                    "Invalid b_vec: ciphertext_level exceeds modulus count".to_string(),
                )
            })?;
        if value.b_vec.len() != expected_b_vec_len {
            return Err(Error::DefaultError(format!(
                "Invalid b_vec length: expected {expected_b_vec_len}, got {}",
                value.b_vec.len()
            )));
        }

        let key_ctx = ksk_r_to_s.ctx_ksk.clone();
        let mut b_vec = Vec::with_capacity(value.b_vec.len());
        for (i, poly_bytes) in value.b_vec.iter().enumerate() {
            let poly = Poly::<NttShoup>::from_bytes(poly_bytes, &key_ctx).map_err(|e| {
                Error::DefaultError(format!("Invalid b_vec polynomial at index {i}: {e}"))
            })?;
            b_vec.push(poly);
        }

        Ok(LBFVRelinearizationKey {
            ksk_r_to_s,
            ksk_s_to_r,
            b_vec,
        })
    }
}

impl Serialize for LBFVRelinearizationKey {
    fn to_bytes(&self) -> Vec<u8> {
        LBFVRelinearizationKeyProto::from(self).encode_to_vec()
    }
}

impl DeserializeParametrized for LBFVRelinearizationKey {
    type Error = Error;

    fn from_bytes(bytes: &[u8], params: &Arc<Self::Parameters>) -> Result<Self> {
        let rk = Message::decode(bytes).map_err(|e| {
            Error::SerializationError(crate::SerializationError::ProtobufError {
                message: e.to_string(),
            })
        })?;
        LBFVRelinearizationKey::try_convert_from(&rk, params)
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

    use fhe_traits::{DeserializeParametrized, Serialize};

    #[test]
    fn test_serialize_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;

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
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;

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

    #[test]
    fn new_leveled_accepts_seedless_public_key_and_explicit_d1() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);

        let seeded = LBFVPublicKey::new_with_seed(&sk, [51u8; 32], &mut rng)?;
        let a_polys: Vec<Poly<Ntt>> = seeded
            .c
            .iter()
            .map(|ciphertext| ciphertext.c.get(1).cloned())
            .collect::<Option<_>>()
            .ok_or("missing public-key a polynomial")?;

        // Build a seedless PK using from_crs with explicit a_polys.
        let seedless = LBFVPublicKey::from_crs(&sk, &a_polys, None, &mut rng)?;
        let generated_d1_key =
            LBFVRelinearizationKey::new_leveled(&sk, &seedless, None, 0, 0, &mut rng)?;

        let d1_polys = KeySwitchingKey::c1_from_seed(
            params.context_at_level(0)?,
            [61u8; 32],
            params.moduli().len(),
        );
        let explicit_d1_key = LBFVRelinearizationKey::new_leveled_with_polys(
            &sk, &seedless, d1_polys, 0, 0, &mut rng,
        )?;

        let plaintext = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;
        let ciphertext = seedless.try_encrypt(&plaintext, &mut rng)?;
        let mut product = &ciphertext * &ciphertext;
        generated_d1_key.relinearizes(&mut product)?;
        assert_eq!(
            Vec::<u64>::try_decode(&sk.try_decrypt(&product)?, Encoding::poly())?[0],
            9
        );

        let mut explicit_product = &ciphertext * &ciphertext;
        explicit_d1_key.relinearizes(&mut explicit_product)?;
        assert_eq!(
            Vec::<u64>::try_decode(&sk.try_decrypt(&explicit_product)?, Encoding::poly())?[0],
            9
        );

        Ok(())
    }

    /// A tampered public key where the concrete `a` polynomials have been
    /// changed but `pk.seed` is left unchanged must be rejected immediately
    /// by the seeded RLK path — contradictory seed metadata is an error.
    #[test]
    fn tampered_pk_concrete_a_rejected_by_seeded_rlk_path() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);

        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);

        // Build a valid PK from the seed.
        let valid_pk = LBFVPublicKey::new_with_seed(&sk, seed, &mut rng)?;

        // Tamper: replace one of the concrete a_j polynomials with a random one,
        // but leave pk.seed unchanged.
        let ctx0 = params.context_at_level(0)?;
        let mut tampered_cts = valid_pk.c.clone();
        let original_a0 = tampered_cts[0].c[1].clone();
        tampered_cts[0].c[1] = Poly::<Ntt>::small(ctx0, params.variance, &mut rng)?;
        let mut tampered_pk = valid_pk.clone();
        tampered_pk.c = tampered_cts;

        // The tampered PK should still have seed = Some(seed).
        assert_eq!(tampered_pk.seed, Some(seed));
        // But the concrete a0 no longer matches the seed.
        assert_ne!(tampered_pk.c[0].c[1], original_a0);

        // The seeded RLK path must reject the contradictory seed immediately.
        let d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let result =
            LBFVRelinearizationKey::new_leveled(&sk, &tampered_pk, Some(d1_seed), 0, 0, &mut rng);
        assert!(
            result.is_err(),
            "Seeded RLK path must reject a PK whose concrete a_j contradict its stored seed"
        );

        Ok(())
    }
}
