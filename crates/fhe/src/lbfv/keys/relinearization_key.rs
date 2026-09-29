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
use crate::{Error, Result, SerializationError};
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
    /// Reconstruct the level-0 public key embedded in this relinearization key.
    ///
    /// The relinearization key carries the public key's secret-dependent `b`
    /// rows in `b_vec` and the same CRS `a` rows in its `s -> r` key-switching
    /// key. This operation is intentionally restricted to level 0 because a
    /// leveled relinearization key does not retain enough information to recover
    /// the original full-level public key. The reconstructed key retains the
    /// CRS seed when the relinearization key carries it; otherwise it uses the
    /// explicit, seedless representation of the same concrete polynomials.
    pub fn reconstruct_public_key(&self) -> Result<LBFVPublicKey> {
        if self.ciphertext_level() != 0 || self.key_level() != 0 {
            return Err(Error::DefaultError(
                "Reconstructing an LBFV public key requires a level-0 relinearization key"
                    .to_string(),
            ));
        }

        let b_polynomials = self
            .b_vec
            .iter()
            .cloned()
            .map(Poly::<NttShoup>::into_ntt)
            .collect();
        let a_polynomials = self
            .ksk_s_to_r
            .c1
            .iter()
            .cloned()
            .map(Poly::<NttShoup>::into_ntt)
            .collect();

        LBFVPublicKey::from_parts(
            b_polynomials,
            a_polynomials,
            self.parameters(),
            self.ksk_s_to_r.seed,
        )
    }

    /// Return the secret-dependent `d0` components in gadget-row order.
    #[must_use]
    pub fn d0_components(&self) -> &[Poly<NttShoup>] {
        &self.ksk_r_to_s.c0
    }

    /// Return the shared `d1` (URS) components in gadget-row order.
    #[must_use]
    pub fn d1_components(&self) -> &[Poly<NttShoup>] {
        &self.ksk_r_to_s.c1
    }

    /// Return the secret-dependent `d2` components in gadget-row order.
    #[must_use]
    pub fn d2_components(&self) -> &[Poly<NttShoup>] {
        &self.ksk_s_to_r.c0
    }

    /// Return the shared `a` (CRS) components in gadget-row order.
    #[must_use]
    pub fn a_components(&self) -> &[Poly<NttShoup>] {
        &self.ksk_s_to_r.c1
    }

    /// Return the public-key `b` components used during relinearization.
    #[must_use]
    pub fn b_components(&self) -> &[Poly<NttShoup>] {
        &self.b_vec
    }

    /// Return the key-switching decomposition base logarithm.
    ///
    /// A value of zero denotes the RNS decomposition used by l-BFV.
    /// Deserialization and [`from_components`](Self::from_components) only
    /// accept constructor-compatible layouts, so for an operational l-BFV
    /// key this is always zero: the single-modulus decomposition
    /// (`log_base != 0`) is rejected because the l-BFV constructors refuse
    /// single-modulus key and ciphertext contexts.
    #[must_use]
    pub const fn decomposition_log_base(&self) -> usize {
        self.ksk_r_to_s.log_base
    }

    /// Generate the two key-switching-key components from a secret key using
    /// provided seeds for `d1` (URS) and `a` (CRS).
    ///
    /// The two seeds must be distinct: the URS and CRS are separate reference
    /// strings and must be generated independently. Identical seeds are
    /// rejected before any key material is produced, and the generated
    /// concrete rows are validated (row uniqueness and CRS/URS separation)
    /// before the KSKs are returned.
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

        // The URS `d1` and CRS `a` must not be derived from the same seed.
        // The role-neutral primitive reports the collision; the public
        // multiparty error is assigned here at the l-BFV boundary.
        crate::reference_string::validate_distinct_seeds(&d1_seed, &a_seed)
            .map_err(|_| crate::MultipartyError::IdenticalReferenceStringSeeds)?;

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

        // Final row-level gate on the generated concrete rows. Distinct seeds
        // make collisions implausible, but this boundary also returns key
        // material directly to callers (for example threshold shares), so the
        // generated URS `d1` and CRS `a` rows are validated like every other
        // reference-string input before the KSKs are handed out.
        crate::reference_string::validate_reference_string_pair(
            ctx_relin_key,
            &ksk_s_to_r.c1,
            &ksk_r_to_s.c1,
        )?;

        Ok((ksk_r_to_s, ksk_s_to_r))
    }

    /// Generate the two key-switching-key components from a secret key using
    /// explicit URS/CRS polynomials instead of seeds.
    ///
    /// The CRS `a_polys` and URS `d1_polys` must be generated independently:
    /// rows repeated within either vector and rows shared between the two
    /// vectors are rejected before any secret-dependent computation runs.
    /// The checks operate on the supplied concrete values only; they cannot
    /// certify independence of deliberately correlated but unequal randomness.
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

        // Validate the reference-string rows (context, row uniqueness, and
        // CRS/URS separation) before sampling the ephemeral key `r`.
        crate::reference_string::validate_reference_string_pair(
            ctx_relin_key,
            &a_polys,
            &d1_polys,
        )?;

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
    /// The same URS/CRS validation applies: identical rows across the two
    /// reference strings and repeated rows within either vector are rejected
    /// before any secret-dependent computation.
    ///
    /// Returns `(ksk_r_to_s, ksk_s_to_r, r, errors_d0, errors_d2)` where:
    /// - `r` is the ephemeral `SecretKey`; auto-zeroized when dropped.
    /// - `errors_d0[i]` is the small error `eᵢ` such that `d0ᵢ = eᵢ − sk·d1ᵢ + gᵢ·r`.
    /// - `errors_d2[i]` is the small error `eᵢ` such that `d2ᵢ = eᵢ + r·aᵢ + gᵢ·sk`.
    ///
    /// The error rows are secret-dependent and are handed over as wipe-on-drop
    /// [`Zeroizing`] owners: ownership transfers to the caller, each row keeps
    /// variable-time computations disabled, and dropping it — normally, on an
    /// early error, or during an unwind — wipes its coefficients and Shoup
    /// tables.
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
        Vec<Zeroizing<Poly<NttShoup>>>,
        Vec<Zeroizing<Poly<NttShoup>>>,
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

        // Validate the reference-string rows before sampling the ephemeral key.
        crate::reference_string::validate_reference_string_pair(
            ctx_relin_key,
            &a_polys,
            &d1_polys,
        )?;

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
    /// `b_vec` has the correct length. The URS `d1` (the `r -> s` key's `c1`
    /// rows) and the CRS `a` (the `s -> r` key's `c1` rows) are validated as
    /// reference strings: repeated rows within either vector and rows shared
    /// between the two vectors are rejected, so no operational key built from
    /// observably reused randomness is ever returned.
    ///
    /// # Structural invariants
    ///
    /// The components must describe the layout the l-BFV constructors
    /// produce: matching parameters, ciphertext level, key level, and
    /// decomposition base; contexts in both KSKs that match the parameters
    /// at the declared levels (and therefore each other; compared by value,
    /// so distinct but value-equal contexts are accepted); a ciphertext
    /// level not below the key level; key-switching contexts with more than
    /// one modulus; the standard RNS decomposition (`log_base = 0`); gadget
    /// rows in both KSKs whose count equals the number of
    /// ciphertext-context moduli and whose c0 rows use the key context (the
    /// c1 rows are context-gated by the reference-string validation); and a
    /// `b_vec` of `#moduli − ciphertext_level` polynomials, each using the
    /// key context. These are the same invariants the deserializers enforce,
    /// so an aggregated key is never built from shares the decoders would
    /// have rejected.
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

        // The l-BFV constructors reject single-modulus key and ciphertext
        // contexts and never produce the single-modulus decomposition
        // (`log_base != 0`), so only the standard RNS layout over
        // multi-modulus contexts is accepted here. An inverted level
        // ordering, a context that does not match the parameters at the
        // declared levels (including stale context fields), or a row count
        // that does not match the ciphertext context is likewise rejected
        // at this boundary instead of surfacing later during
        // relinearization.
        if ksk_r_to_s.ciphertext_level < ksk_r_to_s.ksk_level {
            return Err(Error::DefaultError(
                "RLK KSKs have ciphertext_level below ksk_level".to_string(),
            ));
        }
        // Both KSKs must carry the contexts the parameters derive at the
        // (already-matched) declared levels; context equality is by value,
        // so distinct but value-equal contexts are accepted.
        let expected_ctx_ciphertext = ksk_r_to_s
            .params
            .context_at_level(ksk_r_to_s.ciphertext_level)?
            .clone();
        let expected_ctx_ksk = ksk_r_to_s
            .params
            .context_at_level(ksk_r_to_s.ksk_level)?
            .clone();
        if ksk_r_to_s.ctx_ciphertext != expected_ctx_ciphertext
            || ksk_r_to_s.ctx_ksk != expected_ctx_ksk
            || ksk_s_to_r.ctx_ciphertext != expected_ctx_ciphertext
            || ksk_s_to_r.ctx_ksk != expected_ctx_ksk
        {
            return Err(Error::DefaultError(
                "RLK KSK contexts do not match the parameters at the declared levels".to_string(),
            ));
        }
        if ksk_r_to_s.ctx_ksk.moduli().len() == 1 || ksk_r_to_s.ctx_ciphertext.moduli().len() == 1 {
            return Err(Error::DefaultError(
                "These parameters do not support key switching".to_string(),
            ));
        }
        if ksk_r_to_s.log_base != 0 {
            return Err(Error::DefaultError(
                "RLK KSKs must use the standard RNS decomposition (log_base = 0)".to_string(),
            ));
        }
        // Both KSKs must carry one gadget row per ciphertext-context
        // modulus, and every c0 row must use the key context: internal
        // c0/c1 agreement alone is not enough (a truncated-but-internally-
        // consistent KSK would otherwise pass), the c1 rows are already
        // context-gated by the reference-string check below, and a c0 row
        // in another context would fail only during relinearization.
        let expected_rows = ksk_r_to_s.ctx_ciphertext.moduli().len();
        for (name, ksk) in [("ksk_r_to_s", &ksk_r_to_s), ("ksk_s_to_r", &ksk_s_to_r)] {
            if ksk.c0.len() != expected_rows {
                return Err(Error::DefaultError(format!(
                    "{name} row count mismatch: expected {expected_rows}, got {}",
                    ksk.c0.len()
                )));
            }
            if let Some(i) = ksk
                .c0
                .iter()
                .position(|row| row.ctx() != &ksk_r_to_s.ctx_ksk)
            {
                return Err(Error::DefaultError(format!(
                    "{name} c0 polynomial at index {i} does not use the key context"
                )));
            }
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
        // Each b_vec row must live in the key context: relinearization
        // combines them with the key-switching rows, and a row from any
        // other context cannot be reduced into the ciphertext context.
        if let Some(i) = b_vec.iter().position(|b| b.ctx() != &ksk_r_to_s.ctx_ksk) {
            return Err(Error::DefaultError(format!(
                "b_vec polynomial at index {i} does not use the key context"
            )));
        }

        // Reference-string gate: the shared URS `d1` rows (ksk_r_to_s.c1) and
        // CRS `a` rows (ksk_s_to_r.c1) must be distinct within each vector and
        // disjoint across the two vectors. The structural checks above already
        // guarantee a common key context.
        crate::reference_string::validate_reference_string_pair(
            &ksk_r_to_s.ctx_ksk,
            &ksk_s_to_r.c1,
            &ksk_r_to_s.c1,
        )?;

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
    ///
    /// # Reference-string validation
    ///
    /// The URS `d1` and the CRS `a` are two shared reference strings that the
    /// protocol must generate independently. Identical `d1_seed` and `a_seed`
    /// values are rejected before any key material is produced. When the
    /// public key carries a CRS seed, it must differ from `d1_seed`. These
    /// equality checks catch observably reused randomness; they cannot
    /// certify independence of deliberately correlated but unequal
    /// randomness, which remains a protocol responsibility.
    pub fn new_leveled<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        pk: &LBFVPublicKey,
        d1_seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        if ciphertext_level < key_level {
            return Err(Error::InvalidLevel {
                level: ciphertext_level,
                min_level: key_level,
                max_level: sk.params.max_level(),
            });
        }
        if sk.params.context_at_level(key_level)?.moduli().len() == 1
            || sk.params.context_at_level(ciphertext_level)?.moduli().len() == 1
        {
            return Err(crate::EvaluationKeyError::KeySwitchingNotSupported.into());
        }

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
    /// # Reference-string validation
    ///
    /// The caller-supplied URS `d1_polys` must be pairwise distinct and must
    /// not share any row with the public key's CRS `a` rows (all row-pairs are
    /// compared, so cross-index collisions are rejected too). Rows are
    /// validated before any secret-dependent computation, and the assembled
    /// key is validated again before it is returned. The checks compare
    /// concrete values only: they reject observably reused randomness but
    /// cannot certify independence of deliberately correlated yet unequal
    /// randomness.
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
    /// The URS vector must be independent of the public key's CRS: rows
    /// shared between the two vectors are rejected before any key material is
    /// produced.
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
        let expected = self
            .ksk_r_to_s
            .params
            .max_level()
            .checked_add(1)
            .and_then(|v| v.checked_sub(self.ciphertext_level()))
            .ok_or_else(|| {
                Error::DefaultError("ciphertext_level exceeds max_level in l()".to_string())
            })?;
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
                    poly_i_coefficients
                        .as_slice()
                        .ok_or(fhe_math::Error::NonContiguousCoefficients)?,
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
        }
    }
}

impl TryConvertFrom<&LBFVRelinearizationKeyProto> for LBFVRelinearizationKey {
    fn try_convert_from(
        value: &LBFVRelinearizationKeyProto,
        params: &Arc<BfvParameters>,
    ) -> Result<Self> {
        let ksk_r_to_s = KeySwitchingKey::try_convert_from(
            value
                .ksk_r_to_s
                .as_ref()
                .ok_or(SerializationError::MissingField {
                    field: crate::SerializedField::RelinearizationKeySwitchingKey,
                })?,
            params,
        )?;
        let ksk_s_to_r = KeySwitchingKey::try_convert_from(
            value
                .ksk_s_to_r
                .as_ref()
                .ok_or(SerializationError::MissingField {
                    field: crate::SerializedField::RelinearizationKeySwitchingKey,
                })?,
            params,
        )?;

        // --- Cross-KSK structural validation ---
        // These checks keep the decoder's accepted shape in sync with
        // `from_components` and the share decoder: an inconsistent layout is
        // rejected with a typed serialization error instead of failing later
        // during relinearization.
        if ksk_s_to_r.params != ksk_r_to_s.params {
            return Err(SerializationError::InvalidFormat {
                reason: "RLK KSKs have mismatched parameters".to_string(),
            }
            .into());
        }
        if ksk_s_to_r.ciphertext_level != ksk_r_to_s.ciphertext_level {
            return Err(SerializationError::InvalidFormat {
                reason: "RLK KSKs have mismatched ciphertext levels".to_string(),
            }
            .into());
        }
        if ksk_s_to_r.ksk_level != ksk_r_to_s.ksk_level {
            return Err(SerializationError::InvalidFormat {
                reason: "RLK KSKs have mismatched key levels".to_string(),
            }
            .into());
        }
        if ksk_s_to_r.ctx_ciphertext != ksk_r_to_s.ctx_ciphertext {
            return Err(SerializationError::InvalidFormat {
                reason: "RLK KSKs have mismatched ciphertext contexts".to_string(),
            }
            .into());
        }
        if ksk_s_to_r.ctx_ksk != ksk_r_to_s.ctx_ksk {
            return Err(SerializationError::InvalidFormat {
                reason: "RLK KSKs have mismatched key contexts".to_string(),
            }
            .into());
        }
        if ksk_s_to_r.log_base != ksk_r_to_s.log_base {
            return Err(SerializationError::InvalidFormat {
                reason: "RLK KSKs have mismatched log_base".to_string(),
            }
            .into());
        }
        // Validate c0/c1 dimensions in each KSK
        if ksk_r_to_s.c0.len() != ksk_r_to_s.c1.len() {
            return Err(SerializationError::InvalidFormat {
                reason: "ksk_r_to_s has mismatched c0/c1 dimensions".to_string(),
            }
            .into());
        }
        if ksk_s_to_r.c0.len() != ksk_s_to_r.c1.len() {
            return Err(SerializationError::InvalidFormat {
                reason: "ksk_s_to_r has mismatched c0/c1 dimensions".to_string(),
            }
            .into());
        }

        // The l-BFV constructors reject single-modulus key and ciphertext
        // contexts ("These parameters do not support key switching"), so a
        // serialized key that decodes into such a layout — including the
        // single-modulus decomposition (`log_base != 0`) the generic
        // key-switching-key decoder admits — is rejected here instead of
        // failing later during relinearization.
        if ksk_r_to_s.ctx_ksk.moduli().len() == 1 || ksk_r_to_s.ctx_ciphertext.moduli().len() == 1 {
            return Err(SerializationError::InvalidFormat {
                reason: "RLK key-switching contexts must have more than one modulus".to_string(),
            }
            .into());
        }

        // Reference-string gate: the shared URS `d1` rows (ksk_r_to_s.c1) and
        // CRS `a` rows (ksk_s_to_r.c1) must be distinct within each vector and
        // disjoint across the two vectors. A serialized key built from reused
        // reference-string randomness is rejected instead of being published.
        crate::reference_string::validate_reference_string_pair(
            &ksk_r_to_s.ctx_ksk,
            &ksk_s_to_r.c1,
            &ksk_r_to_s.c1,
        )?;

        // --- b_vec validation ---
        let expected_b_vec_len = params
            .moduli()
            .len()
            .checked_sub(ksk_r_to_s.ciphertext_level)
            .ok_or_else(|| SerializationError::InvalidFormat {
                reason: "Invalid b_vec: ciphertext_level exceeds modulus count".to_string(),
            })?;
        if value.b_vec.len() != expected_b_vec_len {
            return Err(SerializationError::WrongPolynomialCount {
                component: crate::SerializedPolynomialComponent::RelinearizationKeyBVec,
                expected: expected_b_vec_len,
                actual: value.b_vec.len(),
            }
            .into());
        }

        let key_ctx = ksk_r_to_s.ctx_ksk.clone();
        let mut b_vec = Vec::with_capacity(value.b_vec.len());
        for (i, poly_bytes) in value.b_vec.iter().enumerate() {
            let poly = Poly::<NttShoup>::from_bytes(poly_bytes, &key_ctx).map_err(|e| {
                SerializationError::InvalidFormat {
                    reason: format!("Invalid b_vec polynomial at index {i}: {e}"),
                }
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
        let rk =
            crate::serialization::decode(bytes, crate::SerializedObject::LbfvRelinearizationKey)?;
        LBFVRelinearizationKey::try_convert_from(&rk, params)
    }
}
#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::bfv::{Encoding, Plaintext};
    use crate::support::presets::insecure;
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::rng;
    use std::error::Error;
    use std::result::Result;

    use fhe_traits::{DeserializeParametrized, Serialize};

    fn assert_same_key_material(left: &LBFVPublicKey, right: &LBFVPublicKey) {
        assert_eq!(left.parameters(), right.parameters());
        assert_eq!(left.row_count(), right.row_count());
        assert_eq!(left.rows().len(), right.rows().len());
        for (left_row, right_row) in left.rows().iter().zip(right.rows()) {
            assert_eq!(left_row.level, right_row.level);
            assert!(left_row.iter().eq(right_row.iter()));
        }
    }

    #[test]
    fn test_serialize_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;

        // Create relinearization key
        let relin_key = LBFVRelinearizationKey::new(&sk, &pk, None, &mut rng)?;

        // Serialize and deserialize
        let bytes = relin_key.to_bytes();
        let deserialized_key = LBFVRelinearizationKey::from_bytes(&bytes, &params)?;

        assert_eq!(pk.parameters(), params.as_ref());
        assert!(pk.seed().is_some());
        assert_eq!(pk.rows().len(), pk.row_count());
        assert_eq!(deserialized_key.d0_components().len(), pk.row_count());
        assert_eq!(deserialized_key.d1_components().len(), pk.row_count());
        assert_eq!(deserialized_key.d2_components().len(), pk.row_count());
        assert_eq!(deserialized_key.a_components().len(), pk.row_count());
        assert_eq!(deserialized_key.b_components().len(), pk.row_count());
        assert_eq!(deserialized_key.decomposition_log_base(), 0);
        let reconstructed_pk = deserialized_key.reconstruct_public_key()?;
        assert_same_key_material(&pk, &reconstructed_pk);
        assert_eq!(reconstructed_pk, pk);

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
    fn from_bytes_preserves_protobuf_decode_error() {
        let params = insecure().unwrap().parameters;
        let error = LBFVRelinearizationKey::from_bytes(&[0x0a], &params).unwrap_err();

        assert!(matches!(
            error,
            crate::Error::SerializationError(SerializationError::Decode {
                object: crate::SerializedObject::LbfvRelinearizationKey,
                message,
            }) if !message.is_empty()
        ));
    }

    #[test]
    fn test_multiplication() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        // Keep the small local profile here because this test intentionally
        // covers both polynomial and SIMD encodings. The shared insecure
        // profile does not provide SIMD parameters.
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
        let params = insecure().unwrap().parameters;
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
        let generated_reconstruction = generated_d1_key.reconstruct_public_key()?;
        let explicit_reconstruction = explicit_d1_key.reconstruct_public_key()?;
        assert_same_key_material(&seedless, &generated_reconstruction);
        assert_same_key_material(&seedless, &explicit_reconstruction);
        assert_eq!(generated_reconstruction, seedless);
        assert_eq!(explicit_reconstruction, seedless);

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

    #[test]
    fn public_key_reconstruction_rejects_leveled_keys() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new_with_seed(&sk, [71u8; 32], &mut rng)?;
        let leveled =
            LBFVRelinearizationKey::new_leveled(&sk, &pk, Some([72u8; 32]), 1, 0, &mut rng)?;

        assert!(leveled.reconstruct_public_key().is_err());

        let (ksk_r_to_s, ksk_s_to_r) = LBFVRelinearizationKey::generate_components_with_seed(
            &sk, [73u8; 32], [74u8; 32], 1, 1, &mut rng,
        )?;
        let b_vec = ksk_r_to_s.c0.to_vec();
        let fully_leveled = LBFVRelinearizationKey::from_components(ksk_r_to_s, ksk_s_to_r, b_vec)?;
        assert!(fully_leveled.reconstruct_public_key().is_err());
        Ok(())
    }

    #[test]
    fn public_key_reconstruction_preserves_rows_across_seed_representations()
    -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let seeded_pk = LBFVPublicKey::new_with_seed(&sk, [76u8; 32], &mut rng)?;
        let seedless_pk = LBFVPublicKey::from_parts(
            seeded_pk
                .rows()
                .iter()
                .map(|row| row.first().cloned())
                .collect::<Option<_>>()
                .ok_or("missing public-key b polynomial")?,
            seeded_pk
                .rows()
                .iter()
                .map(|row| row.get(1).cloned())
                .collect::<Option<_>>()
                .ok_or("missing public-key a polynomial")?,
            params.clone(),
            None,
        )?;

        let seeded_rlk = LBFVRelinearizationKey::new(&sk, &seeded_pk, Some([77u8; 32]), &mut rng)?;
        let seedless_rlk =
            LBFVRelinearizationKey::new(&sk, &seedless_pk, Some([78u8; 32]), &mut rng)?;

        assert_same_key_material(&seedless_pk, &seeded_rlk.reconstruct_public_key()?);
        assert_same_key_material(&seeded_pk, &seedless_rlk.reconstruct_public_key()?);
        Ok(())
    }

    /// Verify per-row KSK equations from the paper for `generate_components_with_polys_extended`:
    /// - `d0ᵢ + sk·d1ᵢ = e0ᵢ + gᵢ·r`  (ksk_r_to_s)
    /// - `d2ᵢ − r·aᵢ = e2ᵢ + gᵢ·sk`   (ksk_s_to_r, using neg_r so sign cancels)
    #[test]
    fn generate_components_extended_witness_equations() -> Result<(), Box<dyn std::error::Error>> {
        use crate::bfv::KeySwitchingKey;
        use fhe_math::rns::RnsContext;
        use fhe_math::rq::traits::TryConvertFrom as TryConvertFromPoly;

        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let ctx = params.context_at_level(0)?;

        let d1_polys = KeySwitchingKey::c1_from_seed(ctx, [11u8; 32], params.moduli().len());
        let a_polys = KeySwitchingKey::c1_from_seed(ctx, [22u8; 32], params.moduli().len());

        let (ksk_r_to_s, ksk_s_to_r, r, errors_d0, errors_d2) =
            LBFVRelinearizationKey::generate_components_with_polys_extended(
                &sk,
                d1_polys.clone(),
                a_polys.clone(),
                0,
                0,
                &mut rng,
            )?;

        let rns = RnsContext::new(&params.moduli)?;

        let sk_ntt =
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx, false)?.into_ntt();
        let r_pb = Poly::<PowerBasis>::try_convert_from(r.coeffs.as_ref(), ctx, false)?;
        let sk_pb = Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx, false)?;

        // d0ᵢ + sk·d1ᵢ = e0ᵢ + gᵢ·r
        for (i, ((d0_i, d1_i), e0_i)) in ksk_r_to_s
            .c0
            .iter()
            .zip(ksk_r_to_s.c1.iter())
            .zip(errors_d0.iter())
            .enumerate()
        {
            // The witness error rows are wipe-on-drop owners and remain
            // secret in time policy.
            assert!(!e0_i.allows_variable_time_computations());
            let lhs = (&d0_i.clone().into_ntt() + &(&d1_i.clone().into_ntt() * &sk_ntt))
                .into_power_basis();
            let gi = rns.get_garner(i).expect("garner");
            let rhs =
                (&e0_i.as_ref().clone().into_ntt() + &(gi * &r_pb).into_ntt()).into_power_basis();
            assert_eq!(lhs, rhs, "d0 witness equation failed at row {i}");
        }

        // ksk_s_to_r was built with neg_r = −r as the "sk" argument.
        // KSK invariant: c0ᵢ + c1ᵢ·(encrypting_key) = eᵢ + gᵢ·(from_key)
        // Here encrypting_key = neg_r, from_key = sk, so: d2ᵢ + aᵢ·(−r) = e2ᵢ + gᵢ·sk
        // Rearranged (paper form):  d2ᵢ = e2ᵢ + r·aᵢ + gᵢ·sk  ✓
        let mut neg_r_coeffs = r.coeffs.clone();
        neg_r_coeffs.iter_mut().for_each(|c| *c = c.wrapping_neg());
        let neg_r_pb = Poly::<PowerBasis>::try_convert_from(neg_r_coeffs.as_ref(), ctx, false)?;
        let neg_r_ntt = neg_r_pb.into_ntt();

        for (i, ((d2_i, a_i), e2_i)) in ksk_s_to_r
            .c0
            .iter()
            .zip(ksk_s_to_r.c1.iter())
            .zip(errors_d2.iter())
            .enumerate()
        {
            assert!(!e2_i.allows_variable_time_computations());
            let lhs = (&d2_i.clone().into_ntt() + &(&a_i.clone().into_ntt() * &neg_r_ntt))
                .into_power_basis();
            let gi = rns.get_garner(i).expect("garner");
            let rhs =
                (&e2_i.as_ref().clone().into_ntt() + &(gi * &sk_pb).into_ntt()).into_power_basis();
            assert_eq!(lhs, rhs, "d2 witness equation failed at row {i}");
        }

        Ok(())
    }

    /// A tampered public key where the concrete `a` polynomials have been
    /// changed but `pk.seed` is left unchanged must be rejected immediately
    /// by the seeded RLK path — contradictory seed metadata is an error.
    #[test]
    fn tampered_pk_concrete_a_rejected_by_seeded_rlk_path() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
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

    /// The seeded URS/CRS path must reject identical seeds — the two reference
    /// strings must be generated independently.
    #[test]
    fn rlk_generation_rejects_identical_urs_and_crs_seeds() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);

        let same_seed: <ChaCha8Rng as SeedableRng>::Seed = [91u8; 32];

        // Direct component generation rejects identical seeds.
        assert!(matches!(
            LBFVRelinearizationKey::generate_components_with_seed(
                &sk, same_seed, same_seed, 0, 0, &mut rng
            ),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::IdenticalReferenceStringSeeds
            ))
        ));

        // So does the public constructor when the public key's CRS seed equals
        // the caller-supplied URS seed.
        let pk = LBFVPublicKey::new_with_seed(&sk, same_seed, &mut rng)?;
        assert!(matches!(
            LBFVRelinearizationKey::new(&sk, &pk, Some(same_seed), &mut rng),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::IdenticalReferenceStringSeeds
            ))
        ));

        // Control: distinct seeds are accepted.
        let pk_ok = LBFVRelinearizationKey::new(&sk, &pk, Some([92u8; 32]), &mut rng)?;
        assert_eq!(pk_ok.ciphertext_level(), 0);
        Ok(())
    }

    /// The explicit-polynomial path must reject URS rows that repeat within
    /// the vector or collide with CRS rows at any index pairing.
    #[test]
    fn rlk_explicit_path_rejects_reused_and_repeated_rows() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let ctx0 = params.context_at_level(0)?;

        // Seedless public key with explicit CRS rows.
        let seeded = LBFVPublicKey::new_with_seed(&sk, [51u8; 32], &mut rng)?;
        let a_polys: Vec<Poly<Ntt>> = seeded
            .c
            .iter()
            .map(|ciphertext| ciphertext.c.get(1).cloned())
            .collect::<Option<_>>()
            .ok_or("missing public-key a polynomial")?;
        let seedless = LBFVPublicKey::from_crs(&sk, &a_polys, None, &mut rng)?;

        let mut d1_polys = KeySwitchingKey::c1_from_seed(ctx0, [61u8; 32], params.moduli().len());

        // Control: the independent vectors are accepted.
        let control = LBFVRelinearizationKey::new_leveled_with_polys(
            &sk,
            &seedless,
            d1_polys.clone(),
            0,
            0,
            &mut rng,
        )?;
        assert_eq!(control.d1_components().len(), d1_polys.len());

        // Cross-index collision: URS row 2 equals CRS row 1.
        let mut colliding = d1_polys.clone();
        colliding[2] = a_polys[1].clone().into_ntt_shoup();
        assert!(matches!(
            LBFVRelinearizationKey::new_leveled_with_polys(
                &sk, &seedless, colliding, 0, 0, &mut rng
            ),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::OverlappingReferenceStringRows {
                    crs_index: 1,
                    urs_index: 2,
                }
            ))
        ));

        // Repeated row inside the URS vector.
        d1_polys[2] = d1_polys[0].clone();
        assert!(matches!(
            LBFVRelinearizationKey::new_leveled_with_polys(
                &sk, &seedless, d1_polys, 0, 0, &mut rng
            ),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::RepeatedReferenceStringRow {
                    role: crate::ReferenceStringRole::Urs,
                    first_index: 0,
                    second_index: 2,
                }
            ))
        ));

        Ok(())
    }

    /// Public-API regressions: the URS CRP supplied to `new_leveled_with_crp`
    /// / `new_with_crp` must not be the same vector as the public key's CRS
    /// CRP, in both the seeded and seedless CRP forms, with independent-input
    /// controls.
    #[test]
    fn crp_paths_reject_urs_equal_to_pk_crs() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);

        // Seeded CRP form: the URS vector is the PK's CRS vector (same master
        // seed, hence identical concrete rows).
        let crs_seed: <ChaCha8Rng as SeedableRng>::Seed = [81u8; 32];
        let crp_crs = CommonRandomPolyVec::from_seed(&params, crs_seed)?;
        let pk_seeded = LBFVPublicKey::new_with_crp(&sk, &crp_crs, &mut rng)?;
        assert_eq!(pk_seeded.seed, Some(crs_seed));

        let crp_urs_same = CommonRandomPolyVec::from_seed(&params, crs_seed)?;
        assert!(matches!(
            LBFVRelinearizationKey::new_leveled_with_crp(
                &sk,
                &pk_seeded,
                &crp_urs_same,
                0,
                0,
                &mut rng
            ),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::OverlappingReferenceStringRows {
                    crs_index: 0,
                    urs_index: 0,
                }
            ))
        ));
        assert!(matches!(
            LBFVRelinearizationKey::new_with_crp(&sk, &pk_seeded, &crp_urs_same, &mut rng),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::OverlappingReferenceStringRows {
                    crs_index: 0,
                    urs_index: 0,
                }
            ))
        ));

        // Seedless CRP form: same concrete rows, no seed metadata.
        let crp_crs_seedless = CommonRandomPolyVec::from_polys(&params, crp_crs.to_polys(), None)?;
        let pk_seedless = LBFVPublicKey::new_with_crp(&sk, &crp_crs_seedless, &mut rng)?;
        assert!(pk_seedless.seed.is_none());
        let crp_urs_seedless = CommonRandomPolyVec::from_polys(
            &params,
            pk_seedless
                .c
                .iter()
                .map(|ct| ct.c.get(1).cloned())
                .collect::<Option<_>>()
                .ok_or("missing public-key a polynomial")?,
            None,
        )?;
        assert!(matches!(
            LBFVRelinearizationKey::new_leveled_with_crp(
                &sk,
                &pk_seedless,
                &crp_urs_seedless,
                0,
                0,
                &mut rng
            ),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::OverlappingReferenceStringRows {
                    crs_index: 0,
                    urs_index: 0,
                }
            ))
        ));

        // Control: an independent URS CRP is accepted against both PK forms.
        let urs_seed: <ChaCha8Rng as SeedableRng>::Seed = [82u8; 32];
        let crp_urs_independent = CommonRandomPolyVec::from_seed(&params, urs_seed)?;
        assert!(
            LBFVRelinearizationKey::new_leveled_with_crp(
                &sk,
                &pk_seeded,
                &crp_urs_independent,
                0,
                0,
                &mut rng
            )
            .is_ok()
        );
        assert!(
            LBFVRelinearizationKey::new_with_crp(&sk, &pk_seedless, &crp_urs_independent, &mut rng)
                .is_ok()
        );
        Ok(())
    }

    /// `new_leveled` with a seedless public key whose CRS rows coincide with
    /// the concrete rows the caller-supplied URS seed derives must be
    /// rejected; an independent seed is accepted.
    #[test]
    fn new_leveled_seedless_pk_rejects_d1_seed_deriving_matching_crs_rows()
    -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let ctx0 = params.context_at_level(0)?;

        let colliding_seed: <ChaCha8Rng as SeedableRng>::Seed = [61u8; 32];
        let derived = KeySwitchingKey::c1_from_seed(ctx0, colliding_seed, params.moduli().len());
        let a_rows: Vec<Poly<Ntt>> = derived.into_iter().map(|poly| poly.into_ntt()).collect();

        // Seedless public key whose CRS rows are exactly the rows the seed
        // derives.
        let pk = LBFVPublicKey::from_crs(&sk, &a_rows, None, &mut rng)?;
        assert!(pk.seed.is_none());

        assert!(matches!(
            LBFVRelinearizationKey::new_leveled(&sk, &pk, Some(colliding_seed), 0, 0, &mut rng),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::OverlappingReferenceStringRows {
                    crs_index: 0,
                    urs_index: 0,
                }
            ))
        ));

        // Control: an independent URS seed is accepted.
        let independent_seed: <ChaCha8Rng as SeedableRng>::Seed = [62u8; 32];
        assert!(
            LBFVRelinearizationKey::new_leveled(&sk, &pk, Some(independent_seed), 0, 0, &mut rng)
                .is_ok()
        );
        Ok(())
    }

    /// The seeded path enforces reference-string separation at a nonzero
    /// ciphertext level too, with an independent-input control.
    #[test]
    fn seeded_path_enforces_reference_strings_at_nonzero_ciphertext_level()
    -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let crs_seed: <ChaCha8Rng as SeedableRng>::Seed = [83u8; 32];
        let pk = LBFVPublicKey::new_with_seed(&sk, crs_seed, &mut rng)?;

        // Negative: identical URS and CRS seeds at ciphertext level 1.
        assert!(matches!(
            LBFVRelinearizationKey::new_leveled(&sk, &pk, Some(crs_seed), 1, 0, &mut rng),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::IdenticalReferenceStringSeeds
            ))
        ));

        // Control: independent seeds at ciphertext level 1 succeed.
        let d1_seed: <ChaCha8Rng as SeedableRng>::Seed = [84u8; 32];
        let key = LBFVRelinearizationKey::new_leveled(&sk, &pk, Some(d1_seed), 1, 0, &mut rng)?;
        assert_eq!(key.ciphertext_level(), 1);
        Ok(())
    }

    /// A serialized relinearization key whose URS/CRS rows are reused or
    /// repeated must be rejected at deserialization time.
    #[test]
    fn serialized_rlk_with_reused_reference_string_rows_rejected() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let ctx0 = params.context_at_level(0)?;

        let seeded = LBFVPublicKey::new_with_seed(&sk, [51u8; 32], &mut rng)?;
        let a_polys: Vec<Poly<Ntt>> = seeded
            .c
            .iter()
            .map(|ciphertext| ciphertext.c.get(1).cloned())
            .collect::<Option<_>>()
            .ok_or("missing public-key a polynomial")?;
        let seedless = LBFVPublicKey::from_crs(&sk, &a_polys, None, &mut rng)?;
        let d1_polys = KeySwitchingKey::c1_from_seed(ctx0, [61u8; 32], params.moduli().len());
        let key = LBFVRelinearizationKey::new_leveled_with_polys(
            &sk, &seedless, d1_polys, 0, 0, &mut rng,
        )?;

        // Control: the honest payload round-trips.
        let roundtripped = LBFVRelinearizationKey::from_bytes(&key.to_bytes(), &params)?;
        assert_eq!(roundtripped, key);

        // Tamper: URS row 0 becomes a copy of CRS row 0.
        let mut overlapping: LBFVRelinearizationKeyProto =
            LBFVRelinearizationKeyProto::decode(key.to_bytes().as_slice())?;
        let crs_row0 = overlapping
            .ksk_s_to_r
            .as_ref()
            .ok_or("missing ksk_s_to_r")?
            .c1[0]
            .clone();
        if let Some(urs) = overlapping.ksk_r_to_s.as_mut() {
            urs.c1[0] = crs_row0;
        }
        assert!(matches!(
            LBFVRelinearizationKey::from_bytes(&overlapping.encode_to_vec(), &params),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::OverlappingReferenceStringRows {
                    crs_index: 0,
                    urs_index: 0,
                }
            ))
        ));

        // Tamper: repeat a row within the URS vector.
        let mut repeated: LBFVRelinearizationKeyProto =
            LBFVRelinearizationKeyProto::decode(key.to_bytes().as_slice())?;
        if let Some(urs) = repeated.ksk_r_to_s.as_mut() {
            urs.c1[2] = urs.c1[0].clone();
        }
        assert!(matches!(
            LBFVRelinearizationKey::from_bytes(&repeated.encode_to_vec(), &params),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::RepeatedReferenceStringRow {
                    role: crate::ReferenceStringRole::Urs,
                    first_index: 0,
                    second_index: 2,
                }
            ))
        ));

        Ok(())
    }

    /// Mutation tests for the operational l-BFV RLK decoder: every field the
    /// l-BFV constructors constrain (levels, contexts via levels, gadget-row
    /// counts, the decomposition base, and `b_vec`) must be rejected at
    /// decode time with a typed error instead of deferring to
    /// `relinearizes`.
    #[test]
    fn serialized_rlk_rejects_inconsistent_layouts() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;
        let key = LBFVRelinearizationKey::new(&sk, &pk, Some([91u8; 32]), &mut rng)?;

        // Control: the honest payload round-trips.
        assert_eq!(
            LBFVRelinearizationKey::from_bytes(&key.to_bytes(), &params)?,
            key
        );

        let decode_proto =
            |proto: &LBFVRelinearizationKeyProto| -> std::result::Result<LBFVRelinearizationKey, crate::Error> {
                LBFVRelinearizationKey::from_bytes(&proto.encode_to_vec(), &params)
            };

        // Control: decoding the re-encoded proto keeps the same rows.
        let proto: LBFVRelinearizationKeyProto =
            LBFVRelinearizationKeyProto::decode(key.to_bytes().as_slice())?;
        assert_eq!(decode_proto(&proto)?, key);

        // Tamper: truncate a gadget row; the decoder must enforce the
        // constructor row count (one row per ciphertext-context modulus).
        let mut row_count = proto.clone();
        row_count.ksk_r_to_s.as_mut().expect("ksk_r_to_s").c0.pop();
        assert!(matches!(
            decode_proto(&row_count),
            Err(crate::Error::SerializationError(
                SerializationError::WrongPolynomialCount {
                    component: crate::SerializedPolynomialComponent::KeySwitchingKeyC0,
                    expected: 3,
                    actual: 2,
                }
            ))
        ));

        // Tamper: a nonzero decomposition base on a multi-modulus key
        // context is a layout no l-BFV constructor produces.
        let mut log_base = proto.clone();
        if let Some(ksk) = log_base.ksk_r_to_s.as_mut() {
            ksk.log_base = 3;
        }
        if let Some(ksk) = log_base.ksk_s_to_r.as_mut() {
            ksk.log_base = 3;
        }
        assert!(matches!(
            decode_proto(&log_base),
            Err(crate::Error::SerializationError(
                SerializationError::InvalidKeySwitchingLogBase {
                    log_base: 3,
                    expected_log_base: 0,
                }
            ))
        ));

        // Tamper: moving both levels to the maximal level keeps the level
        // ordering coherent but puts the key context in a single-modulus
        // context; with the standard `log_base = 0` this is not a
        // constructor layout.
        let mut key_level = proto.clone();
        if let Some(ksk) = key_level.ksk_r_to_s.as_mut() {
            ksk.ksk_level = params.max_level() as u32;
            ksk.ciphertext_level = params.max_level() as u32;
        }
        if let Some(ksk) = key_level.ksk_s_to_r.as_mut() {
            ksk.ksk_level = params.max_level() as u32;
            ksk.ciphertext_level = params.max_level() as u32;
        }
        assert!(matches!(
            decode_proto(&key_level),
            Err(crate::Error::SerializationError(
                SerializationError::InvalidKeySwitchingLogBase { log_base: 0, .. }
            ))
        ));

        // Tamper: key levels above the ciphertext level are rejected by the
        // key-switching-key decoder before any rows are inspected.
        let mut level_order = proto.clone();
        if let Some(ksk) = level_order.ksk_r_to_s.as_mut() {
            ksk.ksk_level = 1;
        }
        if let Some(ksk) = level_order.ksk_s_to_r.as_mut() {
            ksk.ksk_level = 1;
        }
        assert!(matches!(
            decode_proto(&level_order),
            Err(crate::Error::SerializationError(
                SerializationError::InvalidKeySwitchingLevelOrder {
                    ciphertext_level: 0,
                    key_level: 1,
                }
            ))
        ));

        // Tamper: a maximal ciphertext level (one-modulus ciphertext
        // context) with matching row surgery is still a layout the l-BFV
        // constructors reject, so the decoder must not accept it even though
        // the row counts now cohere.
        let mut single_modulus = proto.clone();
        {
            let ksk_r_to_s = single_modulus.ksk_r_to_s.as_mut().expect("ksk_r_to_s");
            ksk_r_to_s.ciphertext_level = params.max_level() as u32;
            ksk_r_to_s.c0.truncate(1);
            ksk_r_to_s.c1.truncate(1);
            let ksk_s_to_r = single_modulus.ksk_s_to_r.as_mut().expect("ksk_s_to_r");
            ksk_s_to_r.ciphertext_level = params.max_level() as u32;
            ksk_s_to_r.c0.truncate(1);
            ksk_s_to_r.c1.truncate(1);
            single_modulus.b_vec.truncate(1);
        }
        assert!(matches!(
            decode_proto(&single_modulus),
            Err(crate::Error::SerializationError(
                SerializationError::InvalidFormat { reason }
            )) if reason.contains("one modulus")
        ));

        // Tamper: an extra `b_vec` row breaks the `#moduli − ciphertext
        // level` invariant.
        let mut b_vec = proto.clone();
        let extra_row = b_vec.b_vec.first().expect("b_vec row").clone();
        b_vec.b_vec.push(extra_row);
        assert!(matches!(
            decode_proto(&b_vec),
            Err(crate::Error::SerializationError(
                SerializationError::WrongPolynomialCount {
                    component: crate::SerializedPolynomialComponent::RelinearizationKeyBVec,
                    expected: 3,
                    actual: 4,
                }
            ))
        ));

        Ok(())
    }

    /// Valid seeded keys round-trip at a nonzero ciphertext level too.
    #[test]
    fn serialized_rlk_roundtrips_nonzero_ciphertext_level() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;

        let key = LBFVRelinearizationKey::new_leveled(&sk, &pk, Some([93u8; 32]), 1, 0, &mut rng)?;
        assert_eq!(key.ciphertext_level(), 1);
        assert_eq!(key.key_level(), 0);
        assert_eq!(
            LBFVRelinearizationKey::from_bytes(&key.to_bytes(), &params)?,
            key
        );
        Ok(())
    }

    /// `from_components` enforces the same structural invariants as the
    /// decoders, so an operational key can never be assembled — directly or
    /// through aggregation — from KSKs the deserializers would have
    /// rejected.
    #[test]
    fn from_components_rejects_inconsistent_ksk_layouts() -> Result<(), Box<dyn Error>> {
        use crate::bfv::KeySwitchingKey;

        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;
        let b_vec = pk.extract_b_polynomials(0, 0, Representation::NttShoup)?;

        // Control: honest components assemble.
        let (ksk_r_to_s, ksk_s_to_r) = LBFVRelinearizationKey::generate_components_with_seed(
            &sk, [95u8; 32], [96u8; 32], 0, 0, &mut rng,
        )?;
        assert!(
            LBFVRelinearizationKey::from_components(
                ksk_r_to_s.clone(),
                ksk_s_to_r.clone(),
                b_vec.clone(),
            )
            .is_ok()
        );

        // Tamper: key levels above the ciphertext level.
        let mut below = ksk_r_to_s.clone();
        below.ksk_level = 1;
        let mut below_s = ksk_s_to_r.clone();
        below_s.ksk_level = 1;
        assert!(matches!(
            LBFVRelinearizationKey::from_components(below, below_s, b_vec.clone()),
            Err(crate::Error::DefaultError(msg)) if msg.contains("ciphertext_level below ksk_level")
        ));

        // Tamper: `log_base != 0` on multi-modulus contexts is a layout the
        // l-BFV constructors never produce.
        let mut decomposition = ksk_r_to_s.clone();
        decomposition.log_base = 31;
        let mut decomposition_s = ksk_s_to_r.clone();
        decomposition_s.log_base = 31;
        assert!(matches!(
            LBFVRelinearizationKey::from_components(decomposition, decomposition_s, b_vec.clone()),
            Err(crate::Error::DefaultError(msg)) if msg.contains("standard RNS decomposition")
        ));

        // Tamper: a gadget-row count that does not match the ciphertext
        // context (dims kept equal so the earlier per-KSK check passes).
        let drop_last_row = |ksk: &mut KeySwitchingKey| {
            let mut c0 = ksk.c0.to_vec();
            c0.pop();
            let mut c1 = ksk.c1.to_vec();
            c1.pop();
            ksk.c0 = c0.into_boxed_slice();
            ksk.c1 = c1.into_boxed_slice();
        };
        let mut rows = ksk_r_to_s.clone();
        drop_last_row(&mut rows);
        let mut rows_s = ksk_s_to_r.clone();
        drop_last_row(&mut rows_s);
        assert!(matches!(
            LBFVRelinearizationKey::from_components(rows, rows_s, b_vec.clone()),
            Err(crate::Error::DefaultError(msg)) if msg.contains("row count mismatch")
        ));

        // Tamper: a one-modulus ciphertext context. The generic key-switching
        // key constructor supports this layout, but the l-BFV constructors
        // reject it, so `from_components` must reject it too.
        let ctx_ksk = params.context_at_level(params.max_level() - 1)?;
        let from_1 = Poly::<PowerBasis>::small(ctx_ksk, 10, &mut rng)?;
        let from_2 = Poly::<PowerBasis>::small(ctx_ksk, 10, &mut rng)?;
        let single_ct_1 = KeySwitchingKey::new(&sk, &from_1, params.max_level(), 1, &mut rng)?;
        let single_ct_2 = KeySwitchingKey::new(&sk, &from_2, params.max_level(), 1, &mut rng)?;
        assert_eq!(single_ct_1.log_base, 0);
        assert_eq!(
            single_ct_1.ctx_ciphertext.moduli().len(),
            1,
            "the ciphertext context must be single-modulus for this mutation"
        );
        let single_ct_rows = single_ct_1.c0.to_vec();
        assert!(matches!(
            LBFVRelinearizationKey::from_components(single_ct_1, single_ct_2, single_ct_rows),
            Err(crate::Error::DefaultError(msg))
                if msg.contains("do not support key switching")
        ));

        // Tamper: a one-modulus key context (the single-modulus decomposition
        // layout) is likewise rejected.
        let ctx_max = params.context_at_level(params.max_level())?;
        let from_1 = Poly::<PowerBasis>::small(ctx_max, 10, &mut rng)?;
        let from_2 = Poly::<PowerBasis>::small(ctx_max, 10, &mut rng)?;
        let single_key_1 = KeySwitchingKey::new(&sk, &from_1, params.max_level(), 2, &mut rng)?;
        let single_key_2 = KeySwitchingKey::new(&sk, &from_2, params.max_level(), 2, &mut rng)?;
        assert!(single_key_1.log_base > 0);
        let single_key_rows = single_key_1.c0.to_vec();
        assert!(matches!(
            LBFVRelinearizationKey::from_components(single_key_1, single_key_2, single_key_rows),
            Err(crate::Error::DefaultError(msg))
                if msg.contains("do not support key switching")
        ));

        // Tamper: an s_to_r KSK truncated to a shorter but internally
        // matched row count must be caught by the shared expected count,
        // not only by the r_to_s check.
        let mut truncated_s = ksk_s_to_r.clone();
        drop_last_row(&mut truncated_s);
        assert!(matches!(
            LBFVRelinearizationKey::from_components(
                ksk_r_to_s.clone(),
                truncated_s,
                b_vec.clone(),
            ),
            Err(crate::Error::DefaultError(msg))
                if msg.contains("ksk_s_to_r row count mismatch")
        ));

        // Tamper: an s_to_r KSK whose key context belongs to another level
        // does not describe one coherent layout with its r_to_s partner.
        let mut cross_ctx = ksk_s_to_r.clone();
        cross_ctx.ctx_ksk = params.context_at_level(1)?.clone();
        assert!(matches!(
            LBFVRelinearizationKey::from_components(
                ksk_r_to_s.clone(),
                cross_ctx,
                b_vec.clone(),
            ),
            Err(crate::Error::DefaultError(msg))
                if msg.contains("do not match the parameters at the declared levels")
        ));

        // Tamper: stale context fields inconsistent with the declared
        // levels (levels moved up coherently, contexts left at level 0)
        // must be rejected even though the levels themselves are valid.
        let mut stale_r = ksk_r_to_s.clone();
        stale_r.ciphertext_level = 1;
        stale_r.ksk_level = 1;
        let mut stale_s = ksk_s_to_r.clone();
        stale_s.ciphertext_level = 1;
        stale_s.ksk_level = 1;
        assert!(matches!(
            LBFVRelinearizationKey::from_components(stale_r, stale_s, b_vec.clone()),
            Err(crate::Error::DefaultError(msg))
                if msg.contains("do not match the parameters at the declared levels")
        ));

        // Tamper: a b_vec row from another context cannot participate in
        // relinearization and must be rejected even at the correct length.
        let ctx_other = params.context_at_level(1)?;
        let stray = Poly::<NttShoup>::try_convert_from(
            vec![0u64; ctx_other.moduli().len() * params.degree()],
            ctx_other,
            false,
        )
        .map_err(crate::Error::MathError)?;
        let mut wrong_ctx_b_vec = b_vec.clone();
        *wrong_ctx_b_vec.first_mut().expect("b_vec row") = stray;
        assert!(matches!(
            LBFVRelinearizationKey::from_components(
                ksk_r_to_s.clone(),
                ksk_s_to_r.clone(),
                wrong_ctx_b_vec,
            ),
            Err(crate::Error::DefaultError(msg))
                if msg.contains("does not use the key context")
        ));

        // Tamper: c0 rows are caller-supplied (KeySwitchingKey fields are
        // public), so a row from another context — which would fail only
        // during relinearization — must be rejected in both KSKs.
        let stray_c0 = Poly::<NttShoup>::try_convert_from(
            vec![0u64; ctx_other.moduli().len() * params.degree()],
            ctx_other,
            false,
        )
        .map_err(crate::Error::MathError)?;
        let mut stray_r = ksk_r_to_s.clone();
        let mut r_rows = stray_r.c0.to_vec();
        *r_rows.first_mut().expect("c0 row") = stray_c0.clone();
        stray_r.c0 = r_rows.into_boxed_slice();
        assert!(matches!(
            LBFVRelinearizationKey::from_components(stray_r, ksk_s_to_r.clone(), b_vec.clone()),
            Err(crate::Error::DefaultError(msg)) if msg.contains(
                "ksk_r_to_s c0 polynomial at index 0 does not use the key context"
            )
        ));
        let mut stray_s = ksk_s_to_r.clone();
        let mut s_rows = stray_s.c0.to_vec();
        *s_rows.first_mut().expect("c0 row") = stray_c0;
        stray_s.c0 = s_rows.into_boxed_slice();
        assert!(matches!(
            LBFVRelinearizationKey::from_components(ksk_r_to_s.clone(), stray_s, b_vec.clone()),
            Err(crate::Error::DefaultError(msg)) if msg.contains(
                "ksk_s_to_r c0 polynomial at index 0 does not use the key context"
            )
        ));

        // Value-equal but distinct contexts are still accepted: the
        // aggregation path compares decoded contexts by value, so identity
        // must not be required.
        let twin_ctx_ksk =
            Context::new_arc(params.moduli(), params.degree()).map_err(crate::Error::MathError)?;
        assert!(
            !Arc::ptr_eq(&twin_ctx_ksk, params.context_at_level(0)?),
            "the rebuilt context must be a distinct allocation"
        );
        let twin_r = {
            let mut twin = ksk_r_to_s.clone();
            twin.ctx_ksk = twin_ctx_ksk;
            twin
        };
        LBFVRelinearizationKey::from_components(twin_r, ksk_s_to_r.clone(), b_vec.clone())?;

        Ok(())
    }
}
