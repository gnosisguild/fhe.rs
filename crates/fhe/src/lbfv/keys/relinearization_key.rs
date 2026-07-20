/*!
 * Implementation of the l-BFV relinearization algorithm as described in
 * Robust Multiparty Computation from Threshold Encryption Based on RLWE
 * [1](https://eprint.iacr.org/2024/1285.pdf).
 *
 * This module contains the relinearization key for the l-BFV scheme, along
 * with the relinearization algorithm.
 *
 * # Concrete polynomial authority
 *
 * The shared polynomials `d1` (URS) and `a` (CRS) are verified by actual
 * coefficient comparison during aggregation, not by seed equality alone.
 * Seeds are optional compression metadata: a seed present in a KSK is
 * verified against the concrete polynomials at deserialization, and
 * contradictory encodings (seed ≠ inline c1) are rejected.
 *
 * # Bound vs. unbound construction
 *
 * [`LBFVRelinKeyShare`] constructors come in two forms:
 *
 * - **Unbound** (`contribution`, `contribution_with_polys`) — produce
 *   standalone shares without participant metadata.  These are used by the
 *   single-party [`LBFVRelinearizationKey::new`] and
 *   [`LBFVRelinearizationKey::new_leveled`] paths.
 *
 * - **Bound** (`contribution_with_binding`,
 *   `contribution_with_polys_and_binding`) — attach an
 *   [`LBFVContributionBinding`] so that distributed aggregation can enforce
 *   exact participant-set/session equality and reject duplicate or missing
 *   contributions.
 *
 * [`LBFVRelinearizationKey::aggregate`] requires bound shares; the unbound
 * single-party path is restricted to one share with no bindings.
 *
 * Participant bindings are **consistency metadata, not authentication**.
 * No signatures, broadcast protocol, or full DKG orchestration is provided.
 * See Urban–Rambaud (2024, §5) for the robust-DKG adversarial model.
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

use super::{LBFVContributionBinding, LBFVParticipantSet, LBFVPublicKey};
use crate::lbfv::crs::LBFVCommonReferenceString;

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
    /// Optional participant set for aggregated bound keys.
    participant_set: Option<LBFVParticipantSet>,
}

/// One ciphernode's additive contribution to a distributed l-BFV
/// relinearization key, following Eq. (4) of §5.2 of
/// [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
///
/// A contribution is computed from a single party's secret-key contribution
/// `sk_i` and a locally sampled ephemeral `r_i`, using the common shared
/// strings `d1` (URS) and `a` (CRS). It holds the per-node key-switching
/// material `(d0_i, d1)` and `(d2_i, a)`; the `b_vec` is not part of a
/// contribution. Please, note that it comes from the aggregated threshold
/// public key when the contributions are combined in [`LBFVRelinearizationKey::aggregate`].
///
/// Because l-BFV's relinearization-key generation is linear in the secret key,
/// the sum of the contributions over a set `S` of parties is exactly a valid
/// relinearization key for `sk = Σ_{i∈S} sk_i`, with `r = Σ_{i∈S} r_i`.
///
/// # Assumptions and current limitations
///
/// - Consistency is checked at aggregation: correctness requires every party to
///   use the *same* `d1` (URS) and `a` (CRS) seeds, and `a` must be the very
///   seed used to build the threshold public key whose `b_vec` relinearization
///   consumes. The `-a_j·sk` term in `b_vec` and the `+r·a_j·sk` term in `d2`
///   must cancel during relinearization. [`LBFVRelinearizationKey::aggregate`]
///   checks both: that the seeds/levels match across shares, and that the
///   shares' CRS `a` matches the public key's seed.
/// - Contributions, not Shamir shares: `contribution` consumes a secret-key
///   *contribution* `sk_i` (a summand of `sk = Σ sk_i`), not a Shamir share of
///   `sk`. The rlk aggregates additively over contributions, exactly like the
///   public key; it is unrelated to the `t`-of-`n` Shamir sharing used for
///   threshold decryption.
/// - Noise growth: each contribution injects its own error `(e0_i, e2_i)`,
///   so the aggregated key carries `Σ e_i` (variance ~`|S|·σ²`). The smudging /
///   noise analysis must account for this `|S|` factor).
/// - Level 0 only: only `ciphertext_level = key_level = 0` is
///   exercised/tested. The leveled path is inherited from the single-key code
///   and is currently untested for distributed keys.
///
/// The threshold public key whose `b_vec` is consumed here is itself built from
/// aggregated contributions via [`LBFVPublicKey::aggregate`](super::LBFVPublicKey::aggregate),
/// so end to end no party ever assembles `sk`: it exists only as the implicit
/// sum of the per-node `sk_i`.
///
/// Individual RLK shares are serializable via the `protobuf` feature (see
/// [`Serialize`] and [`DeserializeParametrized`] implementations).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LBFVRelinKeyShare {
    /// Per-node key-switching key from r to s: `(d0_i, d1)` where
    /// `d0_i = -sk_i·d1 + e0_i + r_i·g`.
    ksk_r_to_s: KeySwitchingKey,
    /// Per-node key-switching key from s to r: `(d2_i, a)` where
    /// `d2_i = r_i·a + e2_i + sk_i·g` (built by encrypting `sk_i` under
    /// `-r_i`, mirroring the single-key construction).
    ksk_s_to_r: KeySwitchingKey,
    /// Optional participant binding for distributed aggregation.
    binding: Option<LBFVContributionBinding>,
}

impl LBFVRelinKeyShare {
    /// Compute this party's contribution to the distributed relinearization
    /// key from its secret-key contribution `sk_i`.
    ///
    /// # Arguments
    /// * `sk_i` - This party's secret-key contribution (one summand of the
    ///   joint `sk = Σ sk_i`), *not* a Shamir share.
    /// * `d1_seed` - Seed for the common URS `d1` (must be identical across all
    ///   parties, otherwise the contributions cannot be summed).
    /// * `a_seed` - Seed for the common CRS `a` (the same `a` used by the
    ///   threshold public key's `b_vec`; must be identical across all parties).
    /// * `ciphertext_level` / `key_level` - Levels of the ciphertext to
    ///   relinearize and of the key, as in [`LBFVRelinearizationKey::new_leveled`].
    /// * `rng` - RNG used to sample the local ephemeral `r_i` and the errors.
    pub fn contribution<R: RngCore + CryptoRng>(
        sk_i: &SecretKey,
        d1_seed: <ChaCha8Rng as SeedableRng>::Seed,
        a_seed: <ChaCha8Rng as SeedableRng>::Seed,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let ctx_relin_key = sk_i.params.context_at_level(key_level)?;
        let ctx_ciphertext = sk_i.params.context_at_level(ciphertext_level)?;
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

        // Sample this node's ephemeral r_i from the key distribution. It is a
        // second secret key (like sk_i), used only as scratch to build this
        // contribution, and is toxic waste: never shared, never reused, dropped
        // (and zeroized) here. The joint ephemeral r = Σ r_i is what the
        // aggregated key effectively uses, but r is never materialized anywhere:
        // it only exists implicitly as the sum, mirroring sk = Σ sk_i.
        let r = Zeroizing::new(SecretKey::random(&sk_i.params, rng));
        let r_poly = Zeroizing::new(Poly::<PowerBasis>::try_convert_from(
            r.coeffs.as_ref(),
            ctx_ciphertext,
            false,
        )?);
        let r_switched_up = Zeroizing::new(r_poly.switch(&switcher_up)?);

        let sk_poly = Zeroizing::new(Poly::<PowerBasis>::try_convert_from(
            sk_i.coeffs.as_ref(),
            ctx_ciphertext,
            false,
        )?);
        let sk_switched_up = Zeroizing::new(sk_poly.switch(&switcher_up)?);

        // (d0_i, d1) = (-sk_i·d1 + e0_i + r_i·g, d1)
        let ksk_r_to_s = KeySwitchingKey::new_with_seed(
            sk_i,
            &r_switched_up,
            d1_seed,
            ciphertext_level,
            key_level,
            rng,
        )?;

        // (d2_i, a) = (r_i·a + e2_i + sk_i·g, a), obtained by encrypting sk_i
        // under -r_i (see the note on the single-key construction).
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

        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
            binding: None,
        })
    }

    /// Compute this party's contribution using explicit URS/CRS polynomials
    /// instead of seeds.
    ///
    /// This is the on-chain URS path: the caller provides the shared `d1` and
    /// `a` polynomials (as `NttShoup`) directly. The same `d1` and `a` must be
    /// used by all parties and must match the public key's CRS `a_j`.
    ///
    /// # Arguments
    /// * `sk_i` - This party's secret-key contribution.
    /// * `d1_polys` - The shared URS polynomials for the `(d0, d1)` key.
    /// * `a_polys` - The shared CRS polynomials; must be identical to the
    ///   polynomials embedded in the threshold public key's ciphertexts.
    /// * `ciphertext_level` / `key_level` - Levels.
    /// * `rng` - RNG for `r_i` and the errors.
    pub fn contribution_with_polys<R: RngCore + CryptoRng>(
        sk_i: &SecretKey,
        d1_polys: Vec<Poly<NttShoup>>,
        a_polys: Vec<Poly<NttShoup>>,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let ctx_relin_key = sk_i.params.context_at_level(key_level)?;
        let ctx_ciphertext = sk_i.params.context_at_level(ciphertext_level)?;
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

        let r = Zeroizing::new(SecretKey::random(&sk_i.params, rng));
        let r_poly = Zeroizing::new(Poly::<PowerBasis>::try_convert_from(
            r.coeffs.as_ref(),
            ctx_ciphertext,
            false,
        )?);
        let r_switched_up = Zeroizing::new(r_poly.switch(&switcher_up)?);

        let sk_poly = Zeroizing::new(Poly::<PowerBasis>::try_convert_from(
            sk_i.coeffs.as_ref(),
            ctx_ciphertext,
            false,
        )?);
        let sk_switched_up = Zeroizing::new(sk_poly.switch(&switcher_up)?);

        // (d0_i, d1) = (-sk_i·d1 + e0_i + r_i·g, d1)
        let ksk_r_to_s = KeySwitchingKey::new_with_c1(
            sk_i,
            &r_switched_up,
            d1_polys,
            ciphertext_level,
            key_level,
            rng,
        )?;

        // (d2_i, a) = (r_i·a + e2_i + sk_i·g, a)
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

        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
            binding: None,
        })
    }

    /// Compute this party's contribution to the distributed relinearization
    /// key with participant binding metadata.
    ///
    /// This is the bound version of [`contribution`](Self::contribution).
    pub fn contribution_with_binding<R: RngCore + CryptoRng>(
        sk_i: &SecretKey,
        d1_seed: <ChaCha8Rng as SeedableRng>::Seed,
        a_seed: <ChaCha8Rng as SeedableRng>::Seed,
        binding: LBFVContributionBinding,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let mut share =
            Self::contribution(sk_i, d1_seed, a_seed, ciphertext_level, key_level, rng)?;
        share.binding = Some(binding);
        Ok(share)
    }

    /// Compute this party's contribution using explicit URS/CRS polynomials
    /// with participant binding metadata.
    ///
    /// This is the bound version of [`contribution_with_polys`](Self::contribution_with_polys).
    pub fn contribution_with_polys_and_binding<R: RngCore + CryptoRng>(
        sk_i: &SecretKey,
        d1_polys: Vec<Poly<NttShoup>>,
        a_polys: Vec<Poly<NttShoup>>,
        binding: LBFVContributionBinding,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let mut share = Self::contribution_with_polys(
            sk_i,
            d1_polys,
            a_polys,
            ciphertext_level,
            key_level,
            rng,
        )?;
        share.binding = Some(binding);
        Ok(share)
    }

    /// Compute this party's contribution using explicit [`LBFVCommonReferenceString`]s.
    ///
    /// Preferred over [`contribution`](Self::contribution) when following the paper's
    /// protocol: both shared strings are named first-class objects, making it clear
    /// that `crs_d1` (for `d₀`) and `crs_a` (for `d₂` and the public key) are
    /// independent and agreed upon separately via coin-tossing.
    ///
    /// # Arguments
    /// * `crs_d1` — shared string for `d₁` (used in `ksk_r_to_s`, RLK `d₀`)
    /// * `crs_a`  — shared string for `a`  (used in `ksk_s_to_r`, RLK `d₂`; must
    ///              match the `crs_a` passed to [`LBFVPublicKey::new_from_crs`])
    pub fn contribution_from_crs<R: RngCore + CryptoRng>(
        sk_i: &SecretKey,
        crs_d1: &LBFVCommonReferenceString,
        crs_a: &LBFVCommonReferenceString,
        ciphertext_level: usize,
        key_level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        Self::contribution(
            sk_i,
            crs_d1.seed,
            crs_a.seed,
            ciphertext_level,
            key_level,
            rng,
        )
    }
}

/// Sum the `c0` components of a set of key-switching keys, coordinate-wise over
/// the gadget dimension.
///
/// This is the additive aggregation `Σ d0_i` / `Σ d2_i` of Eq. (4): each share's
/// secret-dependent part (`d0_i` for `ksk_r_to_s`, `d2_i` for `ksk_s_to_r`) is
/// stored as that key-switching key's `c0` component, so summing the `c0`s is
/// exactly summing the `d0_i` / `d2_i`. The shared `c1` (= `d1` / `a`) is not
/// summed — it is identical across shares and carried over by the caller.
///
/// The `c0` polynomials are stored in `NttShoup` representation. `NttShoup` is
/// the same NTT (evaluation) form as `Ntt`, but additionally carries, per
/// coefficient, a precomputed Shoup constant `floor(b·2^k / q)` that turns a
/// modular multiply by that (fixed) coefficient into a multiply-high plus a
/// conditional subtraction with no general reduction. Key material is stored this
/// way because at *use* time (`KeySwitchingKey::key_switch`) it is always the
/// fixed right-hand multiplicand, so the Shoup table is computed once at key
/// generation and amortized over every relinearization.
///
/// The flip side is that `NttShoup` intentionally has no `AddAssign`: the Shoup
/// constants are derived from the coefficient values, so summing two `NttShoup`
/// polynomials would invalidate every precomputed factor. Aggregation is a rare
/// generation-time operation, so we pay the cost here: convert each operand to
/// `Ntt` (which supports addition), sum, and rebuild the Shoup table once via
/// `into_ntt_shoup` for the cheap-multiply property to hold on the hot path.
fn sum_ksk_c0<'a>(
    ksks: impl Iterator<Item = &'a KeySwitchingKey>,
) -> Result<Box<[Poly<NttShoup>]>> {
    let mut acc: Vec<Option<Poly<Ntt>>> = Vec::new();
    for ksk in ksks {
        if acc.is_empty() {
            acc.resize_with(ksk.c0.len(), || None);
        } else if acc.len() != ksk.c0.len() {
            return Err(Error::DefaultError(
                "Relinearization key shares have mismatched gadget dimension".to_string(),
            ));
        }
        // Convert and sum in NTT.
        for (slot, c0_j) in acc.iter_mut().zip(ksk.c0.iter()) {
            let c0_j_ntt = c0_j.clone().into_ntt();
            match slot {
                Some(sum) => *sum += &c0_j_ntt,
                None => *slot = Some(c0_j_ntt),
            }
        }
    }
    if acc.is_empty() {
        return Err(Error::DefaultError(
            "Cannot sum an empty set of key-switching keys".to_string(),
        ));
    }
    // Convert again in NTTShoup.
    let out = acc
        .into_iter()
        .map(|p| {
            p.ok_or_else(|| Error::DefaultError("missing c0 component".to_string()))
                .map(Poly::<Ntt>::into_ntt_shoup)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(out.into_boxed_slice())
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
        // The single-key key is the aggregate of a single contribution. The CRS
        // `a` is the public key's seed (shared with its `b_vec`), and `d1` is the
        // provided URS seed, or a fresh one if none was given.
        let d1_seed = d1_seed.unwrap_or_else(|| {
            let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut seed);
            seed
        });

        // When the public key carries a seed we can derive both a and d1 from
        // seeds deterministically (fast seed-only path). When the public key is
        // seedless we must extract its concrete a polynomials and build explicit
        // d1 polynomials from the d1 seed.
        let share = match pk.seed {
            Some(a_seed) => LBFVRelinKeyShare::contribution(
                sk,
                d1_seed,
                a_seed,
                ciphertext_level,
                key_level,
                rng,
            )?,
            None => {
                let a_polys = pk.a_polynomials_for_level(ciphertext_level, key_level)?;
                let d1_context = pk.params.context_at_level(key_level)?;
                let d1_polys = KeySwitchingKey::c1_from_seed(d1_context, d1_seed, a_polys.len());

                LBFVRelinKeyShare::contribution_with_polys(
                    sk,
                    d1_polys,
                    a_polys,
                    ciphertext_level,
                    key_level,
                    rng,
                )?
            }
        };

        Self::aggregate_single_unbound(&[share], pk)
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
        let share = LBFVRelinKeyShare::contribution_with_polys(
            sk,
            d1_polys,
            a_polys,
            ciphertext_level,
            key_level,
            rng,
        )?;
        Self::aggregate_single_unbound(&[share], pk)
    }

    /// Aggregate per-node contributions into a distributed relinearization key,
    /// following Eq. (4) of §5.2 of
    /// [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf).
    ///
    /// The contributions are summed coordinate-wise:
    /// `rlk = (Σ d0_i, d1, Σ d2_i)`. Because l-BFV relinearization-key
    /// generation is linear in the secret key, the result is a valid
    /// relinearization key for `sk = Σ sk_i` (with `r = Σ r_i`).
    ///
    /// The `b_vec` is taken from `pk` (the aggregated threshold public key), and
    /// the CRS `a` it was built under is checked against the `a`
    /// the contributions used for their `d2` (`ksk_s_to_r`'s c1). This closes
    /// the consistency loop: the `-a_j·sk` term in `b_vec` and the `+r·a_j·sk`
    /// term in `d2` only cancel during relinearization if both use the same `a`.
    ///
    /// Every share must carry an [`LBFVContributionBinding`] metadata created
    /// with the same [`LBFVParticipantSet`]. All participant IDs in the set
    /// must appear exactly once (no duplicates, no missing IDs), and all
    /// shares must share the same concrete d1 and a polynomials. The resulting
    /// key carries the participant set.
    ///
    /// # Arguments
    /// * `shares` - The contributions from the participating parties. They must
    ///   all share the same `d1`/`a` polynomials and levels, and each must be
    ///   bound to the same participant set.
    /// * `pk` - The aggregated threshold public key (e.g. from
    ///   [`LBFVPublicKey::aggregate`](super::LBFVPublicKey::aggregate)). It must
    ///   have been built under the same CRS `a` as the contributions, and
    ///   it supplies the `b_vec` used in relinearization.
    ///
    /// # Errors
    /// Returns an error if `shares` is empty, if the shares disagree on their
    /// d1/a polynomials or levels, if participant bindings are missing or
    /// inconsistent, or if the CRS `a` does not match the public key.
    pub fn aggregate(shares: &[LBFVRelinKeyShare], pk: &LBFVPublicKey) -> Result<Self> {
        Self::aggregate_internal(shares, pk, true)
    }

    /// Internal aggregation with an optional participant-binding requirement.
    ///
    /// When `require_binding` is true, every share must carry a valid
    /// contribution binding for the same participant set as the public key,
    /// and the public key must be an aggregated bound key. The resulting RLK
    /// carries the participant set.
    ///
    /// When `require_binding` is false (single-party standalone use), only
    /// one unbound share is allowed, the public key must not carry a binding,
    /// and no share may have a binding.
    fn aggregate_internal(
        shares: &[LBFVRelinKeyShare],
        pk: &LBFVPublicKey,
        require_binding: bool,
    ) -> Result<Self> {
        let (first, rest) = shares.split_first().ok_or_else(|| {
            Error::DefaultError("Cannot aggregate zero relinearization key shares".to_string())
        })?;

        // --- Full structural validation of the public key before any field
        //     access (Fix 1: validate pk structure, l, contexts, ciphertexts) ---
        pk.validate_structure()?;

        // --- Structural validation of every share's KSKs ---
        for (i, share) in shares.iter().enumerate() {
            // ---------- ksk_r_to_s validation ----------
            if share.ksk_r_to_s.params != first.ksk_r_to_s.params {
                return Err(Error::DefaultError(format!(
                    "Relinearization key share {i} has different r->s parameters"
                )));
            }
            // Validate that KSK parameters match the public key parameters
            if i == 0 && share.ksk_r_to_s.params != pk.params {
                return Err(Error::DefaultError(
                    "Relinearization key share parameters do not match public key parameters"
                        .to_string(),
                ));
            }
            if share.ksk_r_to_s.c0.len() != share.ksk_r_to_s.c1.len()
                || share.ksk_s_to_r.c0.len() != share.ksk_s_to_r.c1.len()
            {
                return Err(Error::DefaultError(format!(
                    "Relinearization key share {i} has mismatched c0/c1 dimensions"
                )));
            }
            if share.ksk_r_to_s.ciphertext_level != first.ksk_r_to_s.ciphertext_level
                || share.ksk_r_to_s.ksk_level != first.ksk_r_to_s.ksk_level
            {
                return Err(Error::DefaultError(
                    "Relinearization key shares are inconsistent (differing r->s levels)"
                        .to_string(),
                ));
            }
            if share.ksk_r_to_s.ctx_ciphertext != first.ksk_r_to_s.ctx_ciphertext
                || share.ksk_r_to_s.ctx_ksk != first.ksk_r_to_s.ctx_ksk
            {
                return Err(Error::DefaultError(
                    "Relinearization key shares are inconsistent (differing r->s contexts)"
                        .to_string(),
                ));
            }

            // ---------- ksk_s_to_r validation ----------
            if share.ksk_s_to_r.params != first.ksk_s_to_r.params {
                return Err(Error::DefaultError(format!(
                    "Relinearization key share {i} has different s->r parameters"
                )));
            }
            if share.ksk_s_to_r.ciphertext_level != first.ksk_s_to_r.ciphertext_level
                || share.ksk_s_to_r.ksk_level != first.ksk_s_to_r.ksk_level
            {
                return Err(Error::DefaultError(
                    "Relinearization key shares are inconsistent (differing s->r levels)"
                        .to_string(),
                ));
            }
            if share.ksk_s_to_r.ctx_ciphertext != first.ksk_s_to_r.ctx_ciphertext
                || share.ksk_s_to_r.ctx_ksk != first.ksk_s_to_r.ctx_ksk
            {
                return Err(Error::DefaultError(
                    "Relinearization key shares are inconsistent (differing s->r contexts)"
                        .to_string(),
                ));
            }
            if share.ksk_s_to_r.log_base != first.ksk_s_to_r.log_base {
                return Err(Error::DefaultError(format!(
                    "Relinearization key share {i} has inconsistent s->r log_base"
                )));
            }

            // Cross-validate that r->s and s->r dimensions match within each share
            if share.ksk_r_to_s.c0.len() != share.ksk_s_to_r.c0.len() {
                return Err(Error::DefaultError(format!(
                    "Relinearization key share {i} has mismatched r->s/s->r c0 dimensions"
                )));
            }

            // --- Cross-KSK consistency: every share's ksk_r_to_s and ksk_s_to_r
            //     must share the same parameters, levels, contexts, and log_base.
            //     A malformed share with internally inconsistent KSKs would
            //     produce a corrupted aggregate. ---
            if share.ksk_r_to_s.params != share.ksk_s_to_r.params {
                return Err(Error::DefaultError(format!(
                    "Relinearization key share {i} has mismatched r->s/s->r parameters"
                )));
            }
            if share.ksk_r_to_s.ciphertext_level != share.ksk_s_to_r.ciphertext_level {
                return Err(Error::DefaultError(format!(
                    "Relinearization key share {i} has mismatched r->s/s->r ciphertext levels"
                )));
            }
            if share.ksk_r_to_s.ksk_level != share.ksk_s_to_r.ksk_level {
                return Err(Error::DefaultError(format!(
                    "Relinearization key share {i} has mismatched r->s/s->r key levels"
                )));
            }
            if share.ksk_r_to_s.ctx_ciphertext != share.ksk_s_to_r.ctx_ciphertext {
                return Err(Error::DefaultError(format!(
                    "Relinearization key share {i} has mismatched r->s/s->r ciphertext contexts"
                )));
            }
            if share.ksk_r_to_s.ctx_ksk != share.ksk_s_to_r.ctx_ksk {
                return Err(Error::DefaultError(format!(
                    "Relinearization key share {i} has mismatched r->s/s->r key contexts"
                )));
            }
            if share.ksk_r_to_s.log_base != share.ksk_s_to_r.log_base {
                return Err(Error::DefaultError(format!(
                    "Relinearization key share {i} has mismatched r->s/s->r log_base"
                )));
            }
        }

        // --- Participant-binding validation ---
        let participant_set = if require_binding {
            let pk_set = pk.aggregate_binding()?.clone();
            let bindings = shares
                .iter()
                .map(|share| {
                    share.binding.as_ref().ok_or_else(|| {
                        Error::DefaultError(
                            "LBFV RLK share is missing participant binding".to_string(),
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            pk_set.validate_contributions(bindings.iter().copied())?;
            Some(pk_set)
        } else {
            // Standalone (unbound) path: restricted to one single share with no
            // binding on either side.
            if shares.len() != 1 || pk.binding.is_some() {
                return Err(Error::DefaultError(
                    "Unbound l-BFV aggregation is restricted to one standalone share".to_string(),
                ));
            }
            if shares
                .first()
                .and_then(|share| share.binding.as_ref())
                .is_some()
            {
                return Err(Error::DefaultError(
                    "Standalone l-BFV aggregation cannot contain bound shares".to_string(),
                ));
            }
            None
        };

        // --- Verify the concrete d1 (URS) polynomials match across all shares ---
        // Concrete polynomials are authoritative. Seeds are optional compression
        // metadata (Fix 3): we validate the actual polynomial content, not seed
        // equality. Mixed seeded/explicit shares with identical concrete d1/a
        // are accepted.
        for s in rest {
            if s.ksk_r_to_s.c1 != first.ksk_r_to_s.c1 {
                return Err(Error::DefaultError(
                    "Relinearization key shares have inconsistent d1 (URS) polynomials".to_string(),
                ));
            }
        }

        // --- Verify the concrete a (CRS) polynomials match across all shares ---
        for s in rest {
            if s.ksk_s_to_r.c1 != first.ksk_s_to_r.c1 {
                return Err(Error::DefaultError(
                    "Relinearization key shares have inconsistent a (CRS) polynomials".to_string(),
                ));
            }
        }

        // --- Determine whether all input KSKs share the same seeds; if not,
        //     the aggregate output must not carry an incorrect seed ---
        let seeds_match = shares
            .iter()
            .all(|s| s.ksk_r_to_s.seed == first.ksk_r_to_s.seed)
            && shares
                .iter()
                .all(|s| s.ksk_s_to_r.seed == first.ksk_s_to_r.seed);

        // --- CRS binding: the a polynomials in ksk_s_to_r.c1 must match the
        //     public key's a_j ciphertext polynomials ---
        //
        // For leveled keys the KSK has l - ciphertext_level polynomials; we
        // compare each against the PK's first l - ciphertext_level ciphertexts.
        let pk_ctx0 = pk.params.context_at_level(0)?;
        let ksk_ctx = &first.ksk_s_to_r.ctx_ksk;
        if ksk_ctx != pk_ctx0 {
            return Err(Error::DefaultError(
                "Cannot verify CRS binding: RLK key context differs from public key level-0 context"
                    .to_string(),
            ));
        }
        let new_l =
            pk.l.checked_sub(first.ksk_r_to_s.ciphertext_level)
                .ok_or_else(|| {
                    Error::DefaultError(
                        "CRS binding failed: ciphertext_level exceeds public-key l".to_string(),
                    )
                })?;
        if first.ksk_s_to_r.c1.len() != new_l {
            return Err(Error::DefaultError(
                "CRS binding failed: RLK's a polynomial count does not match expected l - ciphertext_level"
                    .to_string(),
            ));
        }
        for (j, c1_j) in first.ksk_s_to_r.c1.iter().enumerate() {
            let mut a_ksk: Poly<Ntt> = c1_j.clone().into_ntt();
            a_ksk.disallow_variable_time_computations();
            let pk_a_j = pk.c.get(j).and_then(|ct| ct.c.get(1)).ok_or_else(|| {
                Error::DefaultError("Public key is missing its a_j polynomial".to_string())
            })?;
            if a_ksk != *pk_a_j {
                return Err(Error::DefaultError(
                    "CRS binding failed: RLK's a_j does not match public key's a_j".to_string(),
                ));
            }
        }

        // --- Levels are defined by the shares; b_vec is extracted from the public
        //     key at those levels ---
        let ciphertext_level = first.ksk_r_to_s.ciphertext_level;
        let key_level = first.ksk_r_to_s.ksk_level;
        let b_vec =
            pk.extract_b_polynomials(ciphertext_level, key_level, Representation::NttShoup)?;

        // --- Clone the first share as template (shared c1 = d1/a and metadata),
        //     then overwrite c0 with summed d0/d2 ---
        //
        // Summing the c0 components adds up the per-node secrets together: both
        // the real key sk_i and the ephemeral r_i are additive across nodes, so
        //   Σ d0_i = -(Σ sk_i)·d1 + Σ e0_i + (Σ r_i)·g = -sk·d1 + e0 + r·g
        //   Σ d2_i =  (Σ r_i)·a   + Σ e2_i + (Σ sk_i)·g =  r·a   + e2 + sk·g
        // with sk = Σ sk_i and r = Σ r_i. The shared c1 (= d1 / a) is identical
        // in every share, so it is carried over unchanged from the template. The
        // result is exactly a single-key rlk for the joint sk, with neither sk
        // nor r ever assembled in one place.
        let mut ksk_r_to_s = first.ksk_r_to_s.clone();
        ksk_r_to_s.c0 = sum_ksk_c0(shares.iter().map(|s| &s.ksk_r_to_s))?;

        let mut ksk_s_to_r = first.ksk_s_to_r.clone();
        ksk_s_to_r.c0 = sum_ksk_c0(shares.iter().map(|s| &s.ksk_s_to_r))?;

        // Fix 3: Strips the seed from the aggregate output when input shares
        // had different seeds (or a mix of seeded/explicit). A seed stored in
        // the aggregate would otherwise be incorrect for shares that didn't
        // use it.
        if !seeds_match {
            ksk_r_to_s.seed = None;
            ksk_s_to_r.seed = None;
        }

        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
            b_vec,
            participant_set,
        })
    }

    /// Aggregate a single unbound share for standalone (non-distributed) use.
    ///
    /// This is the private path used by [`new_leveled`](Self::new_leveled) and
    /// [`new`](Self::new). It requires exactly one share with no participant
    /// bindings on either the share or the public key.
    fn aggregate_single_unbound(shares: &[LBFVRelinKeyShare], pk: &LBFVPublicKey) -> Result<Self> {
        Self::aggregate_internal(shares, pk, false)
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

            let poly_i = unsafe {
                Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                    poly_i_coefficients.as_slice().ok_or_else(|| {
                        Error::DefaultError(
                            "Non-contiguous coefficient array in decompose_poly_and_product_sum"
                                .to_string(),
                        )
                    })?,
                    &ksk_ctx,
                )
            };
            out += &(&poly_i * arr_i);
        }
        Ok(out)
    }
}

/// Associates the [`LBFVRelinearizationKey`] with BFV parameters
impl FheParametrized for LBFVRelinearizationKey {
    type Parameters = BfvParameters;
}

/// Associates the [`LBFVRelinKeyShare`] with BFV parameters
impl FheParametrized for LBFVRelinKeyShare {
    type Parameters = BfvParameters;
}

#[cfg(feature = "protobuf")]
mod protobuf {
    use super::*;
    use crate::bfv::traits::TryConvertFrom;
    use crate::proto::bfv::{
        KeySwitchingKey as KeySwitchingKeyProto, LbfvRelinKeyShare as LBFVRelinKeyShareProto,
        LbfvRelinearizationKey as LBFVRelinearizationKeyProto,
    };
    use fhe_traits::{DeserializeParametrized, DeserializeWithContext, Serialize};
    use prost::Message;

    impl From<&LBFVRelinearizationKey> for LBFVRelinearizationKeyProto {
        fn from(value: &LBFVRelinearizationKey) -> Self {
            let mut rk = LBFVRelinearizationKeyProto {
                ksk_r_to_s: Some(KeySwitchingKeyProto::from(&value.ksk_r_to_s)),
                ksk_s_to_r: Some(KeySwitchingKeyProto::from(&value.ksk_s_to_r)),
                b_vec: value.b_vec.iter().map(|p| p.to_bytes()).collect(),
                binding: None,
            };
            if let Some(ref set) = value.participant_set {
                use super::super::binding::LBFVKeyBinding;
                rk.binding = Some(
                    crate::lbfv::keys::binding::proto_helpers::key_binding_to_proto(
                        &LBFVKeyBinding::Aggregate(set.clone()),
                    ),
                );
            }
            rk
        }
    }

    impl TryConvertFrom<&LBFVRelinearizationKeyProto> for LBFVRelinearizationKey {
        fn try_convert_from(
            value: &LBFVRelinearizationKeyProto,
            par: &Arc<BfvParameters>,
        ) -> Result<Self> {
            let ksk_r_to_s = value
                .ksk_r_to_s
                .as_ref()
                .ok_or_else(|| {
                    Error::DefaultError("Invalid serialization: missing ksk_r_to_s".to_string())
                })
                .and_then(|ksk| KeySwitchingKey::try_convert_from(ksk, par))?;
            let ksk_s_to_r = value
                .ksk_s_to_r
                .as_ref()
                .ok_or_else(|| {
                    Error::DefaultError("Invalid serialization: missing ksk_s_to_r".to_string())
                })
                .and_then(|ksk| KeySwitchingKey::try_convert_from(ksk, par))?;

            // --- Cross-KSK structural validation ---
            // Both KSKs must share consistent parameters, levels, contexts, and
            // dimensions. Validating only ksk_r_to_s leaves ksk_s_to_r unchecked.
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
            // b_vec must have l - ciphertext_level elements, each at the key context.
            let expected_b_vec_len = par
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

            // Decode binding if present. Accept absent binding for backward
            // compatibility with old unbound standalone RLKs. A contribution
            // binding must be rejected — it belongs on RLK shares, never on
            // the final aggregated key.
            let participant_set = {
                let binding_opt =
                    crate::lbfv::keys::binding::proto_helpers::key_binding_from_proto(
                        value.binding.as_ref(),
                    )?;
                match binding_opt {
                    None => None,
                    Some(crate::lbfv::keys::binding::LBFVKeyBinding::Contribution(_)) => {
                        return Err(Error::SerializationError(
                            crate::SerializationError::InvalidFormat {
                                reason:
                                    "LBFV RLK carries a Contribution binding; expected Aggregate or absent"
                                        .to_string(),
                            },
                        ));
                    }
                    Some(crate::lbfv::keys::binding::LBFVKeyBinding::Aggregate(set)) => Some(set),
                }
            };

            Ok(LBFVRelinearizationKey {
                ksk_r_to_s,
                ksk_s_to_r,
                b_vec,
                participant_set,
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

        fn from_bytes(bytes: &[u8], par: &Arc<Self::Parameters>) -> Result<Self> {
            let rk = Message::decode(bytes).map_err(|e| {
                Error::SerializationError(crate::SerializationError::ProtobufError {
                    message: e.to_string(),
                })
            })?;
            LBFVRelinearizationKey::try_convert_from(&rk, par)
        }
    }

    // --- LBFVRelinKeyShare protobuf serialization ---

    impl From<&LBFVRelinKeyShare> for LBFVRelinKeyShareProto {
        fn from(share: &LBFVRelinKeyShare) -> Self {
            LBFVRelinKeyShareProto {
                ksk_r_to_s: Some(KeySwitchingKeyProto::from(&share.ksk_r_to_s)),
                ksk_s_to_r: Some(KeySwitchingKeyProto::from(&share.ksk_s_to_r)),
                binding: share.binding.as_ref().map(|b| {
                    crate::lbfv::keys::binding::proto_helpers::contribution_binding_to_proto(b)
                }),
            }
        }
    }

    impl TryConvertFrom<&LBFVRelinKeyShareProto> for LBFVRelinKeyShare {
        fn try_convert_from(
            value: &LBFVRelinKeyShareProto,
            par: &Arc<BfvParameters>,
        ) -> Result<Self> {
            let ksk_r_to_s = value
                .ksk_r_to_s
                .as_ref()
                .ok_or_else(|| {
                    Error::DefaultError(
                        "Invalid serialization: missing ksk_r_to_s in RLK share".to_string(),
                    )
                })
                .and_then(|ksk| KeySwitchingKey::try_convert_from(ksk, par))?;
            let ksk_s_to_r = value
                .ksk_s_to_r
                .as_ref()
                .ok_or_else(|| {
                    Error::DefaultError(
                        "Invalid serialization: missing ksk_s_to_r in RLK share".to_string(),
                    )
                })
                .and_then(|ksk| KeySwitchingKey::try_convert_from(ksk, par))?;

            // --- Cross-KSK structural validation ---
            if ksk_s_to_r.params != ksk_r_to_s.params {
                return Err(Error::DefaultError(
                    "RLK share KSKs have mismatched parameters".to_string(),
                ));
            }
            if ksk_s_to_r.ciphertext_level != ksk_r_to_s.ciphertext_level {
                return Err(Error::DefaultError(
                    "RLK share KSKs have mismatched ciphertext levels".to_string(),
                ));
            }
            if ksk_s_to_r.ksk_level != ksk_r_to_s.ksk_level {
                return Err(Error::DefaultError(
                    "RLK share KSKs have mismatched key levels".to_string(),
                ));
            }
            if ksk_s_to_r.ctx_ciphertext != ksk_r_to_s.ctx_ciphertext {
                return Err(Error::DefaultError(
                    "RLK share KSKs have mismatched ciphertext contexts".to_string(),
                ));
            }
            if ksk_s_to_r.ctx_ksk != ksk_r_to_s.ctx_ksk {
                return Err(Error::DefaultError(
                    "RLK share KSKs have mismatched key contexts".to_string(),
                ));
            }
            if ksk_s_to_r.log_base != ksk_r_to_s.log_base {
                return Err(Error::DefaultError(
                    "RLK share KSKs have mismatched log_base".to_string(),
                ));
            }

            // Validate share dimensions
            if ksk_r_to_s.c0.len() != ksk_r_to_s.c1.len()
                || ksk_s_to_r.c0.len() != ksk_s_to_r.c1.len()
            {
                return Err(Error::DefaultError(
                    "RLK share has mismatched c0/c1 dimensions".to_string(),
                ));
            }

            // Decode contribution binding (reject aggregate bindings)
            let binding =
                crate::lbfv::keys::binding::proto_helpers::contribution_binding_from_proto(
                    value.binding.as_ref(),
                )?;

            Ok(LBFVRelinKeyShare {
                ksk_r_to_s,
                ksk_s_to_r,
                binding,
            })
        }
    }

    impl Serialize for LBFVRelinKeyShare {
        fn to_bytes(&self) -> Vec<u8> {
            LBFVRelinKeyShareProto::from(self).encode_to_vec()
        }
    }

    impl DeserializeParametrized for LBFVRelinKeyShare {
        type Error = Error;

        fn from_bytes(bytes: &[u8], par: &Arc<Self::Parameters>) -> Result<Self> {
            let share = LBFVRelinKeyShareProto::decode(bytes).map_err(|e| {
                Error::SerializationError(crate::SerializationError::ProtobufError {
                    message: e.to_string(),
                })
            })?;
            LBFVRelinKeyShare::try_convert_from(&share, par)
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::bfv::{Encoding, Plaintext};
    use crate::lbfv::{LBFVContributionBinding, LBFVParticipantSet};
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::rng;
    use std::error::Error;
    use std::result::Result;

    #[cfg(feature = "protobuf")]
    mod protobuf {
        use super::*;
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
        fn relin_share_serializes_binding_and_key_material()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let set = LBFVParticipantSet::new([71u8; 32], vec![1])?;
            let binding = LBFVContributionBinding::new(set, 1)?;

            let share = LBFVRelinKeyShare::contribution_with_binding(
                &sk, [72u8; 32], [73u8; 32], binding, 0, 0, &mut rng,
            )?;

            let decoded = LBFVRelinKeyShare::from_bytes(&share.to_bytes(), &params)?;
            assert_eq!(decoded, share);
            Ok(())
        }

        /// A bound RLK share built from explicit inline `d1`/`a` polynomials
        /// (the on-chain URS path, no seeds) must round-trip identically.
        #[test]
        fn explicit_polys_share_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);

            let mut a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut a_seed);
            let a_polys_shoup: Vec<Poly<NttShoup>> = {
                let tmp = LBFVPublicKey::new_with_seed(&sk, a_seed, &mut rng)?;
                tmp.c
                    .iter()
                    .map(|ct| ct.c[1].clone().into_ntt_shoup())
                    .collect()
            };
            let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut d1_seed);
            let d1_polys: Vec<Poly<NttShoup>> = {
                let ksk_tmp = KeySwitchingKey::new_with_seed(
                    &sk,
                    &Poly::<PowerBasis>::try_convert_from(
                        sk.coeffs.as_ref(),
                        params.context_at_level(0)?,
                        false,
                    )?,
                    d1_seed,
                    0,
                    0,
                    &mut rng,
                )?;
                ksk_tmp.c1.to_vec()
            };

            let set = LBFVParticipantSet::new([90u8; 32], vec![1, 2])?;
            let binding = LBFVContributionBinding::new(set, 1)?;
            let share = LBFVRelinKeyShare::contribution_with_polys_and_binding(
                &sk,
                d1_polys,
                a_polys_shoup,
                binding,
                0,
                0,
                &mut rng,
            )?;

            let decoded = LBFVRelinKeyShare::from_bytes(&share.to_bytes(), &params)?;
            assert_eq!(decoded, share);
            Ok(())
        }

        /// Malformed binding metadata carried by a serialized RLK *share* must be
        /// rejected: bad session length, duplicate IDs, empty set, and an
        /// aggregate binding (shares only ever carry contribution bindings).
        #[test]
        fn rlk_share_rejects_malformed_binding() -> Result<(), Box<dyn std::error::Error>> {
            use crate::proto::bfv::LbfvRelinKeyShare as LBFVRelinKeyShareProto;
            use prost::Message;

            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let set = LBFVParticipantSet::new([91u8; 32], vec![1, 2])?;
            let binding = LBFVContributionBinding::new(set, 1)?;
            let share = LBFVRelinKeyShare::contribution_with_binding(
                &sk, [92u8; 32], [93u8; 32], binding, 0, 0, &mut rng,
            )?;

            // Wrong session_id length.
            let mut p = LBFVRelinKeyShareProto::from(&share);
            p.binding.as_mut().unwrap().session_id = vec![0u8; 31];
            assert!(
                LBFVRelinKeyShare::from_bytes(&p.encode_to_vec(), &params).is_err(),
                "31-byte session_id must be rejected"
            );

            // Duplicate participant IDs.
            let mut p = LBFVRelinKeyShareProto::from(&share);
            p.binding.as_mut().unwrap().participant_ids = vec![1, 1];
            assert!(
                LBFVRelinKeyShare::from_bytes(&p.encode_to_vec(), &params).is_err(),
                "duplicate participant IDs must be rejected"
            );

            // Empty participant set.
            let mut p = LBFVRelinKeyShareProto::from(&share);
            p.binding.as_mut().unwrap().participant_ids = vec![];
            assert!(
                LBFVRelinKeyShare::from_bytes(&p.encode_to_vec(), &params).is_err(),
                "empty participant set must be rejected"
            );

            // Aggregate binding must be rejected on a share.
            let mut p = LBFVRelinKeyShareProto::from(&share);
            {
                let b = p.binding.as_mut().unwrap();
                b.aggregate = true;
                b.participant_id = 0;
            }
            assert!(
                LBFVRelinKeyShare::from_bytes(&p.encode_to_vec(), &params).is_err(),
                "aggregate binding on an RLK share must be rejected"
            );

            Ok(())
        }

        /// Serializing every RLK share, then deserializing them in a shuffled
        /// order, must still aggregate to a functionally correct key — the
        /// aggregation is additive and order-independent.
        #[test]
        fn shuffled_shares_after_serialization_aggregate() -> Result<(), Box<dyn std::error::Error>>
        {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let n = 3;
            let set = LBFVParticipantSet::new([94u8; 32], (1..=n as u32).collect())?;

            let sk_shares: Vec<SecretKey> = (0..n)
                .map(|_| SecretKey::random(&params, &mut rng))
                .collect();
            let mut sum_coeffs = vec![0i64; params.degree()];
            for sk in &sk_shares {
                for (acc, c) in sum_coeffs.iter_mut().zip(sk.coeffs.iter()) {
                    *acc = acc.wrapping_add(*c);
                }
            }
            let sk_joint = SecretKey::new(sum_coeffs, &params);

            let mut a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut a_seed);
            let pk_contributions: Vec<LBFVPublicKey> = sk_shares
                .iter()
                .enumerate()
                .map(|(i, sk_i)| {
                    let binding = LBFVContributionBinding::new(set.clone(), (i + 1) as u32)?;
                    LBFVPublicKey::new_with_seed_and_binding(sk_i, a_seed, binding, &mut rng)
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let pk = LBFVPublicKey::aggregate(&pk_contributions)?;

            let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut d1_seed);
            let shares: Vec<LBFVRelinKeyShare> = sk_shares
                .iter()
                .enumerate()
                .map(|(i, sk_i)| {
                    let binding = LBFVContributionBinding::new(set.clone(), (i + 1) as u32)?;
                    LBFVRelinKeyShare::contribution_with_binding(
                        sk_i, d1_seed, a_seed, binding, 0, 0, &mut rng,
                    )
                })
                .collect::<std::result::Result<_, _>>()?;

            // Round-trip every share through serialization, then reverse the order.
            let mut deserialized: Vec<LBFVRelinKeyShare> = shares
                .iter()
                .map(|s| LBFVRelinKeyShare::from_bytes(&s.to_bytes(), &params))
                .collect::<std::result::Result<_, _>>()?;
            deserialized.reverse();

            let relin_key = LBFVRelinearizationKey::aggregate(&deserialized, &pk)?;

            let pt1 = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;
            let pt2 = Plaintext::try_encode(&[5u64], Encoding::poly(), &params)?;
            let ct1 = pk.try_encrypt(&pt1, &mut rng)?;
            let ct2 = pk.try_encrypt(&pt2, &mut rng)?;
            let mut ct_product = &ct1 * &ct2;
            relin_key.relinearizes(&mut ct_product)?;
            let result =
                Vec::<u64>::try_decode(&sk_joint.try_decrypt(&ct_product)?, Encoding::poly())?;
            assert_eq!(result[0], 15);

            Ok(())
        }

        #[test]
        fn bound_rlk_roundtrip_preserves_aggregate_binding()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let n = 3;
            let set = LBFVParticipantSet::new([74u8; 32], (1..=n as u32).collect())?;

            let sk_shares: Vec<SecretKey> = (0..n)
                .map(|_| SecretKey::random(&params, &mut rng))
                .collect();

            let mut a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut a_seed);
            let pk_contributions: Vec<LBFVPublicKey> = sk_shares
                .iter()
                .enumerate()
                .map(|(i, sk_i)| {
                    let binding = LBFVContributionBinding::new(set.clone(), (i + 1) as u32)?;
                    LBFVPublicKey::new_with_seed_and_binding(sk_i, a_seed, binding, &mut rng)
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let pk = LBFVPublicKey::aggregate(&pk_contributions)?;

            let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut d1_seed);
            let shares: Vec<LBFVRelinKeyShare> = sk_shares
                .iter()
                .enumerate()
                .map(|(i, sk_i)| {
                    let binding = LBFVContributionBinding::new(set.clone(), (i + 1) as u32)?;
                    LBFVRelinKeyShare::contribution_with_binding(
                        sk_i, d1_seed, a_seed, binding, 0, 0, &mut rng,
                    )
                })
                .collect::<std::result::Result<_, _>>()?;
            let relin_key = LBFVRelinearizationKey::aggregate(&shares, &pk)?;

            let bytes = relin_key.to_bytes();
            let decoded = LBFVRelinearizationKey::from_bytes(&bytes, &params)?;

            // Verify the binding was preserved
            assert_eq!(decoded.participant_set.as_ref(), Some(&set));

            // Old unbound format (no binding) must still be accepted
            let mut old_format_pk = pk.clone();
            old_format_pk.binding = None;
            let unbound_rlk = LBFVRelinearizationKey::new(
                &SecretKey::random(&params, &mut rng),
                &old_format_pk,
                None,
                &mut rng,
            )?;
            let old_bytes = unbound_rlk.to_bytes();
            let decoded_old = LBFVRelinearizationKey::from_bytes(&old_bytes, &params)?;
            assert!(decoded_old.participant_set.is_none());

            Ok(())
        }

        /// An RLK carrying a Contribution binding (instead of an Aggregate
        /// binding) must be rejected at deserialization time, not silently
        /// converted to `None`. Contribution bindings belong on RLK *shares*,
        /// never on the final aggregated key.
        #[test]
        fn rlk_deserialization_rejects_contribution_binding()
        -> Result<(), Box<dyn std::error::Error>> {
            use crate::proto::bfv::{
                LbfvBinding, LbfvRelinearizationKey as LBFVRelinearizationKeyProto,
            };
            use prost::Message;

            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let pk = LBFVPublicKey::new(&sk, &mut rng)?;
            let rlk = LBFVRelinearizationKey::new(&sk, &pk, None, &mut rng)?;

            // Serialize the valid RLK to proto, then inject a Contribution binding.
            let mut proto: LBFVRelinearizationKeyProto = LBFVRelinearizationKeyProto::from(&rlk);
            proto.binding = Some(LbfvBinding {
                session_id: vec![0u8; 32],
                participant_ids: vec![1, 2, 3],
                participant_id: 1,
                aggregate: false, // Contribution, not Aggregate
            });

            let bytes = proto.encode_to_vec();
            let result = LBFVRelinearizationKey::from_bytes(&bytes, &params);
            assert!(
                result.is_err(),
                "RLK deserialization must reject a Contribution binding"
            );

            Ok(())
        }

        /// A serialized RLK with reversed KSK levels (ciphertext_level <
        /// ksk_level) must be rejected.
        #[test]
        fn rlk_deserialization_rejects_reversed_levels() -> Result<(), Box<dyn std::error::Error>> {
            use crate::proto::bfv::LbfvRelinearizationKey as LBFVRelinearizationKeyProto;
            use prost::Message;

            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let pk = LBFVPublicKey::new(&sk, &mut rng)?;
            let rlk = LBFVRelinearizationKey::new(&sk, &pk, None, &mut rng)?;

            // Serialize the valid RLK to proto, then set ksk_level > ciphertext_level
            // in ksk_r_to_s to create a reversed-level KSK.
            let mut proto: LBFVRelinearizationKeyProto = LBFVRelinearizationKeyProto::from(&rlk);
            if let Some(ref mut ksk) = proto.ksk_r_to_s {
                // Ensure ksk_level > ciphertext_level to trigger the rejection.
                ksk.ksk_level = 1;
                ksk.ciphertext_level = 0;
            }

            let bytes = proto.encode_to_vec();
            assert!(
                LBFVRelinearizationKey::from_bytes(&bytes, &params).is_err(),
                "RLK deserialization must reject reversed KSK levels"
            );

            Ok(())
        }

        /// A serialized RLK whose two KSKs have mismatched contexts must be
        /// rejected — validating only ksk_r_to_s is insufficient.
        #[test]
        fn rlk_deserialization_rejects_mismatched_ksk_contexts()
        -> Result<(), Box<dyn std::error::Error>> {
            use crate::proto::bfv::LbfvRelinearizationKey as LBFVRelinearizationKeyProto;
            use prost::Message;

            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let pk = LBFVPublicKey::new(&sk, &mut rng)?;
            let rlk = LBFVRelinearizationKey::new(&sk, &pk, None, &mut rng)?;

            let mut proto: LBFVRelinearizationKeyProto = LBFVRelinearizationKeyProto::from(&rlk);
            // Give ksk_s_to_r a different ksk_level than ksk_r_to_s.
            if let Some(ref mut ksk) = proto.ksk_s_to_r {
                ksk.ksk_level = (ksk.ksk_level + 1).min(params.max_level() as u32);
            }

            let bytes = proto.encode_to_vec();
            assert!(
                LBFVRelinearizationKey::from_bytes(&bytes, &params).is_err(),
                "RLK deserialization must reject mismatched KSK contexts"
            );

            Ok(())
        }

        /// A serialized RLK with an invalid b_vec length must be rejected.
        #[test]
        fn rlk_deserialization_rejects_invalid_b_vec() -> Result<(), Box<dyn std::error::Error>> {
            use crate::proto::bfv::LbfvRelinearizationKey as LBFVRelinearizationKeyProto;
            use prost::Message;

            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let pk = LBFVPublicKey::new(&sk, &mut rng)?;
            let rlk = LBFVRelinearizationKey::new(&sk, &pk, None, &mut rng)?;

            // b_vec too short (truncate).
            let mut proto: LBFVRelinearizationKeyProto = LBFVRelinearizationKeyProto::from(&rlk);
            proto.b_vec.pop();
            let bytes = proto.encode_to_vec();
            assert!(
                LBFVRelinearizationKey::from_bytes(&bytes, &params).is_err(),
                "RLK deserialization must reject truncated b_vec"
            );

            // b_vec too long (append a copy of the first entry).
            let mut proto2: LBFVRelinearizationKeyProto = LBFVRelinearizationKeyProto::from(&rlk);
            if let Some(first) = proto2.b_vec.first().cloned() {
                proto2.b_vec.push(first);
            }
            let bytes2 = proto2.encode_to_vec();
            assert!(
                LBFVRelinearizationKey::from_bytes(&bytes2, &params).is_err(),
                "RLK deserialization must reject overlong b_vec"
            );

            Ok(())
        }
    }

    #[test]
    fn test_distributed_relinearization() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);

        // n parties, each with its own secret-key contribution sk_i.
        let n = 3;
        let sk_shares: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        // The joint secret key sk = Σ sk_i, held by nobody in the real protocol
        // but assembled here to build the public key and to decrypt.
        let mut sum_coeffs = vec![0i64; params.degree()];
        for sk in &sk_shares {
            for (acc, c) in sum_coeffs.iter_mut().zip(sk.coeffs.iter()) {
                *acc = acc.wrapping_add(*c);
            }
        }
        let sk_joint = SecretKey::new(sum_coeffs, &params);

        // Participant set and bindings for distributed key generation.
        let participant_set = LBFVParticipantSet::new([15u8; 32], (1..=n as u32).collect())?;

        // Threshold public key built by aggregating per-node contributions
        // (F2) — sk_joint is NOT used to construct it. All contributions share
        // the CRS seed `a_seed`, which the rlk's d2 must reuse.
        let mut a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut a_seed);
        let pk_contributions: Vec<LBFVPublicKey> = sk_shares
            .iter()
            .enumerate()
            .map(|(i, sk_i)| {
                let binding =
                    LBFVContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                LBFVPublicKey::new_with_seed_and_binding(sk_i, a_seed, binding, &mut rng)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let pk = LBFVPublicKey::aggregate(&pk_contributions)?;

        // Common URS d1 for all contributions.
        let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut d1_seed);

        // Each party computes its contribution from its own sk_i and local r_i.
        let shares: Vec<LBFVRelinKeyShare> = sk_shares
            .iter()
            .enumerate()
            .map(|(i, sk_i)| {
                let binding =
                    LBFVContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                LBFVRelinKeyShare::contribution_with_binding(
                    sk_i, d1_seed, a_seed, binding, 0, 0, &mut rng,
                )
            })
            .collect::<std::result::Result<_, _>>()?;

        // Aggregate into a single relinearization key for the joint sk. The
        // public key supplies b_vec and is checked to share the CRS `a`.
        let relin_key = LBFVRelinearizationKey::aggregate(&shares, &pk)?;

        // Aggregating with inconsistent d1 seeds across shares must be rejected.
        // The test preserves a complete valid participant set (same session,
        // unique ids 1,2,3) so the binding check passes, and the d1 polynomial
        // mismatch is what actually causes the rejection.
        let mut bad_d1 = d1_seed;
        bad_d1[0] ^= 0xff;
        let bad_binding = LBFVContributionBinding::new(participant_set.clone(), 3)?;
        let bad_share = LBFVRelinKeyShare::contribution_with_binding(
            &sk_shares[2],
            bad_d1,
            a_seed,
            bad_binding,
            0,
            0,
            &mut rng,
        )?;
        let mut mismatched_d1_shares = shares.clone();
        mismatched_d1_shares[2] = bad_share;
        assert!(
            LBFVRelinearizationKey::aggregate(&mismatched_d1_shares, &pk).is_err(),
            "d1 polynomial mismatch must be rejected"
        );

        // A public key built under a different CRS `a` than the shares must be
        // rejected (the b_vec / d2 cancellation would otherwise be broken).
        // Use the same session and participant set so the binding check passes,
        // and the CRS a mismatch is what actually causes the rejection.
        let mut other_a = a_seed;
        other_a[0] ^= 0xff;
        let pk_other_contributions: Vec<LBFVPublicKey> = sk_shares
            .iter()
            .enumerate()
            .map(|(i, sk_i)| {
                let binding =
                    LBFVContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                LBFVPublicKey::new_with_seed_and_binding(sk_i, other_a, binding, &mut rng)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let pk_other = LBFVPublicKey::aggregate(&pk_other_contributions)?;
        assert!(
            LBFVRelinearizationKey::aggregate(&shares, &pk_other).is_err(),
            "CRS a mismatch between PK and RLK shares must be rejected"
        );

        // The aggregated key must relinearize a product that decrypts under the
        // joint sk, for both encodings.
        for encoding in [Encoding::poly(), Encoding::simd()] {
            let pt1 = Plaintext::try_encode(&[3u64], encoding.clone(), &params)?;
            let pt2 = Plaintext::try_encode(&[5u64], encoding.clone(), &params)?;
            let ct1 = pk.try_encrypt(&pt1, &mut rng)?;
            let ct2 = pk.try_encrypt(&pt2, &mut rng)?;

            let mut ct_product = &ct1 * &ct2;
            relin_key.relinearizes(&mut ct_product)?;

            let pt_result = sk_joint.try_decrypt(&ct_product)?;
            let result = Vec::<u64>::try_decode(&pt_result, encoding.clone())?;
            assert_eq!(result[0], 15);
        }

        Ok(())
    }

    // Boundary test: aggregation over a larger participant set still produces a
    // functionally correct relinearization key. RLK noise grows ~|S|·σ², so this
    // pins the caller-visible upper end of the noise budget for these params: a
    // larger set (or smaller modulus) would push multiplication out of budget.
    #[test]
    fn test_distributed_relinearization_large_participant_set() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);

        let n = 8;
        let sk_shares: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        let mut sum_coeffs = vec![0i64; params.degree()];
        for sk in &sk_shares {
            for (acc, c) in sum_coeffs.iter_mut().zip(sk.coeffs.iter()) {
                *acc = acc.wrapping_add(*c);
            }
        }
        let sk_joint = SecretKey::new(sum_coeffs, &params);

        let participant_set = LBFVParticipantSet::new([42u8; 32], (1..=n as u32).collect())?;

        let mut a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut a_seed);
        let pk_contributions: Vec<LBFVPublicKey> = sk_shares
            .iter()
            .enumerate()
            .map(|(i, sk_i)| {
                let binding =
                    LBFVContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                LBFVPublicKey::new_with_seed_and_binding(sk_i, a_seed, binding, &mut rng)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let pk = LBFVPublicKey::aggregate(&pk_contributions)?;

        let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut d1_seed);

        let shares: Vec<LBFVRelinKeyShare> = sk_shares
            .iter()
            .enumerate()
            .map(|(i, sk_i)| {
                let binding =
                    LBFVContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                LBFVRelinKeyShare::contribution_with_binding(
                    sk_i, d1_seed, a_seed, binding, 0, 0, &mut rng,
                )
            })
            .collect::<std::result::Result<_, _>>()?;

        let relin_key = LBFVRelinearizationKey::aggregate(&shares, &pk)?;

        let pt1 = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;
        let pt2 = Plaintext::try_encode(&[5u64], Encoding::poly(), &params)?;
        let ct1 = pk.try_encrypt(&pt1, &mut rng)?;
        let ct2 = pk.try_encrypt(&pt2, &mut rng)?;

        let mut ct_product = &ct1 * &ct2;
        relin_key.relinearizes(&mut ct_product)?;

        let pt_result = sk_joint.try_decrypt(&ct_product)?;
        let result = Vec::<u64>::try_decode(&pt_result, Encoding::poly())?;
        assert_eq!(result[0], 15);

        Ok(())
    }

    #[test]
    fn test_distributed_relinearization_with_explicit_polys() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let n = 3;

        let sk_shares: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        let mut sum_coeffs = vec![0i64; params.degree()];
        for sk in &sk_shares {
            for (acc, c) in sum_coeffs.iter_mut().zip(sk.coeffs.iter()) {
                *acc = acc.wrapping_add(*c);
            }
        }
        let sk_joint = SecretKey::new(sum_coeffs, &params);

        // Participant set and bindings.
        let participant_set = LBFVParticipantSet::new([17u8; 32], (1..=n as u32).collect())?;

        // Build shared CRS a polynomials from a seed.
        let mut a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut a_seed);
        let a_polys_ntt: Vec<Poly<Ntt>> = {
            let tmp = LBFVPublicKey::new_with_seed(&sk_shares[0], a_seed, &mut rng)?;
            tmp.c.iter().map(|ct| ct.c[1].clone()).collect()
        };

        // Build shared URS d1 polynomials.
        let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut d1_seed);
        let d1_polys: Vec<Poly<NttShoup>> = {
            let ksk_tmp = KeySwitchingKey::new_with_seed(
                &sk_shares[0],
                &Poly::<PowerBasis>::try_convert_from(
                    sk_shares[0].coeffs.as_ref(),
                    params.context_at_level(0)?,
                    false,
                )?,
                d1_seed,
                0,
                0,
                &mut rng,
            )?;
            ksk_tmp.c1.to_vec()
        };

        // Convert a polys to NttShoup for the RLK contribution API.
        let a_polys_shoup: Vec<Poly<NttShoup>> = a_polys_ntt
            .iter()
            .map(|p| p.clone().into_ntt_shoup())
            .collect();

        // Build PK from contributions using explicit a polys with bindings.
        let pk_contributions: Vec<LBFVPublicKey> = sk_shares
            .iter()
            .enumerate()
            .map(|(i, sk_i)| {
                let binding =
                    LBFVContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                LBFVPublicKey::contribute_with_binding(sk_i, &a_polys_ntt, binding, &mut rng)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let pk = LBFVPublicKey::aggregate(&pk_contributions)?;

        // Build RLK shares using explicit d1 and a polys with bindings.
        let shares: Vec<LBFVRelinKeyShare> = sk_shares
            .iter()
            .enumerate()
            .map(|(i, sk_i)| {
                let binding =
                    LBFVContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                LBFVRelinKeyShare::contribution_with_polys_and_binding(
                    sk_i,
                    d1_polys.clone(),
                    a_polys_shoup.clone(),
                    binding,
                    0,
                    0,
                    &mut rng,
                )
            })
            .collect::<std::result::Result<_, _>>()?;

        let relin_key = LBFVRelinearizationKey::aggregate(&shares, &pk)?;

        // Aggregating with mismatched d1 polys must be rejected.
        // Preserve a complete valid participant set (same session, unique
        // ids 1,2,3) so the binding check passes and the d1 polynomial
        // mismatch is what actually causes the rejection.
        let bad_d1: Vec<Poly<NttShoup>> = {
            let mut bad = d1_polys.clone();
            let ctx0 = params.context_at_level(0)?;
            bad[0] = Poly::<NttShoup>::random_from_seed(
                ctx0,
                <ChaCha8Rng as SeedableRng>::Seed::default(),
            );
            bad
        };
        let bad_binding3 = LBFVContributionBinding::new(participant_set.clone(), 3)?;
        let bad_share = LBFVRelinKeyShare::contribution_with_polys_and_binding(
            &sk_shares[2],
            bad_d1,
            a_polys_shoup.clone(),
            bad_binding3,
            0,
            0,
            &mut rng,
        )?;
        let mut mismatched_d1_shares = shares.clone();
        mismatched_d1_shares[2] = bad_share;
        assert!(
            LBFVRelinearizationKey::aggregate(&mismatched_d1_shares, &pk).is_err(),
            "d1 polynomial mismatch must be rejected"
        );

        // Aggregating with an RLK built under a different CRS a than the PK
        // must be rejected. Use the same session and participant set so the
        // binding check passes; the CRS a mismatch is what causes the rejection.
        let mut other_a_seed = a_seed;
        other_a_seed[0] ^= 0xff;
        let pk_other_contributions: Vec<LBFVPublicKey> = sk_shares
            .iter()
            .enumerate()
            .map(|(i, sk_i)| {
                let binding =
                    LBFVContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                LBFVPublicKey::new_with_seed_and_binding(sk_i, other_a_seed, binding, &mut rng)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let pk_other = LBFVPublicKey::aggregate(&pk_other_contributions)?;
        assert!(
            LBFVRelinearizationKey::aggregate(&shares, &pk_other).is_err(),
            "CRS a mismatch between PK and RLK shares must be rejected"
        );

        // The aggregated key must relinearize correctly.
        for encoding in [Encoding::poly(), Encoding::simd()] {
            let pt1 = Plaintext::try_encode(&[3u64], encoding.clone(), &params)?;
            let pt2 = Plaintext::try_encode(&[5u64], encoding.clone(), &params)?;
            let ct1 = pk.try_encrypt(&pt1, &mut rng)?;
            let ct2 = pk.try_encrypt(&pt2, &mut rng)?;

            let mut ct_product = &ct1 * &ct2;
            relin_key.relinearizes(&mut ct_product)?;

            let pt_result = sk_joint.try_decrypt(&ct_product)?;
            let result = Vec::<u64>::try_decode(&pt_result, encoding.clone())?;
            assert_eq!(result[0], 15);
        }

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
    fn aggregate_checks_participant_sets_and_component_linearity() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let set = LBFVParticipantSet::new([21u8; 32], vec![1, 2, 3])?;
        let secret_keys: Vec<SecretKey> = (0..3)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        let public_keys: Vec<LBFVPublicKey> = secret_keys
            .iter()
            .enumerate()
            .map(|(index, sk)| {
                let binding = LBFVContributionBinding::new(set.clone(), (index + 1) as u32)?;
                LBFVPublicKey::new_with_seed_and_binding(sk, [31u8; 32], binding, &mut rng)
            })
            .collect::<std::result::Result<_, _>>()?;
        let public_key = LBFVPublicKey::aggregate(&public_keys)?;

        let shares: Vec<LBFVRelinKeyShare> = secret_keys
            .iter()
            .enumerate()
            .map(|(index, sk)| {
                let binding = LBFVContributionBinding::new(set.clone(), (index + 1) as u32)?;
                LBFVRelinKeyShare::contribution_with_binding(
                    sk, [41u8; 32], [31u8; 32], binding, 0, 0, &mut rng,
                )
            })
            .collect::<std::result::Result<_, _>>()?;

        let aggregate = LBFVRelinearizationKey::aggregate(&shares, &public_key)?;

        // Component linearity: Σ d0_i = sum of all three shares' c0 for ksk_r_to_s.
        for (j, actual) in aggregate.ksk_r_to_s.c0.iter().enumerate() {
            let actual_ntt: fhe_math::rq::Poly<fhe_math::rq::Ntt> = actual.clone().into_ntt();
            let mut expected = shares[0].ksk_r_to_s.c0[j].clone().into_ntt();
            for share in shares.iter().skip(1) {
                expected += &share.ksk_r_to_s.c0[j].clone().into_ntt();
            }
            assert_eq!(
                actual_ntt, expected,
                "c0 linearity mismatch for ksk_r_to_s at index {j}"
            );
        }

        // Component linearity: Σ d2_i = sum of all three shares' c0 for ksk_s_to_r.
        for (j, actual) in aggregate.ksk_s_to_r.c0.iter().enumerate() {
            let actual_ntt: fhe_math::rq::Poly<fhe_math::rq::Ntt> = actual.clone().into_ntt();
            let mut expected = shares[0].ksk_s_to_r.c0[j].clone().into_ntt();
            for share in shares.iter().skip(1) {
                expected += &share.ksk_s_to_r.c0[j].clone().into_ntt();
            }
            assert_eq!(
                actual_ntt, expected,
                "c0 linearity mismatch for ksk_s_to_r at index {j}"
            );
        }

        // Common c1 values are copied unchanged, not summed.
        assert_eq!(aggregate.ksk_r_to_s.c1, shares[0].ksk_r_to_s.c1);
        assert_eq!(aggregate.ksk_s_to_r.c1, shares[0].ksk_s_to_r.c1);
        assert_eq!(aggregate.participant_set.as_ref(), Some(&set));

        // Mismatched sessions must be rejected.
        let other_set = LBFVParticipantSet::new([22u8; 32], vec![1, 2, 3])?;
        let other_binding = LBFVContributionBinding::new(other_set.clone(), 3)?;
        let cross_session = LBFVRelinKeyShare::contribution_with_binding(
            &secret_keys[2],
            [41u8; 32],
            [31u8; 32],
            other_binding,
            0,
            0,
            &mut rng,
        )?;
        let mut cross_shares = shares.clone();
        cross_shares[2] = cross_session;
        assert!(LBFVRelinearizationKey::aggregate(&cross_shares, &public_key).is_err());

        // Duplicate IDs must be rejected.
        let duplicate_shares = vec![shares[0].clone(), shares[0].clone(), shares[2].clone()];
        assert!(LBFVRelinearizationKey::aggregate(&duplicate_shares, &public_key).is_err());

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

        let seedless = LBFVPublicKey::contribute(&sk, &a_polys, &mut rng)?;
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

    /// RLK aggregation must reject shares bound to a different session than
    /// the public key, even when the `a`/`d1` seeds and participant IDs are
    /// identical.  The rejection must come from the participant-binding check,
    /// not the CRS-binding check.
    #[test]
    fn rlk_aggregation_rejects_shares_from_different_session() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let n = 3;

        let secret_keys: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        // Two participant sets with the same IDs but different session IDs.
        let set_a = LBFVParticipantSet::new([100u8; 32], (1..=n as u32).collect())?;
        let set_b = LBFVParticipantSet::new([101u8; 32], (1..=n as u32).collect())?;

        let mut a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut a_seed);
        let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut d1_seed);

        // PK bound to session A.
        let pk_contributions: Vec<LBFVPublicKey> = secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = LBFVContributionBinding::new(set_a.clone(), (i + 1) as u32)?;
                LBFVPublicKey::new_with_seed_and_binding(sk, a_seed, binding, &mut rng)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pk_a = LBFVPublicKey::aggregate(&pk_contributions)?;

        // RLK shares bound to session B (same seeds, so same a/d1 polynomials).
        let shares_b: Vec<LBFVRelinKeyShare> = secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = LBFVContributionBinding::new(set_b.clone(), (i + 1) as u32)?;
                LBFVRelinKeyShare::contribution_with_binding(
                    sk, d1_seed, a_seed, binding, 0, 0, &mut rng,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        // The different session IDs must be caught by the binding check.
        assert!(LBFVRelinearizationKey::aggregate(&shares_b, &pk_a).is_err());

        Ok(())
    }

    /// RLK aggregation must reject shares whose accepted set differs from
    /// the public key's set, even when the session ID and `a`/`d1` seeds
    /// are identical.
    #[test]
    fn rlk_aggregation_rejects_different_pk_participant_set() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let n = 3;

        let secret_keys: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        // Same session ID, different participant ID lists.
        let session_id = [102u8; 32];
        let set_pk = LBFVParticipantSet::new(session_id, vec![1, 2, 3])?;
        let set_rlk = LBFVParticipantSet::new(session_id, vec![1, 2, 4])?;

        let mut a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut a_seed);
        let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut d1_seed);

        // PK bound to set {1,2,3}.
        let pk_contributions: Vec<LBFVPublicKey> = secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = LBFVContributionBinding::new(
                    set_pk.clone(),
                    (i + 1) as u32, // IDs 1,2,3
                )?;
                LBFVPublicKey::new_with_seed_and_binding(sk, a_seed, binding, &mut rng)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pk = LBFVPublicKey::aggregate(&pk_contributions)?;

        // RLK shares bound to set {1,2,4}.
        let rlk_ids = [1u32, 2, 4];
        let shares: Vec<LBFVRelinKeyShare> = secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = LBFVContributionBinding::new(set_rlk.clone(), rlk_ids[i])?;
                LBFVRelinKeyShare::contribution_with_binding(
                    sk, d1_seed, a_seed, binding, 0, 0, &mut rng,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        // The different participant IDs must be caught by the binding check.
        assert!(LBFVRelinearizationKey::aggregate(&shares, &pk).is_err());

        Ok(())
    }

    /// RLK aggregation must explicitly validate the public-key structure before
    /// accessing `pk.l` or individual ciphertext polynomials.
    #[test]
    fn rlk_aggregation_rejects_malformed_public_key() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let n = 2;

        let set = LBFVParticipantSet::new([51u8; 32], (1..=n as u32).collect())?;
        let secret_keys: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        let mut a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut a_seed);
        let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut d1_seed);

        // Build a valid PK and valid RLK shares.
        let pk_contributions: Vec<LBFVPublicKey> = secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = LBFVContributionBinding::new(set.clone(), (i + 1) as u32)?;
                LBFVPublicKey::new_with_seed_and_binding(sk, a_seed, binding, &mut rng)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pk = LBFVPublicKey::aggregate(&pk_contributions)?;

        let shares: Vec<LBFVRelinKeyShare> = secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = LBFVContributionBinding::new(set.clone(), (i + 1) as u32)?;
                LBFVRelinKeyShare::contribution_with_binding(
                    sk, d1_seed, a_seed, binding, 0, 0, &mut rng,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Malformed PK: wrong l value.
        let mut bad_pk = pk.clone();
        bad_pk.l = 1;
        assert!(
            LBFVRelinearizationKey::aggregate(&shares, &bad_pk).is_err(),
            "RLK aggregation must reject a public key with a mismatched l value"
        );

        // Malformed PK: truncated ciphertexts.
        let mut truncated_pk = pk.clone();
        truncated_pk.c.pop();
        assert!(
            LBFVRelinearizationKey::aggregate(&shares, &truncated_pk).is_err(),
            "RLK aggregation must reject a public key with truncated ciphertexts"
        );

        Ok(())
    }

    /// RLK aggregation must validate ksk_s_to_r fully, not just ksk_r_to_s.
    /// A share whose ksk_s_to_r differs in levels or contexts must be rejected.
    #[test]
    fn rlk_aggregation_rejects_malformed_second_ksk() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let n = 2;

        let set = LBFVParticipantSet::new([53u8; 32], (1..=n as u32).collect())?;
        let secret_keys: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        let mut a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut a_seed);
        let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut d1_seed);

        // Build a valid PK.
        let pk_contributions: Vec<LBFVPublicKey> = secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = LBFVContributionBinding::new(set.clone(), (i + 1) as u32)?;
                LBFVPublicKey::new_with_seed_and_binding(sk, a_seed, binding, &mut rng)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pk = LBFVPublicKey::aggregate(&pk_contributions)?;

        // Build two valid shares.
        let s0 = LBFVRelinKeyShare::contribution_with_binding(
            &secret_keys[0],
            d1_seed,
            a_seed,
            LBFVContributionBinding::new(set.clone(), 1)?,
            0,
            0,
            &mut rng,
        )?;
        let s1 = LBFVRelinKeyShare::contribution_with_binding(
            &secret_keys[1],
            d1_seed,
            a_seed,
            LBFVContributionBinding::new(set.clone(), 2)?,
            0,
            0,
            &mut rng,
        )?;

        // Now create a share with a deliberately malformed ksk_s_to_r
        // (keeping ksk_r_to_s intact).
        let mut bad_s1 = s1.clone();

        // Tamper with ksk_s_to_r's ciphertext_level.
        bad_s1.ksk_s_to_r.ciphertext_level = 1;
        assert!(
            LBFVRelinearizationKey::aggregate(&[s0.clone(), bad_s1], &pk).is_err(),
            "RLK aggregation must reject a share with a diverging ksk_s_to_r ciphertext_level"
        );

        // Tamper with ksk_s_to_r's ksk_level.
        let mut bad_s2 = s1.clone();
        bad_s2.ksk_s_to_r.ksk_level = 1;
        assert!(
            LBFVRelinearizationKey::aggregate(&[s0.clone(), bad_s2], &pk).is_err(),
            "RLK aggregation must reject a share with a diverging ksk_s_to_r ksk_level"
        );

        // Tamper with ksk_s_to_r's log_base.
        let mut bad_s3 = s1.clone();
        bad_s3.ksk_s_to_r.log_base = 99;
        assert!(
            LBFVRelinearizationKey::aggregate(&[s0.clone(), bad_s3], &pk).is_err(),
            "RLK aggregation must reject a share with a diverging ksk_s_to_r log_base"
        );

        Ok(())
    }

    /// Mixed seeded/explicit RLK shares with identical concrete d1/a polynomials
    /// must aggregate successfully. Seeds are compression metadata — they need
    /// not match when the concrete polynomials do.
    #[test]
    fn rlk_aggregation_allows_mixed_seed_representations() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let n = 2;

        let set = LBFVParticipantSet::new([52u8; 32], (1..=n as u32).collect())?;
        let secret_keys: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        // Common seeds for a and d1.
        let mut a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut a_seed);
        let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut d1_seed);

        // Build the PK.
        let pk_contributions: Vec<LBFVPublicKey> = secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let binding = LBFVContributionBinding::new(set.clone(), (i + 1) as u32)?;
                LBFVPublicKey::new_with_seed_and_binding(sk, a_seed, binding, &mut rng)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pk = LBFVPublicKey::aggregate(&pk_contributions)?;

        // Share 0: seeded (the normal path).
        let s0 = LBFVRelinKeyShare::contribution_with_binding(
            &secret_keys[0],
            d1_seed,
            a_seed,
            LBFVContributionBinding::new(set.clone(), 1)?,
            0,
            0,
            &mut rng,
        )?;

        // Share 1: explicit polynomials, same concrete d1 and a as share 0.
        // Extract the concrete polynomials from s0's KSKs.
        let d1_polys = s0.ksk_r_to_s.c1.to_vec();
        let a_polys: Vec<Poly<NttShoup>> = s0.ksk_s_to_r.c1.to_vec();
        let s1 = LBFVRelinKeyShare::contribution_with_polys_and_binding(
            &secret_keys[1],
            d1_polys,
            a_polys,
            LBFVContributionBinding::new(set.clone(), 2)?,
            0,
            0,
            &mut rng,
        )?;

        // The shares should have different KSK seeds.
        assert_ne!(s0.ksk_r_to_s.seed, s1.ksk_r_to_s.seed);

        // Aggregation must succeed despite the seed mismatch.
        let rlk = LBFVRelinearizationKey::aggregate(&[s0, s1], &pk)?;

        // The output must not retain an incorrect seed when inputs differ.
        assert!(
            rlk.ksk_r_to_s.seed.is_none(),
            "Aggregate RLK must not retain a seed when input seeds differ"
        );
        assert!(
            rlk.ksk_s_to_r.seed.is_none(),
            "Aggregate RLK must not retain a seed when input seeds differ"
        );

        // Functional check: the aggregated key must relinearize correctly.
        let mut sum_coeffs = vec![0i64; params.degree()];
        for sk in &secret_keys {
            for (acc, c) in sum_coeffs.iter_mut().zip(sk.coeffs.iter()) {
                *acc = acc.wrapping_add(*c);
            }
        }
        let sk_joint = SecretKey::new(sum_coeffs, &params);
        let pt = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        let mut ct_sq = &ct * &ct;
        rlk.relinearizes(&mut ct_sq)?;
        assert_eq!(
            Vec::<u64>::try_decode(&sk_joint.try_decrypt(&ct_sq)?, Encoding::poly())?[0],
            9
        );

        Ok(())
    }

    /// `aggregate_internal` must reject a share whose `ksk_r_to_s` and
    /// `ksk_s_to_r` have mismatched internal consistency (parameters, levels,
    /// contexts, or log_base).
    #[test]
    fn aggregate_rejects_internally_inconsistent_share() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);

        // Build a valid unbound PK and a valid unbound share.
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;
        let valid_share = LBFVRelinKeyShare::contribution(
            &sk, [61u8; 32], // d1_seed
            [51u8; 32], // a_seed (matches pk seedlessness is ok; CRS check passes anyway)
            0, 0, &mut rng,
        )?;

        // Clone the valid share and corrupt ksk_s_to_r by giving it a
        // different ciphertext_level than ksk_r_to_s.
        let mut malformed = valid_share.clone();
        malformed.ksk_s_to_r.ciphertext_level = 1;

        // The single-share unbound path must reject the malformed share.
        assert!(
            LBFVRelinearizationKey::aggregate_single_unbound(&[malformed], &pk).is_err(),
            "aggregate_single_unbound should reject share with mismatched ciphertext levels"
        );

        // Also test mismatched log_base.
        let mut malformed2 = valid_share.clone();
        malformed2.ksk_s_to_r.log_base = 1;
        assert!(
            LBFVRelinearizationKey::aggregate_single_unbound(&[malformed2], &pk).is_err(),
            "aggregate_single_unbound should reject share with mismatched log_base"
        );

        // Also test mismatched params (use a different parameter set).
        let params2 = BfvParameters::default_arc(7, 8);
        let sk2 = SecretKey::random(&params2, &mut rng);
        let _pk2 = LBFVPublicKey::new(&sk2, &mut rng)?;
        let share2 = LBFVRelinKeyShare::contribution(&sk2, [62u8; 32], [52u8; 32], 0, 0, &mut rng)?;
        let mut malformed3 = valid_share.clone();
        malformed3.ksk_s_to_r = share2.ksk_s_to_r.clone();
        assert!(
            LBFVRelinearizationKey::aggregate_single_unbound(&[malformed3], &pk).is_err(),
            "aggregate_single_unbound should reject share with mismatched KSK parameters"
        );

        Ok(())
    }
}
