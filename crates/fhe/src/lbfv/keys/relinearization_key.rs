/*!
 * Implementation of the l-BFV relinearization algorithm as described in
 * Robust Multiparty Computation from Threshold Encryption Based on RLWE
 * [1](https://eprint.iacr.org/2024/1285.pdf).
 *
 * This module contains the relinearization key for the l-BFV scheme, along with the relinearization key
 * relinearization algorithm.
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
/// # Not yet implemented
///
/// - Serialization of a single `LBFVRelinKeyShare` for transport/broadcast
///   (only the aggregated [`LBFVRelinearizationKey`] is currently serializable).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LBFVRelinKeyShare {
    /// Per-node key-switching key from r to s: `(d0_i, d1)` where
    /// `d0_i = -sk_i·d1 + e0_i + r_i·g`.
    ksk_r_to_s: KeySwitchingKey,
    /// Per-node key-switching key from s to r: `(d2_i, a)` where
    /// `d2_i = r_i·a + e2_i + sk_i·g` (built by encrypting `sk_i` under
    /// `-r_i`, mirroring the single-key construction).
    ksk_s_to_r: KeySwitchingKey,
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
        let r: SecretKey = SecretKey::random(&sk_i.params, rng);
        let r_poly =
            Poly::<PowerBasis>::try_convert_from(r.coeffs.as_ref(), ctx_ciphertext, false)?;
        let r_switched_up = r_poly.switch(&switcher_up)?;

        let sk_poly =
            Poly::<PowerBasis>::try_convert_from(sk_i.coeffs.as_ref(), ctx_ciphertext, false)?;
        let sk_switched_up = sk_poly.switch(&switcher_up)?;

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
        let mut neg_r = r.clone();
        neg_r.coeffs.iter_mut().for_each(|x| *x = x.wrapping_neg());
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

        let r: SecretKey = SecretKey::random(&sk_i.params, rng);
        let r_poly =
            Poly::<PowerBasis>::try_convert_from(r.coeffs.as_ref(), ctx_ciphertext, false)?;
        let r_switched_up = r_poly.switch(&switcher_up)?;

        let sk_poly =
            Poly::<PowerBasis>::try_convert_from(sk_i.coeffs.as_ref(), ctx_ciphertext, false)?;
        let sk_switched_up = sk_poly.switch(&switcher_up)?;

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
        let mut neg_r = r.clone();
        neg_r.coeffs.iter_mut().for_each(|x| *x = x.wrapping_neg());
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
        })
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
        // The CRS (a) seed must always be given (since is the same of the sk generation).
        let a_seed = pk
            .seed
            .ok_or_else(|| Error::DefaultError("Public key is missing its seed".to_string()))?;

        let share =
            LBFVRelinKeyShare::contribution(sk, d1_seed, a_seed, ciphertext_level, key_level, rng)?;

        Self::aggregate(&[share], pk)
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
    /// the CRS `a` it was built under — `pk.seed` — is checked against the `a`
    /// the contributions used for their `d2` (`ksk_s_to_r`'s seed). This closes
    /// the consistency loop: the `-a_j·sk` term in `b_vec` and the `+r·a_j·sk`
    /// term in `d2` only cancel during relinearization if both use the same `a`.
    /// The ciphertext/key levels are taken from the shares themselves.
    ///
    /// # Arguments
    /// * `shares` - The contributions from the participating parties. They must
    ///   all share the same `d1`/`a` seeds and levels, otherwise their `d1`/`a`
    ///   components do not line up and aggregation is rejected.
    /// * `pk` - The aggregated threshold public key (e.g. from
    ///   [`LBFVPublicKey::aggregate`](super::LBFVPublicKey::aggregate)). It must
    ///   have been built under the same CRS seed `a` as the contributions, and
    ///   it supplies the `b_vec` used in relinearization.
    ///
    /// # Errors
    /// Returns an error if `shares` is empty, if the shares disagree on their
    /// seeds/levels, or if `pk.seed` does not match the CRS seed the
    /// contributions used (a mismatched CRS `a` between `b_vec` and `d2`).
    #[allow(clippy::indexing_slicing)] // c1.len() checked against new_l; both indexed under same j
    pub fn aggregate(shares: &[LBFVRelinKeyShare], pk: &LBFVPublicKey) -> Result<Self> {
        let (first, rest) = shares.split_first().ok_or_else(|| {
            Error::DefaultError("Cannot aggregate zero relinearization key shares".to_string())
        })?;

        for s in rest {
            if s.ksk_r_to_s.seed != first.ksk_r_to_s.seed
                || s.ksk_s_to_r.seed != first.ksk_s_to_r.seed
                || s.ksk_r_to_s.ciphertext_level != first.ksk_r_to_s.ciphertext_level
                || s.ksk_r_to_s.ksk_level != first.ksk_r_to_s.ksk_level
            {
                return Err(Error::DefaultError(
                    "Relinearization key shares are inconsistent (differing seeds or levels)"
                        .to_string(),
                ));
            }
        }

        // Verify the concrete d1 (URS) polynomials match across all shares.
        for s in rest {
            if s.ksk_r_to_s.c1 != first.ksk_r_to_s.c1 {
                return Err(Error::DefaultError(
                    "Relinearization key shares have inconsistent d1 (URS) polynomials".to_string(),
                ));
            }
        }

        // Verify the concrete a (CRS) polynomials match across all shares.
        for s in rest {
            if s.ksk_s_to_r.c1 != first.ksk_s_to_r.c1 {
                return Err(Error::DefaultError(
                    "Relinearization key shares have inconsistent a (CRS) polynomials".to_string(),
                ));
            }
        }

        // CRS binding: the `a` polynomials embedded in ksk_s_to_r.c1 must
        // match the public key's `a_j` ciphertext polynomials.  This is the
        // concrete cross-check that seed equality alone cannot guarantee.
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
        let new_l = pk.l - first.ksk_r_to_s.ciphertext_level;
        if first.ksk_s_to_r.c1.len() != new_l {
            return Err(Error::DefaultError(
                "CRS binding failed: RLK's a polynomial count does not match expected l - ciphertext_level"
                    .to_string(),
            ));
        }
        for (j, c1_j) in first.ksk_s_to_r.c1.iter().enumerate() {
            let mut a_ksk: Poly<Ntt> = c1_j.clone().into_ntt();
            a_ksk.disallow_variable_time_computations();
            if a_ksk != pk.c[j].c[1] {
                return Err(Error::DefaultError(
                    "CRS binding failed: RLK's a_j does not match public key's a_j".to_string(),
                ));
            }
        }

        // Levels are defined by the shares; b_vec is extracted from the public
        // key at those levels.
        let ciphertext_level = first.ksk_r_to_s.ciphertext_level;
        let key_level = first.ksk_r_to_s.ksk_level;
        let b_vec =
            pk.extract_b_polynomials(ciphertext_level, key_level, Representation::NttShoup)?;

        // Clone a share as the template (carrying the shared c1 = d1 / a and all
        // context/level metadata), then overwrite its c0 with the summed d0 / d2.
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

        Ok(Self {
            ksk_r_to_s,
            ksk_s_to_r,
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
                    poly_i_coefficients.as_slice().unwrap(),
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

#[cfg(feature = "protobuf")]
mod protobuf {
    use super::*;
    use crate::bfv::traits::TryConvertFrom;
    use crate::proto::bfv::{
        KeySwitchingKey as KeySwitchingKeyProto,
        LbfvRelinearizationKey as LBFVRelinearizationKeyProto,
    };
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
            par: &Arc<BfvParameters>,
        ) -> Result<Self> {
            if value.ksk_r_to_s.is_none() || value.ksk_s_to_r.is_none() {
                return Err(Error::DefaultError(
                    "Invalid serialization: missing key switching keys".to_string(),
                ));
            }

            let ksk_r_to_s =
                KeySwitchingKey::try_convert_from(value.ksk_r_to_s.as_ref().unwrap(), par)?;
            let ksk_s_to_r =
                KeySwitchingKey::try_convert_from(value.ksk_s_to_r.as_ref().unwrap(), par)?;

            // Deserialize b_vec
            let key_ctx = ksk_r_to_s.ctx_ksk.clone();
            let mut b_vec = Vec::with_capacity(value.b_vec.len());
            for poly_bytes in &value.b_vec {
                let poly = Poly::<NttShoup>::from_bytes(poly_bytes, &key_ctx)?;
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

        fn from_bytes(bytes: &[u8], par: &Arc<Self::Parameters>) -> Result<Self> {
            let rk = Message::decode(bytes);
            if let Ok(rk) = rk {
                LBFVRelinearizationKey::try_convert_from(&rk, par)
            } else {
                Err(Error::DefaultError("Invalid serialization".to_string()))
            }
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

    #[cfg(feature = "protobuf")]
    mod protobuf {
        use super::*;
        use fhe_traits::{DeserializeParametrized, Serialize};

        #[test]
        fn test_serialize_deserialize() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let pk = LBFVPublicKey::new(&sk, &mut rng);

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

        // Threshold public key built by aggregating per-node contributions
        // (F2) — sk_joint is NOT used to construct it. All contributions share
        // the CRS seed `a_seed`, which the rlk's d2 must reuse.
        let mut a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut a_seed);
        let pk_contributions: Vec<LBFVPublicKey> = sk_shares
            .iter()
            .map(|sk_i| LBFVPublicKey::new_with_seed(sk_i, a_seed, &mut rng))
            .collect();
        let pk = LBFVPublicKey::aggregate(&pk_contributions)?;

        // Common URS d1 for all contributions.
        let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut d1_seed);

        // Each party computes its contribution from its own sk_i and local r_i.
        let shares: Vec<LBFVRelinKeyShare> = sk_shares
            .iter()
            .map(|sk_i| {
                LBFVRelinKeyShare::contribution(sk_i, d1_seed, a_seed, 0, 0, &mut rng).unwrap()
            })
            .collect();

        // Aggregate into a single relinearization key for the joint sk. The
        // public key supplies b_vec and is checked to share the CRS `a`.
        let relin_key = LBFVRelinearizationKey::aggregate(&shares, &pk)?;

        // Aggregating with inconsistent d1 seeds across shares must be rejected.
        let mut bad_d1 = d1_seed;
        bad_d1[0] ^= 0xff;
        let bad_share =
            LBFVRelinKeyShare::contribution(&sk_shares[0], bad_d1, a_seed, 0, 0, &mut rng)?;
        assert!(LBFVRelinearizationKey::aggregate(&[shares[0].clone(), bad_share], &pk).is_err());

        // A public key built under a different CRS `a` than the shares must be
        // rejected (the b_vec / d2 cancellation would otherwise be broken).
        let mut other_a = a_seed;
        other_a[0] ^= 0xff;
        let pk_other = LBFVPublicKey::aggregate(
            &sk_shares
                .iter()
                .map(|sk_i| LBFVPublicKey::new_with_seed(sk_i, other_a, &mut rng))
                .collect::<Vec<_>>(),
        )?;
        assert!(LBFVRelinearizationKey::aggregate(&shares, &pk_other).is_err());

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

        // Build shared CRS a polynomials from a seed.
        let mut a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut a_seed);
        let a_polys_ntt: Vec<Poly<Ntt>> = {
            let tmp = LBFVPublicKey::new_with_seed(&sk_shares[0], a_seed, &mut rng);
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

        // Build PK from contributions using explicit a polys.
        let pk_contributions: Vec<LBFVPublicKey> = sk_shares
            .iter()
            .map(|sk_i| LBFVPublicKey::contribute(sk_i, &a_polys_ntt, &mut rng).unwrap())
            .collect();
        let pk = LBFVPublicKey::aggregate(&pk_contributions)?;

        // Build RLK shares using explicit d1 and a polys.
        let shares: Vec<LBFVRelinKeyShare> = sk_shares
            .iter()
            .map(|sk_i| {
                LBFVRelinKeyShare::contribution_with_polys(
                    sk_i,
                    d1_polys.clone(),
                    a_polys_shoup.clone(),
                    0,
                    0,
                    &mut rng,
                )
                .unwrap()
            })
            .collect();

        let relin_key = LBFVRelinearizationKey::aggregate(&shares, &pk)?;

        // Aggregating with mismatched d1 polys must be rejected.
        let bad_d1: Vec<Poly<NttShoup>> = {
            let mut bad = d1_polys.clone();
            let ctx0 = params.context_at_level(0)?;
            bad[0] = Poly::<NttShoup>::random_from_seed(
                ctx0,
                <ChaCha8Rng as SeedableRng>::Seed::default(),
            );
            bad
        };
        let bad_share = LBFVRelinKeyShare::contribution_with_polys(
            &sk_shares[0],
            bad_d1,
            a_polys_shoup.clone(),
            0,
            0,
            &mut rng,
        )?;
        assert!(LBFVRelinearizationKey::aggregate(&[shares[0].clone(), bad_share], &pk).is_err());

        // Aggregating with an RLK built under a different CRS a than the PK
        // must be rejected.
        let mut other_a_seed = a_seed;
        other_a_seed[0] ^= 0xff;
        let pk_other = LBFVPublicKey::aggregate(
            &sk_shares
                .iter()
                .map(|sk_i| LBFVPublicKey::new_with_seed(sk_i, other_a_seed, &mut rng))
                .collect::<Vec<_>>(),
        )?;
        assert!(LBFVRelinearizationKey::aggregate(&shares, &pk_other).is_err());

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
        let pk = LBFVPublicKey::new(&sk, &mut rng);

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
