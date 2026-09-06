//! Hybrid (special-prime + digit-decomposition) key switching for CKKS.
//!
//! One key at modulus `Q·P` serves EVERY level of the modulus chain, with
//! `dnum ≈ L/k` gadget digits instead of the `L_ℓ` digits of the per-level
//! RNS-decomposition key ([`crate::ckks::CkksRelinearizationKey`]), and
//! key-switching noise divided by the special modulus `P`.
//!
//! References: Han–Ki, *Better Bootstrapping for Approximate Homomorphic
//! Encryption* (CT-RSA 2020, <https://eprint.iacr.org/2019/688>), which
//! combines RNS decomposition with the "temporary modulus" (special-prime)
//! technique of Gentry–Halevi–Smart to cut the number of temporary moduli in
//! key switching; the RNS variant follows Lattigo's
//! `rlwe.Evaluator.GadgetProduct` / `KeySwitch` (`ring.BasisExtender`).
//!
//! # Gadget
//!
//! Let `Q = q_0⋯q_{L-1}` be the level-0 ciphertext modulus, `P = p_0⋯p_{k-1}`
//! the special primes, and split the limbs of `Q` into `dnum` consecutive
//! digits `D_j = ∏_{i∈digit j} q_i` of `alpha = k` limbs each (the last may
//! be shorter). The CRT gadget is
//!
//! ```text
//! g_j = (Q/D_j) · [ (Q/D_j)^{-1} ]_{D_j}        so g_j ≡ 1 (mod D_j), g_j ≡ 0 (mod q_i ∉ D_j)
//! ```
//!
//! and for any `c ∈ R_Q`, with `digit_j(c) = c mod D_j` (its residues on the
//! limbs of digit `j`, CRT-lifted to an integer in `(-D_j/2, D_j/2]`):
//!
//! ```text
//! Σ_j digit_j(c) · g_j ≡ c   (mod Q)        [`gadget_identity_holds` unit-tests this]
//! ```
//!
//! # Key
//!
//! A key switching `s' → s` is `dnum` pairs over `R_{Q·P}`:
//!
//! ```text
//! a_j  uniform,     b_j = -a_j·s + P·g_j·s' + e_j
//! ```
//!
//! For relinearization `s' = s²`. Elements of `R_{Q·P}` are stored as a
//! `(Q-part, P-part)` pair ([`CkksQpPoly`]) so no `Q·P` NTT context is ever
//! built (a `fhe-math` context carries a full modulus-drop chain).
//!
//! # Key switch of `c ∈ R_{Q_ℓ}` at level `ℓ` (only the first `L_ℓ` limbs)
//!
//! 1. Digits at level `ℓ`: the level-0 digits restricted to the surviving
//!    limbs, `D'_j = D_j ∩ Q_ℓ` (`ceil(L_ℓ/alpha)` of them). Since
//!    `g_j mod q_i` is still the indicator of digit `j` on the surviving
//!    limbs, `Σ_j digit'_j(c)·g_j ≡ c (mod Q_ℓ)` — this is why ONE level-0
//!    key serves all levels.
//! 2. Mod-up (basis extension `D'_j → Q_ℓ ∪ P`, exact, `fhe-math`
//!    [`RnsScaler`] with factor 1): `d_j = digit'_j(c)` as an element of
//!    `R_{Q_ℓ·P}` with `|d_j| ≤ D'_j/2`.
//! 3. Inner product over `Q_ℓ·P` with the key limbs restricted to
//!    `(Q_ℓ, P)`: `k_0 = Σ_j d_j·b_j`, `k_1 = Σ_j d_j·a_j`, so that
//!    `k_0 + k_1·s = P·(Σ_j d_j·g_j)·s' + Σ_j d_j·e_j = P·c·s' + e_ks`,
//!    with `‖e_ks‖ ≤ Σ_j ‖d_j‖·‖e_j‖ ≈ dnum·(D/2)·N·B_err`.
//! 4. Mod-down (`Q_ℓ·P → Q_ℓ`, exact division with rounding, standard RNS
//!    form): `round(x/P) ≡ (x − [x]_P)·P^{-1} (mod q_i)` where `[x]_P` is the
//!    centered residue lifted from the `P` limbs to the `Q_ℓ` limbs
//!    (`RnsScaler`, factor 1). Result `(k_0', k_1')` with
//!    `k_0' + k_1'·s = c·s' + e_ks/P + e_round`, `‖e_round‖ ≤ (1+‖s‖₁)/2`.
//! 5. `(c_0, c_1) += (k_0', k_1')`.
//!
//! The key-switch noise is therefore `≈ dnum·N·B_err·(D/P)` instead of the
//! RNS-decomposition key's `≈ L_ℓ·q_max·N·B_err`: a factor `≈ P` smaller
//! when `D ≈ P`. The key is `2·dnum·(L+k)` polynomials (all levels) instead
//! of `2·L_ℓ²` PER LEVEL.
//!
//! The multiparty (two-round) variant is
//! [`crate::trckks::CkksHybridRelinKeyGenerator`].

use crate::ckks::wire::{decode_hybrid_polys, encode_hybrid_polys};
use crate::ckks::{CkksCiphertext, CkksParameters, CkksSecretKey};
use crate::{Error, Result};
use fhe_math::{
    rns::{RnsContext, RnsScaler, ScalingFactor},
    rq::{Context, Ntt, Poly, PowerBasis, traits::TryConvertFrom},
};
use itertools::izip;
use ndarray::{Array2, Axis, s};
use num_bigint::BigUint;
use num_traits::One;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::ops::Range;
use std::sync::{Arc, OnceLock};
use zeroize::{Zeroize, Zeroizing};

// ─────────────────────────────────────────────────────────────────────────────
// Parameter-side tables
// ─────────────────────────────────────────────────────────────────────────────

/// Per-level precomputed tables for the hybrid key switch.
struct LevelTables {
    /// Limb ranges of the (restricted) digits at this level.
    digits: Vec<Range<usize>>,
    /// Basis extension `D'_j → Q_ℓ` (all `L_ℓ` limbs), per digit.
    up_q: Vec<RnsScaler>,
    /// Basis extension `D'_j → P`, per digit.
    up_p: Vec<RnsScaler>,
    /// Centered lift `P → Q_ℓ` for the mod-down.
    down: RnsScaler,
}

/// Hybrid key-switching tables attached to [`CkksParameters`].
pub(crate) struct HybridParams {
    /// Special primes `p_0..p_{k-1}`.
    pub(crate) special_moduli: Box<[u64]>,
    /// Context over `P` (single level; `k` limbs).
    pub(crate) context_p: Arc<Context>,
    /// Limbs per digit.
    pub(crate) alpha: usize,
    /// Number of digits at level 0.
    pub(crate) dnum: usize,
    /// `g_j` (plain CRT gadget, mod `Q`), per digit — kept for the gadget
    /// identity test; the key uses `P·g_j`.
    #[cfg_attr(not(test), allow(dead_code))]
    gadget: Vec<BigUint>,
    /// `P·g_j`, per digit (the constant that multiplies `s'` in the key).
    p_gadget: Vec<BigUint>,
    /// `P^{-1} mod q_i` for every level-0 limb.
    p_inv_mod_q: Vec<u64>,
    /// Lazily built per-level tables (index = level).
    levels: Vec<OnceLock<LevelTables>>,
    /// Level-0 context (to rebuild per-level tables).
    context_q: Arc<Context>,
}

impl PartialEq for HybridParams {
    fn eq(&self, other: &Self) -> bool {
        self.special_moduli == other.special_moduli
            && self.alpha == other.alpha
            && self.dnum == other.dnum
    }
}

impl HybridParams {
    pub(crate) fn new(
        context_q: &Arc<Context>,
        special_moduli: &[u64],
        dnum: Option<usize>,
        degree: usize,
    ) -> Result<Self> {
        let q_moduli = context_q.moduli();
        let num_limbs = q_moduli.len();
        let k = special_moduli.len();
        if k == 0 {
            return Err(Error::DefaultError(
                "at least one special prime is required".into(),
            ));
        }
        for p in special_moduli {
            if q_moduli.contains(p) {
                return Err(Error::DefaultError(format!(
                    "special prime {p} is also a ciphertext modulus"
                )));
            }
        }
        // Coprimality of Q and P (and of the special primes among
        // themselves) is enforced by the RNS context constructor below.
        let context_p = Context::new_arc(special_moduli, degree)?;
        let _qp_rns = RnsContext::new(&[q_moduli, special_moduli].concat())?;

        let dnum = match dnum {
            None => num_limbs.div_ceil(k),
            Some(d) => {
                if d == 0 || d > num_limbs {
                    return Err(Error::DefaultError(format!(
                        "dnum must be in 1..={num_limbs}, got {d}"
                    )));
                }
                if d * k < num_limbs {
                    return Err(Error::DefaultError(format!(
                        "dnum·k = {}·{k} < L = {num_limbs}: a digit would exceed P (precision loss); \
                         add special primes or raise dnum",
                        d
                    )));
                }
                d
            }
        };
        let alpha = num_limbs.div_ceil(dnum);
        let dnum = num_limbs.div_ceil(alpha);

        let q_big = context_q.modulus().clone();
        let p_big = context_p.modulus().clone();
        let mut gadget: Vec<BigUint> = Vec::with_capacity(dnum);
        let mut p_gadget = Vec::with_capacity(dnum);
        for j in 0..dnum {
            let range = j * alpha..((j + 1) * alpha).min(num_limbs);
            let d_j = q_moduli[range]
                .iter()
                .fold(BigUint::one(), |acc, q| acc * BigUint::from(*q));
            let q_over_d = &q_big / &d_j;
            let inv = q_over_d.modinv(&d_j).ok_or_else(|| {
                Error::DefaultError("digit product not invertible (moduli not coprime)".into())
            })?;
            let g_j = (&q_over_d * inv) % &q_big;
            p_gadget.push((&g_j * &p_big) % &q_big);
            gadget.push(g_j);
        }

        let p_inv_mod_q = q_moduli
            .iter()
            .zip(context_q.moduli_operators().iter())
            .map(|(q, qi)| {
                let p_mod_qi: u64 = (&p_big % BigUint::from(*q))
                    .try_into()
                    .map_err(|_| Error::DefaultError("P mod q_i does not fit in u64".into()))?;
                qi.inv(p_mod_qi)
                    .ok_or_else(|| Error::DefaultError("P not invertible mod q_i".into()))
            })
            .collect::<Result<Vec<u64>>>()?;

        Ok(Self {
            special_moduli: special_moduli.into(),
            context_p,
            alpha,
            dnum,
            gadget,
            p_gadget,
            p_inv_mod_q,
            levels: (0..num_limbs).map(|_| OnceLock::new()).collect(),
            context_q: context_q.clone(),
        })
    }

    /// `g_j` (plain CRT gadget).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn gadget(&self, j: usize) -> &BigUint {
        &self.gadget[j]
    }

    /// `P·g_j` (mod `Q`).
    pub(crate) fn p_gadget(&self, j: usize) -> &BigUint {
        &self.p_gadget[j]
    }

    /// Per-level tables (built on first use).
    fn level(&self, ctx_l: &Arc<Context>) -> Result<&LevelTables> {
        let num_limbs_l = ctx_l.moduli().len();
        let level = self.context_q.moduli().len() - num_limbs_l;
        let slot = self
            .levels
            .get(level)
            .ok_or_else(|| Error::DefaultError("level out of range".into()))?;
        if let Some(t) = slot.get() {
            return Ok(t);
        }
        let built = self.build_level(ctx_l)?;
        Ok(slot.get_or_init(|| built))
    }

    fn build_level(&self, ctx_l: &Arc<Context>) -> Result<LevelTables> {
        let num_limbs_l = ctx_l.moduli().len();
        let digits: Vec<Range<usize>> = (0..num_limbs_l.div_ceil(self.alpha))
            .map(|j| j * self.alpha..((j + 1) * self.alpha).min(num_limbs_l))
            .collect();
        let rns_q = &ctx_l.rns;
        let rns_p = &self.context_p.rns;
        let mut up_q = Vec::with_capacity(digits.len());
        let mut up_p = Vec::with_capacity(digits.len());
        for r in &digits {
            let rns_d = Arc::new(RnsContext::new(&ctx_l.moduli()[r.clone()])?);
            up_q.push(RnsScaler::new(&rns_d, rns_q, ScalingFactor::one()));
            up_p.push(RnsScaler::new(&rns_d, rns_p, ScalingFactor::one()));
        }
        let down = RnsScaler::new(rns_p, rns_q, ScalingFactor::one());
        Ok(LevelTables {
            digits,
            up_q,
            up_p,
            down,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Q·P elements
// ─────────────────────────────────────────────────────────────────────────────

/// An element of `R_{Q·P}` in NTT form, stored as its `Q`-part (over the
/// level-0 ciphertext context) and its `P`-part (over the special-prime
/// context). Public key material: `Debug` is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkksQpPoly {
    pub(crate) q: Poly<Ntt>,
    pub(crate) p: Poly<Ntt>,
}

impl Zeroize for CkksQpPoly {
    fn zeroize(&mut self) {
        self.q.zeroize();
        self.p.zeroize();
    }
}

impl CkksQpPoly {
    /// The `Q`-part (over the level-0 context).
    #[must_use]
    pub fn q(&self) -> &Poly<Ntt> {
        &self.q
    }

    /// The `P`-part (over the special-prime context).
    #[must_use]
    pub fn p(&self) -> &Poly<Ntt> {
        &self.p
    }

    /// Uniform element from a seed (CRP / key `a`).
    pub(crate) fn random_from_seed(par: &CkksParameters, seed: [u8; 32]) -> Result<Self> {
        let h = par.hybrid()?;
        let mut rng = ChaCha8Rng::from_seed(seed);
        let mut seed_q = [0u8; 32];
        let mut seed_p = [0u8; 32];
        rng.fill_bytes(&mut seed_q);
        rng.fill_bytes(&mut seed_p);
        Ok(Self {
            q: Poly::<Ntt>::random_from_seed(&par.context, seed_q),
            p: Poly::<Ntt>::random_from_seed(&h.context_p, seed_p),
        })
    }

    /// The SAME small integer polynomial reduced mod `Q` and mod `P`.
    pub(crate) fn from_small_coeffs(par: &CkksParameters, coeffs: &[i64]) -> Result<Self> {
        let h = par.hybrid()?;
        Ok(Self {
            q: Poly::<PowerBasis>::try_convert_from(coeffs, &par.context, false)?.into_ntt(),
            p: Poly::<PowerBasis>::try_convert_from(coeffs, &h.context_p, false)?.into_ntt(),
        })
    }

    /// Fresh error `e` with the parameter variance, over both parts.
    pub(crate) fn small<R: RngCore + CryptoRng>(par: &CkksParameters, rng: &mut R) -> Result<Self> {
        let coeffs = Zeroizing::new(
            fhe_util::sample_vec_cbd(par.degree(), par.variance, rng)
                .map_err(|e| Error::DefaultError(e.to_string()))?,
        );
        Self::from_small_coeffs(par, &coeffs)
    }

    pub(crate) fn add_assign(&mut self, o: &Self) {
        self.q += &o.q;
        self.p += &o.p;
    }

    pub(crate) fn sub_assign(&mut self, o: &Self) {
        self.q -= &o.q;
        self.p -= &o.p;
    }

    /// Component-wise product with another `Q·P` element.
    pub(crate) fn mul(&self, o: &Self) -> Self {
        Self {
            q: &self.q * &o.q,
            p: &self.p * &o.p,
        }
    }

    pub(crate) fn neg(&self) -> Self {
        Self {
            q: -&self.q,
            p: -&self.p,
        }
    }

    /// Multiply the `Q`-part by a scalar (the `P`-part of `P·g_j` is 0, so
    /// the `P`-part is zeroed).
    pub(crate) fn mul_scalar_q_only(&self, c: &BigUint) -> Self {
        Self {
            q: &self.q * c,
            p: Poly::<Ntt>::zero(self.p.ctx()),
        }
    }

    pub(crate) fn disallow_variable_time(&mut self) {
        self.q.disallow_variable_time_computations();
        self.p.disallow_variable_time_computations();
    }

    pub(crate) fn allow_variable_time(&mut self) {
        unsafe {
            self.q.allow_variable_time_computations();
            self.p.allow_variable_time_computations();
        }
    }

    /// The `Q`-part restricted to the first `num_limbs` limbs (NTT rows are
    /// per-limb, so this is a row truncation).
    fn q_at(&self, ctx_l: &Arc<Context>) -> Poly<Ntt> {
        let keep = ctx_l.moduli().len();
        let mut out = Poly::<Ntt>::zero(ctx_l);
        out.set_coefficients(self.q.coefficients().slice(s![..keep, ..]).to_owned());
        unsafe { out.allow_variable_time_computations() }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Key-switching key
// ─────────────────────────────────────────────────────────────────────────────

/// Hybrid key-switching key `s' → s`: `dnum` pairs `(b_j, a_j)` over
/// `R_{Q·P}` with `b_j = -a_j·s + P·g_j·s' + e_j`. Serves every level.
#[derive(Debug, Clone)]
pub struct CkksHybridKeySwitchKey {
    par: Arc<CkksParameters>,
    /// `b_j` (the `c0` side).
    b: Box<[CkksQpPoly]>,
    /// `a_j` (the `c1` side).
    a: Box<[CkksQpPoly]>,
}

impl CkksHybridKeySwitchKey {
    /// Assemble a key from its elements (multiparty aggregation, wire).
    pub(crate) fn from_parts(
        par: Arc<CkksParameters>,
        b: Vec<CkksQpPoly>,
        a: Vec<CkksQpPoly>,
    ) -> Result<Self> {
        let dnum = par.dnum();
        if dnum == 0 || b.len() != dnum || a.len() != dnum {
            return Err(Error::DefaultError(format!(
                "hybrid key needs dnum = {dnum} digits, got {}/{}",
                b.len(),
                a.len()
            )));
        }
        Ok(Self {
            par,
            b: b.into_boxed_slice(),
            a: a.into_boxed_slice(),
        })
    }

    /// Generate a key switching from the secret `s'` (given as the small
    /// integer coefficients of a ring element, e.g. another party's secret
    /// key) to `sk`.
    pub fn new<R: RngCore + CryptoRng>(
        s_from: &[i64],
        sk: &CkksSecretKey,
        rng: &mut R,
    ) -> Result<Self> {
        let par = sk.par.clone();
        let s_prime = Zeroizing::new(CkksQpPoly::from_small_coeffs(&par, s_from)?);
        Self::new_from_qp(&s_prime, sk, rng)
    }

    /// Generate a key switching from `s'` given directly as a `Q·P` element
    /// (used for `s' = s²`).
    pub(crate) fn new_from_qp<R: RngCore + CryptoRng>(
        s_prime: &CkksQpPoly,
        sk: &CkksSecretKey,
        rng: &mut R,
    ) -> Result<Self> {
        let par = sk.par.clone();
        let h = par.hybrid()?;
        let s = Zeroizing::new(CkksQpPoly::from_small_coeffs(&par, sk.coeffs.as_ref())?);

        let mut b = Vec::with_capacity(h.dnum);
        let mut a = Vec::with_capacity(h.dnum);
        for j in 0..h.dnum {
            let mut seed = [0u8; 32];
            rng.fill(&mut seed);
            let a_j = CkksQpPoly::random_from_seed(&par, seed)?;

            // b_j = -a_j*s + P*g_j*s' + e_j
            let mut b_j = a_j.neg();
            b_j.disallow_variable_time();
            b_j = b_j.mul(&s);
            b_j.add_assign(&s_prime.mul_scalar_q_only(h.p_gadget(j)));
            b_j.add_assign(&CkksQpPoly::small(&par, rng)?);
            b_j.allow_variable_time();
            let mut a_j = a_j;
            a_j.allow_variable_time();
            b.push(b_j);
            a.push(a_j);
        }
        Ok(Self {
            par,
            b: b.into_boxed_slice(),
            a: a.into_boxed_slice(),
        })
    }

    /// Returns the parameters of this key.
    #[must_use]
    pub fn parameters(&self) -> &Arc<CkksParameters> {
        &self.par
    }

    /// Number of gadget digits.
    #[must_use]
    pub fn dnum(&self) -> usize {
        self.b.len()
    }

    /// The `b_j` elements.
    #[must_use]
    pub fn b(&self) -> &[CkksQpPoly] {
        &self.b
    }

    /// The `a_j` elements.
    #[must_use]
    pub fn a(&self) -> &[CkksQpPoly] {
        &self.a
    }

    /// Key-switch `c` (over `Q_ℓ`, any level, NTT form): returns
    /// `(k_0', k_1')` over `Q_ℓ` with `k_0' + k_1'·s ≈ c·s'`.
    pub fn key_switch(&self, c: &Poly<Ntt>) -> Result<(Poly<Ntt>, Poly<Ntt>)> {
        let h = self.par.hybrid()?;
        let ctx_l = c.ctx().clone();
        // The context must be a prefix of the level-0 chain.
        let num_limbs_l = ctx_l.moduli().len();
        if num_limbs_l > self.par.moduli.len() || ctx_l.moduli() != &self.par.moduli[..num_limbs_l]
        {
            return Err(Error::DefaultError(
                "key-switch input is not over a level of these parameters".into(),
            ));
        }
        let tables = h.level(&ctx_l)?;
        let ctx_p = &h.context_p;
        let degree = self.par.degree();
        let k = ctx_p.moduli().len();

        let c_pb = c.clone().into_power_basis();
        let c_coeffs = c_pb.coefficients();

        let mut k0_q = Poly::<Ntt>::zero(&ctx_l);
        let mut k1_q = Poly::<Ntt>::zero(&ctx_l);
        let mut k0_p = Poly::<Ntt>::zero(ctx_p);
        let mut k1_p = Poly::<Ntt>::zero(ctx_p);
        unsafe {
            k0_q.allow_variable_time_computations();
            k1_q.allow_variable_time_computations();
            k0_p.allow_variable_time_computations();
            k1_p.allow_variable_time_computations();
        }

        for (j, range) in tables.digits.iter().enumerate() {
            // Mod-up: digit residues -> all Q_l limbs and all P limbs.
            let digit_rows = c_coeffs.slice(s![range.clone(), ..]);
            let mut dq = Array2::<u64>::zeros((num_limbs_l, degree));
            let mut dp = Array2::<u64>::zeros((k, degree));
            izip!(
                dq.axis_iter_mut(Axis(1)),
                dp.axis_iter_mut(Axis(1)),
                digit_rows.axis_iter(Axis(1))
            )
            .for_each(|(oq, op, col)| {
                tables.up_q[j].scale(col, oq, 0);
                tables.up_p[j].scale(col, op, 0);
            });
            let mut d_q = Poly::<PowerBasis>::zero(&ctx_l);
            d_q.set_coefficients(dq);
            let mut d_p = Poly::<PowerBasis>::zero(ctx_p);
            d_p.set_coefficients(dp);
            unsafe {
                d_q.allow_variable_time_computations();
                d_p.allow_variable_time_computations();
            }
            let d_q = d_q.into_ntt();
            let d_p = d_p.into_ntt();

            // Inner product with the key restricted to (Q_l, P).
            k0_q += &(&d_q * &self.b[j].q_at(&ctx_l));
            k1_q += &(&d_q * &self.a[j].q_at(&ctx_l));
            k0_p += &(&d_p * &self.b[j].p);
            k1_p += &(&d_p * &self.a[j].p);
        }

        let k0 = Self::mod_down(&ctx_l, tables, &h.p_inv_mod_q[..num_limbs_l], k0_q, k0_p);
        let k1 = Self::mod_down(&ctx_l, tables, &h.p_inv_mod_q[..num_limbs_l], k1_q, k1_p);
        Ok((k0, k1))
    }

    /// `round(x/P)` over `Q_ℓ` from `x = (x_q, x_p) ∈ R_{Q_ℓ·P}`:
    /// `(x_q − [x_p]_P) · P^{-1} mod q_i`.
    fn mod_down(
        ctx_l: &Arc<Context>,
        tables: &LevelTables,
        p_inv: &[u64],
        x_q: Poly<Ntt>,
        x_p: Poly<Ntt>,
    ) -> Poly<Ntt> {
        let num_limbs_l = ctx_l.moduli().len();
        let degree = ctx_l.degree;
        let mut x_q = x_q.into_power_basis();
        let x_p = x_p.into_power_basis();
        let mut lift = Array2::<u64>::zeros((num_limbs_l, degree));
        izip!(
            lift.axis_iter_mut(Axis(1)),
            x_p.coefficients().axis_iter(Axis(1))
        )
        .for_each(|(o, col)| tables.down.scale(col, o, 0));
        let mut lift_poly = Poly::<PowerBasis>::zero(ctx_l);
        lift_poly.set_coefficients(lift);
        unsafe { lift_poly.allow_variable_time_computations() }
        x_q -= &lift_poly;
        let mut coeffs = x_q.coefficients().to_owned();
        izip!(
            coeffs.outer_iter_mut(),
            ctx_l.moduli_operators().iter(),
            p_inv.iter()
        )
        .for_each(|(mut row, qi, inv)| qi.scalar_mul_vec(row.as_slice_mut().unwrap(), *inv));
        let mut out = Poly::<PowerBasis>::zero(ctx_l);
        out.set_coefficients(coeffs);
        unsafe { out.allow_variable_time_computations() }
        out.into_ntt()
    }

    /// Serialize: `dnum | L | k | (len|poly)*` — `b_0.q, b_0.p, …, a_0.q, …`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_hybrid_polys(&self.par, &self.b, &self.a)
    }

    /// Deserialize a key produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8], par: &Arc<CkksParameters>) -> Result<Self> {
        let (b, a) = decode_hybrid_polys(bytes, par, "hybrid key")?;
        Self::from_parts(par.clone(), b, a)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Relinearization key
// ─────────────────────────────────────────────────────────────────────────────

/// Hybrid relinearization key (`s² → s`): ONE key for every level.
///
/// Noise: `≈ dnum·N·B_err·(D/P) + N/3` per relinearization (see the module
/// docs) — with `P ≥ max D_j` this is ~`q_max/…` smaller than the per-level
/// RNS-decomposition key and independent of the level. The multiparty
/// variant is produced by [`crate::trckks::CkksHybridRelinKeyGenerator`].
#[derive(Debug, Clone)]
pub struct CkksHybridRelinKey {
    ksk: CkksHybridKeySwitchKey,
}

impl CkksHybridRelinKey {
    /// Generate a hybrid relinearization key for `sk`.
    pub fn new<R: RngCore + CryptoRng>(sk: &CkksSecretKey, rng: &mut R) -> Result<Self> {
        let par = sk.par.clone();
        let s = Zeroizing::new(CkksQpPoly::from_small_coeffs(&par, sk.coeffs.as_ref())?);
        let s2 = Zeroizing::new(s.mul(&s));
        Ok(Self {
            ksk: CkksHybridKeySwitchKey::new_from_qp(&s2, sk, rng)?,
        })
    }

    /// Assemble from key-switching elements (multiparty aggregation).
    pub(crate) fn from_parts(
        par: Arc<CkksParameters>,
        b: Vec<CkksQpPoly>,
        a: Vec<CkksQpPoly>,
    ) -> Result<Self> {
        Ok(Self {
            ksk: CkksHybridKeySwitchKey::from_parts(par, b, a)?,
        })
    }

    /// Relinearize a three-component ciphertext AT ANY LEVEL in place.
    pub fn relinearizes(&self, ct: &mut CkksCiphertext) -> Result<()> {
        if ct.c.len() != 3 {
            return Err(Error::InvalidCiphertext {
                reason: format!("relinearization expects 3 components, got {}", ct.c.len()),
            });
        }
        if ct.par != self.ksk.par {
            return Err(Error::DefaultError(
                "ciphertext parameters do not match the hybrid relin key".into(),
            ));
        }
        let (k0, k1) = self.ksk.key_switch(&ct.c[2])?;
        ct.c[0] += &k0;
        ct.c[1] += &k1;
        ct.c.truncate(2);
        Ok(())
    }

    /// The underlying generic key-switching key.
    #[must_use]
    pub fn key_switch_key(&self) -> &CkksHybridKeySwitchKey {
        &self.ksk
    }

    /// Returns the parameters of this key.
    #[must_use]
    pub fn parameters(&self) -> &Arc<CkksParameters> {
        &self.ksk.par
    }

    /// Number of gadget digits.
    #[must_use]
    pub fn dnum(&self) -> usize {
        self.ksk.dnum()
    }

    /// Serialize (same framing as [`CkksHybridKeySwitchKey::to_bytes`]).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.ksk.to_bytes()
    }

    /// Deserialize a key produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8], par: &Arc<CkksParameters>) -> Result<Self> {
        Ok(Self {
            ksk: CkksHybridKeySwitchKey::from_bytes(bytes, par)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{CkksHybridKeySwitchKey, CkksHybridRelinKey};
    use crate::ckks::{
        CkksEncoder, CkksParameters, CkksParametersBuilder, CkksPublicKey, CkksRelinearizationKey,
        CkksSecretKey,
    };
    use fhe_math::rq::{Ntt, Poly, PowerBasis, traits::TryConvertFrom};
    use num_bigint::BigUint;
    use num_traits::Zero;
    use rand::rng;
    use std::error::Error;
    use std::sync::Arc;

    fn params(degree: usize, sizes: &[usize], special: &[usize]) -> Arc<CkksParameters> {
        CkksParametersBuilder::new()
            .set_degree(degree)
            .set_moduli_sizes(sizes)
            .set_special_moduli_sizes(special)
            .set_scale(2f64.powi(40))
            .build_arc()
            .unwrap()
    }

    /// Σ_j digit_j(c)·g_j ≡ c (mod Q) for random c, at level 0 AND at
    /// deeper levels with the level-0 gadget.
    #[test]
    fn gadget_identity_holds() -> std::result::Result<(), Box<dyn Error>> {
        let par = params(16, &[45, 40, 40, 40, 40], &[50, 50]);
        let h = par.hybrid()?;
        let mut rng = rng();
        for level in 0..par.moduli().len() {
            let ctx = par.context_at_level(level)?;
            let q_l = ctx.modulus();
            let c = Poly::<PowerBasis>::random(ctx, &mut rng);
            let c_big = Vec::<BigUint>::from(&c);
            let ranges = par.digit_ranges_at_level(level)?;
            for (coeff_idx, c_val) in c_big.iter().enumerate() {
                let mut acc = BigUint::zero();
                for (j, r) in ranges.iter().enumerate() {
                    // digit_j(c): CRT lift of the residues on the digit's limbs
                    // (non-negative representative is fine for the identity).
                    let rns_d = fhe_math::rns::RnsContext::new(&ctx.moduli()[r.clone()])?;
                    let rests: Vec<u64> = r
                        .clone()
                        .map(|i| c.coefficients()[[i, coeff_idx]])
                        .collect();
                    let digit = rns_d.lift(ndarray::ArrayView1::from(&rests));
                    acc += digit * (h.gadget(j) % q_l);
                }
                assert_eq!(&acc % q_l, *c_val, "level {level} coeff {coeff_idx}");
            }
            // g_j ≡ 1 on its own limbs, 0 elsewhere.
            for (j, r) in ranges.iter().enumerate() {
                for (i, q) in ctx.moduli().iter().enumerate() {
                    let g_mod = (h.gadget(j) % q).try_into().unwrap_or(u64::MAX);
                    assert_eq!(g_mod, u64::from(r.contains(&i)), "g_{j} mod q_{i}");
                }
            }
        }
        Ok(())
    }

    /// One hybrid key relinearizes correctly at EVERY level, matching the
    /// per-level RNS keys within tolerance.
    #[test]
    fn hybrid_relin_every_level_matches_per_level() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let par = params(64, &[45, 40, 40, 40, 40, 40], &[50, 50]);
        assert_eq!(par.dnum(), 3);
        let encoder = CkksEncoder::new(&par);
        let sk = CkksSecretKey::random(&par, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng)?;
        let hk = CkksHybridRelinKey::new(&sk, &mut rng)?;
        let x = vec![1.5, -2.0, 0.75];
        let ct = pk.try_encrypt(&encoder.encode(&x, 0)?, &mut rng)?;
        for level in 0..par.moduli().len() - 1 {
            let rk = CkksRelinearizationKey::new_leveled(&sk, level, &mut rng)?;
            let mut op = ct.clone();
            op.mod_switch_to_level(level)?;
            let prod = op.try_mul(&op)?;
            let mut a = prod.clone();
            hk.relinearizes(&mut a)?;
            assert_eq!(a.len(), 2);
            let mut b = prod;
            rk.relinearizes(&mut b)?;
            let da = encoder.decode(&sk.try_decrypt(&a)?)?;
            let db = encoder.decode(&sk.try_decrypt(&b)?)?;
            for (i, xi) in x.iter().enumerate() {
                assert!(
                    (da[i] - xi * xi).abs() < 1e-3,
                    "hybrid level {level} slot {i}: {}",
                    da[i]
                );
                assert!((da[i] - db[i]).abs() < 1e-2, "level {level} slot {i}");
            }
        }
        Ok(())
    }

    /// Generic key switch `s' -> s`: a ciphertext under `sk1` re-keyed to
    /// `sk2` decrypts under `sk2`.
    #[test]
    fn generic_key_switch_rekeys_ciphertext() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let par = params(64, &[45, 40, 40], &[50]);
        let encoder = CkksEncoder::new(&par);
        let sk1 = CkksSecretKey::random(&par, &mut rng);
        let sk2 = CkksSecretKey::random(&par, &mut rng);
        let pk1 = CkksPublicKey::new(&sk1, &mut rng)?;
        let ksk = CkksHybridKeySwitchKey::new(sk1.coeffs.as_ref(), &sk2, &mut rng)?;
        let x = vec![3.25, -1.0];
        let mut ct = pk1.try_encrypt(&encoder.encode(&x, 0)?, &mut rng)?;
        ct.mod_switch_to_level(1)?;
        // (c0, c1) under s1 -> (c0 + k0, k1) under s2 with k0 + k1 s2 ~ c1 s1.
        let (k0, k1) = ksk.key_switch(&ct[1])?;
        let mut out = ct.clone();
        out.c[0] += &k0;
        out.c[1] = k1;
        let d = encoder.decode(&sk2.try_decrypt(&out)?)?;
        for (i, xi) in x.iter().enumerate() {
            assert!((d[i] - xi).abs() < 1e-3, "slot {i}: {}", d[i]);
        }
        // Wrong-params input (different moduli chain) rejected.
        let other = params(64, &[44, 41, 41], &[50]);
        let ctx = other.context_at_level(0)?;
        let bad = Poly::<Ntt>::random(ctx, &mut rng);
        assert!(ksk.key_switch(&bad).is_err());
        // Non-3-component ciphertext rejected by relin.
        let hk = CkksHybridRelinKey::new(&sk2, &mut rng)?;
        assert!(hk.relinearizes(&mut out).is_err());
        Ok(())
    }

    /// Wire round-trip + truncation / wrong-shape rejection; hybrid must be
    /// enabled on the parameters.
    #[test]
    fn wire_round_trip_and_rejections() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let par = params(32, &[45, 40, 40, 40], &[50, 50]);
        let sk = CkksSecretKey::random(&par, &mut rng);
        let hk = CkksHybridRelinKey::new(&sk, &mut rng)?;
        let bytes = hk.to_bytes();
        let back = CkksHybridRelinKey::from_bytes(&bytes, &par)?;
        assert_eq!(back.to_bytes(), bytes);
        assert_eq!(back.dnum(), 2);
        assert!(CkksHybridRelinKey::from_bytes(&bytes[..bytes.len() - 1], &par).is_err());
        let mut ext = bytes.clone();
        ext.push(0);
        assert!(CkksHybridRelinKey::from_bytes(&ext, &par).is_err());
        // Different dnum / special primes => rejected.
        let other = CkksParametersBuilder::new()
            .set_degree(32)
            .set_moduli(par.moduli())
            .set_special_moduli_sizes(&[50, 50])
            .set_dnum(4)
            .set_scale(2f64.powi(40))
            .build_arc()?;
        assert!(CkksHybridRelinKey::from_bytes(&bytes, &other).is_err());
        // Hybrid disabled => key generation and decoding fail.
        let plain = CkksParametersBuilder::new()
            .set_degree(32)
            .set_moduli(par.moduli())
            .set_scale(2f64.powi(40))
            .build_arc()?;
        let sk_plain = CkksSecretKey::random(&plain, &mut rng);
        assert!(CkksHybridRelinKey::new(&sk_plain, &mut rng).is_err());
        assert!(CkksHybridRelinKey::from_bytes(&bytes, &plain).is_err());
        // Key built for other params rejects this ciphertext.
        let encoder = CkksEncoder::new(&plain);
        let pk = CkksPublicKey::new(&sk_plain, &mut rng)?;
        let ct = pk.try_encrypt(&encoder.encode(&[1.0], 0)?, &mut rng)?;
        let mut prod = ct.try_mul(&ct)?;
        assert!(hk.relinearizes(&mut prod).is_err());
        Ok(())
    }

    /// Sign-extraction-shaped chain at the interfold ladder: 45-bit base +
    /// 37×40-bit limbs, Δ = 2^40, k special primes; 12 iterations of
    /// f(y) = (1.5 − 0.5·y²)·y with ONE hybrid key drive ±0.9 to ±1.
    #[test]
    fn single_key_sign_extraction_ladder_n512() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let mut sizes = vec![45usize];
        sizes.extend(std::iter::repeat_n(40usize, 37));
        let par = CkksParametersBuilder::new()
            .set_degree(512)
            .set_moduli_sizes(&sizes)
            .set_special_moduli_sizes(&[60, 60, 60])
            .set_scale(2f64.powi(40))
            .build_arc()?;
        assert_eq!(par.dnum(), 13);
        let encoder = CkksEncoder::new(&par);
        let sk = CkksSecretKey::random(&par, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng)?;
        let hk = CkksHybridRelinKey::new(&sk, &mut rng)?;

        let inputs = vec![0.9, -0.9, 0.5, -0.3, 0.05, -0.02];
        let mut y = pk.try_encrypt(&encoder.encode(&inputs, 0)?, &mut rng)?;
        // Mirror the policy's level schedule: mults at levels 1+3i and 3+3i.
        y.mod_switch_to_level(1)?;
        for _ in 0..12 {
            // y2 = y*y (relin, rescale)
            let mut y2 = y.try_mul(&y)?;
            hk.relinearizes(&mut y2)?;
            y2.rescale()?;
            // t = 1.5 - 0.5*y2  (plaintext mul by -0.5 at scale Δ, rescale, add 1.5)
            let half = encoder.encode_with_scale(&[-0.5; 256], y2.level, par.scale())?;
            let mut t = y2.try_mul_plaintext(&half)?;
            t.rescale()?;
            let one_half = encoder.encode_with_scale(&[1.5; 256], t.level, t.scale)?;
            let t = t.try_add_plaintext(&one_half)?;
            // y = t * y (relin, rescale)
            let mut y_aligned = y.clone();
            y_aligned.mod_switch_to_level(t.level)?;
            let mut next = t.try_mul(&y_aligned)?;
            hk.relinearizes(&mut next)?;
            next.rescale()?;
            y = next;
        }
        let out = encoder.decode(&sk.try_decrypt(&y)?)?;
        for (i, x) in inputs.iter().enumerate() {
            let expected = x.signum();
            assert!(
                (out[i] - expected).abs() < 0.05,
                "slot {i}: {} vs {expected}",
                out[i]
            );
        }
        Ok(())
    }

    /// Size proof: the single hybrid key is far smaller than the summed
    /// per-level keys — at most `(dnum·(L+k)/Σ L_ℓ² + 5 %)` of them.
    #[test]
    fn hybrid_key_size_bound() -> std::result::Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let par = params(64, &[45, 40, 40, 40, 40, 40, 40, 40], &[50, 50]);
        let sk = CkksSecretKey::random(&par, &mut rng);
        let hk = CkksHybridRelinKey::new(&sk, &mut rng)?;
        let hybrid_bytes = hk.to_bytes().len();
        let num_limbs = par.moduli().len();
        let k = par.special_moduli().len();
        let mut summed = 0usize;
        let mut sum_sq = 0usize;
        for level in 0..num_limbs - 1 {
            summed += CkksRelinearizationKey::new_leveled(&sk, level, &mut rng)?
                .to_bytes()
                .len();
            sum_sq += (num_limbs - level).pow(2);
        }
        let ratio = par.dnum() as f64 * (num_limbs + k) as f64 / sum_sq as f64;
        assert!(
            (hybrid_bytes as f64) <= (ratio + 0.05) * summed as f64,
            "hybrid {hybrid_bytes} B vs summed per-level {summed} B (bound ratio {ratio:.3})"
        );
        // And smaller than the level-0 key alone.
        let level0 = CkksRelinearizationKey::new(&sk, &mut rng)?.to_bytes().len();
        assert!(hybrid_bytes < level0, "{hybrid_bytes} vs level-0 {level0}");
        Ok(())
    }

    #[test]
    fn qp_poly_conversion_is_consistent() -> std::result::Result<(), Box<dyn Error>> {
        let par = params(16, &[45, 40], &[50]);
        let coeffs: Vec<i64> = (0..16).map(|i| i - 8).collect();
        let qp = super::CkksQpPoly::from_small_coeffs(&par, &coeffs)?;
        let q = Poly::<PowerBasis>::try_convert_from(coeffs.as_slice(), &par.context, false)?
            .into_ntt();
        assert_eq!(qp.q(), &q);
        assert_eq!(qp.p().ctx().moduli(), par.special_moduli());
        Ok(())
    }
}
