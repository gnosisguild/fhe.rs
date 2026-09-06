//! Multiparty HYBRID relinearization key generation for threshold CKKS.
//!
//! The two-round CRP protocol `RelinKeyGen` of Mouchet et al.
//! (<https://eprint.iacr.org/2020/304>, Protocol 2) — the same protocol as
//! [`crate::trckks::CkksRelinKeyGenerator`] — instantiated with the hybrid
//! gadget of [`crate::ckks::hybrid`] (Han–Ki 2019/688; Lattigo `RKGProtocol`
//! over `Q·P`). All key material lives over `Q·P` (as `(Q, P)` pairs,
//! [`CkksQpPoly`]) and there are `dnum` digits instead of `L_ℓ`, so ONE
//! ceremony yields a key for EVERY level. With `a_j` the `dnum` CRPs over
//! `Q·P` and `P·g_j` the hybrid gadget constants (`Q`-part only):
//!
//! - Round 1: party `i` publishes
//!   `h0_i[j] = -a_j·u_i + P·g_j·s_i + e0` and `h1_i[j] = a_j·s_i + e1`.
//! - Aggregate: `h0[j] = -a_j·u + P·g_j·s + e0`, `h1[j] = a_j·s + e1`
//!   (`u = Σ u_i`, `s = Σ s_i`).
//! - Round 2: party `i` publishes
//!   `h0'_i[j] = h0[j]·s_i + e` and `h1'_i[j] = h1[j]·(u_i − s_i) + e`.
//! - Aggregate: `b_j = Σ_i h0'_i[j] + Σ_i h1'_i[j] = -h1[j]·s + P·g_j·s² + e'`
//!   and `a_j := h1[j]`, i.e. exactly a [`CkksHybridRelinKey`] digit
//!   `(b_j, a_j)` with `b_j + a_j·s = P·g_j·s² + e'` for the joint secret.
//!
//! The same ephemeral `u_i` MUST be used in both rounds
//! ([`CkksHybridRelinKeyGenerator::new_from_seed`] supports state machines).
//! Shares carry `(dnum, L, k)` and aggregation rejects mismatches. No
//! zero-knowledge proofs cover the ceremony (verify by determinism, as for
//! the per-level protocol).

use crate::ckks::hybrid::CkksQpPoly;
use crate::ckks::wire::{decode_hybrid_polys, encode_hybrid_polys};
use crate::ckks::{CkksHybridRelinKey, CkksParameters, CkksSecretKey};
use crate::trckks::relin_gen::{R1, R1Aggregated, R2};
use crate::{Error, Result};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::marker::PhantomData;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// A party's share in the hybrid relinearization key protocol (PUBLIC
/// protocol message; `Debug` is safe to log).
#[derive(Debug, Clone)]
pub struct CkksHybridRelinKeyShare<Round = R1> {
    pub(crate) par: Arc<CkksParameters>,
    pub(crate) h0: Box<[CkksQpPoly]>,
    pub(crate) h1: Box<[CkksQpPoly]>,
    last_round: Option<Arc<CkksHybridRelinKeyShare<R1Aggregated>>>,
    _phantom: PhantomData<Round>,
}

/// Per-party generator for the two-round hybrid relinearization protocol.
///
/// Holds the party's secret-key share (by reference) and the ephemeral
/// secret `u` (zeroized on drop; `Debug` redacts both).
pub struct CkksHybridRelinKeyGenerator<'a, 'b> {
    sk_share: &'a CkksSecretKey,
    crp: &'b [CkksQpPoly],
    u: Zeroizing<CkksQpPoly>,
}

impl std::fmt::Debug for CkksHybridRelinKeyGenerator<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksHybridRelinKeyGenerator")
            .field("dnum", &self.crp.len())
            .field("sk_share", &"<redacted>")
            .field("u", &"<redacted>")
            .finish()
    }
}

impl<'a, 'b> CkksHybridRelinKeyGenerator<'a, 'b> {
    /// Create a generator for this party. `crp` must be the `dnum` CRPs
    /// over `Q·P` from [`crate::trckks::CkksCrp::vec_from_seed_qp`].
    pub fn new<R: RngCore + CryptoRng>(
        sk_share: &'a CkksSecretKey,
        crp: &'b [CkksQpPoly],
        rng: &mut R,
    ) -> Result<Self> {
        Self::validate(sk_share, crp)?;
        let u = Zeroizing::new(CkksQpPoly::small(&sk_share.par, rng)?);
        Ok(Self { sk_share, crp, u })
    }

    /// Create a generator with the ephemeral secret `u` derived
    /// deterministically from `u_seed` (domain-separated from the per-level
    /// protocol's seeds).
    ///
    /// `u_seed` must be a fresh, SECRET, per-party, per-ceremony value;
    /// zeroize it once the ceremony completes. `_rng` is unused (signature
    /// symmetry with [`Self::new`]); round noise comes from the RNG passed
    /// to `round_1` / `round_2`.
    pub fn new_from_seed<R: RngCore + CryptoRng>(
        sk_share: &'a CkksSecretKey,
        crp: &'b [CkksQpPoly],
        u_seed: [u8; 32],
        _rng: &mut R,
    ) -> Result<Self> {
        Self::validate(sk_share, crp)?;
        let mut seed = u_seed;
        // Distinct from every per-level seed (`level ^ 0x00..`): flip the
        // top bytes.
        seed[30] ^= 0x48;
        seed[31] ^= 0x59;
        let mut u_rng = ChaCha8Rng::from_seed(seed);
        let u = Zeroizing::new(CkksQpPoly::small(&sk_share.par, &mut u_rng)?);
        seed.zeroize();
        Ok(Self { sk_share, crp, u })
    }

    fn validate(sk_share: &CkksSecretKey, crp: &[CkksQpPoly]) -> Result<()> {
        let par = &sk_share.par;
        let dnum = par.dnum();
        if dnum == 0 {
            return Err(Error::DefaultError(
                "hybrid key switching is not enabled on these parameters".into(),
            ));
        }
        if crp.len() != dnum {
            return Err(Error::DefaultError(format!(
                "the CRP vector must have dnum = {dnum} elements, got {}",
                crp.len()
            )));
        }
        let ctx_p = par.context_p()?;
        if crp
            .iter()
            .any(|c| c.q.ctx() != &par.context || c.p.ctx() != ctx_p)
        {
            return Err(Error::DefaultError(
                "CRP elements are not over these parameters' Q·P".into(),
            ));
        }
        Ok(())
    }

    /// Generate this party's round-1 share.
    pub fn round_1<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<CkksHybridRelinKeyShare<R1>> {
        let par = self.sk_share.par.clone();
        let h = par.hybrid()?;
        let s = Zeroizing::new(CkksQpPoly::from_small_coeffs(
            &par,
            self.sk_share.coeffs.as_ref(),
        )?);
        let mut h0 = Vec::with_capacity(self.crp.len());
        let mut h1 = Vec::with_capacity(self.crp.len());
        for (j, a) in self.crp.iter().enumerate() {
            // h0 = -a*u + P*g_j*s + e0
            let mut x = a.neg();
            x.disallow_variable_time();
            x = x.mul(&self.u);
            x.add_assign(&s.mul_scalar_q_only(h.p_gadget(j)));
            x.add_assign(&CkksQpPoly::small(&par, rng)?);
            h0.push(x);
            // h1 = a*s + e1
            let mut y = a.clone();
            y.disallow_variable_time();
            y = y.mul(&s);
            y.add_assign(&CkksQpPoly::small(&par, rng)?);
            h1.push(y);
        }
        Ok(CkksHybridRelinKeyShare {
            par,
            h0: h0.into_boxed_slice(),
            h1: h1.into_boxed_slice(),
            last_round: None,
            _phantom: PhantomData,
        })
    }

    /// Generate this party's round-2 share from the aggregated round 1.
    pub fn round_2<R: RngCore + CryptoRng>(
        &self,
        r1: &Arc<CkksHybridRelinKeyShare<R1Aggregated>>,
        rng: &mut R,
    ) -> Result<CkksHybridRelinKeyShare<R2>> {
        let par = self.sk_share.par.clone();
        if r1.par != par || r1.h0.len() != self.crp.len() {
            return Err(Error::DefaultError(
                "round-1 aggregation does not match this generator's parameters".into(),
            ));
        }
        let s = Zeroizing::new(CkksQpPoly::from_small_coeffs(
            &par,
            self.sk_share.coeffs.as_ref(),
        )?);
        let mut u_minus_s = Zeroizing::new((*self.u).clone());
        u_minus_s.sub_assign(&s);

        let mut h0 = Vec::with_capacity(r1.h0.len());
        for h in r1.h0.iter() {
            let mut x = h.clone();
            x.disallow_variable_time();
            x = x.mul(&s);
            x.add_assign(&CkksQpPoly::small(&par, rng)?);
            h0.push(x);
        }
        let mut h1 = Vec::with_capacity(r1.h1.len());
        for h in r1.h1.iter() {
            let mut y = h.clone();
            y.disallow_variable_time();
            y = y.mul(&u_minus_s);
            y.add_assign(&CkksQpPoly::small(&par, rng)?);
            h1.push(y);
        }
        Ok(CkksHybridRelinKeyShare {
            par,
            h0: h0.into_boxed_slice(),
            h1: h1.into_boxed_slice(),
            last_round: Some(Arc::clone(r1)),
            _phantom: PhantomData,
        })
    }
}

impl<Round> CkksHybridRelinKeyShare<Round> {
    /// Serialize this share (hybrid framing of [`crate::ckks::wire`]). The
    /// round-1 back-reference of an R2 share is NOT serialized — reattach
    /// it via [`CkksHybridRelinKeyShare::aggregate_into_key_with_r1`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_hybrid_polys(&self.par, &self.h0, &self.h1)
    }

    /// Deserialize a share produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8], par: &Arc<CkksParameters>) -> Result<Self> {
        let (h0, h1) = decode_hybrid_polys(bytes, par, "hybrid relin share")?;
        Ok(Self {
            par: par.clone(),
            h0: h0.into_boxed_slice(),
            h1: h1.into_boxed_slice(),
            last_round: None,
            _phantom: PhantomData,
        })
    }

    /// Number of gadget digits.
    #[must_use]
    pub fn dnum(&self) -> usize {
        self.h0.len()
    }

    /// The `h0` elements (one per digit).
    #[must_use]
    pub fn h0(&self) -> &[CkksQpPoly] {
        &self.h0
    }

    /// The `h1` elements (one per digit).
    #[must_use]
    pub fn h1(&self) -> &[CkksQpPoly] {
        &self.h1
    }

    fn check_same_shape(&self, other: &CkksHybridRelinKeyShare<impl Sized>) -> Result<()> {
        if self.par != other.par || self.h0.len() != other.h0.len() {
            return Err(Error::DefaultError(
                "cannot aggregate hybrid relin shares with different parameters".into(),
            ));
        }
        Ok(())
    }
}

impl CkksHybridRelinKeyShare<R1Aggregated> {
    /// Aggregate round-1 shares.
    pub fn from_shares(shares: Vec<CkksHybridRelinKeyShare<R1>>) -> Result<Self> {
        let mut iter = shares.into_iter();
        let share = iter.next().ok_or(Error::TooFewValues {
            actual: 0,
            minimum: 1,
        })?;
        let mut h0 = share.h0;
        let mut h1 = share.h1;
        for sh in iter {
            if share.par != sh.par || sh.h0.len() != h0.len() {
                return Err(Error::DefaultError(
                    "cannot aggregate hybrid relin shares with different parameters".into(),
                ));
            }
            for (a, b) in h0.iter_mut().zip(sh.h0.iter()) {
                a.add_assign(b);
            }
            for (a, b) in h1.iter_mut().zip(sh.h1.iter()) {
                a.add_assign(b);
            }
        }
        Ok(Self {
            par: share.par,
            h0,
            h1,
            last_round: None,
            _phantom: PhantomData,
        })
    }
}

impl CkksHybridRelinKeyShare<R2> {
    /// Aggregate round-2 shares into the joint key, supplying the round-1
    /// aggregation explicitly (wire shares lose the back-reference).
    pub fn aggregate_into_key_with_r1(
        mut shares: Vec<Self>,
        r1: Arc<CkksHybridRelinKeyShare<R1Aggregated>>,
    ) -> Result<CkksHybridRelinKey> {
        for sh in &mut shares {
            sh.check_same_shape(&r1)?;
            sh.last_round = Some(Arc::clone(&r1));
        }
        Self::aggregate_into_key(shares)
    }

    /// Aggregate round-2 shares into the joint [`CkksHybridRelinKey`].
    pub fn aggregate_into_key(shares: Vec<Self>) -> Result<CkksHybridRelinKey> {
        let mut iter = shares.into_iter();
        let share = iter.next().ok_or(Error::TooFewValues {
            actual: 0,
            minimum: 1,
        })?;
        let par = share.par.clone();
        let r1 = share.last_round.clone().ok_or(Error::DefaultError(
            "round-2 shares must carry the round-1 aggregation".to_string(),
        ))?;
        let mut h0 = share.h0;
        let mut h1 = share.h1;
        for sh in iter {
            if sh.par != par || sh.h0.len() != h0.len() {
                return Err(Error::DefaultError(
                    "cannot aggregate hybrid relin shares with different parameters".into(),
                ));
            }
            for (a, b) in h0.iter_mut().zip(sh.h0.iter()) {
                a.add_assign(b);
            }
            for (a, b) in h1.iter_mut().zip(sh.h1.iter()) {
                a.add_assign(b);
            }
        }
        // b_j = Σ h0' + Σ h1' ;  a_j = h1 (round-1 aggregate).
        let mut b = Vec::from(h0);
        for (bj, h1j) in b.iter_mut().zip(h1.iter()) {
            bj.add_assign(h1j);
            bj.allow_variable_time();
        }
        let a = r1
            .h1
            .iter()
            .map(|x| {
                let mut x = x.clone();
                x.allow_variable_time();
                x
            })
            .collect::<Vec<_>>();
        CkksHybridRelinKey::from_parts(par, b, a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckks::{CkksEncoder, CkksParameters, CkksParametersBuilder, CkksRelinearizationKey};
    use crate::trckks::TRCKKS;
    use crate::trckks::keygen::{CkksCrp, CkksPublicKeyShare};
    use crate::trckks::relin_gen::{CkksRelinKeyGenerator, CkksRelinKeyShare};
    use ndarray::Array2;
    use rand::rng;
    use std::error::Error as StdError;

    fn collect(matrices: &[Vec<Array2<u64>>], j: usize) -> Vec<Array2<u64>> {
        matrices
            .iter()
            .map(|dealer| {
                let mut arr = Array2::<u64>::zeros((dealer.len(), dealer[0].ncols()));
                for (r, m) in dealer.iter().enumerate() {
                    arr.row_mut(r).assign(&m.row(j));
                }
                arr
            })
            .collect()
    }

    /// Run the hybrid ceremony for `sks` (optionally through the wire).
    fn hybrid_ceremony(
        params: &Arc<CkksParameters>,
        sks: &[CkksSecretKey],
        via_wire: bool,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<CkksHybridRelinKey> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let crp = CkksCrp::vec_from_seed_qp(params, seed)?;
        let generators = sks
            .iter()
            .map(|sk| CkksHybridRelinKeyGenerator::new(sk, &crp, rng))
            .collect::<Result<Vec<_>>>()?;
        let r1: Vec<_> = generators
            .iter()
            .map(|g| {
                let s = g.round_1(rng)?;
                if via_wire {
                    CkksHybridRelinKeyShare::<R1>::from_bytes(&s.to_bytes(), params)
                } else {
                    Ok(s)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let r1_agg = Arc::new(CkksHybridRelinKeyShare::<R1Aggregated>::from_shares(r1)?);
        let r2: Vec<_> = generators
            .iter()
            .map(|g| g.round_2(&r1_agg, rng))
            .collect::<Result<Vec<_>>>()?;
        if via_wire {
            let r2 = r2
                .iter()
                .map(|s| CkksHybridRelinKeyShare::<R2>::from_bytes(&s.to_bytes(), params))
                .collect::<Result<Vec<_>>>()?;
            let r1_agg = Arc::new(CkksHybridRelinKeyShare::<R1Aggregated>::from_bytes(
                &r1_agg.to_bytes(),
                params,
            )?);
            let key = CkksHybridRelinKeyShare::<R2>::aggregate_into_key_with_r1(r2, r1_agg)?;
            CkksHybridRelinKey::from_bytes(&key.to_bytes(), params)
        } else {
            CkksHybridRelinKeyShare::<R2>::aggregate_into_key(r2)
        }
    }

    /// Per-level RNS ceremony (the existing protocol) at `level`.
    fn rns_ceremony(
        params: &Arc<CkksParameters>,
        sks: &[CkksSecretKey],
        level: usize,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<CkksRelinearizationKey> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let len = params.moduli().len() - level;
        let crp = CkksCrp::vec_from_seed_leveled(params, seed, len, level)?;
        let generators = sks
            .iter()
            .map(|sk| CkksRelinKeyGenerator::new_leveled(sk, &crp, level, rng))
            .collect::<Result<Vec<_>>>()?;
        let r1 = generators
            .iter()
            .map(|g| g.round_1(rng))
            .collect::<Result<Vec<_>>>()?;
        let r1_agg = Arc::new(CkksRelinKeyShare::<R1Aggregated>::from_shares(r1)?);
        let r2 = generators
            .iter()
            .map(|g| g.round_2(&r1_agg, rng))
            .collect::<Result<Vec<_>>>()?;
        CkksRelinKeyShare::<R2>::aggregate_into_key(r2)
    }

    /// PRECISION + SIZE PROOF at a secure-shaped ladder (N=8192, 45 + 7×40
    /// bits, Δ=2^40, n=5): a depth-4 chain with (a) per-level RNS keys and
    /// (b) ONE hybrid key. The hybrid error must be ≥ 10× smaller, both
    /// must decrypt correctly, and the hybrid key must be ≤
    /// `dnum·(L+k)/Σ L_ℓ² + 5 %` of the summed per-level keys.
    #[test]
    fn hybrid_vs_rns_depth_four_multiparty_precision_and_size()
    -> std::result::Result<(), Box<dyn StdError>> {
        let mut rng = rng();
        let params = CkksParametersBuilder::new()
            .set_degree(8192)
            .set_moduli_sizes(&[45, 40, 40, 40, 40, 40, 40, 40])
            .set_special_moduli_sizes(&[60, 60])
            .set_scale(2f64.powi(40))
            .build_arc()?;
        let n = 5;
        let encoder = CkksEncoder::new(&params);
        let sks: Vec<_> = (0..n)
            .map(|_| CkksSecretKey::random(&params, &mut rng))
            .collect();
        let mut seed_pk = [0u8; 32];
        rng.fill_bytes(&mut seed_pk);
        let crp_pk = CkksCrp::from_seed(&params, seed_pk)?;
        let pk = CkksPublicKeyShare::aggregate(
            &sks.iter()
                .map(|sk| CkksPublicKeyShare::new(sk, crp_pk.clone(), &mut rng))
                .collect::<Result<Vec<_>>>()?,
        )?;
        let mut joint = vec![0i64; params.degree()];
        for sk in &sks {
            for (j, c) in sk.coeffs.iter().enumerate() {
                joint[j] += *c;
            }
        }
        let sk_joint = CkksSecretKey::new(joint, &params);

        // Keys.
        let hybrid = hybrid_ceremony(&params, &sks, false, &mut rng)?;
        let depth = 4;
        let rns: Vec<_> = (0..depth)
            .map(|l| rns_ceremony(&params, &sks, l, &mut rng))
            .collect::<Result<Vec<_>>>()?;

        // Depth-4 chain: x -> x^2 -> x^4 -> x^8 -> x^16 (mul, relin, rescale).
        let x: Vec<f64> = vec![1.1, -0.9, 0.7, 1.05];
        let expected: Vec<f64> = x.iter().map(|v| v.powi(16)).collect();
        let ct = pk.try_encrypt(&encoder.encode(&x, 0)?, &mut rng)?;
        let run = |relin: &dyn Fn(&mut crate::ckks::CkksCiphertext, usize) -> Result<()>| {
            let mut y = ct.clone();
            for l in 0..depth {
                let mut sq = y.try_mul(&y)?;
                relin(&mut sq, l)?;
                sq.rescale()?;
                y = sq;
            }
            let d = encoder.decode(&sk_joint.try_decrypt(&y)?)?;
            let err = expected
                .iter()
                .zip(d.iter())
                .map(|(e, v)| ((e - v) / e).abs())
                .fold(0f64, f64::max);
            Ok::<f64, Error>(err)
        };
        let err_rns = run(&|c, l| rns[l].relinearizes(c))?;
        let err_hybrid = run(&|c, _| hybrid.relinearizes(c))?;
        eprintln!("depth-4 rel err: rns={err_rns:.3e} hybrid={err_hybrid:.3e}");
        // The RNS chain is MARGINAL at this shape (observed 5e-2..4e-1
        // relative error run to run: key-switch noise ~ n·N·q_max·B_err
        // vs Δ=2^40) — that is the measured problem hybrid fixes, so only
        // finiteness is required of it. The hybrid chain must be correct.
        assert!(err_rns.is_finite(), "RNS chain produced NaN/inf");
        assert!(err_hybrid < 1e-3, "hybrid chain decrypts: {err_hybrid}");
        assert!(
            err_hybrid * 10.0 <= err_rns,
            "hybrid error {err_hybrid:.3e} not 10x below RNS {err_rns:.3e}"
        );

        // Size: one hybrid key vs the summed per-level keys the chain needs
        // (all L-1 keyable levels, the honest "serve every level" comparison).
        let num_limbs = params.moduli().len();
        let k = params.special_moduli().len();
        let hybrid_bytes = hybrid.to_bytes().len();
        let mut summed = 0usize;
        let mut sum_sq = 0usize;
        for l in 0..num_limbs - 1 {
            let key = match rns.get(l) {
                Some(k) => k.to_bytes().len(),
                None => rns_ceremony(&params, &sks, l, &mut rng)?.to_bytes().len(),
            };
            summed += key;
            sum_sq += (num_limbs - l).pow(2);
        }
        let ratio = params.dnum() as f64 * (num_limbs + k) as f64 / sum_sq as f64;
        eprintln!(
            "key bytes: hybrid={hybrid_bytes} summed-rns={summed} ratio={:.3} bound={:.3}",
            hybrid_bytes as f64 / summed as f64,
            ratio
        );
        assert!((hybrid_bytes as f64) <= (ratio + 0.05) * summed as f64);
        assert!(hybrid_bytes * 4 < summed, "hybrid is not ≥ 4× smaller");
        Ok(())
    }

    /// Multiparty hybrid key through the wire + threshold decryption of a
    /// product at level 2 (key generated once, used at a deep level).
    #[test]
    fn multiparty_hybrid_wire_and_threshold_decrypt() -> std::result::Result<(), Box<dyn StdError>>
    {
        let mut rng = rng();
        let params = CkksParametersBuilder::new()
            .set_degree(512)
            .set_moduli_sizes(&[45, 40, 40, 40, 40])
            .set_special_moduli_sizes(&[60, 60])
            .set_scale(2f64.powi(40))
            .build_arc()?;
        let n = 5;
        let threshold = 2;
        let trckks = TRCKKS::new(n, threshold, params.clone())?;
        let encoder = CkksEncoder::new(&params);
        let sks: Vec<_> = (0..n)
            .map(|_| CkksSecretKey::random(&params, &mut rng))
            .collect();
        let mut seed_pk = [0u8; 32];
        rng.fill_bytes(&mut seed_pk);
        let crp_pk = CkksCrp::from_seed(&params, seed_pk)?;
        let pk = CkksPublicKeyShare::aggregate(
            &sks.iter()
                .map(|sk| CkksPublicKeyShare::new(sk, crp_pk.clone(), &mut rng))
                .collect::<Result<Vec<_>>>()?,
        )?;
        let rlk = hybrid_ceremony(&params, &sks, true, &mut rng)?;
        assert_eq!(rlk.dnum(), 3);

        let mut sk_share_matrices = Vec::new();
        let mut es_share_matrices = Vec::new();
        for sk_i in &sks {
            let sk_poly = trckks.coeffs_to_poly(sk_i.coeffs.as_ref())?;
            sk_share_matrices.push(trckks.generate_secret_shares_from_poly(sk_poly, &mut rng)?);
            let es = trckks.generate_smudging_error(20, &mut rng)?;
            let es_poly = trckks.smudging_to_poly(&es)?;
            es_share_matrices.push(trckks.generate_secret_shares_from_poly(es_poly, &mut rng)?);
        }

        let a = vec![3.0, -1.5];
        let b = vec![2.0, 4.0];
        let mut ct_a = pk.try_encrypt(&encoder.encode(&a, 0)?, &mut rng)?;
        let mut ct_b = pk.try_encrypt(&encoder.encode(&b, 0)?, &mut rng)?;
        ct_a.mod_switch_to_level(2)?;
        ct_b.mod_switch_to_level(2)?;
        let mut product = ct_a.try_mul(&ct_b)?;
        rlk.relinearizes(&mut product)?;
        product.rescale()?;
        assert_eq!(product.level, 3);

        let parties: Vec<usize> = vec![1, 3, 5];
        let mut d_shares = Vec::new();
        for &j in &parties {
            let sk_j = trckks.aggregate_collected_shares(&collect(&sk_share_matrices, j - 1))?;
            let es_j = trckks.aggregate_collected_shares(&collect(&es_share_matrices, j - 1))?;
            let sk_j = trckks.project_share_to_level(&sk_j, product.level)?;
            let es_j = trckks.project_share_to_level(&es_j, product.level)?;
            d_shares.push(trckks.decryption_share(&product, sk_j.into_ntt(), es_j)?);
        }
        let pt = trckks.decrypt(d_shares, parties, &product)?;
        let decoded = encoder.decode(&pt)?;
        for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
            assert!(
                (decoded[i] - x * y).abs() < 0.5,
                "slot {i}: {} vs {}",
                decoded[i],
                x * y
            );
        }
        Ok(())
    }

    /// Seeded-u determinism, rejections: wrong CRP length / params, mixed
    /// shares, truncated wire, hybrid disabled.
    #[test]
    fn hybrid_generator_rejections_and_seeded_u() -> std::result::Result<(), Box<dyn StdError>> {
        let mut rng = rng();
        let params = CkksParametersBuilder::new()
            .set_degree(64)
            .set_moduli_sizes(&[45, 40, 40, 40])
            .set_special_moduli_sizes(&[50, 50])
            .set_scale(2f64.powi(40))
            .build_arc()?;
        let sk = CkksSecretKey::random(&params, &mut rng);
        let mut seed = [7u8; 32];
        rng.fill_bytes(&mut seed);
        let crp = CkksCrp::vec_from_seed_qp(&params, seed)?;
        assert_eq!(crp.len(), params.dnum());

        // Seeded u: two generators from the same seed produce identical
        // round-2 material on identical R1 (noise aside, u must match) —
        // check via u equality on the generator itself.
        let g1 = CkksHybridRelinKeyGenerator::new_from_seed(&sk, &crp, seed, &mut rng)?;
        let g2 = CkksHybridRelinKeyGenerator::new_from_seed(&sk, &crp, seed, &mut rng)?;
        assert_eq!(*g1.u, *g2.u);
        let g3 = CkksHybridRelinKeyGenerator::new_from_seed(&sk, &crp, [1u8; 32], &mut rng)?;
        assert_ne!(*g1.u, *g3.u);
        let dbg = format!("{g1:?}");
        assert!(dbg.contains("<redacted>"));

        // Wrong CRP length.
        assert!(CkksHybridRelinKeyGenerator::new(&sk, &crp[..1], &mut rng).is_err());
        // Hybrid disabled.
        let plain = CkksParametersBuilder::new()
            .set_degree(64)
            .set_moduli(params.moduli())
            .set_scale(2f64.powi(40))
            .build_arc()?;
        let sk_plain = CkksSecretKey::random(&plain, &mut rng);
        assert!(CkksCrp::vec_from_seed_qp(&plain, seed).is_err());
        assert!(CkksHybridRelinKeyGenerator::new(&sk_plain, &crp, &mut rng).is_err());

        // Wire truncation and mixed-shape aggregation.
        let r1 = g1.round_1(&mut rng)?;
        let bytes = r1.to_bytes();
        assert!(
            CkksHybridRelinKeyShare::<R1>::from_bytes(&bytes[..bytes.len() - 2], &params).is_err()
        );
        let other = CkksParametersBuilder::new()
            .set_degree(64)
            .set_moduli(params.moduli())
            .set_special_moduli_sizes(&[50, 50])
            .set_dnum(4)
            .set_scale(2f64.powi(40))
            .build_arc()?;
        assert!(CkksHybridRelinKeyShare::<R1>::from_bytes(&bytes, &other).is_err());
        let sk_o = CkksSecretKey::random(&other, &mut rng);
        let crp_o = CkksCrp::vec_from_seed_qp(&other, seed)?;
        let r1_o = CkksHybridRelinKeyGenerator::new(&sk_o, &crp_o, &mut rng)?.round_1(&mut rng)?;
        assert!(
            CkksHybridRelinKeyShare::<R1Aggregated>::from_shares(vec![r1.clone(), r1_o]).is_err()
        );
        // R2 without back-reference.
        let r1_agg = Arc::new(CkksHybridRelinKeyShare::<R1Aggregated>::from_shares(vec![
            r1,
        ])?);
        let r2 = g1.round_2(&r1_agg, &mut rng)?;
        let r2_wire = CkksHybridRelinKeyShare::<R2>::from_bytes(&r2.to_bytes(), &params)?;
        assert!(CkksHybridRelinKeyShare::<R2>::aggregate_into_key(vec![r2_wire.clone()]).is_err());
        assert!(
            CkksHybridRelinKeyShare::<R2>::aggregate_into_key_with_r1(vec![r2_wire], r1_agg)
                .is_ok()
        );
        Ok(())
    }
}
