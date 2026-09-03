//! Multiparty relinearization key generation for threshold CKKS.
//!
//! Two-round CRP-based protocol `RelinKeyGen` from Mouchet et al.,
//! *Multiparty Homomorphic Encryption from Ring-Learning-with-Errors*
//! (<https://eprint.iacr.org/2020/304>, Protocol 2), adapted from the BFV
//! implementation in [`crate::mbfv`]. The protocol is plaintext-space-
//! agnostic (it only manipulates key material), so it applies to CKKS
//! unchanged. With `a_j` the per-limb CRPs and `g_j` the RNS Garner
//! constants of the key's level:
//!
//! - Round 1: party `i` publishes
//!   `h0_i[j] = -a_j*u_i + g_j*s_i + e` and `h1_i[j] = a_j*s_i + e`.
//! - Round 2 (after aggregating round 1): party `i` publishes
//!   `h0'_i[j] = h0[j]*s_i + e` and `h1'_i[j] = h1[j]*(u_i - s_i) + e`.
//! - Aggregation of round 2 yields the key-switching elements for the joint
//!   secret `s = sum_i s_i`.
//!
//! Keys are leveled (one protocol instance per multiplication level, see
//! [`CkksRelinKeyGenerator::new_leveled`]); shares carry their level and
//! aggregation rejects mixed levels. The same ephemeral `u_i` MUST be used
//! in both rounds — [`CkksRelinKeyGenerator::new_leveled_from_seed`]
//! supports state machines that cannot hold the generator across rounds.
//!
//! Wire format: [`CkksRelinKeyShare::to_bytes`] / `from_bytes`, identical
//! in shape to [`CkksRelinearizationKey::to_bytes`]. No zero-knowledge
//! proofs cover this ceremony; correctness is verified by determinism
//! (every party aggregates the same public shares to the same key).

use crate::ckks::wire::{decode_leveled_polys, encode_leveled_polys};
use crate::ckks::{CkksParameters, CkksRelinearizationKey, CkksSecretKey};
use crate::trckks::keygen::CkksCrp;
use crate::{Error, Result};
use fhe_math::rns::RnsContext;
use fhe_math::rq::{Ntt, NttShoup, Poly, PowerBasis, traits::TryConvertFrom};
use itertools::izip;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::marker::PhantomData;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Marker type: round-1 share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct R1;
/// Marker type: aggregated round-1 shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct R1Aggregated;
/// Marker type: round-2 share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct R2;

/// A party's share in the CKKS relinearization key generation protocol.
///
/// Shares are PUBLIC protocol messages (the `Debug` output is safe to
/// log). Produced by [`CkksRelinKeyGenerator::round_1`] /
/// [`CkksRelinKeyGenerator::round_2`], aggregated by
/// [`CkksRelinKeyShare::from_shares`] and
/// [`CkksRelinKeyShare::aggregate_into_key`].
#[derive(Debug, Clone)]
pub struct CkksRelinKeyShare<Round = R1> {
    pub(crate) par: Arc<CkksParameters>,
    pub(crate) h0: Box<[Poly<Ntt>]>,
    pub(crate) h1: Box<[Poly<Ntt>]>,
    /// Level this share's key material is bound to.
    pub(crate) level: usize,
    last_round: Option<Arc<CkksRelinKeyShare<R1Aggregated>>>,
    _phantom: PhantomData<Round>,
}

/// Per-party generator for the two-round relinearization key protocol.
///
/// Holds the party's secret-key share (by reference) and the ephemeral
/// secret `u`, which is zeroized on drop. `Debug` redacts both.
pub struct CkksRelinKeyGenerator<'a, 'b> {
    sk_share: &'a CkksSecretKey,
    crp: &'b [CkksCrp],
    u: Zeroizing<Poly<Ntt>>,
    level: usize,
}

impl std::fmt::Debug for CkksRelinKeyGenerator<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksRelinKeyGenerator")
            .field("level", &self.level)
            .field("crp_len", &self.crp.len())
            .field("sk_share", &"<redacted>")
            .field("u", &"<redacted>")
            .finish()
    }
}

impl<'a, 'b> CkksRelinKeyGenerator<'a, 'b> {
    /// Create a generator for this party at level 0.
    ///
    /// `crp` must contain one CRP per RNS modulus at level 0 (see
    /// [`CkksCrp::vec_from_seed`]).
    pub fn new<R: RngCore + CryptoRng>(
        sk_share: &'a CkksSecretKey,
        crp: &'b [CkksCrp],
        rng: &mut R,
    ) -> Result<Self> {
        Self::new_leveled(sk_share, crp, 0, rng)
    }

    /// Create a generator bound to `level`.
    ///
    /// The resulting joint key relinearizes ciphertexts AT that level (i.e.
    /// after `level` rescales); deeper circuits run one protocol instance per
    /// multiplication level. `crp` must come from
    /// [`CkksCrp::vec_from_seed_leveled`] with the same level, with one CRP
    /// per REMAINING RNS modulus.
    pub fn new_leveled<R: RngCore + CryptoRng>(
        sk_share: &'a CkksSecretKey,
        crp: &'b [CkksCrp],
        level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let ctx = Self::validate(sk_share, crp, level)?;
        let u = Zeroizing::new(Poly::<Ntt>::small(ctx, sk_share.par.variance, rng)?);
        Ok(Self {
            sk_share,
            crp,
            u,
            level,
        })
    }

    /// Create a generator bound to `level` with the ephemeral secret `u`
    /// derived deterministically from `u_seed` (domain-separated by level).
    ///
    /// The two-round protocol REQUIRES the same `u` in round 1 and round 2;
    /// state machines that cross a persistence/serialization boundary
    /// between rounds reconstruct the generator from the SAME seed at each
    /// round instead of holding it in memory. `u_seed` must be a fresh,
    /// SECRET, per-party, per-ceremony value (leaking it leaks `u`, which
    /// combined with the public shares reveals the party's secret key
    /// share); zeroize the stored seed once the ceremony completes.
    ///
    /// The `_rng` argument is unused (kept for signature symmetry with
    /// [`Self::new_leveled`]); round noise still comes from the RNG passed
    /// to `round_1` / `round_2`.
    pub fn new_leveled_from_seed<R: RngCore + CryptoRng>(
        sk_share: &'a CkksSecretKey,
        crp: &'b [CkksCrp],
        level: usize,
        u_seed: [u8; 32],
        _rng: &mut R,
    ) -> Result<Self> {
        let ctx = Self::validate(sk_share, crp, level)?;
        // Domain-separate per level so distinct levels use independent u.
        let mut seed = u_seed;
        seed[0] ^= (level & 0xff) as u8;
        seed[1] ^= ((level >> 8) & 0xff) as u8;
        let mut u_rng = ChaCha8Rng::from_seed(seed);
        let u = Zeroizing::new(Poly::<Ntt>::small(ctx, sk_share.par.variance, &mut u_rng)?);
        seed.zeroize();
        Ok(Self {
            sk_share,
            crp,
            u,
            level,
        })
    }

    /// Shared validation for the constructors: the level must support key
    /// switching (at least two limbs) and `crp` must be one CRP per limb at
    /// that level. Returns the level's context.
    fn validate(
        sk_share: &'a CkksSecretKey,
        crp: &[CkksCrp],
        level: usize,
    ) -> Result<&'a Arc<fhe_math::rq::Context>> {
        let ctx = sk_share.par.context_at_level(level)?;
        if ctx.moduli().len() == 1 {
            return Err(Error::DefaultError(
                "these parameters do not support key switching".to_string(),
            ));
        }
        if crp.len() != ctx.moduli().len() {
            return Err(Error::DefaultError(
                "the CRP vector length must equal the number of ciphertext moduli".to_string(),
            ));
        }
        if crp.iter().any(|c| c.poly.ctx() != ctx) {
            return Err(Error::DefaultError(
                "CRP level does not match the requested key level".to_string(),
            ));
        }
        Ok(ctx)
    }

    /// Generate this party's round-1 share.
    pub fn round_1<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<CkksRelinKeyShare<R1>> {
        Ok(self.round_1_extended(rng)?.0)
    }

    /// Generate this party's round-1 share, also returning the error
    /// polynomials `(e0_i, e1_i)` sampled for each decomposition index.
    ///
    /// The extra outputs are SECRET witness material (analogous to
    /// `try_encrypt_extended`): they let a prover attest that
    /// `h0_i = -a_i*u + g_i*s + e0_i` and `h1_i = a_i*s + e1_i` are
    /// well-formed in zero knowledge. Never publish them.
    #[allow(clippy::type_complexity)]
    pub fn round_1_extended<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(CkksRelinKeyShare<R1>, Vec<Poly<Ntt>>, Vec<Poly<Ntt>>)> {
        let par = self.sk_share.par.clone();
        let ctx = par.context_at_level(self.level)?;

        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(self.sk_share.coeffs.as_ref(), ctx, false)?
                .into_ntt(),
        );
        let rns = RnsContext::new(ctx.moduli())?;

        let mut h0 = Vec::with_capacity(self.crp.len());
        let mut h1 = Vec::with_capacity(self.crp.len());
        let mut e0s = Vec::with_capacity(self.crp.len());
        let mut e1s = Vec::with_capacity(self.crp.len());
        for (i, a) in self.crp.iter().enumerate() {
            let w = rns.get_garner(i).unwrap();
            let w_s = Zeroizing::new(w * s.as_ref());

            let e0 = Poly::<Ntt>::small(ctx, par.variance, rng)?;
            let mut h = -a.poly.clone();
            h.disallow_variable_time_computations();
            h *= self.u.as_ref();
            h += w_s.as_ref();
            h += &e0;
            h0.push(h);
            e0s.push(e0);

            let e1 = Poly::<Ntt>::small(ctx, par.variance, rng)?;
            let mut g = a.poly.clone();
            g.disallow_variable_time_computations();
            g *= s.as_ref();
            g += &e1;
            h1.push(g);
            e1s.push(e1);
        }

        Ok((
            CkksRelinKeyShare {
                par,
                h0: h0.into_boxed_slice(),
                h1: h1.into_boxed_slice(),
                level: self.level,
                last_round: None,
                _phantom: PhantomData,
            },
            e0s,
            e1s,
        ))
    }

    /// The ephemeral secret `u` of this generator (SECRET witness material
    /// for proving round-1 share well-formedness; never publish it).
    #[must_use]
    pub fn u_poly(&self) -> &Poly<Ntt> {
        &self.u
    }

    /// Generate this party's round-2 share from the aggregated round 1.
    pub fn round_2<R: RngCore + CryptoRng>(
        &self,
        r1: &Arc<CkksRelinKeyShare<R1Aggregated>>,
        rng: &mut R,
    ) -> Result<CkksRelinKeyShare<R2>> {
        let par = self.sk_share.par.clone();
        if r1.level != self.level {
            return Err(Error::DefaultError(format!(
                "round-1 aggregation is at level {}, generator at level {}",
                r1.level, self.level
            )));
        }
        let ctx = par.context_at_level(self.level)?;

        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(self.sk_share.coeffs.as_ref(), ctx, false)?
                .into_ntt(),
        );
        let u_minus_s = Zeroizing::new(self.u.as_ref() - s.as_ref());

        let mut h0 = Vec::with_capacity(r1.h0.len());
        for h in r1.h0.iter() {
            let e = Zeroizing::new(Poly::<Ntt>::small(ctx, par.variance, rng)?);
            let mut h_prime = h.clone();
            h_prime.disallow_variable_time_computations();
            h_prime *= s.as_ref();
            h_prime += e.as_ref();
            h0.push(h_prime);
        }

        let mut h1 = Vec::with_capacity(r1.h1.len());
        for h in r1.h1.iter() {
            let e = Zeroizing::new(Poly::<Ntt>::small(ctx, par.variance, rng)?);
            let mut h_prime = h.clone();
            h_prime.disallow_variable_time_computations();
            h_prime *= u_minus_s.as_ref();
            h_prime += e.as_ref();
            h1.push(h_prime);
        }

        Ok(CkksRelinKeyShare {
            par,
            h0: h0.into_boxed_slice(),
            h1: h1.into_boxed_slice(),
            level: self.level,
            last_round: Some(Arc::clone(r1)),
            _phantom: PhantomData,
        })
    }
}

impl<Round> CkksRelinKeyShare<Round> {
    /// Serialize this share: level, then the h0/h1 polynomials,
    /// length-prefixed. The round-1 back-reference of an R2 share is NOT
    /// serialized — reattach it at aggregation via
    /// [`CkksRelinKeyShare::aggregate_into_key_with_r1`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_leveled_polys(self.level, &self.h0, &self.h1)
    }

    /// Deserialize a share produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8], par: &Arc<CkksParameters>) -> Result<Self> {
        let d = decode_leveled_polys::<Ntt>(bytes, par, "relin share")?;
        Ok(Self {
            par: par.clone(),
            h0: d.first.into_boxed_slice(),
            h1: d.second.into_boxed_slice(),
            level: d.level,
            last_round: None,
            _phantom: PhantomData,
        })
    }

    /// The level this share is bound to.
    #[must_use]
    pub fn level(&self) -> usize {
        self.level
    }

    /// The `h0` polynomials of this share (one per decomposition index).
    #[must_use]
    pub fn h0(&self) -> &[Poly<Ntt>] {
        &self.h0
    }

    /// The `h1` polynomials of this share (one per decomposition index).
    #[must_use]
    pub fn h1(&self) -> &[Poly<Ntt>] {
        &self.h1
    }
}

impl CkksRelinKeyShare<R1Aggregated> {
    /// Aggregate round-1 shares (all must be at the same level).
    pub fn from_shares(shares: Vec<CkksRelinKeyShare<R1>>) -> Result<Self> {
        let mut iter = shares.into_iter();
        let share = iter.next().ok_or(Error::TooFewValues {
            actual: 0,
            minimum: 1,
        })?;
        let mut h0 = share.h0;
        let mut h1 = share.h1;
        for sh in iter {
            if sh.level != share.level {
                return Err(Error::DefaultError(format!(
                    "cannot aggregate round-1 shares at levels {} and {}",
                    share.level, sh.level
                )));
            }
            izip!(h0.iter_mut(), sh.h0.iter()).for_each(|(a, b)| *a += b);
            izip!(h1.iter_mut(), sh.h1.iter()).for_each(|(a, b)| *a += b);
        }
        Ok(Self {
            par: share.par,
            h0,
            h1,
            level: share.level,
            last_round: None,
            _phantom: PhantomData,
        })
    }
}

impl CkksRelinKeyShare<R2> {
    /// Aggregate round-2 shares into the joint key, supplying the round-1
    /// aggregation explicitly (for shares that crossed a serialization
    /// boundary and lost their back-reference).
    pub fn aggregate_into_key_with_r1(
        mut shares: Vec<Self>,
        r1: Arc<CkksRelinKeyShare<R1Aggregated>>,
    ) -> Result<CkksRelinearizationKey> {
        for sh in &mut shares {
            if sh.level != r1.level {
                return Err(Error::DefaultError(format!(
                    "round-2 share at level {} cannot bind round-1 aggregation at level {}",
                    sh.level, r1.level
                )));
            }
            sh.last_round = Some(Arc::clone(&r1));
        }
        Self::aggregate_into_key(shares)
    }

    /// Aggregate round-2 shares into the joint [`CkksRelinearizationKey`].
    pub fn aggregate_into_key(shares: Vec<Self>) -> Result<CkksRelinearizationKey> {
        let mut iter = shares.into_iter();
        let share = iter.next().ok_or(Error::TooFewValues {
            actual: 0,
            minimum: 1,
        })?;
        let par = share.par.clone();
        let level = share.level;
        let ctx = par.context_at_level(level)?.clone();
        let r1 = share.last_round.ok_or(Error::DefaultError(
            "round-2 shares must carry the round-1 aggregation".to_string(),
        ))?;

        let mut h0 = share.h0;
        let mut h1 = share.h1;
        for sh in iter {
            if sh.level != level {
                return Err(Error::DefaultError(format!(
                    "cannot aggregate round-2 shares at levels {level} and {}",
                    sh.level
                )));
            }
            izip!(h0.iter_mut(), h1.iter_mut(), sh.h0.iter(), sh.h1.iter()).for_each(
                |(a0, a1, b0, b1)| {
                    *a0 += b0;
                    *a1 += b1;
                },
            );
        }

        let mut c0 = Vec::from(h0);
        izip!(c0.iter_mut(), h1.iter()).for_each(|(c0, h1)| *c0 += h1);
        let c0 = c0
            .into_iter()
            .map(Poly::<Ntt>::into_ntt_shoup)
            .collect::<Vec<Poly<NttShoup>>>();

        let c1 = r1
            .h1
            .iter()
            .cloned()
            .map(Poly::<Ntt>::into_ntt_shoup)
            .collect::<Vec<Poly<NttShoup>>>();

        Ok(CkksRelinearizationKey::from_parts(par, c0, c1, level, ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckks::{CkksEncoder, CkksParametersBuilder};
    use crate::trckks::TRCKKS;
    use crate::trckks::keygen::CkksPublicKeyShare;
    use ndarray::Array2;
    use rand::rng;
    use std::error::Error as StdError;

    /// Serialization round-trip: shares and the aggregated key survive
    /// the wire, and a key rebuilt from serialized R2 shares (via
    /// aggregate_into_key_with_r1) still relinearizes correctly.
    #[test]
    fn relin_serialization_round_trip() -> std::result::Result<(), Box<dyn StdError>> {
        let mut rng = rng();
        let params = CkksParametersBuilder::new()
            .set_degree(64)
            .set_moduli_sizes(&[45, 45, 45])
            .set_scale(2f64.powi(40))
            .build_arc()?;
        let n = 3;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let crp = CkksCrp::vec_from_seed(&params, seed, params.moduli().len())?;
        let sks: Vec<_> = (0..n)
            .map(|_| crate::ckks::CkksSecretKey::random(&params, &mut rng))
            .collect();
        let generators = sks
            .iter()
            .map(|sk| CkksRelinKeyGenerator::new(sk, &crp, &mut rng))
            .collect::<Result<Vec<_>>>()?;

        // Round 1 over the wire.
        let r1_wire: Vec<Vec<u8>> = generators
            .iter()
            .map(|g| Ok(g.round_1(&mut rng)?.to_bytes()))
            .collect::<Result<Vec<_>>>()?;
        let r1_shares = r1_wire
            .iter()
            .map(|b| CkksRelinKeyShare::<R1>::from_bytes(b, &params))
            .collect::<Result<Vec<_>>>()?;
        let r1_agg = Arc::new(CkksRelinKeyShare::<R1Aggregated>::from_shares(r1_shares)?);

        // Round 1 aggregation itself over the wire (aggregator -> parties).
        let r1_agg_wire =
            CkksRelinKeyShare::<R1Aggregated>::from_bytes(&r1_agg.to_bytes(), &params)?;
        let r1_agg = Arc::new(r1_agg_wire);

        // Round 2 over the wire; back-reference reattached explicitly.
        let r2_wire: Vec<Vec<u8>> = generators
            .iter()
            .map(|g| Ok(g.round_2(&r1_agg, &mut rng)?.to_bytes()))
            .collect::<Result<Vec<_>>>()?;
        let r2_shares = r2_wire
            .iter()
            .map(|b| CkksRelinKeyShare::<R2>::from_bytes(b, &params))
            .collect::<Result<Vec<_>>>()?;
        let rlk =
            CkksRelinKeyShare::<R2>::aggregate_into_key_with_r1(r2_shares, Arc::clone(&r1_agg))?;

        // Key over the wire.
        let rlk = CkksRelinearizationKey::from_bytes(&rlk.to_bytes(), &params)?;
        assert_eq!(rlk.level(), 0);

        // The deserialized key still relinearizes a real product under the
        // joint secret (sum of party secrets).
        let mut joint = vec![0i64; 64];
        for sk in &sks {
            for (j, c) in sk.coeffs.iter().enumerate() {
                joint[j] += *c;
            }
        }
        let sk_joint = crate::ckks::CkksSecretKey::new(joint, &params);
        let encoder = CkksEncoder::new(&params);
        let mut seed_pk = [0u8; 32];
        rng.fill_bytes(&mut seed_pk);
        let crp_pk = CkksCrp::from_seed(&params, seed_pk)?;
        let pk_shares = sks
            .iter()
            .map(|sk| CkksPublicKeyShare::new(sk, crp_pk.clone(), &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let pk = CkksPublicKeyShare::aggregate(&pk_shares)?;
        let a = vec![3.0, -2.0];
        let ct = pk.try_encrypt(&encoder.encode(&a, 0)?, &mut rng)?;
        let mut sq = ct.try_mul(&ct)?;
        rlk.relinearizes(&mut sq)?;
        sq.rescale()?;
        let decoded = encoder.decode(&sk_joint.try_decrypt(&sq)?)?;
        for (i, x) in a.iter().enumerate() {
            assert!(
                (decoded[i] - x * x).abs() < 0.1,
                "slot {i}: {} vs {}",
                decoded[i],
                x * x
            );
        }

        // Truncated bytes rejected.
        let bytes = r1_wire[0].clone();
        assert!(CkksRelinKeyShare::<R1>::from_bytes(&bytes[..bytes.len() - 3], &params).is_err());
        Ok(())
    }

    /// Leveled relin keys: a depth-2 circuit (x*y at level 0, rescale,
    /// then *z at level 1 with a LEVEL-1 key, rescale) threshold-decrypts
    /// correctly. This is the primitive iterated sign extraction needs.
    #[test]
    fn leveled_relin_keys_depth_two() -> std::result::Result<(), Box<dyn StdError>> {
        let mut rng = rng();
        let params = CkksParametersBuilder::new()
            .set_degree(512)
            .set_moduli_sizes(&[45, 45, 45, 45])
            .set_scale(2f64.powi(40))
            .build_arc()?;
        let n = 5;
        let threshold = 2;
        let trckks = TRCKKS::new(n, threshold, params.clone())?;
        let encoder = CkksEncoder::new(&params);

        let mut seed_pk = [0u8; 32];
        rng.fill_bytes(&mut seed_pk);
        let crp_pk = CkksCrp::from_seed(&params, seed_pk)?;

        let sks: Vec<_> = (0..n)
            .map(|_| crate::ckks::CkksSecretKey::random(&params, &mut rng))
            .collect();
        let pk_shares = sks
            .iter()
            .map(|sk| CkksPublicKeyShare::new(sk, crp_pk.clone(), &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let pk = CkksPublicKeyShare::aggregate(&pk_shares)?;

        // One relin key per multiplication level, each from its own
        // leveled CRP vector (sized to the REMAINING moduli).
        let mut rlks = Vec::new();
        for level in 0..2usize {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let len = params.moduli().len() - level;
            let crp = CkksCrp::vec_from_seed_leveled(&params, seed, len, level)?;
            let generators = sks
                .iter()
                .map(|sk| CkksRelinKeyGenerator::new_leveled(sk, &crp, level, &mut rng))
                .collect::<Result<Vec<_>>>()?;
            let r1 = generators
                .iter()
                .map(|g| g.round_1(&mut rng))
                .collect::<Result<Vec<_>>>()?;
            let r1_agg = Arc::new(CkksRelinKeyShare::<R1Aggregated>::from_shares(r1)?);
            let r2 = generators
                .iter()
                .map(|g| g.round_2(&r1_agg, &mut rng))
                .collect::<Result<Vec<_>>>()?;
            rlks.push(CkksRelinKeyShare::<R2>::aggregate_into_key(r2)?);
        }

        // Level mismatch is rejected: level-0 key on a rescaled ct.
        // (constructed below after the first rescale)

        // Deal key + smudging shares.
        let mut sk_share_matrices = Vec::new();
        let mut es_share_matrices = Vec::new();
        for sk_i in &sks {
            let sk_poly = trckks.coeffs_to_poly(sk_i.coeffs.as_ref())?;
            sk_share_matrices.push(trckks.generate_secret_shares_from_poly(sk_poly, &mut rng)?);
            let es = trckks.generate_smudging_error(20, &mut rng)?;
            let es_poly = trckks.smudging_to_poly(&es)?;
            es_share_matrices.push(trckks.generate_secret_shares_from_poly(es_poly, &mut rng)?);
        }
        let collect = |matrices: &[Vec<Array2<u64>>], j: usize| -> Vec<Array2<u64>> {
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
        };

        // Depth-2 circuit: (x*y) rescale, (*z) rescale.
        let x = vec![3.0, -1.5];
        let y = vec![2.0, 4.0];
        let z = vec![0.5, -2.0];
        let ct_x = pk.try_encrypt(&encoder.encode(&x, 0)?, &mut rng)?;
        let ct_y = pk.try_encrypt(&encoder.encode(&y, 0)?, &mut rng)?;
        let ct_z = pk.try_encrypt(&encoder.encode(&z, 0)?, &mut rng)?;

        let mut xy = ct_x.try_mul(&ct_y)?;
        rlks[0].relinearizes(&mut xy)?;
        xy.rescale()?;
        assert_eq!(xy.level, 1);

        // z must move to level 1 before multiplying (mod-switch drops the
        // spent limb; scale is untouched — try_mul tracks the product
        // scale, so no alignment is needed for multiplication).
        let mut z1 = ct_z.clone();
        z1.mod_switch_to_level(1)?;

        let mut xyz = xy.try_mul(&z1)?;
        // Level-0 key must be REJECTED at level 1.
        assert!(rlks[0].relinearizes(&mut xyz).is_err());
        rlks[1].relinearizes(&mut xyz)?;
        xyz.rescale()?;
        assert_eq!(xyz.level, 2);

        // Threshold decrypt at level 2.
        let parties: Vec<usize> = vec![1, 3, 4];
        let mut d_shares = Vec::new();
        for &j in &parties {
            let sk_j = trckks.aggregate_collected_shares(&collect(&sk_share_matrices, j - 1))?;
            let es_j = trckks.aggregate_collected_shares(&collect(&es_share_matrices, j - 1))?;
            let sk_j = trckks.project_share_to_level(&sk_j, xyz.level)?;
            let es_j = trckks.project_share_to_level(&es_j, xyz.level)?;
            d_shares.push(trckks.decryption_share(&xyz, sk_j.into_ntt(), es_j)?);
        }
        let pt = trckks.decrypt(d_shares, parties, &xyz)?;
        let decoded = encoder.decode(&pt)?;

        for i in 0..x.len() {
            let expected = x[i] * y[i] * z[i];
            assert!(
                (decoded[i] - expected).abs() < 0.5,
                "slot {i}: {} vs {expected}",
                decoded[i],
            );
        }
        Ok(())
    }

    /// Complete threshold CKKS flow with multiplication:
    /// multiparty keygen -> multiparty relin keygen -> encrypt -> multiply ->
    /// relinearize -> rescale -> threshold decrypt.
    #[test]
    fn multiparty_relin_multiply_threshold_decrypt() -> std::result::Result<(), Box<dyn StdError>> {
        let mut rng = rng();
        let params = CkksParametersBuilder::new()
            .set_degree(512)
            .set_moduli_sizes(&[45, 45, 45])
            .set_scale(2f64.powi(40))
            .build_arc()?;
        let n = 5;
        let threshold = 2;
        let trckks = TRCKKS::new(n, threshold, params.clone())?;
        let encoder = CkksEncoder::new(&params);

        // Public CRPs.
        let mut seed_pk = [0u8; 32];
        rng.fill_bytes(&mut seed_pk);
        let crp_pk = CkksCrp::from_seed(&params, seed_pk)?;
        let mut seed_rlk = [0u8; 32];
        rng.fill_bytes(&mut seed_rlk);
        let crp_rlk = CkksCrp::vec_from_seed(&params, seed_rlk, params.moduli().len())?;

        // Parties.
        let sks: Vec<_> = (0..n)
            .map(|_| crate::ckks::CkksSecretKey::random(&params, &mut rng))
            .collect();

        // Multiparty public key.
        let pk_shares = sks
            .iter()
            .map(|sk| CkksPublicKeyShare::new(sk, crp_pk.clone(), &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let pk = CkksPublicKeyShare::aggregate(&pk_shares)?;

        // Multiparty relinearization key (two rounds).
        let generators = sks
            .iter()
            .map(|sk| CkksRelinKeyGenerator::new(sk, &crp_rlk, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let r1_shares = generators
            .iter()
            .map(|g| g.round_1(&mut rng))
            .collect::<Result<Vec<_>>>()?;
        let r1_agg = Arc::new(CkksRelinKeyShare::<R1Aggregated>::from_shares(r1_shares)?);
        let r2_shares = generators
            .iter()
            .map(|g| g.round_2(&r1_agg, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let rlk = CkksRelinKeyShare::<R2>::aggregate_into_key(r2_shares)?;

        // Deal key + smudging shares.
        let mut sk_share_matrices = Vec::new();
        let mut es_share_matrices = Vec::new();
        for sk_i in &sks {
            let sk_poly = trckks.coeffs_to_poly(sk_i.coeffs.as_ref())?;
            sk_share_matrices.push(trckks.generate_secret_shares_from_poly(sk_poly, &mut rng)?);
            let es = trckks.generate_smudging_error(20, &mut rng)?;
            let es_poly = trckks.smudging_to_poly(&es)?;
            es_share_matrices.push(trckks.generate_secret_shares_from_poly(es_poly, &mut rng)?);
        }
        let collect = |matrices: &[Vec<Array2<u64>>], j: usize| -> Vec<Array2<u64>> {
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
        };

        // Encrypt and multiply.
        let a = vec![3.0, -1.5];
        let b = vec![2.0, 4.0];
        let ct_a = pk.try_encrypt(&encoder.encode(&a, 0)?, &mut rng)?;
        let ct_b = pk.try_encrypt(&encoder.encode(&b, 0)?, &mut rng)?;

        let mut product = ct_a.try_mul(&ct_b)?;
        rlk.relinearizes(&mut product)?;
        assert_eq!(product.len(), 2);
        product.rescale()?;

        // Threshold decrypt. Shares are per-modulus independent sharings, so
        // moving to the rescaled ciphertext level means dropping RNS rows
        // (project_share_to_level), never divide-and-round switching.
        let parties: Vec<usize> = vec![1, 2, 4];
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
}
