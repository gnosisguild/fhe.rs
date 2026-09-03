//! Length-prefixed wire framing shared by the CKKS relinearization key and
//! the multiparty relinearization-key shares.
//!
//! Layout (all integers little-endian `u32`):
//!
//! ```text
//! level | count | (len | poly bytes) * 2*count
//! ```
//!
//! The first `count` polynomials are the `c0`/`h0` side, the next `count`
//! the `c1`/`h1` side. A key and a share at the same level therefore have
//! exactly the same size on the wire.
//!
//! Hybrid (`Q·P`) key material uses a sibling framing:
//!
//! ```text
//! 0xffff_fffe | dnum | L | k | (len | poly bytes) * 4*dnum
//! ```
//!
//! where the leading sentinel is an impossible level (so the two framings
//! can never be confused), `L`/`k` are the ciphertext / special limb counts
//! the material is bound to, and the polynomials are
//! `b_0.q, b_0.p, …, b_{dnum-1}.p, a_0.q, a_0.p, …`.

use crate::ckks::CkksParameters;
use crate::ckks::hybrid::CkksQpPoly;
use crate::{Error, Result};
use fhe_math::rq::{Context, Ntt, Poly, RepresentationTag};
use fhe_traits::{DeserializeWithContext, Serialize};
use std::sync::Arc;

/// Upper bound on the decomposition width accepted when decoding. The width
/// equals the number of RNS limbs at the key's level; 64 exceeds any chain
/// this crate can build (62-bit limbs, `Q` well under 4000 bits).
const MAX_WIDTH: usize = 64;

/// Sentinel in the `level` slot marking the hybrid framing.
const HYBRID_SENTINEL: u32 = 0xffff_fffe;

/// Byte reader shared by both decoders.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    what: &'a str,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|&e| e <= self.bytes.len())
            .ok_or_else(|| Error::DefaultError(format!("truncated {}", self.what)))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u32(&mut self) -> Result<usize> {
        let b = self.take(4)?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(b);
        Ok(u32::from_le_bytes(arr) as usize)
    }

    fn poly<R: RepresentationTag>(&mut self, ctx: &Arc<Context>) -> Result<Poly<R>>
    where
        Poly<R>: DeserializeWithContext<Error = fhe_math::Error, Context = Context>,
    {
        let len = self.u32()?;
        let b = self.take(len)?;
        Poly::<R>::from_bytes(b, ctx).map_err(Error::MathError)
    }

    fn finish(&self) -> Result<()> {
        if self.at != self.bytes.len() {
            return Err(Error::DefaultError(format!(
                "trailing bytes after {}",
                self.what
            )));
        }
        Ok(())
    }
}

fn push_poly<R: RepresentationTag>(out: &mut Vec<u8>, poly: &Poly<R>) {
    let b = poly.to_bytes();
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(&b);
}

/// Serialize hybrid key material `first ++ second` (each `dnum` `Q·P`
/// elements).
pub(crate) fn encode_hybrid_polys(
    par: &CkksParameters,
    first: &[CkksQpPoly],
    second: &[CkksQpPoly],
) -> Vec<u8> {
    debug_assert_eq!(first.len(), second.len());
    let mut out = Vec::new();
    out.extend_from_slice(&HYBRID_SENTINEL.to_le_bytes());
    out.extend_from_slice(&(first.len() as u32).to_le_bytes());
    out.extend_from_slice(&(par.moduli().len() as u32).to_le_bytes());
    out.extend_from_slice(&(par.special_moduli().len() as u32).to_le_bytes());
    for qp in first.iter().chain(second.iter()) {
        push_poly(&mut out, &qp.q);
        push_poly(&mut out, &qp.p);
    }
    out
}

/// Decode a buffer produced by [`encode_hybrid_polys`] against `par`
/// (hybrid must be enabled; `dnum`, `L` and `k` must match).
pub(crate) fn decode_hybrid_polys(
    bytes: &[u8],
    par: &Arc<CkksParameters>,
    what: &str,
) -> Result<(Vec<CkksQpPoly>, Vec<CkksQpPoly>)> {
    let ctx_p = par.context_p()?.clone();
    let ctx_q = par.context_at_level(0)?.clone();
    let mut r = Reader { bytes, at: 0, what };
    if r.u32()? != HYBRID_SENTINEL as usize {
        return Err(Error::DefaultError(format!(
            "{what}: not a hybrid key-material framing"
        )));
    }
    let dnum = r.u32()?;
    let num_limbs = r.u32()?;
    let k = r.u32()?;
    if dnum == 0 || dnum > MAX_WIDTH || dnum != par.dnum() {
        return Err(Error::DefaultError(format!(
            "{what} has {dnum} digits, parameters expect {}",
            par.dnum()
        )));
    }
    if num_limbs != par.moduli().len() || k != par.special_moduli().len() {
        return Err(Error::DefaultError(format!(
            "{what} bound to (L={num_limbs}, k={k}), parameters have (L={}, k={})",
            par.moduli().len(),
            par.special_moduli().len()
        )));
    }
    let mut polys = Vec::with_capacity(2 * dnum);
    for _ in 0..2 * dnum {
        let q = r.poly::<Ntt>(&ctx_q)?;
        let p = r.poly::<Ntt>(&ctx_p)?;
        polys.push(CkksQpPoly { q, p });
    }
    r.finish()?;
    let second = polys.split_off(dnum);
    Ok((polys, second))
}

/// Serialize `level` followed by `first ++ second`, length-prefixed.
/// `first` and `second` must have equal length.
pub(crate) fn encode_leveled_polys<R: RepresentationTag>(
    level: usize,
    first: &[Poly<R>],
    second: &[Poly<R>],
) -> Vec<u8> {
    debug_assert_eq!(first.len(), second.len());
    let mut out = Vec::new();
    out.extend_from_slice(&(level as u32).to_le_bytes());
    out.extend_from_slice(&(first.len() as u32).to_le_bytes());
    for poly in first.iter().chain(second.iter()) {
        push_poly(&mut out, poly);
    }
    out
}

/// Decoded payload: `(level, context at that level, first, second)`.
pub(crate) struct LeveledPolys<R: RepresentationTag> {
    /// Level the polynomials are bound to.
    pub level: usize,
    /// Context at `level`.
    pub ctx: Arc<Context>,
    /// The `c0`/`h0` side.
    pub first: Vec<Poly<R>>,
    /// The `c1`/`h1` side.
    pub second: Vec<Poly<R>>,
}

/// Decode a buffer produced by [`encode_leveled_polys`] against `par`.
///
/// `what` names the object in error messages ("relin key" / "relin share").
pub(crate) fn decode_leveled_polys<R: RepresentationTag>(
    bytes: &[u8],
    par: &Arc<CkksParameters>,
    what: &str,
) -> Result<LeveledPolys<R>>
where
    Poly<R>: DeserializeWithContext<Error = fhe_math::Error, Context = Context>,
{
    let mut r = Reader { bytes, at: 0, what };
    let level = r.u32()?;
    if level == HYBRID_SENTINEL as usize {
        return Err(Error::DefaultError(format!(
            "{what}: hybrid key material, use the hybrid decoder"
        )));
    }
    let ctx = par.context_at_level(level)?.clone();
    let count = r.u32()?;
    if count == 0 || count > MAX_WIDTH {
        return Err(Error::DefaultError(format!(
            "implausible {what} width {count}"
        )));
    }
    if count != ctx.moduli().len() {
        return Err(Error::DefaultError(format!(
            "{what} width {count} does not match the {} moduli at level {level}",
            ctx.moduli().len()
        )));
    }
    let mut polys = Vec::with_capacity(2 * count);
    for _ in 0..2 * count {
        polys.push(r.poly::<R>(&ctx)?);
    }
    r.finish()?;
    let second = polys.split_off(count);
    Ok(LeveledPolys {
        level,
        ctx,
        first: polys,
        second,
    })
}

#[cfg(test)]
mod tests {
    use super::{decode_leveled_polys, encode_leveled_polys};
    use crate::ckks::CkksParametersBuilder;
    use fhe_math::rq::{Ntt, Poly};

    #[test]
    fn round_trip_and_rejections() {
        let params = CkksParametersBuilder::new()
            .set_degree(16)
            .set_moduli_sizes(&[40, 40, 40])
            .set_scale(2f64.powi(30))
            .build_arc()
            .unwrap();
        let mut rng = rand::rng();
        let ctx = params.context_at_level(1).unwrap();
        let a: Vec<Poly<Ntt>> = (0..2).map(|_| Poly::random(ctx, &mut rng)).collect();
        let b: Vec<Poly<Ntt>> = (0..2).map(|_| Poly::random(ctx, &mut rng)).collect();
        let bytes = encode_leveled_polys(1, &a, &b);

        let d = decode_leveled_polys::<Ntt>(&bytes, &params, "x").unwrap();
        assert_eq!(d.level, 1);
        assert_eq!(&d.ctx, ctx);
        assert_eq!(a, d.first);
        assert_eq!(b, d.second);

        // Truncated, trailing garbage, and wrong-width payloads are rejected.
        assert!(decode_leveled_polys::<Ntt>(&bytes[..bytes.len() - 1], &params, "x").is_err());
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(decode_leveled_polys::<Ntt>(&extended, &params, "x").is_err());
        let wrong_width = encode_leveled_polys(0, &a, &b); // level 0 has 3 moduli
        assert!(decode_leveled_polys::<Ntt>(&wrong_width, &params, "x").is_err());
    }
}
