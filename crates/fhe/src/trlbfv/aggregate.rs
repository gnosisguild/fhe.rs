//! Aggregation of threshold l-BFV key shares.
//!
//! Public-key and relinearization-key aggregation validate their shared
//! reference strings and combine additive contributions into operational keys.

use crate::aggregate::Aggregate;
use crate::bfv::KeySwitchingKey;
use crate::lbfv::{LBFVPublicKey, LBFVRelinearizationKey};
use crate::{Error, Result};
use fhe_math::rq::{Ntt, NttShoup, Poly, Representation};

use super::public_key_share::PublicKeyShare;
use super::relin_key_share::RelinKeyShare;

// ---------------------------------------------------------------------------
// Public-key aggregation helpers
// ---------------------------------------------------------------------------

/// Core public-key aggregation: CRS polynomial validation, b-polynomial
/// summation, seed preservation, and key construction.
fn aggregate_pk_shares_core(shares: &[PublicKeyShare]) -> Result<LBFVPublicKey> {
    let (first, rest) = shares.split_first().ok_or_else(|| {
        Error::DefaultError("Cannot aggregate zero public-key shares".to_string())
    })?;

    // Concrete CRS `a` polynomials must match.
    for (j, first_ct) in first.key.c.iter().enumerate() {
        let a_first = first_ct.c.get(1).ok_or_else(|| {
            Error::DefaultError("LBFV public-key ciphertext is missing a".to_string())
        })?;
        for share in rest {
            let ct_j = share.key.c.get(j).ok_or_else(|| {
                Error::DefaultError("LBFV public-key ciphertext count changed".to_string())
            })?;
            let a_other = ct_j.c.get(1).ok_or_else(|| {
                Error::DefaultError("LBFV public-key ciphertext is missing a".to_string())
            })?;
            if a_first != a_other {
                return Err(Error::DefaultError(
                    "Public-key shares use different CRS polynomials".to_string(),
                ));
            }
        }
    }

    // Extract the shared a polynomials from the first share.
    let a_polys: Vec<Poly<Ntt>> = first
        .key
        .c
        .iter()
        .map(|ct| {
            ct.c.get(1).cloned().ok_or_else(|| {
                Error::DefaultError("LBFV public-key ciphertext is missing a".to_string())
            })
        })
        .collect::<Result<_>>()?;

    // Sum b polynomials across all shares.
    let b_sums: Vec<Poly<Ntt>> = (0..first.key.c.len())
        .map(|j| {
            let mut sum = first
                .key
                .c
                .get(j)
                .and_then(|ct| ct.c.first())
                .cloned()
                .ok_or_else(|| {
                    Error::DefaultError("LBFV public-key ciphertext is missing b".to_string())
                })?;
            for share in rest {
                let b = share
                    .key
                    .c
                    .get(j)
                    .and_then(|ct| ct.c.first())
                    .ok_or_else(|| {
                        Error::DefaultError("LBFV public-key ciphertext is missing b".to_string())
                    })?;
                sum += b;
            }
            Ok(sum)
        })
        .collect::<Result<_>>()?;

    // Preserve seed only when all shares have the same seed.
    let shared_seed = first
        .key
        .seed
        .filter(|seed| shares.iter().all(|share| share.key.seed == Some(*seed)));

    LBFVPublicKey::from_parts(b_sums, a_polys, first.key.params.clone(), shared_seed)
}

impl Aggregate<PublicKeyShare> for LBFVPublicKey {
    /// Aggregate public-key shares after validating their parameters and CRS.
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = PublicKeyShare>,
    {
        let shares = iter.into_iter().collect::<Vec<_>>();
        let (first, rest) = shares.split_first().ok_or_else(|| {
            Error::DefaultError("Cannot aggregate zero public-key shares".to_string())
        })?;

        // Validate structure of every share's key.
        first.key.validate_structure()?;
        for share in rest {
            share.key.validate_structure()?;
        }

        // Parameters must match.
        if rest.iter().any(|s| s.key.params != first.key.params) {
            return Err(Error::DefaultError(
                "Public-key shares use different parameters".to_string(),
            ));
        }

        aggregate_pk_shares_core(&shares)
    }
}

// ---------------------------------------------------------------------------
// Relinearization-key aggregation helpers
// ---------------------------------------------------------------------------

/// Sum the `c0` components of a set of key-switching keys, coordinate-wise over
/// the gadget dimension.
///
/// This is the additive aggregation `Σ d0_i` / `Σ d2_i`: each share's
/// secret-dependent part (`d0_i` for `ksk_r_to_s`, `d2_i` for `ksk_s_to_r`) is
/// stored as that key-switching key's `c0` component, so summing the `c0`s is
/// exactly summing the `d0_i` / `d2_i`. The shared `c1` (= `d1` / `a`) is not
/// summed — it is identical across shares and carried over by the caller.
///
/// Aggregation is a rare generation-time operation, so we pay the cost here:
/// convert each operand to `Ntt` (which supports addition), sum, and rebuild
/// the Shoup table once via `into_ntt_shoup` for the cheap-multiply property
/// to hold on the hot path.
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

// ---------------------------------------------------------------------------
// Relinearization-key aggregation
// ---------------------------------------------------------------------------

/// Aggregate threshold l-BFV relinearization-key contributions into an
/// operational [`LBFVRelinearizationKey`].
///
/// The caller is responsible for selecting and authenticating contributions
/// and for preventing duplicate inclusion. This function validates arithmetic
/// structure, shared URS/CRS values, and consistency with `public_key`.
///
/// The aggregate error grows with the number of summed contributions. Callers
/// must ensure that `shares.len()` is supported by their parameter set's noise
/// budget.
pub fn aggregate_relinearization_key(
    shares: &[RelinKeyShare],
    public_key: &LBFVPublicKey,
) -> Result<LBFVRelinearizationKey> {
    let (first, rest) = shares.split_first().ok_or_else(|| {
        Error::DefaultError("Cannot aggregate zero relinearization key shares".to_string())
    })?;

    // Validate public key structure.
    public_key.validate_structure()?;

    // Structural validation of every share's KSKs.
    for (i, share) in shares.iter().enumerate() {
        if share.ksk_r_to_s.params != first.ksk_r_to_s.params {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has different r->s parameters"
            )));
        }
        if i == 0 && share.ksk_r_to_s.params != public_key.params {
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
                "Relinearization key shares are inconsistent (differing r->s levels)".to_string(),
            ));
        }
        if share.ksk_r_to_s.ctx_ciphertext != first.ksk_r_to_s.ctx_ciphertext
            || share.ksk_r_to_s.ctx_ksk != first.ksk_r_to_s.ctx_ksk
        {
            return Err(Error::DefaultError(
                "Relinearization key shares are inconsistent (differing r->s contexts)".to_string(),
            ));
        }
        if share.ksk_s_to_r.params != first.ksk_s_to_r.params {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has different s->r parameters"
            )));
        }
        if share.ksk_s_to_r.ciphertext_level != first.ksk_s_to_r.ciphertext_level
            || share.ksk_s_to_r.ksk_level != first.ksk_s_to_r.ksk_level
        {
            return Err(Error::DefaultError(
                "Relinearization key shares are inconsistent (differing s->r levels)".to_string(),
            ));
        }
        if share.ksk_s_to_r.ctx_ciphertext != first.ksk_s_to_r.ctx_ciphertext
            || share.ksk_s_to_r.ctx_ksk != first.ksk_s_to_r.ctx_ksk
        {
            return Err(Error::DefaultError(
                "Relinearization key shares are inconsistent (differing s->r contexts)".to_string(),
            ));
        }
        if share.ksk_s_to_r.log_base != first.ksk_s_to_r.log_base {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has inconsistent s->r log_base"
            )));
        }
        if share.ksk_r_to_s.c0.len() != share.ksk_s_to_r.c0.len() {
            return Err(Error::DefaultError(format!(
                "Relinearization key share {i} has mismatched r->s/s->r c0 dimensions"
            )));
        }
        // Cross-KSK consistency.
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

    // Determine whether all input KSKs share the same seeds.
    let seeds_match = shares
        .iter()
        .all(|s| s.ksk_r_to_s.seed == first.ksk_r_to_s.seed)
        && shares
            .iter()
            .all(|s| s.ksk_s_to_r.seed == first.ksk_s_to_r.seed);

    // CRS consistency: the a polynomials in ksk_s_to_r.c1 must match the
    // public key's a_j ciphertext polynomials.
    let pk_ctx0 = public_key.params.context_at_level(0)?;
    let ksk_ctx = &first.ksk_s_to_r.ctx_ksk;
    if ksk_ctx != pk_ctx0 {
        return Err(Error::DefaultError(
            "Cannot verify CRS consistency: RLK key context differs from public key level-0 context"
                .to_string(),
        ));
    }
    let new_l = public_key
        .l
        .checked_sub(first.ksk_r_to_s.ciphertext_level)
        .ok_or_else(|| {
            Error::DefaultError(
                "CRS consistency failed: ciphertext_level exceeds public-key l".to_string(),
            )
        })?;
    if first.ksk_s_to_r.c1.len() != new_l {
        return Err(Error::DefaultError(
            "CRS consistency failed: RLK's a polynomial count does not match expected l - ciphertext_level"
                .to_string(),
        ));
    }
    for (j, c1_j) in first.ksk_s_to_r.c1.iter().enumerate() {
        let mut a_ksk: Poly<Ntt> = c1_j.clone().into_ntt();
        a_ksk.disallow_variable_time_computations();
        let pk_a_j = public_key
            .c
            .get(j)
            .and_then(|ct| ct.c.get(1))
            .ok_or_else(|| {
                Error::DefaultError("Public key is missing its a_j polynomial".to_string())
            })?;
        if a_ksk != *pk_a_j {
            return Err(Error::DefaultError(
                "CRS consistency failed: RLK's a_j does not match public key's a_j".to_string(),
            ));
        }
    }

    let ciphertext_level = first.ksk_r_to_s.ciphertext_level;
    let key_level = first.ksk_r_to_s.ksk_level;
    let b_vec =
        public_key.extract_b_polynomials(ciphertext_level, key_level, Representation::NttShoup)?;

    let mut ksk_r_to_s = first.ksk_r_to_s.clone();
    ksk_r_to_s.c0 = sum_ksk_c0(shares.iter().map(|s| &s.ksk_r_to_s))?;

    let mut ksk_s_to_r = first.ksk_s_to_r.clone();
    ksk_s_to_r.c0 = sum_ksk_c0(shares.iter().map(|s| &s.ksk_s_to_r))?;

    if !seeds_match {
        ksk_r_to_s.seed = None;
        ksk_s_to_r.seed = None;
    }

    LBFVRelinearizationKey::from_components(ksk_r_to_s, ksk_s_to_r, b_vec)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

    use super::*;
    use crate::aggregate::AggregateIter;
    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn distributed_aggregation_works() -> Result<()> {
        let mut rng = rand::rng();
        let params = BfvParameters::default_arc(6, 8);

        let sks: Vec<SecretKey> = (0..3)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        let a_seed = {
            let mut s = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill_bytes(&mut s);
            s
        };
        let d1_seed = {
            let mut s = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill_bytes(&mut s);
            s
        };

        let pk_shares: Vec<PublicKeyShare> = sks
            .iter()
            .map(|sk| PublicKeyShare::new_with_seed(sk, a_seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;

        let pk: LBFVPublicKey = pk_shares.into_iter().aggregate()?;

        let rlk_shares: Vec<RelinKeyShare> = sks
            .iter()
            .map(|sk| RelinKeyShare::contribution(sk, d1_seed, a_seed, 0, 0, &mut rng))
            .collect::<Result<Vec<_>>>()?;

        let rlk = aggregate_relinearization_key(&rlk_shares, &pk)?;

        // Verify multiplication + relinearization works.
        let joint_coeffs: Vec<i64> = (0..params.degree())
            .map(|d| sks.iter().map(|sk| sk.coeffs[d]).sum())
            .collect();
        let joint_sk = SecretKey::new(joint_coeffs, &params);
        let pt = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        let mut square = &ct * &ct;
        rlk.relinearizes(&mut square)?;
        assert_eq!(
            Vec::<u64>::try_decode(&joint_sk.try_decrypt(&square)?, Encoding::poly())?.first(),
            Some(&9)
        );

        Ok(())
    }
}
