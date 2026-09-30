//! Aggregation of threshold l-BFV key shares.
//!
//! Public-key and relinearization-key aggregation validate their shared
//! reference strings and combine additive contributions into operational keys.

use crate::aggregate::Aggregate;
use crate::bfv::KeySwitchingKey;
use crate::lbfv::{LBFVPublicKey, LBFVRelinearizationKey};
use crate::{Error, MultipartyError, Result};
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

/// Sum secret-dependent `c0` rows (`d0`/`d2`) in NTT form, then rebuild Shoup
/// tables. Shared `c1` rows (`d1`/`a`) are carried over, not summed.
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
/// Validates structure, parameters, levels, contexts, dimensions, shared URS/CRS
/// rows, and agreement with `public_key`'s CRS. Repeated or overlapping
/// reference-string rows are rejected; independence still requires honest
/// generation (see [`crate::lbfv`]).
///
/// The caller must use the same contributor set for both keys. This function
/// cannot verify that relation or same-secret consistency; mismatches can pass
/// validation and decrypt incorrectly. Prefer [`aggregate_key_pair`] to avoid
/// accidental collection mismatch. Authentication, duplicate/replay policy,
/// and proof verification are outside this API.
///
/// # Errors
///
/// Returns an error if `shares` is empty or if any observable property above
/// fails to hold.
/// Reference-string mismatch errors report zero-based indices in `shares`,
/// comparing against share 0. They do not establish which contributor is honest.
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
    for (index, s) in rest.iter().enumerate() {
        if s.ksk_r_to_s.c1 != first.ksk_r_to_s.c1 {
            return Err(crate::MultipartyError::ReferenceStringMismatch {
                role: crate::ReferenceStringRole::Urs,
                share_index: index + 1,
                reference_share_index: 0,
            }
            .into());
        }
    }

    // Verify the concrete a (CRS) polynomials match across all shares.
    for (index, s) in rest.iter().enumerate() {
        if s.ksk_s_to_r.c1 != first.ksk_s_to_r.c1 {
            return Err(crate::MultipartyError::ReferenceStringMismatch {
                role: crate::ReferenceStringRole::Crs,
                share_index: index + 1,
                reference_share_index: 0,
            }
            .into());
        }
    }

    // Reference-string gate on the shared rows: every share carries the same
    // URS `d1` and CRS `a` vectors (checked above), so validating the first
    // share's rows validates the assembled key. Repeated rows within either
    // vector and rows shared between the URS and CRS are rejected before the
    // aggregated key is built or published.
    crate::reference_string::validate_reference_string_pair(
        &first.ksk_r_to_s.ctx_ksk,
        &first.ksk_s_to_r.c1,
        &first.ksk_r_to_s.c1,
    )?;

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
            return Err(crate::MultipartyError::PublicKeyCrsMismatch {
                share_index: 0,
                row_index: j,
            }
            .into());
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

/// Aggregate paired public-key and relinearization-key contributions from one
/// selected contributor set into an operational
/// `(`[`LBFVPublicKey`]`, `[`LBFVRelinearizationKey`]`)` pair.
///
/// Both outputs use the same paired collection: omitting a pair omits both
/// halves. Form each pair from one contributor's secret summand. This prevents
/// accidental one-sided omissions, not malicious mispairing: same-secret
/// consistency is not proved or verified. Caller-side `zip` can also truncate
/// lists before submission. Duplicate pairs are summed twice; identities,
/// admission, and replay are not checked.
///
/// Uses [`Aggregate`] and [`aggregate_relinearization_key`]; their structural
/// validation and reference-string requirements apply.
///
/// # Errors
///
/// Returns an error if the collection is empty, or if any observable
/// validation performed by the underlying aggregation fails.
///
/// The aggregate error grows with the number of summed contributions. Callers
/// must ensure that the pair count is supported by their parameter set's
/// noise budget.
pub fn aggregate_key_pair<I>(pairs: I) -> Result<(LBFVPublicKey, LBFVRelinearizationKey)>
where
    I: IntoIterator<Item = (PublicKeyShare, RelinKeyShare)>,
{
    let pairs = pairs.into_iter().collect::<Vec<_>>();
    if pairs.is_empty() {
        return Err(Error::Multiparty(MultipartyError::NoShares));
    }

    // One paired collection becomes one PK collection and one RLK collection
    // of identical length; aggregation reuses the existing validated path.
    let (pk_shares, rlk_shares): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    let public_key = <LBFVPublicKey as Aggregate<PublicKeyShare>>::from_shares(pk_shares)?;
    let relin_key = aggregate_relinearization_key(&rlk_shares, &public_key)?;
    Ok((public_key, relin_key))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

    use super::*;
    use crate::aggregate::AggregateIter;
    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};
    use crate::support::presets::insecure;
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use std::sync::Arc;

    #[test]
    fn distributed_aggregation_works() -> Result<()> {
        let mut rng = rand::rng();
        let params = insecure().unwrap().parameters;

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
            .map(|sk| PublicKeyShare::contribute_with_seed(sk, a_seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;

        let pk: LBFVPublicKey = pk_shares.into_iter().aggregate()?;

        let rlk_shares: Vec<RelinKeyShare> = sks
            .iter()
            .map(|sk| RelinKeyShare::contribute_with_seed(sk, d1_seed, a_seed, 0, 0, &mut rng))
            .collect::<Result<Vec<_>>>()?;

        let rlk = aggregate_relinearization_key(&rlk_shares, &pk)?;

        // Verify multiplication + relinearization works.
        let joint_coeffs: Vec<i64> = (0..params.degree())
            .map(|d| sks.iter().map(|sk| sk.coeffs[d]).sum())
            .collect();
        let joint_sk = SecretKey::new(joint_coeffs, &params)?;
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

    /// Build a relinearization-key share from explicit URS/CRS rows without
    /// going through the validating contribution constructors, so the
    /// aggregation boundary can be exercised directly.
    fn crafted_share<R: rand::RngCore + rand::CryptoRng>(
        sk: &SecretKey,
        crs: &[Poly<NttShoup>],
        urs: &[Poly<NttShoup>],
        rng: &mut R,
    ) -> Result<RelinKeyShare> {
        use fhe_math::rq::{PowerBasis, traits::TryConvertFrom as TryConvertFromPoly};

        let ctx = sk.params.context_at_level(0)?;
        let sk_pb = Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), ctx, false)?;
        Ok(RelinKeyShare {
            ksk_r_to_s: KeySwitchingKey::new_with_c1(sk, &sk_pb, urs.to_vec(), 0, 0, rng)?,
            ksk_s_to_r: KeySwitchingKey::new_with_c1(sk, &sk_pb, crs.to_vec(), 0, 0, rng)?,
        })
    }

    /// Aggregation must refuse to publish a key whose URS rows collide with
    /// its CRS rows, even when every share is internally consistent.
    #[test]
    fn aggregation_rejects_urs_row_equal_to_crs_row() -> Result<()> {
        let mut rng = rand::rng();
        let params = insecure().unwrap().parameters;
        let sks: Vec<SecretKey> = (0..2)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let ctx0 = params.context_at_level(0)?;

        // Concrete CRS rows shared by the public key and the RLK shares.
        let a_ntt: Vec<Poly<Ntt>> = (0..params.moduli().len())
            .map(|_| Poly::<Ntt>::random(ctx0, &mut rng))
            .collect();
        let crs: Vec<Poly<NttShoup>> = a_ntt.iter().map(|p| p.clone().into_ntt_shoup()).collect();

        let pk_shares: Vec<PublicKeyShare> = sks
            .iter()
            .map(|sk| PublicKeyShare::contribute_with_polys(sk, &a_ntt, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let public_key: LBFVPublicKey = pk_shares.into_iter().aggregate()?;

        // URS rows colliding with CRS row 1 at a cross-index position.
        let mut urs = KeySwitchingKey::c1_from_seed(ctx0, [31u8; 32], params.moduli().len());
        urs[2] = crs[1].clone();

        let shares: Vec<RelinKeyShare> = sks
            .iter()
            .map(|sk| crafted_share(sk, &crs, &urs, &mut rng))
            .collect::<Result<Vec<_>>>()?;

        assert!(matches!(
            aggregate_relinearization_key(&shares, &public_key),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::OverlappingReferenceStringRows {
                    crs_index: 1,
                    urs_index: 2,
                }
            ))
        ));

        // Control: fully independent URS rows aggregate successfully.
        let independent = KeySwitchingKey::c1_from_seed(ctx0, [32u8; 32], params.moduli().len());
        let shares: Vec<RelinKeyShare> = sks
            .iter()
            .map(|sk| crafted_share(sk, &crs, &independent, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        aggregate_relinearization_key(&shares, &public_key)?;
        Ok(())
    }

    /// Aggregation must refuse to publish a key whose URS vector repeats a
    /// row.
    #[test]
    fn aggregation_rejects_repeated_urs_rows() -> Result<()> {
        let mut rng = rand::rng();
        let params = insecure().unwrap().parameters;
        let sks: Vec<SecretKey> = (0..2)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let ctx0 = params.context_at_level(0)?;

        let a_ntt: Vec<Poly<Ntt>> = (0..params.moduli().len())
            .map(|_| Poly::<Ntt>::random(ctx0, &mut rng))
            .collect();
        let crs: Vec<Poly<NttShoup>> = a_ntt.iter().map(|p| p.clone().into_ntt_shoup()).collect();

        let pk_shares: Vec<PublicKeyShare> = sks
            .iter()
            .map(|sk| PublicKeyShare::contribute_with_polys(sk, &a_ntt, &mut rng))
            .collect::<Result<Vec<_>>>()?;
        let public_key: LBFVPublicKey = pk_shares.into_iter().aggregate()?;

        let mut urs = KeySwitchingKey::c1_from_seed(ctx0, [41u8; 32], params.moduli().len());
        urs[2] = urs[0].clone();

        let shares: Vec<RelinKeyShare> = sks
            .iter()
            .map(|sk| crafted_share(sk, &crs, &urs, &mut rng))
            .collect::<Result<Vec<_>>>()?;

        assert!(matches!(
            aggregate_relinearization_key(&shares, &public_key),
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

    // -------------------------------------------------------------------------
    // Paired (PublicKeyShare, RelinKeyShare) aggregation
    // -------------------------------------------------------------------------

    /// One `(pk, rlk)` contribution pair per secret key, all bound to the
    /// shared CRS/URS seeds, mirroring what an integrating protocol would
    /// collect from its (externally authenticated) contributors.
    fn paired_contributions<R: rand::RngCore + rand::CryptoRng>(
        sks: &[SecretKey],
        crs_seed: <ChaCha8Rng as SeedableRng>::Seed,
        urs_seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Result<Vec<(PublicKeyShare, RelinKeyShare)>> {
        sks.iter()
            .map(|sk| {
                Ok((
                    PublicKeyShare::contribute_with_seed(sk, crs_seed, rng)?,
                    RelinKeyShare::contribute_with_seed(sk, urs_seed, crs_seed, 0, 0, rng)?,
                ))
            })
            .collect()
    }

    /// Encrypt `value` under `pk`, square, relinearize with `rlk`, and
    /// decrypt under the sum of `sks`. Returns the decoded first coefficient.
    fn square_decrypt<R: rand::RngCore + rand::CryptoRng>(
        pk: &LBFVPublicKey,
        rlk: &LBFVRelinearizationKey,
        sks: &[SecretKey],
        params: &Arc<BfvParameters>,
        rng: &mut R,
        value: u64,
    ) -> Result<u64> {
        let pt = Plaintext::try_encode(&[value], Encoding::poly(), params)?;
        let ct = pk.try_encrypt(&pt, rng)?;
        let mut square = &ct * &ct;
        rlk.relinearizes(&mut square)?;
        let joint_coeffs: Vec<i64> = (0..params.degree())
            .map(|d| sks.iter().map(|sk| sk.coeffs[d]).sum())
            .collect();
        let joint_sk = SecretKey::new(joint_coeffs, params)?;
        let decoded = Vec::<u64>::try_decode(&joint_sk.try_decrypt(&square)?, Encoding::poly())?;
        Ok(decoded.first().copied().expect("decoded coefficient"))
    }

    /// Control: a matched three-pair submission yields keys that multiply,
    /// relinearize, and decrypt correctly under the corresponding summed
    /// secret key.
    #[test]
    fn paired_aggregation_three_contributors_is_functional() -> Result<()> {
        let mut rng = rand::rng();
        let params = insecure().unwrap().parameters;
        let sks: Vec<SecretKey> = (0..3)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let pairs = paired_contributions(
            &sks,
            <ChaCha8Rng as SeedableRng>::Seed::default(),
            [10u8; 32],
            &mut rng,
        )?;

        let (pk, rlk) = aggregate_key_pair(pairs)?;
        assert_eq!(square_decrypt(&pk, &rlk, &sks, &params, &mut rng, 3)?, 9);
        Ok(())
    }

    /// The empty submission is rejected.
    #[test]
    fn paired_aggregation_rejects_empty_input() {
        let result = aggregate_key_pair(Vec::<(PublicKeyShare, RelinKeyShare)>::new());
        assert!(matches!(
            result,
            Err(crate::Error::Multiparty(crate::MultipartyError::NoShares))
        ));
    }

    /// Omitting a whole pair yields a coherent two-contributor key, functional
    /// under the summed secret keys of exactly the selected pairs. This is the
    /// paired-path rendering of the historical mismatch (a public key from
    /// three contributors against a relinearization key from two): the
    /// one-sided version of that mismatch cannot be expressed here — a pair
    /// submission has as many PK halves as RLK halves, and dropping a
    /// contributor necessarily drops both of its halves. The library cannot
    /// tell whether the *remaining* set is the protocol's intended one; that
    /// selection is the caller's responsibility.
    #[test]
    fn paired_aggregation_whole_pair_omission_is_functional() -> Result<()> {
        let mut rng = rand::rng();
        let params = insecure().unwrap().parameters;
        let sks: Vec<SecretKey> = (0..3)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let pairs = paired_contributions(
            &sks,
            <ChaCha8Rng as SeedableRng>::Seed::default(),
            [10u8; 32],
            &mut rng,
        )?;

        // Submit only the pairs of the first two contributors.
        let (pk, rlk) = aggregate_key_pair(vec![pairs[0].clone(), pairs[1].clone()])?;
        assert_eq!(
            square_decrypt(&pk, &rlk, &sks[0..2], &params, &mut rng, 3)?,
            9
        );
        Ok(())
    }

    /// Whole-pair reordering yields the same operational keys: aggregation is
    /// a commutative sum over the submitted pairs (and all shares carry the
    /// same reference-string seeds, so seed preservation is unaffected by
    /// which pair comes first).
    #[test]
    fn paired_aggregation_is_order_independent() -> Result<()> {
        let mut rng = rand::rng();
        let params = insecure().unwrap().parameters;
        let sks: Vec<SecretKey> = (0..3)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let pairs = paired_contributions(
            &sks,
            <ChaCha8Rng as SeedableRng>::Seed::default(),
            [10u8; 32],
            &mut rng,
        )?;

        let forward = aggregate_key_pair(pairs.clone())?;
        let mut reversed = pairs;
        reversed.reverse();
        let backward = aggregate_key_pair(reversed)?;

        assert_eq!(forward.0, backward.0);
        assert_eq!(forward.1, backward.1);
        assert_eq!(
            square_decrypt(&backward.0, &backward.1, &sks, &params, &mut rng, 3)?,
            9
        );
        Ok(())
    }

    /// Duplicating a whole pair is honest arithmetic, not an error: the
    /// duplicated contribution is summed twice, and the keys decrypt under
    /// the corresponding multiset of secret keys. Duplicate policing is
    /// application-level admission policy, outside this arithmetic library.
    #[test]
    fn paired_aggregation_of_duplicated_pair_matches_multiset() -> Result<()> {
        let mut rng = rand::rng();
        let params = insecure().unwrap().parameters;
        let sks: Vec<SecretKey> = (0..2)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let pairs = paired_contributions(
            &sks,
            <ChaCha8Rng as SeedableRng>::Seed::default(),
            [10u8; 32],
            &mut rng,
        )?;

        // Multiset {A, A, B}: the repeated pair counts twice.
        let duplicated = vec![pairs[0].clone(), pairs[0].clone(), pairs[1].clone()];
        let (pk, rlk) = aggregate_key_pair(duplicated)?;

        // Functional under the multiset sum sk_a + sk_a + sk_b.
        let multiset_sks = vec![sks[0].clone(), sks[0].clone(), sks[1].clone()];
        assert_eq!(
            square_decrypt(&pk, &rlk, &multiset_sks, &params, &mut rng, 3)?,
            9
        );

        Ok(())
    }

    /// Intentionally cross-paired input — a PK half from one contributor set
    /// paired with an RLK half from another — is accepted and cannot be
    /// detected: the library validates observable reference strings, not
    /// which contributor produced which half. The output is exactly what the
    /// separate-list path produces from the same halves,
    /// which is the point: pairing constrains counts, not provenance.
    #[test]
    fn intentionally_cross_paired_input_is_accepted_undetected() -> Result<()> {
        let mut rng = rand::rng();
        let params = insecure().unwrap().parameters;
        let sks_a: Vec<SecretKey> = (0..2)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let sks_b: Vec<SecretKey> = (0..2)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        // One broadcast CRS (as a protocol coin-toss would establish) and a
        // distinct URS per set.
        let crs_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let pairs_a = paired_contributions(&sks_a, crs_seed, [10u8; 32], &mut rng)?;
        let pairs_b = paired_contributions(&sks_b, crs_seed, [11u8; 32], &mut rng)?;

        let cross = vec![
            (pairs_a[0].0.clone(), pairs_b[0].1.clone()),
            (pairs_a[1].0.clone(), pairs_b[1].1.clone()),
        ];
        let (pk_cross, rlk_cross) = aggregate_key_pair(cross)?;

        // The PK half is exactly set A's public key.
        let pk_a_halves: Vec<PublicKeyShare> = pairs_a.iter().map(|(pk, _)| pk.clone()).collect();
        let pk_a: LBFVPublicKey = pk_a_halves.into_iter().aggregate()?;
        assert_eq!(pk_cross, pk_a);

        // The RLK half is exactly B's RLK aggregated against A's public key —
        // i.e. what the separate-list API produces for this mismatch.
        let rlk_b_halves: Vec<RelinKeyShare> = pairs_b.iter().map(|(_, rlk)| rlk.clone()).collect();
        let rlk_b_against_a = aggregate_relinearization_key(&rlk_b_halves, &pk_a)?;
        assert_eq!(rlk_cross, rlk_b_against_a);
        Ok(())
    }

    /// The truncation hazard lives in caller-side input construction, not in
    /// this API: zipping two separately-built half lists of unequal lengths
    /// yields a shorter pair iterator, and the library honestly aggregates
    /// exactly the pairs it receives. Generating both halves together per
    /// contributor — as the paired examples do — avoids the hazard by
    /// construction instead of relying on the library to catch it.
    #[test]
    fn caller_side_zip_truncation_is_aggregated_as_submitted() -> Result<()> {
        let mut rng = rand::rng();
        let params = insecure().unwrap().parameters;
        let sks: Vec<SecretKey> = (0..3)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let crs_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let pairs = paired_contributions(&sks, crs_seed, [10u8; 32], &mut rng)?;

        // Caller builds the halves separately and zips 3 PK halves against
        // 2 RLK halves: the zip truncates before this API is reached.
        let pk_halves = pairs.iter().map(|(pk, _)| pk.clone());
        let rlk_halves = pairs.iter().take(2).map(|(_, rlk)| rlk.clone());
        let truncated: Vec<(PublicKeyShare, RelinKeyShare)> = pk_halves.zip(rlk_halves).collect();
        assert_eq!(truncated.len(), 2, "caller-side zip truncated to 2 pairs");

        // The library aggregates exactly the submitted pairs: a coherent,
        // functional two-contributor key for the surviving summands.
        let (pk, rlk) = aggregate_key_pair(truncated)?;
        assert_eq!(
            square_decrypt(&pk, &rlk, &sks[0..2], &params, &mut rng, 3)?,
            9
        );
        Ok(())
    }
}
