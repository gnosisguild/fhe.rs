use super::{Aggregate, LBFVPublicKey, LBFVRelinearizationKey, PublicKeyShare, RelinKeyShare};
use crate::bfv::KeySwitchingKey;
use crate::lbfv::keys::components::{Components, validate_crs_tail};
use crate::reference_string::same_concrete_values;
use crate::{
    Error, EvaluationKeyError, MultipartyError, ParameterSource, ReferenceStringRole, Result,
};
use fhe_math::rq::{Ntt, NttShoup, Poly};

impl Aggregate<PublicKeyShare> for LBFVPublicKey {
    fn from_shares<T: IntoIterator<Item = PublicKeyShare>>(iter: T) -> Result<Self> {
        let mut shares = iter.into_iter();
        let mut pk = shares.next().ok_or(MultipartyError::NoShares)?.0;
        // The private PublicKeyShare wrapper is validated on construction and import.
        // Only the b rows add; a is one common random string, even for a singleton.
        for (i, PublicKeyShare(key)) in shares.enumerate() {
            if key.par != pk.par {
                return Err(Error::ParameterMismatch {
                    left: ParameterSource::PublicKey,
                    right: ParameterSource::Parameters,
                });
            }
            for (row, other) in pk.c.iter_mut().zip(&key.c) {
                let ([sum, a], [b, other_a]) = (row.c.as_mut_slice(), other.c.as_slice()) else {
                    return Err(EvaluationKeyError::InvalidLbfvLayout {
                        reason: "public-key contribution is not a pair",
                    }
                    .into());
                };
                if !same_concrete_values(a, other_a) {
                    return Err(MultipartyError::ReferenceStringMismatch {
                        role: ReferenceStringRole::Crs,
                        share_index: i + 1,
                        reference_share_index: 0,
                    }
                    .into());
                }
                *sum += b;
            }
            if pk.seed != key.seed {
                pk.seed = None;
            }
        }
        if pk.seed.is_none() {
            pk.c.iter_mut().for_each(|row| row.seed = None);
        }
        Ok(pk)
    }
}

/// Sum one direction of the key switch in NTT form, then rebuild its Shoup
/// tables. Only `c0` adds; `c1` is the same reference string for every party.
fn sum_direction<'a>(
    first: &KeySwitchingKey,
    rest: impl Iterator<Item = &'a KeySwitchingKey>,
) -> KeySwitchingKey {
    let mut key = first.clone();
    let mut sums: Vec<_> = std::mem::take(&mut key.c0)
        .into_vec()
        .into_iter()
        .map(Poly::<NttShoup>::into_ntt)
        .collect();
    for part in rest {
        for (sum, row) in sums.iter_mut().zip(&part.c0) {
            *sum += &row.clone().into_ntt();
        }
    }
    key.c0 = sums.into_iter().map(Poly::<Ntt>::into_ntt_shoup).collect();
    key
}

/// Combine relinearization shares with an already aggregated public key. The
/// caller must select exactly the same contributors for both keys. Prefer
/// [`aggregate_key_pair`] when both sets of contributions are available.
/// Its dealer-admission and confidentiality requirements apply here as well.
pub fn aggregate_relinearization_key(
    shares: &[RelinKeyShare],
    public_key: &LBFVPublicKey,
) -> Result<LBFVRelinearizationKey> {
    let (first, rest) = shares.split_first().ok_or(MultipartyError::NoShares)?;
    public_key.validate_rows()?;
    if first.0.r_to_s.params != public_key.par {
        return Err(Error::ParameterMismatch {
            left: ParameterSource::RelinearizationKey,
            right: ParameterSource::PublicKey,
        });
    }
    let count = first.a_components().len();
    for (i, share) in rest.iter().enumerate() {
        if share.0.r_to_s.params != public_key.par
            || share.ciphertext_level() != first.ciphertext_level()
        {
            return Err(EvaluationKeyError::InvalidLbfvLayout {
                reason: "contributions have different parameters or levels",
            }
            .into());
        }
        for (role, expected, actual) in [
            (
                ReferenceStringRole::Crs,
                first.a_components(),
                share.a_components(),
            ),
            (
                ReferenceStringRole::Urs,
                first.d1_components(),
                share.d1_components(),
            ),
        ] {
            if actual.len() != count
                || !expected
                    .iter()
                    .zip(actual)
                    .all(|(a, b)| same_concrete_values(a, b))
            {
                return Err(MultipartyError::ReferenceStringMismatch {
                    role,
                    share_index: i + 1,
                    reference_share_index: 0,
                }
                .into());
            }
        }
    }
    // All contributors now agree on a. Compare the actual canonical NTT
    // residues with the PK prefix; the Shoup table is not part of the value.
    for (row_index, (a, row)) in first.a_components().iter().zip(&public_key.c).enumerate() {
        if row
            .get(1)
            .is_none_or(|pk_a| pk_a.coefficients() != a.coefficients())
        {
            return Err(MultipartyError::PublicKeyCrsMismatch { row_index }.into());
        }
    }
    validate_crs_tail(
        public_key.c.iter().filter_map(|row| row.get(1)),
        first.d1_components(),
    )?;
    let mut r_to_s = sum_direction(&first.0.r_to_s, rest.iter().map(|s| &s.0.r_to_s));
    let mut s_to_r = sum_direction(&first.0.s_to_r, rest.iter().map(|s| &s.0.s_to_r));
    // As on dev, retain the RLK's seed metadata only by unanimous agreement
    // on both directions. Otherwise serialize the verified concrete rows.
    if rest
        .iter()
        .any(|share| share.0.r_to_s.seed != r_to_s.seed || share.0.s_to_r.seed != s_to_r.seed)
    {
        r_to_s.seed = None;
        s_to_r.seed = None;
    }
    LBFVRelinearizationKey::from_components(
        Components::checked(r_to_s, s_to_r)?,
        public_key.b_prefix(count),
    )
}

/// Aggregate both operational keys from one collection of matched contributions.
/// An omitted pair is omitted from both keys. Admit one pair per authenticated
/// dealer for this epoch and level, including on retries: every submitted pair is summed.
/// The caller verifies that each pair uses the same secret summand as its Shamir sharing.
/// Form pairs at admission: zipping independent streams silently truncates to the shorter one.
///
/// An authenticated dealer who chooses its contribution after seeing the
/// others' can compromise confidentiality: it may know the aggregate decryption
/// key. Use a binding, hiding commit-then-reveal protocol for the full pairs
/// (fix all commitments before any reveal), or verify proofs of knowledge and
/// correct formation bound to the ceremony. Aggregation verifies neither.
pub fn aggregate_key_pair<I: IntoIterator<Item = (PublicKeyShare, RelinKeyShare)>>(
    pairs: I,
) -> Result<(LBFVPublicKey, LBFVRelinearizationKey)> {
    let (pk, rlk): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    let pk = LBFVPublicKey::from_shares(pk)?;
    let rlk = aggregate_relinearization_key(&rlk, &pk)?;
    Ok((pk, rlk))
}
