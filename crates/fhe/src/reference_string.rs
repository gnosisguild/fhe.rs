//! Reference-string validation primitives and the l-BFV boundary that maps
//! them onto the public multiparty errors.
//!
//! # Role-neutral core
//!
//! The core primitives (`same_concrete_values`, `validate_distinct_seeds`,
//! `find_repeated_row`, `find_cross_overlap`) assign no protocol meaning to
//! their arguments: seeds are compared by `Eq` and row vectors are named
//! `left`/`right`, with hits reported as index pairs or the small internal
//! [`IdenticalSeeds`] error. Any two reference strings or seed types can be
//! compared; which side is a CRS or a URS is decided by the callers.
//!
//! # l-BFV boundary
//!
//! `validate_no_repeated_rows`, `validate_no_cross_overlap`, and
//! `validate_reference_string_pair` form the l-BFV-specific boundary; the
//! seeded key-generation caller maps `IdenticalSeeds` there as well. They
//! attach the protocol roles — the common reference string (CRS) `a` and the
//! uniform random string (URS) `d1` — and map core failures onto
//! [`MultipartyError::IdenticalReferenceStringSeeds`],
//! [`MultipartyError::RepeatedReferenceStringRow`], and
//! [`MultipartyError::OverlappingReferenceStringRows`] with
//! [`ReferenceStringRole`] information. l-BFV key generation requires the two
//! reference strings to be **generated independently**: these checks reject
//! observably reused randomness (identical seeds, repeated rows, shared rows)
//! before a key or share built from it can be returned or published, but they
//! **cannot certify** independence of deliberately correlated yet unequal
//! randomness. That guarantee remains a protocol responsibility: the
//! reference strings must come from an independently sampled, honestly
//! generated source.
//!
//! # Comparison semantics
//!
//! Row comparisons inspect the RNS coefficient values at a common context,
//! reduced by each row's modulus when the raw residues differ, so
//! lazily-reduced and canonical representations of the same value compare
//! equal. Representation bookkeeping that is not part of a polynomial's
//! mathematical value (such as the variable-time execution flag) is ignored,
//! while genuinely different values are never reported as equal.

use fhe_math::rq::{Poly, RepresentationTag};

use crate::{Error, MultipartyError, ParameterSource, ReferenceStringRole, Result};

/// Role-neutral failure reported when two seeds that must be distinct are
/// identical. The caller assigns the protocol meaning and maps it onto the
/// appropriate public error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IdenticalSeeds;

/// Reject two seeds that must be distinct but are identical.
///
/// Role-neutral and generic over any equatable seed type; callers assign the
/// protocol meaning (for l-BFV key generation these are the URS `d1` and CRS
/// `a` seeds) and map [`IdenticalSeeds`] onto the public error.
pub(crate) fn validate_distinct_seeds<S: Eq>(
    left: &S,
    right: &S,
) -> std::result::Result<(), IdenticalSeeds> {
    if left == right {
        return Err(IdenticalSeeds);
    }
    Ok(())
}

/// Return `true` when both polynomials represent the same mathematical value
/// at the same context.
///
/// Raw RNS coefficient views are compared first. When they differ, the rows
/// are compared by their residues reduced by each row's modulus, so a
/// lazily-reduced representation of a value compares equal to the canonical
/// representation of the same value, while genuinely different values never
/// compare equal. Representation bookkeeping that is not part of the
/// mathematical value (variable-time flag, Shoup table) is ignored.
fn same_concrete_values<R: RepresentationTag>(left: &Poly<R>, right: &Poly<R>) -> bool {
    if left.ctx() != right.ctx() {
        return false;
    }
    let left_coeffs = left.coefficients();
    let right_coeffs = right.coefficients();
    if left_coeffs.dim() != right_coeffs.dim() {
        return false;
    }
    if left_coeffs == right_coeffs {
        return true;
    }
    let moduli = left.ctx().moduli();
    left_coeffs
        .outer_iter()
        .zip(right_coeffs.outer_iter())
        .zip(moduli.iter())
        .all(|((left_row, right_row), &modulus)| {
            if left_row == right_row {
                return true;
            }
            // Two canonically reduced rows with differing raw residues hold
            // different values. Otherwise at least one row is lazily reduced,
            // and equality must be decided on the reduced residues.
            let both_canonical = left_row
                .iter()
                .chain(right_row.iter())
                .all(|&value| value < modulus);
            !both_canonical
                && left_row
                    .iter()
                    .zip(right_row.iter())
                    .all(|(&l, &r)| l % modulus == r % modulus)
        })
}

/// Find the same concrete row at two positions of one vector.
///
/// Role-neutral: the returned indices refer to the `left`-most and `right`-most
/// occurrence found by the all-pairs scan, so a duplicate is detected at any
/// two positions, not only at adjacent or same-index positions.
pub(crate) fn find_repeated_row<'a, R, I>(rows: I) -> Option<(usize, usize)>
where
    R: RepresentationTag,
    I: IntoIterator<Item = &'a Poly<R>>,
{
    let rows: Vec<&Poly<R>> = rows.into_iter().collect();
    for (left_index, left) in rows.iter().enumerate() {
        for (right_index, right) in rows.iter().enumerate().skip(left_index + 1) {
            if same_concrete_values(left, right) {
                return Some((left_index, right_index));
            }
        }
    }
    None
}

/// Find an equal concrete row between two vectors.
///
/// Role-neutral: every row of `left` is compared against every row of `right`
/// (all row-pairs), and the returned indices locate the first hit as
/// `(left_index, right_index)`, so a cross-index collision is reported just
/// like an aligned one.
pub(crate) fn find_cross_overlap<'a, R, I, J>(left: I, right: J) -> Option<(usize, usize)>
where
    R: RepresentationTag,
    I: IntoIterator<Item = &'a Poly<R>>,
    J: IntoIterator<Item = &'a Poly<R>>,
{
    let left_rows: Vec<&Poly<R>> = left.into_iter().collect();
    let right_rows: Vec<&Poly<R>> = right.into_iter().collect();
    for (left_index, left_row) in left_rows.iter().enumerate() {
        for (right_index, right_row) in right_rows.iter().enumerate() {
            if same_concrete_values(left_row, right_row) {
                return Some((left_index, right_index));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// l-BFV boundary: role assignment and public-error mapping
// ---------------------------------------------------------------------------

/// Reject a reference-string vector that contains the same concrete row twice.
///
/// l-BFV boundary over [`find_repeated_row`]: the caller assigns the
/// [`ReferenceStringRole`] of the vector (CRS, URS, or an unbound
/// common-random-polynomial vector), and the found index pair is mapped onto
/// [`MultipartyError::RepeatedReferenceStringRow`] without changing its
/// fields.
pub(crate) fn validate_no_repeated_rows<'a, R, I>(role: ReferenceStringRole, rows: I) -> Result<()>
where
    R: RepresentationTag,
    I: IntoIterator<Item = &'a Poly<R>>,
{
    find_repeated_row(rows).map_or(Ok(()), |(first_index, second_index)| {
        Err(MultipartyError::RepeatedReferenceStringRow {
            role,
            first_index,
            second_index,
        }
        .into())
    })
}

/// Reject any equal concrete row between the CRS `a` and URS `d1` vectors.
///
/// l-BFV boundary over [`find_cross_overlap`]: the left vector is the CRS and
/// the right vector is the URS, and the found index pair is mapped onto
/// [`MultipartyError::OverlappingReferenceStringRows`] without changing its
/// fields.
pub(crate) fn validate_no_cross_overlap<'a, R, I, J>(crs_rows: I, urs_rows: J) -> Result<()>
where
    R: RepresentationTag,
    I: IntoIterator<Item = &'a Poly<R>>,
    J: IntoIterator<Item = &'a Poly<R>>,
{
    find_cross_overlap(crs_rows, urs_rows).map_or(Ok(()), |(crs_index, urs_index)| {
        Err(MultipartyError::OverlappingReferenceStringRows {
            crs_index,
            urs_index,
        }
        .into())
    })
}

/// Validate the URS/CRS row pair of an l-BFV key generation before any
/// secret-dependent operation runs.
///
/// Every row must sit at `expected_context`; a row elsewhere is reported as a
/// parameter mismatch exactly as the key-switching-key constructors would.
/// After the context gate, repeated rows within each vector and rows shared
/// between the CRS and the URS are rejected. The checks operate on the
/// supplied concrete values only: they cannot certify independence of
/// deliberately correlated but unequal randomness (see the module docs).
pub(crate) fn validate_reference_string_pair<R: RepresentationTag>(
    expected_context: &std::sync::Arc<fhe_math::rq::Context>,
    crs_rows: &[Poly<R>],
    urs_rows: &[Poly<R>],
) -> Result<()> {
    for (rows, role) in [
        (crs_rows, ReferenceStringRole::Crs),
        (urs_rows, ReferenceStringRole::Urs),
    ] {
        for row in rows {
            if row.ctx() != expected_context {
                return Err(Error::ParameterMismatch {
                    left: ParameterSource::Polynomial,
                    right: ParameterSource::KeySwitchingKey,
                });
            }
        }
        validate_no_repeated_rows(role, rows)?;
    }
    validate_no_cross_overlap(crs_rows, urs_rows)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::bfv::BfvParameters;
    use fhe_math::rq::Ntt;
    use rand::{Rng, rng};

    #[test]
    fn distinct_seed_check_is_generic_over_seed_type() {
        // The 32-byte ChaCha8 seed type used by l-BFV key generation.
        let a: [u8; 32] = [7u8; 32];
        let b: [u8; 32] = [8u8; 32];
        assert_eq!(validate_distinct_seeds(&a, &b), Ok(()));
        assert_eq!(validate_distinct_seeds(&a, &a), Err(IdenticalSeeds));

        // A different equatable seed type: the primitive is role- and
        // type-neutral.
        let small: u64 = 1;
        assert_eq!(validate_distinct_seeds(&small, &2u64), Ok(()));
        assert_eq!(validate_distinct_seeds(&small, &small), Err(IdenticalSeeds));
    }

    /// The core primitive reports the duplicate's index pair directly and
    /// finds it at any two positions.
    #[test]
    fn find_repeated_row_reports_index_pair() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let ctx = params.context_at_level(0).unwrap();
        let rows: Vec<Poly<Ntt>> = (0..4).map(|_| Poly::<Ntt>::random(ctx, &mut rng)).collect();
        assert_eq!(find_repeated_row(&rows), None);

        // Duplicate the first row into the last position.
        let mut repeated = rows.clone();
        repeated[3] = rows[0].clone();
        assert_eq!(find_repeated_row(&repeated), Some((0, 3)));
    }

    /// The core primitive reports the colliding row as
    /// `(left_index, right_index)` across the two vectors.
    #[test]
    fn find_cross_overlap_reports_left_and_right_indices() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let ctx = params.context_at_level(0).unwrap();
        let left: Vec<Poly<Ntt>> = (0..3).map(|_| Poly::<Ntt>::random(ctx, &mut rng)).collect();
        let right: Vec<Poly<Ntt>> = (0..3).map(|_| Poly::<Ntt>::random(ctx, &mut rng)).collect();
        assert_eq!(find_cross_overlap(&left, &right), None);

        let mut colliding = right;
        colliding[2] = left[1].clone();
        assert_eq!(find_cross_overlap(&left, &colliding), Some((1, 2)));
    }

    /// The l-BFV boundary preserves the role and the found indices in the
    /// public repeated-row error.
    #[test]
    fn repeated_row_detection_is_all_pairs() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let ctx = params.context_at_level(0).unwrap();
        let rows: Vec<Poly<Ntt>> = (0..4).map(|_| Poly::<Ntt>::random(ctx, &mut rng)).collect();
        assert!(validate_no_repeated_rows(ReferenceStringRole::Crs, &rows).is_ok());

        let mut repeated = rows.clone();
        repeated[3] = rows[0].clone();
        assert!(matches!(
            validate_no_repeated_rows(ReferenceStringRole::Crs, &repeated),
            Err(Error::Multiparty(
                MultipartyError::RepeatedReferenceStringRow {
                    role: ReferenceStringRole::Crs,
                    first_index: 0,
                    second_index: 3,
                }
            ))
        ));
    }

    /// The l-BFV boundary preserves the found indices as CRS/URS indices in
    /// the public cross-overlap error.
    #[test]
    fn cross_overlap_detection_reports_both_indices() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let ctx = params.context_at_level(0).unwrap();
        let crs: Vec<Poly<Ntt>> = (0..3).map(|_| Poly::<Ntt>::random(ctx, &mut rng)).collect();
        let mut urs: Vec<Poly<Ntt>> = (0..3).map(|_| Poly::<Ntt>::random(ctx, &mut rng)).collect();
        assert!(validate_no_cross_overlap(&crs, &urs).is_ok());

        urs[2] = crs[1].clone();
        assert!(matches!(
            validate_no_cross_overlap(&crs, &urs),
            Err(Error::Multiparty(
                MultipartyError::OverlappingReferenceStringRows {
                    crs_index: 1,
                    urs_index: 2,
                }
            ))
        ));
    }

    /// `Poly::PartialEq` is sensitive to representation metadata and raw
    /// residues: a lazily-reduced polynomial and the canonical polynomial of
    /// the same mathematical value compare unequal. Row identity checks must
    /// still recognise them as the same row, while genuinely different values
    /// are never reported as equal.
    #[test]
    fn lazy_residues_compare_by_mathematical_value() {
        use fhe_math::rq::{PowerBasis, traits::TryConvertFrom as TryConvertFromPoly};

        let params = BfvParameters::default_arc(6, 8);
        let ctx = params.context_at_level(0).unwrap();
        let mut rng = rng();

        let coefficients: Vec<i64> = (0..ctx.degree())
            .map(|_| rng.random_range(0..(1 << 40)))
            .collect();

        let canonical =
            Poly::<PowerBasis>::try_convert_from(coefficients.as_slice(), ctx, false).unwrap();
        let canonical = canonical.into_ntt();

        let variable_time = fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
        let power_basis_coefficients: Vec<u64> = coefficients
            .iter()
            .map(|&coefficient| coefficient as u64)
            .collect();
        let lazy =
            Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                &power_basis_coefficients,
                ctx,
                variable_time,
            );

        // The two representations must differ in raw view; otherwise the test
        // would not exercise the residue-reduction path.
        assert_ne!(canonical.coefficients(), lazy.coefficients());
        assert_ne!(canonical, lazy);
        assert!(same_concrete_values(&canonical, &lazy));

        // A genuinely different value must never compare equal.
        let other: Vec<i64> = coefficients.iter().map(|c| c + 1).collect();
        let other = Poly::<PowerBasis>::try_convert_from(other.as_slice(), ctx, false)
            .unwrap()
            .into_ntt();
        assert!(!same_concrete_values(&canonical, &other));
    }
}
