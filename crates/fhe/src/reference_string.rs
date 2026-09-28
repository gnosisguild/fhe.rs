//! Validation of independently generated l-BFV reference strings.
//!
//! l-BFV public-key and relinearization-key generation consume two shared
//! reference strings: the common reference string (CRS) `a` and the uniform
//! random string (URS) `d1`. The protocol requires the two strings to be
//! **generated independently**. The helpers in this module reject the inputs
//! that are observably unsafe — identical seeds, repeated rows within one
//! vector, and rows shared between the two vectors — before a key or share
//! built from them can be returned or published.
//!
//! # Threat-model limit
//!
//! Equality checks operate on the concrete values the caller supplies. They
//! prevent the reuse of identical randomness, but they **cannot certify**
//! that deliberately correlated yet unequal randomness (for example rows
//! derived from a common hidden value) is independent. That guarantee remains
//! a protocol responsibility: the reference strings must come from an
//! independently sampled, honestly generated source.
//!
//! Comparisons inspect the RNS coefficient values of polynomials at a common
//! context, reduced by each row's modulus when the raw residues differ, so
//! lazily-reduced and canonical representations of the same value compare
//! equal. Representation bookkeeping that is not part of a polynomial's
//! mathematical value (such as the variable-time execution flag) is ignored,
//! while genuinely different values are never reported as equal.

use fhe_math::rq::{Poly, RepresentationTag};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::{Error, MultipartyError, ParameterSource, ReferenceStringRole, Result};

/// The 32-byte ChaCha8 seed type used for deterministic reference strings.
pub(crate) type ReferenceStringSeed = <ChaCha8Rng as SeedableRng>::Seed;

/// Reject a URS seed that is identical to the CRS seed.
///
/// Seeded key generation derives the URS `d1` and the CRS `a` from two seeds.
/// Supplying the same seed for both makes the two reference strings identical,
/// so the resulting key material must not be produced.
pub(crate) fn validate_distinct_seeds(
    urs_seed: &ReferenceStringSeed,
    crs_seed: &ReferenceStringSeed,
) -> Result<()> {
    if urs_seed == crs_seed {
        return Err(MultipartyError::IdenticalReferenceStringSeeds.into());
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

/// Reject a reference-string vector that contains the same concrete row twice.
///
/// Comparisons are all-pairs: a duplicate may appear at any two positions,
/// not only at adjacent or same-index positions.
pub(crate) fn validate_no_repeated_rows<'a, R, I>(role: ReferenceStringRole, rows: I) -> Result<()>
where
    R: RepresentationTag,
    I: IntoIterator<Item = &'a Poly<R>>,
{
    let rows: Vec<&Poly<R>> = rows.into_iter().collect();
    for (first_index, first) in rows.iter().enumerate() {
        for (second_index, second) in rows.iter().enumerate().skip(first_index + 1) {
            if same_concrete_values(first, second) {
                return Err(MultipartyError::RepeatedReferenceStringRow {
                    role,
                    first_index,
                    second_index,
                }
                .into());
            }
        }
    }
    Ok(())
}

/// Reject any equal concrete row between the CRS `a` and URS `d1` vectors.
///
/// Every CRS row is compared against every URS row (all row-pairs), so a
/// cross-index collision is rejected just like an aligned one.
pub(crate) fn validate_no_cross_overlap<'a, R, I, J>(crs_rows: I, urs_rows: J) -> Result<()>
where
    R: RepresentationTag,
    I: IntoIterator<Item = &'a Poly<R>>,
    J: IntoIterator<Item = &'a Poly<R>>,
{
    let crs_rows: Vec<&Poly<R>> = crs_rows.into_iter().collect();
    let urs_rows: Vec<&Poly<R>> = urs_rows.into_iter().collect();
    for (crs_index, crs_row) in crs_rows.iter().enumerate() {
        for (urs_index, urs_row) in urs_rows.iter().enumerate() {
            if same_concrete_values(crs_row, urs_row) {
                return Err(MultipartyError::OverlappingReferenceStringRows {
                    crs_index,
                    urs_index,
                }
                .into());
            }
        }
    }
    Ok(())
}

/// Validate a caller-supplied URS/CRS row pair before any secret-dependent
/// key generation happens.
///
/// Every row must sit at `expected_context`; a row elsewhere is reported as a
/// parameter mismatch exactly as the key-switching-key constructors would.
/// After the context gate, repeated rows within each vector and rows shared
/// between the two vectors are rejected.
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
    fn distinct_seed_check_rejects_only_identical_seeds() {
        let a: ReferenceStringSeed = [7u8; 32];
        let b: ReferenceStringSeed = [8u8; 32];
        assert!(validate_distinct_seeds(&a, &b).is_ok());
        assert!(validate_distinct_seeds(&a, &a).is_err());
    }

    #[test]
    fn repeated_row_detection_is_all_pairs() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let ctx = params.context_at_level(0).unwrap();
        let rows: Vec<Poly<Ntt>> = (0..4).map(|_| Poly::<Ntt>::random(ctx, &mut rng)).collect();
        assert!(validate_no_repeated_rows(ReferenceStringRole::Crs, &rows).is_ok());

        // Duplicate the first row into the last position.
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
