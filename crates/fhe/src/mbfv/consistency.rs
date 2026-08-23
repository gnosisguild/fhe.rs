//! Internal consistency helpers shared by the MBFV aggregation entry points.
//!
//! These helpers implement the structural (concrete-value) comparisons and
//! exact participant-coverage validation required before any polynomial
//! arithmetic in an aggregation. They provide consistency only: they do not
//! authenticate a contributor or prove that a share was formed correctly.

use std::sync::Arc;

use fhe_math::rq::{Ntt, Poly};

use crate::{
    Error, MbfvError, Result,
    bfv::{BfvParameters, Ciphertext},
    identity::{ContributionBinding, ParticipantSet},
};

/// Validate that every contribution binding refers to the same participant
/// set with exact, one-per-member coverage, and return that set.
pub(crate) fn validate_binding_coverage<'a, I>(bindings: I) -> Result<ParticipantSet>
where
    I: IntoIterator<Item = &'a ContributionBinding>,
{
    let mut bindings = bindings.into_iter();
    let first = bindings
        .next()
        .ok_or(Error::Mbfv(MbfvError::MissingBinding))?;
    let participant_set = first.participant_set().clone();
    participant_set.validate_contributions(std::iter::once(first).chain(bindings))?;
    Ok(participant_set)
}

/// Require every share in an aggregation to carry exactly one contribution
/// binding and validate exact, one-per-member coverage across all of them,
/// returning the common validated [`ParticipantSet`].
///
/// A share without a binding is rejected with [`MbfvError::MissingBinding`];
/// it must never be silently excluded from coverage while its polynomial is
/// still summed. Aggregators must call this immediately after collecting the
/// non-empty share list, before any parameter, context, CRP,
/// ciphertext-component, or share-polynomial access.
pub(crate) fn validate_all_bindings<'a, I>(bindings: I) -> Result<ParticipantSet>
where
    I: IntoIterator<Item = &'a Option<ContributionBinding>>,
{
    let mut bound = Vec::new();
    for binding in bindings {
        bound.push(
            binding
                .as_ref()
                .ok_or(Error::Mbfv(MbfvError::MissingBinding))?,
        );
    }
    validate_binding_coverage(bound)
}

/// Require two BFV parameter sets to be structurally equal.
pub(crate) fn require_same_parameters(
    found: &Arc<BfvParameters>,
    expected: &Arc<BfvParameters>,
) -> Result<()> {
    if found == expected {
        Ok(())
    } else {
        Err(Error::Mbfv(MbfvError::ParameterMismatch))
    }
}

/// Require two ciphertexts to agree as structural public inputs: parameters,
/// level, component count, component contexts, and every concrete component
/// polynomial must be equal. Seed/cache metadata is deliberately excluded so
/// mathematically identical inputs never appear different.
pub(crate) fn require_same_ciphertext_input(
    found: &Ciphertext,
    expected: &Ciphertext,
) -> Result<()> {
    if expected.params != found.params {
        return Err(Error::Mbfv(MbfvError::ParameterMismatch));
    }
    if found.level != expected.level {
        return Err(Error::Mbfv(MbfvError::LevelMismatch {
            found: found.level,
            expected: expected.level,
        }));
    }
    if found.len() != expected.len() {
        return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
            reason: format!(
                "ciphertext component count differs: {} instead of {}",
                found.len(),
                expected.len()
            ),
        }));
    }
    for (i, (found_i, expected_i)) in found.iter().zip(expected.iter()).enumerate() {
        if found_i.ctx() != expected_i.ctx() {
            return Err(Error::Mbfv(MbfvError::InvalidContext));
        }
        if found_i != expected_i {
            return Err(Error::Mbfv(MbfvError::PublicInputMismatch {
                reason: format!("ciphertext component {i} differs"),
            }));
        }
    }
    Ok(())
}

/// Require a polynomial to live in the given context.
pub(crate) fn require_poly_context(
    poly: &Poly<Ntt>,
    ctx: &Arc<fhe_math::rq::Context>,
) -> Result<()> {
    if poly.ctx() == ctx {
        Ok(())
    } else {
        Err(Error::Mbfv(MbfvError::InvalidContext))
    }
}

/// Require two polynomial vectors to agree structurally: exact equal lengths,
/// per-index context equality, and concrete value equality of every component.
pub(crate) fn require_same_poly_vector(
    found: &[Poly<Ntt>],
    expected: &[Poly<Ntt>],
    what: &str,
) -> Result<()> {
    if found.len() != expected.len() {
        return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
            reason: format!(
                "{what} vector length differs: found {} instead of {}",
                found.len(),
                expected.len()
            ),
        }));
    }
    for (i, (found_i, expected_i)) in found.iter().zip(expected.iter()).enumerate() {
        require_poly_context(found_i, expected_i.ctx())?;
        if found_i != expected_i {
            return Err(Error::Mbfv(MbfvError::PublicInputMismatch {
                reason: format!("{what} component {i} differs"),
            }));
        }
    }
    Ok(())
}

/// Require a polynomial vector to have exactly `expected_len` components,
/// all living in the given context. This anchors aggregation vectors to an
/// explicit context (e.g. the parameters' level-zero context) rather than
/// the first vector's own context, and rejects empty vectors because
/// `expected_len` is derived from the level-zero modulus count (at least
/// one).
pub(crate) fn require_anchored_poly_vector(
    vector: &[Poly<Ntt>],
    ctx: &Arc<fhe_math::rq::Context>,
    expected_len: usize,
    what: &str,
) -> Result<()> {
    if vector.len() != expected_len {
        return Err(Error::Mbfv(MbfvError::ShareShapeMismatch {
            reason: format!(
                "{what} vector has {} components instead of the expected {expected_len}",
                vector.len()
            ),
        }));
    }
    for component in vector {
        require_poly_context(component, ctx)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bfv::Ciphertext;

    #[test]
    fn binding_coverage_accepts_exact_and_rejects_duplicates() -> Result<()> {
        use crate::identity::{ContributionBinding, SessionId};
        let set = ParticipantSet::new(SessionId::new([3; 32]), vec![1, 2])?;
        let one = ContributionBinding::new(set.clone(), 1)?;
        let two = ContributionBinding::new(set.clone(), 2)?;

        let validated = validate_binding_coverage([&two, &one])?;
        assert_eq!(validated, set);

        assert!(validate_binding_coverage([&one, &one]).is_err());
        assert!(validate_binding_coverage([&one]).is_err());
        assert!(
            validate_binding_coverage(Vec::<&ContributionBinding>::new()).is_err(),
            "empty coverage must fail rather than panic"
        );
        Ok(())
    }

    #[test]
    fn same_ciphertext_input_ignores_seed_metadata() -> Result<()> {
        use crate::bfv::{Encoding, Plaintext, SecretKey};
        use fhe_traits::{FheEncoder, FheEncrypter};
        use rand::rng;

        let mut rng = rng();
        let params = crate::bfv::BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pt = Plaintext::try_encode(&[0u64, 1, 2, 3, 4, 5, 6, 7], Encoding::poly(), &params)?;
        let ct_a: Ciphertext = sk.try_encrypt(&pt, &mut rng)?;
        let ct_b = ct_a.clone();

        // Identical concrete inputs compare equal regardless of seed metadata.
        let mut seeded = ct_b.clone();
        seeded.seed = Some(<rand_chacha::ChaCha8Rng as rand::SeedableRng>::Seed::default());
        require_same_ciphertext_input(&ct_a, &seeded)?;

        // A different concrete input is rejected.
        let ct_c = sk.try_encrypt(&pt, &mut rng)?;
        assert!(matches!(
            require_same_ciphertext_input(&ct_a, &ct_c),
            Err(Error::Mbfv(MbfvError::PublicInputMismatch { .. }))
        ));
        Ok(())
    }
}
