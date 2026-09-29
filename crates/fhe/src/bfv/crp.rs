use std::sync::Arc;

use crate::Result;
use crate::bfv::BfvParameters;
use fhe_math::rq::{Ntt, Poly};
use fhe_traits::{DeserializeWithContext, Serialize};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

// ---------------------------------------------------------------------------
// CommonRandomPoly — a single BFV random polynomial (CRP)
// ---------------------------------------------------------------------------

/// A polynomial sampled from a random common reference string.
///
/// Each [`CommonRandomPoly`] is a single uniformly random polynomial in R_q
/// (NTT representation). It is used by multiparty protocols (MBFV, l-BFV) as
/// a shared nonce to derandomise the public-key and relinearization-key
/// generation: all parties use the *same* polynomial to ensure that additive
/// contributions can later be summed.
///
/// # Protocol coordination
///
/// All participants in one protocol execution must use the identical concrete
/// CRP (and, for [`CommonRandomPolyVec`], the identical ordered polynomial
/// vector). This type carries no session identifier and does not bind a CRP to
/// a protocol transcript; callers must coordinate and validate that association
/// themselves. The protocol must define its CRP reuse policy. This library does
/// not establish that reuse across executions is safe; absent a protocol-specific
/// justification, generate independent CRPs for separate executions.
///
/// [`CommonRandomPoly::new`] samples using the caller-provided `CryptoRng`.
/// [`CommonRandomPoly::new_deterministic`] trusts the supplied seed and adds no
/// session or protocol domain separation, so callers are responsible for seed
/// generation, distribution, and separation.
///
/// # Serialization
///
/// When the `protobuf` feature is enabled, a [`CommonRandomPoly`] can be
/// serialised to / deserialised from raw bytes via [`Serialize`] /
/// [`DeserializeWithContext`](fhe_traits::DeserializeWithContext).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CommonRandomPoly {
    pub(crate) poly: Poly<Ntt>,
}

impl CommonRandomPoly {
    /// Generate a new random CRP at the parameter's level-0 context.
    pub fn new<R: RngCore + CryptoRng>(params: &Arc<BfvParameters>, rng: &mut R) -> Result<Self> {
        Self::new_leveled(params, 0, rng)
    }

    /// Reconstruct a CRP deterministically from a shared seed.
    pub fn new_deterministic(
        params: &Arc<BfvParameters>,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
    ) -> Result<Self> {
        Self::new_leveled_deterministic(params, 0, seed)
    }

    /// Generate a new random CRP at a specific level.
    pub fn new_leveled<R: RngCore + CryptoRng>(
        params: &Arc<BfvParameters>,
        level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let ctx = params.context_at_level(level)?;
        let poly = Poly::<Ntt>::random(ctx, rng);
        Ok(Self { poly })
    }

    /// Reconstruct a CRP deterministically from a saved seed at a specific level.
    pub fn new_leveled_deterministic(
        params: &Arc<BfvParameters>,
        level: usize,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
    ) -> Result<Self> {
        let ctx = params.context_at_level(level)?;
        let poly = Poly::<Ntt>::random_from_seed(ctx, seed);
        Ok(Self { poly })
    }

    /// Borrow the underlying NTT polynomial.
    #[must_use]
    pub fn poly(&self) -> &Poly<Ntt> {
        &self.poly
    }

    /// Consume `self` and return the underlying polynomial.
    #[must_use]
    pub fn into_poly(self) -> Poly<Ntt> {
        self.poly
    }
}

// ---------------------------------------------------------------------------
// CommonRandomPolyVec — a vector of l CRPs with optional seed metadata
// ---------------------------------------------------------------------------

/// A vector of [`CommonRandomPoly`] values together with optional seed metadata.
///
/// The vector length is `l = |{q_i}|`, the number of RNS moduli at level 0 of
/// the associated [`BfvParameters`]. This is the common random material used by:
///
/// - **MBFV** relinearization key generation (Protocol 2, <https://eprint.iacr.org/2020/304>),
///   where the CRP vector is passed to [`RelinKeyGenerator`](crate::aggregate::RelinKeyGenerator).
/// - **l-BFV** public-key and relinearization-key generation, where two
///   independent vectors (the CRS `a` and the URS `d1`) serve as the shared
///   polynomials `a_j` and `d1_j` in the linear-key protocol
///   (<https://eprint.iacr.org/2024/1285>).
///
/// # Concrete vs. seed-derived
///
/// Every [`CommonRandomPolyVec`] **always** stores concrete polynomials. The
/// optional `seed` is pure metadata: it records the seed from which the
/// polynomials *would* be deterministically reconstructed. It is preserved for
/// compact broadcast/reconstruction, but the authoritative values are the
/// concrete polynomials; equality comparisons and aggregation checks always use
/// the polynomials, never the seed.
///
/// All parties in one protocol execution must use the same ordered vector. The
/// vector itself does not identify a session or prevent cross-session reuse;
/// those requirements and the protocol-specific reuse policy belong to the
/// surrounding protocol.
///
/// # Independence requirement
///
/// When two [`CommonRandomPolyVec`] values are used together as the l-BFV
/// reference strings — the CRS `a` and the URS `d1` of
/// [`LBFVRelinearizationKey`](crate::lbfv::LBFVRelinearizationKey) and
/// [`RelinKeyShare`](crate::trlbfv::RelinKeyShare) generation — the two
/// vectors must be generated independently (distinct seeds or separately
/// sampled polynomials). Constructors that build keys from both vectors
/// reject identical seeds, rows repeated within one vector, and rows shared
/// between the two vectors. These equality checks only catch observably
/// reused randomness; they cannot certify that deliberately correlated but
/// unequal randomness is independent, which remains a protocol
/// responsibility.
///
/// # Construction
///
/// - [`CommonRandomPolyVec::new`] samples `l` independent random polynomials.
/// - [`CommonRandomPolyVec::from_seed`] deterministically reconstructs `l`
///   polynomials from a single 32-byte seed.
/// - [`CommonRandomPolyVec::from_polys`] accepts explicit `Poly<Ntt>` values
///   together with optional seed metadata, validating context, length,
///   row uniqueness, and seed consistency.
#[derive(Debug, Clone)]
pub struct CommonRandomPolyVec {
    polys: Box<[CommonRandomPoly]>,
    seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
}

// Equality compares only concrete polynomials; seed metadata is excluded.
impl PartialEq for CommonRandomPolyVec {
    fn eq(&self, other: &Self) -> bool {
        self.polys == other.polys
    }
}

impl Eq for CommonRandomPolyVec {}

impl CommonRandomPolyVec {
    /// Sample a fresh random vector of `l` independent CRPs.
    ///
    /// `l` is the number of RNS moduli at level 0. No seed metadata is stored.
    ///
    /// The no-repeat invariant is enforced here: a degenerate or malicious RNG
    /// that samples the same row twice causes an error rather than an unbounded
    /// retry loop.
    pub fn new<R: RngCore + CryptoRng>(params: &Arc<BfvParameters>, rng: &mut R) -> Result<Self> {
        let l = params.moduli().len();
        let mut polys = Vec::with_capacity(l);
        for _ in 0..l {
            polys.push(CommonRandomPoly::new(params, rng)?);
        }
        crate::reference_string::validate_no_repeated_rows(
            crate::ReferenceStringRole::CommonRandomPolyVector,
            polys.iter().map(|crp| &crp.poly),
        )?;
        Ok(Self {
            polys: polys.into_boxed_slice(),
            seed: None,
        })
    }

    /// Deterministically reconstruct `l` CRPs from a shared 32-byte seed.
    ///
    /// Derives `l` sub-seeds from `seed` (one per RNS modulus) using ChaCha8,
    /// then calls [`CommonRandomPoly::new_deterministic`] for each. Every
    /// caller using the same `seed` and `params` obtains identical polynomials.
    /// The seed is stored as metadata.
    ///
    /// The seed expansion is unchanged; the derived rows are still checked
    /// against the no-repeat invariant before the vector is returned.
    pub fn from_seed(
        params: &Arc<BfvParameters>,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
    ) -> Result<Self> {
        let l = params.moduli().len();
        let mut seed_rng = ChaCha8Rng::from_seed(seed);
        let mut polys = Vec::with_capacity(l);
        for _ in 0..l {
            let mut seed_i = <ChaCha8Rng as SeedableRng>::Seed::default();
            seed_rng.fill(&mut seed_i);
            polys.push(CommonRandomPoly::new_deterministic(params, seed_i)?);
        }
        crate::reference_string::validate_no_repeated_rows(
            crate::ReferenceStringRole::CommonRandomPolyVector,
            polys.iter().map(|crp| &crp.poly),
        )?;
        Ok(Self {
            polys: polys.into_boxed_slice(),
            seed: Some(seed),
        })
    }

    /// Build a vector from explicit `Polys<Ntt>` with optional seed metadata.
    ///
    /// # Validation
    ///
    /// - `polys.len()` must equal `params.moduli().len()` (the level-0 modulus
    ///   count).
    /// - Every polynomial must be at the level-0 context of `params`.
    /// - The vector must not contain the same concrete polynomial row twice;
    ///   reference-string vectors feed protocols that require independent
    ///   rows.
    /// - If `seed` is `Some`, the concrete polynomials are verified to match the
    ///   deterministic output of that seed. A contradictory seed is rejected.
    pub fn from_polys(
        params: &Arc<BfvParameters>,
        polys: Vec<Poly<Ntt>>,
        seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
    ) -> Result<Self> {
        let expected_l = params.moduli().len();
        if polys.len() != expected_l {
            return Err(crate::MultipartyError::InvalidCommonRandomPolynomialCount {
                actual: polys.len(),
                expected: expected_l,
            }
            .into());
        }

        let ctx0 = params.context_at_level(0)?;
        for p in &polys {
            if p.ctx() != ctx0 {
                return Err(crate::Error::ParameterMismatch {
                    left: crate::ParameterSource::Polynomial,
                    right: crate::ParameterSource::Parameters,
                });
            }
        }

        // The vector may serve as a CRS or URS reference string; repeated
        // concrete rows are rejected before any key material depends on it.
        crate::reference_string::validate_no_repeated_rows(
            crate::ReferenceStringRole::CommonRandomPolyVector,
            &polys,
        )?;

        // If a seed is given, verify it reproduces the supplied polynomials.
        if let Some(ref seed) = seed {
            let mut seed_rng = ChaCha8Rng::from_seed(*seed);
            for (i, poly) in polys.iter().enumerate() {
                let mut seed_i = <ChaCha8Rng as SeedableRng>::Seed::default();
                seed_rng.fill(&mut seed_i);
                let expected = Poly::<Ntt>::random_from_seed(ctx0, seed_i);
                if expected != *poly {
                    return Err(crate::MultipartyError::CommonRandomPolynomialSeedMismatch {
                        index: i,
                    }
                    .into());
                }
            }
        }

        let crps: Vec<CommonRandomPoly> = polys
            .into_iter()
            .map(|poly| CommonRandomPoly { poly })
            .collect();

        Ok(Self {
            polys: crps.into_boxed_slice(),
            seed,
        })
    }

    // ---- accessors ----

    /// View the vector as a slice of [`CommonRandomPoly`].
    #[must_use]
    pub fn as_slice(&self) -> &[CommonRandomPoly] {
        &self.polys
    }

    /// Clone the concrete polynomials out of the vector.
    #[must_use]
    pub fn to_polys(&self) -> Vec<Poly<Ntt>> {
        self.polys.iter().map(|crp| crp.poly.clone()).collect()
    }

    /// Number of polynomials in the vector (= `l`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.polys.len()
    }

    /// Returns `true` if the vector is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.polys.is_empty()
    }

    /// The seed metadata, if any.
    ///
    /// When `Some`, this is the 32-byte ChaCha8 seed that would
    /// deterministically reconstruct the same concrete polynomials.
    #[must_use]
    pub fn seed(&self) -> Option<<ChaCha8Rng as SeedableRng>::Seed> {
        self.seed
    }
}

// ---------------------------------------------------------------------------
// Protobuf serialization (feature-gated)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

impl CommonRandomPoly {
    /// Deserialize a CRP from bytes.
    pub fn deserialize(bytes: &[u8], par: &Arc<BfvParameters>) -> Result<Self> {
        let ctx = par.context_at_level(0)?;
        let poly = Poly::<Ntt>::from_bytes(bytes, ctx)?;
        Ok(Self { poly })
    }
}

impl Serialize for CommonRandomPoly {
    fn to_bytes(&self) -> Vec<u8> {
        self.poly.to_bytes()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod proto_tests {
    use super::*;
    use crate::bfv::BfvParameters;
    use rand::rng;

    #[test]
    fn common_random_poly_vec_from_seed_is_deterministic() {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(6, 8),
            BfvParameters::default_arc(1, 8),
        ] {
            let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut seed);

            let v1 = CommonRandomPolyVec::from_seed(&params, seed).unwrap();
            let v2 = CommonRandomPolyVec::from_seed(&params, seed).unwrap();

            assert_eq!(v1.len(), params.moduli().len());
            assert_eq!(v2.len(), v1.len());
            assert_eq!(v1.seed, Some(seed));
            assert_eq!(v2.seed, Some(seed));

            // Concrete polynomials must match.
            assert_eq!(v1.to_polys(), v2.to_polys());
        }
    }

    #[test]
    fn common_random_poly_vec_seedless_new_is_random() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);

        let v1 = CommonRandomPolyVec::new(&params, &mut rng).unwrap();
        let v2 = CommonRandomPolyVec::new(&params, &mut rng).unwrap();

        assert_eq!(v1.len(), params.moduli().len());
        assert_eq!(v2.len(), v1.len());
        assert!(v1.seed().is_none());
        assert!(v2.seed().is_none());

        // With overwhelming probability the two random vectors differ.
        assert_ne!(v1.to_polys(), v2.to_polys());
    }

    #[test]
    fn from_polys_validates_length() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);

        let too_few: Vec<Poly<Ntt>> = vec![];
        assert!(matches!(
            CommonRandomPolyVec::from_polys(&params, too_few, None),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::InvalidCommonRandomPolynomialCount { .. }
            ))
        ));

        let ctx0 = params.context_at_level(0).unwrap();
        let too_many: Vec<Poly<Ntt>> = (0..params.moduli().len() + 1)
            .map(|_| Poly::<Ntt>::random(ctx0, &mut rng))
            .collect();
        assert!(matches!(
            CommonRandomPolyVec::from_polys(&params, too_many, None),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::InvalidCommonRandomPolynomialCount { .. }
            ))
        ));
    }

    #[test]
    fn from_polys_rejects_inconsistent_seed() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);

        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);

        // Build a valid vector from the seed.
        let valid = CommonRandomPolyVec::from_seed(&params, seed).unwrap();
        let polys = valid.to_polys();

        // A different seed must be rejected.
        let mut other_seed = seed;
        other_seed[0] ^= 0xff;
        assert!(matches!(
            CommonRandomPolyVec::from_polys(&params, polys, Some(other_seed)),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::CommonRandomPolynomialSeedMismatch { index: 0 }
            ))
        ));

        // The correct seed must be accepted.
        let valid_from_polys =
            CommonRandomPolyVec::from_polys(&params, valid.to_polys(), Some(seed)).unwrap();
        assert_eq!(valid.polys, valid_from_polys.polys);
    }

    #[test]
    fn from_polys_seedless_roundtrip() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let ctx0 = params.context_at_level(0).unwrap();

        let polys: Vec<Poly<Ntt>> = (0..params.moduli().len())
            .map(|_| Poly::<Ntt>::random(ctx0, &mut rng))
            .collect();

        let vec = CommonRandomPolyVec::from_polys(&params, polys.clone(), None).unwrap();
        assert!(vec.seed().is_none());
        assert_eq!(vec.to_polys(), polys);
        assert_eq!(vec.len(), params.moduli().len());
        assert!(!vec.is_empty());
    }

    /// A reference-string vector must not contain the same concrete row twice.
    #[test]
    fn from_polys_rejects_repeated_rows() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let ctx0 = params.context_at_level(0).unwrap();

        // Control: distinct rows are accepted.
        let distinct: Vec<Poly<Ntt>> = (0..params.moduli().len())
            .map(|_| Poly::<Ntt>::random(ctx0, &mut rng))
            .collect();
        assert!(CommonRandomPolyVec::from_polys(&params, distinct, None).is_ok());

        // Duplicate a row at a non-adjacent position.
        let mut repeated: Vec<Poly<Ntt>> = (0..params.moduli().len())
            .map(|_| Poly::<Ntt>::random(ctx0, &mut rng))
            .collect();
        repeated[params.moduli().len() - 1] = repeated[0].clone();
        assert!(matches!(
            CommonRandomPolyVec::from_polys(&params, repeated, None),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::RepeatedReferenceStringRow {
                    role: crate::ReferenceStringRole::CommonRandomPolyVector,
                    first_index: 0,
                    second_index: _
                }
            ))
        ));
    }

    /// A lazily-reduced duplicate of a canonical row is the same mathematical
    /// row and must be rejected, even though `Poly::PartialEq` (raw residues
    /// plus metadata) would not see the two representations as equal.
    #[test]
    fn from_polys_rejects_lazy_duplicate_of_canonical_row() {
        use fhe_math::rq::{PowerBasis, traits::TryConvertFrom as TryConvertFromPoly};

        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let ctx0 = params.context_at_level(0).unwrap();

        let coefficients: Vec<i64> = (0..ctx0.degree())
            .map(|_| rng.random_range(0..(1 << 40)))
            .collect();
        let canonical =
            Poly::<PowerBasis>::try_convert_from(coefficients.as_slice(), ctx0, false).unwrap();
        let canonical = canonical.into_ntt();
        let variable_time = fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
        let power_basis_coefficients: Vec<u64> = coefficients
            .iter()
            .map(|&coefficient| coefficient as u64)
            .collect();
        let lazy =
            Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                &power_basis_coefficients,
                ctx0,
                variable_time,
            );
        // The representations differ in raw view but hold the same value.
        assert_ne!(canonical.coefficients(), lazy.coefficients());

        // Control: fully independent rows are accepted.
        let mut polys: Vec<Poly<Ntt>> = (0..params.moduli().len())
            .map(|_| Poly::<Ntt>::random(ctx0, &mut rng))
            .collect();
        assert!(CommonRandomPolyVec::from_polys(&params, polys.clone(), None).is_ok());

        // The lazy duplicate of the canonical row 0 must be rejected as a
        // repeat of the same mathematical row.
        polys[0] = canonical;
        polys[params.moduli().len() - 1] = lazy;
        assert!(matches!(
            CommonRandomPolyVec::from_polys(&params, polys, None),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::RepeatedReferenceStringRow {
                    role: crate::ReferenceStringRole::CommonRandomPolyVector,
                    first_index: 0,
                    second_index: _,
                }
            ))
        ));
    }

    /// A deterministic RNG whose output never varies: every sampled row ends
    /// up with identical coefficients.
    struct FixedRng;

    impl rand::RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            0xdead_beef
        }

        fn next_u64(&mut self) -> u64 {
            0xdead_beef_dead_beef
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0xa5);
        }
    }

    impl rand::CryptoRng for FixedRng {}

    /// A degenerate RNG that emits identical bytes must make `new` fail with a
    /// repeated-row error instead of returning a reference-string vector with
    /// duplicate rows (no unbounded retry).
    #[test]
    fn new_rejects_degenerate_rng_repeating_rows() {
        let params = BfvParameters::default_arc(6, 8);

        // Control: a real RNG yields distinct rows.
        let mut rng = rng();
        assert!(CommonRandomPolyVec::new(&params, &mut rng).is_ok());

        // Degenerate RNG: every row samples to the same polynomial.
        assert!(matches!(
            CommonRandomPolyVec::new(&params, &mut FixedRng),
            Err(crate::Error::Multiparty(
                crate::MultipartyError::RepeatedReferenceStringRow {
                    role: crate::ReferenceStringRole::CommonRandomPolyVector,
                    first_index: 0,
                    second_index: 1,
                }
            ))
        ));
    }

    #[test]
    fn common_random_poly_new_deterministic() {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(6, 8),
            BfvParameters::default_arc(1, 8),
        ] {
            let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut seed);

            let crp1 = CommonRandomPoly::new_deterministic(&params, seed).unwrap();
            let crp2 = CommonRandomPoly::new_deterministic(&params, seed).unwrap();

            assert_eq!(crp1.poly(), crp2.poly());
        }
    }

    /// Equality compares only concrete polynomials; seed metadata is ignored.
    #[test]
    fn common_random_poly_vec_partial_eq_excludes_seed() {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);

        let seeded = CommonRandomPolyVec::from_seed(&params, seed).unwrap();
        assert!(seeded.seed().is_some());

        let seedless = CommonRandomPolyVec::from_polys(&params, seeded.to_polys(), None).unwrap();
        assert!(seedless.seed().is_none());

        // Different seeds, same concrete polys → must be equal.
        assert_eq!(seeded, seedless);
        assert_eq!(seedless, seeded);

        // Different concrete polys → must be unequal.
        let different = CommonRandomPolyVec::new(&params, &mut rng).unwrap();
        assert_ne!(seeded, different);
    }
}
