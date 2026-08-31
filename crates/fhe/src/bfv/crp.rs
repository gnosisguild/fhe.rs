use std::sync::Arc;

use crate::Result;
use crate::bfv::BfvParameters;
use fhe_math::rq::{Ntt, Poly};
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
///   where the CRP vector is passed to [`RelinKeyGenerator`](crate::mbfv::RelinKeyGenerator).
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
/// # Construction
///
/// - [`CommonRandomPolyVec::new`] samples `l` independent random polynomials.
/// - [`CommonRandomPolyVec::from_seed`] deterministically reconstructs `l`
///   polynomials from a single 32-byte seed.
/// - [`CommonRandomPolyVec::from_polys`] accepts explicit `Poly<Ntt>` values
///   together with optional seed metadata, validating context, length, and
///   seed consistency.
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
    pub fn new<R: RngCore + CryptoRng>(params: &Arc<BfvParameters>, rng: &mut R) -> Result<Self> {
        let l = params.moduli().len();
        let mut polys = Vec::with_capacity(l);
        for _ in 0..l {
            polys.push(CommonRandomPoly::new(params, rng)?);
        }
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
    /// - If `seed` is `Some`, the concrete polynomials are verified to match the
    ///   deterministic output of that seed. A contradictory seed is rejected.
    pub fn from_polys(
        params: &Arc<BfvParameters>,
        polys: Vec<Poly<Ntt>>,
        seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
    ) -> Result<Self> {
        let expected_l = params.moduli().len();
        if polys.len() != expected_l {
            return Err(crate::Error::DefaultError(format!(
                "CommonRandomPolyVec expected {} polynomials (one per modulus), got {}",
                expected_l,
                polys.len()
            )));
        }

        let ctx0 = params.context_at_level(0)?;
        for (i, p) in polys.iter().enumerate() {
            if p.ctx() != ctx0 {
                return Err(crate::Error::DefaultError(format!(
                    "CommonRandomPolyVec polynomial {i} has an incorrect context"
                )));
            }
        }

        // If a seed is given, verify it reproduces the supplied polynomials.
        if let Some(ref seed) = seed {
            let mut seed_rng = ChaCha8Rng::from_seed(*seed);
            for (i, poly) in polys.iter().enumerate() {
                let mut seed_i = <ChaCha8Rng as SeedableRng>::Seed::default();
                seed_rng.fill(&mut seed_i);
                let expected = Poly::<Ntt>::random_from_seed(ctx0, seed_i);
                if expected != *poly {
                    return Err(crate::Error::DefaultError(format!(
                        "CommonRandomPolyVec seed does not match the concrete polynomial at index {i}"
                    )));
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
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
        assert!(CommonRandomPolyVec::from_polys(&params, too_few, None).is_err());

        let ctx0 = params.context_at_level(0).unwrap();
        let too_many: Vec<Poly<Ntt>> = (0..params.moduli().len() + 1)
            .map(|_| Poly::<Ntt>::random(ctx0, &mut rng))
            .collect();
        assert!(CommonRandomPolyVec::from_polys(&params, too_many, None).is_err());
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
        assert!(CommonRandomPolyVec::from_polys(&params, polys, Some(other_seed)).is_err());

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
