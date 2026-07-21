use std::sync::Arc;

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::Result;
use crate::bfv::BfvParameters;
use crate::mbfv::CommonRandomPoly;

/// The common reference string for the l-BFV protocol.
///
/// Holds the vector `a = (a₀, ..., a_{l-1})` of l uniformly random polynomials
/// in R_q that all parties must share. In the paper (§3.1 and §5.2) this is the
/// CRS used both for public key generation (`b_j = -a_j·sk + e_j`) and for the
/// relinearization key's `d₂` component.
///
/// Constructed once (via coin-tossing in a real protocol), then passed to
/// [`LBFVPublicKey::new_from_crs`] and [`LBFVRelinKeyShare::contribution_from_crs`]
/// by every party. The internal seed is kept for efficient binding checks during
/// key aggregation; `polys` exposes the actual `a_j` polynomials as first-class
/// objects (e.g. for circuit inputs).
#[derive(Debug, Clone)]
pub struct LBFVCommonReferenceString {
    /// The l CRP polynomials `a₀, ..., a_{l-1}`, one per RNS modulus.
    pub polys: Vec<CommonRandomPoly>,
    /// The seed from which all `polys` are deterministically derived.
    pub(crate) seed: <ChaCha8Rng as SeedableRng>::Seed,
}

impl LBFVCommonReferenceString {
    /// Sample a fresh CRS uniformly at random.
    pub fn new<R: RngCore + CryptoRng>(par: &Arc<BfvParameters>, rng: &mut R) -> Result<Self> {
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);
        Self::from_seed(par, seed)
    }

    /// Reconstruct the CRS deterministically from a shared `seed`.
    ///
    /// Every party calling this with the same `seed` and `par` obtains the
    /// identical `a` vector — this is the CRS agreement step.
    pub fn from_seed(
        par: &Arc<BfvParameters>,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
    ) -> Result<Self> {
        let polys = CommonRandomPoly::new_vec_deterministic(par, seed)?;
        Ok(Self { polys, seed })
    }

    /// The raw seed (32 bytes) from which this CRS was derived.
    ///
    /// Suitable for compact broadcast: a receiver can call [`from_seed`](Self::from_seed)
    /// to reconstruct the full polynomial vector without transferring `l` polynomials.
    #[must_use]
    pub fn seed(&self) -> <ChaCha8Rng as SeedableRng>::Seed {
        self.seed
    }
}
