use std::sync::Arc;

use crate::Result;
use crate::bfv::BfvParameters;
use fhe_math::rq::{Ntt, Poly};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// A polynomial sampled from a random _common reference string_.
// TODO CRS->CRP implementation. For now just a random polynomial.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CommonRandomPoly {
    pub(crate) poly: Poly<Ntt>,
}

impl CommonRandomPoly {
    /// Generate a new random CRP.
    pub fn new<R: RngCore + CryptoRng>(params: &Arc<BfvParameters>, rng: &mut R) -> Result<Self> {
        Self::new_leveled(params, 0, rng)
    }

    /// Generate a new CRP from a shared deterministic seed.
    pub fn new_deterministic(
        params: &Arc<BfvParameters>,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
    ) -> Result<Self> {
        Self::new_leveled_deterministic(params, 0, seed)
    }

    /// Generate a new random CRP vector.
    ///
    /// The size of the vector is equal to the number of ciphertext moduli, as
    /// required for the relinearization key generation protocol.
    pub fn new_vec<R: RngCore + CryptoRng>(
        params: &Arc<BfvParameters>,
        rng: &mut R,
    ) -> Result<Vec<Self>> {
        (0..params.moduli().len())
            .map(|_| Self::new(params, rng))
            .collect()
    }

    /// Generate a new random leveled CRP.
    pub fn new_leveled<R: RngCore + CryptoRng>(
        params: &Arc<BfvParameters>,
        level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let ctx = params.context_at_level(level)?;
        let poly = Poly::<Ntt>::random(ctx, rng);
        Ok(Self { poly })
    }

    /// Generate a new deterministic leveled CRP.
    pub fn new_leveled_deterministic(
        params: &Arc<BfvParameters>,
        level: usize,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
    ) -> Result<Self> {
        let ctx = params.context_at_level(level)?;
        let poly = Poly::<Ntt>::random_from_seed(ctx, seed);
        Ok(Self { poly })
    }

    /// Get a reference to the underlying polynomial.
    #[must_use]
    pub fn poly(&self) -> &Poly<Ntt> {
        &self.poly
    }

    /// Get the underlying polynomial (consumes self).
    #[must_use]
    pub fn into_poly(self) -> Poly<Ntt> {
        self.poly
    }
}

#[cfg(feature = "protobuf")]
mod protobuf {
    use super::*;
    use fhe_traits::{DeserializeWithContext, Serialize};

    impl CommonRandomPoly {
        /// Deserialize a CRP from bytes.
        pub fn deserialize(bytes: &[u8], par: &std::sync::Arc<BfvParameters>) -> Result<Self> {
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
}
