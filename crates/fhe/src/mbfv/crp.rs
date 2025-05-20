use std::sync::Arc;

use crate::bfv::BfvParameters;
use crate::Result;
use fhe_math::rq::Poly;
use fhe_traits::{DeserializeWithContext, Serialize};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// A polynomial sampled from a random _common reference string_.
// TODO CRS->CRP implementation. For now just a random polynomial.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CommonRandomPoly {
    pub(crate) poly: Poly,
}

impl CommonRandomPoly {
    /// Generate a new random CRP.
    pub fn new<R: RngCore + CryptoRng>(par: &Arc<BfvParameters>, rng: &mut R) -> Result<Self> {
        Self::new_leveled(par, 0, rng)
    }

    /// Generate a new CRP from a shared deterministic seed.
    pub fn new_deterministic(
        par: &Arc<BfvParameters>,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
    ) -> Result<Self> {
        Self::new_leveled_deterministic(par, 0, seed)
    }

    /// Generate a new random CRP vector.
    ///
    /// The size of the vector is equal to the number of ciphertext moduli, as
    /// required for the relinearization key generation protocol.
    pub fn new_vec<R: RngCore + CryptoRng>(
        par: &Arc<BfvParameters>,
        rng: &mut R,
    ) -> Result<Vec<Self>> {
        (0..par.moduli().len())
            .map(|_| Self::new(par, rng))
            .collect()
    }

    /// Generate a new random leveled CRP.
    pub fn new_leveled<R: RngCore + CryptoRng>(
        par: &Arc<BfvParameters>,
        level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let ctx = par.ctx_at_level(level)?;
        let poly = Poly::random(ctx, fhe_math::rq::Representation::Ntt, rng);
        Ok(Self { poly })
    }

    /// Generate a new deterministic leveled CRP.
    pub fn new_leveled_deterministic(
        par: &Arc<BfvParameters>,
        level: usize,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
    ) -> Result<Self> {
        let ctx = par.ctx_at_level(level)?;
        let poly = Poly::random_from_seed(ctx, fhe_math::rq::Representation::Ntt, seed);
        Ok(Self { poly })
    }

    /// Deserialize a CRP from bytes
    pub fn deserialize(bytes: &[u8], par: &Arc<BfvParameters>) -> Result<Self> {
        let test = Poly::from_bytes(bytes, par.ctx_at_level(0).unwrap());
        Ok(Self {
            poly: test.unwrap(),
        })
    }
}

impl Serialize for CommonRandomPoly {
    fn to_bytes(&self) -> Vec<u8> {
        //PublicKeyProto::from(self).encode_to_vec()
        //Vec::new()
        self.poly.to_bytes()
    }
}
