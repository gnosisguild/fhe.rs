use std::sync::Arc;

use fhe_math::rq::{Ntt, Poly};
use fhe_traits::{DeserializeParametrized, Serialize};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
use crate::lbfv::LBFVPublicKey;
use crate::{Error, Result};

/// A party's additive contribution to threshold l-BFV public-key generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyShare {
    pub(crate) key: LBFVPublicKey,
}

impl PublicKeyShare {
    /// Return cloned public-key `b` components (`c[0]`) in gadget-row order.
    pub fn b_components(&self) -> Result<Vec<Poly<Ntt>>> {
        self.key.validate_structure()?;
        self.key
            .c
            .iter()
            .enumerate()
            .map(|(index, ciphertext)| {
                ciphertext.c.first().cloned().ok_or_else(|| {
                    Error::DefaultError(format!(
                        "LBFV public-key ciphertext {index} is missing b component"
                    ))
                })
            })
            .collect()
    }

    /// Return cloned concrete CRS `a` components (`c[1]`) in gadget-row order.
    pub fn a_components(&self) -> Result<Vec<Poly<Ntt>>> {
        self.key.validate_structure()?;
        self.key
            .c
            .iter()
            .enumerate()
            .map(|(index, ciphertext)| {
                ciphertext.c.get(1).cloned().ok_or_else(|| {
                    Error::DefaultError(format!(
                        "LBFV public-key ciphertext {index} is missing a component"
                    ))
                })
            })
            .collect()
    }

    /// Create a public-key contribution from a secret-key contribution and a
    /// shared CRS seed.
    pub fn new_with_seed<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Result<Self> {
        Ok(Self {
            key: LBFVPublicKey::new_with_seed(sk, seed, rng)?,
        })
    }

    /// Create a public-key contribution from explicit CRS polynomials.
    pub fn contribute<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        a_polynomials: &[Poly<Ntt>],
        rng: &mut R,
    ) -> Result<Self> {
        Ok(Self {
            key: LBFVPublicKey::from_crs(sk, a_polynomials, None, rng)?,
        })
    }

    /// Create a public-key contribution from a shared CRS vector.
    pub fn contribute_with_crp<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        crp: &CommonRandomPolyVec,
        rng: &mut R,
    ) -> Result<Self> {
        let a_polys = crp.to_polys();
        Ok(Self {
            key: LBFVPublicKey::from_crs(sk, &a_polys, crp.seed(), rng)?,
        })
    }

    /// Build a public-key contribution from explicit key polynomials.
    pub fn from_parts(
        b_polynomials: Vec<Poly<Ntt>>,
        a_polynomials: Vec<Poly<Ntt>>,
        params: Arc<BfvParameters>,
        seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
    ) -> Result<Self> {
        Ok(Self {
            key: LBFVPublicKey::from_parts(b_polynomials, a_polynomials, params, seed)?,
        })
    }
}

impl fhe_traits::FheParametrized for PublicKeyShare {
    type Parameters = BfvParameters;
}

impl Serialize for PublicKeyShare {
    fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes()
    }
}

impl DeserializeParametrized for PublicKeyShare {
    type Error = crate::Error;

    fn from_bytes(bytes: &[u8], params: &Arc<BfvParameters>) -> Result<Self> {
        Ok(Self {
            key: LBFVPublicKey::from_bytes(bytes, params)?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::aggregate::{Aggregate, AggregateIter};
    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};
    use fhe_traits::{FheDecrypter, FheEncoder, FheEncrypter};
    use rand::{SeedableRng, rng};

    #[test]
    fn contributions_aggregate_into_operational_key() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sks = [
            SecretKey::random(&params, &mut rng),
            SecretKey::random(&params, &mut rng),
        ];
        let seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let shares = sks
            .iter()
            .map(|sk| PublicKeyShare::new_with_seed(sk, seed, &mut rng))
            .collect::<Result<Vec<_>>>()?;

        let aggregated: LBFVPublicKey = shares.into_iter().aggregate()?;
        let joint_coeffs = (0..params.degree())
            .map(|index| sks.iter().map(|sk| sk.coeffs[index]).sum())
            .collect();
        let joint_sk = SecretKey::new(joint_coeffs, &params);
        let plaintext = Plaintext::try_encode(&[7u64], Encoding::poly(), &params)?;
        let ciphertext = aggregated.try_encrypt(&plaintext, &mut rng)?;

        assert_eq!(joint_sk.try_decrypt(&ciphertext)?, plaintext);
        Ok(())
    }

    #[test]
    fn aggregation_rejects_inconsistent_crs() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk1 = SecretKey::random(&params, &mut rng);
        let sk2 = SecretKey::random(&params, &mut rng);
        let seed1 = <ChaCha8Rng as SeedableRng>::Seed::default();
        let mut seed2 = seed1;
        seed2[0] = 1;
        let share1 = PublicKeyShare::new_with_seed(&sk1, seed1, &mut rng)?;
        let share2 = PublicKeyShare::new_with_seed(&sk2, seed2, &mut rng)?;

        assert!(
            <LBFVPublicKey as Aggregate<PublicKeyShare>>::from_shares([share1, share2]).is_err()
        );
        Ok(())
    }

    #[test]
    fn crp_components_and_serialization_roundtrip() -> Result<()> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        let share = PublicKeyShare::contribute_with_crp(&sk, &crp, &mut rng)?;

        assert_eq!(share.key.seed, crp.seed());
        assert_eq!(share.a_components()?, crp.to_polys());
        assert_eq!(share.b_components()?.len(), params.moduli().len());
        assert_eq!(
            PublicKeyShare::from_bytes(&share.to_bytes(), &params)?,
            share
        );
        Ok(())
    }

    #[test]
    fn aggregation_rejects_zero_shares() {
        let result = Vec::<PublicKeyShare>::new()
            .into_iter()
            .aggregate::<LBFVPublicKey>();
        assert!(result.is_err());
    }
}
