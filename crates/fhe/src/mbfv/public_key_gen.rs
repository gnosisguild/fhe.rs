use std::sync::Arc;

use crate::bfv::{BfvParameters, Ciphertext, PublicKey, SecretKey};
use crate::errors::Result;
use crate::Error;
use fhe_math::rq::{traits::TryConvertFrom, Poly, Representation};
use fhe_traits::{DeserializeWithContext, Serialize};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;
//use serde::{Serialize, Deserialize};

use super::{Aggregate, CommonRandomPoly};

/// A party's share in public key generation protocol.
///
/// Each party uses the `PublicKeyShare` to generate their share of the public key and participate in the in the "Protocol 1: EncKeyGen", as detailed in [Multiparty BFV](https://eprint.iacr.org/2020/304.pdf) (p6). Use the [`Aggregate`] impl to combine the shares into a [`PublicKey`].
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKeyShare {
    pub(crate) par: Arc<BfvParameters>,
    pub(crate) crp: CommonRandomPoly,
    pub(crate) p0_share: Poly,
}

impl PublicKeyShare {
    /// Participate in a new EncKeyGen protocol.
    ///
    /// 1. *Private input*: BFV secret key share
    /// 2. *Public input*: common random polynomial
    //
    // Implementation note: This is largely the same approach taken by fhe.rs, a
    // symmetric encryption of zero, the difference being that the crp is used
    // instead of a random poly. Might be possible to just pass a valid seed to
    // each party and basically take the SecretKey::try_encrypt implementation,
    // but with the hardcoded seed.
    pub fn new<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        crp: CommonRandomPoly,
        rng: &mut R,
    ) -> Result<Self> {
        let par = sk_share.par.clone();
        let ctx = par.ctx_at_level(0)?;

        // Convert secret key to usable polynomial
        let mut s = Zeroizing::new(Poly::try_convert_from(
            sk_share.coeffs.as_ref(),
            ctx,
            false,
            Representation::PowerBasis,
        )?);
        s.change_representation(Representation::Ntt);

        // Sample error
        let e = Zeroizing::new(Poly::small(ctx, Representation::Ntt, par.variance, rng)?);
        // Create p0_i share
        let mut p0_share = -crp.poly.clone();
        p0_share.disallow_variable_time_computations();
        p0_share.change_representation(Representation::Ntt);
        p0_share *= s.as_ref();
        p0_share += e.as_ref();
        unsafe { p0_share.allow_variable_time_computations() }

        Ok(Self { par, crp, p0_share })
    }

    /// Deserialize a PublicKeyShare from bytes with the given parameters and
    /// CRP
    pub fn deserialize(
        bytes: &[u8],
        par: &Arc<BfvParameters>,
        crp: CommonRandomPoly,
    ) -> Result<Self> {
        let test = Poly::from_bytes(bytes, par.ctx_at_level(0).unwrap());
        Ok(Self {
            par: par.clone(),
            crp: crp.clone(),
            p0_share: test.unwrap(),
        })
    }

    /// Generate an MBFV PublicKeyShare from threshold parties' individual MBFV shares.
    ///
    /// SECURE: This method aggregates individual MBFV public key shares from threshold parties
    /// without ever reconstructing the underlying group secret. Each party contributes their
    /// individual MBFV share, and these are aggregated using the MBFV additive property.
    ///
    /// This maintains threshold security - no single party knows the group secret, and the
    /// group MBFV share is controlled by the threshold parties collectively.
    pub fn new_from_threshold_parties(
        individual_pk_shares: Vec<PublicKeyShare>, // Individual MBFV shares from threshold parties (take ownership)
        threshold: usize,
    ) -> Result<Self> {
        if individual_pk_shares.len() < threshold {
            return Err(crate::Error::DefaultError(format!(
                "Need at least {} individual shares for threshold {}, got {}",
                threshold,
                threshold,
                individual_pk_shares.len()
            )));
        }

        // Take exactly threshold shares and aggregate them
        // SECURE: No secret reconstruction - only MBFV share aggregation
        let shares_to_aggregate = individual_pk_shares
            .into_iter()
            .take(threshold)
            .collect::<Vec<_>>();

        // Use existing secure MBFV aggregation
        Self::from_shares(shares_to_aggregate)
    }
}

impl Aggregate<PublicKeyShare> for PublicKey {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = PublicKeyShare>,
    {
        let mut shares = iter.into_iter();
        let share = shares.next().ok_or(Error::TooFewValues(0, 1))?;
        let mut p0 = share.p0_share;
        for sh in shares {
            p0 += &sh.p0_share;
        }

        Ok(PublicKey {
            c: Ciphertext::new(vec![p0, share.crp.poly], &share.par)?,
            par: share.par,
        })
    }
}

impl Aggregate<PublicKeyShare> for PublicKeyShare {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = PublicKeyShare>,
    {
        let mut shares = iter.into_iter();
        let first_share = shares.next().ok_or(Error::TooFewValues(0, 1))?;

        let mut aggregated_p0_share = first_share.p0_share.clone();
        let par = first_share.par.clone();
        let crp = first_share.crp.clone();

        // Add all subsequent p0_shares
        for share in shares {
            // Verify compatibility
            if share.par != par {
                return Err(Error::DefaultError("Incompatible parameters".to_string()));
            }
            if share.crp != crp {
                return Err(Error::DefaultError(
                    "Incompatible common random polynomials".to_string(),
                ));
            }

            aggregated_p0_share += &share.p0_share;
        }

        Ok(PublicKeyShare {
            par,
            crp,
            p0_share: aggregated_p0_share,
        })
    }
}

// impl From<&PublicKeyShare> for PublicKeyShare {
//     fn from(pks: &PublicKeyShare) -> Self {
//         PublicKeyShareProto {
//             c: Some(CiphertextProto::from(&p0_share.p0)),
//         }
//     }
// }

impl Serialize for PublicKeyShare {
    fn to_bytes(&self) -> Vec<u8> {
        //PublicKeyShareProto::from(self).encode_to_vec()
        // PublicKeyShare {
        //     par: self.par,
        //     crp: self.crp,
        //     p0_share: self.p0_share,
        // }
        // .encode_to_vec()
        self.p0_share.to_bytes()
    }
}

// impl DeserializeWithCRP for PublicKeyShare {
//     type Error = Error;

//     fn from_bytes(bytes: &[u8], par: &Arc<Self::Parameters>, crp:
// CommonRandomPoly) -> Result<Self> {         Ok(Self {
//             par: par.clone(),
//             crp: crp.clone(),
//             p0_share,
//         })
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    use fhe_traits::{FheEncoder, FheEncrypter};
    use rand::thread_rng;

    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};

    const NUM_PARTIES: usize = 11;

    #[test]
    // This just makes sure the public key creation is successful, and arbitrary
    // encryptions complete without error. See a full encrypt->decrypt test in
    // `secret_key_switch`.
    fn protocol_creates_valid_pk() {
        let mut rng = thread_rng();
        for par in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            for level in 0..=par.max_level() {
                for _ in 0..20 {
                    let crp = CommonRandomPoly::new(&par, &mut rng).unwrap();

                    let mut pk_shares: Vec<PublicKeyShare> = vec![];

                    // Parties collectively generate public key
                    for _ in 0..NUM_PARTIES {
                        let sk_share = SecretKey::random(&par, &mut rng);
                        let pk_share =
                            PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();
                        pk_shares.push(pk_share);
                    }
                    let public_key = PublicKey::from_shares(pk_shares).unwrap();

                    // Use it to encrypt a random polynomial
                    let pt = Plaintext::try_encode(
                        &par.plaintext.random_vec(par.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &par,
                    )
                    .unwrap();
                    let _ct = public_key.try_encrypt(&pt, &mut rng).unwrap();
                }
            }
        }
    }
}
