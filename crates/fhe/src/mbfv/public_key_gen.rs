use std::sync::Arc;

use crate::Result;
use crate::bfv::{BfvParameters, Ciphertext, PublicKey, SecretKey};
use fhe_math::rq::{Ntt, Poly, PowerBasis, traits::TryConvertFrom};
use fhe_traits::{DeserializeWithContext, Serialize};
use rand::{CryptoRng, Rng as RngCore};
use zeroize::{Zeroize, Zeroizing};
//use serde::{Serialize, Deserialize};

use crate::bfv::CommonRandomPoly;

use super::Aggregate;

/// A party's share in public key generation protocol.
///
/// Each party uses the `PublicKeyShare` to generate their share of the public key and participate in the in the "Protocol 1: EncKeyGen", as detailed in [Multiparty BFV](https://eprint.iacr.org/2020/304.pdf) (p6). Use the [`Aggregate`] impl to combine the shares into a [`PublicKey`].
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKeyShare {
    pub(crate) params: Arc<BfvParameters>,
    pub(crate) crp: CommonRandomPoly,
    pub(crate) p0_share: Poly<Ntt>,
}

/// Intermediates from multiparty BFV public-key share generation.
///
/// These intermediates zeroize their polynomials when dropped. Retain them only while the
/// calling protocol needs these values.
pub struct PublicKeyShareIntermediates {
    secret_key: Poly<Ntt>,
    error: Poly<Ntt>,
}

impl PublicKeyShareIntermediates {
    /// Returns the secret-key share polynomial in NTT form.
    #[must_use]
    pub fn secret_key(&self) -> &Poly<Ntt> {
        &self.secret_key
    }

    /// Returns the public-key share error polynomial.
    #[must_use]
    pub fn error(&self) -> &Poly<Ntt> {
        &self.error
    }
}

impl Zeroize for PublicKeyShareIntermediates {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
        self.error.zeroize();
    }
}

impl Drop for PublicKeyShareIntermediates {
    fn drop(&mut self) {
        self.zeroize();
    }
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
        let params = sk_share.params.clone();
        let ctx = params.context_at_level(0)?;

        // Convert secret key to usable polynomial
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?.into_ntt(),
        );

        // Sample error
        let e = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);
        // Create p0_i share
        let mut p0_share = -crp.poly.clone();
        p0_share.disallow_variable_time_computations();
        p0_share *= s.as_ref();
        p0_share += e.as_ref();
        p0_share.allow_variable_time_computations(fhe_traits::VariableTime::new(
            fhe_traits::PublicData::assert_public(),
        ));

        Ok(Self {
            params,
            crp,
            p0_share,
        })
    }

    /// Generate a public-key share and return the secret-key polynomial and sampled error.
    ///
    /// The intermediates zeroize their polynomials when dropped.
    pub fn new_with_intermediates<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        crp: CommonRandomPoly,
        rng: &mut R,
    ) -> Result<(Self, PublicKeyShareIntermediates)> {
        let params = sk_share.params.clone();
        let ctx = params.context_at_level(0)?;

        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?.into_ntt(),
        );
        let e = Zeroizing::new(Poly::<Ntt>::small(ctx, params.variance, rng)?);

        let mut p0_share = -crp.poly.clone();
        p0_share.disallow_variable_time_computations();
        p0_share *= s.as_ref();
        p0_share += e.as_ref();
        p0_share.allow_variable_time_computations(fhe_traits::VariableTime::new(
            fhe_traits::PublicData::assert_public(),
        ));

        Ok((
            Self {
                params,
                crp,
                p0_share,
            },
            PublicKeyShareIntermediates {
                secret_key: (*s).clone(),
                error: (*e).clone(),
            },
        ))
    }

    /// Deserialize a PublicKeyShare from bytes with the given parameters and
    /// CRP
    pub fn deserialize(
        bytes: &[u8],
        params: &Arc<BfvParameters>,
        crp: CommonRandomPoly,
    ) -> Result<Self> {
        let ctx = params.context_at_level(0)?;
        let p0_share = Poly::<Ntt>::from_bytes(bytes, ctx)?;
        Ok(Self {
            params: params.clone(),
            crp,
            p0_share,
        })
    }
    /// Convert this PublicKeyShare to an individual PublicKey without aggregation.
    ///
    /// This creates a PublicKey that can be used for individual encryption/decryption
    /// with the corresponding SecretKey. The resulting PublicKey is NOT suitable for
    /// threshold operations - use aggregation for that.
    // pub fn to_public_key(&self) -> Result<PublicKey> {
    //     Ok(PublicKey {
    //         c: Ciphertext::new(
    //             vec![self.p0_share.clone(), self.crp.poly.clone()],
    //             &self.params,
    //         )?,
    //         params: self.params.clone(),
    //     })
    // }
    pub fn to_public_key(&self) -> Result<PublicKey> {
        let mut p0 = self.p0_share.clone();
        let mut p1 = self.crp.poly.clone();

        p0.disallow_variable_time_computations();
        p1.disallow_variable_time_computations();

        Ok(PublicKey {
            c: Ciphertext::new(vec![p0, p1], &self.params)?,
            params: self.params.clone(),
        })
    }

    /// Get a reference to the underlying p0_share polynomial.
    #[must_use]
    pub fn p0_share(&self) -> &Poly<Ntt> {
        &self.p0_share
    }

    /// Get the underlying p0_share polynomial (consumes self).
    #[must_use]
    pub fn into_p0_share(self) -> Poly<Ntt> {
        self.p0_share
    }
}

impl Aggregate<PublicKeyShare> for PublicKey {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = PublicKeyShare>,
    {
        let mut shares = iter.into_iter();
        let share = shares.next().ok_or(crate::MultipartyError::NoShares)?;
        let mut p0 = share.p0_share;
        for sh in shares {
            p0 += &sh.p0_share;
        }

        Ok(PublicKey {
            c: Ciphertext::new(vec![p0, share.crp.poly], &share.params)?,
            params: share.params,
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
        //     params: self.params,
        //     crp: self.crp,
        //     p0_share: self.p0_share,
        // }
        // .encode_to_vec()
        self.p0_share.to_bytes()
    }
}

// impl DeserializeWithCRP for PublicKeyShare {
//     type Error = Error;

//     fn from_bytes(bytes: &[u8], params: &Arc<Self::Parameters>, crp:
// CommonRandomPoly) -> Result<Self> {         Ok(Self {
//             params: params.clone(),
//             crp: crp.clone(),
//             p0_share,
//         })
//     }
// }

#[cfg(test)]
mod tests {
    use fhe_traits::{FheEncoder, FheEncrypter};
    use rand::rng;

    use crate::{
        bfv::{BfvParameters, CommonRandomPoly, Encoding, Plaintext, PublicKey, SecretKey},
        mbfv::Aggregate as _,
    };

    use super::PublicKeyShare;

    const NUM_PARTIES: usize = 11;

    #[test]
    // This just makes sure the public key creation is successful, and arbitrary
    // encryptions complete without error. See a full encrypt->decrypt test in
    // `secret_key_switch`.
    fn protocol_creates_valid_pk() {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 32),
        ] {
            for level in 0..=params.max_level() {
                for _ in 0..20 {
                    let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();

                    let mut pk_shares: Vec<PublicKeyShare> = vec![];

                    // Parties collectively generate public key
                    for _ in 0..NUM_PARTIES {
                        let sk_share = SecretKey::random(&params, &mut rng);
                        let pk_share =
                            PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();
                        pk_shares.push(pk_share);
                    }
                    let public_key = PublicKey::from_shares(pk_shares).unwrap();

                    // Use it to encrypt a random polynomial
                    let pt = Plaintext::try_encode(
                        &fhe_math::zq::Modulus::new(params.plaintext())
                            .unwrap()
                            .random_vec(params.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &params,
                    )
                    .unwrap();
                    let _ct = public_key.try_encrypt(&pt, &mut rng).unwrap();
                }
            }
        }
    }

    #[test]
    fn test_new_with_intermediates() {
        let mut rng = rng();

        // Test with different parameter configurations
        for params in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            let sk_share = SecretKey::random(&params, &mut rng);
            let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();

            let (share, intermediates) =
                PublicKeyShare::new_with_intermediates(&sk_share, crp.clone(), &mut rng).unwrap();
            let pk_0 = &share.p0_share;
            let pk_1 = &share.crp.poly;
            let s = intermediates.secret_key();
            let e = intermediates.error();

            // Verify pk_1 is the same as crp polynomial
            assert_eq!(*pk_1, crp.poly, "pk_1 should be the same as crp polynomial");

            // Verify the relationship: pk_0 = -a*s + e
            // Compute -a*s + e and compare with pk_0
            let mut expected = -crp.poly.clone();
            expected.disallow_variable_time_computations();
            expected *= s;
            expected += e;
            expected.allow_variable_time_computations(fhe_traits::VariableTime::new(
                fhe_traits::PublicData::assert_public(),
            ));

            assert_eq!(*pk_0, expected, "pk_0 should equal -a*s + e");

            assert_eq!(s.representation(), fhe_math::rq::Representation::Ntt);
            assert_eq!(e.representation(), fhe_math::rq::Representation::Ntt);
            assert_eq!(pk_0.representation(), fhe_math::rq::Representation::Ntt);
        }
    }

    #[test]
    fn test_new_with_intermediates_multiple_parties() {
        let mut rng = rng();
        const NUM_PARTIES: usize = 5;

        let params = BfvParameters::default_arc(1, 8);
        let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();

        let mut intermediates_data = vec![];
        for _ in 0..NUM_PARTIES {
            let sk_share = SecretKey::random(&params, &mut rng);
            let (share, intermediates) =
                PublicKeyShare::new_with_intermediates(&sk_share, crp.clone(), &mut rng).unwrap();
            intermediates_data.push((share, intermediates));
        }

        for (share, _) in &intermediates_data {
            assert_eq!(share.crp.poly, crp.poly, "All parties use the same CRP");
        }

        // Verify the mathematical relationship holds for each party
        for (share, intermediates) in &intermediates_data {
            let mut expected = -share.crp.poly.clone();
            expected.disallow_variable_time_computations();
            expected *= intermediates.secret_key();
            expected += intermediates.error();
            expected.allow_variable_time_computations(fhe_traits::VariableTime::new(
                fhe_traits::PublicData::assert_public(),
            ));
            assert_eq!(
                share.p0_share, expected,
                "pk_0 should equal -a*s + e for each party"
            );
        }
    }

    #[test]
    fn test_new_with_intermediates_consistency_with_new() {
        let mut rng = rng();

        let params = BfvParameters::default_arc(1, 8);
        let sk_share = SecretKey::random(&params, &mut rng);
        let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();

        // Create PublicKeyShare using original new()
        let pks = PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();

        let (share, _intermediates) =
            PublicKeyShare::new_with_intermediates(&sk_share, crp.clone(), &mut rng).unwrap();

        assert_eq!(
            share.crp.poly, pks.crp.poly,
            "pk_1 from new_with_intermediates should match crp from PublicKeyShare"
        );
        assert_eq!(
            share.crp.poly, crp.poly,
            "pk_1 should be the crp polynomial"
        );
    }

    #[test]
    fn public_key_share_intermediates_zeroize_their_polynomials() {
        use zeroize::Zeroize;

        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk_share = SecretKey::random(&params, &mut rng);
        let crp = CommonRandomPoly::new(&params, &mut rng).unwrap();
        let (_share, mut intermediates) =
            PublicKeyShare::new_with_intermediates(&sk_share, crp, &mut rng).unwrap();

        intermediates.zeroize();
        for poly in [intermediates.secret_key(), intermediates.error()] {
            assert!(
                poly.coefficients()
                    .iter()
                    .all(|&coefficient| coefficient == 0)
            );
        }
    }
}
