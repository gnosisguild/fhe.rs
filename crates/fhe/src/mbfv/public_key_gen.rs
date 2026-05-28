use std::sync::Arc;

use crate::bfv::{BfvParameters, Ciphertext, PublicKey, SecretKey};
use crate::{Error, Result};
use fhe_math::rq::{Ntt, Poly, PowerBasis, traits::TryConvertFrom};
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
    pub(crate) p0_share: Poly<Ntt>,
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
        let ctx = par.context_at_level(0)?;

        // Convert secret key to usable polynomial
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?.into_ntt(),
        );

        // Sample error
        let e = Zeroizing::new(Poly::<Ntt>::small(ctx, par.variance, rng)?);
        // Create p0_i share
        let mut p0_share = -crp.poly.clone();
        p0_share.disallow_variable_time_computations();
        p0_share *= s.as_ref();
        p0_share += e.as_ref();
        unsafe { p0_share.allow_variable_time_computations() }

        Ok(Self { par, crp, p0_share })
    }

    /// Extended version of `new` that returns intermediate values for debugging/testing.
    ///
    /// Returns: (pk_0, pk_1, sk_poly, e)
    /// - pk_0: the p0_share (public key part 0 share) = -a*s + e
    /// - pk_1: the crp_poly (common random polynomial `a`, public key part 1)
    /// - sk_poly: the secret key polynomial in NTT form
    /// - e: the error polynomial
    #[allow(clippy::type_complexity)]
    pub fn new_extended<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        crp: CommonRandomPoly,
        rng: &mut R,
    ) -> Result<(Poly<Ntt>, Poly<Ntt>, Poly<Ntt>, Poly<Ntt>)> {
        let par = sk_share.par.clone();
        let ctx = par.context_at_level(0)?;

        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?.into_ntt(),
        );
        let e = Zeroizing::new(Poly::<Ntt>::small(ctx, par.variance, rng)?);

        let mut pk_0 = -crp.poly.clone();
        pk_0.disallow_variable_time_computations();
        pk_0 *= s.as_ref();
        pk_0 += e.as_ref();
        unsafe { pk_0.allow_variable_time_computations() }

        let pk_1 = crp.poly.clone();

        Ok((pk_0, pk_1, (*s).clone(), (*e).clone()))
    }

    /// Deserialize a PublicKeyShare from bytes with the given parameters and
    /// CRP
    pub fn deserialize(
        bytes: &[u8],
        par: &Arc<BfvParameters>,
        crp: CommonRandomPoly,
    ) -> Result<Self> {
        let ctx = par.context_at_level(0)?;
        let p0_share = Poly::<Ntt>::from_bytes(bytes, ctx)?;
        Ok(Self {
            par: par.clone(),
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
    //             &self.par,
    //         )?,
    //         par: self.par.clone(),
    //     })
    // }
    pub fn to_public_key(&self) -> Result<PublicKey> {
        let mut p0 = self.p0_share.clone();
        let mut p1 = self.crp.poly.clone();

        p0.disallow_variable_time_computations();
        p1.disallow_variable_time_computations();

        Ok(PublicKey {
            c: Ciphertext::new(vec![p0, p1], &self.par)?,
            par: self.par.clone(),
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
        let share = shares.next().ok_or(Error::TooFewValues {
            actual: 0,
            minimum: 1,
        })?;
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
    use fhe_traits::{FheEncoder, FheEncrypter};
    use rand::rng;

    use crate::{
        bfv::{BfvParameters, Encoding, Plaintext, PublicKey, SecretKey},
        mbfv::{Aggregate as _, CommonRandomPoly},
    };

    use super::PublicKeyShare;

    const NUM_PARTIES: usize = 11;

    #[test]
    // This just makes sure the public key creation is successful, and arbitrary
    // encryptions complete without error. See a full encrypt->decrypt test in
    // `secret_key_switch`.
    fn protocol_creates_valid_pk() {
        let mut rng = rng();
        for par in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 32),
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
                        &fhe_math::zq::Modulus::new(par.plaintext())
                            .unwrap()
                            .random_vec(par.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &par,
                    )
                    .unwrap();
                    let _ct = public_key.try_encrypt(&pt, &mut rng).unwrap();
                }
            }
        }
    }

    #[test]
    fn test_new_extended() {
        let mut rng = rng();

        // Test with different parameter configurations
        for par in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            let sk_share = SecretKey::random(&par, &mut rng);
            let crp = CommonRandomPoly::new(&par, &mut rng).unwrap();

            // Call new_extended
            let (pk_0, pk_1, s, e) =
                PublicKeyShare::new_extended(&sk_share, crp.clone(), &mut rng).unwrap();

            // Verify pk_1 is the same as crp polynomial
            assert_eq!(pk_1, crp.poly, "pk_1 should be the same as crp polynomial");

            // Verify the relationship: pk_0 = -a*s + e
            // Compute -a*s + e and compare with pk_0
            let mut expected = -crp.poly.clone();
            expected.disallow_variable_time_computations();
            expected *= &s;
            expected += &e;
            unsafe { expected.allow_variable_time_computations() }

            assert_eq!(pk_0, expected, "pk_0 should equal -a*s + e");

            assert_eq!(s.representation(), fhe_math::rq::Representation::Ntt);
            assert_eq!(e.representation(), fhe_math::rq::Representation::Ntt);
            assert_eq!(pk_0.representation(), fhe_math::rq::Representation::Ntt);
        }
    }

    #[test]
    fn test_new_extended_multiple_parties() {
        let mut rng = rng();
        const NUM_PARTIES: usize = 5;

        let par = BfvParameters::default_arc(1, 8);
        let crp = CommonRandomPoly::new(&par, &mut rng).unwrap();

        // Generate extended data for multiple parties
        let mut extended_data = vec![];
        for _ in 0..NUM_PARTIES {
            let sk_share = SecretKey::random(&par, &mut rng);
            let (pk_0, pk_1, s, e) =
                PublicKeyShare::new_extended(&sk_share, crp.clone(), &mut rng).unwrap();
            extended_data.push((pk_0, pk_1, s, e));
        }

        // Verify all parties have the same pk_1 (crp)
        for (_, pk_1, _, _) in &extended_data {
            assert_eq!(
                *pk_1, crp.poly,
                "All parties should have the same pk_1 (crp)"
            );
        }

        // Verify the mathematical relationship holds for each party
        for (pk_0, pk_1, s, e) in &extended_data {
            let mut expected = -pk_1.clone();
            expected.disallow_variable_time_computations();
            expected *= s;
            expected += e;
            unsafe { expected.allow_variable_time_computations() }
            assert_eq!(*pk_0, expected, "pk_0 should equal -a*s + e for each party");
        }
    }

    #[test]
    fn test_new_extended_consistency_with_new() {
        let mut rng = rng();

        let par = BfvParameters::default_arc(1, 8);
        let sk_share = SecretKey::random(&par, &mut rng);
        let crp = CommonRandomPoly::new(&par, &mut rng).unwrap();

        // Create PublicKeyShare using original new()
        let pks = PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();

        // Verify that new_extended produces pk_1 that matches the crp
        let (_pk_0, pk_1, _s, _e) =
            PublicKeyShare::new_extended(&sk_share, crp.clone(), &mut rng).unwrap();

        assert_eq!(
            pk_1, pks.crp.poly,
            "pk_1 from new_extended should match crp from PublicKeyShare"
        );
        assert_eq!(pk_1, crp.poly, "pk_1 should be the crp polynomial");
    }
}
