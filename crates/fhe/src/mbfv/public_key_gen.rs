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

    /// Extended version of `new` that returns intermediate values for debugging/testing.
    ///
    /// Returns: (pk_0, pk_1, sk_poly, e)
    /// - pk_0: the p0_share (public key part 0 share) = -a*s + e
    /// - pk_1: the crp_poly (common random polynomial `a`, public key part 1)
    /// - sk_poly: the secret key polynomial in NTT form
    /// - e: the error polynomial
    pub fn new_extended<R: RngCore + CryptoRng>(
        sk_share: &SecretKey,
        crp: CommonRandomPoly,
        rng: &mut R,
    ) -> Result<(Poly, Poly, Poly, Poly)> {
        let par = sk_share.par.clone();
        let ctx = par.ctx_at_level(0)?;

        // Convert secret key to usable polynomial
        let mut s = Poly::try_convert_from(
            sk_share.coeffs.as_ref(),
            ctx,
            false,
            Representation::PowerBasis,
        )?;
        s.change_representation(Representation::Ntt);

        // Sample error
        let e = Poly::small(ctx, Representation::Ntt, par.variance, rng)?;

        // Create p0_share (which is pk_0) = -a*s + e
        // where `a` is the crp (common random polynomial)
        let mut pk_0 = -crp.poly.clone();
        pk_0.disallow_variable_time_computations();
        pk_0.change_representation(Representation::Ntt);
        pk_0 *= &s;
        pk_0 += &e;
        unsafe { pk_0.allow_variable_time_computations() }

        // pk_1 is `a`, the common random polynomial (crp)
        let pk_1 = crp.poly.clone();

        Ok((pk_0, pk_1, s, e))
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

        // Ensure both are in NTT representation
        if *p0.representation() != Representation::Ntt {
            p0.change_representation(Representation::Ntt);
        }
        if *p1.representation() != Representation::Ntt {
            p1.change_representation(Representation::Ntt);
        }

        // Disable variable time computations for public key security
        p0.disallow_variable_time_computations();
        p1.disallow_variable_time_computations();

        Ok(PublicKey {
            c: Ciphertext::new(vec![p0, p1], &self.par)?,
            par: self.par.clone(),
        })
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

    #[test]
    fn test_new_extended() {
        let mut rng = thread_rng();

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
            expected.change_representation(Representation::Ntt);
            expected *= &s;
            expected += &e;
            unsafe { expected.allow_variable_time_computations() }

            assert_eq!(pk_0, expected, "pk_0 should equal -a*s + e");

            // Verify s is in NTT representation
            assert_eq!(
                *s.representation(),
                Representation::Ntt,
                "s should be in NTT form"
            );

            // Verify e is in NTT representation
            assert_eq!(
                *e.representation(),
                Representation::Ntt,
                "e should be in NTT form"
            );

            // Verify pk_0 is in NTT representation
            assert_eq!(
                *pk_0.representation(),
                Representation::Ntt,
                "pk_0 should be in NTT form"
            );
        }
    }

    #[test]
    fn test_new_extended_multiple_parties() {
        let mut rng = thread_rng();
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
            expected.change_representation(Representation::Ntt);
            expected *= s;
            expected += e;
            unsafe { expected.allow_variable_time_computations() }
            assert_eq!(*pk_0, expected, "pk_0 should equal -a*s + e for each party");
        }
    }

    #[test]
    fn test_new_extended_consistency_with_new() {
        let mut rng = thread_rng();

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
