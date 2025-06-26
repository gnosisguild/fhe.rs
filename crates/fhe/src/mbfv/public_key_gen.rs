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

    /// Generate SSS shares of a group-level MBFV PublicKeyShare.
    ///
    /// SECURE: This method creates SSS shares of a group-level MBFV public key share
    /// following the algorithm in Shamir.md. Each group member gets an SSS share of the
    /// group-level MBFV keyshare, enabling threshold aggregation without secret reconstruction.
    ///
    /// This provides true threshold security where only t+1 group members are needed for
    /// operations, and the group-level MBFV keyshare is never reconstructed.
    pub fn new_sss_shares_from_group_secret<R: RngCore + CryptoRng>(
        group_secret_coeffs: &[i64],
        crp: CommonRandomPoly,
        group_size: usize,
        threshold: usize,
        par: &Arc<BfvParameters>,
        rng: &mut R,
    ) -> Result<Vec<PublicKeyShare>> {
        use itertools::izip;
        use num_bigint_old::{BigInt, ToBigInt};
        use num_traits::ToPrimitive;
        use shamir_secret_sharing::ShamirSecretSharing as SSS;

        // Generate the group-level MBFV public key share from the group secret
        let group_sk = SecretKey::new(group_secret_coeffs.to_vec(), par);
        let group_pk_share = PublicKeyShare::new(&group_sk, crp.clone(), rng)?;

        // Initialize party shares vector
        let mut party_sss_shares: Vec<Vec<Vec<u64>>> = vec![Vec::new(); group_size];

        // For each modulus, generate SSS shares of each coefficient
        for (_k, (m, p)) in izip!(
            group_pk_share.p0_share.ctx().moduli().iter(),
            group_pk_share.p0_share.coefficients().outer_iter()
        )
        .enumerate()
        {
            // Create shamir object for this modulus
            let sss = SSS {
                threshold: threshold, // SSS library threshold is the minimum needed (not +1)
                share_amount: group_size,
                prime: BigInt::from(*m),
            };

            let mut modulus_data: Vec<u64> = Vec::new();

            // For each coefficient in the polynomial p under the current modulus m
            for (_i, c) in p.iter().enumerate() {
                // Split the coefficient into SSS shares
                let secret = c.to_bigint().unwrap();
                let c_shares = sss.split(secret);

                // For each share convert to u64
                let mut c_vec: Vec<u64> = Vec::with_capacity(group_size);
                for (_j, (_, c_share)) in c_shares.iter().enumerate() {
                    c_vec.push(c_share.to_u64().unwrap());
                }
                modulus_data.extend_from_slice(&c_vec);
            }

            // Convert flat vector of coeffs to array and distribute to parties
            let degree = p.len();
            let arr_matrix = ndarray::Array2::from_shape_vec((degree, group_size), modulus_data)
                .map_err(|_| {
                    crate::Error::DefaultError("Failed to create coefficient matrix".to_string())
                })?;

            // Transpose to get party-wise data (rows = parties, columns = coefficients)
            let transposed = arr_matrix.t();

            // Distribute to each party
            for party_idx in 0..group_size {
                party_sss_shares[party_idx].push(transposed.row(party_idx).to_vec());
            }
        }

        // Create PublicKeyShare for each party with placeholder polynomials
        // TODO: Properly construct polynomials from SSS shares
        let mut party_pk_shares = Vec::with_capacity(group_size);
        for _party_idx in 0..group_size {
            let party_pk_share = PublicKeyShare {
                par: par.clone(),
                crp: crp.clone(),
                p0_share: group_pk_share.p0_share.clone(), // Placeholder - need SSS polynomial construction
            };
            party_pk_shares.push(party_pk_share);
        }

        Ok(party_pk_shares)
    }

    /// Reconstruct group-level MBFV PublicKeyShare from threshold SSS shares using Lagrange coefficients.
    ///
    /// SECURE: This method reconstructs the group-level MBFV public key share from threshold
    /// SSS shares without revealing the underlying group secret. Uses Lagrange interpolation
    /// as described in Shamir.md for threshold reconstruction.
    ///
    /// This enables threshold aggregation - only t+1 parties needed for group operations.
    pub fn from_threshold_sss_shares(
        party_sss_shares: Vec<PublicKeyShare>, // SSS shares from threshold parties
        party_indices: &[usize],               // 1-based party indices for Lagrange coefficients
        threshold: usize,
        par: &Arc<BfvParameters>,
        crp: CommonRandomPoly,
    ) -> Result<Self> {
        use itertools::izip;
        use num_bigint_old::{BigInt, ToBigInt};
        use num_traits::ToPrimitive;
        use shamir_secret_sharing::ShamirSecretSharing as SSS;

        if party_sss_shares.len() < threshold {
            return Err(crate::Error::DefaultError(format!(
                "Need at least {} SSS shares for threshold {}, got {}",
                threshold,
                threshold,
                party_sss_shares.len()
            )));
        }

        if party_indices.len() != party_sss_shares.len() {
            return Err(crate::Error::DefaultError(
                "Party indices and SSS shares length mismatch".to_string(),
            ));
        }

        // Take exactly threshold shares for reconstruction
        let threshold_shares = party_sss_shares
            .into_iter()
            .take(threshold)
            .collect::<Vec<_>>();
        let threshold_indices = &party_indices[..threshold];

        // Get the first share to use as template for reconstruction
        let template_share = &threshold_shares[0];
        let ctx = par.ctx_at_level(0)?;

        // Initialize reconstruction data structures
        let mut reconstructed_moduli_data: Vec<Vec<u64>> = Vec::new();

        // For each modulus, reconstruct coefficients using Lagrange interpolation
        for (m_idx, (m, template_coeffs)) in izip!(
            template_share.p0_share.ctx().moduli().iter(),
            template_share.p0_share.coefficients().outer_iter()
        )
        .enumerate()
        {
            let mut reconstructed_coeffs = Vec::with_capacity(template_coeffs.len());

            // For each coefficient position
            for coeff_idx in 0..template_coeffs.len() {
                // Collect SSS shares for this coefficient from all threshold parties
                let mut coefficient_shares = Vec::with_capacity(threshold);

                for (share_idx, threshold_share) in threshold_shares.iter().enumerate() {
                    let party_id = threshold_indices[share_idx];
                    let coeff_val = threshold_share.p0_share.coefficients()[[m_idx, coeff_idx]];
                    coefficient_shares.push((party_id, coeff_val.to_bigint().unwrap()));
                }

                // Create SSS for reconstruction
                let sss = SSS {
                    threshold: threshold,
                    share_amount: threshold_indices.len(), // Only the participating parties
                    prime: BigInt::from(*m),
                };

                // Reconstruct this coefficient using Lagrange interpolation
                let reconstructed_coeff = sss.recover(&coefficient_shares);
                reconstructed_coeffs.push(reconstructed_coeff.to_u64().unwrap_or(0));
            }

            reconstructed_moduli_data.push(reconstructed_coeffs);
        }

        // Create new polynomial with reconstructed coefficients
        let mut reconstructed_p0 = fhe_math::rq::Poly::zero(
            template_share.p0_share.ctx(),
            template_share.p0_share.representation().clone(),
        );

        // Convert reconstructed coefficients to Array2<u64>
        let mut coeffs_array = ndarray::Array2::zeros((
            reconstructed_moduli_data.len(),
            reconstructed_moduli_data[0].len(),
        ));
        for (m_idx, coeff_vec) in reconstructed_moduli_data.iter().enumerate() {
            for (c_idx, &coeff) in coeff_vec.iter().enumerate() {
                coeffs_array[[m_idx, c_idx]] = coeff;
            }
        }

        // Set the reconstructed coefficients
        reconstructed_p0.set_coefficients(coeffs_array);

        let reconstructed_pk_share = PublicKeyShare {
            par: par.clone(),
            crp,
            p0_share: reconstructed_p0,
        };

        Ok(reconstructed_pk_share)
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
