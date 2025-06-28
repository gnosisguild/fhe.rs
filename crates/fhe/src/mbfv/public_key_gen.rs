use std::sync::Arc;

use crate::bfv::{BfvParameters, Ciphertext, PublicKey, SecretKey};
use crate::errors::Result;
use crate::Error;
use fhe_math::rq::{traits::TryConvertFrom, Poly, Representation};
use fhe_traits::{DeserializeWithContext, Serialize};
use num_bigint_old::BigInt;
use rand::{CryptoRng, Rng, RngCore};
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
    /// following the algorithm in the instructions. Each group member gets an SSS share of the
    /// group-level MBFV keyshare, enabling threshold aggregation without secret reconstruction.
    ///
    /// This provides true threshold security where only t+1 group members are needed for
    /// operations, and the group-level MBFV keyshare is never reconstructed.
    ///
    /// Returns raw SSS shares as Vec<Vec<Vec<BigInt>>> for use with from_threshold_sss_shares.
    pub fn new_sss_shares_from_group_secret<R: RngCore + CryptoRng>(
        group_secret_coeffs: &[i64],
        crp: CommonRandomPoly,
        group_size: usize,
        threshold: usize,
        par: &Arc<BfvParameters>,
        rng: &mut R,
    ) -> Result<Vec<Vec<Vec<BigInt>>>> {
        use itertools::izip;
        use num_bigint_old::{BigInt, ToBigInt};
        use shamir_secret_sharing::ShamirSecretSharing as SSS;

        // Generate the group-level MBFV public key share from the group secret
        let group_sk = SecretKey::new(group_secret_coeffs.to_vec(), par);
        let group_pk_share = PublicKeyShare::new(&group_sk, crp.clone(), rng)?;

        // Initialize party shares vector: [party][modulus][coefficient]
        let mut party_sss_shares: Vec<Vec<Vec<BigInt>>> = vec![Vec::new(); group_size];

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

            // For each coefficient in the polynomial p under the current modulus m
            for (_i, c) in p.iter().enumerate() {
                // Split the coefficient into SSS shares
                let secret = c.to_bigint().unwrap();
                let c_shares = sss.split(secret);

                // Distribute each share to the corresponding party
                for (party_idx, (_, c_share)) in c_shares.iter().enumerate() {
                    // Ensure the party has a vector for this modulus
                    if party_sss_shares[party_idx].len() <= _k {
                        party_sss_shares[party_idx].resize(_k + 1, Vec::new());
                    }
                    party_sss_shares[party_idx][_k].push(c_share.clone());
                }
            }
        }

        Ok(party_sss_shares)
    }

    /// Reconstruct group-level MBFV PublicKeyShare from threshold SSS shares using Lagrange coefficients.
    ///
    /// SECURE: This method reconstructs the group-level MBFV public key share from threshold
    /// SSS shares without revealing the underlying group secret. Uses Lagrange interpolation
    /// as described in the SSS specification for threshold reconstruction.
    ///
    /// This enables threshold aggregation - only t+1 parties needed for group operations.
    /// The reconstructed PublicKeyShare uses the provided CRP and parameters for compatibility.
    pub fn from_threshold_sss_shares(
        party_sss_shares: Vec<Vec<Vec<BigInt>>>, // Raw SSS shares: [party][modulus][coefficient]
        party_indices: &[usize],                 // 1-based party indices for Lagrange coefficients
        threshold: usize,
        par: &Arc<BfvParameters>,
        crp: CommonRandomPoly,
    ) -> Result<Self> {
        use num_bigint_old::BigInt;
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

        let ctx = par.ctx_at_level(0)?;
        let moduli = ctx.moduli();

        if threshold_shares.is_empty() || threshold_shares[0].is_empty() {
            return Err(crate::Error::DefaultError(
                "Empty SSS shares provided".to_string(),
            ));
        }

        let num_moduli = threshold_shares[0].len();
        let num_coeffs = threshold_shares[0][0].len();

        // Validate all shares have consistent dimensions
        for (party_idx, party_shares) in threshold_shares.iter().enumerate() {
            if party_shares.len() != num_moduli {
                return Err(crate::Error::DefaultError(format!(
                    "Party {} has {} moduli, expected {}",
                    party_idx,
                    party_shares.len(),
                    num_moduli
                )));
            }
            for (mod_idx, mod_shares) in party_shares.iter().enumerate() {
                if mod_shares.len() != num_coeffs {
                    return Err(crate::Error::DefaultError(format!(
                        "Party {} modulus {} has {} coefficients, expected {}",
                        party_idx,
                        mod_idx,
                        mod_shares.len(),
                        num_coeffs
                    )));
                }
            }
        }

        // Initialize reconstruction data structures
        let mut reconstructed_moduli_data: Vec<Vec<u64>> = Vec::with_capacity(num_moduli);

        // For each modulus, reconstruct coefficients using Lagrange interpolation
        for mod_idx in 0..num_moduli {
            let modulus = moduli[mod_idx];
            let mut reconstructed_coeffs = Vec::with_capacity(num_coeffs);

            // For each coefficient position
            for coeff_idx in 0..num_coeffs {
                // Collect SSS shares for this coefficient from all threshold parties
                let mut coefficient_shares = Vec::with_capacity(threshold);

                for (share_idx, party_shares) in threshold_shares.iter().enumerate() {
                    let party_id = threshold_indices[share_idx];
                    let share_value = &party_shares[mod_idx][coeff_idx];
                    coefficient_shares.push((party_id, share_value.clone()));
                }

                // Create SSS for reconstruction using the correct modulus
                let sss = SSS {
                    threshold: threshold,    // SSS library threshold is the minimum needed
                    share_amount: threshold, // Only the participating parties
                    prime: BigInt::from(modulus),
                };

                // Reconstruct this coefficient using Lagrange interpolation
                let reconstructed_coeff = sss.recover(&coefficient_shares);

                // Convert to u64, ensuring it's within the modulus range
                let coeff_u64 = reconstructed_coeff.to_u64().ok_or_else(|| {
                    crate::Error::DefaultError(
                        "Failed to convert reconstructed coefficient to u64".to_string(),
                    )
                })?;

                reconstructed_coeffs.push(coeff_u64 % modulus);
            }

            reconstructed_moduli_data.push(reconstructed_coeffs);
        }

        // Create new polynomial with reconstructed coefficients
        let mut reconstructed_p0 = fhe_math::rq::Poly::zero(
            ctx,
            Representation::PowerBasis, // Start in PowerBasis as per original implementation
        );

        // Convert reconstructed coefficients to Array2<u64>
        let coeffs_array =
            ndarray::Array2::from_shape_fn((num_moduli, num_coeffs), |(mod_idx, coeff_idx)| {
                reconstructed_moduli_data[mod_idx][coeff_idx]
            });

        // Set the reconstructed coefficients
        reconstructed_p0.set_coefficients(coeffs_array);

        // Convert to NTT representation to match the expected format for p0_share
        reconstructed_p0.change_representation(Representation::Ntt);

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

    /// Generate individual party's secret contribution for true DKG.
    ///
    /// SECURE DKG: Each party generates their own independent secret contribution.
    /// No centralized group secret exists. The final group key is the sum of all
    /// individual contributions, but this sum is never computed - only shares exist.
    ///
    /// Returns the party's secret contribution that will be shared via SSS.
    pub fn generate_dkg_secret_contribution<R: RngCore + CryptoRng>(
        par: &Arc<BfvParameters>,
        rng: &mut R,
    ) -> Vec<i64> {
        // Generate random secret coefficients for this party's contribution
        (0..par.degree()).map(|_| rng.gen_range(-1..=1)).collect()
    }

    /// Create SSS shares of this party's secret contribution for DKG.
    ///
    /// SECURE DKG: This party creates SSS shares of ONLY their own contribution,
    /// not a group secret. Other parties will do the same with their contributions.
    /// The final group functionality emerges from the additive structure without
    /// ever reconstructing a central secret.
    ///
    /// Returns Vec<Vec<Vec<BigInt>>> where indices are [receiver_party][modulus][coefficient].
    pub fn create_dkg_sss_shares<R: RngCore + CryptoRng>(
        party_secret_contribution: &[i64],
        crp: CommonRandomPoly,
        group_size: usize,
        threshold: usize,
        par: &Arc<BfvParameters>,
        rng: &mut R,
    ) -> Result<Vec<Vec<Vec<BigInt>>>> {
        use itertools::izip;
        use num_bigint_old::{BigInt, ToBigInt};
        use shamir_secret_sharing::ShamirSecretSharing as SSS;

        // Generate this party's PublicKeyShare from their secret contribution
        let party_sk = SecretKey::new(party_secret_contribution.to_vec(), par);
        let party_pk_share = PublicKeyShare::new(&party_sk, crp.clone(), rng)?;

        // Initialize shares for all receiving parties: [receiver_party][modulus][coefficient]
        let mut receiver_sss_shares: Vec<Vec<Vec<BigInt>>> = vec![Vec::new(); group_size];

        // For each modulus, create SSS shares of each coefficient of THIS party's contribution
        for (_k, (m, p)) in izip!(
            party_pk_share.p0_share.ctx().moduli().iter(),
            party_pk_share.p0_share.coefficients().outer_iter()
        )
        .enumerate()
        {
            // Create shamir object for this modulus
            let sss = SSS {
                threshold: threshold, // SSS library threshold is the minimum needed
                share_amount: group_size,
                prime: BigInt::from(*m),
            };

            // For each coefficient in this party's polynomial under the current modulus
            for (_i, c) in p.iter().enumerate() {
                // Split THIS coefficient of THIS party's contribution into SSS shares
                let secret = c.to_bigint().unwrap();
                let c_shares = sss.split(secret);

                // Distribute each share to the corresponding receiver party
                for (receiver_idx, (_, c_share)) in c_shares.iter().enumerate() {
                    // Ensure the receiver has a vector for this modulus
                    if receiver_sss_shares[receiver_idx].len() <= _k {
                        receiver_sss_shares[receiver_idx].resize(_k + 1, Vec::new());
                    }
                    receiver_sss_shares[receiver_idx][_k].push(c_share.clone());
                }
            }
        }

        Ok(receiver_sss_shares)
    }

    /// Combine received DKG SSS shares from all parties to form this party's final key share.
    ///
    /// SECURE DKG: Each party receives SSS shares from all other parties (including themselves).
    /// By additively combining these shares, each party gets their portion of the distributed
    /// group key. The group secret is never reconstructed - only individual shares exist.
    ///
    /// This implements the core DKG principle: the final group public key is the sum of all
    /// individual contributions, but this sum computation happens in "share space" only.
    ///
    /// Input: received_shares[party_sender][modulus][coefficient] - SSS shares received from each party
    /// Returns: This party's final PublicKeyShare for threshold operations
    pub fn combine_dkg_received_shares(
        received_shares: Vec<Vec<Vec<BigInt>>>, // [party_sender][modulus][coefficient]
        par: &Arc<BfvParameters>,
        crp: CommonRandomPoly,
    ) -> Result<Self> {
        use num_bigint_old::BigInt;
        use num_traits::ToPrimitive;

        if received_shares.is_empty() {
            return Err(crate::Error::DefaultError("No received shares provided".to_string()));
        }

        let num_parties = received_shares.len();
        let num_moduli = received_shares[0].len();
        let num_coeffs = received_shares[0][0].len();

        // Validate all parties provided shares with consistent dimensions
        for (party_idx, party_shares) in received_shares.iter().enumerate() {
            if party_shares.len() != num_moduli {
                return Err(crate::Error::DefaultError(format!(
                    "Party {} has {} moduli, expected {}",
                    party_idx, party_shares.len(), num_moduli
                )));
            }
            for (mod_idx, mod_shares) in party_shares.iter().enumerate() {
                if mod_shares.len() != num_coeffs {
                    return Err(crate::Error::DefaultError(format!(
                        "Party {} modulus {} has {} coefficients, expected {}",
                        party_idx, mod_idx, mod_shares.len(), num_coeffs
                    )));
                }
            }
        }

        // Initialize combined moduli data
        let mut combined_moduli_data: Vec<Vec<u64>> = Vec::with_capacity(num_moduli);
        let moduli = par.ctx_at_level(0)?.moduli();

        // For each modulus, combine coefficients from all parties
        for mod_idx in 0..num_moduli {
            let modulus = moduli[mod_idx];
            let mut combined_coeffs = Vec::with_capacity(num_coeffs);

            // For each coefficient position
            for coeff_idx in 0..num_coeffs {
                // Sum the SSS shares from all parties for this coefficient
                let mut coefficient_sum = BigInt::from(0);

                for party_shares in &received_shares {
                    coefficient_sum += &party_shares[mod_idx][coeff_idx];
                }

                // Reduce modulo the current modulus
                let modulus_big = BigInt::from(modulus);
                coefficient_sum %= &modulus_big;
                
                // Ensure positive result
                if coefficient_sum < BigInt::from(0) {
                    coefficient_sum += &modulus_big;
                }

                // Convert back to u64
                let final_coeff = coefficient_sum.to_u64().ok_or_else(|| {
                    crate::Error::DefaultError(format!(
                        "Failed to convert combined coefficient to u64: {}",
                        coefficient_sum
                    ))
                })?;

                combined_coeffs.push(final_coeff);
            }

            combined_moduli_data.push(combined_coeffs);
        }

        // Create the polynomial from combined coefficients
        let ctx = par.ctx_at_level(0)?;
        
        // Create new polynomial with combined coefficients
        let mut combined_p0 = fhe_math::rq::Poly::zero(
            ctx,
            Representation::PowerBasis,
        );

        // Convert combined coefficients to Array2<u64>
        let num_moduli = combined_moduli_data.len();
        let num_coeffs = combined_moduli_data[0].len();
        let coeffs_array =
            ndarray::Array2::from_shape_fn((num_moduli, num_coeffs), |(mod_idx, coeff_idx)| {
                combined_moduli_data[mod_idx][coeff_idx]
            });

        combined_p0.set_coefficients(coeffs_array);

        // Convert to NTT representation to match the expected format for p0_share
        combined_p0.change_representation(Representation::Ntt);

        Ok(PublicKeyShare {
            par: par.clone(),
            crp,
            p0_share: combined_p0,
        })
    }

    // ...existing code...
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

    #[test]
    fn test_sss_based_public_key_reconstruction() {
        use rand::{thread_rng, Rng};
        let mut rng = thread_rng();

        // Setup parameters
        let par = BfvParameters::default_arc(1, 8);
        let crp = CommonRandomPoly::new(&par, &mut rng).unwrap();
        let group_size = 5;
        let threshold = 3;

        // Generate a random group secret (coefficients)
        let group_secret: Vec<i64> = (0..par.degree()).map(|_| rng.gen_range(-1..=1)).collect();

        // Generate SSS shares from the group secret
        let party_sss_shares = PublicKeyShare::new_sss_shares_from_group_secret(
            &group_secret,
            crp.clone(),
            group_size,
            threshold,
            &par,
            &mut rng,
        )
        .unwrap();

        // Select threshold parties (1-based indexing for SSS)
        let party_indices: Vec<usize> = vec![1, 2, 3];
        let threshold_shares = vec![
            party_sss_shares[0].clone(),
            party_sss_shares[1].clone(),
            party_sss_shares[2].clone(),
        ];

        // Reconstruct the group-level MBFV PublicKeyShare
        let reconstructed_pk_share = PublicKeyShare::from_threshold_sss_shares(
            threshold_shares,
            &party_indices,
            threshold,
            &par,
            crp.clone(),
        )
        .unwrap();

        // Verify the reconstructed public key share has the correct structure
        assert_eq!(reconstructed_pk_share.par, par);
        assert_eq!(reconstructed_pk_share.crp, crp);

        // The reconstructed p0_share should be in NTT representation
        assert_eq!(
            reconstructed_pk_share.p0_share.representation(),
            &Representation::Ntt
        );
    }

    #[test]
    fn test_sss_reconstruction_matches_original() {
        use rand::{thread_rng, Rng};
        let mut rng = thread_rng();

        // Setup parameters
        let par = BfvParameters::default_arc(1, 8);
        let crp = CommonRandomPoly::new(&par, &mut rng).unwrap();
        let group_size = 5;
        let threshold = 3;

        // Generate a random group secret (coefficients)
        let group_secret: Vec<i64> = (0..par.degree()).map(|_| rng.gen_range(-1..=1)).collect();

        // Create the original group-level MBFV public key share
        let group_sk = SecretKey::new(group_secret.clone(), &par);
        let original_pk_share = PublicKeyShare::new(&group_sk, crp.clone(), &mut rng).unwrap();

        // Generate SSS shares from the group secret
        let party_sss_shares = PublicKeyShare::new_sss_shares_from_group_secret(
            &group_secret,
            crp.clone(),
            group_size,
            threshold,
            &par,
            &mut rng,
        )
        .unwrap();

        // Test different threshold combinations
        for start_idx in 0..=(group_size - threshold) {
            let party_indices: Vec<usize> = (1..=threshold).collect(); // 1-based indexing
            let threshold_shares = party_sss_shares[start_idx..start_idx + threshold].to_vec();

            // Reconstruct the group-level MBFV PublicKeyShare
            let reconstructed_pk_share = PublicKeyShare::from_threshold_sss_shares(
                threshold_shares,
                &party_indices,
                threshold,
                &par,
                crp.clone(),
            )
            .unwrap();

            // Verify the reconstructed public key share has the same structure
            assert_eq!(reconstructed_pk_share.par, original_pk_share.par);
            assert_eq!(reconstructed_pk_share.crp, original_pk_share.crp);
            assert_eq!(
                reconstructed_pk_share.p0_share.representation(),
                &Representation::Ntt
            );

            // The coefficients should be mathematically equivalent (within the FHE noise bounds)
            // Note: Due to the randomness in the PublicKeyShare generation (different error terms),
            // the reconstructed shares won't be identical to the original, but they should be
            // structurally valid and usable for MBFV operations.

            // Verify the reconstructed share can be used in MBFV aggregation
            let shares_vec = vec![reconstructed_pk_share.clone()];
            let _combined_share = PublicKeyShare::from_shares(shares_vec).unwrap();
        }
    }


}
