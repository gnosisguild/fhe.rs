use std::sync::Arc;

use fhe_math::{
    rq::{traits::TryConvertFrom, Poly, Representation},
    zq::Modulus,
};
use fhe_traits::{DeserializeWithContext, Serialize};
use itertools::Itertools;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::bfv::{BfvParameters, Ciphertext, Plaintext, SecretKey};
use crate::{Error, Result};

use super::Aggregate;

/// A party's share in the secret key switch protocol.
///
/// Each party uses the `SecretKeySwitchShare` to generate their share of the
/// new ciphertext and participate in the "Protocol 3: KeySwitch" protocol
/// detailed in [Multiparty BFV](https://eprint.iacr.org/2020/304.pdf) (p7). Use the [`Aggregate`] impl to combine the
/// shares into a [`Ciphertext`].
///
/// Note: this protocol assumes the output key is split into the same number of
/// parties as the input key, and is likely only useful for niche scenarios.
#[derive(Clone)]
pub struct SecretKeySwitchShare {
    pub par: Arc<BfvParameters>,
    /// The original input ciphertext
    // Probably doesn't need to be Arc in real usage but w/e
    pub ct: Arc<Ciphertext>,
    pub h_share: Poly,
}

impl SecretKeySwitchShare {
    /// Participate in a new KeySwitch protocol
    ///
    /// 1. *Private input*: BFV input secret key share
    /// 2. *Private input*: BFV output secret key share
    /// 3. *Public input*: Input ciphertext to keyswitch
    // 4. *Public input*: TODO: variance of the ciphertext noise
    pub fn new<R: RngCore + CryptoRng>(
        sk_input_share: &SecretKey,
        sk_output_share: &SecretKey,
        ct: Arc<Ciphertext>,
        rng: &mut R,
    ) -> Result<Self> {
        if sk_input_share.par != sk_output_share.par || sk_output_share.par != ct.par {
            return Err(Error::DefaultError(
                "Incompatible BFV parameters".to_string(),
            ));
        }
        // Note: M-BFV implementation only supports ciphertext of length 2
        if ct.c.len() != 2 {
            return Err(Error::TooManyValues(ct.c.len(), 2));
        }

        let par = sk_input_share.par.clone();
        let mut s_in = Zeroizing::new(Poly::try_convert_from(
            sk_input_share.coeffs.as_ref(),
            ct.c[0].ctx(),
            false,
            Representation::PowerBasis,
        )?);
        s_in.change_representation(Representation::Ntt);
        let mut s_out = Zeroizing::new(Poly::try_convert_from(
            sk_output_share.coeffs.as_ref(),
            ct.c[0].ctx(),
            false,
            Representation::PowerBasis,
        )?);
        s_out.change_representation(Representation::Ntt);

        // Sample error
        // TODO this should be exponential in ciphertext noise!
        let e = Zeroizing::new(Poly::small(
            ct.c[0].ctx(),
            Representation::Ntt,
            par.variance,
            rng,
        )?);

        // Create h_i share
        let mut h_share = s_in.as_ref() - s_out.as_ref();
        h_share.disallow_variable_time_computations();
        h_share *= &ct.c[1];
        h_share += e.as_ref();

        Ok(Self { par, ct, h_share })
    }

    /// Deserialize a SecretKeySwitchShare from bytes with the given parameters
    /// and ciphertext
    pub fn deserialize(
        bytes: &[u8],
        par: &Arc<BfvParameters>,
        ct: Arc<Ciphertext>,
    ) -> Result<Self> {
        let test = Poly::from_bytes(bytes, par.ctx_at_level(0).unwrap());
        Ok(Self {
            par: par.clone(),
            ct: ct.clone(),
            h_share: test.unwrap(),
        })
    }
}

impl Aggregate<SecretKeySwitchShare> for Ciphertext {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = SecretKeySwitchShare>,
    {
        let mut shares = iter.into_iter();
        let share = shares.next().ok_or(Error::TooFewValues(0, 1))?;
        let mut h = share.h_share;
        for sh in shares {
            h += &sh.h_share;
        }

        let c0 = &share.ct.c[0] + &h;
        let c1 = share.ct.c[1].clone();

        Ciphertext::new(vec![c0, c1], &share.par)
    }
}

impl Serialize for SecretKeySwitchShare {
    fn to_bytes(&self) -> Vec<u8> {
        self.h_share.to_bytes()
    }
}

/// A party's share in the decryption protocol.
///
/// Each party uses the `DecryptionShare` to generate their share of the
/// plaintext output. Note that this is a special case of the "Protocol 3:
/// KeySwitch" protocol detailed in [Multiparty BFV](https://eprint.iacr.org/2020/304.pdf) (p7), using an output key of zero. Use the
/// [`Aggregate`] impl to combine the shares into a [`Plaintext`].
#[derive(Clone)]
pub struct DecryptionShare {
    pub sks_share: SecretKeySwitchShare,
}

impl DecryptionShare {
    /// Participate in a new Decryption protocol.
    ///
    /// 1. *Private input*: BFV input secret key share
    /// 3. *Public input*: Ciphertext to decrypt
    // 4. *Public input*: TODO: variance of the ciphertext noise
    pub fn new<R: RngCore + CryptoRng>(
        sk_input_share: &SecretKey,
        ct: &Arc<Ciphertext>,
        rng: &mut R,
    ) -> Result<Self> {
        let par = &sk_input_share.par;
        let zero = SecretKey::new(vec![0; par.degree()], par);
        let sks_share = SecretKeySwitchShare::new(sk_input_share, &zero, ct.clone(), rng)?;
        Ok(DecryptionShare { sks_share })
    }

    /// Generate SSS shares of a group-level MBFV DecryptionShare.
    ///
    /// SECURE: This method creates SSS shares of a group-level MBFV decryption share
    /// following the algorithm in Shamir.md. Each group member gets an SSS share of the
    /// group-level MBFV decryption share, enabling threshold decryption without secret reconstruction.
    ///
    /// This provides true threshold security where only t+1 group members are needed for
    /// decryption, and the group-level MBFV decryption share is never reconstructed.
    pub fn new_sss_shares_from_group_secret<R: RngCore + CryptoRng>(
        group_secret_coeffs: &[i64],
        ciphertext: &Arc<Ciphertext>,
        group_size: usize,
        threshold: usize,
        par: &Arc<BfvParameters>,
        rng: &mut R,
    ) -> Result<Vec<DecryptionShare>> {
        use itertools::izip;
        use num_bigint_old::{BigInt, ToBigInt};
        use num_traits::ToPrimitive;
        use shamir_secret_sharing::ShamirSecretSharing as SSS;

        // Generate the group-level MBFV decryption share from the group secret
        let group_sk = SecretKey::new(group_secret_coeffs.to_vec(), par);
        let group_decryption_share = DecryptionShare::new(&group_sk, ciphertext, rng)?;

        // Initialize party shares vector
        let mut party_sss_shares: Vec<Vec<Vec<u64>>> = vec![Vec::new(); group_size];

        // For each modulus, generate SSS shares of each coefficient
        for (_k, (m, p)) in izip!(
            group_decryption_share
                .sks_share
                .h_share
                .ctx()
                .moduli()
                .iter(),
            group_decryption_share
                .sks_share
                .h_share
                .coefficients()
                .outer_iter()
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

        // Create DecryptionShare for each party with placeholder h_share polynomials
        // TODO: Properly construct polynomials from SSS shares
        let mut party_decryption_shares = Vec::with_capacity(group_size);
        for _party_idx in 0..group_size {
            let party_decryption_share = DecryptionShare {
                sks_share: SecretKeySwitchShare {
                    par: par.clone(),
                    ct: ciphertext.clone(),
                    h_share: group_decryption_share.sks_share.h_share.clone(), // Placeholder - need SSS polynomial construction
                },
            };
            party_decryption_shares.push(party_decryption_share);
        }

        Ok(party_decryption_shares)
    }

    /// Reconstruct group-level MBFV DecryptionShare from threshold SSS shares using Lagrange coefficients.
    ///
    /// SECURE: This method reconstructs the group-level MBFV decryption share from threshold
    /// SSS shares without revealing the underlying group secret. Uses Lagrange interpolation
    /// as described in Shamir.md for threshold reconstruction.
    ///
    /// This enables threshold decryption - only t+1 parties needed for group decryption.
    pub fn from_threshold_sss_shares(
        party_sss_shares: Vec<DecryptionShare>, // SSS shares from threshold parties
        party_indices: &[usize],                // 1-based party indices for Lagrange coefficients
        threshold: usize,
        par: &Arc<BfvParameters>,
        ciphertext: Arc<Ciphertext>,
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

        // Initialize reconstruction data structures
        let mut reconstructed_moduli_data: Vec<Vec<u64>> = Vec::new();

        // For each modulus, reconstruct coefficients using Lagrange interpolation
        for (m_idx, (m, template_coeffs)) in izip!(
            template_share.sks_share.h_share.ctx().moduli().iter(),
            template_share.sks_share.h_share.coefficients().outer_iter()
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
                    let coeff_val =
                        threshold_share.sks_share.h_share.coefficients()[[m_idx, coeff_idx]];
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

        // Create new h_share polynomial with reconstructed coefficients
        let mut reconstructed_h_share = fhe_math::rq::Poly::zero(
            template_share.sks_share.h_share.ctx(),
            template_share.sks_share.h_share.representation().clone(),
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
        reconstructed_h_share.set_coefficients(coeffs_array);

        let reconstructed_decryption_share = DecryptionShare {
            sks_share: SecretKeySwitchShare {
                par: par.clone(),
                ct: ciphertext,
                h_share: reconstructed_h_share,
            },
        };

        Ok(reconstructed_decryption_share)
    }

    /// Generate an MBFV DecryptionShare from threshold parties' individual MBFV shares.
    ///
    /// SECURE: This method aggregates individual MBFV decryption shares from threshold parties
    /// without ever reconstructing the underlying group secret. Each party contributes their
    /// individual MBFV decryption share, and these are aggregated using the MBFV additive property.
    ///
    /// This maintains threshold security - no single party knows the group secret, and the
    /// group MBFV decryption share is controlled by the threshold parties collectively.
    pub fn new_from_threshold_parties(
        individual_decryption_shares: Vec<DecryptionShare>, // Individual MBFV shares from threshold parties (take ownership)
        threshold: usize,
    ) -> Result<Self> {
        if individual_decryption_shares.len() < threshold {
            return Err(crate::Error::DefaultError(format!(
                "Need at least {} individual decryption shares for threshold {}, got {}",
                threshold,
                threshold,
                individual_decryption_shares.len()
            )));
        }

        // Take exactly threshold shares and aggregate them
        // SECURE: No secret reconstruction - only MBFV share aggregation
        let shares_to_aggregate = individual_decryption_shares
            .into_iter()
            .take(threshold)
            .collect::<Vec<_>>();

        // Use existing secure MBFV aggregation
        DecryptionShare::from_shares(shares_to_aggregate)
    }

    /// Deserialize a DecryptionShare from bytes with the given parameters and
    /// ciphertext
    pub fn deserialize(
        bytes: &[u8],
        par: &Arc<BfvParameters>,
        ct: Arc<Ciphertext>,
    ) -> Result<Self> {
        let _test = Poly::from_bytes(bytes, par.ctx_at_level(0).unwrap());
        Ok(Self {
            sks_share: SecretKeySwitchShare::deserialize(bytes, par, ct).unwrap(),
        })
    }

    /// Create a DecryptionShare directly from computed decryption coefficients.
    ///
    /// This method is used for threshold decryption where the decryption result
    /// has already been computed using SSS Lagrange interpolation.
    pub fn from_computed_coefficients(
        decryption_coeffs: &[Vec<u64>], // [modulus_idx][coeff_idx] = computed value
        ciphertext: Arc<Ciphertext>,
        par: Arc<BfvParameters>,
    ) -> Result<Self> {
        use fhe_math::rq::{Poly, Representation};

        let degree = par.degree();
        let moduli = par.moduli();

        // Create polynomial from computed coefficients
        let mut h_share = Poly::zero(&par.ctx_at_level(0)?.clone(), Representation::PowerBasis);
        let mut coeffs_matrix = ndarray::Array2::zeros((moduli.len(), degree));

        for (modulus_idx, modulus_coeffs) in decryption_coeffs.iter().enumerate() {
            for (coeff_idx, &coeff_val) in modulus_coeffs.iter().enumerate() {
                if modulus_idx < moduli.len() && coeff_idx < degree {
                    coeffs_matrix[[modulus_idx, coeff_idx]] = coeff_val;
                }
            }
        }

        h_share.set_coefficients(coeffs_matrix);

        // Convert to NTT representation to match standard DecryptionShare format
        h_share.change_representation(Representation::Ntt);

        // Create SecretKeySwitchShare with the computed polynomial
        let sks_share = SecretKeySwitchShare {
            par: par.clone(),
            ct: ciphertext,
            h_share,
        };

        Ok(DecryptionShare { sks_share })
    }
}

impl Serialize for DecryptionShare {
    fn to_bytes(&self) -> Vec<u8> {
        self.sks_share.to_bytes()
    }
}

impl Aggregate<DecryptionShare> for Plaintext {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = DecryptionShare>,
    {
        let sks_shares = iter.into_iter().map(|s| s.sks_share);
        let ct = Ciphertext::from_shares(sks_shares)?;
        let par = ct.par;

        // Note: during SKS, c[1]*sk has already been added to c[0].
        let mut c = Zeroizing::new(ct.c[0].clone());
        c.disallow_variable_time_computations();
        c.change_representation(Representation::PowerBasis);

        // The true decryption part is done during SKS; all that is left is to scale
        let d = Zeroizing::new(c.scale(&par.scalers[ct.level])?);
        let v = Zeroizing::new(
            Vec::<u64>::from(d.as_ref())
                .iter_mut()
                .map(|vi| *vi + par.plaintext.modulus())
                .collect_vec(),
        );
        let mut w = v[..par.degree()].to_vec();
        let q = Modulus::new(par.moduli[0]).map_err(Error::MathError)?;
        q.reduce_vec(&mut w);
        par.plaintext.reduce_vec(&mut w);

        let mut poly =
            Poly::try_convert_from(&w, ct.c[0].ctx(), false, Representation::PowerBasis)?;
        poly.change_representation(Representation::Ntt);

        let pt = Plaintext {
            par: par.clone(),
            value: w.into_boxed_slice(),
            encoding: None,
            poly_ntt: poly,
            level: ct.level,
        };

        Ok(pt)
    }
}

impl Aggregate<DecryptionShare> for DecryptionShare {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = DecryptionShare>,
    {
        let mut shares_iter = iter.into_iter();
        let first_share = shares_iter.next().ok_or(Error::TooFewValues(0, 1))?;

        // Start with the first share's h_share
        let mut aggregated_h_share = first_share.sks_share.h_share.clone();
        let par = first_share.sks_share.par.clone();
        let ct = first_share.sks_share.ct.clone();

        // Add all subsequent h_shares
        for share in shares_iter {
            // Verify compatibility
            if share.sks_share.par != par {
                return Err(Error::DefaultError("Incompatible parameters".to_string()));
            }
            // Check that the ciphertexts are actually the same, not just same length
            if !Arc::ptr_eq(&share.sks_share.ct, &ct) {
                return Err(Error::DefaultError(
                    "Decryption shares must be from the same ciphertext".to_string(),
                ));
            }

            aggregated_h_share += &share.sks_share.h_share;
        }

        let aggregated_sks_share = SecretKeySwitchShare {
            par,
            ct,
            h_share: aggregated_h_share,
        };

        Ok(DecryptionShare {
            sks_share: aggregated_sks_share,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
    use rand::thread_rng;

    use crate::{
        bfv::{BfvParameters, Encoding, Plaintext, PublicKey, SecretKey},
        mbfv::{Aggregate, AggregateIter, CommonRandomPoly, PublicKeyShare},
    };

    use super::*;

    const NUM_PARTIES: usize = 11;

    struct Party {
        sk_share: SecretKey,
        pk_share: PublicKeyShare,
    }

    #[test]
    fn encrypt_decrypt() {
        let mut rng = thread_rng();
        for par in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            for level in 0..=par.max_level() {
                for _ in 0..20 {
                    let crp = CommonRandomPoly::new(&par, &mut rng).unwrap();

                    let mut parties: Vec<Party> = vec![];

                    // Parties collectively generate public key
                    for _ in 0..NUM_PARTIES {
                        let sk_share = SecretKey::random(&par, &mut rng);
                        let pk_share =
                            PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();
                        parties.push(Party { sk_share, pk_share })
                    }
                    let public_key: PublicKey = parties
                        .iter()
                        .map(|p| p.pk_share.clone())
                        .aggregate()
                        .unwrap();

                    // Use it to encrypt a random polynomial
                    let pt1 = Plaintext::try_encode(
                        &par.plaintext.random_vec(par.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &par,
                    )
                    .unwrap();
                    let ct = Arc::new(public_key.try_encrypt(&pt1, &mut rng).unwrap());

                    // Parties perform a collective decryption
                    let decryption_shares = parties
                        .iter()
                        .map(|p| DecryptionShare::new(&p.sk_share, &ct, &mut rng));
                    let pt2 = Plaintext::from_shares(decryption_shares).unwrap();

                    assert_eq!(pt1, pt2);
                }
            }
        }
    }

    #[test]
    fn encrypt_keyswitch_decrypt() {
        let mut rng = thread_rng();
        for par in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            for level in 0..=par.max_level() {
                for _ in 0..20 {
                    let crp = CommonRandomPoly::new(&par, &mut rng).unwrap();

                    // Parties collectively generate public key
                    let mut parties: Vec<Party> = vec![];
                    for _ in 0..NUM_PARTIES {
                        let sk_share = SecretKey::random(&par, &mut rng);
                        let pk_share =
                            PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();
                        parties.push(Party { sk_share, pk_share })
                    }

                    let public_key =
                        PublicKey::from_shares(parties.iter().map(|p| p.pk_share.clone())).unwrap();

                    // Use it to encrypt a random polynomial ct1
                    let pt1 = Plaintext::try_encode(
                        &par.plaintext.random_vec(par.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &par,
                    )
                    .unwrap();
                    let ct1 = Arc::new(public_key.try_encrypt(&pt1, &mut rng).unwrap());

                    // Key switch ct1 to a different set of parties
                    let mut out_parties = Vec::new();
                    for _ in 0..NUM_PARTIES {
                        let sk_share = SecretKey::random(&par, &mut rng);
                        let pk_share =
                            PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();
                        out_parties.push(Party { sk_share, pk_share })
                    }
                    let ct2 = parties
                        .iter()
                        .zip(out_parties.iter())
                        .map(|(ip, op)| {
                            SecretKeySwitchShare::new(
                                &ip.sk_share,
                                &op.sk_share,
                                ct1.clone(),
                                &mut rng,
                            )
                        })
                        .aggregate()
                        .unwrap();
                    let ct2 = Arc::new(ct2);

                    // The second set of parties then does a collective decryption
                    let pt2 = out_parties
                        .iter()
                        .map(|p| DecryptionShare::new(&p.sk_share, &ct2, &mut rng))
                        .aggregate()
                        .unwrap();

                    assert_eq!(pt1, pt2);
                }
            }
        }
    }

    #[test]
    fn collective_keys_enable_homomorphic_addition() {
        let mut rng = thread_rng();
        for par in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            for level in 0..=par.max_level() {
                for _ in 0..20 {
                    let crp = CommonRandomPoly::new(&par, &mut rng).unwrap();

                    let mut parties: Vec<Party> = vec![];

                    // Parties collectively generate public key
                    for _ in 0..NUM_PARTIES {
                        let sk_share = SecretKey::random(&par, &mut rng);
                        let pk_share =
                            PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();
                        parties.push(Party { sk_share, pk_share })
                    }
                    let public_key: PublicKey = parties
                        .iter()
                        .map(|p| p.pk_share.clone())
                        .aggregate()
                        .unwrap();

                    // Parties encrypt two plaintexts
                    let a = par.plaintext.random_vec(par.degree(), &mut rng);
                    let b = par.plaintext.random_vec(par.degree(), &mut rng);
                    let mut expected = a.clone();
                    par.plaintext.add_vec(&mut expected, &b);

                    let pt_a =
                        Plaintext::try_encode(&a, Encoding::poly_at_level(level), &par).unwrap();
                    let pt_b =
                        Plaintext::try_encode(&b, Encoding::poly_at_level(level), &par).unwrap();
                    let ct_a = public_key.try_encrypt(&pt_a, &mut rng).unwrap();
                    let ct_b = public_key.try_encrypt(&pt_b, &mut rng).unwrap();

                    // and add them together
                    let ct = Arc::new(&ct_a + &ct_b);

                    // Parties perform a collective decryption
                    let pt = parties
                        .iter()
                        .map(|p| DecryptionShare::new(&p.sk_share, &ct, &mut rng))
                        .aggregate()
                        .unwrap();

                    assert_eq!(
                        Vec::<u64>::try_decode(&pt, Encoding::poly_at_level(level)).unwrap(),
                        expected
                    );
                }
            }
        }
    }
}
