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
pub struct SecretKeySwitchShare {
    pub(crate) par: Arc<BfvParameters>,
    /// The original input ciphertext
    // Probably doesn't need to be Arc in real usage but w/e
    pub(crate) ct: Arc<Ciphertext>,
    pub(crate) h_share: Poly,
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
pub struct DecryptionShare {
    pub(crate) sks_share: SecretKeySwitchShare,
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

    /// Generate an MBFV DecryptionShare from collected SSS shares of other parties' secrets.
    /// 
    /// This method allows a party to generate their MBFV decryption share using SSS shares
    /// they've collected from other parties. Each party can reconstruct a threshold subset
    /// of other parties' individual secrets (not a group master secret) to create their
    /// own contribution to the final aggregated decryption.
    /// 
    /// This is the SSS-enabled equivalent of `DecryptionShare::new()` for threshold scenarios.
    pub fn new_from_sss_shares<R: RngCore + CryptoRng>(
        collected_sk_sss_shares: &[Vec<ndarray::Array2<u64>>],  // collected_sk_sss_shares[party_idx][modulus_idx] = shares from party_idx
        threshold: usize,
        party_ids: &[usize],  // 1-based party IDs to use for reconstruction (must have >= threshold elements)
        par: Arc<BfvParameters>,
        ct: &Arc<Ciphertext>,
        rng: &mut R,
    ) -> Result<Self> {
        use shamir_secret_sharing::ShamirSecretSharing as SSS;
        use num_bigint_old::{BigInt, ToBigInt};
        use num_traits::ToPrimitive;
        
        if party_ids.len() < threshold {
            return Err(crate::Error::DefaultError(
                format!("Need at least {} party IDs for threshold {}, got {}", threshold, threshold, party_ids.len())
            ));
        }
        
        // Reconstruct individual secrets from the first `threshold` parties and sum them
        // This follows the MBFV model where each party's secret contributes additively
        let mut combined_secret_coeffs = vec![0i64; par.degree()];
        
        for &party_id in party_ids.iter().take(threshold) {
            let party_idx = party_id - 1; // Convert to 0-based index
            
            if party_idx >= collected_sk_sss_shares.len() {
                return Err(crate::Error::DefaultError(
                    format!("Party ID {} out of range", party_id)
                ));
            }
            
            let party_shares = &collected_sk_sss_shares[party_idx];
            
            // Reconstruct this party's secret using SSS interpolation
            let mut party_secret_coeffs = Vec::with_capacity(par.degree());
            
            for coeff_idx in 0..par.degree() {
                // For each modulus, reconstruct the coefficient using SSS
                for (modulus_idx, modulus) in par.moduli.iter().enumerate() {
                    let sss = SSS {
                        threshold,
                        share_amount: party_ids.len(), 
                        prime: BigInt::from(*modulus),
                    };
                    
                    // Collect shares for this coefficient from different parties
                    let mut coefficient_shares: Vec<(usize, BigInt)> = Vec::new();
                    for (share_idx, &share_party_id) in party_ids.iter().enumerate() {
                        if share_idx >= threshold { break; } // Only need threshold shares
                        
                        let share_party_idx = share_party_id - 1;
                        if share_party_idx < collected_sk_sss_shares.len() && modulus_idx < party_shares.len() {
                            let share_array = &collected_sk_sss_shares[share_party_idx][modulus_idx];
                            if party_idx < share_array.dim().0 && coeff_idx < share_array.dim().1 {
                                let share_value = share_array[[party_idx, coeff_idx]];
                                coefficient_shares.push((share_party_id, share_value.to_bigint().unwrap()));
                            }
                        }
                    }
                    
                    if coefficient_shares.len() >= threshold {
                        let reconstructed = sss.recover(&coefficient_shares[0..threshold]);
                        // Use first modulus for the coefficient (assuming single modulus for now)
                        if modulus_idx == 0 {
                            party_secret_coeffs.push(reconstructed.to_i64().unwrap_or(0));
                        }
                    }
                }
            }
            
            // Add this party's reconstructed secret to the combined secret (MBFV additive model)
            for (i, &coeff) in party_secret_coeffs.iter().enumerate() {
                if i < combined_secret_coeffs.len() {
                    combined_secret_coeffs[i] = combined_secret_coeffs[i].wrapping_add(coeff);
                }
            }
        }
        
        // Create a SecretKey from the combined coefficients
        let combined_sk = crate::bfv::SecretKey::new(combined_secret_coeffs, &par);
        
        // Use the standard DecryptionShare::new method with the combined secret
        Self::new(&combined_sk, ct, rng)
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
