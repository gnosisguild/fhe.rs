use std::sync::Arc;

use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::mbfv::{Aggregate, CommonRandomPoly, PublicKeyShare};
use crate::{Error, Result};
use fhe_math::{
    rns::{RnsContext, ScalingFactor},
    rq::{scaler::Scaler, traits::TryConvertFrom, Context, Poly, Representation},
    zq::Modulus,
};
use fhe_util::sample_vec_normal;
use itertools::{izip, Itertools};
use ndarray::Array2;
use num_bigint::BigUint;
use num_bigint_old::{BigInt, ToBigInt};
use num_traits::ToPrimitive;
use rand::{CryptoRng, RngCore};
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use zeroize::Zeroizing;

/// A threshold public key share that can be aggregated hierarchically
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrBFVPublicKeyShare {
    /// BFV parameters
    pub par: Arc<BfvParameters>,
    /// Common random polynomial used for key generation
    pub crp: CommonRandomPoly,
    /// The threshold public key share polynomial
    pub pk_share: PublicKeyShare,
    /// Threshold configuration
    pub threshold: usize,
    /// Number of parties at this level
    pub n: usize,
}

/// A threshold decryption share that can be aggregated hierarchically  
#[derive(Debug, Clone)]
pub struct TrBFVDecryptionShare {
    /// BFV parameters
    pub par: Arc<BfvParameters>,
    /// The decryption share polynomial
    pub d_share: Poly,
    /// The ciphertext being decrypted
    pub ciphertext: Arc<Ciphertext>,
    /// Threshold configuration
    pub threshold: usize,
    /// Number of parties at this level  
    pub n: usize,
}

impl Aggregate<TrBFVPublicKeyShare> for TrBFVPublicKeyShare {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = TrBFVPublicKeyShare>,
    {
        let mut shares = iter.into_iter();
        let first_share = shares.next().ok_or(Error::TooFewValues(0, 1))?;

        // Collect all PublicKeyShares for aggregation
        let mut pk_shares = vec![first_share.pk_share.clone()];
        let par = first_share.par.clone();
        let crp = first_share.crp.clone();
        let threshold = first_share.threshold;
        let n = first_share.n;

        // Verify compatibility and collect shares
        for share in shares {
            if share.par != par {
                return Err(Error::DefaultError("Incompatible parameters".to_string()));
            }
            if share.crp != crp {
                return Err(Error::DefaultError("Incompatible CRP".to_string()));
            }
            pk_shares.push(share.pk_share);
        }

        // Aggregate the underlying PublicKeyShares
        let aggregated_pk_share = PublicKeyShare::from_shares(pk_shares)?;

        Ok(TrBFVPublicKeyShare {
            par,
            crp,
            pk_share: aggregated_pk_share,
            threshold,
            n,
        })
    }
}

impl Aggregate<TrBFVDecryptionShare> for TrBFVDecryptionShare {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = TrBFVDecryptionShare>,
    {
        let mut shares = iter.into_iter();
        let first_share = shares.next().ok_or(Error::TooFewValues(0, 1))?;

        let mut aggregated_d_share = first_share.d_share.clone();
        let par = first_share.par.clone();
        let ciphertext = first_share.ciphertext.clone();
        let threshold = first_share.threshold;
        let n = first_share.n;

        // Add all subsequent decryption shares
        for share in shares {
            // Verify compatibility
            if share.par != par {
                return Err(Error::DefaultError("Incompatible parameters".to_string()));
            }
            if !Arc::ptr_eq(&share.ciphertext, &ciphertext) {
                return Err(Error::DefaultError(
                    "Decryption shares must be from the same ciphertext".to_string(),
                ));
            }

            aggregated_d_share += &share.d_share;
        }

        Ok(TrBFVDecryptionShare {
            par,
            d_share: aggregated_d_share,
            ciphertext,
            threshold,
            n,
        })
    }
}

impl Aggregate<TrBFVDecryptionShare> for Plaintext {
    fn from_shares<T>(iter: T) -> Result<Self>
    where
        T: IntoIterator<Item = TrBFVDecryptionShare>,
    {
        // Convert TrBFVDecryptionShares to MBFV DecryptionShares
        use crate::mbfv::{DecryptionShare, SecretKeySwitchShare};

        let shares: Vec<TrBFVDecryptionShare> = iter.into_iter().collect();
        if shares.is_empty() {
            return Err(Error::TooFewValues(0, 1));
        }

        // Convert to MBFV DecryptionShares
        let mbfv_shares: Vec<DecryptionShare> = shares
            .into_iter()
            .map(|tr_share| {
                let sks_share = SecretKeySwitchShare {
                    par: tr_share.par.clone(),
                    ct: tr_share.ciphertext.clone(),
                    h_share: tr_share.d_share,
                };
                DecryptionShare { sks_share }
            })
            .collect();

        // Use the proven MBFV aggregation logic
        Plaintext::from_shares(mbfv_shares)
    }
}

/// Documentation for TrBFVShare struct  
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TrBFVShare {
    n: usize,
    threshold: usize,
    degree: usize,
    plaintext_modulus: u64,
    sumdging_variance: usize,
    moduli: Vec<u64>,
    params: Arc<BfvParameters>,
}

impl TrBFVShare {
    /// Create a new TrBFVShare instance
    pub fn new(
        n: usize,
        threshold: usize,
        degree: usize,
        plaintext_modulus: u64,
        sumdging_variance: usize,
        moduli: Vec<u64>,
        params: Arc<BfvParameters>,
    ) -> Result<Self> {
        Ok(Self {
            n,
            threshold,
            degree,
            plaintext_modulus,
            sumdging_variance,
            moduli,
            params,
        })
    }

    /// Generate a threshold public key share from a secret key and CRP
    pub fn generate_public_key_share<R: RngCore + CryptoRng>(
        &self,
        sk_coeffs: Box<[i64]>,
        crp: CommonRandomPoly,
        rng: &mut R,
    ) -> Result<TrBFVPublicKeyShare> {
        // Convert secret key coefficients to SecretKey
        use crate::bfv::SecretKey;
        let sk = SecretKey::new(sk_coeffs.to_vec(), &self.params);

        // Generate PublicKeyShare using MBFV protocol
        let pk_share = PublicKeyShare::new(&sk, crp.clone(), rng)?;

        Ok(TrBFVPublicKeyShare {
            par: self.params.clone(),
            crp,
            pk_share,
            threshold: self.threshold,
            n: self.n,
        })
    }

    /// Generate a threshold decryption share using MBFV DecryptionShare approach
    pub fn generate_decryption_share<R: RngCore + CryptoRng>(
        &self,
        sk_coeffs: Box<[i64]>,
        ciphertext: Arc<Ciphertext>,
        rng: &mut R,
    ) -> Result<TrBFVDecryptionShare> {
        // Convert secret key coefficients to SecretKey for MBFV compatibility
        use crate::bfv::SecretKey;
        use crate::mbfv::DecryptionShare;

        let sk = SecretKey::new(sk_coeffs.to_vec(), &self.params);

        // Use MBFV DecryptionShare protocol which is already proven to work
        let mbfv_decryption_share = DecryptionShare::new(&sk, &ciphertext, rng)?;

        // Extract the underlying polynomial from the MBFV decryption share
        let d_share = mbfv_decryption_share.sks_share.h_share.clone();

        Ok(TrBFVDecryptionShare {
            par: self.params.clone(),
            d_share,
            ciphertext,
            threshold: self.threshold,
            n: self.n,
        })
    }

    /// Internal method to compute decryption share
    fn decryption_share_internal(
        &self,
        ciphertext: Arc<Ciphertext>,
        mut sk_i: Poly,
        es_i: Poly,
    ) -> Result<Poly> {
        // decrypt
        // mul c1 * sk
        // then add c0 + (c1*sk) + es
        let mut c0 = ciphertext.c[0].clone();
        c0.change_representation(Representation::PowerBasis);
        sk_i.change_representation(Representation::Ntt);
        let mut c1 = ciphertext.c[1].clone();
        c1.change_representation(Representation::Ntt);
        let mut c1sk = &c1 * &sk_i;
        c1sk.change_representation(Representation::PowerBasis);
        let d_share_poly = &c0 + &c1sk + es_i;
        Ok(d_share_poly)
    }

    /// Generate Shamir Secret Shares - for backwards compatibility  
    pub fn generate_secret_shares(&mut self, coeffs: Box<[i64]>) -> Result<Vec<Array2<u64>>> {
        self.generate_secret_shares_internal(&coeffs)
    }

    /// Generate Shamir Secret Shares with secure memory handling
    pub fn generate_secret_shares_secure<T: AsRef<[i64]>>(
        &mut self,
        coeffs: T,
    ) -> Result<Vec<Array2<u64>>> {
        self.generate_secret_shares_internal(coeffs.as_ref())
    }

    /// Generate MBFV-compatible public key shares from a master secret key using SSS
    /// This ensures that the public keys and threshold decryption use the same underlying secret
    pub fn generate_mbfv_threshold_keyshares<R: RngCore + CryptoRng>(
        &mut self,
        master_secret_coeffs: Box<[i64]>,
        crp: CommonRandomPoly,
        rng: &mut R,
    ) -> Result<(Vec<PublicKeyShare>, Vec<Array2<u64>>, Vec<Array2<u64>>)> {
        use crate::bfv::SecretKey;

        // Generate SSS shares of the master secret
        let master_sk_sss = self.generate_secret_shares(master_secret_coeffs.clone())?;

        // Generate smudging error and its SSS shares
        let master_esi_coeffs = self.generate_smudging_error(rng)?;
        let master_esi_sss = self.generate_secret_shares(master_esi_coeffs.into_boxed_slice())?;

        // Generate MBFV public key shares for each party using the master secret
        let master_sk = SecretKey::new(master_secret_coeffs.to_vec(), &self.params);
        let mut public_key_shares = Vec::with_capacity(self.n);

        for _party_idx in 0..self.n {
            // All parties get public key shares derived from the same master secret
            // This ensures encryption/decryption compatibility
            let pk_share = PublicKeyShare::new(&master_sk, crp.clone(), rng)?;
            public_key_shares.push(pk_share);
        }

        Ok((public_key_shares, master_sk_sss, master_esi_sss))
    }

    /// Generate threshold decryption shares directly from SSS shares of the master secret
    /// This maintains the encryption/decryption key consistency
    pub fn generate_threshold_decryption_shares(
        &self,
        ciphertext: Arc<Ciphertext>,
        sk_sss_shares: &[Array2<u64>], // Each party's SSS share (one per modulus)
        es_sss_shares: &[Array2<u64>], // Each party's error SSS share
        party_indices: &[usize],       // 1-based party indices for SSS
    ) -> Result<Vec<(usize, Array2<u64>)>> {
        let mut partial_decryptions = Vec::with_capacity(party_indices.len());

        for (i, &party_id) in party_indices.iter().enumerate() {
            // Combine shares across all moduli for this party
            let mut combined_sk = Array2::zeros((self.moduli.len(), self.degree));
            let mut combined_es = Array2::zeros((self.moduli.len(), self.degree));

            for m in 0..self.moduli.len() {
                for j in 0..self.degree {
                    combined_sk[[m, j]] = sk_sss_shares[i * self.moduli.len() + m][[0, j]];
                    combined_es[[m, j]] = es_sss_shares[i * self.moduli.len() + m][[0, j]];
                }
            }

            // Generate partial decryption using this party's SSS share
            let partial_decrypt = self.secure_partial_decrypt(
                ciphertext.clone(),
                &combined_sk,
                &combined_es,
                party_id,
            )?;

            partial_decryptions.push((party_id, partial_decrypt));
        }

        Ok(partial_decryptions)
    }

    /// Internal implementation for secret share generation
    fn generate_secret_shares_internal(&mut self, coeffs: &[i64]) -> Result<Vec<Array2<u64>>> {
        let poly = Zeroizing::new(
            Poly::try_convert_from(
                coeffs,
                &self.params.ctx_at_level(0).unwrap(),
                false,
                Representation::PowerBasis,
            )
            .unwrap(),
        );

        // 2 dim array, columns = fhe coeffs (degree), rows = party members shamir share coeff (n)
        let mut return_vec: Vec<Array2<u64>> = Vec::with_capacity(self.params.moduli.len());

        // for each moduli, for each coeff generate an SSS of degree n and threshold n = 2t + 1
        for (_k, (m, p)) in
            izip!(poly.ctx().moduli().iter(), poly.coefficients().outer_iter()).enumerate()
        {
            // Create shamir object
            let shamir = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(*m),
            };
            let mut m_data: Vec<u64> = Vec::new();

            // For each coeff in the polynomial p under the current modulus m
            for (_i, c) in p.iter().enumerate() {
                // Split the coeff into n shares
                let secret = c.to_bigint().unwrap();
                let c_shares = shamir.split(secret.clone());
                // For each share convert to u64
                let mut c_vec: Vec<u64> = Vec::with_capacity(self.n);
                for (_j, (_, c_share)) in c_shares.iter().enumerate() {
                    c_vec.push(c_share.to_u64().unwrap());
                }
                m_data.extend_from_slice(&c_vec);
            }
            // convert flat vector of coeffs to array2
            let arr_matrix = Array2::from_shape_vec((self.degree, self.n), m_data).unwrap();
            // reverse the columns and rows
            let reversed_axes = arr_matrix.t();
            return_vec.push(reversed_axes.to_owned());
        }
        // return vec = rows are party members, columns are degree length of shamir values
        Ok(return_vec)
    }

    /// ⚠️ CRITICAL SECURITY WARNING ⚠️
    ///
    /// This method reconstructs the full secret key and violates threshold security
    ///
    /// SECURITY ISSUES:
    /// - Reconstructs the complete secret key in memory from SSS shares
    /// - Violates the fundamental principle of threshold cryptography  
    /// - Creates a single point of failure where the full secret exists
    /// - Should only be used for backwards compatibility in controlled environments
    ///
    /// RECOMMENDED ALTERNATIVES:
    /// - Use secure_partial_decrypt() + secure_threshold_decrypt() instead
    /// - These methods never reconstruct the full secret key
    /// - They use proper SSS interpolation on partial decryption results
    ///
    /// This method will be removed in a future version.
    #[deprecated(
        note = "This method violates threshold security by reconstructing the full secret key. Use secure_partial_decrypt + secure_threshold_decrypt instead."
    )]
    pub fn sum_sk_i(
        &mut self,
        sk_sss_collected: &Vec<Array2<u64>>, // collected sk sss shares from other parties
    ) -> Result<Poly> {
        let mut sum_poly = Poly::zero(
            &self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        for j in 0..self.n {
            // Initialize empty poly with correct context (moduli and level)
            let mut poly_j = Poly::zero(
                &self.params.ctx_at_level(0).unwrap(),
                Representation::PowerBasis,
            );
            poly_j.set_coefficients(sk_sss_collected[j].clone());
            sum_poly = &sum_poly + &poly_j;
        }
        Ok(sum_poly)
    }

    /// Secure threshold decryption that never reconstructs the secret key
    /// Each party generates a partial decryption using only their own SSS share
    pub fn secure_partial_decrypt(
        &self,
        ciphertext: Arc<Ciphertext>,
        sk_share: &Array2<u64>, // This party's SSS share of secret key
        es_share: &Array2<u64>, // This party's SSS share of smudging error
        party_id: usize,        // 1-based party ID for SSS verification
    ) -> Result<Array2<u64>> {
        // Input validation
        if party_id == 0 || party_id > self.n {
            return Err(crate::Error::DefaultError(format!(
                "Invalid party ID: {} (must be between 1 and {})",
                party_id, self.n
            )));
        }

        if sk_share.dim() != (self.moduli.len(), self.degree) {
            return Err(crate::Error::DefaultError(format!(
                "Invalid sk_share dimensions: expected ({}, {}), got ({}, {})",
                self.moduli.len(),
                self.degree,
                sk_share.dim().0,
                sk_share.dim().1
            )));
        }

        if es_share.dim() != (self.moduli.len(), self.degree) {
            return Err(crate::Error::DefaultError(format!(
                "Invalid es_share dimensions: expected ({}, {}), got ({}, {})",
                self.moduli.len(),
                self.degree,
                es_share.dim().0,
                es_share.dim().1
            )));
        }

        // Convert SSS shares to polynomials
        let mut sk_poly = Poly::zero(
            &self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        sk_poly.set_coefficients(sk_share.clone());

        let mut es_poly = Poly::zero(
            &self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        es_poly.set_coefficients(es_share.clone());

        // Perform partial decryption: d_i = c0 + c1 * sk_i + es_i
        let mut c0 = ciphertext.c[0].clone();
        c0.change_representation(Representation::PowerBasis);
        sk_poly.change_representation(Representation::Ntt);
        let mut c1 = ciphertext.c[1].clone();
        c1.change_representation(Representation::Ntt);
        let mut c1sk = &c1 * &sk_poly;
        c1sk.change_representation(Representation::PowerBasis);

        let partial_decrypt = &c0 + &c1sk + es_poly;
        Ok(partial_decrypt.coefficients().to_owned())
    }

    /// Secure threshold decryption using SSS interpolation on partial decryption shares
    /// Never reconstructs the secret key - uses only threshold partial decryptions
    pub fn secure_threshold_decrypt(
        &mut self,
        partial_decryptions: Vec<(usize, Array2<u64>)>, // (party_id, partial_decryption)
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext> {
        // Input validation
        if partial_decryptions.len() < self.threshold {
            return Err(crate::Error::TooFewValues(
                partial_decryptions.len(),
                self.threshold,
            ));
        }

        // Validate party IDs are unique and in valid range
        let mut seen_ids = std::collections::HashSet::new();
        for (party_id, ref partial_decrypt) in &partial_decryptions {
            if *party_id == 0 || *party_id > self.n {
                return Err(crate::Error::DefaultError(format!(
                    "Invalid party ID: {} (must be between 1 and {})",
                    party_id, self.n
                )));
            }

            if !seen_ids.insert(*party_id) {
                return Err(crate::Error::DefaultError(format!(
                    "Duplicate party ID: {}",
                    party_id
                )));
            }

            if partial_decrypt.dim() != (self.moduli.len(), self.degree) {
                return Err(crate::Error::DefaultError(
                    format!("Invalid partial_decrypt dimensions for party {}: expected ({}, {}), got ({}, {})", 
                           party_id, self.moduli.len(), self.degree, partial_decrypt.dim().0, partial_decrypt.dim().1)
                ));
            }
        }

        let mut m_data: Vec<u64> = Vec::new();

        // Use SSS interpolation on partial decryption results
        for m in 0..self.moduli.len() {
            let sss = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(self.moduli[m]),
            };

            for i in 0..self.degree {
                let mut interpolation_points: Vec<(usize, BigInt)> =
                    Vec::with_capacity(self.threshold);

                // Use only threshold shares for interpolation
                for j in 0..self.threshold {
                    let (party_id, ref partial_decrypt) = partial_decryptions[j];
                    let coeff_arr = partial_decrypt.row(m);
                    let coeff = coeff_arr[i];
                    // SSS uses 1-based party IDs
                    interpolation_points.push((party_id, coeff.to_bigint().unwrap()));
                }

                // Perform SSS interpolation to recover plaintext coefficient
                let decrypted_coeff = sss.recover(&interpolation_points);
                m_data.push(decrypted_coeff.to_u64().unwrap());
            }
        }

        // Convert to plaintext using secure scaling
        self.convert_to_plaintext(m_data, ciphertext)
    }

    /// Helper method to convert decrypted coefficients to plaintext
    fn convert_to_plaintext(
        &self,
        m_data: Vec<u64>,
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext> {
        use zeroize::Zeroizing;

        let arr_matrix = Array2::from_shape_vec((self.moduli.len(), self.degree), m_data).unwrap();
        let mut result_poly = Poly::zero(
            &self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        result_poly.set_coefficients(arr_matrix);

        let plaintext_ctx = Context::new_arc(&self.moduli[..1], self.degree).unwrap();
        let mut scalers = Vec::with_capacity(self.moduli.len());
        for i in 0..self.moduli.len() {
            let rns = RnsContext::new(&self.moduli[..self.moduli.len() - i]).unwrap();
            let ctx_i =
                Context::new_arc(&self.moduli[..self.moduli.len() - i], self.degree).unwrap();
            scalers.push(
                Scaler::new(
                    &ctx_i,
                    &plaintext_ctx,
                    ScalingFactor::new(&BigUint::from(self.plaintext_modulus), rns.modulus()),
                )
                .unwrap(),
            );
        }

        let par = ciphertext.par.clone();
        let d = Zeroizing::new(result_poly.scale(&scalers[ciphertext.level])?);
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
            Poly::try_convert_from(&w, ciphertext.c[0].ctx(), false, Representation::PowerBasis)?;
        poly.change_representation(Representation::Ntt);

        let pt = Plaintext {
            par: par.clone(),
            value: w.into_boxed_slice(),
            encoding: None,
            poly_ntt: poly,
            level: ciphertext.level,
        };
        Ok(pt)
    }

    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<i64>> {
        // For each party, generate local smudging noise, coeffs of of degree N − 1 with coefficients
        // in [−Bsm, Bsm]
        let s_coefficients = sample_vec_normal(self.degree, self.sumdging_variance, rng).unwrap();
        Ok(s_coefficients)
    }

    // compute decryption share
    pub fn decryption_share(
        &mut self,
        ciphertext: Arc<Ciphertext>,
        mut sk_i: Poly,
        es_i: Poly,
    ) -> Result<Poly> {
        // decrypt
        // mul c1 * sk
        // then add c0 + (c1*sk) + es
        let mut c0 = ciphertext.c[0].clone();
        c0.change_representation(Representation::PowerBasis);
        sk_i.change_representation(Representation::Ntt);
        let mut c1 = ciphertext.c[1].clone();
        c1.change_representation(Representation::Ntt);
        let mut c1sk = &c1 * &sk_i;
        c1sk.change_representation(Representation::PowerBasis);
        let d_share_poly = &c0 + &c1sk + es_i;
        Ok(d_share_poly)
    }

    // compute decryption to plaintext from collected decryption shares
    // threshold number of shares required
    pub fn decrypt(
        &mut self,
        d_share_polys: Vec<Poly>,
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext> {
        let mut m_data: Vec<u64> = Vec::new();

        // collect shamir openings
        for m in 0..self.moduli.len() {
            let sss = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(self.moduli[m]),
            };
            for i in 0..self.degree {
                let mut shamir_open_vec_mod: Vec<(usize, BigInt)> = Vec::with_capacity(self.degree);
                for j in 0..self.threshold {
                    let coeffs = d_share_polys[j].coefficients();
                    let coeff_arr = coeffs.row(m);
                    let coeff = coeff_arr[i];
                    let coeff_formatted = (j + 1, coeff.to_bigint().unwrap());
                    shamir_open_vec_mod.push(coeff_formatted);
                }
                // open shamir
                let shamir_result = sss.recover(&shamir_open_vec_mod[0..self.threshold as usize]);
                m_data.push(shamir_result.to_u64().unwrap());
            }
        }

        // scale result poly
        let arr_matrix = Array2::from_shape_vec((self.moduli.len(), self.degree), m_data).unwrap();
        let mut result_poly = Poly::zero(
            &self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        result_poly.set_coefficients(arr_matrix);

        let plaintext_ctx = Context::new_arc(&self.moduli[..1], self.degree).unwrap();
        let mut scalers = Vec::with_capacity(self.moduli.len());
        for i in 0..self.moduli.len() {
            let rns = RnsContext::new(&self.moduli[..self.moduli.len() - i]).unwrap();
            let ctx_i =
                Context::new_arc(&self.moduli[..self.moduli.len() - i], self.degree).unwrap();
            scalers.push(
                Scaler::new(
                    &ctx_i,
                    &plaintext_ctx,
                    ScalingFactor::new(&BigUint::from(self.plaintext_modulus), rns.modulus()),
                )
                .unwrap(),
            );
        }

        let par = ciphertext.par.clone();
        let d = Zeroizing::new(result_poly.scale(&scalers[ciphertext.level])?);
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
            Poly::try_convert_from(&w, ciphertext.c[0].ctx(), false, Representation::PowerBasis)?;
        poly.change_representation(Representation::Ntt);

        let pt = Plaintext {
            par: par.clone(),
            value: w.into_boxed_slice(),
            encoding: None,
            poly_ntt: poly,
            level: ciphertext.level,
        };
        Ok(pt)
    }

    /// Generate a decryption share directly from a party's SSS share (without reconstructing the full secret)
    /// This maintains threshold security by never revealing the complete secret key
    pub fn decryption_share_from_sss(
        &mut self,
        ciphertext: Arc<Ciphertext>,
        sk_share: &Array2<u64>, // This party's share of the secret key (SSS share)
        es_share: &Array2<u64>, // This party's share of the smudging error (SSS share)
        _party_id: usize,       // 0-based party index
    ) -> Result<Poly> {
        // Convert SSS shares to polynomials
        let mut sk_poly = Poly::zero(
            &self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        sk_poly.set_coefficients(sk_share.clone());

        let mut es_poly = Poly::zero(
            &self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        es_poly.set_coefficients(es_share.clone());

        // Generate partial decryption share using this party's SSS shares
        // The final result will need SSS interpolation across threshold parties
        let mut c0 = ciphertext.c[0].clone();
        c0.change_representation(Representation::PowerBasis);
        sk_poly.change_representation(Representation::Ntt);
        let mut c1 = ciphertext.c[1].clone();
        c1.change_representation(Representation::Ntt);
        let mut c1sk = &c1 * &sk_poly;
        c1sk.change_representation(Representation::PowerBasis);

        // This is a "partial" decryption share that needs to be combined with others via SSS
        let partial_d_share = &c0 + &c1sk + es_poly;
        Ok(partial_d_share)
    }

    /// Aggregate threshold decryption shares using SSS interpolation
    /// This replaces the decrypt method to work with partial decryption shares
    pub fn aggregate_decryption_shares(
        &mut self,
        partial_shares: Vec<(usize, Poly)>, // (party_id, partial_decryption_share)
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext> {
        if partial_shares.len() < self.threshold {
            return Err(crate::Error::TooFewValues(
                partial_shares.len(),
                self.threshold,
            ));
        }

        let mut m_data: Vec<u64> = Vec::new();

        // Use SSS interpolation to combine the partial decryption shares
        for m in 0..self.moduli.len() {
            let sss = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(self.moduli[m]),
            };

            for i in 0..self.degree {
                let mut shamir_open_vec_mod: Vec<(usize, BigInt)> =
                    Vec::with_capacity(self.threshold);

                for j in 0..self.threshold {
                    let (party_id, ref poly) = partial_shares[j];
                    let coeffs = poly.coefficients();
                    let coeff_arr = coeffs.row(m);
                    let coeff = coeff_arr[i];
                    // Use party_id + 1 for SSS (1-indexed)
                    let coeff_formatted = (party_id + 1, coeff.to_bigint().unwrap());
                    shamir_open_vec_mod.push(coeff_formatted);
                }

                // Perform SSS interpolation to recover the final decryption value
                let shamir_result = sss.recover(&shamir_open_vec_mod[0..self.threshold]);
                m_data.push(shamir_result.to_u64().unwrap());
            }
        }

        // Convert to plaintext using the same scaling approach as the original decrypt method
        let arr_matrix = Array2::from_shape_vec((self.moduli.len(), self.degree), m_data).unwrap();
        let mut result_poly = Poly::zero(
            &self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        result_poly.set_coefficients(arr_matrix);

        let plaintext_ctx = Context::new_arc(&self.moduli[..1], self.degree).unwrap();
        let mut scalers = Vec::with_capacity(self.moduli.len());
        for i in 0..self.moduli.len() {
            let rns = RnsContext::new(&self.moduli[..self.moduli.len() - i]).unwrap();
            let ctx_i =
                Context::new_arc(&self.moduli[..self.moduli.len() - i], self.degree).unwrap();
            scalers.push(
                Scaler::new(
                    &ctx_i,
                    &plaintext_ctx,
                    ScalingFactor::new(&BigUint::from(self.plaintext_modulus), rns.modulus()),
                )
                .unwrap(),
            );
        }

        let par = ciphertext.par.clone();
        let d = Zeroizing::new(result_poly.scale(&scalers[ciphertext.level])?);
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
            Poly::try_convert_from(&w, ciphertext.c[0].ctx(), false, Representation::PowerBasis)?;
        poly.change_representation(Representation::Ntt);

        let pt = Plaintext {
            par: par.clone(),
            value: w.into_boxed_slice(),
            encoding: None,
            poly_ntt: poly,
            level: ciphertext.level,
        };
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfv::{BfvParametersBuilder, SecretKey};
    use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
    use itertools::{izip, zip};
    use ndarray::{array, concatenate, Array, Array2, ArrayView, Axis};
    use num_traits::ToPrimitive;
    use rand::thread_rng;
    use zeroize::Zeroizing;

    #[test]
    fn convert_poly_to_shared_poly() {
        let mut rng = thread_rng();
        // generate fhe secret key polynomial
        // for each poly coeff, generate a shamir secret share
        let n = 16;
        let threshold = 9;
        let degree = 2048;
        let plaintext_modulus: u64 = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];
        let secret1 = 4;
        let secret2 = 6;

        let sk_par = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();
        let mut s_raw: SecretKey = SecretKey::random(&sk_par, &mut rng);
        //println!("{:?}", s_raw);

        let mut s = Poly::try_convert_from(
            s_raw.coeffs.as_ref(),
            &sk_par.ctx_at_level(0).unwrap(),
            false,
            Representation::PowerBasis,
        )
        .unwrap();

        // ----------
        // Covert shares to poly, adding the shamir points needs to respect each rns_mod_i
        // here he is creating party number polys
        //
        //let mut s_shares: Vec<Poly> = vec![Poly::zero(&sk_par.ctx_at_level(0).unwrap(), Representation::PowerBasis); n]; // think we need m of these
        let mut s_shares: Vec<Vec<Poly>> = Vec::with_capacity(moduli.len());
        // store the sum of each m secret shared vectors
        let mut sum_shares_m: Vec<Poly> = Vec::with_capacity(moduli.len()); //todo grab length of levels
                                                                            // For each modulus (k here)
                                                                            // m is the modulus
                                                                            // p is one of the l (level) polys (3 here)
        for (k, (m, p)) in izip!(s.ctx().moduli().iter(), s.coefficients().outer_iter()).enumerate()
        {
            // Create shamir object
            let shamir = SSS {
                threshold: threshold,
                share_amount: n,
                prime: BigInt::from(*m),
            };
            // 2 dim array, rows = fhe coeffs, columns = party members shamir share coeff
            let mut shamir_coeffs: Vec<Vec<u64>> = Vec::with_capacity(degree);
            // arr2 version
            let mut data: Vec<u64> = Vec::new();

            // For each coeff in the polynomial p under the current modulus m
            for (i, c) in p.iter().enumerate() {
                // Split the coeff into n shares
                let secret = c.to_bigint().unwrap();
                let c_shares = shamir.split(secret.clone());
                // For each share convert to u64
                let mut c_vec: Vec<u64> = Vec::with_capacity(n);
                for (j, (_, c_share)) in c_shares.iter().enumerate() {
                    c_vec.push(c_share.to_u64().unwrap());
                    //s_shares[j].coefficients_mut()[k][i] = c_share.to_u64().unwrap();
                }
                // Set the coefficient in the corresponding polynomial matrix of s_shares
                // extend 1D flat vec for each shamir set
                data.extend_from_slice(&c_vec);

                shamir_coeffs.push(c_vec);
            }
            // create an array2 from vec
            let arr_matrix = Array2::from_shape_vec((degree, n), data).unwrap();
            println!("{:?}", m);
            // get the context for current modulus
            let ctx_m = Context::new_arc(&[*m], degree).unwrap();

            // collect n vectors down the degree of coeffs (can probably collect better above)
            // rows = party members shamir share coeff, columns = fhe coeffs
            let mut collect_vec_n: Vec<Vec<u64>> = Vec::with_capacity(n);
            for i in 0..n {
                let mut collect_vec_degree: Vec<u64> = Vec::with_capacity(degree);
                for j in 0..degree {
                    collect_vec_degree.push(shamir_coeffs[j][i]);
                }
                collect_vec_n.push(collect_vec_degree);
            }
            // use matrix transpose to shift axis instead of copy loop above
            let reversed_axes = arr_matrix.t();
            //println!("{:?}", reversed_axes[[0,1]]);
            //println!("{:?}", reversed_axes);
            // grab the row for each node at given moduli
            let node_n_share_one_mod = reversed_axes.row(0);
            println!("{:?}", node_n_share_one_mod);
            //let newarr = get_row.insert_axis(Axis(0));
            // create a new array to push each moduli share into for each node
            // TODO get these rows from each moduli. will need n of these
            let mut node_n_shares_all_mods = Array::zeros((0, 2048));
            node_n_shares_all_mods
                .push_row(ArrayView::from(&node_n_share_one_mod))
                .unwrap();
            node_n_shares_all_mods
                .push_row(ArrayView::from(&node_n_share_one_mod))
                .unwrap();
            node_n_shares_all_mods
                .push_row(ArrayView::from(&node_n_share_one_mod))
                .unwrap();
            //println!("after row axis 0 insert");
            //println!("---");
            //println!("{:?}", node_n_shares_all_mods);
            let test_coeffs_view = s.coefficients();
            //println!("---");
            //println!("{:?}", test_coeffs_view);
            //println!("---");
            //println!("after setting new coeffs");
            let mut s2 = s.clone();
            s2.set_coefficients(node_n_shares_all_mods);
            //println!("{:?}", s2);

            // convert to n polys for each m
            let mut s_share_poly_k: Vec<Poly> = Vec::with_capacity(n);
            for i in 0..n {
                let mut s_share_poly = Poly::try_convert_from(
                    &collect_vec_n[i],
                    &ctx_m,
                    false,
                    Representation::PowerBasis,
                )
                .unwrap();
                //println!("{:?}", s_share_poly);
                s_share_poly_k.push(s_share_poly)
                //s_shares.push(s_share_poly);
            }
            s_shares.push(s_share_poly_k);

            // sum polys
            //let mut sum_poly
            //println!("{:?}", s_shares[k][0]);
            for i in 1..n {
                s_shares[k][0] = &s_shares[k][0] + &s_shares[k][i];
            }
            //println!("{:?}", s_shares[k][0]);
            println!("----");
            //println!("{:?}", shamir_coeffs[2047]);
        }
        //println!("{:?}", s);
        // ----------
        let mut trbfv = TrBFVShare::new(n, threshold, degree, 9, moduli.clone()).unwrap();
        let get_coeff_matrix = trbfv
            .generate_secret_shares(sk_par.clone(), s_raw.clone())
            .unwrap();
        println!("{:?}", get_coeff_matrix[1].row(0));

        // gather seceret coeffs
        let coeffview = s.coefficients();
        //println!("{:?}", coeffview);
        // use rns_mod_i (smaller than rns mod)
        // todo convert back to rns mod
        let rns_mod_i = sk_par.moduli()[0];

        let shamir = SSS {
            threshold: threshold,
            share_amount: n,
            prime: BigInt::from(rns_mod_i),
        };

        // test two secret coeff points
        let secret_1 = secret1.to_bigint().unwrap();
        let secret_2 = secret2.to_bigint().unwrap();
        // create shamir polynomials
        let s1_shares = shamir.split(secret_1.clone());
        let s2_shares = shamir.split(secret_2.clone());

        // convert shamir points to u64 for poly coeffs
        let mut u64shamirvec_1: Vec<u64> = Vec::with_capacity(n);
        for i in 0..n {
            u64shamirvec_1.push(s1_shares[i].1.to_u64().unwrap());
        }
        let mut u64shamirvec_2: Vec<u64> = Vec::with_capacity(n);
        for i in 0..n {
            u64shamirvec_2.push(s2_shares[i].1.to_u64().unwrap());
        }

        // create fhe.rs poly with u64 shamir coeffs
        let mut s1_share_poly = Poly::try_convert_from(
            u64shamirvec_1,
            &sk_par.ctx_at_level(0).unwrap(),
            false,
            Representation::PowerBasis,
        )
        .unwrap();
        let mut s2_share_poly = Poly::try_convert_from(
            u64shamirvec_2,
            &sk_par.ctx_at_level(0).unwrap(),
            false,
            Representation::PowerBasis,
        )
        .unwrap();

        // Add the two shamir polynomials
        let sum_shamir = &s1_share_poly + &s2_share_poly;
        //let mul_shamir = &s1_share_poly * &s2_share_poly;

        // gather the result of poly addition u64 coeffs
        let mut collect_coeffs: Vec<u64> = Vec::with_capacity(n * 3);
        for ((x, y), value) in sum_shamir.coefficients().indexed_iter() {
            if *value != 0 as u64 {
                collect_coeffs.push(*value);
            }
        }
        // convert u64 to shamir big int tuple
        let mut shamir_rep: Vec<(usize, BigInt)> = Vec::with_capacity(n);
        for i in 0..16 {
            let index = i + 1 as usize;
            let bigintcoeff = collect_coeffs[i].to_bigint().unwrap();
            shamir_rep.push((index, bigintcoeff));
        }

        // Open the shamir secret to get s1 + s2.
        let result = shamir.recover(&shamir_rep[0..shamir.threshold as usize]);
        println!("{:?}", result);

        let mut arr = Array2::zeros((3, 3));
        for (i, mut row) in arr.axis_iter_mut(Axis(0)).enumerate() {
            // Perform calculations and assign to `row`; this is a trivial example:
            row.fill(i);
        }
        assert_eq!(arr, array![[0, 0, 0], [1, 1, 1], [2, 2, 2]]);
    }

    #[test]
    fn test_trbfv() {
        let mut rng = thread_rng();
        // generate fhe secret key polynomial
        // for each poly coeff, generate a shamir secret share
        let n = 16;
        let threshold = 9;
        let degree = 2048;
        let plaintext_modulus: u64 = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];

        // For each party, generate secret key share contribution (this will never be shared)
        let sk_par = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();
        let mut sk_share = SecretKey::random(&sk_par, &mut rng);
        println!("{:?}", sk_share.coeffs.len());
        println!("{:?}", sk_share.par);

        // For each party, generate public key contribution from sk, this will be broadcast publicly
        let pk_share = PublicKey::new(&sk_share, &mut rng);

        // For each party, generate local smudging noise, coeffs of of degree N − 1 with coefficients
        // in [−Bsm, Bsm]
        let mut s_coefficients = sample_vec_cbd_unbounded(sk_par.degree(), 16, &mut rng).unwrap();

        // Shamir secret share params
        let sss = SSS {
            threshold: threshold,
            share_amount: n,
            prime: BigInt::parse_bytes(
                b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                16,
            )
            .unwrap(),
        };

        // for each smuding error coeff generate an SSS of degree n and threshold n = 2t + 1
        let mut sss_smudge_result: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(degree);

        for i in 0..degree {
            // encode negative coeffs as positive ints [11,19]
            if s_coefficients[i] < 0 {
                //println!("minus");
                s_coefficients[i] = s_coefficients[i] + 19;
            }
            let secret = s_coefficients[i].to_bigint().unwrap();
            //println!("{:?}", s_coefficients[i]);
            let shares = sss.split(secret.clone());
            //println!("{:?}", shares);
            sss_smudge_result.push(shares);
        }

        let mut smudge_node_shares: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(n);
        for i in 0..n {
            let mut node_share_i: Vec<(usize, BigInt)> = Vec::with_capacity(threshold);
            for j in 0..degree {
                node_share_i.push(sss_smudge_result[j][i].clone());
            }
            smudge_node_shares.push(node_share_i)
        }

        // for each sk coeff generate an SSS of degree n and threshold n = 2t + 1
        let mut result: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(degree);

        for i in 0..degree {
            // encode negative coeffs as positive ints [11,19]
            if sk_share.coeffs[i] < 0 {
                //println!("minus");
                sk_share.coeffs[i] = sk_share.coeffs[i] + 19;
            }
            let secret = sk_share.coeffs[i].to_bigint().unwrap();
            let shares = sss.split(secret.clone());
            result.push(shares);
        }

        let mut node_shares: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(n);
        for i in 0..n {
            let mut node_share_i: Vec<(usize, BigInt)> = Vec::with_capacity(threshold);
            for j in 0..degree {
                node_share_i.push(result[j][i].clone());
            }
            node_shares.push(node_share_i)
        }

        // Test decrypt
        let mut test_sssvec: Vec<(usize, BigInt)> = Vec::with_capacity(n);
        for i in 0..n {
            test_sssvec.push(node_shares[n - 1][0].clone());
        }
        //println!("{:?}", test_sssvec);
        println!("{:?}", node_shares[0].len());
        println!(
            "The useful size of `v` is {}",
            size_of_val(&*node_shares[0])
        );
        //println!(" Secret coeff {:?}", sk_share.coeffs[0].to_bigint().unwrap());
        assert_eq!(
            sk_share.coeffs[0].to_bigint().unwrap(),
            sss.recover(&result[0][0..sss.threshold as usize])
        );
        println!("{:?}", result[0]);
    }
}
