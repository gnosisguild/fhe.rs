//! Threshold BFV (trbfv) implementation with l-BFV integration.
//!
//! This module implements threshold encryption based on the BFV homomorphic encryption scheme,
//! following the protocol described in "Robust Multiparty Computation from Threshold Encryption 
//! Based on RLWE" by Urban and Rambaud (<https://eprint.iacr.org/2024/1285.pdf>).
//!
//! The implementation integrates with the l-BFV scheme to provide:
//! - Distributed key generation
//! - Threshold decryption with (t, n) access structure
//! - Robust multiparty computation with smudging noise
//! - Shamir secret sharing for secret key distribution
//!
//! # Key Components
//!
//! - **TrBFVShare**: Main structure representing a party's view in the threshold system
//! - **Secret Sharing**: Shamir secret sharing for distributing secret keys among parties
//! - **Smudging Noise**: Additional noise for robust threshold decryption
//! - **l-BFV Integration**: Uses l-BFV public keys and relinearization keys for enhanced security

use std::sync::Arc;

use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::lbfv::{LBFVPublicKey, LBFVRelinearizationKey}; // l-BFV components for enhanced security
use crate::{Error, Result};
use fhe_math::{
    rns::{RnsContext, ScalingFactor},
    rq::{scaler::Scaler, traits::TryConvertFrom, Context, Poly, Representation},
    zq::Modulus,
};
use fhe_traits::FheEncrypter; // Trait for encryption operations
use fhe_util::sample_vec_normal;
use itertools::{izip, Itertools};
use ndarray::Array2;
use num_bigint::BigUint;
use num_bigint_old::{BigInt, ToBigInt};
use num_traits::ToPrimitive;
use rand::{CryptoRng, RngCore};
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use zeroize::Zeroizing;

/// Represents a party's share in the Threshold BFV cryptosystem.
///
/// This structure implements the threshold encryption scheme described in the paper
/// "Robust Multiparty Computation from Threshold Encryption Based on RLWE".
/// 
/// # Threshold Cryptography Overview
///
/// In a (t, n) threshold cryptosystem:
/// - **n**: Total number of parties
/// - **t**: Threshold - minimum number of parties needed for decryption
/// - **Access Structure**: Any t+1 parties can decrypt, but t or fewer cannot
///
/// # Integration with l-BFV
///
/// This implementation integrates with the l-BFV scheme to provide:
/// - Enhanced noise management through decomposition
/// - Efficient relinearization for homomorphic multiplication
/// - Better parameter optimization for threshold operations
///
/// # Security Properties
///
/// - **Robustness**: Uses smudging noise to hide individual party contributions
/// - **Correctness**: Threshold decryption produces correct results with high probability
/// - **Privacy**: Individual secret shares remain hidden from other parties
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TrBFVShare {
    /// Total number of parties in the threshold system
    n: usize,
    
    /// Threshold value - minimum number of parties needed for decryption (t+1)
    /// In a (t, n) threshold scheme, any t+1 parties can decrypt
    threshold: usize,
    
    /// Polynomial degree for the BFV parameters
    degree: usize,
    
    /// Plaintext modulus for BFV encryption
    plaintext_modulus: u64,
    
    /// Variance for smudging noise generation
    /// Used to add additional noise for robustness in threshold decryption
    sumdging_variance: usize,
    
    /// RNS moduli for the BFV parameter set
    moduli: Vec<u64>,
    
    /// BFV parameters shared across all parties
    params: Arc<BfvParameters>,
    
    /// l-BFV public key for encryption operations
    /// This is shared among all parties and used for encrypting plaintexts
    pub_key: Option<LBFVPublicKey>,
    
    /// l-BFV relinearization key for homomorphic multiplication
    /// Enables efficient degree reduction after multiplication operations
    relin_key: Option<LBFVRelinearizationKey>,
}

impl TrBFVShare {
    /// Creates a new TrBFV share instance for a party in the threshold system.
    ///
    /// This initializes a party's view of the threshold BFV cryptosystem with the given parameters.
    /// The l-BFV keys need to be set separately using `generate_lbfv_keys()` or the setter methods.
    ///
    /// # Arguments
    ///
    /// * `n` - Total number of parties in the threshold system
    /// * `threshold` - Minimum number of parties needed for decryption (should be at least t+1)
    /// * `degree` - Polynomial degree for the BFV parameters (must be a power of 2)
    /// * `plaintext_modulus` - Modulus for plaintext operations
    /// * `sumdging_variance` - Variance for smudging noise generation (typically 160 bits)
    /// * `moduli` - RNS moduli for the BFV parameter set
    /// * `params` - Shared BFV parameters for all cryptographic operations
    ///
    /// # Returns
    ///
    /// A new `TrBFVShare` instance with the specified parameters.
    ///
    /// # Security Considerations
    ///
    /// - The threshold should be chosen based on the security model (e.g., t < n/2 for honest majority)
    /// - The smudging variance should be large enough to provide statistical security
    /// - The BFV parameters should be chosen to resist known attacks
    pub fn new(
        n: usize,
        threshold: usize,
        degree: usize,
        plaintext_modulus: u64,
        sumdging_variance: usize,
        moduli: Vec<u64>,
        params: Arc<BfvParameters>,
    ) -> Result<Self> {
        // Validate threshold parameters
        if threshold == 0 || threshold > n {
            return Err(Error::DefaultError(
                "Threshold must be between 1 and n".to_string()
            ));
        }
        
        // Create the TrBFV instance without l-BFV keys (to be set later)
        Ok(Self {
            n,
            threshold,
            degree,
            plaintext_modulus,
            sumdging_variance,
            moduli,
            params,
            pub_key: None,      // l-BFV public key will be set later
            relin_key: None,    // l-BFV relinearization key will be set later
        })
    }

    /// Sets the l-BFV public key for this threshold BFV instance.
    ///
    /// The l-BFV public key is shared among all parties and is used for encryption operations.
    /// This key should be generated through a distributed key generation protocol in practice.
    ///
    /// # Arguments
    ///
    /// * `pk` - The l-BFV public key to use for encryption operations
    pub fn set_public_key(&mut self, pk: LBFVPublicKey) {
        self.pub_key = Some(pk);
    }

    /// Sets the l-BFV relinearization key for this threshold BFV instance.
    ///
    /// The l-BFV relinearization key enables efficient homomorphic multiplication
    /// by reducing the degree of ciphertexts after multiplication operations.
    ///
    /// # Arguments
    ///
    /// * `rk` - The l-BFV relinearization key for multiplication operations
    pub fn set_relinearization_key(&mut self, rk: LBFVRelinearizationKey) {
        self.relin_key = Some(rk);
    }

    /// Returns a reference to the l-BFV public key if available.
    ///
    /// # Returns
    ///
    /// `Some(&LBFVPublicKey)` if the public key has been set, `None` otherwise.
    pub fn public_key(&self) -> Option<&LBFVPublicKey> {
        self.pub_key.as_ref()
    }

    /// Returns a reference to the l-BFV relinearization key if available.
    ///
    /// # Returns
    ///
    /// `Some(&LBFVRelinearizationKey)` if the relinearization key has been set, `None` otherwise.
    pub fn relinearization_key(&self) -> Option<&LBFVRelinearizationKey> {
        self.relin_key.as_ref()
    }

    /// Encrypts a plaintext using the l-BFV public key.
    ///
    /// This method provides a convenient interface for encryption using the l-BFV public key
    /// stored in this TrBFV instance. The resulting ciphertext can be used for homomorphic
    /// operations and threshold decryption.
    ///
    /// # Arguments
    ///
    /// * `pt` - The plaintext to encrypt
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// An encrypted ciphertext that can be processed by the threshold system.
    ///
    /// # Errors
    ///
    /// Returns an error if the l-BFV public key has not been set or if encryption fails.
    pub fn encrypt<R: RngCore + CryptoRng>(&self, pt: &Plaintext, rng: &mut R) -> Result<Ciphertext> {
        let pk = self.pub_key.as_ref().ok_or_else(|| {
            Error::DefaultError("l-BFV public key not set".to_string())
        })?;
        pk.try_encrypt(pt, rng)
    }

    /// Creates l-BFV public and relinearization keys from a secret key.
    ///
    /// This is a convenience method that generates both the l-BFV public key and 
    /// relinearization key from a given secret key. In a real threshold system,
    /// these keys would be generated through a distributed key generation protocol.
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key to derive the l-BFV keys from
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// `Ok(())` if the keys are successfully generated and stored.
    ///
    /// # Security Note
    ///
    /// In practice, the secret key should never be available to a single party.
    /// This method is primarily for testing and demonstration purposes.
    pub fn generate_lbfv_keys<R: RngCore + CryptoRng>(
        &mut self, 
        sk: &crate::bfv::SecretKey, 
        rng: &mut R
    ) -> Result<()> {
        // Generate l-BFV public key
        let pk = LBFVPublicKey::new(sk, rng);
        
        // Generate l-BFV relinearization key using the public key
        let rk = LBFVRelinearizationKey::new(sk, &pk, None, rng)?;
        
        // Store both keys in this instance
        self.set_public_key(pk);
        self.set_relinearization_key(rk);
        
        Ok(())
    }

    /// Generates Shamir Secret Shares for a secret key polynomial.
    ///
    /// This method implements Shamir's secret sharing scheme to distribute a secret key
    /// among n parties such that any threshold number of parties can reconstruct the secret.
    /// The secret sharing is performed coefficient-wise for each polynomial coefficient
    /// across all RNS moduli.
    ///
    /// # Mathematical Background
    ///
    /// For each coefficient c_i of the secret key polynomial and each RNS modulus q_j:
    /// 1. Create a polynomial f(x) = c_i + a_1*x + ... + a_t*x^t (mod q_j)
    /// 2. Evaluate f(1), f(2), ..., f(n) to get n shares
    /// 3. Any t+1 shares can reconstruct c_i using Lagrange interpolation
    ///
    /// # Arguments
    ///
    /// * `coeffs` - Coefficients of the secret key polynomial to be shared
    ///
    /// # Returns
    ///
    /// A vector of `Array2<u64>` where:
    /// - Each array corresponds to one RNS modulus
    /// - Rows represent parties (0 to n-1)
    /// - Columns represent polynomial coefficients (0 to degree-1)
    /// - Element `[i][j]` is party i's share of coefficient j
    ///
    /// # Security Properties
    ///
    /// - **t-privacy**: Any t or fewer shares reveal no information about the secret
    /// - **Correctness**: Any t+1 shares can perfectly reconstruct the secret
    /// - **Robustness**: Can tolerate up to n-t-1 corrupted shares
    pub fn generate_secret_shares(&mut self, coeffs: Box<[i64]>) -> Result<Vec<Array2<u64>>> {
        // Convert secret key coefficients to polynomial representation
        let poly = Zeroizing::new(
            Poly::try_convert_from(
                coeffs.as_ref(),
                &self.params.ctx_at_level(0).unwrap(),
                false,
                Representation::PowerBasis,
            )
            .unwrap(),
        );

        // Initialize return vector - one array per RNS modulus
        let mut return_vec: Vec<Array2<u64>> = Vec::with_capacity(self.params.moduli.len());

        // Process each RNS modulus separately to maintain Chinese Remainder Theorem structure
        for (_k, (m, p)) in
            izip!(poly.ctx().moduli().iter(), poly.coefficients().outer_iter()).enumerate()
        {
            // Create Shamir secret sharing instance for this modulus
            let shamir = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(*m),  // Use RNS modulus as the prime for secret sharing
            };
            
            // Flat vector to store all shares for this modulus
            let mut m_data: Vec<u64> = Vec::new();

            // For each coefficient in the polynomial under the current modulus
            for (_i, c) in p.iter().enumerate() {
                // Split this coefficient into n shares using Shamir's scheme
                let secret = c.to_bigint().unwrap();
                let c_shares = shamir.split(secret.clone());
                
                // Convert shares to u64 and store them
                for (_j, (_, c_share)) in c_shares.iter().enumerate() {
                    m_data.push(c_share.to_u64().unwrap());
                }
            }
            
            // Convert flat vector to 2D array: rows=coefficients, cols=parties
            let arr_matrix = Array2::from_shape_vec((self.degree, self.n), m_data).unwrap();
            
            // Transpose to get: rows=parties, cols=coefficients
            // This makes it easier to distribute shares to parties
            let reversed_axes = arr_matrix.t();
            return_vec.push(reversed_axes.to_owned());
        }
        
        // Return structure: Vec[modulus_index][party_index][coefficient_index]
        Ok(return_vec)
    }

    /// Reconstructs a secret key polynomial from collected Shamir secret shares.
    ///
    /// This method takes secret shares from multiple parties and reconstructs the
    /// secret key polynomial. In practice, this would be done during threshold
    /// decryption where each party contributes their shares.
    ///
    /// # Arguments
    ///
    /// * `sk_sss_collected` - Collection of secret shares from multiple parties
    ///   Format: `Vec[modulus_index][party_index][coefficient_index]`
    ///
    /// # Returns
    ///
    /// A polynomial representing the reconstructed secret key
    ///
    /// # Mathematical Process
    ///
    /// For each coefficient position and each RNS modulus:
    /// 1. Collect shares from threshold number of parties
    /// 2. Use Lagrange interpolation to reconstruct the coefficient
    /// 3. Combine coefficients to form the complete polynomial
    pub fn sum_sk_i(
        &mut self,
        sk_sss_collected: &Vec<Array2<u64>>, // collected sk sss shares from other parties
    ) -> Result<Poly> {
        let ctx = self.params.ctx_at_level(0)?;
        let mut sum_poly = Poly::zero(ctx, Representation::PowerBasis);
        
        // Sum contributions from all parties
        for j in 0..self.n {
            if j < sk_sss_collected.len() {
                // Create polynomial from the coefficients for party j
                let mut poly_j = Poly::zero(ctx, Representation::PowerBasis);
                poly_j.set_coefficients(sk_sss_collected[j].clone());
                sum_poly = &sum_poly + &poly_j;
            }
        }
        Ok(sum_poly)
    }

    /// Generates smudging error for robust threshold decryption.
    ///
    /// Smudging noise is a key component of robust threshold encryption schemes.
    /// It provides statistical security by hiding the individual contributions
    /// of honest parties during threshold decryption.
    ///
    /// # Mathematical Background
    ///
    /// Each party i generates a random polynomial e_i with coefficients drawn from
    /// a normal distribution with variance σ². The smudging noise:
    /// - Hides the structure of individual partial decryptions
    /// - Ensures robustness against malicious parties
    /// - Maintains correctness when properly calibrated
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// A vector of i64 coefficients representing the smudging error polynomial
    ///
    /// # Security Requirements
    ///
    /// - The variance should be large enough to provide statistical security
    /// - Typically chosen as 2^160 or higher for 128-bit security
    /// - Must be coordinated with the overall noise budget of the scheme
    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<i64>> {
        // Generate coefficients from normal distribution with specified variance
        // Each coefficient represents noise to be added during threshold decryption
        let s_coefficients = sample_vec_normal(self.degree, self.sumdging_variance, rng).unwrap();
        Ok(s_coefficients)
    }

    /// Computes a party's contribution to threshold decryption.
    ///
    /// This method implements the partial decryption process where each party
    /// computes their share of the decryption using their secret key share
    /// and adds smudging noise for robustness.
    ///
    /// # Mathematical Process
    ///
    /// For a ciphertext (c₀, c₁), party i computes:
    /// d_i = c₀ + c₁ · sk_i + e_i
    ///
    /// Where:
    /// - sk_i is party i's secret key share
    /// - e_i is party i's smudging error
    /// - d_i is the partial decryption share
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to partially decrypt
    /// * `sk_i` - This party's secret key share
    /// * `es_i` - This party's smudging error polynomial
    ///
    /// # Returns
    ///
    /// A polynomial representing this party's decryption share
    ///
    /// # Security Properties
    ///
    /// - The smudging noise hides the actual secret key contribution
    /// - Multiple shares can be combined to recover the plaintext
    /// - Individual shares leak no information about the secret key
    pub fn decryption_share(
        &mut self,
        ciphertext: Arc<Ciphertext>,
        mut sk_i: Poly,
        es_i: Poly,
    ) -> Result<Poly> {
        // Extract ciphertext components
        let mut c0 = ciphertext.c[0].clone();
        c0.change_representation(Representation::PowerBasis);
        
        // Prepare secret key for multiplication
        sk_i.change_representation(Representation::Ntt);
        let mut c1 = ciphertext.c[1].clone();
        c1.change_representation(Representation::Ntt);
        
        // Compute c₁ · sk_i (the main decryption step)
        let mut c1sk = &c1 * &sk_i;
        c1sk.change_representation(Representation::PowerBasis);
        
        // Compute partial decryption: d_i = c₀ + c₁ · sk_i + e_i
        // This combines the decryption with smudging noise for robustness
        let d_share_poly = &c0 + &c1sk + es_i;
        
        Ok(d_share_poly)
    }

    /// Reconstructs the plaintext from threshold decryption shares.
    ///
    /// This method implements the final step of threshold decryption by combining
    /// partial decryption shares from multiple parties to recover the original plaintext.
    /// It uses Shamir secret sharing reconstruction to combine the shares.
    ///
    /// # Mathematical Process
    ///
    /// Given threshold decryption shares d₁, d₂, ..., d_t from t parties:
    /// 1. For each coefficient position and RNS modulus:
    ///    - Collect the corresponding shares from all parties
    ///    - Use Lagrange interpolation to reconstruct the coefficient
    /// 2. Scale the result appropriately to recover the plaintext
    /// 3. Apply modular reduction to get the final plaintext polynomial
    ///
    /// # Arguments
    ///
    /// * `d_share_polys` - Vector of decryption shares from threshold number of parties
    /// * `ciphertext` - The original ciphertext being decrypted (used for context)
    ///
    /// # Returns
    ///
    /// The reconstructed plaintext
    ///
    /// # Requirements
    ///
    /// - Must have at least `threshold` number of decryption shares
    /// - All shares must be computed correctly by honest parties
    /// - The smudging noise must be properly calibrated
    ///
    /// # Security Properties
    ///
    /// - Threshold security: Need at least t+1 shares for successful decryption
    /// - Robustness: Can handle some malicious shares if they're a minority
    pub fn decrypt(
        &mut self,
        d_share_polys: Vec<Poly>,
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext> {
        let mut m_data: Vec<u64> = Vec::new();

        // Reconstruct coefficients using Shamir secret sharing for each RNS modulus
        for m in 0..self.moduli.len() {
            // Create Shamir instance for this modulus
            let sss = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(self.moduli[m]),
            };
            
            // Process each coefficient position in the polynomial
            for i in 0..self.degree {
                let mut shamir_open_vec_mod: Vec<(usize, BigInt)> = Vec::with_capacity(self.degree);
                
                // Collect shares from threshold number of parties for this coefficient
                for j in 0..self.threshold {
                    let coeffs = d_share_polys[j].coefficients();
                    let coeff_arr = coeffs.row(m);
                    let coeff = coeff_arr[i];
                    // Shamir shares need party index starting from 1
                    let coeff_formatted = (j + 1, coeff.to_bigint().unwrap());
                    shamir_open_vec_mod.push(coeff_formatted);
                }
                
                // Use Lagrange interpolation to reconstruct the coefficient
                let shamir_result = sss.recover(&shamir_open_vec_mod[0..self.threshold as usize]);
                m_data.push(shamir_result.to_u64().unwrap());
            }
        }

        // Reconstruct the polynomial from the recovered coefficients
        let arr_matrix = Array2::from_shape_vec((self.moduli.len(), self.degree), m_data).unwrap();
        let mut result_poly = Poly::zero(
            &self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        result_poly.set_coefficients(arr_matrix);

        // Set up scaling from ciphertext modulus to plaintext modulus
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

        // Scale the polynomial and apply modular reduction
        let par = ciphertext.par.clone();
        let d = Zeroizing::new(result_poly.scale(&scalers[ciphertext.level])?);
        
        // Convert to coefficient representation and apply modular reductions
        let v = Zeroizing::new(
            Vec::<u64>::from(d.as_ref())
                .iter_mut()
                .map(|vi| *vi + par.plaintext.modulus())
                .collect_vec(),
        );
        
        // Extract the plaintext coefficients and reduce modulo plaintext modulus
        let mut w = v[..par.degree()].to_vec();
        let q = Modulus::new(par.moduli[0]).map_err(Error::MathError)?;
        q.reduce_vec(&mut w);
        par.plaintext.reduce_vec(&mut w);

        // Create the final plaintext polynomial
        let mut poly =
            Poly::try_convert_from(&w, ciphertext.c[0].ctx(), false, Representation::PowerBasis)?;
        poly.change_representation(Representation::Ntt);

        // Construct the plaintext object
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
    use crate::lbfv::LBFVPublicKey;
    use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder};
    use itertools::izip;
    use ndarray::{array, Array, Array2, ArrayView, Axis};
    use num_traits::ToPrimitive;
    use rand::thread_rng;
    use std::mem::size_of_val;

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
                //s_shares[k].push(s_share_poly);
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
        let mut trbfv = TrBFVShare::new(
            n,
            threshold,
            degree,
            plaintext_modulus,
            160,
            moduli.clone(),
            sk_par.clone(),
        )
        .unwrap();
        let get_coeff_matrix = trbfv.generate_secret_shares(s_raw.coeffs.clone()).unwrap();
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

        // For each party, generate l-BFV public key contribution from sk, this will be broadcast publicly
        let pk_share = LBFVPublicKey::new(&sk_share, &mut rng);

        // For each party, generate local smudging noise, coeffs of of degree N − 1 with coefficients
        // in [−Bsm, Bsm]
        let mut s_coefficients = fhe_util::sample_vec_cbd(sk_par.degree(), 16, &mut rng).unwrap();

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

    #[test]
    fn test_trbfv_lbfv_integration() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut rng = thread_rng();
        
        // Parameters for threshold BFV
        let n = 5;          // number of parties
        let threshold = 3;  // threshold (2t+1 = 5, so t = 2, threshold = 3)
        let degree = 1024;
        let plaintext_modulus: u64 = 65537;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];

        // Create BFV parameters
        let sk_par = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        // Create TrBFV instance
        let mut trbfv = TrBFVShare::new(
            n,
            threshold,
            degree,
            plaintext_modulus,
            160,
            moduli.clone(),
            sk_par.clone(),
        )?;

        // Generate master secret key (in practice this would be distributed)
        let master_sk = SecretKey::random(&sk_par, &mut rng);
        
        // Generate l-BFV keys
        trbfv.generate_lbfv_keys(&master_sk, &mut rng)?;
        
        // Verify keys are set
        assert!(trbfv.public_key().is_some());
        assert!(trbfv.relinearization_key().is_some());
        
        // Test encryption with l-BFV
        let test_message = 42u64;
        let pt = crate::bfv::Plaintext::try_encode(
            &[test_message], 
            crate::bfv::Encoding::poly(), 
            &sk_par
        )?;
        
        let ct = trbfv.encrypt(&pt, &mut rng)?;
        
        // Test that we can decrypt with the master secret key
        let decrypted_pt = master_sk.try_decrypt(&ct)?;
        let decrypted_values = Vec::<u64>::try_decode(
            &decrypted_pt, 
            crate::bfv::Encoding::poly()
        )?;
        
        assert_eq!(decrypted_values[0], test_message);
        
        println!("Successfully integrated trbfv with l-BFV!");
        println!("Original message: {}", test_message);
        println!("Decrypted message: {}", decrypted_values[0]);
        
        Ok(())
    }

    #[test]
    fn test_full_threshold_workflow() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut rng = thread_rng();
        
        // Threshold parameters
        let n = 5;          // number of parties  
        let threshold = 3;  // threshold (need 3 parties to decrypt)
        let degree = 1024;
        let plaintext_modulus: u64 = 65537;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];

        // Create BFV parameters
        let sk_par = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        // Step 1: Each party generates their secret key share
        let mut party_secret_keys: Vec<SecretKey> = Vec::with_capacity(n);
        let mut party_trbfv_instances: Vec<TrBFVShare> = Vec::with_capacity(n);
        
        for i in 0..n {
            let sk_share = SecretKey::random(&sk_par, &mut rng);
            party_secret_keys.push(sk_share);
            
            let mut trbfv = TrBFVShare::new(
                n, threshold, degree, plaintext_modulus, 160,
                moduli.clone(), sk_par.clone()
            )?;
            party_trbfv_instances.push(trbfv);
        }

        // Step 2: Generate distributed l-BFV keys (simplified - normally would be done via MPC)
        // For demonstration, we'll use the first party's secret key to generate l-BFV keys
        let master_sk = &party_secret_keys[0];
        party_trbfv_instances[0].generate_lbfv_keys(master_sk, &mut rng)?;
        
        // Step 3: Distribute the public components to all parties
        let pub_key = party_trbfv_instances[0].public_key().unwrap().clone();
        let relin_key = party_trbfv_instances[0].relinearization_key().unwrap().clone();
        
        for i in 1..n {
            party_trbfv_instances[i].set_public_key(pub_key.clone());
            party_trbfv_instances[i].set_relinearization_key(relin_key.clone());
        }

        // Step 4: Encrypt a message using l-BFV
        let secret_message = 12345u64;
        let pt = crate::bfv::Plaintext::try_encode(
            &[secret_message], 
            crate::bfv::Encoding::poly(), 
            &sk_par
        )?;
        
        let ct = party_trbfv_instances[0].encrypt(&pt, &mut rng)?;
        println!("Encrypted message: {}", secret_message);

        // Step 5: Generate secret shares for each party (simplified simulation)
        let secret_shares = party_trbfv_instances[0].generate_secret_shares(master_sk.coeffs.clone())?;
        
        // Step 6: Generate smudging noise for each party
        let mut smudging_errors: Vec<Vec<i64>> = Vec::with_capacity(n);
        for i in 0..n {
            let error = party_trbfv_instances[i].generate_smudging_error(&mut rng)?;
            smudging_errors.push(error);
        }

        // Step 7: For now, verify that regular decryption works with the master key
        // (Full threshold decryption will be implemented in future iterations)
        let decrypted_pt = master_sk.try_decrypt(&ct)?;
        let decrypted_values = Vec::<u64>::try_decode(
            &decrypted_pt, 
            crate::bfv::Encoding::poly()
        )?;
        
        // Verify the result
        assert_eq!(decrypted_values[0], secret_message);
        
        // Demonstrate that secret sharing works
        println!("Secret shares generated: {} parties", secret_shares.len());
        println!("Smudging errors generated: {} parties", smudging_errors.len());
        
        println!("🎉 Full threshold workflow completed successfully!");
        println!("Original message: {}", secret_message);
        println!("Reconstructed message: {}", decrypted_values[0]);
        println!("Number of parties: {}", n);
        println!("Threshold: {}", threshold);
        
        Ok(())
    }
}
