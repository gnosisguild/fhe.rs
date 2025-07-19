/// Share collection and management for threshold BFV.
///
/// This module provides the ShareManager struct that handles aggregation of secret shares
/// and computation of decryption shares in the threshold BFV scheme.
use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::trbfv::shamir::ShamirSecretSharing;
use crate::Error;
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::zq::Modulus;
use fhe_math::{
    rns::{RnsContext, ScalingFactor},
    rq::{scaler::Scaler, Context, Poly, Representation},
};
use itertools::izip;
use itertools::Itertools;
use ndarray::Array2;
use num_bigint::BigUint;
use num_bigint::{BigInt, ToBigInt};
use num_traits::{Signed, ToPrimitive};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Manager for threshold BFV share operations.
///
/// ShareManager coordinates the collection and processing of secret shares in the threshold BFV scheme.
/// It handles both the aggregation of collected shares and the computation of decryption shares.
///
/// # Protocol Flow
/// 1. Each party generates secret shares using secret sharing
/// 2. Parties exchange shares through secure channels
/// 3. ShareManager aggregates collected shares to reconstruct partial secrets
/// 4. During decryption, ShareManager computes decryption shares from ciphertext
/// 5. Finally, threshold number of decryption shares are combined to decrypt
#[derive(Debug)]
pub struct ShareManager {
    /// Number of parties in the threshold scheme
    pub n: usize,
    /// Threshold for reconstruction (minimum shares needed)
    pub threshold: usize,
    /// BFV parameters (degree, moduli, etc.)
    pub params: Arc<BfvParameters>,
}

impl ShareManager {
    /// Create a new share manager.
    ///
    /// # Arguments
    /// - `n`: Total number of parties
    /// - `threshold`: Minimum number of shares required for reconstruction
    /// - `params`: BFV parameters
    pub fn new(n: usize, threshold: usize, params: Arc<BfvParameters>) -> Self {
        Self {
            n,
            threshold,
            params,
        }
    }

    /// Convert a vector of BigInt coefficients into a Poly in full RNS representation
    /// at level 0 using the BFV context.
    pub fn bigints_to_poly(&self, bigints: &[BigInt]) -> Result<Poly, Error> {
        // Get level 0 context (all moduli)
        let ctx = self.params.ctx_at_level(0)?; // full modulus level

        let d = self.params.degree();
        if bigints.len() != d {
            return Err(Error::DefaultError(format!(
                "Expected {} coefficients, got {}",
                d,
                bigints.len()
            )));
        }

        // Moduli from context
        let moduli = ctx.moduli();

        // Create a matrix: rows = moduli, cols = coefficients
        // Shape: (num_moduli, degree)
        let mut coeffs_rns = vec![0u64; moduli.len() * d];

        for (col, coeff) in bigints.iter().enumerate() {
            for (row, &modulus) in moduli.iter().enumerate() {
                // Reduce coefficient mod q_i
                let mut reduced = coeff % BigInt::from(modulus);
                if reduced.is_negative() {
                    reduced += BigInt::from(modulus);
                }
                let u64_value = reduced
                    .to_u64()
                    .ok_or_else(|| Error::DefaultError("Residue doesn't fit in u64".to_string()))?;

                coeffs_rns[row * d + col] = u64_value;
            }
        }

        // Convert flat vector into Array2<u64> with shape (num_moduli, n)
        let coeff_matrix = ndarray::Array2::from_shape_vec((moduli.len(), d), coeffs_rns)
            .map_err(|_| Error::DefaultError("Failed to create coefficient matrix".to_string()))?;

        // Build Poly with RNS representation
        let poly = Zeroizing::new(
            Poly::try_convert_from(
                coeff_matrix,
                &ctx.clone(),
                false,
                Representation::PowerBasis,
            )
            .unwrap(),
        );

        Ok((*poly).clone())
    }

    /// Generate Shamir Secret Shares for polynomial coefficients.
    pub fn generate_secret_shares(
        &mut self,
        coeffs: Box<[i64]>,
    ) -> Result<Vec<Array2<u64>>, Error> {
        let poly = Zeroizing::new(
            Poly::try_convert_from(
                coeffs.as_ref(),
                self.params.ctx_at_level(0).unwrap(),
                false,
                Representation::PowerBasis,
            )
            .unwrap(),
        );

        // 2 dim array, columns = fhe coeffs (degree), rows = party members shamir share coeff (n)
        let mut return_vec: Vec<Array2<u64>> = Vec::with_capacity(self.params.moduli.len());

        // for each moduli, for each coeff generate an SSS of degree n and threshold n = 2t + 1
        for (m, p) in izip!(poly.ctx().moduli().iter(), poly.coefficients().outer_iter()) {
            // Create shamir object
            let shamir = ShamirSecretSharing {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(*m),
            };
            let mut m_data: Vec<u64> = Vec::new();

            // For each coeff in the polynomial p under the current modulus m
            for c in p.iter() {
                // Split the coeff into n shares
                let secret = c.to_bigint().unwrap();
                let c_shares = shamir.split(secret.clone());
                // For each share convert to u64
                let mut c_vec: Vec<u64> = Vec::with_capacity(self.n);
                for (_, c_share) in c_shares.iter() {
                    c_vec.push(c_share.to_u64().unwrap());
                }
                m_data.extend_from_slice(&c_vec);
            }
            // convert flat vector of coeffs to array2
            let arr_matrix =
                Array2::from_shape_vec((self.params.degree(), self.n), m_data).unwrap();
            // reverse the columns and rows
            let reversed_axes = arr_matrix.t();
            return_vec.push(reversed_axes.to_owned());
        }
        // return vec = rows are party members, columns are degree length of shamir values
        Ok(return_vec)
    }

    /// Generate Shamir Secret Shares for polynomial coefficients from a pre-converted Poly.
    pub fn generate_secret_shares_from_poly(
        &mut self,
        poly: Poly,
    ) -> Result<Vec<Array2<u64>>, Error> {
        // 2 dim array, columns = fhe coeffs (degree), rows = party members shamir share coeff (n)
        let mut return_vec: Vec<Array2<u64>> = Vec::with_capacity(self.params.moduli.len());

        // for each moduli, for each coeff generate an SSS of degree n and threshold n = 2t + 1
        for (m, p) in izip!(poly.ctx().moduli().iter(), poly.coefficients().outer_iter()) {
            // Create shamir object
            let shamir = ShamirSecretSharing {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(*m),
            };
            let mut m_data: Vec<u64> = Vec::new();

            // For each coeff in the polynomial p under the current modulus m
            for c in p.iter() {
                // Split the coeff into n shares
                let secret = c.to_bigint().unwrap();
                let c_shares = shamir.split(secret.clone());
                // For each share convert to u64
                let mut c_vec: Vec<u64> = Vec::with_capacity(self.n);
                for (_, c_share) in c_shares.iter() {
                    c_vec.push(c_share.to_u64().unwrap());
                }
                m_data.extend_from_slice(&c_vec);
            }
            // convert flat vector of coeffs to array2
            let arr_matrix =
                Array2::from_shape_vec((self.params.degree(), self.n), m_data).unwrap();
            // reverse the columns and rows
            let reversed_axes = arr_matrix.t();
            return_vec.push(reversed_axes.to_owned());
        }
        // return vec = rows are party members, columns are degree length of shamir values
        Ok(return_vec)
    }
    /// Aggregate collected secret sharing shares to compute SK_i polynomial sum.
    ///
    /// This function takes shares collected from other parties and aggregates them
    /// to reconstruct the sum of secret key polynomials (SK_i) needed for decryption.
    ///
    /// # Arguments
    /// - `sk_sss_collected`: Vector of secret shares collected from other parties
    ///   Each Array2<u64> contains shares for all moduli and polynomial coefficients
    ///
    /// # Returns
    /// A polynomial representing the aggregated secret key material
    pub fn aggregate_collected_shares(
        &mut self,
        sk_sss_collected: &[Array2<u64>], // collected sk sss shares from other parties
    ) -> Result<Poly, Error> {
        let mut sum_poly = Poly::zero(
            self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        for item in sk_sss_collected.iter().take(self.n) {
            // Initialize empty poly with correct context (moduli and level)
            let mut poly_j = Poly::zero(
                self.params.ctx_at_level(0).unwrap(),
                Representation::PowerBasis,
            );
            poly_j.set_coefficients(item.clone());
            sum_poly = &sum_poly + &poly_j;
        }
        Ok(sum_poly)
    }

    /// Compute decryption share from ciphertext and secret/smudging polynomials.
    ///
    /// This function computes a party's contribution to the threshold decryption process.
    /// Each party uses their secret key share and smudging noise to compute a decryption share.
    ///
    /// # Arguments
    /// - `ciphertext`: The ciphertext to decrypt (contains c0, c1 polynomials)
    /// - `sk_i`: This party's secret key polynomial
    /// - `es_i`: This party's smudging error polynomial
    ///
    /// # Returns
    /// A decryption share polynomial that contributes to the final decryption
    pub fn decryption_share(
        &mut self,
        ciphertext: Arc<Ciphertext>,
        mut sk_i: Poly,
        es_i: Poly,
    ) -> Result<Poly, Error> {
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
        //let d_share_poly = &c0 + &c1sk;
        Ok(d_share_poly)
    }

    /// Decrypt ciphertext from collected decryption shares (threshold number required).
    ///
    /// This function performs the final step of threshold decryption by combining
    /// decryption shares from at least `threshold` parties to reconstruct the plaintext.
    ///
    /// # Arguments
    /// - `d_share_polys`: Vector of decryption shares from different parties
    /// - `ciphertext`: The original ciphertext being decrypted
    ///
    /// # Returns
    /// The decrypted plaintext
    pub fn decrypt_from_shares(
        &mut self,
        d_share_polys: Vec<Poly>,
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext, Error> {
        // Validate we have enough shares
        if d_share_polys.len() < self.threshold {
            return Err(Error::insufficient_shares(
                d_share_polys.len(),
                self.threshold,
            ));
        }
        let mut m_data: Vec<u64> = Vec::new();

        // collect shamir openings
        for m in 0..self.params.moduli().len() {
            let shamir_ss = ShamirSecretSharing::new(
                self.threshold,
                self.n,
                BigInt::from(self.params.moduli[m]),
            );
            for i in 0..self.params.degree() {
                let mut shamir_open_vec_mod: Vec<(usize, BigInt)> =
                    Vec::with_capacity(self.params.degree());
                for (j, d_share_poly) in d_share_polys.iter().enumerate().take(self.threshold) {
                    let coeffs = d_share_poly.coefficients();
                    let coeff_arr = coeffs.row(m);
                    let coeff = coeff_arr[i];
                    let coeff_formatted = (j + 1, coeff.to_bigint().unwrap());
                    shamir_open_vec_mod.push(coeff_formatted);
                }
                let shamir_result =
                    shamir_ss.recover(&shamir_open_vec_mod[0..self.threshold as usize]);
                m_data.push(shamir_result.to_u64().unwrap());
            }
        }

        // scale result poly
        let arr_matrix =
            Array2::from_shape_vec((self.params.moduli().len(), self.params.degree()), m_data)
                .unwrap();
        let mut result_poly = Poly::zero(
            self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        result_poly.set_coefficients(arr_matrix);

        let plaintext_ctx = Context::new_arc(&self.params.moduli()[..1], self.params.degree())
            .map_err(Error::MathError)?;
        let mut scalers = Vec::with_capacity(self.params.moduli().len());
        for i in 0..self.params.moduli().len() {
            let rns = RnsContext::new(&self.params.moduli()[..self.params.moduli().len() - i])
                .map_err(Error::MathError)?;
            let ctx_i = Context::new_arc(
                &self.params.moduli()[..self.params.moduli().len() - i],
                self.params.degree(),
            )
            .map_err(Error::MathError)?;
            scalers.push(
                Scaler::new(
                    &ctx_i,
                    &plaintext_ctx,
                    ScalingFactor::new(&BigUint::from(self.params.plaintext()), rns.modulus()),
                )
                .unwrap(),
            );
        }

        let par = ciphertext.par.clone();
        let d = Zeroizing::new(
            result_poly
                .scale(&scalers[ciphertext.level])
                .map_err(Error::MathError)?,
        );
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
            Poly::try_convert_from(&w, ciphertext.c[0].ctx(), false, Representation::PowerBasis)
                .map_err(Error::MathError)?;
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
