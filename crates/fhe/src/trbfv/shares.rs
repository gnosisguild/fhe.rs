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
use itertools::Itertools;
use ndarray::Array2;
use num_bigint::BigUint;
use num_bigint::{BigInt, ToBigInt};
use num_traits::{Signed, ToPrimitive};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
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
        //Note that in case we consider in the future using qi's that are not prime numbers (so
        //they would be only satisfying the condition of being coprime to each other which is
        //sufficient for Greco etc), we can use the utility get_smallest_prime_factor implemented
        //in crates/fhe-util/src/lib.rs

        let min_modulus = params.moduli().iter().min().unwrap();
        assert!(
            n < *min_modulus as usize,
            "n must be smaller than the smallest moduli"
        );

        Self {
            n,
            threshold,
            params,
        }
    }

    /// Utility to create a Zeroizing<Poly> from coefficients.
    ///
    /// # Arguments
    /// - `coeffs`: Coefficients that can be converted to Poly (Box<[i64]>, Array2<u64>, etc.)
    /// - `ctx`: BFV context to use for the polynomial
    ///
    /// # Returns
    /// A Zeroizing<Poly> in PowerBasis representation
    pub fn coeffs_to_poly<T>(&self, coeffs: T, ctx: &Arc<Context>) -> Result<Zeroizing<Poly>, Error>
    where
        Poly: TryConvertFrom<T>,
    {
        let poly = Poly::try_convert_from(coeffs, ctx, false, Representation::PowerBasis)?;
        Ok(Zeroizing::new(poly))
    }

    /// Convenience method using level 0 context from parameters.
    pub fn coeffs_to_poly_level0<T>(&self, coeffs: T) -> Result<Zeroizing<Poly>, Error>
    where
        Poly: TryConvertFrom<T>,
    {
        let ctx = self.params.ctx_at_level(0)?;
        self.coeffs_to_poly(coeffs, ctx)
    }

    /// Convert a vector of BigInt coefficients into a Poly in full RNS representation
    /// at level 0 using the BFV context.
    pub fn bigints_to_poly(&self, bigints: &[BigInt]) -> Result<Zeroizing<Poly>, Error> {
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

        // Use the utility function instead of duplicate code
        self.coeffs_to_poly(coeff_matrix, ctx)
    }

    /// Generate Shamir Secret Shares for polynomial coefficients from a pre-converted Poly.
    pub fn generate_secret_shares_from_poly<R: RngCore + CryptoRng>(
        &mut self,
        poly: Zeroizing<Poly>,
        mut rng: R,
    ) -> Result<Vec<Array2<u64>>, Error> {
        let moduli: Vec<u64> = poly.ctx().moduli().to_vec();

        let min_modulus = moduli.iter().min().expect("moduli vector is empty");

        assert!(
            self.n < (*min_modulus).try_into().unwrap(),
            "n {} is not smaller than the smallest modulus {}, the MPC protocol implemented assumes that n is smaller than the smallest moduli defining the ciphertext space",
            self.n,
            min_modulus
        );

        let coefficients = poly.coefficients();
        let coeff_rows: Vec<_> = coefficients.outer_iter().collect();

        // Generate seeds deterministically from the input RNG
        let seeds: Vec<u64> = (0..moduli.len()).map(|_| rng.gen()).collect();

        let return_vec: Result<Vec<Array2<u64>>, Error> = moduli
            .par_iter()
            .zip(coeff_rows.par_iter())
            .enumerate()
            .map(|(i, (m, p))| -> Result<Array2<u64>, Error> {
                // Get rng from seed
                let rng = ChaCha20Rng::seed_from_u64(seeds[i]);

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

                    let c_shares = shamir.split(secret.clone(), rng.clone());
                    // For each share convert to u64
                    let mut c_vec: Vec<u64> = Vec::with_capacity(self.n);
                    for (_, c_share) in c_shares.iter() {
                        c_vec.push(c_share.to_u64().unwrap());
                    }
                    m_data.extend_from_slice(&c_vec);
                }

                // convert flat vector of coeffs to array2
                let arr_matrix = Array2::from_shape_vec((self.params.degree(), self.n), m_data)
                    .map_err(|_| {
                        Error::DefaultError("Failed to create coefficient matrix".to_string())
                    })?;
                // reverse the columns and rows
                let reversed_axes = arr_matrix.t();
                Ok(reversed_axes.to_owned())
            })
            .collect();

        return_vec
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
        let ctx = self.params.ctx_at_level(0).unwrap();

        let sum_poly = sk_sss_collected
            .par_iter()
            .take(self.n)
            .map(|item| {
                let mut poly_j = Poly::zero(ctx, Representation::PowerBasis);
                poly_j.set_coefficients(item.clone());
                poly_j
            })
            .reduce(
                || Poly::zero(ctx, Representation::PowerBasis),
                |acc, poly| &acc + &poly,
            );

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
        if d_share_polys.len() < (self.threshold + 1) {
            return Err(Error::insufficient_shares(
                d_share_polys.len(),
                self.threshold + 1,
            ));
        }
        let m_data: Vec<u64> = (0..self.params.moduli().len())
            .into_par_iter()
            .flat_map(|m| {
                let shamir_ss = ShamirSecretSharing::new(
                    self.threshold,
                    self.n,
                    BigInt::from(self.params.moduli[m]),
                );

                // Parallelize coefficient recovery within each modulus
                (0..self.params.degree())
                    .into_par_iter()
                    .map(|i| {
                        let mut shamir_open_vec_mod: Vec<(usize, BigInt)> =
                            Vec::with_capacity(self.params.degree());
                        for (j, d_share_poly) in
                            d_share_polys.iter().enumerate().take(self.threshold + 1)
                        {
                            let coeffs = d_share_poly.coefficients();
                            let coeff_arr = coeffs.row(m);
                            let coeff = coeff_arr[i];
                            let coeff_formatted = (j + 1, coeff.to_bigint().unwrap());
                            shamir_open_vec_mod.push(coeff_formatted);
                        }
                        let shamir_result =
                            shamir_ss.recover(&shamir_open_vec_mod[0..self.threshold + 1]);
                        shamir_result.to_u64().unwrap()
                    })
                    .collect::<Vec<u64>>()
            })
            .collect();

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

        let scalers: Result<Vec<_>, Error> = (0..self.params.moduli().len())
            .into_par_iter()
            .map(|i| {
                let rns = RnsContext::new(&self.params.moduli()[..self.params.moduli().len() - i])
                    .map_err(Error::MathError)?;
                let ctx_i = Context::new_arc(
                    &self.params.moduli()[..self.params.moduli().len() - i],
                    self.params.degree(),
                )
                .map_err(Error::MathError)?;
                Ok(Scaler::new(
                    &ctx_i,
                    &plaintext_ctx,
                    ScalingFactor::new(&BigUint::from(self.params.plaintext()), rns.modulus()),
                )
                .unwrap())
            })
            .collect();
        let scalers = scalers?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfv::{BfvParametersBuilder, Encoding, PublicKey, SecretKey};
    use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
    use rand::{rngs::OsRng, thread_rng};

    fn test_params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(4096)
            .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
            .build_arc()
            .unwrap()
    }

    #[test]
    fn test_share_manager_creation() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone());
        assert_eq!(manager.n, 5);
        assert_eq!(manager.threshold, 2);
        assert_eq!(manager.params, params);
    }

    #[test]
    fn test_coeffs_to_poly_utility() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone());

        // Test with i64 coefficients
        let coeffs = vec![1i64, 2, 3, 4].into_boxed_slice();
        let ctx = params.ctx_at_level(0).unwrap();
        let poly = manager.coeffs_to_poly(coeffs.as_ref(), ctx).unwrap();
        assert_eq!(poly.ctx(), ctx);

        // Test convenience method
        let coeffs2 = vec![5i64, 6, 7, 8].into_boxed_slice();
        let poly2 = manager.coeffs_to_poly_level0(coeffs2.as_ref()).unwrap();
        assert_eq!(poly2.ctx(), ctx);
    }

    #[test]
    fn test_bigints_to_poly() {
        let params = test_params();
        let manager = ShareManager::new(5, 3, params.clone());

        // Create BigInt coefficients (full degree)
        let degree = params.degree();
        let bigints: Vec<BigInt> = (0..degree).map(|i| BigInt::from(i as i64)).collect();

        let poly = manager.bigints_to_poly(&bigints).unwrap();
        assert_eq!(poly.coefficients().ncols(), degree);
        assert_eq!(poly.coefficients().nrows(), params.moduli().len());
    }

    #[test]
    fn test_bigints_to_poly_wrong_size() {
        let params = test_params();
        let manager = ShareManager::new(5, 2, params.clone());

        // Wrong number of coefficients
        let bigints = vec![BigInt::from(1), BigInt::from(2)]; // Too few
        let result = manager.bigints_to_poly(&bigints);
        assert!(result.is_err());
    }

    #[test]
    fn test_decryption_share_computation() {
        let mut rng = thread_rng();
        let params = test_params();
        let n = 3;
        //Fix threshold to be 0 for the purpose of this test so that any single party can decrypt.
        //I.e., the secret key is given to all parties and not secret shared
        let threshold = 0;
        let mut manager = ShareManager::new(n.try_into().unwrap(), threshold, params.clone());

        // Setup: Generate keys and encrypt a plaintext
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let mut plaintext_data = vec![42u64, 100, 400];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct: Arc<Ciphertext> = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());
        //let ct = pk.try_encrypt(&pt, &mut rng).unwrap();

        // Generate polynomials for decryption share
        let sk_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
        let ctx = params.ctx_at_level(0).unwrap();
        //Setting smuding noise to be zero in this test
        let es_poly = Poly::zero(ctx, Representation::PowerBasis);

        // Compute decryption share
        let decryption_share = manager
            .decryption_share(ct.clone(), (*sk_poly).clone(), es_poly)
            .unwrap();

        let shares = vec![decryption_share.clone()];

        let result = manager.decrypt_from_shares(shares, ct);
        let plaintext_found = result.expect("Failed to decrypt from shares");

        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");

        assert_eq!(decoded, plaintext_data);
    }

    #[test]
    fn test_threshold_decryption_workflow() {
        let mut rng = OsRng;
        let params = test_params();
        let n = 3;
        let threshold = 1;

        let ctx = params.ctx_at_level(0).unwrap();

        // Setup multiple share managers (simulating different parties)
        let mut managers: Vec<ShareManager> = (0..n)
            .map(|_| ShareManager::new(n, threshold, params.clone()))
            .collect();

        // One party generates the secret key and secret shares it among the other parties
        let secret_key = SecretKey::random(&params, &mut rng);

        let sk_poly = managers[0]
            .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
            .unwrap();

        let sk_sss = managers[0]
            .generate_secret_shares_from_poly(sk_poly, rng)
            .unwrap();

        let mut sk_sss_collected: Vec<Vec<Array2<u64>>> = vec![vec![], vec![], vec![]];

        let mut sk_poly_sums: Vec<Poly> = (0..n)
            .map(|_| Poly::zero(ctx, Representation::PowerBasis))
            .collect();

        for i in 0..n {
            let mut node_share_m = Array2::zeros((0, params.degree()));
            for sk_sss_m in sk_sss.iter().take(params.moduli().len()) {
                node_share_m
                    .push_row(ndarray::ArrayView::from(sk_sss_m.row(i)))
                    .unwrap();
            }
            sk_sss_collected[i].push(node_share_m);

            let share_slice: &[Array2<u64>] = &sk_sss_collected[i];
            sk_poly_sums[i] = managers[i].aggregate_collected_shares(share_slice).unwrap();
        }

        // Create a test ciphertext
        let pk = PublicKey::new(&secret_key, &mut rng);
        let mut plaintext_data = vec![123u64];
        plaintext_data.resize(params.degree(), 0);
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Each party generates their decryption share
        let mut decryption_shares = Vec::new();

        //Testing for decryption between parties 0 and 1
        //TODO Add tests for decyption between different parties than the first ones
        for i in 0..(threshold + 1) {
            let ctx = params.ctx_at_level(0).unwrap();
            //Setting smuding noise to be zero in this test
            let es_poly = Poly::zero(ctx, Representation::PowerBasis);

            let share = managers[i]
                .decryption_share(ct.clone(), sk_poly_sums[i].clone(), es_poly)
                .unwrap();
            decryption_shares.push(share);
        }

        // Verify we have enough shares
        assert_eq!(decryption_shares.len(), threshold + 1);

        // Test decrypt_from_shares
        let result = managers[0].decrypt_from_shares(decryption_shares.clone(), ct.clone());
        assert!(result.is_ok());

        // Test if we had correct decyption
        let plaintext_found = result.expect("Failed to decrypt from shares");
        let decoded: Vec<u64> = Vec::<u64>::try_decode(&plaintext_found, Encoding::poly())
            .expect("Decoding plaintext failed");

        assert_eq!(decoded, plaintext_data);
    }
}
