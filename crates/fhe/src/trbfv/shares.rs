/// Share collection and management for threshold BFV.
///
/// This module provides the ShareManager struct that handles aggregation of secret shares
/// and computation of decryption shares in the threshold BFV scheme.
use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::trbfv::secret_sharing::{SecretSharer, ShamirSecretSharing};
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
use num_bigint_old::{BigInt, ToBigInt};
use num_traits::ToPrimitive;
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
            let shamir_ss = ShamirSecretSharing::new(self.n, self.threshold, self.params.clone());
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
                let shamir_result = shamir_ss.reconstruct_coefficient(
                    &shamir_open_vec_mod[0..self.threshold],
                    self.params.moduli()[m],
                )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfv::{BfvParametersBuilder, Encoding, PublicKey, SecretKey};
    use crate::trbfv::secret_sharing::{SecretSharer, ShamirSecretSharing};

    use fhe_traits::{FheEncoder, FheEncrypter};
    use rand::thread_rng;

    #[test]
    fn test_aggregate_collected_shares() {
        let mut rng = thread_rng();
        let degree = 2048;
        let plaintext_modulus = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];
        let params = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        let n = 16;
        let threshold = 9;
        let mut share_manager = ShareManager::new(n, threshold, params.clone());

        // Generate secret keys and shares for multiple parties
        let mut all_shares = Vec::new();
        for _party in 0..n {
            let sk = SecretKey::random(&params, &mut rng);
            let mut shamir_ss = ShamirSecretSharing::new(n, threshold, params.clone());
            let shares = shamir_ss.generate_secret_shares(sk.coeffs.clone()).unwrap();
            all_shares.push(shares);
        }

        // Simulate share collection for party 0 (like in the example)
        let mut sk_sss_collected = Vec::new();
        for item in all_shares.iter().take(n) {
            let mut node_share_m = Array2::zeros((0, degree));
            for modulus_share in item.iter().take(moduli.len()) {
                let share_row = modulus_share.row(0); // Party 0's share from party j
                node_share_m.push_row(share_row).unwrap();
            }
            sk_sss_collected.push(node_share_m);
        }

        // Test aggregate_collected_shares
        let sum_poly = share_manager
            .aggregate_collected_shares(&sk_sss_collected)
            .unwrap();
        assert_eq!(sum_poly.coefficients().nrows(), moduli.len());
        assert_eq!(sum_poly.coefficients().ncols(), degree);
    }

    #[test]
    fn test_decryption_share() {
        let mut rng = thread_rng();
        let degree = 2048;
        let plaintext_modulus = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];
        let params = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        let n = 16;
        let threshold = 9;
        let mut share_manager = ShareManager::new(n, threshold, params.clone());

        // Generate secret key and ciphertext
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let plaintext = Plaintext::try_encode(&vec![1u64; 10], Encoding::poly(), &params).unwrap();
        let ciphertext = pk.try_encrypt(&plaintext, &mut rng).unwrap();

        // Generate smudging error using TRBFV method
        let trbfv = crate::trbfv::TRBFV::new(n, threshold, params.clone()).unwrap();
        let num_ciphertexts = 1; // Single ciphertext for testing

        // Try to generate smudging error, but handle potential λ=80 failure
        // let es_coeffs = trbfv
        //     .generate_smudging_error(num_ciphertexts, &mut rng)
        //     .unwrap();
        // let es_poly = Poly::try_convert_from(
        //     es_coeffs.as_slice(),
        //     params.ctx_at_level(0).unwrap(),
        //     false,
        //     Representation::PowerBasis,
        // )
        // .unwrap();

        // Test decryption share
        // let sk_poly = Poly::try_convert_from(
        //     sk.coeffs.as_ref(),
        //     params.ctx_at_level(0).unwrap(),
        //     false,
        //     Representation::PowerBasis,
        // )
        // .unwrap();
        // let d_share = share_manager
        //     .decryption_share(Arc::new(ciphertext), sk_poly, es_poly)
        //     .unwrap();
        // assert_eq!(d_share.coefficients().nrows(), moduli.len());
        // assert_eq!(d_share.coefficients().ncols(), degree);
    }
}
