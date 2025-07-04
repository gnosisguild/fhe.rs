use std::sync::Arc;

use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::trbfv::traits::{SecretSharer, SmudgingGenerator};
use crate::Error;
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

/// Threshold BFV configuration and operations.
///
/// This struct manages threshold secret sharing for BFV homomorphic encryption,
/// enabling distributed decryption among multiple parties where only a threshold
/// number of parties are needed to reconstruct the plaintext.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TRBFV {
    /// Number of parties
    pub n: usize,
    /// Threshold for reconstruction (must be < n)
    pub threshold: usize,
    /// Variance for smudging noise generation
    pub smudging_variance: usize,
    /// BFV parameters (contains degree, plaintext_modulus, moduli, etc.)
    pub params: Arc<BfvParameters>,
}

impl TRBFV {
    /// Creates a new threshold BFV configuration.
    ///
    /// # Arguments
    /// * `n` - Number of parties
    /// * `threshold` - Threshold for reconstruction (must be < n)
    /// * `smudging_variance` - Variance for smudging noise generation
    /// * `params` - BFV parameters
    pub fn new(
        n: usize,
        threshold: usize,
        smudging_variance: usize,
        params: Arc<BfvParameters>,
    ) -> Result<Self, Error> {
        // Validate threshold configuration
        if n == 0 {
            return Err(Error::invalid_party_count(n, 1));
        }
        if threshold >= n {
            return Err(Error::threshold_too_large(threshold, n));
        }
        if threshold == 0 {
            return Err(Error::UnspecifiedInput(
                "Threshold must be at least 1".to_string(),
            ));
        }

        Ok(Self {
            n,
            threshold,
            smudging_variance,
            params,
        })
    }

    /// Generate Shamir Secret Shares for polynomial coefficients.
    pub fn generate_secret_shares(
        &mut self,
        coeffs: Box<[i64]>,
    ) -> Result<Vec<Array2<u64>>, Error> {
        let poly = Zeroizing::new(
            Poly::try_convert_from(
                coeffs.as_ref(),
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
            let arr_matrix = Array2::from_shape_vec((self.params.degree(), self.n), m_data).unwrap();
            // reverse the columns and rows
            let reversed_axes = arr_matrix.t();
            return_vec.push(reversed_axes.to_owned());
        }
        // return vec = rows are party members, columns are degree length of shamir values
        Ok(return_vec)
    }

    /// Aggregate collected secret sharing shares to compute summed SK_i polynomial.
    pub fn sum_sk_i(
        &mut self,
        sk_sss_collected: &Vec<Array2<u64>>, // collected sk sss shares from other parties
    ) -> Result<Poly, Error> {
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

    /// Generate smudging error coefficients for noise.
    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<i64>, Error> {
        // For each party, generate local smudging noise, coeffs of of degree N − 1 with coefficients
        // in [−Bsm, Bsm]
        let s_coefficients = sample_vec_normal(self.params.degree(), self.smudging_variance, rng)
            .map_err(|e| Error::smudging(format!("Failed to generate smudging noise: {}", e)))?;
        Ok(s_coefficients)
    }

    /// Compute decryption share from ciphertext and secret/smudging polynomials.
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
    pub fn decrypt(
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
            let sss = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(self.params.moduli()[m]),
            };
            for i in 0..self.params.degree() {
                let mut shamir_open_vec_mod: Vec<(usize, BigInt)> = Vec::with_capacity(self.params.degree());
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
        let arr_matrix = Array2::from_shape_vec((self.params.moduli().len(), self.params.degree()), m_data).unwrap();
        let mut result_poly = Poly::zero(
            &self.params.ctx_at_level(0).unwrap(),
            Representation::PowerBasis,
        );
        result_poly.set_coefficients(arr_matrix);

        let plaintext_ctx = Context::new_arc(&self.params.moduli()[..1], self.params.degree()).unwrap();
        let mut scalers = Vec::with_capacity(self.params.moduli().len());
        for i in 0..self.params.moduli().len() {
            let rns = RnsContext::new(&self.params.moduli()[..self.params.moduli().len() - i]).unwrap();
            let ctx_i =
                Context::new_arc(&self.params.moduli()[..self.params.moduli().len() - i], self.params.degree()).unwrap();
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
                .map_err(|e| Error::MathError(e))?,
        );
        let v = Zeroizing::new(
            Vec::<u64>::from(d.as_ref())
                .iter_mut()
                .map(|vi| *vi + par.plaintext.modulus())
                .collect_vec(),
        );
        let mut w = v[..par.degree()].to_vec();
        let q = Modulus::new(par.moduli[0]).map_err(|e| Error::MathError(e))?;
        q.reduce_vec(&mut w);
        par.plaintext.reduce_vec(&mut w);

        let mut poly =
            Poly::try_convert_from(&w, ciphertext.c[0].ctx(), false, Representation::PowerBasis)
                .map_err(|e| Error::MathError(e))?;
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

// Implement the secret sharing traits
impl SecretSharer for TRBFV {
    fn generate_secret_shares(&mut self, coeffs: Box<[i64]>) -> Result<Vec<Array2<u64>>, Error> {
        self.generate_secret_shares(coeffs)
    }
}

impl SmudgingGenerator for TRBFV {
    fn generate_smudging_error<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<Vec<i64>, Error> {
        self.generate_smudging_error(rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfv::{BfvParametersBuilder, PublicKey, SecretKey};
    use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
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
        let mut trbfv = TRBFV::new(n, threshold, 160, sk_par.clone()).unwrap();
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

        // For each party, generate public key contribution from sk, this will be broadcast publicly
        let pk_share = PublicKey::new(&sk_share, &mut rng);

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
    fn test_validation_errors() {
        let degree = 2048;
        let plaintext_modulus: u64 = 4096;
        let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];

        let params = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();

        // Test: Zero parties should fail
        let result = TRBFV::new(
            0,
            3,
            160,
            params.clone(),
        );
        assert!(matches!(result, Err(Error::TooFewValues(0, 1))));

        // Test: Threshold >= parties should fail
        let result = TRBFV::new(
            5,
            5,
            160,
            params.clone(),
        );
        assert!(matches!(
            result,
            Err(Error::UnspecifiedInput(ref msg)) if msg.contains("Threshold 5 must be less than number of parties 5")
        ));

        // Test: Zero threshold should fail
        let result = TRBFV::new(
            5,
            0,
            160,
            params.clone(),
        );
        assert!(matches!(
            result,
            Err(Error::UnspecifiedInput(ref msg)) if msg.contains("Threshold must be at least 1")
        ));

        // Test: Inconsistent degree should fail
        let result = TRBFV::from_params(
            5,
            3,
            1024,
            plaintext_modulus,
            160,
            moduli.clone(),
            params.clone(),
        );
        assert!(matches!(
            result,
            Err(Error::UnspecifiedInput(ref msg)) if msg.contains("Inconsistent polynomial degree: expected 2048, found 1024")
        ));

        // Test: Inconsistent moduli count should fail
        let wrong_moduli = vec![0xffffee001, 0xffffc4001]; // Missing one modulus
        let result = TRBFV::from_params(
            5,
            3,
            degree,
            plaintext_modulus,
            160,
            wrong_moduli,
            params.clone(),
        );
        assert!(matches!(
            result,
            Err(Error::UnspecifiedInput(ref msg)) if msg.contains("Inconsistent moduli: expected 3 moduli, found 2")
        ));

        // Test: Valid parameters should succeed
        let result = TRBFV::new(
            5,
            3,
            160,
            params.clone(),
        );
        assert!(result.is_ok());
    }
}
