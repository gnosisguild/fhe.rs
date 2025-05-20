use std::{sync::Arc};

use crate::bfv::{PublicKey, SecretKey, Ciphertext, BfvParameters};
use zeroize::{Zeroizing};
use fhe_util::sample_vec_cbd_unbounded;
use crate::errors::Result;
use rand::{CryptoRng, RngCore};
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use num_bigint_old::{BigInt, ToBigInt};
use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
use num_traits::ToPrimitive;
use itertools::{izip, zip};
use ndarray::{array, Array2, Array3, Axis};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TrBFVShare {
    n: usize,
    threshold: usize,
    degree: usize,
    sumdging_variance: u64,
    moduli: Vec<u64>
}

impl TrBFVShare {
    // TODO: take params and store, get moduli and dgree from ctx
    pub fn new(
        n: usize,
        threshold: usize,
        degree: usize,
        sumdging_variance: u64,
        moduli: Vec<u64>
    ) -> Result<Self> {
        // generate random secret
        Ok(Self { 
            n,
            threshold,
            degree,
            sumdging_variance,
            moduli
        })
    }

    pub fn gen_sss_shares(
        degree: usize, // todo get this from self
        threshold: usize, // todo get this from self
        share_amount: usize,
        prime: BigInt,
        coeffs: Vec<i64>
    ) -> Result<Vec<Vec<(usize, BigInt)>>> {
        // Shamir secret share params
        let sss = SSS {
            threshold: threshold,
            share_amount: share_amount,
            prime: prime
        };
        // for each coeff generate an SSS of degree n and threshold n = 2t + 1
        let mut result: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(degree);

        for i in 0..degree {
            let secret = coeffs[i as usize].to_bigint().unwrap();
            // Tnegative coeffs are encoded as positive ints [11,19]
            let shares = sss.split(secret.clone());
            result.push(shares);
        }
        Ok(result)
    }

    pub fn gen_sk_poly(
        sk: SecretKey,
        params: BfvParameters
    ) -> Result<Zeroizing<Poly>> {
        // convert sk into polynomial RNS form
        let mut sk_poly = Zeroizing::new(Poly::try_convert_from(
            sk.coeffs.as_ref(),
            &params.ctx_at_level(0).unwrap(),
            false,
            Representation::PowerBasis,
        ).unwrap());
        Ok(sk_poly)
    }

    // convert_poly_to_shares
    pub fn gen_sss_shares_v2(
        &mut self,
        params: Arc<BfvParameters>,
        sk: SecretKey
    ) -> Result<Vec<(Array2<u64>)>> {
        let mut poly = Zeroizing::new(Poly::try_convert_from(
            sk.coeffs.as_ref(),
            &params.ctx_at_level(0).unwrap(),
            false,
            Representation::PowerBasis,
        ).unwrap());

        // 2 dim array, rows = fhe coeffs (degree), columns = party members shamir share coeff (n)
        //let mut shamir_coeffs: Vec<Vec<u64>> = Vec::with_capacity(self.degree * params.moduli.len()); // TODO: need to store m of these
        let mut return_vec: Vec<Array2<u64>> = Vec::with_capacity(params.moduli.len());
        //let mut a = Array3::<u64>::zeros([3, 4, 2]);

        // for each coeff generate an SSS of degree n and threshold n = 2t + 1
        for (k, (m, p)) in izip!(poly.ctx().moduli().iter(), poly.coefficients().outer_iter()).enumerate() {
            // Create shamir object
            let shamir = SSS {
                threshold: self.threshold,
                share_amount: self.n,
                prime: BigInt::from(*m)
            };
            let mut m_data: Vec<u64> = Vec::new();

            // For each coeff in the polynomial p under the current modulus m
            for (i, c) in p.iter().enumerate() {
                // Split the coeff into n shares
                let secret = c.to_bigint().unwrap();
                let c_shares = shamir.split(secret.clone());
                // For each share convert to u64
                let mut c_vec: Vec<u64> = Vec::with_capacity(self.n);
                for (j, (_, c_share)) in c_shares.iter().enumerate() {
                    c_vec.push(c_share.to_u64().unwrap());
                }
                m_data.extend_from_slice(&c_vec);
                //shamir_coeffs.push(c_vec);
            }
            let arr_matrix = Array2::from_shape_vec((self.degree, self.n), m_data).unwrap();
            let reversed_axes = arr_matrix.t();
            return_vec.push(reversed_axes.to_owned());
        }
        Ok(return_vec)
    }

    // This is only for one moduli, call this moduli.len times?
    pub fn convert_shares_to_polys(
        &mut self,
        modulus: u64,
        secret_share_coeffs: &Vec<Vec<u64>>, // num_party shares of u64 shamir coeffs
    ) -> Result<Vec<Poly>> {
        //let mut s_shares: Vec<Poly> = vec![Poly::zero(&sk_par.ctx_at_level(0).unwrap(), Representation::PowerBasis); n]; // think we need m of these
        //s_shares[j].coefficients_mut()[k][i] = c_share.to_u64().unwrap();
        //create array2 from vec<vec<u64>
        //s_shares[j].set_coefficients(array2);

        // moduli.len * share_amount * degree // do this a level up
        let ctx_m = Context::new_arc(&[modulus], self.degree).unwrap();
        // for each modulus there are num_party vecs of degree coeff length u64 shamir coeffs
        let mut s_share_polys: Vec<Poly> = Vec::with_capacity(self.n);
        for i in 0..self.n {
            let mut s_share_poly = Poly::try_convert_from(
                &secret_share_coeffs[i],
                &ctx_m,
                false,
                Representation::PowerBasis,
            ).unwrap();
            s_share_polys.push(s_share_poly)
        }
        // return vec of num_party polys
        Ok(s_share_polys)
    }

    pub fn gen_smudging_error<R: RngCore + CryptoRng>(
        degree: usize, // todo get this from self
        variance: usize, // todo get this from self
        rng: &mut R
    ) -> Result<Vec<i64>> {
        // For each party, generate local smudging noise, coeffs of of degree N − 1 with coefficients
        // in [−Bsm, Bsm]
        let s_coefficients = sample_vec_cbd_unbounded(degree, variance, rng).unwrap();
        Ok(s_coefficients)
    }

    // assumes variance is 19, todo: variable variance
    // no need for this, once raw secret coeffs are input into poly, poly will mod negative values out
    pub fn encode_coeffs(coeffs: &mut Vec<i64>) -> Result<Vec<i64>> {
        for i in 0..coeffs.len() {
            // encode negative coeffs as positive ints [11,19]
            if coeffs[i] < 0 {
                coeffs[i] = coeffs[i] + 19;
            }
        }
        Ok(coeffs.to_vec())
    }

    pub fn decode_coeffs(coeffs: &mut Vec<i64>) -> Result<Vec<i64>> {
        for i in 0..coeffs.len() {
            // encode negative coeffs as positive ints [11,19]
            if coeffs[i] > 9 {
                coeffs[i] = coeffs[i] - 19;
            }
        }
        Ok(coeffs.to_vec())
    }

    // todo: generate sharabe set (simply get nodes id(index) from the vector to send to all other nodes)

    pub fn decryption_share(ciphertext: Arc<Ciphertext>, smudge: Vec<(BigInt)>, sk: Vec<(BigInt)>) -> Result<i64> {
        // sum c0 + c1
        let mut c0c1 = ciphertext.c[0].as_ref() + &ciphertext.c[1];
        // mul c0 + c1 * sk
        //let poly_sk = Poly::try_convert_from(m_v.as_ref(), ctx, false, Representation::PowerBasis).unwrap();
        //poly_sk.change_representation(Representation::Ntt);
        //Poly::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time
        //let cxs = c0c1 * &sk;
        //println!("{:?}", sk[0]);
        // add esm
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::{izip, zip};
    use rand::thread_rng;
    use crate::bfv::{BfvParametersBuilder, SecretKey};
    use zeroize::{Zeroizing};
    use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
    use num_traits::ToPrimitive;
    use ndarray::{array, Array, Array2, Axis, concatenate, ArrayView};

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
        ).unwrap();


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
        for (k, (m, p)) in izip!(s.ctx().moduli().iter(), s.coefficients().outer_iter()).enumerate() {
            // Create shamir object
            let shamir = SSS {
                threshold: threshold,
                share_amount: n,
                prime: BigInt::from(*m)
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
            node_n_shares_all_mods.push_row(ArrayView::from(&node_n_share_one_mod)).unwrap();
            node_n_shares_all_mods.push_row(ArrayView::from(&node_n_share_one_mod)).unwrap();
            node_n_shares_all_mods.push_row(ArrayView::from(&node_n_share_one_mod)).unwrap();
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
                ).unwrap();
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
        let mut trbfv = TrBFVShare::new(n, threshold, degree, 9, moduli.clone()).unwrap();
        let get_coeff_matrix = trbfv.gen_sss_shares_v2(sk_par.clone(), s_raw.clone()).unwrap();
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
            prime: BigInt::from(rns_mod_i)
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
        ).unwrap();
        let mut s2_share_poly = Poly::try_convert_from(
            u64shamirvec_2,
            &sk_par.ctx_at_level(0).unwrap(),
            false,
            Representation::PowerBasis,
        ).unwrap();

        // Add the two shamir polynomials
        let sum_shamir = &s1_share_poly + &s2_share_poly;
        //let mul_shamir = &s1_share_poly * &s2_share_poly;

        // gather the result of poly addition u64 coeffs
        let mut collect_coeffs: Vec<u64> = Vec::with_capacity(n * 3);
        for ((x, y), value) in sum_shamir.coefficients().indexed_iter() {
            if *value != 0 as u64 { collect_coeffs.push(*value); }
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
        assert_eq!(arr, array![[0, 0, 0], [1, 1, 1], [2,2,2]]);
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
            prime: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",16).unwrap()
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
            test_sssvec.push(node_shares[n-1][0].clone());
        }
        //println!("{:?}", test_sssvec);
        println!("{:?}", node_shares[0].len());
        println!("The useful size of `v` is {}", size_of_val(&*node_shares[0]));
        //println!(" Secret coeff {:?}", sk_share.coeffs[0].to_bigint().unwrap());
        assert_eq!(sk_share.coeffs[0].to_bigint().unwrap(), sss.recover(&result[0][0..sss.threshold as usize]));
        println!("{:?}", result[0]);
    }
}
