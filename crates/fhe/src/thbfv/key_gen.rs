use std::{sync::Arc};

use crate::bfv::{PublicKey, Ciphertext};
use fhe_util::sample_vec_cbd_unbounded;
use crate::errors::Result;
use rand::{CryptoRng, RngCore};
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use num_bigint_old::{BigInt, ToBigInt};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TrBFVShare {
    n: u64,
    threshold: u64,
    degree: u64,
    plaintext_modulus: u64,
    sss_modulus: u64,
    sumdging_variance: u64,
    moduli: Vec<u64>
}

impl TrBFVShare {
    pub fn new<R: RngCore + CryptoRng>(
        n: u64,
        threshold: u64,
        degree: u64,
        plaintext_modulus: u64,
        sss_modulus: u64,
        sumdging_variance: u64,
        moduli: Vec<u64>,
        rng: &mut R
    ) -> Result<Self> {
        // generate random secret
        Ok(Self { 
            n,
            threshold,
            degree,
            plaintext_modulus,
            sss_modulus,
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

        let mut s = Zeroizing::new(Poly::try_convert_from(
            s_raw.coeffs.as_ref(),
            &sk_par.ctx_at_level(0).unwrap(),
            false,
            Representation::PowerBasis,
        ).unwrap());

        let mut s_shares: Vec<Poly> = vec![Poly::zero(&sk_par.ctx_at_level(0).unwrap(), Representation::PowerBasis); n];
        // For each modulus
        for (k, (m, p)) in izip!(s.ctx().moduli().iter(), s.coefficients().outer_iter()).enumerate() {
            // Create shamir object
            let shamir = SSS {
                threshold: threshold,
                share_amount: n,
                prime: BigInt::from(*m)
            };
            // For each coeff in the polynomial p under the current modulus m
            for (i, c) in p.iter().enumerate() {
                // Split the coeff into n shares
                let secret = c.to_bigint().unwrap();
                let c_shares = shamir.split(secret.clone());
                // For each share
                for (j, (_, c_share)) in c_shares.iter().enumerate() {
                    // Set the coefficient in the corresponding polynomial matrix of s_shares
                    s_shares[j].coefficients_mut()[k][i] = c_share.to_u64().unwrap();
                }
            }
        }

        // gather seceret coeffs
        let coeffview = s.coefficients();
        println!("{:?}", coeffview);
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
