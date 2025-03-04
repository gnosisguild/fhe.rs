use std::sync::Arc;

use crate::bfv::{BfvParameters, Ciphertext, PublicKey, SecretKey};
use crate::proto::bfv::{Ciphertext as CiphertextProto, PublicKeyShare as PublicKeyShareProto};
use fhe_traits::{DeserializeWithContext, Serialize};
use crate::errors::Result;
use crate::Error;
use fhe_math::rq::{traits::TryConvertFrom, Poly, Representation};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;
//use serde::{Serialize, Deserialize};
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use num_bigint_old::{BigInt, BigUint, ToBigInt};
use num_bigint_old::Sign::*;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TrBFVShare {
    n: u64,
    threshold: u64,
    degree: u64,
    plaintext_modulus: u64,
    sss_modulus: u64,
    moduli: Vec<u64>
}

impl TrBFVShare {
    pub fn new<R: RngCore + CryptoRng>(
        n: u64,
        threshold: u64,
        degree: u64,
        plaintext_modulus: u64,
        sss_modulus: u64,
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
            moduli
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fhe_traits::{FheEncoder, FheEncrypter};
    use rand::thread_rng;

    use crate::bfv::{BfvParameters, BfvParametersBuilder, Encoding, Plaintext, SecretKey};
    use crate::mbfv::{CommonRandomPoly};

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

        // Generate the common random poly BFV parameters structure.
        // let crp_par = BfvParametersBuilder::new()
        //     .set_degree(degree)
        //     .set_plaintext_modulus(plaintext_modulus)
        //     .set_moduli(&moduli)
        //     .build_arc()
        //     .unwrap();

        // let crp = CommonRandomPoly::new(&crp_par, &mut rng).unwrap();
        // println!("{:?}", crp.poly.coefficients.len());
        // println!("{:?}", crp.poly.coefficients[[1, 2047]]);
        // println!("{:?}", crp.poly.coefficients);

        // For each party, generate secret key share contribution (this will never be shared)
        let sk_par = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();
        let sk_share = SecretKey::random(&sk_par, &mut rng);
        println!("{:?}", sk_share.coeffs.len());
        println!("{:?}", sk_share.par);

        // For each party, generate public key contribution from sk, this will be broadcast publicly
        let pk_share = PublicKey::new(&sk_share, &mut rng);

        let sss = SSS {
            threshold: threshold,
            share_amount: n,
            prime: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",16).unwrap()
        };

        // for each coeff generate an SSS of degree n and threshold n = 2t + 1
        let mut result: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(degree);

        for i in 0..degree {
            let secret = sk_share.coeffs[i].to_bigint().unwrap();
            // encode negative coeffs as positive ints [11,19]
            let shares = sss.split(secret.clone());
            // let mut sssvec: Vec<(usize, BigInt)> = Vec::with_capacity(n);
            // for j in 0..n {
            //     sssvec.push(shares[j].clone());
            // }
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


        let mut test_sssvec: Vec<(usize, BigInt)> = Vec::with_capacity(n);
        for i in 0..n {
            test_sssvec.push(node_shares[n-1][0].clone());
        }
        println!("{:?}", test_sssvec);


        println!("{:?}", node_shares[0].len());
        println!("The useful size of `v` is {}", size_of_val(&*node_shares[0]));
        // SSS is failing with negative values
        println!(" Secret coeff {:?}", sk_share.coeffs[0].to_bigint().unwrap());
        assert_eq!(sk_share.coeffs[0].to_bigint().unwrap(), sss.recover(&result[0][0..sss.threshold as usize]));
    }
}
