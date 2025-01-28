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
    pub test: String
}

impl TrBFVShare {
    pub fn new(
        N: u64,
        threshold: u64
    ) -> Result<Self> {
        Ok(Self { test: "test".to_string()})
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
    fn test_tfhe() {
        let mut rng = thread_rng();
        // generate fhe secret key polynomial
        // for each poly coef, generate a shamir secret share
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

        let sk_par = BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()
            .unwrap();
        let sk_share = SecretKey::random(&sk_par, &mut rng);
        println!("{:?}", sk_share.coeffs.len());
        println!("{:?}", sk_share.coeffs);

        let sss = SSS {
            threshold: threshold,
            share_amount: n,
            prime: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",16).unwrap()
            };

        // for each coeff generate an SSS of degree n and threshold n = 2t + 1
        let mut result: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(threshold);

        for i in 0..degree {
            let secret = sk_share.coeffs[i].to_bigint().unwrap();
            // encode negative coeffs as positive ints [11,19]
            let shares = sss.split(secret.clone());
            let mut sssvec: Vec<(usize, BigInt)> = Vec::with_capacity(n);
            for j in 0..n {
                sssvec.push(shares[j].clone());
            }
            result.push(sssvec);
        }

        //println!("{:?}", shares[0]);
        //println!("{:?}", result[0]);

        let mut node_shares: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(n);
        for j in 0..n {
            let mut node_share_i: Vec<(usize, BigInt)> = Vec::with_capacity(threshold);
            for i in 0..threshold {
                node_share_i.push(result[i][j].clone());
            }
            node_shares.push(node_share_i)
        } 

        println!("{:?}", node_shares[0]);
        // SSS is failing with negative values
        //assert_eq!(secret, sss.recover(&shares[0..sss.threshold as usize]));
    }
}
