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
use num_bigint_old::{BigInt, BigUint};
use num_bigint_old::Sign::*;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKeyShare {
    pub test: String
}

impl PublicKeyShare {
    pub fn new() -> Result<Self> {
        Ok(Self { test: "test".to_string()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_tfhe() {
        println!("testing123...");
        let sss = SSS {
            threshold: 3,
            share_amount: 5,
            prime: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",16).unwrap()
            };

        let secret = BigInt::parse_bytes(b"ffffffffffffffffffffffffffffffffffffff", 16).unwrap();

        let shares = sss.split(secret.clone());

        println!("shares: {:?}", shares);
        assert_eq!(secret, sss.recover(&shares[0..sss.threshold as usize]));
    }
}
