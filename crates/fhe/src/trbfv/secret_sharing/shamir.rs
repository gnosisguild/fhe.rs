/// Shamir Secret Sharing implementation for threshold BFV.
///
/// This module provides the concrete implementation of Shamir Secret Sharing
/// for polynomial coefficients in the threshold BFV scheme.
use crate::bfv::BfvParameters;
use crate::trbfv::secret_sharing::traits::SecretSharer;
use crate::Error;
use fhe_math::rq::{traits::TryConvertFrom, Poly, Representation};
use itertools::izip;
use ndarray::Array2;
use num_bigint_old::{BigInt, ToBigInt};
use num_traits::ToPrimitive;
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Shamir Secret Sharing implementation for threshold BFV operations.
#[derive(Debug)]
pub struct ShamirSecretSharing {
    /// Number of parties
    pub n: usize,
    /// Threshold for reconstruction
    pub threshold: usize,
    /// BFV parameters
    pub params: Arc<BfvParameters>,
}

impl ShamirSecretSharing {
    /// Create a new Shamir Secret Sharing instance.
    pub fn new(n: usize, threshold: usize, params: Arc<BfvParameters>) -> Self {
        Self {
            n,
            threshold,
            params,
        }
    }
}

impl SecretSharer for ShamirSecretSharing {
    /// Generate Shamir Secret Shares for polynomial coefficients.
    fn generate_secret_shares(&mut self, coeffs: Box<[i64]>) -> Result<Vec<Array2<u64>>, Error> {
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
            let shamir = SSS {
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

    /// Reconstruct a secret coefficient from shares.
    fn reconstruct_coefficient(
        &self,
        shares: &[(usize, BigInt)],
        modulus: u64,
    ) -> Result<BigInt, Error> {
        let sss = SSS {
            threshold: self.threshold,
            share_amount: self.n,
            prime: BigInt::from(modulus),
        };
        Ok(sss.recover(shares))
    }
}
