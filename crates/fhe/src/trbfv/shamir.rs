use crate::Error;
use fhe_util::rng08;
/// Shamir Secret Sharing implementation for threshold BFV.
///
/// This module provides a complete Shamir Secret Sharing implementation that integrates
/// with the BFV parameter system.
use num_bigint::{BigInt, RandBigInt};
use num_traits::{One, Zero};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;

/// A rust porting of Shamir Secret Sharing over Finite Field
/// from https://docs.rs/shamir_secret_sharing adapted to work with
/// num_bigint v0.4.4.
///
/// ---
///
/// A rust implementation of Shamir Secret Sharing over Finite Field that we use to secret share
/// each RNS representative of a value in the ring Z_Q where Q is the product of prime moduli.
///
/// The lib support large field charactirics `prime` by taking advantage of `num_bigint`.
/// It's not optimized for production purpose, which can be improved in several aspects:
/// 1. replace the `extended_euclid_algo` with machine-friendly `stein_algo` to calculate the modulo inverse;
/// 2. add commitment scheme to make it verifiable
///
///
/// # Example
/// use shamir_secret_sharing::ShamirSecretSharing as SSS;
/// use num_bigint::{BigInt, BigUint};
/// use num_bigint::Sign::*;
/// fn main() {
/// let sss = SSS {
///     threshold: 2,
///     share_amount: 5,
///     prime: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",16).unwrap()
///     };
///
/// let secret = BigInt::parse_bytes(b"ffffffffffffffffffffffffffffffffffffff", 16).unwrap();
///
/// let shares = sss.split(secret.clone());
///
/// println!("shares: {:?}", shares);
/// assert_eq!(secret, sss.recover(&shares[0..sss.threshold +1]).unwrap());
/// }
///
/// Fork a full-entropy ChaCha20 seed from the caller's RNG.
///
/// Used to derive independent per-task RNGs for parallel sampling without
/// sharing the caller's RNG across threads.
pub(crate) fn fork_seed<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    seed
}

#[derive(Debug)]
/// Shamir Secret Sharing
pub struct ShamirSecretSharing {
    /// Threshold for reconstruction (minimum number of shares needed is threshold + 1)
    pub threshold: usize,
    /// Number of parties in the threshold scheme
    pub share_amount: usize,
    /// Prime modulus for the finite field
    pub prime: BigInt,
}

impl ShamirSecretSharing {
    /// Creates a new Shamir Secret Sharing instance.
    ///
    /// # Arguments
    ///
    /// * `threshold + 1` - The minimum number of shares needed to reconstruct the secret
    /// * `share_amount` - The total number of shares to generate
    /// * `prime` - The prime modulus for the finite field operations
    ///
    /// # Returns
    ///
    /// A new `ShamirSecretSharing` instance configured with the given parameters.
    #[must_use]
    pub fn new(threshold: usize, share_amount: usize, prime: BigInt) -> Self {
        Self {
            threshold,
            share_amount,
            prime,
        }
    }

    /// Splits a secret into multiple shares using Shamir's Secret Sharing scheme.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret value to be shared
    /// * `rng` - An rng from which to draw randomness
    ///
    /// # Returns
    ///
    /// A vector of tuples containing (share_index, share_value) pairs.
    /// The share_index starts from 1 and goes up to `share_amount`.
    ///
    /// # Panics
    ///
    /// Panics if `threshold` is greater than `(share_amount - 1) / 2`.
    pub fn split<R: RngCore + CryptoRng>(
        &self,
        secret: BigInt,
        rng: &mut R,
    ) -> Vec<(usize, BigInt)> {
        assert!(self.threshold <= (self.share_amount - 1) / 2);
        let polynomial = self.sample_polynomial(secret, rng);
        self.evaluate_polynomial(polynomial)
    }

    /// Samples a Shamir sharing polynomial over `Z_q` with a fixed constant term.
    ///
    /// This constructs the coefficient vector of a polynomial
    /// `f(x) = c0 + c1*x + c2*x^2 + ... + c_T*x^T` where:
    /// - `c0` is set **exactly** to the provided `secret` (not reduced modulo `q`)
    /// - `c1..c_T` are sampled independently at random
    ///
    /// # Parameters
    /// - `secret`: The constant term `c0`. It is inserted verbatim (no modular
    ///   reduction). If `secret` may lie outside `[0, q)`, handle the lift gap
    ///   externally (e.g., with a separate quotient `d` such that `secret - c0 = d*q`).
    ///
    /// # Returns
    /// - `Vec<BigInt>` of length `self.threshold + 1` in **constant-first** order:
    ///   `[c0, c1, ..., c_T]`, where `T = self.threshold`.
    ///
    pub fn sample_polynomial<R: RngCore + CryptoRng>(
        &self,
        secret: BigInt,
        rng: &mut R,
    ) -> Vec<BigInt> {
        let mut coefficients: Vec<BigInt> = vec![secret];
        let low = BigInt::from(0);
        // gen_bigint_range samples from [low, high), so this covers all of Z_p.
        let high = self.prime.clone();

        // Generate seeds deterministically from the input RNG
        // This is done so clients can test using deterministic rngs
        let seeds: Vec<[u8; 32]> = (0..self.threshold).map(|_| fork_seed(rng)).collect();

        // Use the seeds
        let random_coefficients: Vec<BigInt> = seeds
            .into_par_iter()
            .map(|seed| {
                let mut rng = ChaCha20Rng::from_seed(seed);
                rng08::adapt(&mut rng).gen_bigint_range(&low, &high)
            })
            .collect();
        coefficients.extend(random_coefficients);
        coefficients
    }

    fn evaluate_polynomial(&self, polynomial: Vec<BigInt>) -> Vec<(usize, BigInt)> {
        (1..=self.share_amount)
            .into_par_iter()
            .map(|x| (x, self.mod_evaluate_at(&polynomial, x)))
            .collect()
    }

    fn mod_evaluate_at(&self, polynomial: &[BigInt], x: usize) -> BigInt {
        let x_bigint = BigInt::from(x);
        polynomial.iter().rev().fold(Zero::zero(), |sum, item| {
            (&x_bigint * sum + item) % &self.prime
        })
    }

    /// Recovers the original secret from a subset of shares.
    ///
    /// # Arguments
    ///
    /// * `shares` - A slice of (share_index, share_value) tuples
    ///
    /// # Returns
    ///
    /// The reconstructed secret value.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of shares provided is not equal to
    /// threshold + 1, or if a Lagrange denominator is not invertible
    /// (e.g., duplicate share indices).
    pub fn recover(&self, shares: &[(usize, BigInt)]) -> Result<BigInt, Error> {
        if shares.len() != self.threshold + 1 {
            return Err(Error::secret_sharing(format!(
                "wrong shares number: expected {}, got {}",
                self.threshold + 1,
                shares.len()
            )));
        }
        let (xs, ys): (Vec<usize>, Vec<BigInt>) = shares.iter().cloned().unzip();
        let result = self.lagrange_interpolation(Zero::zero(), xs, ys)?;
        if result < Zero::zero() {
            Ok(result + &self.prime)
        } else {
            Ok(result)
        }
    }

    // indices i and item iterate 0..len, same as xs_bigint.len() and ys.len()
    #[allow(clippy::indexing_slicing)]
    fn lagrange_interpolation(
        &self,
        x: BigInt,
        xs: Vec<usize>,
        ys: Vec<BigInt>,
    ) -> Result<BigInt, Error> {
        let len = xs.len();
        let xs_bigint: Vec<BigInt> = xs.iter().map(|x| BigInt::from(*x as i64)).collect();

        let terms: Result<Vec<BigInt>, Error> = (0..len)
            .into_par_iter()
            .map(|item| {
                let numerator = (0..len).fold(One::one(), |product: BigInt, i| {
                    if i == item {
                        product
                    } else {
                        product * (&x - &xs_bigint[i]) % &self.prime
                    }
                });
                let denominator = (0..len).fold(One::one(), |product: BigInt, i| {
                    if i == item {
                        product
                    } else {
                        product * (&xs_bigint[item] - &xs_bigint[i]) % &self.prime
                    }
                });
                // Calculate this Lagrange term
                Ok((numerator * self.mod_reverse(denominator)? * &ys[item]) % &self.prime)
            })
            .collect();

        Ok(terms?
            .into_iter()
            .fold(Zero::zero(), |sum: BigInt, term| (sum + term) % &self.prime))
    }

    fn mod_reverse(&self, num: BigInt) -> Result<BigInt, Error> {
        let num1 = if num < Zero::zero() {
            num + &self.prime
        } else {
            num
        };
        let (gcd, _, inv) = self.extend_euclid_algo(num1);
        if !gcd.is_one() {
            return Err(Error::secret_sharing(
                "non-invertible Lagrange denominator (duplicate or invalid share indices)",
            ));
        }
        Ok(inv)
    }

    /**
     * https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
     *
     * a*s + b*t = gcd(a,b) a > b
     * r_0 = a*s_0 + b*t_0    s_0 = 1    t_0 = 0
     * r_1 = a*s_1 + b*t_1    s_1 = 0    t_1 = 1
     * r_2 = r_0 - r_1*q_1
     *     = a(s_0 - s_1*q_1) + b(t_0 - t_1*q_1)   s_2 = s_0 - s_1*q_1     t_2 = t_0 - t_1*q_1
     * ...
     * stop when r_k = 0
     */
    fn extend_euclid_algo(&self, num: BigInt) -> (BigInt, BigInt, BigInt) {
        let (mut r, mut next_r, mut s, mut next_s, mut t, mut next_t) = (
            self.prime.clone(),
            num.clone(),
            BigInt::from(1),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(1),
        );
        let mut quotient;
        let mut tmp;
        while next_r > Zero::zero() {
            quotient = r.clone() / next_r.clone();
            tmp = next_r.clone();
            next_r = r.clone() - next_r.clone() * quotient.clone();
            r = tmp.clone();
            tmp = next_s.clone();
            next_s = s - next_s.clone() * quotient.clone();
            s = tmp;
            tmp = next_t.clone();
            next_t = t - next_t * quotient;
            t = tmp;
        }
        // println!(
        // "{} * {} + {} * {} = {} mod {}",
        // num, t, &self.prime, s, r, &self.prime
        // );
        (r, s, t)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn test_wikipedia_example() {
        let sss = ShamirSecretSharing {
            threshold: 2,
            share_amount: 6,
            prime: BigInt::from(1613),
        };
        let shares = sss.evaluate_polynomial(vec![
            BigInt::from(1234),
            BigInt::from(166),
            BigInt::from(94),
        ]);
        assert_eq!(
            shares,
            [
                (1, BigInt::from(1494)),
                (2, BigInt::from(329)),
                (3, BigInt::from(965)),
                (4, BigInt::from(176)),
                (5, BigInt::from(1188)),
                (6, BigInt::from(775))
            ]
        );
        assert_eq!(
            sss.recover(&[
                (1, BigInt::from(1494)),
                (2, BigInt::from(329)),
                (3, BigInt::from(965))
            ])
            .unwrap(),
            BigInt::from(1234)
        );
    }
    #[test]
    fn test_recover_rejects_bad_shares() {
        let sss = ShamirSecretSharing {
            threshold: 2,
            share_amount: 6,
            prime: BigInt::from(1613),
        };
        // Wrong share count
        assert!(
            sss.recover(&[(1, BigInt::from(1494)), (2, BigInt::from(329))])
                .is_err()
        );
        // Duplicate share indices -> non-invertible Lagrange denominator
        assert!(
            sss.recover(&[
                (1, BigInt::from(1494)),
                (1, BigInt::from(1494)),
                (3, BigInt::from(965))
            ])
            .is_err()
        );
    }

    #[test]
    fn test_large_prime() {
        let sss = ShamirSecretSharing {
            threshold: 2,
            share_amount: 5,
            // prime: BigInt::from(6999213259363483493573619703 as i128),
            prime: BigInt::parse_bytes(
                b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                16,
            )
            .unwrap(),
        };
        let secret = BigInt::parse_bytes(b"ffffffffffffffffffffffffffffffffffffff", 16).unwrap();
        let shares = sss.split(secret.clone(), &mut rand::rng());
        assert_eq!(secret, sss.recover(&shares[0..sss.threshold + 1]).unwrap());
    }
}
