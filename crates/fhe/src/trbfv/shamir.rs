/// Shamir Secret Sharing implementation for threshold BFV.
///
/// This module provides a complete Shamir Secret Sharing implementation that integrates
/// with the BFV parameter system.
use num_bigint::{BigInt, RandBigInt};
use num_traits::{One, Zero};

/// A rust porting of Shamir Secret Sharing over Finite Field
/// from https://docs.rs/shamir_secret_sharing adapted to work with
/// num_bigint v0.4.4.
///
/// ---
///
/// A rust implementation of  Shamir Secret Sharing over Finite Field.
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
///     threshold: 3,
///     share_amount: 5,
///     prime: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",16).unwrap()
///     };
///
/// let secret = BigInt::parse_bytes(b"ffffffffffffffffffffffffffffffffffffff", 16).unwrap();
///
/// let shares = sss.split(secret.clone());
///
/// println!("shares: {:?}", shares);
/// assert_eq!(secret, sss.recover(&shares[0..sss.threshold as usize]));
/// }
///
#[derive(Debug)]
pub struct ShamirSecretSharing {
    /// Threshold for reconstruction (minimum number of shares needed)
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
    /// * `threshold` - The minimum number of shares needed to reconstruct the secret
    /// * `share_amount` - The total number of shares to generate
    /// * `prime` - The prime modulus for the finite field operations
    ///
    /// # Returns
    ///
    /// A new `ShamirSecretSharing` instance configured with the given parameters.
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
    ///
    /// # Returns
    ///
    /// A vector of tuples containing (share_index, share_value) pairs.
    /// The share_index starts from 1 and goes up to `share_amount`.
    ///
    /// # Panics
    ///
    /// Panics if `threshold` is greater than or equal to `share_amount`.
    pub fn split(&self, secret: BigInt) -> Vec<(usize, BigInt)> {
        assert!(self.threshold < self.share_amount);
        let polynomial = self.sample_polynomial(secret);
        // println!("polynomial: {:?}", polynomial);
        self.evaluate_polynomial(polynomial)
    }

    fn sample_polynomial(&self, secret: BigInt) -> Vec<BigInt> {
        let mut coefficients: Vec<BigInt> = vec![secret];
        let mut rng = rand::thread_rng();
        let low = BigInt::from(0);
        let high = &self.prime - BigInt::from(1);
        let random_coefficients: Vec<BigInt> = (0..(self.threshold - 1))
            .map(|_| rng.gen_bigint_range(&low, &high))
            .collect();
        coefficients.extend(random_coefficients);
        coefficients
    }

    fn evaluate_polynomial(&self, polynomial: Vec<BigInt>) -> Vec<(usize, BigInt)> {
        (1..=self.share_amount)
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
    /// # Panics
    ///
    /// Panics if the number of shares provided is not equal to the threshold.
    pub fn recover(&self, shares: &[(usize, BigInt)]) -> BigInt {
        assert!(shares.len() == self.threshold, "wrong shares number");
        let (xs, ys): (Vec<usize>, Vec<BigInt>) = shares.iter().cloned().unzip();
        let result = self.lagrange_interpolation(Zero::zero(), xs, ys);
        if result < Zero::zero() {
            result + &self.prime
        } else {
            result
        }
    }

    fn lagrange_interpolation(&self, x: BigInt, xs: Vec<usize>, ys: Vec<BigInt>) -> BigInt {
        let len = xs.len();
        // println!("x: {}, xs: {:?}, ys: {:?}", x, xs, ys);
        let xs_bigint: Vec<BigInt> = xs.iter().map(|x| BigInt::from(*x as i64)).collect();
        // println!("sx_bigint: {:?}", xs_bigint);
        (0..len).fold(Zero::zero(), |sum, item| {
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
            // println!(
            // "numerator: {}, donominator: {}, y: {}",
            // numerator, denominator, &ys[item]
            // );
            (sum + numerator * self.mod_reverse(denominator) * &ys[item]) % &self.prime
        })
    }

    fn mod_reverse(&self, num: BigInt) -> BigInt {
        let num1 = if num < Zero::zero() {
            num + &self.prime
        } else {
            num
        };
        let (_gcd, _, inv) = self.extend_euclid_algo(num1);
        // println!("inv:{}", inv);
        inv
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
mod tests {
    use super::*;
    #[test]
    fn test_wikipedia_example() {
        let sss = ShamirSecretSharing {
            threshold: 3,
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
            ]),
            BigInt::from(1234)
        );
    }
    #[test]
    fn test_large_prime() {
        let sss = ShamirSecretSharing {
            threshold: 3,
            share_amount: 5,
            // prime: BigInt::from(6999213259363483493573619703 as i128),
            prime: BigInt::parse_bytes(
                b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                16,
            )
            .unwrap(),
        };
        let secret = BigInt::parse_bytes(b"ffffffffffffffffffffffffffffffffffffff", 16).unwrap();
        let shares = sss.split(secret.clone());
        assert_eq!(secret, sss.recover(&shares[0..sss.threshold as usize]));
    }
}
