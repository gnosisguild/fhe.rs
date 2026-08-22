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

/// Best-effort drop guard for secret `Vec<BigInt>` scratch values.
///
/// `BigInt` does not implement [`zeroize::Zeroize`], so [`zeroize::Zeroizing`]
/// cannot wrap it directly. On drop this guard replaces every held `BigInt`
/// with zero and clears the container. As with
/// [`crate::trbfv::smudging::SmudgingCoefficients`], this is **best effort**:
/// num-bigint does not expose its private limb allocation for overwriting
/// before deallocation, so this guard does not promise allocator-level or
/// complete historical-copy erasure.
pub(crate) struct ZeroizingBigInts {
    values: Vec<BigInt>,
}

impl ZeroizingBigInts {
    /// Wrap an owned coefficient vector, placing it under best-effort
    /// zeroization on drop.
    pub(crate) fn new(values: Vec<BigInt>) -> Self {
        Self { values }
    }

    /// Create an empty guard with room for `capacity` values.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            values: Vec::with_capacity(capacity),
        }
    }

    /// Append a value to the guarded buffer.
    pub(crate) fn push(&mut self, value: BigInt) {
        self.values.push(value);
    }

    /// Borrow the guarded values (e.g. for Lagrange reconstruction).
    pub(crate) fn as_slice(&self) -> &[BigInt] {
        &self.values
    }
}

impl Drop for ZeroizingBigInts {
    fn drop(&mut self) {
        for value in &mut self.values {
            value.set_zero();
        }
        self.values.clear();
    }
}

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
/// let shares = sss.split(secret.clone(), &mut rand::rng()).unwrap();
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
    /// # Errors
    ///
    /// Returns an error if `threshold` is greater than `(share_amount - 1) / 2`.
    ///
    /// # Cleanup
    ///
    /// The sharing polynomial scratch is guarded (best-effort BigInt cleanup,
    /// see [`ZeroizingBigInts`] and the module docs); callers should treat the
    /// returned share values as secret material.
    pub fn split<R: RngCore + CryptoRng>(
        &self,
        secret: BigInt,
        rng: &mut R,
    ) -> Result<Vec<(usize, BigInt)>, Error> {
        if self.threshold > (self.share_amount.max(1) - 1) / 2 {
            // Best-effort cleanup of the secret before the validation error
            // return: `BigInt` does not implement `Zeroize`, so the guard is
            // a manual `set_zero` on the single value (same limitation as
            // `SmudgingCoefficients`).
            let mut secret = secret;
            secret.set_zero();
            return Err(Error::invalid_threshold(self.threshold, self.share_amount));
        }
        let polynomial = ZeroizingBigInts::new(self.sample_polynomial(secret, rng));
        Ok(self.evaluate_polynomial(&polynomial.values))
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
    /// # Cleanup
    ///
    /// The sampled random coefficients are guarded (best-effort BigInt
    /// cleanup, see [`ZeroizingBigInts`]); the caller (e.g.
    /// [`ShamirSecretSharing::split`]) should guard the returned polynomial,
    /// which contains the secret as its constant term.
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

        // Use the seeds; the sampled coefficients are secret and are guarded
        // until they are appended into the returned polynomial.
        let mut random_coefficients = ZeroizingBigInts::new(
            seeds
                .into_par_iter()
                .map(|seed| {
                    let mut rng = ChaCha20Rng::from_seed(seed);
                    rng08::adapt(&mut rng).gen_bigint_range(&low, &high)
                })
                .collect::<Vec<BigInt>>(),
        );
        coefficients.append(&mut random_coefficients.values);
        coefficients
    }

    fn evaluate_polynomial(&self, polynomial: &[BigInt]) -> Vec<(usize, BigInt)> {
        (1..=self.share_amount)
            .into_par_iter()
            .map(|x| (x, self.mod_evaluate_at(polynomial, x)))
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
    ///
    /// # Cleanup
    ///
    /// The recovered share values are guarded (best-effort BigInt cleanup,
    /// see [`ZeroizingBigInts`]); the returned secret should be consumed
    /// immediately by the caller.
    pub fn recover(&self, shares: &[(usize, BigInt)]) -> Result<BigInt, Error> {
        if shares.len() != self.threshold + 1 {
            return Err(Error::share_count_mismatch(
                shares.len(),
                self.threshold + 1,
            ));
        }
        let (xs, ys): (Vec<usize>, Vec<BigInt>) = shares.iter().cloned().unzip();
        let ys = ZeroizingBigInts::new(ys);
        self.recover_from_parts(&xs, &ys.values)
    }

    /// Internal reconstruction from parallel index/value slices.
    ///
    /// `ys` holds the secret share values and should be guarded by the caller
    /// (the x-coordinates in `xs` are public party indices).
    pub(crate) fn recover_from_parts(&self, xs: &[usize], ys: &[BigInt]) -> Result<BigInt, Error> {
        if xs.len() != self.threshold + 1 {
            return Err(Error::share_count_mismatch(xs.len(), self.threshold + 1));
        }
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
        xs: &[usize],
        ys: &[BigInt],
    ) -> Result<BigInt, Error> {
        let len = xs.len();
        let xs_bigint: Vec<BigInt> = xs.iter().map(|x| BigInt::from(*x as i64)).collect();

        // Each parallel task returns its Lagrange term already under the
        // best-effort guard, so a partial collected vector zeroizes the
        // already-computed terms if any task fails (e.g. a non-invertible
        // Lagrange denominator) instead of dropping a raw partial
        // `Vec<BigInt>`.
        let terms: Result<Vec<ZeroizingBigInts>, Error> = (0..len)
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
                let term = (numerator * self.mod_reverse(denominator)? * &ys[item]) % &self.prime;
                Ok(ZeroizingBigInts::new(vec![term]))
            })
            .collect();

        // The Lagrange terms are secret share values; the final summation
        // folds through each per-term guard (best-effort BigInt cleanup), so
        // the term values remain covered until their guards drop after the
        // fold instead of being moved out (`std::mem::take`) and dropped
        // unzeroized after each step.
        Ok(terms?
            .iter()
            .flat_map(|term| term.as_slice().iter())
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
            return Err(Error::non_invertible_shares());
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
            num,
            BigInt::from(1),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(1),
        );
        while next_r > Zero::zero() {
            let quotient = &r / &next_r;
            r -= &quotient * &next_r;
            std::mem::swap(&mut r, &mut next_r);
            s -= &quotient * &next_s;
            std::mem::swap(&mut s, &mut next_s);
            t -= &quotient * &next_t;
            std::mem::swap(&mut t, &mut next_t);
        }
        (r, s, t)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ThresholdError;
    #[test]
    fn test_wikipedia_example() {
        let sss = ShamirSecretSharing {
            threshold: 2,
            share_amount: 6,
            prime: BigInt::from(1613),
        };
        let shares =
            sss.evaluate_polynomial(&[BigInt::from(1234), BigInt::from(166), BigInt::from(94)]);
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
        // Duplicate share indices -> non-invertible Lagrange denominator.
        // This exercises the guarded per-task error path of
        // `lagrange_interpolation` (issue #126): each parallel task returns
        // its term under `ZeroizingBigInts`, so the partial collected terms
        // zeroize (best-effort BigInt cleanup) when `mod_reverse` fails
        // instead of dropping a raw partial `Vec<BigInt>`.
        assert!(matches!(
            sss.recover(&[
                (1, BigInt::from(1494)),
                (1, BigInt::from(1494)),
                (3, BigInt::from(965))
            ]),
            Err(Error::Threshold(ThresholdError::NonInvertibleShares))
        ));
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
        let shares = sss.split(secret.clone(), &mut rand::rng()).unwrap();
        assert_eq!(secret, sss.recover(&shares[0..sss.threshold + 1]).unwrap());
    }

    #[test]
    fn test_recover_threshold_three_guarded_fold() {
        // Exercises the guarded Lagrange-term fold (issue #126 review finding
        // 3b): the terms are summed through the best-effort guard instead of
        // being moved out of it and dropped unzeroized. Behavior must be
        // unchanged: with `threshold + 1 = 4` shares the round trip recovers
        // the exact secret.
        let sss = ShamirSecretSharing {
            threshold: 3,
            share_amount: 7,
            prime: BigInt::from(1613),
        };
        let secret = BigInt::from(987);
        let shares = sss.split(secret.clone(), &mut rand::rng()).unwrap();
        assert_eq!(shares.len(), 7);
        assert_eq!(secret, sss.recover(&shares[0..sss.threshold + 1]).unwrap());
    }
}
