/// Truncated discrete Gaussian sampling for threshold BFV smudging noise.
///
/// Provides BigInt normal sampling using Box-Muller transform with rejection sampling
/// to generate samples from N(0, (bound/3)²) truncated to [-bound, bound].
use core::f64::consts::PI;
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};
use rand::Rng;

/// Draw `n` samples from centered truncated Gaussian with sigma = bound/3.
pub fn sample_bigint_normal_vec(bound: &BigInt, n: usize) -> Vec<BigInt> {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| sample_single(bound, &mut rng)).collect()
}

/// Sample a single value from N(0, (bound/3)²) truncated to [-bound, bound].
fn sample_single(bound: &BigInt, rng: &mut impl Rng) -> BigInt {
    if bound.is_zero() {
        return BigInt::zero();
    }

    let ratio = sample_truncated_ratio(rng);
    let mut x = ratio_to_bigint(ratio, bound);

    // Safety clamp
    if x > *bound {
        x = bound.clone();
    } else if x < -bound {
        x = -bound.clone();
    }

    x
}

/// Sample a ratio in [-1,1] from Normal(0, 1/3) using rejection sampling.
fn sample_truncated_ratio(rng: &mut impl Rng) -> f64 {
    loop {
        let z = box_muller(rng);
        // formula: r = mean_ratio + std_dev_ratio * z
        // where mean_ratio = 0, std_dev_ratio = 1/3, so r = z / 3.0
        let r = z / 3.0;
        if r >= -1.0 && r <= 1.0 {
            return r;
        }
    }
}

/// Generate standard normal deviate using Box-Muller transform.
fn box_muller(rng: &mut impl Rng) -> f64 {
    let u1: f64 = rng.gen_range(f64::EPSILON..1.0);
    let u2: f64 = rng.gen_range(0.0..1.0);
    (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos()
}

/// Convert ratio in [-1,1] to BigInt in [-bound, bound].
fn ratio_to_bigint(ratio: f64, bound: &BigInt) -> BigInt {
    debug_assert!((-1.0..=1.0).contains(&ratio));

    // Fast path for small bounds
    if let Some(bf) = bound.to_f64() {
        if bf.is_finite() {
            if let Some(v) = (ratio * bf).round().to_i128() {
                return BigInt::from(v);
            }
        }
    }

    // High-precision path for large bounds
    const FP_BITS: u32 = 53;
    let scaled = (ratio * (1u64 << FP_BITS) as f64).round() as i64;
    let scaled_big = BigInt::from(scaled);
    let prod = scaled_big * bound;

    prod >> FP_BITS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sampling() {
        let bound: BigInt = "123456789012345678901234567890".parse().unwrap();
        let samples = sample_bigint_normal_vec(&bound, 1000);

        assert_eq!(samples.len(), 1000);
        for x in &samples {
            assert!(x.abs() <= bound);
        }
    }
}
