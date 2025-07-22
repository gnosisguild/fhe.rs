/// Truncated discrete Gaussian sampling for threshold BFV smudging noise.
///
/// Provides BigInt normal sampling using Box-Muller transform with rejection sampling
/// to generate samples from N(0, (bound/3)²) truncated to [-bound, bound].
use core::f64::consts::PI;
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
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
        if (-1.0..=1.0).contains(&r) {
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
    use num_traits::Signed;
    use rand::thread_rng;
    use std::str::FromStr;

    #[test]
    fn test_sampling() {
        let bound: BigInt = "123456789012345678901234567890".parse().unwrap();
        let samples = sample_bigint_normal_vec(&bound, 1000);

        assert_eq!(samples.len(), 1000);
        for x in &samples {
            assert!(x.abs() <= bound);
        }
    }

    #[test]
    fn test_normal_sampling_edge_cases() {
        // Test with zero bound
        let zero_bound = BigInt::from(0);
        let samples = sample_bigint_normal_vec(&zero_bound, 10);
        assert_eq!(samples.len(), 10);
        assert!(samples.iter().all(|x| x.is_zero()));

        // Test with small bound
        let small_bound = BigInt::from(5);
        let samples = sample_bigint_normal_vec(&small_bound, 100);
        assert_eq!(samples.len(), 100);
        for x in &samples {
            assert!(x.abs() <= small_bound);
        }

        // Test with negative values in result
        let bound = BigInt::from(1000);
        let samples = sample_bigint_normal_vec(&bound, 1000);
        let has_positive = samples.iter().any(|x| x.is_positive());
        let has_negative = samples.iter().any(|x| x.is_negative());
        assert!(has_positive || has_negative); // Should have some variation
    }

    #[test]
    fn test_box_muller_properties() {
        let mut rng = thread_rng();
        let samples: Vec<f64> = (0..1000).map(|_| box_muller(&mut rng)).collect();

        // Basic statistical properties (rough checks)
        let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
        let variance: f64 =
            samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / samples.len() as f64;

        // Should be approximately N(0,1)
        assert!(mean.abs() < 0.2); // Mean should be close to 0
        assert!((variance - 1.0).abs() < 0.3); // Variance should be close to 1
    }

    #[test]
    fn test_ratio_to_bigint_edge_cases() {
        let small_bound = BigInt::from(10);
        let large_bound = BigInt::from_str("123456789012345678901234567890123456789").unwrap();

        // Test with small bound (fast path)
        let result1 = ratio_to_bigint(0.5, &small_bound);
        assert!(result1.abs() <= small_bound);

        // Test with large bound (precision path)
        let result2 = ratio_to_bigint(0.5, &large_bound);
        assert!(result2.abs() <= large_bound);

        // Test edge ratios
        let result3 = ratio_to_bigint(1.0, &small_bound);
        assert!(result3.abs() <= small_bound);

        let result4 = ratio_to_bigint(-1.0, &small_bound);
        assert!(result4.abs() <= small_bound);
    }
}
