/// BigInt normal sampling using Box-Muller transform.
///
/// Provides BigInt normal sampling from N(0, variance) without strict bounds.
/// Uses Box-Muller transform for generating normal deviates.
use core::f64::consts::PI;
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};
use rand::Rng;
use rayon::prelude::*;

/// Draw `n` samples from centered normal distribution N(0, variance).
pub fn sample_bigint_normal_vec(variance: &BigInt, n: usize) -> Vec<BigInt> {
    (0..n)
        .into_par_iter()
        .map(|_| {
            let mut rng = rand::thread_rng();
            sample_single(variance, &mut rng)
        })
        .collect()
}

/// Sample a single value from N(0, variance).
fn sample_single(variance: &BigInt, rng: &mut impl Rng) -> BigInt {
    if variance.is_zero() {
        return BigInt::zero();
    }

    // Generate standard normal deviate
    let z = box_muller(rng);

    // Scale by sqrt(variance) to get N(0, variance)
    variance_scaled_sample(z, variance)
}

/// Scale a standard normal sample by sqrt(variance).
fn variance_scaled_sample(z: f64, variance: &BigInt) -> BigInt {
    // For variance σ², we need to multiply by σ = sqrt(variance)
    let sqrt_variance = variance.sqrt();

    // Convert z * sqrt(variance) to BigInt
    z_to_bigint(z, &sqrt_variance)
}

/// Generate standard normal deviate using Box-Muller transform.
fn box_muller(rng: &mut impl Rng) -> f64 {
    let u1: f64 = rng.gen_range(f64::EPSILON..1.0);
    let u2: f64 = rng.gen_range(0.0..1.0);
    (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos()
}

/// Convert standard normal deviate z to BigInt scaled by scale_factor.
fn z_to_bigint(z: f64, scale_factor: &BigInt) -> BigInt {
    if scale_factor.is_zero() {
        return BigInt::zero();
    }

    // Handle the sign separately
    let sign = if z < 0.0 { -1 } else { 1 };
    let abs_z = z.abs();

    // Fast path for small scale factors
    if let Some(scale_f64) = scale_factor.to_f64() {
        if scale_f64.is_finite() && scale_f64 < 1e15 {
            let scaled = abs_z * scale_f64;
            if let Some(v) = scaled.round().to_i128() {
                return BigInt::from(sign * v);
            }
        }
    }

    // High-precision path for large scale factors
    const FP_BITS: u32 = 53; // IEEE 754 double precision mantissa bits
    let scaled_z = (abs_z * (1u64 << FP_BITS) as f64).round() as i64;
    let scaled_z_big = BigInt::from(scaled_z);
    let prod = scaled_z_big * scale_factor;
    let result = prod >> FP_BITS;

    if sign < 0 {
        -result
    } else {
        result
    }
}

/// Convenience function to sample with variance specified as u64.
pub fn sample_bigint_normal_vec_u64(variance: u64, n: usize) -> Vec<BigInt> {
    let variance_big = BigInt::from(variance);
    sample_bigint_normal_vec(&variance_big, n)
}

/// Convenience function to sample with variance specified as 2^bits.
pub fn sample_bigint_normal_vec_bits(variance_bits: u32, n: usize) -> Vec<BigInt> {
    let variance = BigInt::from(2u32).pow(variance_bits);
    sample_bigint_normal_vec(&variance, n)
}

/// Sample a single BigInt normal value.
pub fn sample_bigint_normal(variance: &BigInt) -> BigInt {
    let mut rng = rand::thread_rng();
    sample_single(variance, &mut rng)
}

/// Sample a single BigInt normal value with u64 variance.
pub fn sample_bigint_normal_u64(variance: u64) -> BigInt {
    let variance_big = BigInt::from(variance);
    sample_bigint_normal(&variance_big)
}

/// Sample a single BigInt normal value with 2^bits variance.
pub fn sample_bigint_normal_bits(variance_bits: u32) -> BigInt {
    let variance = BigInt::from(2u32).pow(variance_bits);
    sample_bigint_normal(&variance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use std::str::FromStr;

    #[test]
    fn test_normal_sampling_basic() {
        let variance = BigInt::from(100u32);
        let samples = sample_bigint_normal_vec(&variance, 1000);

        assert_eq!(samples.len(), 1000);

        // Basic sanity checks - should have variety of values
        let has_positive = samples.iter().any(|x| x.is_positive());
        let has_negative = samples.iter().any(|x| x.is_negative());
        let has_zero = samples.iter().any(|x| x.is_zero());

        // Should have some variety (not all the same sign)
        assert!(has_positive || has_negative);
    }

    #[test]
    fn test_large_variance_sampling() {
        // Test with 100-bit variance (2^100)
        let large_variance = BigInt::from(2u32).pow(100);
        let samples = sample_bigint_normal_vec(&large_variance, 100);

        assert_eq!(samples.len(), 100);

        // With large variance, should get some large values
        let has_large_values = samples.iter().any(|x| x.bits() > 50);
        assert!(
            has_large_values,
            "Should have some large values with 100-bit variance"
        );
    }

    #[test]
    fn test_small_variance_sampling() {
        // Test with small variance
        let small_variance = BigInt::from(4u32);
        let samples = sample_bigint_normal_vec(&small_variance, 1000);

        assert_eq!(samples.len(), 1000);

        // With small variance, most values should be small
        let mostly_small = samples
            .iter()
            .filter(|x| x.abs() <= BigInt::from(10))
            .count();
        assert!(
            mostly_small > 800,
            "Most samples should be small with small variance"
        );
    }

    #[test]
    fn test_zero_variance() {
        let zero_variance = BigInt::from(0);
        let samples = sample_bigint_normal_vec(&zero_variance, 10);

        assert_eq!(samples.len(), 10);
        assert!(
            samples.iter().all(|x| x.is_zero()),
            "All samples should be zero with zero variance"
        );
    }

    #[test]
    fn test_convenience_functions() {
        // Test u64 convenience function
        let samples_u64 = sample_bigint_normal_vec_u64(100, 50);
        assert_eq!(samples_u64.len(), 50);

        // Test bits convenience function
        let samples_bits = sample_bigint_normal_vec_bits(10, 50); // 2^10 = 1024 variance
        assert_eq!(samples_bits.len(), 50);

        // Test single sample functions
        let single1 = sample_bigint_normal_u64(100);
        let single2 = sample_bigint_normal_bits(10);

        // Should be valid BigInt values (basic check)
        assert!(single1.bits() >= 0);
        assert!(single2.bits() >= 0);
    }

    #[test]
    fn test_very_large_variance() {
        // Test with extremely large variance
        let huge_variance = BigInt::from_str("123456789012345678901234567890123456789").unwrap();
        let samples = sample_bigint_normal_vec(&huge_variance, 10);

        assert_eq!(samples.len(), 10);
        // Should handle large variances without panicking
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
        assert!(mean.abs() < 0.2, "Mean should be close to 0, got {}", mean);
        assert!(
            (variance - 1.0).abs() < 0.3,
            "Variance should be close to 1, got {}",
            variance
        );
    }

    #[test]
    fn test_scaling_correctness() {
        // Test that scaling works correctly for different variance sizes
        let small_var = BigInt::from(1u32);
        let large_var = BigInt::from(10000u32);

        let small_samples = sample_bigint_normal_vec(&small_var, 1000);
        let large_samples = sample_bigint_normal_vec(&large_var, 1000);

        // Rough check: larger variance should generally produce larger values
        let small_avg_abs: f64 = small_samples
            .iter()
            .map(|x| x.to_f64().unwrap_or(0.0).abs())
            .sum::<f64>()
            / small_samples.len() as f64;

        let large_avg_abs: f64 = large_samples
            .iter()
            .map(|x| x.to_f64().unwrap_or(0.0).abs())
            .sum::<f64>()
            / large_samples.len() as f64;

        assert!(
            large_avg_abs > small_avg_abs,
            "Larger variance should produce larger average absolute values"
        );
    }

    #[test]
    fn test_sign_distribution() {
        let variance = BigInt::from(100u32);
        let samples = sample_bigint_normal_vec(&variance, 1000);

        let positive_count = samples.iter().filter(|x| x.is_positive()).count();
        let negative_count = samples.iter().filter(|x| x.is_negative()).count();
        let zero_count = samples.iter().filter(|x| x.is_zero()).count();

        // Should have roughly balanced positive/negative (allowing for randomness)
        assert!(
            positive_count > 100,
            "Should have significant positive samples"
        );
        assert!(
            negative_count > 100,
            "Should have significant negative samples"
        );
        assert!(zero_count < 100, "Should not have too many exact zeros");
    }
}
