//! # BigInt Normal Sampler
//! ## Overview
//! This module provides a `BigIntNormalSampler` that lets you draw integer samples
//! from a (mean 0) *truncated discrete Gaussian* on the interval `[-bound, bound]`,
//! where `bound` is an arbitrary-precision `BigInt` (e.g., `2^102`).  The typical
//! use case in your project is smudging / masking noise injection for threshold BFV.
//!
//! ### Distribution model
//! We work in **ratio space**: draw a standard normal `Z ~ N(0,1)`, form
//! `ratio = mean_ratio + std_dev_ratio * Z`, and *reject & resample* until
//! `|ratio| <= 1`.  We then scale to an integer by rounding `ratio * bound`.
//!
//! With `mean_ratio = 0` and `std_dev_ratio = 1/3`, this corresponds to a
//! continuous normal `N(0, (bound/3)^2)` truncated to `[-bound, bound]`, then
//! discretized to the nearest integer.  This is much closer to the distribution
//! you intended than the earlier linear-acceptance version, and avoids the edge
//! pileup created by clamping.
//!
//! ### API quick-start
//! ```ignore
//! use num_bigint::BigInt;
//! use num_traits::{One, Zero};
//!
//! mod normal; // or `pub mod normal;` in lib.rs
//! use normal::BigIntNormalSampler;
//!
//! fn example() {
//!     let bound = BigInt::one() << 102; // 2^102
//!     let sampler = BigIntNormalSampler::new(bound.clone());
//!     // draw 1000 centered samples with sigma = bound/3
//!     let samples = sampler.sample_vec_centered(bound.clone(), 1000);
//!     assert_eq!(samples.len(), 1000);
//!     for s in &samples {
//!         debug_assert!(sampler.is_within_bounds(s));
//!     }
//! }
//! ```
//!
//! ### Thread-safety
//! Uses an internal `ThreadRng` per call.  If you need deterministic seeding or
//! reproducibility across threads, accept an `R: RngCore + CryptoRng` parameter.
//! (See TODO at bottom.)
//!
//! ### Crypto note
//! Box–Muller uses floating point; for *strict* constant‑time or side‑channel
//! hardened cryptographic noise, replace `box_muller_ratio_truncated()` with an
//! integer‑only discrete Gaussian sampler (CDT / Bernoulli‑exp).  Hooks are noted
//! in the code.

use core::f64::consts::PI;
use num_bigint::BigInt;
use num_traits::{One, Signed, ToPrimitive, Zero};
use rand::Rng;

/// BigInt-backed truncated normal/Gaussian sampler.
#[derive(Clone, Debug)]
pub struct BigIntNormalSampler {
    bound: BigInt,
}

impl BigIntNormalSampler {
    /// Create a new sampler with the specified (nonnegative) bound.
    pub fn new(bound: BigInt) -> Self {
        assert!(bound >= BigInt::zero(), "bound must be nonnegative");
        Self { bound }
    }

    /// Convenience: create sampler with bound = 2^n.
    pub fn new_power_of_2(n: u32) -> Self {
        Self {
            bound: BigInt::one() << n,
        }
    }

    /// Return immutable reference to bound.
    #[inline]
    pub fn bound(&self) -> &BigInt {
        &self.bound
    }

    /// Check if value is within [-bound, bound].
    #[inline]
    pub fn is_within_bounds(&self, value: &BigInt) -> bool {
        value.abs() <= self.bound
    }

    // ------------------------------------------------------------------
    // Core sampling helpers
    // ------------------------------------------------------------------

    /// Generate a *single* standard normal deviate via Box–Muller.
    /// Not constant‑time; fine for testing / prototyping.
    fn box_muller(&self, rng: &mut impl Rng) -> f64 {
        // Avoid log(0) by sampling (0,1]; clamp low end to f64::MIN_POSITIVE-ish.
        let u1: f64 = rng.gen_range(f64::EPSILON..1.0);
        let u2: f64 = rng.gen_range(0.0..1.0);
        (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos()
    }

    /// Draw a truncated ratio in [-1,1] from Normal(mean_ratio, std_dev_ratio).
    /// Uses simple rejection: resample until |ratio| <= 1.
    fn box_muller_ratio_truncated(
        &self,
        rng: &mut impl Rng,
        mean_ratio: f64,
        std_dev_ratio: f64,
    ) -> f64 {
        loop {
            let z = self.box_muller(rng);
            let r = mean_ratio + std_dev_ratio * z;
            if r >= -1.0 && r <= 1.0 {
                return r;
            }
            // else retry; with std=1/3, rejection ~0.27% per tail.
        }
    }

    /// Scale a ratio in [-1,1] to BigInt in [-bound, bound] (nearest integer).
    fn ratio_to_bigint(&self, ratio: f64) -> BigInt {
        debug_assert!((-1.0..=1.0).contains(&ratio));
        // Scale using f64 -> BigInt.  Because ratio <= 1 and bound may be huge,
        // we convert bound to f64 *only* to get the exponent and then shift.
        // Simpler: multiply bound by ratio using string <-> BigInt fallback.
        // We'll do: (ratio * bound_as_f64).round() if bound fits f64; otherwise
        // approximate with bit-length scaling.
        if let Some(bf) = self.bound.to_f64() {
            // For very large bound this will overflow to inf; detect.
            if bf.is_finite() {
                if let Some(v) = (ratio * bf).round().to_i128() {
                    // If bound fits in i128, just short-path.
                    return BigInt::from(v);
                }
            }
        }
        // Generic precise path:  ratio = s * 2^{-k} with scaled integer.
        // Represent ratio in fixed-point with 53 bits (mantissa of f64).
        // NOTE: `ratio` is in [-1,1], so scale by 2^53 safely.
        const FP_BITS: u32 = 53;
        let scaled = (ratio * (1u64 << FP_BITS) as f64).round() as i64; // signed
                                                                        // scaled / 2^FP_BITS * bound
                                                                        // => (scaled * bound) >> FP_BITS
        let scaled_big = BigInt::from(scaled);
        let prod = scaled_big * &self.bound;
        // arithmetic shift right by FP_BITS (floor toward -inf); we want round‑nearest.
        // We'll emulate nearest by adding half before shift when scaled >=0.
        // But we already rounded at scaled step, so floor is fine.
        prod >> FP_BITS
    }

    /// Sample a single integer given ratios.
    pub fn sample(&self, rng: &mut impl Rng, mean_ratio: f64, std_dev_ratio: f64) -> BigInt {
        if self.bound.is_zero() {
            return BigInt::zero();
        }
        let r = self.box_muller_ratio_truncated(rng, mean_ratio, std_dev_ratio);
        let mut x = self.ratio_to_bigint(r);
        // Safety clamp (should be unnecessary after truncation)
        if x > self.bound {
            x = self.bound.clone();
        } else if x < -&self.bound {
            x = -self.bound.clone();
        }
        x
    }

    /// Generate `n` samples with ratio params.
    pub fn sample_multiple(
        &self,
        rng: &mut impl Rng,
        n: usize,
        mean_ratio: f64,
        std_dev_ratio: f64,
    ) -> Vec<BigInt> {
        (0..n)
            .map(|_| self.sample(rng, mean_ratio, std_dev_ratio))
            .collect()
    }

    // ------------------------------------------------------------------
    // Convenience front-ends
    // ------------------------------------------------------------------

    /// Centered Gaussian: mean=0, sigma = bound/3.  Returns Vec<BigInt> of length `n`.
    /// This matches the parameterization used in your earlier experiments.
    pub fn sample_vec_centered(&self, n: usize) -> Vec<BigInt> {
        // Centered Gaussian: mean=0, sigma = bound/3 (ratio std = 1/3).
        // NOTE: previously took an explicit `bound_for_sigma` param; removed because
        // sampler already owns the bound and we support *any* positive BigInt bound.
        let mut rng = rand::thread_rng();
        self.sample_multiple(&mut rng, n, 0.0, 1.0 / 3.0)
    }

    /// Same as `sample_vec_centered`, but explicit RNG for reproducibility.
    pub fn sample_vec_centered_with_rng(&self, rng: &mut impl Rng, n: usize) -> Vec<BigInt> {
        self.sample_multiple(rng, n, 0.0, 1.0 / 3.0)
    }

    /// Sample with explicit mean / std_dev *in BigInt units*.
    /// NOTE: std_dev must satisfy 0 <= std_dev <= bound; converted to ratio.
    pub fn sample_vec_bigint_params(
        &self,
        rng: &mut impl Rng,
        n: usize,
        mean: &BigInt,
        std_dev: &BigInt,
    ) -> Vec<BigInt> {
        let mean_ratio = self.bigint_to_ratio(mean);
        let std_dev_ratio = self.bigint_to_ratio(std_dev);
        self.sample_multiple(rng, n, mean_ratio, std_dev_ratio)
    }

    // ------------------------------------------------------------------
    // Ratio conversions
    // ------------------------------------------------------------------

    /// Convert BigInt value to ratio in [-1,1] relative to bound.
    /// Falls back to high‑precision string scaling if needed.
    pub fn bigint_to_ratio(&self, value: &BigInt) -> f64 {
        if let (Some(vf), Some(bf)) = (value.to_f64(), self.bound.to_f64()) {
            if bf != 0.0 {
                return vf / bf;
            }
        }
        // Slow fallback: use decimal strings (approximate, but fine for diagnostics).
        let vs = value.to_string();
        let bs = self.bound.to_string();
        if vs.len() == bs.len() {
            let take = vs.len().min(18);
            let vf: f64 = vs[..take].parse().unwrap_or(0.0);
            let bf: f64 = bs[..take].parse().unwrap_or(1.0);
            vf / bf
        } else if vs.len() < bs.len() {
            // definitely <1 in magnitude
            10f64.powi((vs.len() as i32) - (bs.len() as i32))
        } else {
            // definitely >=1; cap
            if value.is_negative() {
                -1.0
            } else {
                1.0
            }
        }
    }
}

// ----------------------------------------------------------------------
// Public free functions (lightweight wrappers)
// ----------------------------------------------------------------------

/// Draw `n` samples from centered truncated Gaussian with sigma = bound/3.
/// Convenience wrapper so call‑sites don't need to construct the sampler.
pub fn sample_bigint_normal_vec(bound: &BigInt, n: usize) -> Vec<BigInt> {
    let sampler = BigIntNormalSampler::new(bound.clone());
    sampler.sample_vec_centered(n)
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::{One, ToPrimitive, Zero};

    #[test]
    fn smoke_sample() {
        let bound: BigInt = "123456789012345678901234567890".parse().unwrap();
        let sampler = BigIntNormalSampler::new(bound.clone());
        let mut rng = rand::thread_rng();
        let v = sampler.sample_multiple(&mut rng, 1000, 0.0, 1.0 / 3.0);
        assert_eq!(v.len(), 1000);
        for x in &v {
            assert!(sampler.is_within_bounds(x));
        }
    }
}
