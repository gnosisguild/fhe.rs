//! Runtime prime-field arithmetic with Barrett reduction.

use core::fmt;

use rand_core::{CryptoRng, RngCore};

use crate::{Error, primality};

const MAX_MODULUS: u64 = 1_u64 << 62;
const EXPONENT_BITS: u32 = 64;

/// Prime-field operations required by [`crate::ShamirScheme`].
///
/// Implementations store canonical representatives in `[0, q)`. Arithmetic
/// uses `u128` intermediates. The fixed-schedule inversion and arithmetic
/// kernels are designed to avoid secret-dependent branches; rejection
/// sampling has variable random-draw timing, and this trait does not make RNG,
/// allocator, transport, or caller behavior constant time.
pub trait Field: Clone + Send + Sync + fmt::Debug + 'static {
    /// Construct a field after validating that `modulus` is an odd prime in
    /// the supported range.
    fn try_new(modulus: u64) -> Result<Self, Error>
    where
        Self: Sized;

    /// Return the field modulus.
    fn modulus(&self) -> u64;

    /// Add two canonical residues.
    fn add(&self, left: u64, right: u64) -> u64;

    /// Subtract two canonical residues.
    fn sub(&self, left: u64, right: u64) -> u64;

    /// Multiply two canonical residues.
    fn mul(&self, left: u64, right: u64) -> u64;

    /// Reduce an arbitrary `u128` value modulo the field modulus.
    fn reduce_u128(&self, value: u128) -> u64;

    /// Compute a fixed-schedule modular exponentiation.
    fn pow(&self, base: u64, exponent: u64) -> u64;

    /// Invert a canonical residue using Fermat's theorem.
    ///
    /// Zero still runs the complete fixed exponentiation schedule before
    /// returning `None`.
    fn invert(&self, value: u64) -> Option<u64>;

    /// Draw a uniform canonical residue by rejection sampling.
    ///
    /// The number of rejection draws is observable through variable random-draw
    /// timing. After acceptance, the algorithm does not branch or divide based
    /// on the accepted candidate's magnitude; reduction is branchless Barrett.
    fn sample<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u64;
}

/// Barrett-reduction field backend.
#[derive(Clone, Copy)]
pub struct BarrettBackend {
    modulus: u64,
    reciprocal: u128,
}

impl fmt::Debug for BarrettBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BarrettBackend")
            .field("modulus", &self.modulus)
            .finish()
    }
}

/// The default field backend, selected for its straightforward auditability.
pub type BarrettField = BarrettBackend;

/// Short alias for [`BarrettBackend`].
pub type Barrett = BarrettBackend;

/// Compatibility name for the public field abstraction.
pub use Field as FieldBackend;

fn validate_modulus(modulus: u64) -> Result<(), Error> {
    if !(3..MAX_MODULUS).contains(&modulus) || modulus.is_multiple_of(2) {
        return Err(Error::InvalidModulus { modulus });
    }
    if !primality::is_prime(modulus) {
        return Err(Error::CompositeModulus { modulus });
    }
    Ok(())
}

fn sub_modulus(left: u64, right: u64, modulus: u64) -> u64 {
    let (difference, borrow) = left.overflowing_sub(right);
    let mask = 0_u64.wrapping_sub(borrow as u64);
    difference.wrapping_add(modulus & mask)
}

fn pow_fixed<F: Fn(u64, u64) -> u64>(base: u64, exponent: u64, multiply: F) -> u64 {
    let mut result = 1_u64;
    for bit in (0..EXPONENT_BITS).rev() {
        result = multiply(result, result);
        let multiplied = multiply(result, base);
        let mask = 0_u64.wrapping_sub((exponent >> bit) & 1);
        result = (multiplied & mask) | (result & !mask);
    }
    result
}

fn sample_uniform<R, F>(modulus: u64, rng: &mut R, reduce: F) -> u64
where
    R: RngCore + CryptoRng,
    F: Fn(u128) -> u64,
{
    let limit = u64::MAX - u64::MAX % modulus;
    loop {
        let candidate = rng.next_u64();
        if candidate < limit {
            return reduce(candidate as u128);
        }
    }
}

fn mul_high(left: u128, right: u128) -> u128 {
    let left_low = left as u64;
    let left_high = (left >> 64) as u64;
    let right_low = right as u64;
    let right_high = (right >> 64) as u64;
    let low_product = left_low as u128 * right_low as u128;
    let cross_low = left_low as u128 * right_high as u128;
    let cross_high = left_high as u128 * right_low as u128;
    let middle = (low_product >> 64) + (cross_low as u64 as u128) + (cross_high as u64 as u128);
    let high = left_high as u128 * right_high as u128;
    high.wrapping_add(cross_low >> 64)
        .wrapping_add(cross_high >> 64)
        .wrapping_add(middle >> 64)
}

fn barrett_reduce(value: u128, modulus: u64, reciprocal: u128) -> u64 {
    let quotient = mul_high(value, reciprocal);
    let mut remainder = value - quotient * modulus as u128;
    let modulus = modulus as u128;
    let first_mask = 0_u128.wrapping_sub((remainder >= modulus) as u128);
    remainder = remainder.wrapping_sub(modulus & first_mask);
    let second_mask = 0_u128.wrapping_sub((remainder >= modulus) as u128);
    remainder.wrapping_sub(modulus & second_mask) as u64
}

impl Field for BarrettBackend {
    fn try_new(modulus: u64) -> Result<Self, Error> {
        validate_modulus(modulus)?;
        Ok(Self {
            modulus,
            reciprocal: u128::MAX / modulus as u128,
        })
    }

    fn modulus(&self) -> u64 {
        self.modulus
    }

    fn add(&self, left: u64, right: u64) -> u64 {
        self.reduce_u128(left as u128 + right as u128)
    }

    fn sub(&self, left: u64, right: u64) -> u64 {
        sub_modulus(left, right, self.modulus)
    }

    fn mul(&self, left: u64, right: u64) -> u64 {
        self.reduce_u128(left as u128 * right as u128)
    }

    fn reduce_u128(&self, value: u128) -> u64 {
        barrett_reduce(value, self.modulus, self.reciprocal)
    }

    fn pow(&self, base: u64, exponent: u64) -> u64 {
        pow_fixed(base, exponent, |left, right| self.mul(left, right))
    }

    fn invert(&self, value: u64) -> Option<u64> {
        let inverse = self.pow(value, self.modulus - 2);
        (value != 0).then_some(inverse)
    }

    fn sample<R: RngCore + CryptoRng>(&self, rng: &mut R) -> u64 {
        sample_uniform(self.modulus, rng, |value| self.reduce_u128(value))
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use proptest::prelude::*;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    use super::{BarrettBackend, Field};

    fn check_backend<F: Field>(field: F) {
        let modulus = BigUint::from(field.modulus());
        let values = [0, 1, field.modulus() - 1, field.modulus() / 2];
        for left in values {
            for right in values {
                let expected = (&BigUint::from(left) * &BigUint::from(right) % &modulus)
                    .to_u64_digits()
                    .into_iter()
                    .next()
                    .unwrap_or(0);
                assert_eq!(field.mul(left, right), expected);
            }
        }
        assert_eq!(field.invert(0), None);
        assert_eq!(field.mul(field.modulus() - 1, field.modulus() - 1), 1);
    }

    #[test]
    fn barrett_matches_oracle() {
        check_backend(BarrettBackend::try_new(4_611_686_018_326_724_609).unwrap());
    }

    #[test]
    fn constructor_rejects_composites_and_unsupported_values() {
        assert!(BarrettBackend::try_new(1).is_err());
        assert!(BarrettBackend::try_new(15).is_err());
        assert!(BarrettBackend::try_new(1_u64 << 62).is_err());
    }

    #[test]
    fn sampling_is_canonical() {
        let field = BarrettBackend::try_new(1613).unwrap();
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        for _ in 0..1024 {
            assert!(field.sample(&mut rng) < field.modulus());
        }
    }

    proptest! {
        #[test]
        fn barrett_reduces_full_u128(value: u128) {
            let field = BarrettBackend::try_new(4_611_686_018_326_724_609).unwrap();
            prop_assert_eq!(
                field.reduce_u128(value),
                (value % field.modulus() as u128) as u64
            );
        }

    }
}
