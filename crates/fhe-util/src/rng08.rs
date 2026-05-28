//! Bridge rand 0.9 RNGs to APIs that require rand 0.8 (e.g. [`num_bigint::RandBigInt`]).
//!
//! [`num_bigint::RandBigInt`]: num_bigint::RandBigInt

use rand::{RngCore, TryRngCore};

/// Adapts a rand 0.9 [`RngCore`] for use with rand 0.8 / `num-bigint` sampling.
pub struct Adapter<'a, T: ?Sized>(pub &'a mut T);

impl<T: RngCore + ?Sized> rand_v08::RngCore for Adapter<'_, T> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_v08::Error> {
        self.0.try_fill_bytes(dest).map_err(rand_v08::Error::new)
    }
}

/// Wrap `rng` so [`num_bigint::RandBigInt`] methods can be called on it.
#[must_use]
pub fn adapt<'a, T: RngCore + ?Sized>(rng: &'a mut T) -> Adapter<'a, T> {
    Adapter(rng)
}
