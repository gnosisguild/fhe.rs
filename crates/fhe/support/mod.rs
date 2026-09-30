#![allow(dead_code)]

//! Shared support modules for tests, examples, and benchmarks.

pub mod examples;
pub mod presets;

/// An RNG that panics on every draw.
///
/// Use it to assert that a code path rejects its inputs *before* consuming
/// any randomness: build the keys under test with a real RNG first, then pass
/// this RNG to the call under test. If the call returns an `Err` (or `Ok`)
/// instead of panicking, the outcome was decided without RNG use.
pub struct PanicOnUseRng;

impl rand::RngCore for PanicOnUseRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    #[expect(
        clippy::panic,
        reason = "test-only RNG that asserts inputs are rejected before RNG use"
    )]
    fn next_u64(&mut self) -> u64 {
        panic!("RNG must not be used before the inputs are accepted")
    }

    #[expect(
        clippy::panic,
        reason = "test-only RNG that asserts inputs are rejected before RNG use"
    )]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let _ = dest;
        panic!("RNG must not be used before the inputs are accepted")
    }
}

impl rand::CryptoRng for PanicOnUseRng {}
