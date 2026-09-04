//! Deterministic randomness helpers shared by integration test targets.

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

/// Expand a short test seed into the ChaCha8 seed used by the library.
#[must_use]
pub fn seed(value: u8) -> [u8; 32] {
    [value; 32]
}

/// Create a deterministic cryptographic RNG for a named test case.
#[must_use]
pub fn rng(value: u8) -> ChaCha8Rng {
    ChaCha8Rng::from_seed(seed(value))
}
