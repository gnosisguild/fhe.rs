//! Shared unit-test parameter fixtures for the trBFV module.
//!
//! These live inside the crate — the repo-level `support` presets in
//! `crates/fhe/support/mod.rs` cannot be imported by unit tests — and they
//! deliberately use parameter shapes the integration profiles do not
//! provide: a degree-2048 set for fast `ShareManager` tests, a degree-8192
//! set with a small plaintext modulus so the statistically-hiding smudging
//! bound stays feasible, and degree-8 sets for exact CRT oracles.
#![allow(
    clippy::unwrap_used,
    reason = "unit-test fixtures: invalid parameters must fail the test run loudly"
)]

use crate::bfv::{BfvParameters, BfvParametersBuilder};
use std::sync::Arc;

/// Degree-2048 parameters used by the fast `ShareManager` unit tests.
#[must_use]
pub fn params_2048() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(2048)
        .set_plaintext_modulus(4096)
        .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
        .build_arc()
        .unwrap()
}

/// Degree-8192 parameters with a small plaintext modulus. The larger
/// modulus chain leaves room for the statistically-hiding noise bound that
/// large lambda values require.
#[must_use]
pub fn params_8192() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus(16384)
        .set_moduli(&[0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001])
        .build_arc()
        .unwrap()
}
