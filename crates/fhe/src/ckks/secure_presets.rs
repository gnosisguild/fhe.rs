//! 128-bit-secure threshold-CKKS parameter sets with the security budget
//! checked at construction.
//!
//! # Security budget
//!
//! Source: *Homomorphic Encryption Security Standard* (Albrecht, Chase,
//! Chen, Ding, Goldwasser, Gorbunov, Halevi, Hoffstein, Laine, Lauter,
//! Lepoint, Lokam, Micciancio, Moody, Morrison, Sahai, Vaikuntanathan;
//! Nov 2018, <https://homomorphicencryption.org/standard/>), Table 1,
//! uniform ternary secret, classical 128-bit security:
//!
//! | N      | max log2(Q·P) |
//! |--------|---------------|
//! | 1024   | 27            |
//! | 2048   | 54            |
//! | 4096   | 109           |
//! | 8192   | 218           |
//! | 16384  | 438           |
//! | 32768  | 881           |
//! | 65536  | 1772 (estimator extrapolation used by Lattigo / OpenFHE) |
//!
//! The bound applies to the FULL key-switching modulus `Q·P`: the hybrid
//! special primes `P` are part of the RLWE instance the relinearization key
//! is an encryption under, so they COUNT toward the budget (§5.3 of
//! `BENCHMARKS_TRCKKS.md`). [`security_budget`] sums the bit sizes of every
//! ciphertext AND special prime and rejects a set over the table.
//!
//! # The sets
//!
//! - [`s1_stats`]: `N = 32768`, one 60-bit base prime + 17 × 40-bit rescale
//!   limbs (`log2 Q = 740`), `k = 2` 60-bit special primes (`log2 P = 120`),
//!   `Δ = 2^40`, hybrid enabled (`dnum = 9`). `log2(Q·P) = 860 ≤ 881`,
//!   headroom 21 bits. 17 multiplicative levels — the MAXIMUM 40-bit depth
//!   under the budget (an 18th limb gives 900 > 881).
//! - [`s1_cmp`]`(iterations)`: same `N`, the sign-extraction ladder shape
//!   (base + `1 + 3·iterations` 40-bit limbs + `k = 2`). Six iterations need
//!   `60 + 19·40 + 120 = 940 > 881` bits and are REJECTED; the largest
//!   iteration count that fits is [`S1_MAX_SIGN_ITERATIONS`] `= 5`
//!   (`60 + 16·40 + 120 = 820`). Note [`s1_stats`] already carries
//!   `17 ≥ 1 + 3·5` rescale limbs, so it can run a 5-iteration comparison
//!   too; `s1_cmp(5)` is the exact-depth shape (one limb fewer).
//! - [`s2_cmp12`]: `N = 65536`, one 60-bit base + 37 × 40-bit limbs
//!   (`log2 Q = 1540`), `k = 3` 60-bit special primes (`log2 P = 180`),
//!   `Δ = 2^40`, `dnum = 13`. `log2(Q·P) = 1720 ≤ 1772`, headroom 52 bits.
//!   The 12-iteration ladder of interfold's `sign_extraction_params` at
//!   secure `N` (with a 60-bit instead of 45-bit base).
//!
//! Every set is NTT-friendly by construction (`CkksParametersBuilder`
//! generates primes `≡ 1 mod 2N`) — the tests re-check it.
//!
//! Whether threshold decryption's flooding walls close for a given
//! application at these sets is a separate question answered by
//! [`crate::trckks::app_feasibility`].

use crate::ckks::{CkksParameters, CkksParametersBuilder};
use crate::{Error, Result};
use std::sync::Arc;

/// HE Standard 2018 Table 1 (uniform ternary secret, classical 128-bit):
/// `(N, max log2(Q·P))`. The `N = 65536` row is the estimator
/// extrapolation used by Lattigo and OpenFHE default tables.
pub const HE_STD_128_CLASSICAL_TERNARY: [(usize, usize); 7] = [
    (1024, 27),
    (2048, 54),
    (4096, 109),
    (8192, 218),
    (16384, 438),
    (32768, 881),
    (65536, 1772),
];

/// Maximum `log2(Q·P)` for classical 128-bit security at `degree`, or
/// `None` when the degree is not in the table.
#[must_use]
pub fn max_log_qp_bits(degree: usize) -> Option<usize> {
    HE_STD_128_CLASSICAL_TERNARY
        .iter()
        .find(|(n, _)| *n == degree)
        .map(|(_, b)| *b)
}

/// Scale bits shared by every secure set (`Δ = 2^40`, matching the 40-bit
/// rescale limbs so the working scale stays pinned across levels).
pub const SECURE_SCALE_BITS: i32 = 40;
/// Bit size of the rescale limbs.
pub const SECURE_RESCALE_BITS: usize = 40;
/// Bit size of the base (level-`L-1`) prime — the modulus the final
/// opening happens against.
pub const SECURE_BASE_BITS: usize = 60;
/// Bit size of every hybrid special prime.
pub const SECURE_SPECIAL_BITS: usize = 60;

/// `S1` degree.
pub const S1_DEGREE: usize = 32768;
/// Rescale limbs of [`s1_stats`]: the maximum under the 881-bit budget.
pub const S1_STATS_RESCALE_LIMBS: usize = 17;
/// Special primes of the `S1` sets.
pub const S1_SPECIAL_PRIMES: usize = 2;
/// Largest sign-extraction iteration count whose ladder fits `S1`.
pub const S1_MAX_SIGN_ITERATIONS: usize = 5;

/// `S2` degree.
pub const S2_DEGREE: usize = 65536;
/// Sign-extraction iterations of [`s2_cmp12`].
pub const S2_SIGN_ITERATIONS: usize = 12;
/// Special primes of the `S2` sets.
pub const S2_SPECIAL_PRIMES: usize = 3;

/// Bit accounting of a parameter set against the 128-bit budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityBudget {
    /// Ring degree.
    pub degree: usize,
    /// `log2 Q` = sum of the ciphertext-prime bit sizes.
    pub log_q_bits: usize,
    /// `log2 P` = sum of the special-prime bit sizes (0 without hybrid).
    pub log_p_bits: usize,
    /// Maximum `log2(Q·P)` from the table.
    pub budget_bits: usize,
}

impl SecurityBudget {
    /// `log2(Q·P)`.
    #[must_use]
    pub fn log_qp_bits(&self) -> usize {
        self.log_q_bits + self.log_p_bits
    }

    /// Unused bits under the budget (0 when exactly at the bound).
    #[must_use]
    pub fn headroom_bits(&self) -> usize {
        self.budget_bits.saturating_sub(self.log_qp_bits())
    }

    /// True when `log2(Q·P) ≤` the budget.
    #[must_use]
    pub fn fits(&self) -> bool {
        self.log_qp_bits() <= self.budget_bits
    }
}

fn bits_of(m: u64) -> usize {
    64 - m.leading_zeros() as usize
}

/// Bit accounting of `params` against the 128-bit table (special primes
/// included). Errors when the degree is not in the table.
pub fn security_budget(params: &CkksParameters) -> Result<SecurityBudget> {
    let degree = params.degree();
    let budget_bits = max_log_qp_bits(degree).ok_or_else(|| {
        Error::DefaultError(format!(
            "no 128-bit security row for degree {degree} (HE Standard 2018 Table 1)"
        ))
    })?;
    Ok(SecurityBudget {
        degree,
        log_q_bits: params.moduli().iter().map(|&m| bits_of(m)).sum(),
        log_p_bits: params.special_moduli().iter().map(|&m| bits_of(m)).sum(),
        budget_bits,
    })
}

/// Bit sizes of a base + `rescale_limbs` × 40-bit chain.
fn chain_sizes(rescale_limbs: usize) -> Vec<usize> {
    let mut sizes = vec![SECURE_BASE_BITS];
    sizes.extend(std::iter::repeat_n(SECURE_RESCALE_BITS, rescale_limbs));
    sizes
}

/// Planned `log2(Q·P)` of a base + `rescale_limbs` chain with `k` special
/// primes, BEFORE generating any prime (generated primes have exactly the
/// requested bit size).
#[must_use]
pub fn planned_log_qp_bits(rescale_limbs: usize, special_primes: usize) -> usize {
    SECURE_BASE_BITS + rescale_limbs * SECURE_RESCALE_BITS + special_primes * SECURE_SPECIAL_BITS
}

/// Build a secure set, refusing any shape over the budget for its degree.
fn build_checked(
    name: &str,
    degree: usize,
    rescale_limbs: usize,
    special_primes: usize,
) -> Result<Arc<CkksParameters>> {
    let budget = max_log_qp_bits(degree).ok_or_else(|| {
        Error::DefaultError(format!(
            "{name}: no 128-bit security row for degree {degree}"
        ))
    })?;
    let planned = planned_log_qp_bits(rescale_limbs, special_primes);
    if planned > budget {
        return Err(Error::DefaultError(format!(
            "{name}: log2(Q·P) = {SECURE_BASE_BITS} + {rescale_limbs}×{SECURE_RESCALE_BITS} + \
             {special_primes}×{SECURE_SPECIAL_BITS} = {planned} bits exceeds the 128-bit budget \
             of {budget} bits at N = {degree} (HE Standard 2018, ternary secret, classical)"
        )));
    }
    let params = CkksParametersBuilder::new()
        .set_degree(degree)
        .set_moduli_sizes(&chain_sizes(rescale_limbs))
        .set_special_moduli_sizes(&vec![SECURE_SPECIAL_BITS; special_primes])
        .set_scale(2f64.powi(SECURE_SCALE_BITS))
        .build_arc()?;
    // Belt and braces: the generated primes must add up to the plan.
    let actual = security_budget(&params)?;
    if !actual.fits() {
        return Err(Error::DefaultError(format!(
            "{name}: generated primes total {} bits > budget {}",
            actual.log_qp_bits(),
            actual.budget_bits
        )));
    }
    Ok(params)
}

/// `S1_stats`: `N = 32768`, 60 + 17×40-bit limbs, `k = 2`, `Δ = 2^40`;
/// `log2(Q·P) = 860 ≤ 881`. 17 multiplicative levels (statistics,
/// polynomial scoring, comparisons up to 5 iterations).
pub fn s1_stats() -> Result<Arc<CkksParameters>> {
    build_checked(
        "S1_stats",
        S1_DEGREE,
        S1_STATS_RESCALE_LIMBS,
        S1_SPECIAL_PRIMES,
    )
}

/// `S1_cmp`: the `iterations`-iteration sign-extraction ladder at
/// `N = 32768` (base + `1 + 3·iterations` 40-bit limbs, `k = 2`). Errors
/// with the exact bit count when the ladder exceeds 881 bits — six
/// iterations do (940 bits); see [`S1_MAX_SIGN_ITERATIONS`].
pub fn s1_cmp(iterations: usize) -> Result<Arc<CkksParameters>> {
    build_checked(
        &format!("S1_cmp{iterations}"),
        S1_DEGREE,
        1 + 3 * iterations,
        S1_SPECIAL_PRIMES,
    )
}

/// `S1_cmp6` as requested: DOES NOT FIT (940 > 881 bits) — always an
/// error naming the bound. Use [`s1_cmp`]`(`[`S1_MAX_SIGN_ITERATIONS`]`)`.
pub fn s1_cmp6() -> Result<Arc<CkksParameters>> {
    s1_cmp(6)
}

/// `S2_cmp`: the `iterations`-iteration ladder at `N = 65536` (base +
/// `1 + 3·iterations` 40-bit limbs, `k = 3`), budget 1772 bits.
pub fn s2_cmp(iterations: usize) -> Result<Arc<CkksParameters>> {
    build_checked(
        &format!("S2_cmp{iterations}"),
        S2_DEGREE,
        1 + 3 * iterations,
        S2_SPECIAL_PRIMES,
    )
}

/// `S2_cmp12`: `N = 65536`, 60 + 37×40-bit limbs, `k = 3`, `Δ = 2^40`;
/// `log2(Q·P) = 1720 ≤ 1772`. The 12-iteration sign-extraction ladder.
pub fn s2_cmp12() -> Result<Arc<CkksParameters>> {
    s2_cmp(S2_SIGN_ITERATIONS)
}

/// Named secure sets, for CLIs (`--preset`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureSet {
    /// [`s1_stats`].
    S1Stats,
    /// [`s1_cmp`]`(`[`S1_MAX_SIGN_ITERATIONS`]`)`.
    S1Cmp5,
    /// [`s1_cmp6`] — always rejected by the budget.
    S1Cmp6,
    /// [`s2_cmp12`].
    S2Cmp12,
}

impl SecureSet {
    /// Every set, in cost order.
    pub const ALL: [SecureSet; 4] = [
        SecureSet::S1Stats,
        SecureSet::S1Cmp5,
        SecureSet::S1Cmp6,
        SecureSet::S2Cmp12,
    ];

    /// CLI name (`s1-stats`, `s1-cmp5`, `s1-cmp6`, `s2-cmp12`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            SecureSet::S1Stats => "s1-stats",
            SecureSet::S1Cmp5 => "s1-cmp5",
            SecureSet::S1Cmp6 => "s1-cmp6",
            SecureSet::S2Cmp12 => "s2-cmp12",
        }
    }

    /// Parse a CLI name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }

    /// Build the set (errors for [`SecureSet::S1Cmp6`]).
    pub fn build(self) -> Result<Arc<CkksParameters>> {
        match self {
            SecureSet::S1Stats => s1_stats(),
            SecureSet::S1Cmp5 => s1_cmp(S1_MAX_SIGN_ITERATIONS),
            SecureSet::S1Cmp6 => s1_cmp6(),
            SecureSet::S2Cmp12 => s2_cmp12(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_secure_shape(
        params: &CkksParameters,
        degree: usize,
        rescale_limbs: usize,
        special: usize,
        expected_qp: usize,
    ) {
        assert_eq!(params.degree(), degree);
        assert_eq!(params.moduli().len(), 1 + rescale_limbs);
        assert_eq!(params.moduli_sizes()[0], SECURE_BASE_BITS);
        assert!(
            params.moduli_sizes()[1..]
                .iter()
                .all(|&b| b == SECURE_RESCALE_BITS)
        );
        assert_eq!(params.special_moduli().len(), special);
        assert!(params.hybrid_enabled(), "hybrid key switching must be on");
        assert_eq!(params.dnum(), (1 + rescale_limbs).div_ceil(special));
        assert!((params.scale() - 2f64.powi(SECURE_SCALE_BITS)).abs() < 1.0);

        // NTT-friendliness: every prime ≡ 1 (mod 2N), and all distinct.
        let mut all: Vec<u64> = params.moduli().to_vec();
        all.extend_from_slice(params.special_moduli());
        for &p in &all {
            assert_eq!(p % (2 * degree as u64), 1, "{p:#x} is not NTT-friendly");
        }
        let mut dedup = all.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(dedup.len(), all.len(), "primes must be distinct");

        // Budget.
        let b = security_budget(params).unwrap();
        assert_eq!(b.log_qp_bits(), expected_qp);
        assert!(
            b.fits(),
            "log2(Q·P) = {} > {}",
            b.log_qp_bits(),
            b.budget_bits
        );
        assert_eq!(
            b.log_qp_bits(),
            planned_log_qp_bits(rescale_limbs, special),
            "generated primes must have exactly the planned sizes"
        );
    }

    #[test]
    fn s1_stats_fits_881_with_maximum_depth() {
        let p = s1_stats().unwrap();
        assert_secure_shape(&p, 32768, 17, 2, 860);
        assert_eq!(security_budget(&p).unwrap().headroom_bits(), 21);
        assert_eq!(p.max_level(), 17, "17 multiplicative levels");
        // Maximality: one more 40-bit limb breaks the budget.
        assert!(planned_log_qp_bits(18, 2) > 881);
        assert!(build_checked("S1_stats+1", 32768, 18, 2).is_err());
    }

    #[test]
    fn s1_cmp6_does_not_fit_and_cmp5_is_the_largest() {
        let err = s1_cmp6().unwrap_err().to_string();
        assert!(err.contains("940"), "{err}");
        assert!(err.contains("881"), "{err}");
        let p = s1_cmp(S1_MAX_SIGN_ITERATIONS).unwrap();
        assert_secure_shape(&p, 32768, 16, 2, 820);
        assert!(s1_cmp(S1_MAX_SIGN_ITERATIONS + 1).is_err());
        // The stats set carries the 5-iteration ladder too.
        assert!(s1_stats().unwrap().max_level() > 3 * S1_MAX_SIGN_ITERATIONS);
    }

    #[test]
    fn s2_cmp12_fits_1772() {
        let p = s2_cmp12().unwrap();
        assert_secure_shape(&p, 65536, 37, 3, 1720);
        assert_eq!(security_budget(&p).unwrap().headroom_bits(), 52);
        assert_eq!(p.max_level(), 37);
        // 13 iterations (40 limbs) would need 1840 > 1772.
        assert!(s2_cmp(13).is_err());
    }

    #[test]
    fn budget_table_and_special_primes_count() {
        assert_eq!(max_log_qp_bits(32768), Some(881));
        assert_eq!(max_log_qp_bits(65536), Some(1772));
        assert_eq!(max_log_qp_bits(8192), Some(218));
        assert_eq!(max_log_qp_bits(16384), Some(438));
        assert_eq!(max_log_qp_bits(3000), None);
        // The §5.3 trap: secure32768-L20 (45 + 19×40 = 805) with k=2
        // 60-bit specials is 925 > 881.
        let l20 = CkksParametersBuilder::new()
            .set_degree(32768)
            .set_moduli_sizes(&{
                let mut s = vec![45usize];
                s.extend(std::iter::repeat_n(40usize, 19));
                s
            })
            .set_special_moduli_sizes(&[60, 60])
            .set_scale(2f64.powi(40))
            .build_arc()
            .unwrap();
        let b = security_budget(&l20).unwrap();
        assert_eq!(b.log_q_bits, 805);
        assert_eq!(b.log_p_bits, 120);
        assert!(!b.fits());
        assert_eq!(b.headroom_bits(), 0);
    }

    #[test]
    fn cli_names_roundtrip() {
        for s in SecureSet::ALL {
            assert_eq!(SecureSet::from_name(s.name()), Some(s));
        }
        assert_eq!(SecureSet::from_name("nope"), None);
        assert!(SecureSet::S1Cmp6.build().is_err());
    }
}
