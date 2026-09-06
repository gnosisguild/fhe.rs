//! Application feasibility of threshold decryption at the 128-bit-secure
//! parameter sets: does the flooding bound derived by
//! [`CkksSmudgingBoundCalculator`] clear both CKKS correctness walls for a
//! given application class and committee size?
//!
//! The four application classes benchmarked in
//! `examples/trckks_dkg_bench.rs --app …` and their circuit shapes for the
//! calculator (`CkksCircuitShape`), with the input bounds the demo apps
//! use:
//!
//! | app   | shape | input bound | precision target |
//! |-------|-------|-------------|------------------|
//! | `stats` (mean/variance over `m` users, `statistics_packed_policy`) | `one_level(m, output_scale)` — `m` additions, ONE rescale, the one-hot masks (`output_scale = 10^4`) are the largest multiplied operand | 1.0 (salary / cap ∈ [0, 1]) | 0.01 (two decimals of the `10^4`-scaled slot) |
//! | `poly4` (depth-4 polynomial score) | depth 4, operand 1.0 | 1.0 | 0.01 |
//! | `cmpK` (`K`-iteration sign extraction, `sign_extraction_policy`) | depth `1 + 3K`, operand 1.0 (`|y| ≤ 1` throughout) | 1.0 (auction `|y| ≤ 1`) | 0.05 (`|slot| ∈ [0.95, 1.05]`) |
//!
//! `lambda` is the BFV secure floor [`crate::trbfv::MIN_SECURE_LAMBDA`]
//! (50). Every row reports the calculator verdict (`sm_bits` or which wall
//! fails) and — because the walls do NOT close at these sets for the
//! secure floor (see the tests and `BENCHMARKS_TRCKKS.md` §6) — what would
//! close them: the opening scale `Δ_eff` the precision wall needs, and the
//! largest `λ` the walls admit at the set's own `Δ = 2^40`.
//!
//! Why they fail, in one line: the calculator's worst-case sup-norm fresh
//! noise is `B_fresh = (2N + 1)·2σ² ≈ 2^20.3` at `N = 32768` and every
//! multiplicative level multiplies it by `N` (the rescale only cancels
//! `Δ`), so `B_C ≥ 2^(20 + 15·depth)`; the precision wall wants
//! `n·2^λ·B_C ≤ precision·Δ_eff` with `Δ_eff ≈ 2^40`, i.e.
//! `2^(50 + 20 + 15·depth + log n) ≤ 2^(40 − 7)` — impossible at any
//! depth. Multiplying by plaintext masks does not help (signal and noise
//! scale together); only a larger opening scale relative to `B_C`
//! (`Δ_eff ≥ n·2^λ·B_C / precision`, which is `≥ 2^80` even at depth 0
//! and above the encoder's `2^63` coefficient cap), a smaller `λ`
//! (Rényi-divergence flooding arguments admit `≈ λ/2`), or an
//! average-case noise model in the calculator would.

use crate::ckks::CkksParameters;
use crate::ckks::secure_presets::{S1_MAX_SIGN_ITERATIONS, S2_SIGN_ITERATIONS};
use crate::trbfv::{Lambda, MIN_SECURE_LAMBDA};
use crate::trckks::smudging::{CkksCircuitShape, CkksSmudgingBoundCalculator, CkksSmudgingConfig};
use crate::{Error, Result};
use num_bigint::BigUint;
use std::sync::Arc;

/// Public output scale of the statistics app (`10^4`, two on-chain
/// decimals on a normalized aggregate).
pub const STATS_OUTPUT_SCALE: f64 = 1e4;
/// Precision target of the statistics and polynomial apps (absolute, on
/// the opened slot).
pub const STATS_PRECISION: f64 = 0.01;
/// Precision target of the sign-extraction apps (`|slot| ∈ [0.95, 1.05]`).
pub const CMP_PRECISION: f64 = 0.05;
/// Committee sizes of the feasibility matrix.
pub const COMMITTEE_SIZES: [usize; 4] = [3, 5, 10, 20];

/// The application classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppClass {
    /// Mean/variance over `m` users: depth 1, `m` additions, `10^4` mask.
    Stats {
        /// Number of user ciphertexts summed.
        users: usize,
    },
    /// Depth-4 polynomial score on one input vector.
    Poly4,
    /// `iterations`-iteration sign extraction (depth `1 + 3·iterations`).
    Cmp {
        /// Cubic sign-map iterations.
        iterations: usize,
    },
}

impl AppClass {
    /// The four report rows for a set: `stats` (100 users), `poly4`,
    /// `cmp5`/`cmp6`, `cmp12` — filtered to those the set has levels for
    /// by [`AppClass::fits`].
    pub const REPORT_ROWS: [AppClass; 5] = [
        AppClass::Stats { users: 100 },
        AppClass::Poly4,
        AppClass::Cmp {
            iterations: S1_MAX_SIGN_ITERATIONS,
        },
        AppClass::Cmp { iterations: 6 },
        AppClass::Cmp {
            iterations: S2_SIGN_ITERATIONS,
        },
    ];

    /// CLI / table name (`stats`, `poly4`, `cmp<K>`).
    #[must_use]
    pub fn name(self) -> String {
        match self {
            AppClass::Stats { .. } => "stats".into(),
            AppClass::Poly4 => "poly4".into(),
            AppClass::Cmp { iterations } => format!("cmp{iterations}"),
        }
    }

    /// Parse a CLI name (`stats`, `poly4`, `cmp5`, `cmp6`, `cmp12`, …).
    #[must_use]
    pub fn from_name(name: &str, users: usize) -> Option<Self> {
        match name {
            "stats" => Some(AppClass::Stats { users }),
            "poly4" => Some(AppClass::Poly4),
            other => other
                .strip_prefix("cmp")
                .and_then(|k| k.parse::<usize>().ok())
                .filter(|k| *k > 0)
                .map(|iterations| AppClass::Cmp { iterations }),
        }
    }

    /// Multiplicative depth (rescales) consumed before the opening.
    #[must_use]
    pub fn depth(self) -> usize {
        match self {
            AppClass::Stats { .. } => 1,
            AppClass::Poly4 => 4,
            AppClass::Cmp { iterations } => 1 + 3 * iterations,
        }
    }

    /// Whether `params` has enough levels for this app.
    #[must_use]
    pub fn fits(self, params: &CkksParameters) -> bool {
        self.depth() <= params.max_level()
    }

    /// Circuit shape for the calculator.
    #[must_use]
    pub fn circuit(self) -> CkksCircuitShape {
        match self {
            AppClass::Stats { users } => CkksCircuitShape::one_level(users, STATS_OUTPUT_SCALE),
            AppClass::Poly4 => CkksCircuitShape {
                num_additions: 1,
                depth: 4,
                mult_operand_bound: 1.0,
            },
            AppClass::Cmp { iterations } => CkksCircuitShape {
                num_additions: 1,
                depth: 1 + 3 * iterations,
                mult_operand_bound: 1.0,
            },
        }
    }

    /// Sup-norm bound on the encoded inputs.
    #[must_use]
    pub fn input_bound(self) -> f64 {
        1.0
    }

    /// Tolerated absolute error on the opened slots.
    #[must_use]
    pub fn precision(self) -> f64 {
        match self {
            AppClass::Stats { .. } | AppClass::Poly4 => STATS_PRECISION,
            AppClass::Cmp { .. } => CMP_PRECISION,
        }
    }
}

/// Which correctness wall the calculator hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wall {
    /// `eff_scale·B_msg + B_C + n·B_sm ≥ Q_l/2`.
    WrapAround,
    /// `n·B_sm > precision·eff_scale`.
    Precision,
}

/// One row of the feasibility matrix.
#[derive(Debug, Clone, PartialEq)]
pub struct FeasibilityRow {
    /// Application.
    pub app: AppClass,
    /// Committee size.
    pub n_parties: usize,
    /// Statistical security parameter used.
    pub lambda: usize,
    /// Level of the opened ciphertext (= depth).
    pub level: usize,
    /// `log2 B_C` (bits of the worst-case circuit noise bound).
    pub circuit_noise_bits: usize,
    /// `log2 B_sm` = `lambda + circuit_noise_bits` — what
    /// `calculate_sm_bits()` returns when the walls close, and what the
    /// security floor demands regardless.
    pub sm_bits: usize,
    /// `Ok(sm_bits)` when both walls close; `Err(wall)` otherwise.
    pub verdict: std::result::Result<usize, Wall>,
    /// Decoded absolute error the flooding would cause at the set's own
    /// opening scale: `n·B_sm / Δ_eff` (the "precision loss"; ≤ the
    /// target when the precision wall closes).
    pub precision_loss: f64,
    /// `log2` of the opening scale `Δ_eff` the precision wall needs
    /// (`n·B_sm / precision`), given `B_C`.
    pub required_opening_scale_bits: usize,
    /// `log2 Q_l` the wrap wall would then need
    /// (`2·(Δ_eff·B_msg + B_C + n·B_sm)` with that `Δ_eff`).
    pub required_modulus_bits: usize,
    /// `log2 Q_l` the set actually has at the opening level.
    pub available_modulus_bits: usize,
    /// Largest `λ` at which both walls close at the set's own `Δ_eff`
    /// (`None` when not even `λ = 0` closes).
    pub max_closing_lambda: Option<usize>,
}

impl FeasibilityRow {
    /// True when both walls close at `lambda`.
    #[must_use]
    pub fn closes(&self) -> bool {
        self.verdict.is_ok()
    }
}

/// Effective opening scale after `depth` rescales (the calculator's
/// private rule, replicated for the "what would close it" numbers:
/// `Δ^(depth+1) / ∏ dropped moduli`, dropping from the chain's end).
fn effective_scale(params: &CkksParameters, depth: usize) -> Result<f64> {
    let moduli = params.moduli();
    if depth + 1 > moduli.len() {
        return Err(Error::DefaultError(
            "circuit depth exceeds the moduli chain".into(),
        ));
    }
    let mut eff = params.scale();
    for i in 0..depth {
        eff = eff * params.scale() / (moduli[moduli.len() - 1 - i] as f64);
    }
    Ok(eff)
}

fn q_bits_at_level(params: &CkksParameters, level: usize) -> Result<usize> {
    Ok(params
        .context_at_level(level)?
        .moduli()
        .iter()
        .map(|&m| 64 - m.leading_zeros() as usize)
        .sum())
}

/// Evaluate one (set, app, n, λ) cell through the calculator.
pub fn feasibility(
    params: &Arc<CkksParameters>,
    app: AppClass,
    n_parties: usize,
    lambda: Lambda,
) -> Result<FeasibilityRow> {
    if !app.fits(params) {
        return Err(Error::DefaultError(format!(
            "{} needs depth {} but the set has {} levels",
            app.name(),
            app.depth(),
            params.max_level()
        )));
    }
    let level = app.depth();
    let circuit = app.circuit();
    let calc = CkksSmudgingBoundCalculator::new(CkksSmudgingConfig {
        params: params.clone(),
        n_parties,
        circuit: circuit.clone(),
        level,
        input_bound: app.input_bound(),
        precision_loss: app.precision(),
        lambda,
    });
    let b_c = calc.circuit_noise_bound();
    let circuit_noise_bits = b_c.bits() as usize;
    let b_sm = BigUint::from(2u32).pow(lambda.value() as u32) * &b_c;
    let sm_bits = b_sm.bits() as usize;
    let n = BigUint::from(n_parties);
    let n_bsm = &n * &b_sm;

    let verdict = match calc.calculate_sm_bits() {
        Ok(bits) => Ok(bits),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("wrap-around") {
                Err(Wall::WrapAround)
            } else if msg.contains("precision") {
                Err(Wall::Precision)
            } else {
                return Err(e);
            }
        }
    };

    let eff = effective_scale(params, level)?;
    let precision_loss = big_to_f64(&n_bsm) / eff;

    // Message bound after the circuit (the calculator's rule).
    let mut msg_bound = app.input_bound() * circuit.num_additions as f64;
    for _ in 0..circuit.depth {
        msg_bound *= circuit.mult_operand_bound.abs().max(1.0);
    }
    // Precision wall: Δ_eff ≥ n·B_sm / precision.
    let required_eff = big_to_f64(&n_bsm) / app.precision();
    let required_opening_scale_bits = required_eff.log2().ceil().max(0.0) as usize;
    // Wrap wall at that Δ_eff: Q_l > 2·(Δ_eff·B_msg + B_C + n·B_sm).
    let required_modulus_bits = (2.0
        * (required_eff * msg_bound + big_to_f64(&b_c) + big_to_f64(&n_bsm)))
    .log2()
    .ceil() as usize;
    let available_modulus_bits = q_bits_at_level(params, level)?;

    // Largest λ closing BOTH walls at the set's own Δ_eff:
    //   precision: n·2^λ·B_C ≤ p·Δ_eff
    //   wrap:      Δ_eff·B_msg + B_C + n·2^λ·B_C < Q_l/2
    let q_l = {
        let mut q = BigUint::from(1u32);
        for &m in params.context_at_level(level)?.moduli() {
            q *= BigUint::from(m);
        }
        q
    };
    let half_q = &q_l / BigUint::from(2u32);
    let delta_bmsg = BigUint::from((eff * msg_bound).ceil() as u128);
    let precision_budget = BigUint::from((app.precision() * eff).floor() as u128);
    let n_bc = &n * &b_c;
    let by_precision = &precision_budget / &n_bc; // 2^λ ≤ this
    let occupied = &delta_bmsg + &b_c;
    let wrap_room = (half_q > occupied).then(|| &half_q - &occupied);
    let by_wrap = wrap_room.map(|r| r / &n_bc);
    let max_closing_lambda = match by_wrap {
        Some(w) => {
            let cap = if w < by_precision { w } else { by_precision };
            if cap.bits() == 0 {
                None
            } else {
                Some(cap.bits() as usize - 1)
            }
        }
        None => None,
    };

    Ok(FeasibilityRow {
        app,
        n_parties,
        lambda: lambda.value(),
        level,
        circuit_noise_bits,
        sm_bits,
        verdict,
        precision_loss,
        required_opening_scale_bits,
        required_modulus_bits,
        available_modulus_bits,
        max_closing_lambda,
    })
}

fn big_to_f64(x: &BigUint) -> f64 {
    // BigUint -> f64 with exponent handling for values beyond f64 range.
    let bits = x.bits();
    if bits <= 1000 {
        let s = x.to_string();
        s.parse::<f64>().unwrap_or(f64::INFINITY)
    } else {
        f64::INFINITY
    }
}

/// The full matrix for one set at the secure floor: every
/// [`AppClass::REPORT_ROWS`] app that fits × [`COMMITTEE_SIZES`].
pub fn matrix(params: &Arc<CkksParameters>) -> Result<Vec<FeasibilityRow>> {
    let lambda = Lambda::secure(MIN_SECURE_LAMBDA)?;
    let mut rows = Vec::new();
    for app in AppClass::REPORT_ROWS {
        if !app.fits(params) {
            continue;
        }
        for n in COMMITTEE_SIZES {
            rows.push(feasibility(params, app, n, lambda)?);
        }
    }
    Ok(rows)
}

/// Markdown rendering of a matrix (one table).
#[must_use]
pub fn matrix_markdown(set_name: &str, rows: &[FeasibilityRow]) -> String {
    let mut s = String::new();
    s.push_str(
        "| set | app | depth/level | n | λ | log₂B_C | sm_bits | walls close? | flooding error at Δ_eff (target) | Δ_eff needed (bits) | Q_l needed / have (bits) | max closing λ |\n",
    );
    s.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for r in rows {
        let verdict = match r.verdict {
            Ok(_) => "✅ both".to_string(),
            Err(Wall::Precision) => "❌ precision".to_string(),
            Err(Wall::WrapAround) => "❌ wrap-around".to_string(),
        };
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.1e} ({}) | {} | {} / {} | {} |\n",
            set_name,
            r.app.name(),
            r.level,
            r.n_parties,
            r.lambda,
            r.circuit_noise_bits,
            r.sm_bits,
            verdict,
            r.precision_loss,
            r.app.precision(),
            r.required_opening_scale_bits,
            r.required_modulus_bits,
            r.available_modulus_bits,
            r.max_closing_lambda
                .map_or("none".to_string(), |l| l.to_string()),
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckks::secure_presets::{s1_cmp, s1_stats, s2_cmp12};

    #[test]
    fn app_names_roundtrip() {
        for app in AppClass::REPORT_ROWS {
            let users = match app {
                AppClass::Stats { users } => users,
                AppClass::Poly4 | AppClass::Cmp { .. } => 1,
            };
            assert_eq!(AppClass::from_name(&app.name(), users), Some(app));
        }
        assert_eq!(AppClass::from_name("cmp0", 1), None);
        assert_eq!(AppClass::from_name("nope", 1), None);
        assert_eq!(AppClass::Cmp { iterations: 12 }.depth(), 37);
        assert_eq!(AppClass::Stats { users: 7 }.depth(), 1);
    }

    /// Encodes the §6 matrix: at the secure floor λ = 50 and Δ = 2^40, NO
    /// (set, app, n) cell closes. Shallow apps (stats, poly4) fail the
    /// PRECISION wall (the wrap wall has hundreds of bits of room at their
    /// opening level); the deep comparison ladders fail BOTH — the
    /// worst-case `B_C` alone exceeds `Q_l` at the opening level, so the
    /// calculator reports the wrap-around wall (checked first). The
    /// required opening scale is ≥ 2^80 even for the shallowest app.
    #[test]
    fn secure_floor_matrix_hits_the_precision_wall_everywhere() {
        let sets = [
            ("S1_stats", s1_stats().unwrap()),
            ("S1_cmp5", s1_cmp(S1_MAX_SIGN_ITERATIONS).unwrap()),
            ("S2_cmp12", s2_cmp12().unwrap()),
        ];
        for (name, params) in &sets {
            let rows = matrix(params).unwrap();
            assert!(!rows.is_empty());
            for r in &rows {
                assert_eq!(r.lambda, MIN_SECURE_LAMBDA);
                assert!(!r.closes(), "{name} {} n={}", r.app.name(), r.n_parties);
                // The calculator checks the wrap wall first: it fires
                // whenever the worst-case noise no longer fits Q_l (the
                // deep comparison ladders opened near the chain's end);
                // otherwise the precision wall is the one that fails.
                let expected = if r.sm_bits + 2 > r.available_modulus_bits {
                    Wall::WrapAround
                } else {
                    Wall::Precision
                };
                assert_eq!(
                    r.verdict,
                    Err(expected),
                    "{name} {} n={} : {:?}",
                    r.app.name(),
                    r.n_parties,
                    r
                );
                if expected == Wall::WrapAround {
                    // B_C alone does not fit the opening modulus.
                    assert!(r.circuit_noise_bits > r.available_modulus_bits, "{r:?}");
                }
                assert_eq!(r.sm_bits, r.circuit_noise_bits + MIN_SECURE_LAMBDA);
                assert!(r.precision_loss > r.app.precision());
                assert!(r.required_opening_scale_bits >= 80, "{r:?}");
                assert!(r.available_modulus_bits >= 60);
                assert!(r.max_closing_lambda.is_none(), "{name}: {r:?}");
            }
        }
    }

    /// Row shape pins for the report (S1_stats, stats over 100 users).
    #[test]
    fn s1_stats_row_numbers() {
        let params = s1_stats().unwrap();
        let r = feasibility(
            &params,
            AppClass::Stats { users: 100 },
            5,
            Lambda::secure(MIN_SECURE_LAMBDA).unwrap(),
        )
        .unwrap();
        // B_fresh = (2·32768+1)·20 ≈ 2^20.3; ×100 users, ×10^4 mask·N at
        // the one level ⇒ ≈ 2^55.
        assert!((54..=57).contains(&r.circuit_noise_bits), "{r:?}");
        assert_eq!(r.level, 1);
        assert_eq!(r.available_modulus_bits, 60 + 16 * 40);
        assert_eq!(r.sm_bits, r.circuit_noise_bits + 50);
    }

    /// The sign-extraction depth is the killer: B_C grows by N per level.
    #[test]
    fn cmp_rows_grow_fifteen_bits_per_level() {
        let params = s2_cmp12().unwrap();
        let l = Lambda::secure(MIN_SECURE_LAMBDA).unwrap();
        let c6 = feasibility(&params, AppClass::Cmp { iterations: 6 }, 5, l).unwrap();
        let c12 = feasibility(&params, AppClass::Cmp { iterations: 12 }, 5, l).unwrap();
        assert_eq!(c6.level, 19);
        assert_eq!(c12.level, 37);
        let per_level = (c12.circuit_noise_bits - c6.circuit_noise_bits) as f64 / 18.0;
        assert!((15.5..=16.5).contains(&per_level), "{per_level}");
        assert_eq!(c12.available_modulus_bits, 60);
    }

    /// Sanity of the "what closes it" columns: at a tiny insecure λ the
    /// calculator agrees with `max_closing_lambda`.
    #[test]
    fn max_closing_lambda_is_consistent_with_the_calculator() {
        let params = crate::ckks::CkksParametersBuilder::new()
            .set_degree(64)
            .set_moduli_sizes(&[60, 60, 60])
            .set_scale(2f64.powi(52))
            .build_arc()
            .unwrap();
        let app = AppClass::Stats { users: 2 };
        let probe = feasibility(&params, app, 5, Lambda::insecure(2)).unwrap();
        assert!(probe.max_closing_lambda.is_some(), "{probe:?}");
        let lmax = probe.max_closing_lambda.unwrap_or_default();
        assert!(
            feasibility(&params, app, 5, Lambda::insecure(lmax))
                .unwrap()
                .closes()
        );
        assert!(
            !feasibility(&params, app, 5, Lambda::insecure(lmax + 1))
                .unwrap()
                .closes()
        );
        // And the markdown renderer does not panic.
        let md = matrix_markdown("tiny", &[probe]);
        assert!(md.contains("tiny"));
    }
}
