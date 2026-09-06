// SPDX-License-Identifier: MIT

//! Print the §6 feasibility matrix (`BENCHMARKS_TRCKKS.md`) for the
//! 128-bit-secure threshold-CKKS parameter sets as markdown, from the
//! smudging calculator at the secure floor `lambda = MIN_SECURE_LAMBDA`.
//!
//! ```text
//! cargo run --release --example trckks_secure_feasibility
//! ```

#![allow(clippy::indexing_slicing)]

use fhe::ckks::secure_presets::{
    S1_MAX_SIGN_ITERATIONS, s1_cmp, s1_stats, s2_cmp12, security_budget,
};
use fhe::trckks::app_feasibility::{matrix, matrix_markdown};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let sets = [
        ("S1_stats", s1_stats()?),
        ("S1_cmp5", s1_cmp(S1_MAX_SIGN_ITERATIONS)?),
        ("S2_cmp12", s2_cmp12()?),
    ];
    println!(
        "| set | N | limbs (bits) | log₂Q | k | log₂P | log₂(Q·P) | budget | headroom | depth | dnum |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|");
    for (name, p) in &sets {
        let b = security_budget(p)?;
        let sizes = p.moduli_sizes();
        println!(
            "| {} | {} | {} + {}×{} | {} | {} | {} | {} | {} | {} | {} | {} |",
            name,
            p.degree(),
            sizes[0],
            sizes.len() - 1,
            sizes[1],
            b.log_q_bits,
            p.special_moduli().len(),
            b.log_p_bits,
            b.log_qp_bits(),
            b.budget_bits,
            b.headroom_bits(),
            p.max_level(),
            p.dnum()
        );
    }
    println!();
    for (name, p) in &sets {
        let rows = matrix(p)?;
        print!("{}", matrix_markdown(name, &rows));
        println!();
    }
    Ok(())
}
