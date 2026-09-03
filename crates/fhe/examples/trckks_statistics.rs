// SPDX-License-Identifier: MIT

//! Private statistics under threshold CKKS.
//!
//! A committee holds a joint CKKS key (distributed keygen; no single party
//! ever has the secret). Data providers submit encrypted real-valued
//! measurements. The evaluator homomorphically computes ONLY aggregate
//! statistics — count-weighted sum and sum of squares — and the committee
//! threshold-decrypts only those aggregates. Mean and variance are derived
//! publicly; no individual measurement is ever decrypted.
//!
//! The sum-of-squares uses ciphertext-ciphertext multiplication, so this
//! example also exercises the multiparty relinearization key (two-round CRP
//! protocol) and rescaling.
//!
//! Smudging here is demo-sized (20 bits); production MUST derive the bound
//! with `fhe::trckks::CkksSmudgingBoundCalculator` (IND-CPA-D flooding),
//! which will require a wider modulus chain than these demo parameters —
//! see `trckks::tests::threshold_decrypt_with_derived_flooding_bound`.
//!
//! Run with: `cargo run --release --example trckks_statistics`

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksParameters, CkksParametersBuilder};
use fhe::trckks::{
    CkksCrp, CkksPublicKeyShare, CkksRelinKeyGenerator, CkksRelinKeyShare, R1Aggregated, R2, TRCKKS,
};
use ndarray::Array2;
use rand::RngCore;
use std::error::Error;
use std::sync::Arc;

struct CommitteeMember {
    sk_share: fhe_math::rq::Poly<fhe_math::rq::PowerBasis>,
    es_share: fhe_math::rq::Poly<fhe_math::rq::PowerBasis>,
}

fn threshold_decrypt(
    trckks: &TRCKKS,
    members: &[CommitteeMember],
    ct: &CkksCiphertext,
    encoder: &CkksEncoder,
) -> Result<f64, Box<dyn Error>> {
    let parties: Vec<usize> = (1..=trckks.threshold + 1).collect();
    let mut d_shares = Vec::new();
    for &j in &parties {
        let member = &members[j - 1];
        let sk_j = trckks.project_share_to_level(&member.sk_share, ct.level)?;
        let es_j = trckks.project_share_to_level(&member.es_share, ct.level)?;
        d_shares.push(trckks.decryption_share(ct, sk_j.into_ntt(), es_j)?);
    }
    let pt = trckks.decrypt(d_shares, parties, ct)?;
    Ok(encoder.decode(&pt)?[0])
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = rand::rng();

    // Insecure demo parameters. Three moduli: one level is consumed by the
    // squaring's rescale.
    let params: Arc<CkksParameters> = CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli_sizes(&[45, 45, 45])
        .set_scale(2f64.powi(40))
        .build_arc()?;
    let encoder = CkksEncoder::new(&params);

    let n_committee = 5;
    let threshold = 2;
    let trckks = TRCKKS::new(n_committee, threshold, params.clone())?;

    println!("== Private statistics under threshold CKKS ==");
    println!("committee: n={n_committee}, threshold={threshold}");

    // --- Distributed key generation (pk + two-round relin key) ---
    let mut seed_pk = [0u8; 32];
    rng.fill_bytes(&mut seed_pk);
    let crp_pk = CkksCrp::from_seed(&params, seed_pk)?;
    let mut seed_rlk = [0u8; 32];
    rng.fill_bytes(&mut seed_rlk);
    let crp_rlk = CkksCrp::vec_from_seed(&params, seed_rlk, params.moduli().len())?;

    let sks: Vec<_> = (0..n_committee)
        .map(|_| fhe::ckks::CkksSecretKey::random(&params, &mut rng))
        .collect();

    let pk_shares = sks
        .iter()
        .map(|sk| CkksPublicKeyShare::new(sk, crp_pk.clone(), &mut rng))
        .collect::<Result<Vec<_>, _>>()?;
    let pk = CkksPublicKeyShare::aggregate(&pk_shares)?;

    let generators = sks
        .iter()
        .map(|sk| CkksRelinKeyGenerator::new(sk, &crp_rlk, &mut rng))
        .collect::<Result<Vec<_>, _>>()?;
    let r1_shares = generators
        .iter()
        .map(|g| g.round_1(&mut rng))
        .collect::<Result<Vec<_>, _>>()?;
    let r1_agg = Arc::new(CkksRelinKeyShare::<R1Aggregated>::from_shares(r1_shares)?);
    let r2_shares = generators
        .iter()
        .map(|g| g.round_2(&r1_agg, &mut rng))
        .collect::<Result<Vec<_>, _>>()?;
    let rlk = CkksRelinKeyShare::<R2>::aggregate_into_key(r2_shares)?;
    println!("DKG complete: joint public key + multiparty relinearization key");

    // Committee members deal + aggregate key/smudging shares.
    let mut sk_matrices = Vec::new();
    let mut es_matrices = Vec::new();
    for sk_i in &sks {
        let sk_poly = trckks.coeffs_to_poly(sk_i.coeffs.as_ref())?;
        sk_matrices.push(trckks.generate_secret_shares_from_poly(sk_poly, &mut rng)?);
        let es = trckks.generate_smudging_error(20, &mut rng)?;
        let es_poly = trckks.smudging_to_poly(&es)?;
        es_matrices.push(trckks.generate_secret_shares_from_poly(es_poly, &mut rng)?);
    }
    let collect = |matrices: &[Vec<Array2<u64>>], j: usize| -> Vec<Array2<u64>> {
        matrices
            .iter()
            .map(|dealer| {
                let mut arr = Array2::<u64>::zeros((dealer.len(), dealer[0].ncols()));
                for (r, m) in dealer.iter().enumerate() {
                    arr.row_mut(r).assign(&m.row(j));
                }
                arr
            })
            .collect()
    };
    let mut members = Vec::new();
    for j in 0..n_committee {
        members.push(CommitteeMember {
            sk_share: trckks.aggregate_collected_shares(&collect(&sk_matrices, j))?,
            es_share: trckks.aggregate_collected_shares(&collect(&es_matrices, j))?,
        });
    }

    // --- Data providers encrypt their measurements ---
    let measurements = [
        36.61f64, 37.02, 36.55, 38.10, 36.90, 37.44, 36.75, 37.20, 36.40, 37.85,
    ];
    let n_data = measurements.len() as f64;
    println!("\n{} encrypted measurements submitted", measurements.len());

    let cts: Vec<CkksCiphertext> = measurements
        .iter()
        .map(|m| {
            let pt = encoder.encode(&[*m], 0)?;
            pk.try_encrypt(&pt, &mut rng)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // --- Evaluator: homomorphic aggregates only ---
    // sum = Σ x_i  (additions only, exact scale)
    let mut ct_sum = cts[0].clone();
    for ct in &cts[1..] {
        ct_sum = ct_sum.try_add(ct)?;
    }

    // sumsq = Σ x_i²  (square each, relinearize, then sum; single rescale at
    // the end keeps every addend at the same scale)
    let mut ct_sumsq: Option<CkksCiphertext> = None;
    for ct in &cts {
        let mut sq = ct.try_mul(ct)?;
        rlk.relinearizes(&mut sq)?;
        ct_sumsq = Some(match ct_sumsq {
            None => sq,
            Some(acc) => acc.try_add(&sq)?,
        });
    }
    let mut ct_sumsq = ct_sumsq.unwrap();
    ct_sumsq.rescale()?;

    // --- Committee: threshold-decrypt ONLY the two aggregates ---
    let sum = threshold_decrypt(&trckks, &members, &ct_sum, &encoder)?;
    let sumsq = threshold_decrypt(&trckks, &members, &ct_sumsq, &encoder)?;

    let mean = sum / n_data;
    let variance = sumsq / n_data - mean * mean;
    let std_dev = variance.sqrt();

    println!("\ndecrypted aggregates (the only values ever opened):");
    println!("  sum   = {sum:.4}");
    println!("  sumsq = {sumsq:.4}");
    println!("\nderived statistics:");
    println!("  mean     = {mean:.4}");
    println!("  variance = {variance:.4}");
    println!("  std-dev  = {std_dev:.4}");

    // Verify against plaintext computation.
    let true_sum: f64 = measurements.iter().sum();
    let true_mean = true_sum / n_data;
    let true_var = measurements
        .iter()
        .map(|x| (x - true_mean).powi(2))
        .sum::<f64>()
        / n_data;
    assert!((sum - true_sum).abs() < 0.01, "sum error too large");
    assert!((mean - true_mean).abs() < 0.001, "mean error too large");
    assert!(
        (variance - true_var).abs() < 0.05,
        "variance error too large"
    );
    println!(
        "\nverified against plaintext: mean {true_mean:.4}, variance {true_var:.4} — \
         individual measurements never decrypted"
    );
    Ok(())
}
