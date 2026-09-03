// SPDX-License-Identifier: MIT

//! Sealed-bid (Vickrey) auction under threshold CKKS.
//!
//! Demonstrates a complete second-price auction where no single party ever
//! sees an individual bid:
//!
//! 1. A committee of `n` parties runs distributed key generation (CRP-based):
//!    the joint public key exists, the joint secret key never does.
//! 2. Each bidder encrypts its bid under the joint public key.
//! 3. The (untrusted) auctioneer computes MASKED pairwise differences
//!    `r_ij * (b_i - b_j)` homomorphically, with fresh random positive masks
//!    `r_ij`. The committee threshold-decrypts only these masked values:
//!    the SIGN reveals which bid is larger, the magnitude is blinded by the
//!    mask.
//! 4. The comparison tournament yields the winner publicly; the committee
//!    then threshold-decrypts exactly one more value — the SECOND-highest
//!    bid — which is the Vickrey clearing price.
//!
//! What is revealed: the ranking-comparison bits and the clearing price.
//! What is never revealed: any losing bid value, or the winner's own bid.
//!
//! Leakage caveat (for production): a masked difference reveals
//! `r_ij * (b_i - b_j)`; with a uniform mask on a bounded range this leaks
//! some magnitude information beyond the sign. Production deployments
//! should add encrypted additive blinding or use a sign-extraction
//! polynomial instead. Smudging here is demo-sized (20 bits); a deployment
//! MUST derive the bound with `fhe::trckks::CkksSmudgingBoundCalculator`
//! (IND-CPA-D flooding), which will require a wider modulus chain than
//! these demo parameters provide — see
//! `trckks::tests::threshold_decrypt_with_derived_flooding_bound` for the
//! calculator-driven flow.
//!
//! Run with: `cargo run --release --example trckks_auction`

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksParameters, CkksParametersBuilder};
use fhe::trckks::{CkksCrp, CkksPublicKeyShare, TRCKKS};
use ndarray::Array2;
use rand::Rng;
use std::error::Error;
use std::sync::Arc;

/// Committee member state: its dealt share matrices from every dealer.
struct CommitteeMember {
    /// Aggregated share of the joint secret key (level 0).
    sk_share: fhe_math::rq::Poly<fhe_math::rq::PowerBasis>,
    /// Aggregated share of the joint smudging noise.
    es_share: fhe_math::rq::Poly<fhe_math::rq::PowerBasis>,
}

fn setup_committee(
    trckks: &TRCKKS,
    params: &Arc<CkksParameters>,
    n: usize,
    rng: &mut impl rand::CryptoRng,
) -> Result<(fhe::ckks::CkksPublicKey, Vec<CommitteeMember>), Box<dyn Error>> {
    // Public CRP that every party derives from a common seed.
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let crp = CkksCrp::from_seed(params, seed)?;

    // Each committee member samples a secret contribution, publishes a
    // public-key share, and deals Shamir shares of its secret + smudging
    // noise to all members.
    let mut pk_shares = Vec::new();
    let mut sk_matrices = Vec::new();
    let mut es_matrices = Vec::new();
    for _ in 0..n {
        let sk_i = fhe::ckks::CkksSecretKey::random(params, rng);
        pk_shares.push(CkksPublicKeyShare::new(&sk_i, crp.clone(), rng)?);

        let sk_poly = trckks.coeffs_to_poly(sk_i.coeffs.as_ref())?;
        sk_matrices.push(trckks.generate_secret_shares_from_poly(sk_poly, rng)?);

        let es = trckks.generate_smudging_error(20, rng)?;
        let es_poly = trckks.smudging_to_poly(&es)?;
        es_matrices.push(trckks.generate_secret_shares_from_poly(es_poly, rng)?);
    }

    let pk = CkksPublicKeyShare::aggregate(&pk_shares)?;

    // Each member aggregates the rows it received from every dealer.
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
    for j in 0..n {
        members.push(CommitteeMember {
            sk_share: trckks.aggregate_collected_shares(&collect(&sk_matrices, j))?,
            es_share: trckks.aggregate_collected_shares(&collect(&es_matrices, j))?,
        });
    }
    Ok((pk, members))
}

/// Threshold-decrypt a ciphertext with the first `threshold + 1` members.
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

    // Insecure demo parameters (small degree; NOT production security).
    let params: Arc<CkksParameters> = CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli_sizes(&[45, 45])
        .set_scale(2f64.powi(40))
        .build_arc()?;
    let encoder = CkksEncoder::new(&params);

    let n_committee = 5;
    let threshold = 2;
    let trckks = TRCKKS::new(n_committee, threshold, params.clone())?;

    println!("== Sealed-bid Vickrey auction under threshold CKKS ==");
    println!(
        "committee: n={n_committee}, threshold={threshold} (any {} decrypt)",
        threshold + 1
    );

    // 1. Distributed key generation.
    let (pk, members) = setup_committee(&trckks, &params, n_committee, &mut rng)?;
    println!("DKG complete: joint public key aggregated from {n_committee} shares");

    // 2. Bidders encrypt their bids (bid value in slot 0).
    let bids = [312.50f64, 875.25, 640.00, 899.99, 405.75];
    println!("\nsealed bids submitted: {} bidders", bids.len());
    let mut cts = Vec::new();
    for bid in &bids {
        let pt = encoder.encode(&[*bid], 0)?;
        cts.push(pk.try_encrypt(&pt, &mut rng)?);
    }

    // 3. Tournament: find the max via masked pairwise comparisons.
    // compare(i, j) decrypts sign(r * (b_i - b_j)) with a fresh mask r > 0.
    let mut compare = |i: usize, j: usize| -> Result<bool, Box<dyn Error>> {
        let diff = cts[i].try_sub(&cts[j])?;
        let mask = rng.random_range(1.0f64..8.0);
        let mask_pt = encoder.encode(&[mask], 0)?;
        let mut masked = diff.try_mul_plaintext(&mask_pt)?;
        masked.rescale()?;
        let opened = threshold_decrypt(&trckks, &members, &masked, &encoder)?;
        Ok(opened > 0.0)
    };

    // Single pass to find the winner; track the loser of each winner-swap to
    // identify the runner-up candidates.
    let mut winner = 0usize;
    let mut candidates = Vec::new();
    for i in 1..bids.len() {
        if compare(i, winner)? {
            candidates.push(winner);
            winner = i;
        } else {
            candidates.push(i);
        }
    }
    // The second-highest is the max of the candidates that lost to the winner.
    let mut second = candidates[0];
    for &c in &candidates[1..] {
        if compare(c, second)? {
            second = c;
        }
    }
    println!("comparison tournament complete (masked differences only)");
    println!("winner: bidder #{winner}");

    // 4. Threshold-decrypt exactly one value: the clearing price.
    let clearing_price = threshold_decrypt(&trckks, &members, &cts[second], &encoder)?;
    println!("clearing price (2nd-highest bid): {clearing_price:.2}");

    // Verify against the plaintext bids.
    let mut sorted = bids.to_vec();
    sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
    assert_eq!(bids[winner], sorted[0], "tournament found the wrong winner");
    assert!(
        (clearing_price - sorted[1]).abs() < 0.05,
        "clearing price {clearing_price} != expected {}",
        sorted[1]
    );
    println!("\nverified: winner has the highest bid; price equals the second-highest bid");
    println!("losing bids were never decrypted");
    Ok(())
}
