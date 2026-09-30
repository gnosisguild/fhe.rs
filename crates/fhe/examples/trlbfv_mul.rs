// Distributed BFV multiplication following the l-BFV protocol from
// "Robust Multiparty Computation from Threshold Encryption Based on RLWE"
// https://eprint.iacr.org/2024/1285
//
// Three parties use the secure16384 test profile and one multiplication level.
// No share transport or threshold decryption: the joint sk = Σ sk_i is assembled
// locally only to check correctness, not as a production protocol.

#![allow(clippy::indexing_slicing, missing_docs)]

#[path = "../support/mod.rs"]
mod support;

use std::{error::Error, sync::Arc};

use fhe::{
    bfv::{self, CommonRandomPolyVec, Encoding, Plaintext, SecretKey},
    trlbfv::{PublicKeyShare, RelinKeyShare, aggregate_key_pair},
};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use support::examples::util::timeit::timeit;

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = rand::rng();
    let preset = support::presets::secure16384()?;

    // ── Parameters ────────────────────────────────────────────────────────────
    let params: Arc<bfv::BfvParameters> = timeit!("Parameters", preset.parameters.clone());
    let degree = params.degree();
    let plaintext_modulus = params.plaintext();
    println!(
        "l = {} (gadget dimension = num moduli)",
        params.moduli().len()
    );

    let num_parties = 3usize;

    // ── Shared CRP vectors (established by coin-tossing in a real protocol) ──
    // crp_a:  shared CRP vector for a = (a₀,...,a_{l-1}) — used in both pk and RLK d₂.
    // crp_d1: shared CRP vector for d₁ — used in RLK d₀.
    // Both must be identical across all parties.
    let crp_a = CommonRandomPolyVec::new(&params, &mut rng)?;
    let crp_d1 = CommonRandomPolyVec::new(&params, &mut rng)?;

    println!("\n# Phase 1 — per-party key generation");

    // Each party samples its secret-key contribution sk_i.
    let sk_shares: Vec<SecretKey> = (0..num_parties)
        .map(|_| SecretKey::random(&params, &mut rng))
        .collect();

    // Each party computes ONE paired contribution from its sk_i:
    //   pk_share_i = [(b_{0,i}, a₀), ..., (b_{l-1,i}, a_{l-1})]
    //     where b_{j,i} = −a_j · sk_i + e_{j,i}
    //   d₀_i[j] = −sk_i · d₁_j + e₀_{i,j} + g_j · r_i   (ksk_r_to_s, uses crp_d1)
    //   d₂_i[j] =  r_i · a_j  + e₂_{i,j} + g_j · sk_i   (ksk_s_to_r, uses crp_a)
    // r_i is an ephemeral key sampled locally and discarded after this call.
    // Form both halves from the same sk_i; do not zip separately filtered lists.
    let key_pairs: Vec<(PublicKeyShare, RelinKeyShare)> = sk_shares
        .iter()
        .map(|sk_i| -> fhe::Result<(PublicKeyShare, RelinKeyShare)> {
            Ok((
                PublicKeyShare::contribute_with_crp(sk_i, &crp_a, &mut rng)?,
                RelinKeyShare::contribute_with_crp(sk_i, &crp_d1, &crp_a, 0, 0, &mut rng)?,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;

    println!("  {} parties generated (pk_share, rlk_share)", num_parties);

    // ── Phase 2 — aggregation ─────────────────────────────────────────────────
    println!("\n# Phase 2 — aggregation");

    // Pairing prevents one-sided omissions, not malicious inputs. Authentication,
    // duplicate policy, and same-secret proof verification are not provided.
    let (aggregated_pk, rlk) = timeit!(
        "paired pk + rlk aggregation",
        aggregate_key_pair(key_pairs)?
    );
    let pk = &aggregated_pk;
    println!("  rlk l = {}", rlk.l()?);

    // ── Phase 3 — encryption via pk.c[0] ─────────────────────────────────────
    // Encrypts under (b₀, a₀) exactly as a standard BFV encryption:
    //   ct = (u·b₀ + e₁ + Δ·m,  u·a₀ + e₂)
    // This is the paper's encryption step using B[0]/a[0].
    println!("\n# Phase 3 — encryption");

    let a = 31u64;
    let b = 32u64;
    println!(
        "  {} × {} = {} (mod {plaintext_modulus})",
        a,
        b,
        (a * b) % plaintext_modulus
    );

    let ct_a = timeit!("Encrypt a", {
        let pt = Plaintext::try_encode(&[a], Encoding::poly(), &params)?;
        pk.try_encrypt(&pt, &mut rng)?
    });
    let ct_b = timeit!("Encrypt b", {
        let pt = Plaintext::try_encode(&[b], Encoding::poly(), &params)?;
        pk.try_encrypt(&pt, &mut rng)?
    });

    // ── Phase 4 — multiply and relinearize ───────────────────────────────────
    println!("\n# Phase 4 — multiply + relinearize");

    let ct_ab = timeit!("Multiply and relinearize", {
        let mut ct = &ct_a * &ct_b; // 3-component ciphertext (d₀, d₁, d₂)
        rlk.relinearizes(&mut ct)?; // → 2-component ciphertext
        ct
    });
    println!("  ciphertext level after relin: {}", ct_ab.level);

    // ── Phase 5 — decryption ──────────────────────────────────────────────────
    // In production: threshold decryption using Shamir shares of sk.
    // Here we assemble the joint sk = Σ sk_i only to verify correctness.
    println!("\n# Phase 5 — decrypt (joint sk, production would use threshold)");

    let mut sum_coeffs = vec![0i64; degree];
    for sk_i in &sk_shares {
        for (acc, c) in sum_coeffs.iter_mut().zip(sk_i.coeffs.iter()) {
            *acc = acc.wrapping_add(*c);
        }
    }
    let sk_joint = SecretKey::new(sum_coeffs, &params);

    let pt_result = timeit!("Decrypt", sk_joint.try_decrypt(&ct_ab)?);
    let result = Vec::<u64>::try_decode(&pt_result, Encoding::poly())?;

    println!("\nResult:   {}", result[0]);
    println!("Expected: {}", (a * b) % plaintext_modulus);
    assert_eq!(
        result[0],
        (a * b) % plaintext_modulus,
        "l-BFV distributed multiplication failed"
    );
    println!("✓ l-BFV distributed multiplication correct.");

    Ok(())
}
