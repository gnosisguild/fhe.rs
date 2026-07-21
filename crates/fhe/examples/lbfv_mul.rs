// Distributed BFV multiplication following the l-BFV protocol from
// "Robust Multiparty Computation from Threshold Encryption Based on RLWE"
// https://eprint.iacr.org/2024/1285
//
// Protocol (single key type, as in the paper):
//   Each party holds sk_i. There is ONE public key: the l-BFV pk.
//   - Encryption uses pk.c[0]  = (b₀, a₀)        (paper §3.1, B[0]/a[0])
//   - Relinearization uses b_vec = [b₀,...,b_{l-1}]  (paper §5.2)
//
// Unlike trbfv_mul_bfv_share.rs this example has no separate mbfv PublicKeyShare,
// no Shamir share transport, and no second parameter set — minimising the number
// of distinct variables and operations (important for future Noir circuits).
//
// Decryption assembles the joint sk = Σ sk_i only to verify correctness.
// In production this step would be replaced by threshold decryption.
//
//   Parameters: 3 parties, 1 multiplication, 4×61-bit primes, degree 16384, k=1000.
//   Correctness: log₂(B_C after 1 mult) = 193.5 < log₂(Δ) = 234.0  ✓

#![allow(clippy::indexing_slicing, missing_docs)]

mod util;

use std::{error::Error, sync::Arc};

use fhe::{
    bfv::{self, CommonRandomPolyVec, Encoding, Plaintext, SecretKey},
    lbfv::{
        LBFVContributionBinding, LBFVParticipantSet, LBFVPublicKey, LBFVRelinKeyShare,
        LBFVRelinearizationKey,
    },
};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use util::timeit::timeit;

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = rand::rng();

    // ── Parameters ────────────────────────────────────────────────────────────
    // Four 61-bit NTT primes ≡ 1 mod 32768, sufficient noise budget for one
    // multiplication + relinearization (log₂ B_C = 193.5 < log₂ Δ = 234.0).
    let degree = 16384usize;
    let plaintext_modulus = 1_000u64;
    let moduli = [
        0x1fffffffffe10001u64,
        0x1fffffffffe00001,
        0x1fffffffffdd0001,
        0x1fffffffffd08001,
    ];

    let params: Arc<bfv::BfvParameters> = timeit!(
        "Parameters",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .set_variance(10)
            .build_arc()?
    );
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

    let lbfv_session_id: [u8; 32] = rand::random();
    let lbfv_participant_set =
        LBFVParticipantSet::new(lbfv_session_id, (1..=num_parties as u32).collect())?;

    println!("\n# Phase 1 — per-party key generation");

    // Each party samples its secret-key contribution sk_i.
    let sk_shares: Vec<SecretKey> = (0..num_parties)
        .map(|_| SecretKey::random(&params, &mut rng))
        .collect();

    // Each party computes its l-BFV pk contribution:
    //   pk_share_i = [(b_{0,i}, a₀), ..., (b_{l-1,i}, a_{l-1})]
    //   where b_{j,i} = −a_j · sk_i + e_{j,i}
    // All parties use the same crp_a so every a_j is identical across parties.
    let pk_shares: Vec<LBFVPublicKey> = sk_shares
        .iter()
        .enumerate()
        .map(|(i, sk_i)| {
            let binding =
                LBFVContributionBinding::new(lbfv_participant_set.clone(), (i + 1) as u32)?;
            LBFVPublicKey::contribute_with_crp_and_binding(sk_i, &crp_a, binding, &mut rng)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Each party computes its RLK contribution (d₀_i, d₂_i):
    //   d₀_i[j] = −sk_i · d₁_j + e₀_{i,j} + g_j · r_i   (ksk_r_to_s, uses crp_d1)
    //   d₂_i[j] =  r_i · a_j  + e₂_{i,j} + g_j · sk_i   (ksk_s_to_r, uses crp_a)
    // r_i is an ephemeral key sampled locally and discarded after this call.
    // crp_a must equal the crp used for pk_shares (CRS binding check).
    let rlk_shares: Vec<LBFVRelinKeyShare> = sk_shares
        .iter()
        .enumerate()
        .map(|(i, sk_i)| {
            let binding =
                LBFVContributionBinding::new(lbfv_participant_set.clone(), (i + 1) as u32)?;
            LBFVRelinKeyShare::contribution_with_crp_and_binding(
                sk_i, &crp_d1, &crp_a, binding, 0, 0, &mut rng,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    println!("  {} parties generated (pk_share, rlk_share)", num_parties);

    // ── Phase 2 — aggregation ─────────────────────────────────────────────────
    println!("\n# Phase 2 — aggregation");

    // Aggregate l-BFV pk:  b_j = Σ_i b_{j,i} = −a_j · sk + e_j
    // Result: a valid l-BFV pk for the joint sk = Σ sk_i.
    //   c[0] = (b₀, a₀) — used for encryption  (paper: B[0], a[0])
    //   c[j] for j>0    — b_j used for b_vec in the RLK
    let pk = timeit!("pk aggregation", LBFVPublicKey::aggregate(&pk_shares)?);

    // Aggregate RLK:
    //   d₀[j] = Σ_i d₀_i[j] = −sk · d₁_j + e₀_j + r · g_j
    //   d₂[j] = Σ_i d₂_i[j] =  r · a_j  + e₂_j + sk · g_j
    // pk supplies b_vec and enforces that a_seed matches (CRS binding).
    // Neither sk nor r is ever assembled in one place.
    let rlk: LBFVRelinearizationKey = timeit!(
        "rlk aggregation",
        LBFVRelinearizationKey::aggregate(&rlk_shares, &pk)?
    );
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
