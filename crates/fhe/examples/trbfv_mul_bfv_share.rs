// Threshold BFV multiplication with distributed l-BFV RLK and encrypted share transport.
//
// Smudging noise is computed via the secure `Lambda::secure(lambda)` API and
// `generate_smudging_error_with_participant_count(..., num_parties, ...)` so the
// accepted l-BFV participant count is explicit in the smudging bound. Paper-conforming
// robustness requires odd n = 2t + 1; even n is accepted for compatibility but lies
// outside the theorem.
//
// Two BFV parameter sets:
//
//   First set  (computation) — n=19, t=9, k=1000, d=16384, 5×54-bit moduli, λ=38.
//              Smudging feasibility for this exact preset is pinned by the
//              `preset_smudging_feasible` test below (issue #113).
//
//   Second set (share encryption) — k = largest trBFV modulus ≈ 2^54, d=16384,
//              2×62-bit moduli. Each Shamir share value lies in [0, q_i) ⊆ [0, k),
//              so it encodes directly as a BFV plaintext.
//              BFV decrypt rounds t·v/Q, so exact recovery needs the error to
//              stay below Δ/2 ≈ Q/(2k), not merely below Q/2. A fresh-noise
//              sanity check for this preset leaves ≈ 58 bits of Δ/2 headroom.
//
// Protocol:
//  1. Each party generates: an l-BFV pk share, an l-BFV RLK share, Shamir shares of
//     sk and smudging error, and a share-encryption BFV key pair (second set).
//  2. Share-encryption public keys are published. Each party BFV-encrypts its Shamir
//     shares for every receiver under the receiver's share-encryption key.
//  3. Each receiver decrypts and aggregates the collected shares to reconstruct
//     its Lagrange evaluation point of the combined secret key SK = Σ sk_j.
//  4. Four values are encrypted under the aggregated l-BFV pk, multiplied in
//     three chained multiplications with relinearization after each, then
//     threshold-decrypted by t+1 parties.

#![allow(clippy::indexing_slicing, missing_docs)]

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use console::style;
use fhe::{
    bfv::{self, Ciphertext, CommonRandomPolyVec, Encoding, Plaintext, PublicKey, SecretKey},
    lbfv::LBFVRelinearizationKey,
    mbfv::AggregateIter,
    trbfv::{Lambda, SecretPoly, SecretShareMatrix, ShareManager, TRBFV},
    trlbfv::{
        AggregatedPublicKey, ContributionBinding, ParticipantSet, PublicKeyShare, RelinKeyShare,
        aggregate_relinearization_key,
    },
};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use ndarray::ArrayView1;
use rand_distr::{Distribution, Uniform};
use rayon::prelude::*;
use std::time::Instant;
use util::timeit::timeit;

// Preset parameter set for this example. The smudging feasibility of the exact
// trBFV configuration below (degree, plaintext, moduli, n, lambda) is pinned by
// the `preset_smudging_feasible` test in this file — see issue #113.
// Caveat: this preset is verified consistent with the implemented noise/smudging
// bounds (correctness), but has not been independently checked against an RLWE
// estimator for computational security.
const DEGREE: usize = 16384;
const PLAINTEXT_MODULUS_TRBFV: u64 = 1_000;
const MODULI_TRBFV: [u64; 5] = [
    0x003fffffffef8001, // 18014398508400641 (largest)
    0x003fffffffeb8001, // 18014398508138497
    0x003fffffffe38001, // 18014398507614209
    0x003fffffffdd8001, // 18014398507220993
    0x003fffffffd78001, // 18014398506827777
];
const PLAINTEXT_MODULUS_SHARE_ENC: u64 = MODULI_TRBFV[0]; // largest trBFV modulus
const MODULI_SHARE_ENC: [u64; 2] = [0x3fffffffffd78001, 0x3fffffffffe80001];
const DEFAULT_NUM_PARTIES: usize = 19;
const DEFAULT_THRESHOLD: usize = 9;
const DEFAULT_LAMBDA: usize = 38;

fn print_notice_and_exit(error: Option<String>) {
    println!(
        "{} Threshold BFV multiplication with encrypted share transport",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} trbfv_mul_bfv_share [-h] [--num_parties=N] [--threshold=T] [--lambda=L]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} T = (N-1)/2, N ≥ 3, L ≥ {}. Paper-conforming robustness requires odd N (N = 2t + 1);",
        style("constraints:").magenta().bold(),
        fhe::trbfv::MIN_SECURE_LAMBDA,
    );
    println!(
        "{} even N is accepted for compatibility but lies outside the paper's theorem.",
        style("           ").magenta().bold(),
    );
    if let Some(error) = error {
        println!("{} {}", style("     error:").red().bold(), error);
    }
    exit(0);
}

fn main() -> Result<(), Box<dyn Error>> {
    // ── First BFV parameter set (threshold computation) ──────────────────────
    // n=19, t=9, k=1000, λ=38, σ²=10. Five 54-bit NTT primes, each ≡ 1 mod 32768. ✓
    let degree = DEGREE;
    let plaintext_modulus_trbfv = PLAINTEXT_MODULUS_TRBFV;
    let moduli_trbfv = MODULI_TRBFV;

    println!("Building trBFV parameters (first set)...");
    let params_trbfv: Arc<bfv::BfvParameters> = timeit!(
        "Parameters generation (trBFV)",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus_trbfv)
            .set_moduli(&moduli_trbfv)
            .set_variance(10)
            // Var(e_1) from the earlier parameter-tool design point, retained
            // unchanged; the `preset_smudging_feasible` test pins the feasibility
            // of this configuration.
            .set_error1_variance_str("4326914048779023023775413607683413333")?
            .build_arc()?
    );
    println!(
        "✓ trBFV parameters: [{}]",
        params_trbfv
            .moduli()
            .iter()
            .map(|q| format!("0x{q:016x}"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // ── Second BFV parameter set (share encryption) ───────────────────────────
    // Plaintext modulus = largest trBFV modulus ≈ 2^54, so every Shamir share
    // value (each in [0, q_i) ⊆ [0, k)) encodes directly as a BFV plaintext.
    // Two 62-bit NTT primes (≡ 1 mod 32768), coprime to the plaintext modulus.
    // Correctness: BFV decrypt rounds t·v/Q, which recovers the message exactly
    // iff the error stays below Δ/2 ≈ Q/(2k); a fresh-noise sanity check for
    // this preset leaves ≈ 58 bits of Δ/2 headroom.
    let plaintext_modulus_share_enc = PLAINTEXT_MODULUS_SHARE_ENC;
    let moduli_share_enc = MODULI_SHARE_ENC;
    println!("\nBuilding share-encryption parameters (second set)...");
    let params_share_enc: Arc<bfv::BfvParameters> = timeit!(
        "Parameters generation (share enc)",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus_share_enc)
            .set_moduli(&moduli_share_enc)
            .set_variance(10)
            .build_arc()?
    );
    println!(
        "✓ Share-enc parameters: [{}] (plaintext = 0x{:016x})",
        params_share_enc
            .moduli()
            .iter()
            .map(|q| format!("0x{q:016x}"))
            .collect::<Vec<_>>()
            .join(", "),
        plaintext_modulus_share_enc
    );

    // ── CLI argument parsing ──────────────────────────────────────────────────
    let args: Vec<String> = env::args().skip(1).collect();
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    // Defaults: n=19 (odd, paper-conforming 2t+1) tuned to this preset; the
    // `preset_smudging_feasible` test pins smudging feasibility for this exact
    // configuration (issue #113).
    let mut num_parties = DEFAULT_NUM_PARTIES;
    let mut threshold = DEFAULT_THRESHOLD;
    let mut lambda = DEFAULT_LAMBDA;

    for arg in &args {
        if arg.starts_with("--num_parties") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_parties` argument".to_string()))
            } else {
                num_parties = a[0].parse::<usize>()?
            }
        } else if arg.starts_with("--threshold") {
            let parts: Vec<&str> = arg.rsplit('=').collect();
            if parts.len() != 2 || parts[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--threshold` argument".to_string()))
            } else {
                threshold = parts[0].parse::<usize>()?
            }
        } else if arg.starts_with("--lambda") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--lambda` argument".to_string()))
            } else {
                lambda = a[0].parse::<usize>()?
            }
        } else {
            print_notice_and_exit(Some(format!("Unrecognized argument: {arg}")))
        }
    }

    if num_parties < 3 || lambda == 0 {
        print_notice_and_exit(Some(
            "Party count must be at least 3 and lambda must be nonzero".to_string(),
        ))
    }
    if threshold != (num_parties - 1) / 2 {
        print_notice_and_exit(Some(
            "Threshold must be exactly (num_parties - 1) / 2: maximal corruption tolerance with honest-majority reconstruction".to_string(),
        ))
    }

    // λ=38 is the design point of this preset (≥ fhe::trbfv::MIN_SECURE_LAMBDA=35).
    let security = Lambda::secure(lambda)?;
    let mut rng = rand::rng();

    println!("\n# Threshold BFV multiplication");
    println!("  num_parties       = {num_parties}  (params: n=19, k=1000, depth=3, λ=38)");
    println!("  threshold         = {threshold}");
    println!("  lambda            = {lambda}  (secure, >= fhe::trbfv::MIN_SECURE_LAMBDA)");
    println!(
        "  l-BFV participants = {num_parties}  (accepted RLK contributors for smudging bound)"
    );

    // ── Party setup ───────────────────────────────────────────────────────────
    // Two shared CRP vectors for the l-BFV RLK protocol. In deployment these would
    // be established via coin-tossing.
    let crp_a = CommonRandomPolyVec::new(&params_trbfv, &mut rng)?;
    let crp_d1 = CommonRandomPolyVec::new(&params_trbfv, &mut rng)?;

    // Canonical participant set — one common session ID covering all parties.
    let lbfv_session_id: [u8; 32] = rand::random();
    let lbfv_participant_set =
        ParticipantSet::new(lbfv_session_id, (1..=num_parties as u32).collect())?;

    struct Party {
        sk_sss: Vec<SecretShareMatrix>, // sk_sss[m]: shape (num_parties, degree)
        esi_sss: Vec<SecretShareMatrix>, // smudging error Shamir shares, same shape
        sk_sss_collected: Vec<SecretShareMatrix>, // collected from all senders; each (num_moduli, degree)
        es_sss_collected: Vec<SecretShareMatrix>,
        sk_poly_sum: SecretPoly<PowerBasis>,
        es_poly_sum: SecretPoly<PowerBasis>,
        d_share_poly: SecretPoly<PowerBasis>,
        pk_lbfv_share: PublicKeyShare, // l-BFV PK contribution (shared crs_a)
        rlk_share: RelinKeyShare,
        // Share-encryption key pair (second BFV parameter set).
        sk_share_enc: SecretKey,
        pk_share_enc: PublicKey,
    }

    let trbfv: TRBFV = TRBFV::new(num_parties, threshold, params_trbfv.clone())?;
    let num_moduli = params_trbfv.moduli().len();

    println!("\n💻 Available CPU cores: {}", rayon::current_num_threads());
    let mut parties: Vec<Party> = timeit!("Party setup (parallel)", {
        (0..num_parties)
            .into_par_iter()
            .map(|i| -> Result<Party, fhe::Error> {
                let mut rng = rand::rng();

                let sk_share = SecretKey::random(&params_trbfv, &mut rng);

                let mut share_manager =
                    ShareManager::new(num_parties, threshold, params_trbfv.clone())?;
                let sk_poly =
                    share_manager.coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())?;

                let sk_sss = trbfv.generate_secret_shares_from_poly(sk_poly, &mut rng)?;

                // Smudging noise shares (m=1 ciphertext, depth=3 multiplications,
                // accepted l-BFV participant count = num_parties). An infeasible
                // configuration is propagated out of main (issue #113) rather than
                // panicking inside the Rayon worker.
                let esi_coeffs = trbfv.generate_smudging_error_with_participant_count(
                    1,
                    3,
                    num_parties,
                    security,
                    &mut rng,
                )?;
                let esi_poly = share_manager.bigints_to_poly(&esi_coeffs)?;
                let esi_sss = share_manager.generate_secret_shares_from_poly(esi_poly, &mut rng)?;

                // l-BFV PK contribution (shared crp_a, same a_j across all parties).
                let lbfv_binding =
                    ContributionBinding::new(lbfv_participant_set.clone(), (i + 1) as u32)?;
                let pk_lbfv_share = PublicKeyShare::contribute_with_crp_and_binding(
                    &sk_share,
                    &crp_a,
                    lbfv_binding.clone(),
                    &mut rng,
                )?;

                // l-BFV RLK share for SK = Σ sk_j.
                let rlk_share = RelinKeyShare::contribution_with_crp_and_binding(
                    &sk_share,
                    &crp_d1,
                    &crp_a,
                    lbfv_binding,
                    0,
                    0,
                    &mut rng,
                )?;

                // Share-encryption key pair under the second parameter set.
                let sk_share_enc = SecretKey::random(&params_share_enc, &mut rng);
                let pk_share_enc = PublicKey::new(&sk_share_enc, &mut rng);

                let ctx0 = params_trbfv.context_at_level(0)?;
                Ok(Party {
                    sk_sss,
                    esi_sss,
                    sk_sss_collected: Vec::with_capacity(num_parties),
                    es_sss_collected: Vec::with_capacity(num_parties),
                    sk_poly_sum: SecretPoly::new(Poly::<PowerBasis>::zero(ctx0)),
                    es_poly_sum: SecretPoly::new(Poly::<PowerBasis>::zero(ctx0)),
                    d_share_poly: SecretPoly::new(Poly::<PowerBasis>::zero(ctx0)),
                    pk_lbfv_share,
                    rlk_share,
                    sk_share_enc,
                    pk_share_enc,
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    });

    // ── Distributed pk + RLK aggregation ─────────────────────────────────────
    // pk_lbfv is used for both RLK (b_vec) and encryption (c[0]).
    let aggregated_pk: AggregatedPublicKey;
    let rlk: LBFVRelinearizationKey = timeit!("Distributed pk + RLK aggregation", {
        let pk_lbfv_shares: Vec<PublicKeyShare> =
            parties.iter().map(|p| p.pk_lbfv_share.clone()).collect();
        aggregated_pk = pk_lbfv_shares
            .into_iter()
            .aggregate::<AggregatedPublicKey>()?;
        let rlk_shares: Vec<RelinKeyShare> = parties.iter().map(|p| p.rlk_share.clone()).collect();
        aggregate_relinearization_key(&rlk_shares, &aggregated_pk)?
    });
    let pk_lbfv = aggregated_pk.operational();
    println!("✓ pk_lbfv and RLK aggregated (l = {})", rlk.l()?);

    // ── Share encryption and transmission ─────────────────────────────────────
    // Each sender BFV-encrypts the share row it owes to each receiver under that
    // receiver's share-encryption public key (second parameter set). This is safe:
    //   • k = largest trBFV modulus ≥ q_i for all i → share values ∈ [0, q_i) ⊆ [0, k)
    //   • BFV decrypt rounds t·v/Q: exact recovery needs the error below
    //     Δ/2 ≈ Q/(2k), not merely below Q/2 — fresh noise leaves ≈ 58 bits
    //     of Δ/2 headroom for this preset
    //
    // encrypted_shares[sender][receiver] = (Vec<Ciphertext>, Vec<Ciphertext>)
    //   first  vec: one ciphertext per modulus for the sk share row
    //   second vec: one ciphertext per modulus for the smudging error share row
    let pk_share_enc_list: Vec<PublicKey> =
        parties.iter().map(|p| p.pk_share_enc.clone()).collect();

    let encrypted_shares: Vec<Vec<(Vec<Ciphertext>, Vec<Ciphertext>)>> =
        timeit!("Share encryption (parallel)", {
            parties
                .par_iter()
                .map(|party| {
                    (0..num_parties)
                        .map(|receiver_idx| {
                            let mut rng = rand::rng();
                            let rpk = &pk_share_enc_list[receiver_idx];

                            let enc_sk: Vec<Ciphertext> = (0..num_moduli)
                                .map(|m| {
                                    let row = party.sk_sss[m].row(receiver_idx).unwrap().to_vec();
                                    let pt = Plaintext::try_encode(
                                        &row,
                                        Encoding::poly(),
                                        &params_share_enc,
                                    )
                                    .unwrap();
                                    rpk.try_encrypt(&pt, &mut rng).unwrap()
                                })
                                .collect();

                            let enc_es: Vec<Ciphertext> = (0..num_moduli)
                                .map(|m| {
                                    let row = party.esi_sss[m].row(receiver_idx).unwrap().to_vec();
                                    let pt = Plaintext::try_encode(
                                        &row,
                                        Encoding::poly(),
                                        &params_share_enc,
                                    )
                                    .unwrap();
                                    rpk.try_encrypt(&pt, &mut rng).unwrap()
                                })
                                .collect();

                            (enc_sk, enc_es)
                        })
                        .collect()
                })
                .collect()
        });

    // ── Share decryption and collection ───────────────────────────────────────
    timeit!("Share decryption and collection (parallel)", {
        parties
            .par_iter_mut()
            .enumerate()
            .for_each(|(receiver_idx, party)| {
                for sender_shares in encrypted_shares.iter() {
                    let (enc_sk, enc_es) = &sender_shares[receiver_idx];

                    let node_sk_rows = enc_sk
                        .iter()
                        .map(|ct| {
                            let pt = party.sk_share_enc.try_decrypt(ct).unwrap();
                            Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap()
                        })
                        .collect::<Vec<_>>();
                    let node_sk_views = node_sk_rows
                        .iter()
                        .map(|row| ArrayView1::from(row.as_slice()))
                        .collect::<Vec<_>>();
                    party
                        .sk_sss_collected
                        .push(SecretShareMatrix::from_rows(&node_sk_views).unwrap());

                    let node_es_rows = enc_es
                        .iter()
                        .map(|ct| {
                            let pt = party.sk_share_enc.try_decrypt(ct).unwrap();
                            Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap()
                        })
                        .collect::<Vec<_>>();
                    let node_es_views = node_es_rows
                        .iter()
                        .map(|row| ArrayView1::from(row.as_slice()))
                        .collect::<Vec<_>>();
                    party
                        .es_sss_collected
                        .push(SecretShareMatrix::from_rows(&node_es_views).unwrap());
                }
            });
    });

    // ── Lagrange share aggregation ────────────────────────────────────────────
    timeit!("Sum collected shares (parallel)", {
        parties.par_iter_mut().for_each(|party| {
            let temp_trbfv = trbfv.clone();
            party.sk_poly_sum = temp_trbfv
                .aggregate_collected_shares(&party.sk_sss_collected)
                .unwrap();
            party.es_poly_sum = temp_trbfv
                .aggregate_collected_shares(&party.es_sss_collected)
                .unwrap();
        });
    });

    // ── Homomorphic multiplication (depth 3) ─────────────────────────────────
    // k=1000. Three chained multiplications: ((a×b)×c)×d.
    // Values in [1,5] so the max product is 5⁴=625 < 1000.
    let dist = Uniform::new_inclusive(1u64, 5).unwrap();
    let a = dist.sample(&mut rng);
    let b = dist.sample(&mut rng);
    let c = dist.sample(&mut rng);
    let d = dist.sample(&mut rng);
    println!("\n🔢  {} × {} × {} × {} = {}", a, b, c, d, a * b * c * d);

    let ct_a = timeit!("Encrypt a", {
        let pt = Plaintext::try_encode(&[a], Encoding::poly(), &params_trbfv)?;
        pk_lbfv.try_encrypt(&pt, &mut rng)?
    });
    let ct_b = timeit!("Encrypt b", {
        let pt = Plaintext::try_encode(&[b], Encoding::poly(), &params_trbfv)?;
        pk_lbfv.try_encrypt(&pt, &mut rng)?
    });
    let ct_c = timeit!("Encrypt c", {
        let pt = Plaintext::try_encode(&[c], Encoding::poly(), &params_trbfv)?;
        pk_lbfv.try_encrypt(&pt, &mut rng)?
    });
    let ct_d = timeit!("Encrypt d", {
        let pt = Plaintext::try_encode(&[d], Encoding::poly(), &params_trbfv)?;
        pk_lbfv.try_encrypt(&pt, &mut rng)?
    });

    let product = timeit!("Multiply and relinearize (depth 3)", {
        let mut ct_ab = &ct_a * &ct_b;
        rlk.relinearizes(&mut ct_ab)?;
        let mut ct_abc = &ct_ab * &ct_c;
        rlk.relinearizes(&mut ct_abc)?;
        let mut ct_abcd = &ct_abc * &ct_d;
        rlk.relinearizes(&mut ct_abcd)?;
        Arc::new(ct_abcd)
    });
    println!("  Product ciphertext level: {}", product.level);

    // ── Threshold decryption ──────────────────────────────────────────────────
    let t_start = Instant::now();
    parties.par_iter_mut().for_each(|party| {
        party.d_share_poly = trbfv
            .decryption_share(
                product.clone(),
                party.sk_poly_sum.clone().into_ntt(),
                party.es_poly_sum.clone(),
            )
            .unwrap();
    });
    println!(
        "Decryption share generation: {:.2?} ({:.2} ms/party)",
        t_start.elapsed(),
        t_start.elapsed().as_millis() as f64 / num_parties as f64
    );

    let d_shares: Vec<SecretPoly<PowerBasis>> = parties
        .iter()
        .take(threshold + 1)
        .map(|p| p.d_share_poly.clone())
        .collect();

    let result = timeit!("Combine shares and decrypt", {
        let party_indices: Vec<usize> = (1..=threshold + 1).collect();
        let pt = trbfv
            .decrypt(d_shares, party_indices, product.clone())
            .unwrap();
        let v = Vec::<u64>::try_decode(&pt, Encoding::poly())?;
        Ok::<u64, Box<dyn Error>>(v[0])
    })?;

    println!("\nComputed result: {result}");
    println!("Expected result: {}", a * b * c * d);
    assert_eq!(result, a * b * c * d, "Threshold multiplication failed!");
    println!(
        "✅ Threshold BFV multiplication (depth 3) with BFV-encrypted share transport correct!"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::trbfv::{SmudgingBoundCalculator, SmudgingBoundCalculatorConfig};

    /// The exact trBFV preset this example runs with (degree, plaintext modulus,
    /// moduli, n = `DEFAULT_NUM_PARTIES`, lambda = `DEFAULT_LAMBDA`, one
    /// ciphertext, three chained multiplications, all parties accepted into the
    /// l-BFV relinearization set) must yield a feasible smudging bound.
    ///
    /// Regression guard for issue #113: this preset was previously infeasible and
    /// the examples panicked inside Rayon worker closures instead of reporting the
    /// `SmudgingBoundInfeasible` error.
    #[test]
    fn preset_smudging_feasible() {
        let params = bfv::BfvParametersBuilder::new()
            .set_degree(DEGREE)
            .set_plaintext_modulus(PLAINTEXT_MODULUS_TRBFV)
            .set_moduli(&MODULI_TRBFV)
            .set_variance(10)
            .set_error1_variance_str("4326914048779023023775413607683413333")
            .unwrap()
            .build_arc()
            .unwrap();

        let config = SmudgingBoundCalculatorConfig::new_multiplicative(
            params,
            DEFAULT_NUM_PARTIES,
            1, // m: a single ciphertext, as in the example
            3, // mult_depth: three chained multiplications, as in the example
            Lambda::secure(DEFAULT_LAMBDA).unwrap(),
        )
        .unwrap();
        let bound = SmudgingBoundCalculator::new(config)
            .with_accepted_participant_count(DEFAULT_NUM_PARTIES)
            .calculate_sm_bound();
        assert!(
            bound.is_ok(),
            "the preset trBFV configuration must be smudging-feasible, got: {}",
            bound.unwrap_err()
        );
    }
}
