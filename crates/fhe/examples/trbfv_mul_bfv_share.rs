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
//   First set  (computation) — n=5, z=3, k=1000, d=16384, 4×61-bit moduli, λ=40.
//              Correctness: log₂(B_C after mult) = 187.5 < log₂(Δ) = 234.0  ✓
//
//   Second set (share encryption) — k = q[1] of first set ≈ 2^61, d=16384,
//              2×62-bit moduli. Each Shamir share value lies in [0, q_i) ⊆ [0, k),
//              so it encodes directly as a BFV plaintext.
//              BFV decrypt is correct because k ≈ 2^61 < q₀/2 ≈ 2^61.9999  ✓
//
// Protocol:
//  1. Each party generates: trBFV key share, Shamir shares of sk and smudging error,
//     an l-BFV RLK share, and a share-encryption BFV key pair (second set).
//  2. Share-encryption public keys are published. Each party BFV-encrypts its Shamir
//     shares for every receiver under the receiver's share-encryption key.
//  3. Each receiver decrypts and aggregates the collected shares to reconstruct
//     its Lagrange evaluation point of the combined secret key SK = Σ sk_j.
//  4. Two values are encrypted under the combined mbfv PublicKey, multiplied and
//     relinearized using the aggregated RLK, then threshold-decrypted by t+1 parties.
#![allow(missing_docs)]

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use console::style;
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    lbfv::{
        LBFVContributionBinding, LBFVParticipantSet, LBFVPublicKey, LBFVRelinKeyShare,
        LBFVRelinearizationKey,
    },
    mbfv::{AggregateIter, CommonRandomPoly, PublicKeyShare},
    trbfv::{Lambda, ShareManager, TRBFV},
};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use ndarray::{Array, Array2, ArrayView};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use rand_distr::{Distribution, Uniform};
use rayon::prelude::*;
use std::time::Instant;
use util::timeit::timeit;

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
        "{} T ≤ (N-1)/2, N ≥ 1, L ≥ {}. Paper-conforming robustness requires odd N (N = 2t + 1);",
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
    // n=5, z=3, k=1000, λ=40, σ²=10. Four 61-bit NTT primes, each ≡ 1 mod 32768. ✓
    let degree = 16384usize;
    let plaintext_modulus_trbfv: u64 = 1_000;
    let moduli_trbfv = [
        0x1fffffffffe10001u64, // q[1] = 2305843009211662337
        0x1fffffffffe00001,    // q[2] = 2305843009210613761
        0x1fffffffffdd0001,    // q[3] = 2305843009196982273
        0x1fffffffffd08001,    // q[4] = 2305843009177763841
    ];

    println!("Building trBFV parameters (first set)...");
    let params_trbfv: Arc<bfv::BfvParameters> = timeit!(
        "Parameters generation (trBFV)",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus_trbfv)
            .set_moduli(&moduli_trbfv)
            .set_variance(10)
            // Var(e_1) from the parameter tool: n=5, z=3, λ=40.
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
    // Plaintext modulus = q[1] of the first set ≈ 2^61. All Shamir share values
    // lie in [0, q_i) ⊆ [0, q[1]) = [0, k), so they fit as BFV plaintexts.
    // Two 62-bit NTT primes (≡ 1 mod 32768). Correctness: k ≈ 2^61 < q₀/2 ≈ 2^61.0000003 ✓
    let plaintext_modulus_share_enc: u64 = moduli_trbfv[0]; // = q[1]
    let moduli_share_enc = [0x3fffffffffd78001u64, 0x3fffffffffe80001];
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

    // Defaults: n=5 keeps the example fast; the params are correct for n up to 20.
    let mut num_parties = 5usize;
    let mut threshold = 2usize;
    let mut lambda = 40usize;

    fn parse_opt(arg: &str, prefix: &str) -> Option<usize> {
        arg.strip_prefix(prefix)
            .and_then(|v| v.strip_prefix('='))
            .and_then(|v| v.parse::<usize>().ok())
    }

    for arg in &args {
        if let Some(n) = parse_opt(arg, "--num_parties") {
            num_parties = n;
        } else if let Some(t) = parse_opt(arg, "--threshold") {
            threshold = t;
        } else if let Some(l) = parse_opt(arg, "--lambda") {
            lambda = l;
        } else {
            print_notice_and_exit(Some(format!("Unrecognized argument: {arg}")))
        }
    }

    if num_parties == 0 || lambda == 0 {
        print_notice_and_exit(Some("Party count and lambda must be nonzero".to_string()))
    }
    if threshold > (num_parties - 1) / 2 {
        print_notice_and_exit(Some(
            "Threshold must be at most (num_parties - 1) / 2".to_string(),
        ))
    }

    // λ=40 is the design point of this parameter set (≥ fhe::trbfv::MIN_SECURE_LAMBDA=35).
    let security = Lambda::secure(lambda)?;
    let mut rng = rand::rng();

    println!("\n# Threshold BFV multiplication");
    println!("  num_parties       = {num_parties}  (params: n=5, k=1000, z=3, λ=40)");
    println!("  threshold         = {threshold}");
    println!("  lambda            = {lambda}  (secure, >= fhe::trbfv::MIN_SECURE_LAMBDA)");
    println!(
        "  l-BFV participants = {num_parties}  (accepted RLK contributors for smudging bound)"
    );

    // ── Party setup ───────────────────────────────────────────────────────────
    // Two public seeds for the l-BFV RLK protocol. In deployment these would be
    // established via coin-tossing.
    let mut pk_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
    let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
    rng.fill(&mut pk_seed);
    rng.fill(&mut d1_seed);

    // Canonical participant set — one common session ID covering all parties.
    let lbfv_session_id: [u8; 32] = rng.random();
    let lbfv_participant_set =
        LBFVParticipantSet::new(lbfv_session_id, (1..=num_parties as u32).collect())?;

    struct Party {
        pk_share: PublicKeyShare,
        sk_sss: Vec<Array2<u64>>,  // sk_sss[m]: shape (num_parties, degree)
        esi_sss: Vec<Array2<u64>>, // smudging error Shamir shares, same shape
        sk_sss_collected: Vec<Array2<u64>>, // collected from all senders; each (num_moduli, degree)
        es_sss_collected: Vec<Array2<u64>>,
        sk_poly_sum: Poly<PowerBasis>,
        es_poly_sum: Poly<PowerBasis>,
        d_share_poly: Poly<PowerBasis>,
        pk_lbfv_share: LBFVPublicKey, // l-BFV PK contribution (CRS = pk_seed)
        rlk_share: LBFVRelinKeyShare,
        // Share-encryption key pair (second BFV parameter set).
        sk_share_enc: SecretKey,
        pk_share_enc: PublicKey,
    }

    let crp = CommonRandomPoly::new(&params_trbfv, &mut rng)?;
    let trbfv: TRBFV = TRBFV::new(num_parties, threshold, params_trbfv.clone()).unwrap();
    let num_moduli = params_trbfv.moduli().len();

    println!("\n💻 Available CPU cores: {}", rayon::current_num_threads());
    let participant_set_ref = &lbfv_participant_set;
    let mut parties: Vec<Party> = timeit!("Party setup (parallel)", {
        (0..num_parties)
            .into_par_iter()
            .map(|party_idx| {
                let mut rng = rand::rng();
                let participant_id = (party_idx + 1) as u32;

                // Unique contribution binding for this party.
                let binding =
                    LBFVContributionBinding::new(participant_set_ref.clone(), participant_id)
                        .unwrap();

                // trBFV keys and Shamir shares.
                let sk_share = SecretKey::random(&params_trbfv, &mut rng);
                let pk_share = PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();

                let mut share_manager =
                    ShareManager::new(num_parties, threshold, params_trbfv.clone()).unwrap();
                let sk_poly = share_manager
                    .coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())
                    .unwrap();

                let sk_sss = trbfv
                    .generate_secret_shares_from_poly(sk_poly, &mut rng)
                    .unwrap();

                // Smudging noise shares (m=1 ciphertext, depth=3 multiplications,
                // accepted l-BFV participant count = num_parties).
                let esi_coeffs = trbfv
                    .generate_smudging_error_with_participant_count(
                        1,
                        3,
                        num_parties,
                        security,
                        &mut rng,
                    )
                    .unwrap();
                let esi_poly = share_manager.bigints_to_poly(&esi_coeffs).unwrap();
                let esi_sss = share_manager
                    .generate_secret_shares_from_poly(esi_poly, &mut rng)
                    .unwrap();

                // l-BFV PK contribution (CRS seed = pk_seed, shared by all parties).
                let pk_lbfv_share = LBFVPublicKey::new_with_seed_and_binding(
                    &sk_share,
                    pk_seed,
                    binding.clone(),
                    &mut rng,
                )
                .unwrap();

                // l-BFV RLK share for SK = Σ sk_j.
                let rlk_share = LBFVRelinKeyShare::contribution_with_binding(
                    &sk_share, d1_seed, pk_seed, // a_seed must match pk_lbfv_share's CRS seed
                    binding, 0, 0, &mut rng,
                )
                .unwrap();

                // Share-encryption key pair under the second parameter set.
                let sk_share_enc = SecretKey::random(&params_share_enc, &mut rng);
                let pk_share_enc = PublicKey::new(&sk_share_enc, &mut rng);

                let ctx0 = params_trbfv.context_at_level(0).unwrap();
                Party {
                    pk_share,
                    sk_sss,
                    esi_sss,
                    sk_sss_collected: Vec::with_capacity(num_parties),
                    es_sss_collected: Vec::with_capacity(num_parties),
                    sk_poly_sum: Poly::<PowerBasis>::zero(ctx0),
                    es_poly_sum: Poly::<PowerBasis>::zero(ctx0),
                    d_share_poly: Poly::<PowerBasis>::zero(ctx0),
                    pk_lbfv_share,
                    rlk_share,
                    sk_share_enc,
                    pk_share_enc,
                }
            })
            .collect()
    });

    // ── Distributed RLK aggregation ───────────────────────────────────────────
    let rlk: LBFVRelinearizationKey = timeit!("Distributed RLK aggregation", {
        let pk_lbfv_shares: Vec<LBFVPublicKey> =
            parties.iter().map(|p| p.pk_lbfv_share.clone()).collect();
        let pk_lbfv = LBFVPublicKey::aggregate(&pk_lbfv_shares)?;
        let rlk_shares: Vec<LBFVRelinKeyShare> =
            parties.iter().map(|p| p.rlk_share.clone()).collect();
        LBFVRelinearizationKey::aggregate(&rlk_shares, &pk_lbfv)?
    });
    println!("✓ Relinearization key aggregated (l = {})", rlk.l()?);

    // ── Share encryption and transmission ─────────────────────────────────────
    // Each sender BFV-encrypts the share row it owes to each receiver under that
    // receiver's share-encryption public key (second parameter set). This is safe:
    //   • k = q[1] ≥ q_i for all i → share values ∈ [0, q_i) ⊆ [0, k)
    //   • k ≈ 2^57 < q₀/2 ≈ 2^59  → BFV decrypt is algebraically exact
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
                            let rpk = pk_share_enc_list.get(receiver_idx).unwrap();

                            let enc_sk: Vec<Ciphertext> = (0..num_moduli)
                                .map(|m| {
                                    let row =
                                        party.sk_sss.get(m).unwrap().row(receiver_idx).to_vec();
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
                                    let row =
                                        party.esi_sss.get(m).unwrap().row(receiver_idx).to_vec();
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
                    let (enc_sk, enc_es) = sender_shares.get(receiver_idx).unwrap();

                    let mut node_sk = Array::zeros((0, degree));
                    for ct in enc_sk {
                        let pt = party.sk_share_enc.try_decrypt(ct).unwrap();
                        let row: Vec<u64> = Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();
                        node_sk.push_row(ArrayView::from(&row)).unwrap();
                    }
                    party.sk_sss_collected.push(node_sk);

                    let mut node_es = Array::zeros((0, degree));
                    for ct in enc_es {
                        let pt = party.sk_share_enc.try_decrypt(ct).unwrap();
                        let row: Vec<u64> = Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();
                        node_es.push_row(ArrayView::from(&row)).unwrap();
                    }
                    party.es_sss_collected.push(node_es);
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

    // ── mbfv public key aggregation ───────────────────────────────────────────
    let pk = timeit!("Public key aggregation", {
        let pk: PublicKey = parties.iter().map(|p| p.pk_share.clone()).aggregate()?;
        pk
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
        pk.try_encrypt(&pt, &mut rng)?
    });
    let ct_b = timeit!("Encrypt b", {
        let pt = Plaintext::try_encode(&[b], Encoding::poly(), &params_trbfv)?;
        pk.try_encrypt(&pt, &mut rng)?
    });
    let ct_c = timeit!("Encrypt c", {
        let pt = Plaintext::try_encode(&[c], Encoding::poly(), &params_trbfv)?;
        pk.try_encrypt(&pt, &mut rng)?
    });
    let ct_d = timeit!("Encrypt d", {
        let pt = Plaintext::try_encode(&[d], Encoding::poly(), &params_trbfv)?;
        pk.try_encrypt(&pt, &mut rng)?
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

    let d_shares: Vec<Poly<PowerBasis>> = parties
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
        Ok::<u64, Box<dyn Error>>(v.first().copied().unwrap_or_default())
    })?;

    println!("\nComputed result: {result}");
    println!("Expected result: {}", a * b * c * d);
    assert_eq!(result, a * b * c * d, "Threshold multiplication failed!");
    println!(
        "✅ Threshold BFV multiplication (depth 3) with BFV-encrypted share transport correct!"
    );

    Ok(())
}
