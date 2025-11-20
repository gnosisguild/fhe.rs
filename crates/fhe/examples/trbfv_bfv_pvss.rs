// Implementation of threshold addition using the `fhe` and `trbfv` crate
// with BFV encryption of Shamir secret shares during transmission.
// OPTIMIZED: Collect (sum) encrypted shares first, then decrypt once per receiver.

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use console::style;
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, PublicKeyShare},
    trbfv::{ShareManager, TRBFV},
};

use fhe_math::rq::{Poly, Representation};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use ndarray::{Array, Array2, ArrayView};
use rand::{distributions::Uniform, prelude::Distribution, rngs::OsRng, thread_rng};
use rayon::prelude::*;
use std::time::Instant;
use util::timeit::timeit;

fn print_notice_and_exit(error: Option<String>) {
    println!(
        "{} Addition with threshold BFV",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} add [-h] [--help] [--num_summed=<value>] [--num_parties=<value>] [--threshold=<value>]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} {} {} and {} must be at least 1",
        style("constraints:").magenta().bold(),
        style("num_summed").blue(),
        style("num_parties").blue(),
        style("threshold").blue(),
    );
    if let Some(error) = error {
        println!("{} {}", style("     error:").red().bold(), error);
    }
    exit(0);
}

fn main() -> Result<(), Box<dyn Error>> {
    // ============================================================================
    // PARAMETER SETUP
    // ============================================================================

    // Parameters for threshold BFV computation (the actual secure computation)
    let degree = 8192;
    let moduli_trbfv = vec![
        0x00800000022a0001,
        0x00800000021a0001,
        0x0080000002120001,
        0x0080000001f60001,
    ];
    let plaintext_modulus_trbfv: u64 = 1000;

    println!("Building trBFV parameters...");
    let params_trbfv: Arc<bfv::BfvParameters> = timeit!(
        "Parameters generation (threshold BFV)",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus_trbfv)
            .set_moduli(&moduli_trbfv)
            .set_variance(10)
            .set_error1_variance_str(
                "52309181128222339698631578526730685514457152477762943514050560000"
            )?
            .build_arc()?
    );
    println!("✓ trBFV parameters built successfully");

    // BFV parameters for share encryption during transmission
    // CRITICAL: plaintext_modulus_bfv must be > num_parties × max(trBFV_moduli)
    // to prevent wraparound when summing encrypted shares
    println!("\nBuilding BFV parameters for share encryption...");
    let moduli_bfv = vec![0x0400000001460001, 0x0400000000ea0001];
    let plaintext_modulus_bfv: u64 = 144115188075855872;

    let params_bfv: Arc<bfv::BfvParameters> = timeit!(
        "Parameters generation (share encryption BFV)",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus_bfv)
            .set_moduli(&moduli_bfv)
            .set_variance(10)
            .build_arc()?
    );
    println!("✓ BFV parameters built successfully");

    println!("\nParameter sizes:");
    println!("  Degree: {}", degree);
    println!("  trBFV moduli: {:?}", params_trbfv.moduli());
    println!(
        "  BFV plaintext: {} (must be > num_parties × trBFV moduli)",
        plaintext_modulus_bfv
    );
    println!("  BFV ciphertext moduli: {:?}", params_bfv.moduli());

    // ============================================================================
    // COMMAND LINE ARGUMENT PARSING
    // ============================================================================

    let args: Vec<String> = env::args().skip(1).collect();

    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_summed = 50;
    let mut num_parties = 3;
    let mut threshold = 1;

    for arg in &args {
        if arg.starts_with("--num_summed") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_summed` argument".to_string()))
            } else {
                num_summed = a[0].parse::<usize>()?
            }
        } else if arg.starts_with("--num_parties") {
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
        } else {
            print_notice_and_exit(Some(format!("Unrecognized argument: {arg}")))
        }
    }

    if num_summed == 0 || num_parties == 0 {
        print_notice_and_exit(Some(
            "Users, threshold, and party sizes must be nonzero".to_string(),
        ))
    }
    if threshold > (num_parties - 1) / 2 {
        print_notice_and_exit(Some(
            "Threshold must be strictly less than half the number of parties".to_string(),
        ))
    }

    println!("# Addition with trBFV (with encrypted share transmission - OPTIMIZED)");
    println!("\tnum_summed = {num_summed}");
    println!("\tnum_parties = {num_parties}");
    println!("\tthreshold = {threshold}");

    // ============================================================================
    // PARTY STRUCT DEFINITION
    // ============================================================================

    struct Party {
        // Threshold BFV public key share for the aggregate public key
        pk_share: PublicKeyShare,

        // ========================================================================
        // VERIFICATION ONLY: Raw Shamir shares generated by this party
        // In the actual protocol, parties never transmit or use these directly.
        // They are kept only to verify the protocol's correctness.
        // ========================================================================
        sk_sss: Vec<Array2<u64>>,  // Secret key shares (verification only)
        esi_sss: Vec<Array2<u64>>, // Smudging error shares (verification only)

        // ========================================================================
        // ACTUAL PROTOCOL STATE: What parties work with
        // ========================================================================

        // Encrypted shares received from other parties via the network
        // Structure: [sender_idx][modulus_level] -> Ciphertext
        encrypted_sk_sss_collected: Vec<Vec<Ciphertext>>,
        encrypted_esi_sss_collected: Vec<Vec<Ciphertext>>,

        // Homomorphic sum of all encrypted shares
        // Structure: [modulus_level] -> Ciphertext
        // KEY OPTIMIZATION: Sum in encrypted space before decryption
        encrypted_sk_sss_sum: Vec<Ciphertext>,
        encrypted_esi_sss_sum: Vec<Ciphertext>,

        // Decrypted aggregate keys (ACTUALLY USED for threshold decryption)
        // aggregate_sk = decrypt(encrypted_sk_sss_sum)
        // This is what parties use to generate their decryption shares
        aggregate_sk: Poly,
        aggregate_es: Poly,

        // This party's decryption share for threshold reconstruction
        d_share_poly: Poly,

        // ========================================================================
        // VERIFICATION ONLY: For comparing protocol result with expected
        // ========================================================================
        // Computed from raw shares for verification
        // Should equal aggregate_sk but computed differently
        sk_poly_sum: Poly,
        es_poly_sum: Poly,

        // BFV keys for encrypting/decrypting share transmissions
        sk_bfv: SecretKey,
        pk_bfv: PublicKey,
    }

    // ============================================================================
    // PHASE 1: PARTY INITIALIZATION & KEY GENERATION
    // ============================================================================

    let crp = CommonRandomPoly::new(&params_trbfv, &mut thread_rng())?;
    let trbfv: TRBFV = TRBFV::new(num_parties, threshold, params_trbfv.clone()).unwrap();

    println!("💻 Available CPU cores: {}", rayon::current_num_threads());
    let mut parties: Vec<Party> = timeit!("Party setup (parallel)", {
        (0..num_parties)
            .into_par_iter()
            .map(|_| {
                let mut rng = OsRng;
                let mut thread_rng = thread_rng();

                // Generate threshold BFV key share for this party
                let sk_share = SecretKey::random(&params_trbfv, &mut rng);
                let pk_share =
                    PublicKeyShare::new(&sk_share, crp.clone(), &mut thread_rng).unwrap();

                // Convert secret key to polynomial for Shamir sharing
                let mut share_manager =
                    ShareManager::new(num_parties, threshold, params_trbfv.clone());
                let sk_poly = share_manager
                    .coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())
                    .unwrap();

                // Generate Shamir secret shares of this party's secret key
                // NOTE: These raw shares are for VERIFICATION only
                let temp_trbfv = trbfv.clone();
                let sk_sss = temp_trbfv
                    .generate_secret_shares_from_poly(sk_poly, rng)
                    .unwrap();

                // Generate smudging error for noise flooding
                let esi_coeffs = temp_trbfv
                    .generate_smudging_error(num_summed, &mut rng)
                    .unwrap();
                let esi_poly = share_manager.bigints_to_poly(&esi_coeffs).unwrap();
                let esi_sss = share_manager
                    .generate_secret_shares_from_poly(esi_poly, rng)
                    .unwrap();

                // Generate BFV keys for encrypting share transmissions
                let sk_bfv = SecretKey::random(&params_bfv, &mut rng);
                let pk_bfv = PublicKey::new(&sk_bfv, &mut thread_rng);

                // Initialize empty collections and polynomials
                let encrypted_sk_sss_collected: Vec<Vec<Ciphertext>> =
                    Vec::with_capacity(num_parties);
                let encrypted_esi_sss_collected: Vec<Vec<Ciphertext>> =
                    Vec::with_capacity(num_parties);

                let ctx = params_trbfv.ctx_at_level(0).unwrap();
                let aggregate_sk = Poly::zero(ctx, Representation::PowerBasis);
                let aggregate_es = Poly::zero(ctx, Representation::PowerBasis);
                let sk_poly_sum = Poly::zero(ctx, Representation::PowerBasis);
                let es_poly_sum = Poly::zero(ctx, Representation::PowerBasis);
                let d_share_poly = Poly::zero(ctx, Representation::PowerBasis);

                Party {
                    pk_share,
                    sk_sss,
                    esi_sss,
                    encrypted_sk_sss_collected,
                    encrypted_esi_sss_collected,
                    encrypted_sk_sss_sum: Vec::new(),
                    encrypted_esi_sss_sum: Vec::new(),
                    aggregate_sk,
                    aggregate_es,
                    d_share_poly,
                    sk_poly_sum,
                    es_poly_sum,
                    sk_bfv,
                    pk_bfv,
                }
            })
            .collect()
    });

    // Collect all BFV public keys for encryption
    let pk_bfv_list: Vec<PublicKey> = parties.iter().map(|p| p.pk_bfv.clone()).collect();

    // ============================================================================
    // PHASE 2: SHARE ENCRYPTION & TRANSMISSION
    // ============================================================================

    println!("🔐 Encrypting and transmitting shares...");

    // Each party encrypts their Shamir shares for each receiver using BFV
    // This simulates the network transmission phase where parties broadcast
    // encrypted shares without revealing the plaintext values
    let encrypted_shares: Vec<Vec<(Vec<Ciphertext>, Vec<Ciphertext>)>> =
        timeit!("Share encryption (parallel)", {
            parties
                .par_iter()
                .enumerate()
                .map(|(_sender_idx, party)| {
                    let mut sender_encrypted_shares = Vec::new();

                    // For each receiver, encrypt this party's Shamir shares
                    for (receiver_idx, receiver_pk) in
                        pk_bfv_list.iter().enumerate().take(num_parties)
                    {
                        let mut rng = thread_rng();

                        // Encrypt secret key shares (one per trBFV modulus level)
                        let mut encrypted_sk_shares = Vec::new();
                        for m in 0..params_trbfv.moduli().len() {
                            let share_row = party.sk_sss[m].row(receiver_idx);
                            let share_vec: Vec<u64> = share_row.to_vec();
                            let pt =
                                Plaintext::try_encode(&share_vec, Encoding::poly(), &params_bfv)
                                    .unwrap();
                            let ct = receiver_pk.try_encrypt(&pt, &mut rng).unwrap();
                            encrypted_sk_shares.push(ct);
                        }

                        // Encrypt smudging error shares (one per trBFV modulus level)
                        let mut encrypted_esi_shares = Vec::new();
                        for m in 0..params_trbfv.moduli().len() {
                            let share_row = party.esi_sss[m].row(receiver_idx);
                            let share_vec: Vec<u64> = share_row.to_vec();
                            let pt =
                                Plaintext::try_encode(&share_vec, Encoding::poly(), &params_bfv)
                                    .unwrap();
                            let ct = receiver_pk.try_encrypt(&pt, &mut rng).unwrap();
                            encrypted_esi_shares.push(ct);
                        }

                        sender_encrypted_shares.push((encrypted_sk_shares, encrypted_esi_shares));
                    }

                    sender_encrypted_shares
                })
                .collect()
        });

    // ============================================================================
    // PHASE 3: SHARE COLLECTION & HOMOMORPHIC SUMMATION (OPTIMIZED)
    // ============================================================================

    println!("🔢 Collecting encrypted shares and performing homomorphic summation...");
    println!("    KEY OPTIMIZATION: Sum encrypted shares first, decrypt once");
    println!("    Parties work ONLY with encrypted shares - never see raw plaintext shares");

    timeit!("Share collection and homomorphic summation (parallel)", {
        parties
            .par_iter_mut()
            .enumerate()
            .for_each(|(receiver_idx, party)| {
                let num_moduli = params_trbfv.moduli().len();

                // ================================================================
                // STEP 1: Collect encrypted shares from all senders
                // This is what parties actually receive over the network
                // ================================================================
                for sender_encrypted in encrypted_shares.iter().take(num_parties) {
                    let (encrypted_sk_shares, encrypted_esi_shares) =
                        &sender_encrypted[receiver_idx];
                    party
                        .encrypted_sk_sss_collected
                        .push(encrypted_sk_shares.clone());
                    party
                        .encrypted_esi_sss_collected
                        .push(encrypted_esi_shares.clone());
                }

                // ================================================================
                // STEP 2: OPTIMIZATION - Homomorphic summation in encrypted space
                // Instead of: decrypt N shares → sum in plaintext (N decryptions)
                // We do: sum N encrypted shares → decrypt once (1 decryption)
                // ================================================================

                // Sum encrypted sk shares - one summed ciphertext per modulus level
                let mut summed_sk_cts: Vec<Ciphertext> = Vec::new();
                for m in 0..num_moduli {
                    let mut sum_ct = Ciphertext::zero(&params_bfv);
                    for encrypted_sk_shares in &party.encrypted_sk_sss_collected {
                        sum_ct += &encrypted_sk_shares[m];
                    }
                    summed_sk_cts.push(sum_ct);
                }
                party.encrypted_sk_sss_sum = summed_sk_cts;

                // Sum encrypted esi shares - one summed ciphertext per modulus level
                let mut summed_esi_cts: Vec<Ciphertext> = Vec::new();
                for m in 0..num_moduli {
                    let mut sum_ct = Ciphertext::zero(&params_bfv);
                    for encrypted_esi_shares in &party.encrypted_esi_sss_collected {
                        sum_ct += &encrypted_esi_shares[m];
                    }
                    summed_esi_cts.push(sum_ct);
                }
                party.encrypted_esi_sss_sum = summed_esi_cts;
            });
    });

    println!("✅ All parties have computed encrypted sums");

    // ============================================================================
    // PHASE 4: DECRYPT AGGREGATE KEYS
    // ============================================================================

    println!("🔓 Decrypting aggregate keys from encrypted sums...");
    println!("    Each party decrypts their encrypted sum to obtain aggregate key");

    timeit!("Decrypt aggregate keys (parallel)", {
        parties.par_iter_mut().for_each(|party| {
            let ctx = params_trbfv.ctx_at_level(0).unwrap();
            let trb_moduli = params_trbfv.moduli();

            // ================================================================
            // Decrypt encrypted_sk_sss_sum to get aggregate secret key
            // Result: (share_1 + share_2 + ... + share_N) mod BFV_plaintext
            // ================================================================
            let mut sk_sum_array = Array::zeros((0, degree));
            for (m, ct) in party.encrypted_sk_sss_sum.iter().enumerate() {
                let pt = party.sk_bfv.try_decrypt(ct).unwrap();
                let mut decrypted: Vec<u64> =
                    Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();

                // Reduce from BFV modulus space to trBFV modulus space
                // This is a field conversion needed for threshold BFV operations
                let modulus = trb_moduli[m];
                for val in decrypted.iter_mut() {
                    *val %= modulus;
                }

                sk_sum_array.push_row(ArrayView::from(&decrypted)).unwrap();
            }

            // Store as aggregate_sk - THIS IS USED FOR THRESHOLD DECRYPTION
            party.aggregate_sk = Poly::zero(ctx, Representation::PowerBasis);
            party.aggregate_sk.set_coefficients(sk_sum_array);

            // ================================================================
            // Decrypt encrypted_esi_sss_sum to get aggregate error
            // ================================================================
            let mut es_sum_array = Array::zeros((0, degree));
            for (m, ct) in party.encrypted_esi_sss_sum.iter().enumerate() {
                let pt = party.sk_bfv.try_decrypt(ct).unwrap();
                let mut decrypted: Vec<u64> =
                    Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();

                let modulus = trb_moduli[m];
                for val in decrypted.iter_mut() {
                    *val %= modulus;
                }

                es_sum_array.push_row(ArrayView::from(&decrypted)).unwrap();
            }

            party.aggregate_es = Poly::zero(ctx, Representation::PowerBasis);
            party.aggregate_es.set_coefficients(es_sum_array);
        });
    });

    println!("✅ All parties have their aggregate keys (decrypted from encrypted sums)");

    // ============================================================================
    // PHASE 5: VERIFICATION - Compute expected aggregate from raw shares
    // ============================================================================

    println!("🔍 Computing verification values from raw shares...");

    timeit!("Compute verification aggregates (parallel)", {
        // First, collect all raw shares into a structure we can safely access
        let all_sk_sss: Vec<Vec<Array2<u64>>> = parties.iter().map(|p| p.sk_sss.clone()).collect();
        let all_esi_sss: Vec<Vec<Array2<u64>>> =
            parties.iter().map(|p| p.esi_sss.clone()).collect();

        parties
            .par_iter_mut()
            .enumerate()
            .for_each(|(party_idx, party)| {
                let ctx = params_trbfv.ctx_at_level(0).unwrap();

                // Sum raw shares directly (what original protocol would do)
                let mut direct_sk_sum = Poly::zero(ctx, Representation::PowerBasis);
                let mut direct_es_sum = Poly::zero(ctx, Representation::PowerBasis);

                for sender_idx in 0..num_parties {
                    // Secret key shares
                    let mut sk_share_matrix = Array::zeros((0, degree));
                    for m in 0..params_trbfv.moduli().len() {
                        let share_row = all_sk_sss[sender_idx][m].row(party_idx);
                        sk_share_matrix.push_row(share_row).unwrap();
                    }
                    let mut sk_share_poly = Poly::zero(ctx, Representation::PowerBasis);
                    sk_share_poly.set_coefficients(sk_share_matrix);
                    direct_sk_sum = &direct_sk_sum + &sk_share_poly;

                    // Error shares
                    let mut es_share_matrix = Array::zeros((0, degree));
                    for m in 0..params_trbfv.moduli().len() {
                        let share_row = all_esi_sss[sender_idx][m].row(party_idx);
                        es_share_matrix.push_row(share_row).unwrap();
                    }
                    let mut es_share_poly = Poly::zero(ctx, Representation::PowerBasis);
                    es_share_poly.set_coefficients(es_share_matrix);
                    direct_es_sum = &direct_es_sum + &es_share_poly;
                }

                party.sk_poly_sum = direct_sk_sum;
                party.es_poly_sum = direct_es_sum;
            });
    });

    // Verify that aggregate_sk matches sk_poly_sum
    println!("🔍 Verifying: decrypt(Σ Enc(share_i)) = Σ share_i");
    let all_match = parties.iter().all(|party| {
        party.aggregate_sk.coefficients().as_slice() == party.sk_poly_sum.coefficients().as_slice()
            && party.aggregate_es.coefficients().as_slice()
                == party.es_poly_sum.coefficients().as_slice()
    });
    assert!(
        all_match,
        "Verification failed: aggregate keys don't match raw share sums!"
    );
    println!("✅ Verification passed: Optimization is mathematically correct!");

    // ============================================================================
    // PHASE 6: AGGREGATE PUBLIC KEY
    // ============================================================================

    let pk = timeit!("Public key aggregation", {
        let pk: PublicKey = parties.iter().map(|p| p.pk_share.clone()).aggregate()?;
        pk
    });

    // ============================================================================
    // PHASE 7: ENCRYPT DATA FOR COMPUTATION
    // ============================================================================

    let dist = Uniform::new_inclusive(0, 1);
    let numbers: Vec<u64> = dist
        .sample_iter(&mut thread_rng())
        .take(num_summed)
        .collect();

    let numbers_encrypted: Vec<Ciphertext> = timeit!("Encrypting Numbers (parallel)", {
        numbers
            .par_iter()
            .map(|&number| {
                let mut rng = thread_rng();
                let pt = Plaintext::try_encode(&[number], Encoding::poly(), &params_trbfv).unwrap();
                pk.try_encrypt(&pt, &mut rng).unwrap()
            })
            .collect()
    });

    // ============================================================================
    // PHASE 8: HOMOMORPHIC COMPUTATION (SUM)
    // ============================================================================

    let tally = timeit!("Number tallying", {
        let mut sum = Ciphertext::zero(&params_trbfv);
        for ct in &numbers_encrypted {
            sum += ct;
        }
        Arc::new(sum)
    });

    // ============================================================================
    // PHASE 9: THRESHOLD DECRYPTION - SHARE GENERATION
    // ============================================================================

    println!("\n🔓 Generating threshold decryption shares...");
    println!("    Each party uses aggregate_sk (decrypted from encrypted_sk_sss_sum)");

    let share_generation_start = Instant::now();

    parties.par_iter_mut().for_each(|party| {
        // CRITICAL: Use aggregate_sk (decrypted from encrypted sum)
        // NOT sk_poly_sum (which is only for verification)
        party.d_share_poly = trbfv
            .clone()
            .decryption_share(
                tally.clone(),
                party.aggregate_sk.clone(), // Uses decrypted encrypted_sk_sss_sum
                party.aggregate_es.clone(),
            )
            .unwrap();
    });

    let total_share_generation_time = share_generation_start.elapsed();
    let avg_time_per_party = total_share_generation_time.as_millis() as f64 / num_parties as f64;

    println!("Decryption share generation:");
    println!(
        "  Total time (parallel): {:.2?}",
        total_share_generation_time
    );
    println!("  Average time per party: {:.2} ms", avg_time_per_party);

    // ============================================================================
    // PHASE 10: THRESHOLD DECRYPTION - SHAMIR RECONSTRUCTION
    // ============================================================================

    let d_share_polys: Vec<Poly> = parties
        .iter()
        .take(threshold + 1)
        .map(|party| party.d_share_poly.clone())
        .collect();

    let result = timeit!("Share combination and final decryption", {
        let reconstructing_parties: Vec<usize> = (1..=threshold + 1).collect();
        let open_results = trbfv
            .decrypt(d_share_polys, reconstructing_parties, tally.clone())
            .unwrap();
        let result_vec = Vec::<u64>::try_decode(&open_results, Encoding::poly())?;
        Ok::<u64, Box<dyn Error>>(result_vec[0])
    })?;

    // ============================================================================
    // FINAL RESULTS
    // ============================================================================

    let expected_result: u64 = numbers.iter().sum();
    println!("\n📊 RESULTS:");
    println!("  Computed result: {result}");
    println!("  Expected result: {expected_result}");

    assert_eq!(result, expected_result, "Threshold computation failed!");

    println!("\n✅ Threshold BFV computation with encrypted shares successful!");
    println!("   Protocol used aggregate_sk = decrypt(encrypted_sk_sss_sum)");
    println!("   Raw shares (sk_sss) used only for verification");
    println!(
        "\n📈 Performance improvement: {} decryptions per receiver instead of {}",
        params_trbfv.moduli().len(),
        num_parties * params_trbfv.moduli().len()
    );
    println!("   Reduction factor: {}× fewer decryptions", num_parties);

    Ok(())
}
