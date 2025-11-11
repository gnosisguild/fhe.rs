// Implementation of threshold addition using the `fhe` and `trbfv` crate
// with BFV encryption of Shamir secret shares during transmission.

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
    // Parameters for threshold BFV computation
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

    // BFV parameters for share encryption (plaintext must be larger than trBFV moduli)
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
        "  BFV plaintext: {} (must be > trBFV moduli)",
        plaintext_modulus_bfv
    );
    println!("  BFV ciphertext moduli: {:?}", params_bfv.moduli());

    let args: Vec<String> = env::args().skip(1).collect();

    // Print the help if requested.
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_summed = 50;
    let mut num_parties = 3;
    let mut threshold = 1;

    // Update the number of users and/or number of parties / threshold depending on the
    // arguments provided.
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

    println!("# Addition with trBFV (with encrypted share transmission)");
    println!("\tnum_summed = {num_summed}");
    println!("\tnum_parties = {num_parties}");
    println!("\tthreshold = {threshold}");

    struct Party {
        pk_share: PublicKeyShare,
        sk_sss: Vec<Array2<u64>>,
        esi_sss: Vec<Array2<u64>>,
        sk_sss_collected: Vec<Array2<u64>>,
        es_sss_collected: Vec<Array2<u64>>,
        sk_poly_sum: Poly,
        es_poly_sum: Poly,
        d_share_poly: Poly,
        // BFV keys for share encryption
        sk_bfv: SecretKey,
        pk_bfv: PublicKey,
    }

    let crp = CommonRandomPoly::new(&params_trbfv, &mut thread_rng())?;
    let trbfv: TRBFV = TRBFV::new(num_parties, threshold, params_trbfv.clone()).unwrap();

    println!("💻 Available CPU cores: {}", rayon::current_num_threads());
    let mut parties: Vec<Party> = timeit!("Party setup (parallel)", {
        (0..num_parties)
            .into_par_iter()
            .map(|_| {
                let mut rng = OsRng;
                let mut thread_rng = thread_rng();

                let sk_share = SecretKey::random(&params_trbfv, &mut rng);
                let pk_share =
                    PublicKeyShare::new(&sk_share, crp.clone(), &mut thread_rng).unwrap();

                let mut share_manager =
                    ShareManager::new(num_parties, threshold, params_trbfv.clone());
                let sk_poly = share_manager
                    .coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())
                    .unwrap();

                let temp_trbfv = trbfv.clone();
                let sk_sss = temp_trbfv
                    .generate_secret_shares_from_poly(sk_poly, rng)
                    .unwrap();

                let sk_sss_collected: Vec<Array2<u64>> = Vec::with_capacity(num_parties);
                let es_sss_collected: Vec<Array2<u64>> = Vec::with_capacity(num_parties);
                let sk_poly_sum = Poly::zero(
                    params_trbfv.ctx_at_level(0).unwrap(),
                    Representation::PowerBasis,
                );
                let es_poly_sum = Poly::zero(
                    params_trbfv.ctx_at_level(0).unwrap(),
                    Representation::PowerBasis,
                );
                let d_share_poly = Poly::zero(
                    params_trbfv.ctx_at_level(0).unwrap(),
                    Representation::PowerBasis,
                );

                let esi_coeffs = temp_trbfv
                    .generate_smudging_error(num_summed, &mut rng)
                    .unwrap();
                let esi_poly = share_manager.bigints_to_poly(&esi_coeffs).unwrap();
                let esi_sss = share_manager
                    .generate_secret_shares_from_poly(esi_poly, rng)
                    .unwrap();

                let sk_bfv = SecretKey::random(&params_bfv, &mut rng);
                let pk_bfv = PublicKey::new(&sk_bfv, &mut thread_rng);

                Party {
                    pk_share,
                    sk_sss,
                    esi_sss,
                    sk_sss_collected,
                    es_sss_collected,
                    sk_poly_sum,
                    es_poly_sum,
                    d_share_poly,
                    sk_bfv,
                    pk_bfv,
                }
            })
            .collect()
    });

    let pk_bfv_list: Vec<PublicKey> = parties.iter().map(|p| p.pk_bfv.clone()).collect();

    println!("🔐 Encrypting and transmitting shares...");

    // encrypted_shares[sender][receiver] contains (sk_shares, esi_shares)
    let encrypted_shares: Vec<Vec<(Vec<Ciphertext>, Vec<Ciphertext>)>> =
        timeit!("Share encryption (parallel)", {
            parties
                .par_iter()
                .enumerate()
                .map(|(_sender_idx, party)| {
                    let mut sender_encrypted_shares = Vec::new();

                    for (receiver_idx, receiver_pk) in
                        pk_bfv_list.iter().enumerate().take(num_parties)
                    {
                        let mut rng = thread_rng();

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

    timeit!("Share decryption and collection (parallel)", {
        parties
            .par_iter_mut()
            .enumerate()
            .for_each(|(receiver_idx, party)| {
                for sender_encrypted in encrypted_shares.iter().take(num_parties) {
                    let (encrypted_sk_shares, encrypted_esi_shares) =
                        &sender_encrypted[receiver_idx];

                    let mut node_share_m = Array::zeros((0, degree));
                    for ct in encrypted_sk_shares.iter() {
                        let pt = party.sk_bfv.try_decrypt(ct).unwrap();
                        let decrypted_share: Vec<u64> =
                            Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();

                        node_share_m
                            .push_row(ArrayView::from(&decrypted_share))
                            .unwrap();
                    }
                    party.sk_sss_collected.push(node_share_m);

                    let mut es_node_share_m = Array::zeros((0, degree));
                    for ct in encrypted_esi_shares.iter() {
                        let pt = party.sk_bfv.try_decrypt(ct).unwrap();
                        let decrypted_share: Vec<u64> =
                            Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();

                        es_node_share_m
                            .push_row(ArrayView::from(&decrypted_share))
                            .unwrap();
                    }
                    party.es_sss_collected.push(es_node_share_m);
                }
            });
    });

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

    let pk = timeit!("Public key aggregation", {
        let pk: PublicKey = parties.iter().map(|p| p.pk_share.clone()).aggregate()?;
        pk
    });

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

    let tally = timeit!("Number tallying", {
        let mut sum = Ciphertext::zero(&params_trbfv);
        for ct in &numbers_encrypted {
            sum += ct;
        }
        Arc::new(sum)
    });

    let share_generation_start = Instant::now();

    parties.par_iter_mut().for_each(|party| {
        party.d_share_poly = trbfv
            .clone()
            .decryption_share(
                tally.clone(),
                party.sk_poly_sum.clone(),
                party.es_poly_sum.clone(),
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

    let d_share_polys: Vec<Poly> = parties
        .iter()
        .take(threshold + 1)
        .map(|party| party.d_share_poly.clone())
        .collect();

    let result = timeit!("Share combination and final decryption", {
        // Parties are 1-based for Shamir x-coordinates; we used the first (threshold+1) parties
        let reconstructing_parties: Vec<usize> = (1..=threshold + 1).collect();
        let open_results = trbfv
            .decrypt(d_share_polys, reconstructing_parties, tally.clone())
            .unwrap();
        let result_vec = Vec::<u64>::try_decode(&open_results, Encoding::poly())?;
        Ok::<u64, Box<dyn Error>>(result_vec[0])
    })?;

    let expected_result: u64 = numbers.iter().sum();
    println!("Computed result: {result}");
    println!("Expected result: {expected_result}");

    assert_eq!(result, expected_result, "Threshold computation failed!");
    println!("✅ Threshold BFV computation with encrypted shares successful!");

    Ok(())
}
