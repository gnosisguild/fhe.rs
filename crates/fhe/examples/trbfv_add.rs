// Implementation of threshold addition using the `fhe` and `trbfv` crate.

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use console::style;
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, PublicKeyShare},
    trbfv::{ShareManager, TRBFV},
};

use fhe_math::rq::{Poly, Representation};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::{Array, Array2, ArrayView};
use rand::{distributions::Uniform, prelude::Distribution, rngs::OsRng, thread_rng};
use rayon::prelude::*;
use std::time::Instant;
use util::timeit::{timeit, timeit_n};

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
    // BFV parameters
    let degree = 8192;
    let plaintext_modulus: u64 = 1000;
    let moduli = vec![
        0x00800000022a0001,
        0x00800000021a0001,
        0x0080000002120001,
        0x0080000001f60001,
    ];

    let params = timeit!(
        "Parameters generation",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .set_variance(10)
            .set_error1_variance_str(
                "52309181128222339698631578526730685514457152477762943514050560000"
            )?
            .build_arc()?
    );

    // This executable is a command line tool which enables to specify
    // trBFV summations with party and threshold sizes.
    let args: Vec<String> = env::args().skip(1).collect();

    // Print the help if requested.
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_summed = 100;
    let mut num_parties = 10;
    let mut threshold = 4;

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

    // The parameters are within bound, let's go! Let's first display some
    // information about the threshold sum.
    println!("# Addition with trBFV");
    println!("\tnum_summed = {num_summed}");
    println!("\tnum_parties = {num_parties}");
    println!("\tthreshold = {threshold}");

    // Party setup: each party generates a secret key and shares of a collective
    // public key.
    struct Party {
        pk_share: PublicKeyShare,
        sk_sss: Vec<Array2<u64>>,
        esi_sss: Vec<Array2<u64>>,
        sk_sss_collected: Vec<Array2<u64>>,
        es_sss_collected: Vec<Array2<u64>>,
        sk_poly_sum: Poly,
        es_poly_sum: Poly,
        d_share_poly: Poly,
    }

    // Generate a common reference poly for public key generation.
    let crp = CommonRandomPoly::new(&params, &mut thread_rng())?;

    // Setup trBFV module
    let trbfv = TRBFV::new(num_parties, threshold, params.clone()).unwrap();

    // Set up shares for each party in parallel
    println!("💻 Available CPU cores: {}", rayon::current_num_threads());
    let mut parties: Vec<Party> = timeit!("Party setup (parallel)", {
        (0..num_parties)
            .into_par_iter()
            .map(|_| {
                // Each thread gets its own RNG to avoid contention
                let mut rng = OsRng;
                let mut thread_rng = thread_rng();

                let sk_share = SecretKey::random(&params, &mut rng);
                let pk_share =
                    PublicKeyShare::new(&sk_share, crp.clone(), &mut thread_rng).unwrap();

                let mut share_manager = ShareManager::new(num_parties, threshold, params.clone());
                let sk_poly = share_manager
                    .coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())
                    .unwrap();

                // Clone trbfv for thread safety (it's cheap since it's just config)
                let temp_trbfv = trbfv.clone();
                let sk_sss = temp_trbfv
                    .generate_secret_shares_from_poly(sk_poly, rng)
                    .unwrap();

                // vec of 3 moduli and array2 for num_parties rows of coeffs and degree columns
                let sk_sss_collected: Vec<Array2<u64>> = Vec::with_capacity(num_parties);
                let es_sss_collected: Vec<Array2<u64>> = Vec::with_capacity(num_parties);
                let sk_poly_sum =
                    Poly::zero(params.ctx_at_level(0).unwrap(), Representation::PowerBasis);
                let es_poly_sum =
                    Poly::zero(params.ctx_at_level(0).unwrap(), Representation::PowerBasis);
                let d_share_poly =
                    Poly::zero(params.ctx_at_level(0).unwrap(), Representation::PowerBasis);

                let esi_coeffs = temp_trbfv
                    .generate_smudging_error(num_summed, &mut rng)
                    .unwrap();
                let esi_poly = share_manager.bigints_to_poly(&esi_coeffs).unwrap();
                let esi_sss = share_manager
                    .generate_secret_shares_from_poly(esi_poly, rng)
                    .unwrap();

                Party {
                    pk_share,
                    sk_sss,
                    esi_sss,
                    sk_sss_collected,
                    es_sss_collected,
                    sk_poly_sum,
                    es_poly_sum,
                    d_share_poly,
                }
            })
            .collect()
    });

    // Swap shares mocking network comms, party 1 sends share 2 to party 2 etc.
    let mut i = 0;
    timeit_n!(
        "Simulating network (share swapping per party)",
        num_parties as u32,
        {
            for j in 0..num_parties {
                let mut node_share_m = Array::zeros((0, degree));
                let mut es_node_share_m = Array::zeros((0, degree));
                for m in 0..params.moduli().len() {
                    node_share_m
                        .push_row(ArrayView::from(&parties[j].sk_sss[m].row(i).clone()))
                        .unwrap();
                    es_node_share_m
                        .push_row(ArrayView::from(&parties[j].esi_sss[m].row(i).clone()))
                        .unwrap();
                }
                parties[i].sk_sss_collected.push(node_share_m);
                parties[i].es_sss_collected.push(es_node_share_m);
            }
            i += 1;
        }
    );

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

    // Aggregation: same as previous mbfv aggregations
    let pk = timeit!("Public key aggregation", {
        let pk: PublicKey = parties.iter().map(|p| p.pk_share.clone()).aggregate()?;
        pk
    });

    // Encrypted addition setup.
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
                let pt = Plaintext::try_encode(&[number], Encoding::poly(), &params).unwrap();
                pk.try_encrypt(&pt, &mut rng).unwrap()
            })
            .collect()
    });

    // calculation
    let tally = timeit!("Number tallying", {
        let mut sum = Ciphertext::zero(&params);
        for ct in &numbers_encrypted {
            sum += ct;
        }
        Arc::new(sum)
    });

    // Measure decryption share generation (average per party)
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

    // Gather decryption shares from threshold+1 parties
    let d_share_polys: Vec<Poly> = parties
        .iter()
        .take(threshold + 1)
        .map(|party| party.d_share_poly.clone())
        .collect();

    // decrypt result
    let result = timeit!("Threshold decrypt (combine shares)", {
        // Parties are 1-based for Shamir x-coordinates; we used the first (threshold+1) parties
        let reconstructing_parties: Vec<usize> = (1..=threshold + 1).collect();
        let open_results = trbfv
            .decrypt(d_share_polys, reconstructing_parties, tally.clone())
            .unwrap();
        let result_vec = Vec::<u64>::try_decode(&open_results, Encoding::poly())?;
        Ok::<u64, Box<dyn Error>>(result_vec[0])
    })?;

    // Verify correctness
    let expected_result: u64 = numbers.iter().sum();
    println!("Computed result: {result}");
    println!("Expected result: {expected_result}");

    assert_eq!(result, expected_result, "Threshold computation failed!");
    println!("Threshold BFV computation successful!");

    Ok(())
}
