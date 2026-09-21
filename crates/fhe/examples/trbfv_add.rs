//! Threshold BFV addition over encrypted integers.
//!
//! Parties generate distributed keys, encrypt a batch of values, homomorphically
//! sum them, and decrypt the tally via threshold decryption with Shamir secret
//! sharing. Run with `--help` for CLI options (`--num_summed`, `--num_parties`,
//! `--threshold`, `--lambda`).

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

#[path = "../support/mod.rs"]
mod support;
mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use console::style;
use fhe::{
    bfv::{Ciphertext, CommonRandomPoly, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, PublicKeyShare},
    trbfv::{ShareManager, SmudgingConfig, SmudgingNoiseGenerator},
};

use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use rand_distr::{Distribution, Uniform};
use rayon::prelude::*;
use std::time::Instant;
use support::examples::trbfv::{TrbfvShares, parse_cli};
use util::timeit::{timeit, timeit_n};

fn print_notice_and_exit(error: Option<String>) -> ! {
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
    let preset = support::presets::secure8192()?;
    let params = timeit!("Parameters generation", preset.parameters.clone());
    let degree = params.degree();

    // This executable is a command line tool which enables to specify
    // trBFV summations with party and threshold sizes.
    let args: Vec<String> = env::args().skip(1).collect();

    // Print the help if requested.
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let cli = match parse_cli(
        &args,
        preset.num_parties,
        preset.threshold,
        preset.lambda,
        Some(50),
    ) {
        Ok(cli) => cli,
        Err(error) => print_notice_and_exit(Some(error)),
    };
    let num_summed = cli
        .num_summed
        .expect("addition examples provide num_summed");
    let num_parties = cli.num_parties;
    let threshold = cli.threshold;
    let lambda = cli.lambda;

    if threshold != (num_parties - 1) / 2 {
        print_notice_and_exit(Some(
            "Threshold must be exactly (num_parties - 1) / 2: maximal corruption tolerance with honest-majority reconstruction".to_string(),
        ))
    }

    // The parameters are within bound, let's go! Let's first display some
    // information about the threshold sum.
    // Lambda is caller-chosen policy: larger values give a stronger
    // statistical-hiding guarantee, bounded above by smudging's MAX_LAMBDA.

    println!("# Addition with trBFV");
    println!("\tnum_summed = {num_summed}");
    println!("\tnum_parties = {num_parties}");
    println!("\tthreshold = {threshold}");
    println!("\tlambda = {lambda}");

    // Party setup: each party generates a secret key and shares of a collective
    // public key.
    struct Party {
        pk_share: PublicKeyShare,
        shares: TrbfvShares,
        decryption_share: Poly<PowerBasis>,
    }

    // Generate a common reference poly for public key generation.
    let mut rng = rand::rng();
    let crp = CommonRandomPoly::new(&params, &mut rng)?;

    // Setup trBFV module
    let share_manager = ShareManager::new(num_parties, threshold, params.clone()).unwrap();

    // Set up shares for each party in parallel
    println!("💻 Available CPU cores: {}", rayon::current_num_threads());
    let mut parties: Vec<Party> = timeit!("Party setup (parallel)", {
        (0..num_parties)
            .into_par_iter()
            .map(|_| {
                // Each thread gets its own RNG to avoid contention
                let mut rng = rand::rng();

                let secret_key = SecretKey::random(&params, &mut rng);
                let pk_share = PublicKeyShare::new(&secret_key, crp.clone(), &mut rng).unwrap();

                let share_manager =
                    ShareManager::new(num_parties, threshold, params.clone()).unwrap();
                let secret_key_poly = share_manager
                    .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
                    .unwrap();

                let secret_key_shares_transport = share_manager
                    .generate_secret_key_shares(secret_key_poly, &mut rng)
                    .unwrap()
                    .into_transport();

                // vec of 3 moduli and array2 for num_parties rows of coeffs and degree columns
                let ctx = params.context_at_level(0).unwrap();
                let decryption_share = Poly::<PowerBasis>::zero(ctx);

                // Smudging noise shares: compute the bound with the smudging
                // machinery, sample the noise, and deal it immediately.
                let config =
                    SmudgingConfig::new(params.clone(), num_parties, num_summed, lambda).unwrap();
                let generator = SmudgingNoiseGenerator::new(config).unwrap();
                let smudging_noise = generator.generate(&mut rng).unwrap();
                let smudging_shares_transport = share_manager
                    .generate_smudging_shares(smudging_noise, &mut rng)
                    .unwrap()
                    .into_transport();

                Party {
                    pk_share,
                    shares: TrbfvShares::new(
                        secret_key_shares_transport,
                        smudging_shares_transport,
                    ),
                    decryption_share,
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
                let (secret_key_rows, smudging_rows) = TrbfvShares::recipient_rows(
                    &parties[j].shares.secret_key_shares_transport,
                    &parties[j].shares.smudging_shares_transport,
                    i,
                    degree,
                    params.moduli().len(),
                );
                parties[i]
                    .shares
                    .collect_transport(secret_key_rows, smudging_rows);
            }
            i += 1;
        }
    );

    timeit!("Sum collected shares (parallel)", {
        parties.par_iter_mut().for_each(|party| {
            party.shares.aggregate(&share_manager).unwrap();
        });
    });

    // Aggregation: same as previous mbfv aggregations
    let pk = timeit!("Public key aggregation", {
        let pk: PublicKey = parties.iter().map(|p| p.pk_share.clone()).aggregate()?;
        pk
    });

    // Encrypted addition setup.
    let dist = Uniform::new_inclusive(0, 1).unwrap();
    let numbers: Vec<u64> = dist.sample_iter(&mut rng).take(num_summed).collect();

    let numbers_encrypted: Vec<Ciphertext> = timeit!("Encrypting Numbers (parallel)", {
        numbers
            .par_iter()
            .map(|&number| {
                let mut rng = rand::rng();
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
        let smudging = party.shares.take_smudging().unwrap();
        let secret_key = party.shares.secret_key().unwrap();
        party.decryption_share = share_manager
            .decryption_share(tally.clone(), secret_key, smudging)
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
    let decryption_shares: Vec<Poly<PowerBasis>> = parties
        .iter()
        .take(threshold + 1)
        .map(|party| party.decryption_share.clone())
        .collect();

    // decrypt result
    let result = timeit!("Threshold decrypt (combine shares)", {
        // Parties are 1-based for Shamir x-coordinates; we used the first (threshold+1) parties
        let reconstructing_parties: Vec<usize> = (1..=threshold + 1).collect();
        let open_results = share_manager
            .decrypt_from_shares(decryption_shares, reconstructing_parties, tally.clone())
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
