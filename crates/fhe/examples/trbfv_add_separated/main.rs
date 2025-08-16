// Implementation of threshold addition using the `fhe` and `trbfv` crate split into modules.

mod application;
mod ciphernode;
#[path = "../util.rs"]
mod util;

use std::{env, error::Error, process::exit};

use console::style;
use fhe::{
    bfv::{self, PublicKey},
    mbfv::{AggregateIter, CommonRandomPoly},
};
use ciphernode::{
    calculate_d_share_poly, calculate_esi_sss, calculate_pk_share_and_sk_sss,
    calculate_plaintext, calculate_sk_poly_sum_and_es_poly_sum, swap_shares, Ciphernode,
};
use rand::thread_rng;
use rayon::prelude::*;
use util::timeit::timeit;
use application::{calculate_error_size, generate_ciphertexts, run_application};

fn print_notice_and_exit(error: Option<String>) {
    println!(
        "{} Addition with threshold BFV",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} add [-h] [--help] [--num_ciphernodes=<value>] [--threshold=<value>]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} {} and {} must be at least 1",
        style("constraints:").magenta().bold(),
        style("num_ciphernodes").blue(),
        style("threshold").blue(),
    );
    if let Some(error) = error {
        println!("{} {}", style("     error:").red().bold(), error);
    }
    exit(0);
}

fn main() -> Result<(), Box<dyn Error>> {
    const NUM_VOTES_PER_VOTER: usize = 3;
    // Parameters
    let degree = 8192;
    let plaintext_modulus: u64 = 16384;
    let moduli = vec![
        0x1FFFFFFEA0001, // 562949951979521
        0x1FFFFFFE88001, // 562949951881217
        0x1FFFFFFE48001, // 562949951619073
        0xfffffebc001,                 //
    ];

    // This executable is a command line tool which enables to specify
    // trBFV summations with ciphernodes and threshold sizes.
    let args: Vec<String> = env::args().skip(1).collect();

    // Print the help if requested.
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_voters: usize = 1000;
    let mut num_ciphernodes = 10;
    let mut threshold = 4;
    let mut num_votes_per_voter = 3;

    // Update the number of ciphernodes / threshold depending on the arguments provided.
    for arg in &args {
        if arg.starts_with("--num_ciphernodes") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_ciphernodes` argument".to_string()))
            } else {
                num_ciphernodes = a[0].parse::<usize>()?
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

    if num_ciphernodes == 0 {
        print_notice_and_exit(Some(
            "Ciphernode sizes must be nonzero".to_string(),
        ))
    }
    if threshold > (num_ciphernodes - 1) / 2 {
        print_notice_and_exit(Some(
            "Threshold must be strictly less than half the number of ciphernodes".to_string(),
        ))
    }

    // The parameters are within bound, let's go! Let's first display some
    // information about the threshold sum.
    println!("# Addition with trBFV");
    println!("\tnum_ciphernodes = {num_ciphernodes}");
    println!("\tthreshold = {threshold}");
    println!("\tciphertexts per voter = {num_votes_per_voter}");
    println!("\tnum_voters = {num_voters}");

    // Let's generate the BFV parameters structure. This will be shared between ciphernodes and
    // voters
    let params = timeit!(
        "Parameters generation",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()?
    );

    // Generate a common reference poly for public key generation.
    let crp = CommonRandomPoly::new(&params, &mut thread_rng())?;

    // Set up ciphernodes
    println!("💻 Available CPU cores: {}", rayon::current_num_threads());
    let error_size = calculate_error_size(params.clone(), num_ciphernodes, num_voters);
    let mut ciphernodes: Vec<Ciphernode> = timeit!("Generate pk_share and sk_sss", {
        calculate_pk_share_and_sk_sss(params.clone(), num_ciphernodes, threshold, crp.clone())
    });

    timeit!("Generate esi_sss", {
        calculate_esi_sss(
            &mut ciphernodes,
            params.clone(),
            num_ciphernodes,
            threshold,
            &error_size,
            num_votes_per_voter,
        )
    });

    timeit!("Simulating network (share swapping)", {
        swap_shares(&mut ciphernodes, params.clone())
    });

    timeit!("Sum collected shares (parallel)", {
        calculate_sk_poly_sum_and_es_poly_sum(
            &mut ciphernodes,
            params.clone(),
            num_ciphernodes,
            threshold,
        )
    });

    // Aggregation: same as previous mbfv aggregations
    let pk = timeit!("Public key aggregation", {
        let pk: PublicKey = ciphernodes.iter().map(|p| p.pk_share.clone()).aggregate()?;
        pk
    });

    // Each Voters encrypts three ciphertexts.
    let (ciphertexts, numbers) = timeit!("Encrypting Numbers (parallel)", {
        generate_ciphertexts::<NUM_VOTES_PER_VOTER>(&pk, params.clone(), num_voters, num_votes_per_voter)
    });

    // Running application
    let outputs_application = timeit!("Running application", {
        run_application(&ciphertexts, params.clone())
    });

    timeit!("Generate Decrypt Share (parallel)", {
        calculate_d_share_poly(
            &mut ciphernodes,
            params.clone(),
            num_ciphernodes,
            threshold,
            &outputs_application,
        )
    });

    let results = timeit!("Threshold decrypt (combine shares)", {
        calculate_plaintext(
            params.clone(),
            num_ciphernodes,
            threshold,
                &ciphernodes,
            &outputs_application,
        )
    });

    // Show summation result
    let mut expected_result = vec![0u64; 3];
    for vals in &numbers {
        for j in 0..num_votes_per_voter {
            expected_result[j] += vals[j];
        }
    }
    for (i, (res, exp)) in results.iter().zip(expected_result.iter()).enumerate() {
        println!("Tally {i} result = {res} / {exp}");
        assert_eq!(res, exp);
    }

    Ok(())
}
