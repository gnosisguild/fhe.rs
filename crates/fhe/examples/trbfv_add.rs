// Implementation of flat threshold addition using the `fhe` and `trbfv` crate.
//
// This example demonstrates a simple flat threshold BFV setup where all parties
// participate at the same level. This serves as a baseline comparison to the
// hierarchical approach.

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use console::style;
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, Aggregate},
    trbfv::{TrBFVShare, TrBFVPublicKeyShare, TrBFVDecryptionShare},
};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use rand::{distributions::Uniform, prelude::Distribution, rngs::OsRng, thread_rng};
use util::timeit::{timeit, timeit_n};

fn print_notice_and_exit(error: Option<String>) {
    println!(
        "{} Addition with flat threshold BFV",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} add [-h] [--help] [--num_summed=<value>] [--num_parties=<value>] [--threshold=<value>]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} Flat threshold setup with configurable parties and threshold",
        style("      note:").magenta().bold()
    );
    println!(
        "{} {} {} and {} must be at least 1, and threshold <= num_parties",
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
    // Parameters
    let degree = 2048;
    let plaintext_modulus: u64 = 4096;
    let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];

    // Parse command line arguments
    let args: Vec<String> = env::args().skip(1).collect();

    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_summed = 1;
    let mut num_parties = 5; // Default: 5 parties
    let mut threshold = 3; // Default: 3/5 threshold

    // Parse command line arguments
    for arg in &args {
        if arg.starts_with("--num_summed") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_summed` argument".to_string()))
            } else {
                num_summed = a[0].parse::<usize>().unwrap();
            }
        } else if arg.starts_with("--num_parties") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_parties` argument".to_string()))
            } else {
                num_parties = a[0].parse::<usize>().unwrap();
            }
        } else if arg.starts_with("--threshold") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--threshold` argument".to_string()))
            } else {
                threshold = a[0].parse::<usize>().unwrap();
            }
        } else {
            print_notice_and_exit(Some(format!("Unrecognized argument: {arg}")))
        }
    }

    // Validate parameters
    if num_summed == 0 || num_parties == 0 || threshold == 0 {
        print_notice_and_exit(Some("All parameters must be nonzero".to_string()))
    }
    if threshold > num_parties {
        print_notice_and_exit(Some("Threshold must be <= num_parties".to_string()))
    }

    // Display configuration
    println!("# Addition with flat trBFV");
    println!("\tnum_summed = {num_summed}");
    println!("\tnum_parties = {num_parties}");
    println!("\tthreshold = {threshold}/{num_parties}");

    // Generate the BFV parameters structure
    let params = timeit!(
        "Parameters generation",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()?
    );

    // Generate a common reference poly for public key generation
    let crp = CommonRandomPoly::new(&params, &mut thread_rng())?;

    // Create TrBFV instance for threshold operations
    let trbfv = TrBFVShare::new(
        num_parties,
        threshold,
        degree,
        plaintext_modulus,
        160,
        moduli.clone(),
        params.clone(),
    )?;

    // Generate parties
    let parties: Vec<(SecretKey, TrBFVPublicKeyShare)> = timeit!("Generate parties", {
        (0..num_parties)
            .map(|_| {
                let sk = SecretKey::random(&params, &mut OsRng);
                let threshold_pk_share = trbfv
                    .generate_public_key_share(sk.coeffs.clone(), crp.clone(), &mut thread_rng())
                    .unwrap();
                (sk, threshold_pk_share)
            })
            .collect()
    });

    // Aggregate public keys to create final public key
    let final_pk: PublicKey = timeit!("Public key aggregation", {
        parties
            .iter()
            .map(|(_, pk_share)| pk_share.pk_share.clone())
            .aggregate()?
    });

    // Encrypted addition setup
    let dist = Uniform::new_inclusive(0, 1);
    let numbers: Vec<u64> = dist
        .sample_iter(&mut thread_rng())
        .take(num_summed)
        .collect();
    
    let mut numbers_encrypted = Vec::with_capacity(num_summed);
    let mut _i = 0;
    timeit_n!("Encrypting Numbers (per encryption)", num_summed as u32, {
        #[allow(unused_assignments)]
        let pt = Plaintext::try_encode(&[numbers[_i]], Encoding::poly(), &params)?;
        let ct = final_pk.try_encrypt(&pt, &mut thread_rng())?;
        numbers_encrypted.push(ct);
        _i += 1;
    });

    // Homomorphic addition
    let tally = timeit!("Number tallying", {
        let mut sum = Ciphertext::zero(&params);
        for ct in &numbers_encrypted {
            sum += ct;
        }
        Arc::new(sum)
    });

    // Generate decryption shares from all parties
    let decryption_shares: Vec<TrBFVDecryptionShare> = timeit!("Generate decryption shares", {
        parties
            .iter()
            .map(|(sk, _)| {
                trbfv.generate_decryption_share(
                    sk.coeffs.clone(),
                    tally.clone(),
                    &mut thread_rng(),
                ).unwrap()
            })
            .collect()
    });

    // Final decryption using ALL shares (not threshold) since we're using MBFV protocol
    let result = timeit!("Threshold decryption", {
        Plaintext::from_shares(decryption_shares)?
    });

    let result_vec = Vec::<u64>::try_decode(&result, Encoding::poly())?;
    let final_result = result_vec[0];

    // Show summation result
    println!("Sum result = {} / {}", final_result, num_summed);

    let expected_result: u64 = numbers.iter().sum();
    assert_eq!(final_result, expected_result);

    println!("✅ Flat threshold BFV addition completed successfully!");

    Ok(())
}
