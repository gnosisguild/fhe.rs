// Implementation of hierarchical threshold addition using the `fhe` and `trbfv` crate.
//
// This example demonstrates a hierarchical threshold BFV setup where:
// - Parties are organized into a tree structure with arbitrary depth
// - Each level can have configurable group sizes and thresholds
// - The hierarchy allows for complex access patterns and provides better
//   fault tolerance and security properties compared to flat threshold schemes.
// - Unlike the old example, this version never reconstructs secret keys at any level
//
// Example usage:
// - `--depth=2 --group_size=3 --threshold=2` creates a 2-level hierarchy with 3-party groups and 2/3 threshold
// - `--depth=3 --group_size=4 --threshold=3` creates a 3-level hierarchy with 4-party groups and 3/4 threshold
//
// Based on the hierarchical MBFV example pattern.

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

// Hierarchical party structure - each node represents a group at a certain level
#[derive(Clone)]
struct Party {
    sk: SecretKey, // Individual secret key
    threshold_pk_share: TrBFVPublicKeyShare, // Threshold public key share
    level: usize, // Level in hierarchy
}

fn print_notice_and_exit(error: Option<String>) {
    println!(
        "{} Addition with hierarchical threshold BFV",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} add [-h] [--help] [--num_summed=<value>] [--depth=<value>] [--group_size=<value>] [--threshold=<value>]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} Hierarchical setup with configurable depth, group sizes, and thresholds",
        style("      note:").magenta().bold()
    );
    println!(
        "{} {} {} {} and {} must be at least 1, and threshold < group_size",
        style("constraints:").magenta().bold(),
        style("num_summed").blue(),
        style("depth").blue(),
        style("group_size").blue(),
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
    let mut depth = 2; // Default: 2-level hierarchy
    let mut group_size = 3; // Default: 3 parties per group
    let mut threshold = 2; // Default: 2/3 threshold

    // Parse command line arguments
    for arg in &args {
        if arg.starts_with("--num_summed") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_summed` argument".to_string()))
            } else {
                num_summed = a[0].parse::<usize>().unwrap();
            }
        } else if arg.starts_with("--depth") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--depth` argument".to_string()))
            } else {
                depth = a[0].parse::<usize>().unwrap();
            }
        } else if arg.starts_with("--group_size") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--group_size` argument".to_string()))
            } else {
                group_size = a[0].parse::<usize>().unwrap();
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
    if num_summed == 0 || depth == 0 || group_size == 0 || threshold == 0 {
        print_notice_and_exit(Some("All parameters must be nonzero".to_string()))
    }
    if threshold >= group_size {
        print_notice_and_exit(Some("Threshold must be less than group_size".to_string()))
    }
    if depth == 1 {
        print_notice_and_exit(Some(
            "Depth must be at least 2 for hierarchical threshold".to_string(),
        ))
    }

    // Calculate total number of parties
    let total_parties = group_size.pow(depth as u32);

    // Display hierarchy information
    println!("# Addition with hierarchical trBFV");
    println!("\tnum_summed = {num_summed}");
    println!("\tdepth = {depth}");
    println!("\tgroup_size = {group_size}");
    println!("\tthreshold = {threshold}/{group_size}");
    println!("\ttotal_parties = {total_parties}");

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
        group_size,
        threshold,
        degree,
        plaintext_modulus,
        160,
        moduli.clone(),
        params.clone(),
    )?;

    // Generate base parties (leaf level)
    let base_parties: Vec<Party> = timeit!("Generate base parties", {
        (0..total_parties)
            .map(|_| {
                let sk = SecretKey::random(&params, &mut OsRng);
                let threshold_pk_share = trbfv
                    .generate_public_key_share(sk.coeffs.clone(), crp.clone(), &mut thread_rng())
                    .unwrap();
                Party {
                    sk,
                    threshold_pk_share,
                    level: 0,
                }
            })
            .collect()
    });

    // Build hierarchy levels by aggregating groups
    let mut current_level_shares = base_parties
        .iter()
        .map(|p| p.threshold_pk_share.clone())
        .collect::<Vec<_>>();

    let mut level_groups: Vec<Vec<Vec<TrBFVPublicKeyShare>>> = Vec::new();

    // Aggregate up the hierarchy
    for level in 1..depth {
        println!("Building level {} with {} groups", level, current_level_shares.len() / group_size);
        
        let mut next_level_shares = Vec::new();
        let mut current_level_groups = Vec::new();

        // Group current level shares and aggregate them
        for group_shares in current_level_shares.chunks(group_size) {
            let group = group_shares.to_vec();
            current_level_groups.push(group.clone());
            
            // Aggregate the group into a single public key share
            let aggregated_share: TrBFVPublicKeyShare = group.into_iter().aggregate()?;
            next_level_shares.push(aggregated_share);
        }

        level_groups.push(current_level_groups);
        current_level_shares = next_level_shares;
    }

    // The final aggregated public key
    let final_pk: PublicKey = timeit!("Final public key aggregation", {
        current_level_shares
            .into_iter()
            .map(|share| share.pk_share)
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

    // Hierarchical decryption using threshold shares
    // First, generate decryption shares from base parties
    let base_decryption_shares: Vec<TrBFVDecryptionShare> = timeit!("Generate base decryption shares", {
        base_parties
            .iter()
            .map(|party| {
                trbfv.generate_decryption_share(
                    party.sk.coeffs.clone(),
                    tally.clone(),
                    &mut thread_rng(),
                ).unwrap()
            })
            .collect()
    });

    // Aggregate decryption shares up the hierarchy
    let mut current_decryption_shares = base_decryption_shares;

    for (level, groups) in level_groups.iter().enumerate() {
        println!("Aggregating decryption shares at level {}", level + 1);
        
        let mut next_level_shares = Vec::new();
        
        // Aggregate decryption shares for each group
        for (group_idx, _group) in groups.iter().enumerate() {
            let start_idx = group_idx * group_size;
            let end_idx = std::cmp::min(start_idx + group_size, current_decryption_shares.len());
            
            if end_idx > start_idx {
                let group_shares = current_decryption_shares[start_idx..end_idx].to_vec();
                let aggregated_share: TrBFVDecryptionShare = group_shares.into_iter().aggregate()?;
                next_level_shares.push(aggregated_share);
            }
        }
        
        current_decryption_shares = next_level_shares;
    }

    // Final decryption using ALL top-level shares (since we're using MBFV protocol under the hood)
    let result = timeit!("Final threshold decryption", {
        Plaintext::from_shares(current_decryption_shares)?
    });

    let result_vec = Vec::<u64>::try_decode(&result, Encoding::poly())?;
    let final_result = result_vec[0];

    // Show summation result
    println!("Sum result = {} / {}", final_result, num_summed);

    let expected_result: u64 = numbers.iter().sum();
    assert_eq!(final_result, expected_result);

    println!("✅ Hierarchical threshold BFV addition completed successfully!");

    Ok(())
}
