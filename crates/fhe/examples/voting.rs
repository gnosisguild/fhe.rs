// Implementation of threshold voting using the `fhe` and `trbfv` crate with l-BFV integration.
//
// This example demonstrates:
// - Threshold BFV cryptosystem for secure electronic voting
// - Vote encryption using l-BFV for enhanced security
// - Threshold decryption requiring minimum number of election officials
// - Robust vote tallying with smudging noise for privacy protection

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use console::style;
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, SecretKey},
    trbfv::TrBFVShare,
};
use fhe_math::rq::{traits::TryConvertFrom, Poly, Representation};
use fhe_traits::{FheDecoder, FheEncoder};
use ndarray::Array2;
use rand::{distributions::Uniform, prelude::Distribution, rngs::OsRng, thread_rng};
use util::timeit::{timeit, timeit_n};

fn print_notice_and_exit(error: Option<String>) {
    println!(
        "{} Threshold Voting with l-BFV integration",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} voting [-h] [--help] [--num_voters=<value>] [--num_officials=<value>] [--threshold=<value>]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} {} {} and {} must be at least 1, and threshold <= num_officials",
        style("constraints:").magenta().bold(),
        style("num_voters").blue(),
        style("num_officials").blue(),
        style("threshold").blue(),
    );
    if let Some(error) = error {
        println!("{} {}", style("     error:").red().bold(), error);
    }
    exit(0);
}

fn main() -> Result<(), Box<dyn Error>> {
    // Parameters for threshold BFV voting system
    let degree = 4096;
    let plaintext_modulus: u64 = 4096;
    let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];

    // Command line argument parsing
    let args: Vec<String> = env::args().skip(1).collect();

    // Print help if requested
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_voters = 100;
    let mut num_officials = 7;
    let mut threshold = 5;

    // Parse command line arguments
    for arg in &args {
        if arg.starts_with("--num_voters") {
            let parts: Vec<&str> = arg.rsplit('=').collect();
            if parts.len() != 2 || parts[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_voters` argument".to_string()))
            } else {
                num_voters = parts[0].parse::<usize>()?
            }
        } else if arg.starts_with("--num_officials") {
            let parts: Vec<&str> = arg.rsplit('=').collect();
            if parts.len() != 2 || parts[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_officials` argument".to_string()))
            } else {
                num_officials = parts[0].parse::<usize>()?
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

    // Validate parameters
    if num_officials == 0 || num_voters == 0 || threshold == 0 {
        print_notice_and_exit(Some("All parameters must be nonzero".to_string()))
    }
    if threshold > num_officials {
        print_notice_and_exit(Some("Threshold cannot exceed number of officials".to_string()))
    }

    // Display election configuration
    println!("# Threshold Voting with l-BFV Integration");
    println!("\tnum_voters = {num_voters}");
    println!("\tnum_officials = {num_officials}");
    println!("\tthreshold = {threshold} (minimum officials needed to decrypt)");
    println!("\tusing l-BFV for enhanced vote security");

    // Generate shared BFV parameters for the election
    let params = timeit!(
        "Election parameters generation",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()?
    );

    // Step 1: Election setup - generate master election key (in practice, this would be distributed)
    let master_election_key = timeit!("Master election key generation", {
        SecretKey::random(&params, &mut OsRng)
    });

    // Step 2: Create threshold voting system with l-BFV integration
    let mut voting_system = timeit!("Threshold voting system setup", {
        let mut trbfv_instance = TrBFVShare::new(
            num_officials,
            threshold,
            degree,
            plaintext_modulus,
            160, // smudging variance for robust threshold decryption
            moduli.clone(),
            params.clone(),
        )?;

        // Generate l-BFV keys for secure vote encryption
        trbfv_instance.generate_lbfv_keys(&master_election_key, &mut OsRng)?;
        
        trbfv_instance
    });

    // Step 3: Distribute election key shares to officials
    let official_key_shares = timeit!("Election key sharing among officials", {
        voting_system.generate_secret_shares(master_election_key.coeffs.clone())?
    });

    // Step 4: Vote casting phase - voters encrypt their votes
    println!("\n## Vote Casting Phase");
    let dist = Uniform::new_inclusive(0u64, 1u64); // Binary vote: 0 = No, 1 = Yes
    let votes: Vec<u64> = dist
        .sample_iter(&mut thread_rng())
        .take(num_voters)
        .collect();
    
    // Count expected result for verification
    let expected_yes_votes = votes.iter().sum::<u64>();
    let expected_no_votes = num_voters as u64 - expected_yes_votes;
    
    println!("\tExpected results: {} Yes, {} No", expected_yes_votes, expected_no_votes);
    
    let encrypted_votes = timeit_n!("Vote encryption (per vote)", num_voters as u32, {
        let mut encrypted = Vec::with_capacity(num_voters);
        for &vote in &votes {
            let plaintext = Plaintext::try_encode(&[vote], Encoding::poly(), &params)?;
            let ciphertext = voting_system.encrypt(&plaintext, &mut thread_rng())?;
            encrypted.push(ciphertext);
        }
        encrypted
    });

    // Step 5: Vote tallying phase - homomorphic addition of all votes
    println!("\n## Vote Tallying Phase");
    let vote_tally = timeit!("Homomorphic vote tallying", {
        let mut total = Ciphertext::zero(&params);
        for vote_ct in &encrypted_votes {
            total += vote_ct;
        }
        Arc::new(total)
    });

    // Step 6: Threshold decryption phase - requires threshold officials to decrypt
    println!("\n## Threshold Decryption Phase");
    println!("\tRequiring {} out of {} election officials to decrypt tally", threshold, num_officials);
    
    let decryption_shares = timeit!("Threshold decryption by officials", {
        let mut shares = Vec::with_capacity(threshold);
        
        for official_idx in 0..threshold {
            // Each official reconstructs their key share from distributed shares
            let mut official_sk_shares = Vec::new();
            for modulus_idx in 0..moduli.len() {
                official_sk_shares.push(official_key_shares[modulus_idx].row(official_idx).to_owned());
            }
            
            // Convert shares back to polynomial representation
            let mut sk_share_data = Vec::new();
            for modulus_idx in 0..moduli.len() {
                for coeff_idx in 0..degree {
                    sk_share_data.push(official_sk_shares[modulus_idx][coeff_idx]);
                }
            }
            
            let sk_share_matrix = Array2::from_shape_vec((moduli.len(), degree), sk_share_data)?;
            let mut sk_share_poly = Poly::zero(params.ctx_at_level(0)?, Representation::PowerBasis);
            sk_share_poly.set_coefficients(sk_share_matrix);
            
            // Generate smudging error for privacy protection
            let smudging_coeffs = voting_system.generate_smudging_error(&mut OsRng)?;
            let smudging_poly = Poly::try_convert_from(
                &smudging_coeffs,
                params.ctx_at_level(0)?,
                false,
                Representation::PowerBasis,
            )?;
            
            // Official computes their decryption share
            let share = voting_system.decryption_share(
                vote_tally.clone(),
                sk_share_poly,
                smudging_poly,
            )?;
            
            shares.push(share);
            
            println!("\t✓ Official {} contributed decryption share", official_idx + 1);
        }
        
        shares
    });

    // Step 7: Reconstruct the vote tally from threshold decryption shares
    let decrypted_tally = timeit!("Vote tally reconstruction", {
        voting_system.decrypt(decryption_shares, vote_tally)?
    });

    // Step 8: Decode and verify the election results
    let tally_vec = Vec::<u64>::try_decode(&decrypted_tally, Encoding::poly())?;
    let decrypted_yes_votes = tally_vec[0];
    let decrypted_no_votes = num_voters as u64 - decrypted_yes_votes;

    // Display election results
    println!("\n## Election Results");
    println!("┌─────────────────────────────────────────┐");
    println!("│              VOTE RESULTS               │");
    println!("├─────────────────────────────────────────┤");
    println!("│ YES votes: {:8} ({:5.1}%)           │", 
             decrypted_yes_votes, 
             (decrypted_yes_votes as f64 / num_voters as f64) * 100.0);
    println!("│ NO votes:  {:8} ({:5.1}%)           │", 
             decrypted_no_votes, 
             (decrypted_no_votes as f64 / num_voters as f64) * 100.0);
    println!("├─────────────────────────────────────────┤");
    println!("│ Total voters: {:8}                │", num_voters);
    println!("│ Threshold security: {}/{} officials    │", threshold, num_officials);
    println!("└─────────────────────────────────────────┘");

    // Verify election integrity
    let results_match = decrypted_yes_votes == expected_yes_votes;
    println!("\n## Election Integrity Verification");
    println!("\tExpected YES votes: {}", expected_yes_votes);
    println!("\tDecrypted YES votes: {}", decrypted_yes_votes);
    println!("\tIntegrity check: {}", if results_match { "✅ VERIFIED" } else { "❌ FAILED" });

    // Final assertion for correctness
    assert_eq!(
        decrypted_yes_votes, expected_yes_votes,
        "Election integrity compromised: got {} YES votes, expected {}",
        decrypted_yes_votes, expected_yes_votes
    );

    println!("\n🗳️  Threshold voting with l-BFV integration completed successfully!");
    println!("   🔐 Vote privacy protected by threshold cryptography");
    println!("   🛡️  Election integrity verified by threshold decryption");

    Ok(())
}
