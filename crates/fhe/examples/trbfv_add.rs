// Implementation of threshold addition using the `fhe` and `trbfv` crate with l-BFV integration.
//
// This example demonstrates:
// - Threshold BFV cryptosystem with l-BFV integration
// - Secret key sharing among parties
// - Homomorphic addition of encrypted values
// - Robust threshold decryption with smudging noise

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
        "{} Threshold Addition with l-BFV integration",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} add [-h] [--help] [--num_summed=<value>] [--num_parties=<value>] [--threshold=<value>]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} {} {} and {} must be at least 1, and threshold < num_parties",
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
    // Parameters for threshold BFV with l-BFV integration
    let degree = 2048;
    let plaintext_modulus: u64 = 4096;
    let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];

    // Command line argument parsing
    let args: Vec<String> = env::args().skip(1).collect();

    // Print help if requested
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_summed = 1;
    let mut num_parties = 3;
    let mut threshold = 2;

    // Parse command line arguments
    for arg in &args {
        if arg.starts_with("--num_summed") {
            let parts: Vec<&str> = arg.rsplit('=').collect();
            if parts.len() != 2 || parts[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_summed` argument".to_string()))
            } else {
                num_summed = parts[0].parse::<usize>()?
            }
        } else if arg.starts_with("--num_parties") {
            let parts: Vec<&str> = arg.rsplit('=').collect();
            if parts.len() != 2 || parts[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_parties` argument".to_string()))
            } else {
                num_parties = parts[0].parse::<usize>()?
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
    if num_summed == 0 || num_parties == 0 || threshold == 0 {
        print_notice_and_exit(Some(
            "All parameters must be nonzero".to_string(),
        ))
    }
    if threshold >= num_parties {
        print_notice_and_exit(Some(
            "Threshold must be less than number of parties".to_string(),
        ))
    }

    // Display configuration
    println!("# Threshold Addition with l-BFV Integration");
    println!("\tnum_summed = {num_summed}");
    println!("\tnum_parties = {num_parties}");
    println!("\tthreshold = {threshold}");
    println!("\tusing l-BFV for enhanced security and efficiency");

    // Generate shared BFV parameters
    let params = timeit!(
        "BFV Parameters generation",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()?
    );

    // Step 1: Generate a master secret key (in practice, this would be distributed)
    let master_secret_key = timeit!("Master secret key generation", {
        SecretKey::random(&params, &mut OsRng)
    });

    // Step 2: Create TrBFV instance and generate l-BFV keys
    let mut trbfv = timeit!("TrBFV setup with l-BFV keys", {
        let mut trbfv_instance = TrBFVShare::new(
            num_parties,
            threshold,
            degree,
            plaintext_modulus,
            160, // smudging variance for 128-bit security
            moduli.clone(),
            params.clone(),
        )?;

        // Generate l-BFV keys from the master secret key
        trbfv_instance.generate_lbfv_keys(&master_secret_key, &mut OsRng)?;
        
        trbfv_instance
    });

    // Step 3: Generate secret shares for threshold decryption
    let secret_shares = timeit!("Secret key sharing", {
        trbfv.generate_secret_shares(master_secret_key.coeffs.clone())?
    });

    // Step 4: Generate smudging error shares for robust decryption
    let _smudging_errors = timeit!("Smudging error generation", {
        let smudging_coeffs = trbfv.generate_smudging_error(&mut OsRng)?;
        trbfv.generate_secret_shares(smudging_coeffs.into_boxed_slice())?
    });

    // Step 5: Generate random numbers and encrypt them using l-BFV
    let dist = Uniform::new_inclusive(0u64, 10u64);
    let numbers: Vec<u64> = dist
        .sample_iter(&mut thread_rng())
        .take(num_summed)
        .collect();
    
    println!("Numbers to sum: {:?}", numbers);
    
    let encrypted_numbers = timeit_n!("l-BFV Encryption (per number)", num_summed as u32, {
        let mut encrypted = Vec::with_capacity(num_summed);
        for &number in &numbers {
            let plaintext = Plaintext::try_encode(&[number], Encoding::poly(), &params)?;
            let ciphertext = trbfv.encrypt(&plaintext, &mut thread_rng())?;
            encrypted.push(ciphertext);
        }
        encrypted
    });

    // Step 6: Perform homomorphic addition
    let sum_ciphertext = timeit!("Homomorphic addition", {
        let mut result = Ciphertext::zero(&params);
        for ct in &encrypted_numbers {
            result += ct;
        }
        Arc::new(result)
    });

    // Step 7: Simulate threshold decryption by collecting shares from threshold parties
    let decryption_shares = timeit!("Threshold decryption shares", {
        let mut shares = Vec::with_capacity(threshold);
        
        for party_idx in 0..threshold {
            // Reconstruct this party's secret key share
            let mut party_sk_shares = Vec::new();
            for modulus_idx in 0..moduli.len() {
                party_sk_shares.push(secret_shares[modulus_idx].row(party_idx).to_owned());
            }
            
            // Convert shares back to polynomial
            let mut sk_share_data = Vec::new();
            for modulus_idx in 0..moduli.len() {
                for coeff_idx in 0..degree {
                    sk_share_data.push(party_sk_shares[modulus_idx][coeff_idx]);
                }
            }
            
            let sk_share_matrix = Array2::from_shape_vec((moduli.len(), degree), sk_share_data)?;
            let mut sk_share_poly = Poly::zero(params.ctx_at_level(0)?, Representation::PowerBasis);
            sk_share_poly.set_coefficients(sk_share_matrix);
            
            // Generate smudging error for this party
            let smudging_coeffs = trbfv.generate_smudging_error(&mut OsRng)?;
            let smudging_poly = Poly::try_convert_from(
                &smudging_coeffs,
                params.ctx_at_level(0)?,
                false,
                Representation::PowerBasis,
            )?;
            
            // Compute decryption share
            let share = trbfv.decryption_share(
                sum_ciphertext.clone(),
                sk_share_poly,
                smudging_poly,
            )?;
            
            shares.push(share);
        }
        
        shares
    });

    // Step 8: Reconstruct the plaintext from threshold decryption shares
    let decrypted_result = timeit!("Threshold decryption reconstruction", {
        trbfv.decrypt(decryption_shares, sum_ciphertext)?
    });

    // Step 9: Decode the result and verify correctness
    let result_vec = Vec::<u64>::try_decode(&decrypted_result, Encoding::poly())?;
    let decrypted_sum = result_vec[0];
    let expected_sum: u64 = numbers.iter().sum();

    // Display results
    println!("\n# Results:");
    println!("\tEncrypted sum result: {}", decrypted_sum);
    println!("\tExpected sum: {}", expected_sum);
    println!("\tCorrectness: {}", if decrypted_sum == expected_sum { "✓ PASS" } else { "✗ FAIL" });

    // Verify correctness
    assert_eq!(
        decrypted_sum, expected_sum,
        "Threshold decryption failed: got {}, expected {}",
        decrypted_sum, expected_sum
    );

    println!("\n🎉 Threshold BFV with l-BFV integration successful!");

    Ok(())
}
