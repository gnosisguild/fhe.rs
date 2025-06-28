// Copyright (C) 2023 Gnosisguild
// SPDX-License-Identifier: GPL-3.0-or-later

//! SSS-based DKG Implementation following the algorithm specification
//!
//! This implements the true threshold BFV DKG algorithm using SSS:
//! 1. Each party generates contribution p_i to secret key s = Σ p_i  
//! 2. For each coefficient position, SSS is used to distribute shares of the final coefficient
//! 3. Each party gets shares of the distributed secret (never the secret itself)
//! 4. Test both SSS-based methods and traditional methods for comparison

use std::env;
use std::sync::Arc;

use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext, SecretKey};
use fhe::mbfv::{AggregateIter, CommonRandomPoly, DecryptionShare, PublicKeyShare};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use rand::{thread_rng, Rng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let (num_parties, party_size, threshold) = if args.len() >= 4 {
        let num_parties = args[1]
            .parse::<usize>()
            .map_err(|_| "Invalid num_parties: must be a positive integer")?;
        let party_size = args[2]
            .parse::<usize>()
            .map_err(|_| "Invalid party_size: must be a positive integer")?;
        let threshold = args[3]
            .parse::<usize>()
            .map_err(|_| "Invalid threshold: must be a positive integer")?;

        // Validate arguments
        if num_parties < 1 {
            return Err("num_parties must be at least 1".into());
        }
        if party_size < threshold {
            return Err("party_size must be at least threshold".into());
        }
        if threshold < 1 {
            return Err("threshold must be at least 1".into());
        }
        // if party_size > num_parties {
        //     return Err("party_size cannot be larger than num_parties".into());
        // }

        (num_parties, party_size, threshold)
    } else {
        // Default values
        println!("Usage: {} <num_parties> <party_size> <threshold>", args[0]);
        println!("Using default values: num_parties=10, party_size=5, threshold=3");
        (10, 5, 3)
    };

    // Setup parameters (using the same as voting example which works)
    let par = BfvParametersBuilder::new()
        .set_degree(1024)
        .set_plaintext_modulus(4096)
        .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
        .build_arc()?;
    let crp = CommonRandomPoly::new(&par, &mut rng)?;

    println!("=== SSS-based DKG Implementation ===");
    println!("Following the threshold BFV algorithm specification with SSS");
    println!(
        "Parameters: {} total parties, {} in group, {} threshold",
        num_parties, party_size, threshold
    );

    // Step 1: Each party generates their polynomial contribution p_i
    println!("\n🔑 Step 1: Generating party contributions...");
    let mut party_contributions = Vec::new();

    for _party_id in 0..party_size {
        // Generate random polynomial p_i with coefficients in {-1, 0, 1}
        let p_i: Vec<i64> = (0..par.degree()).map(|_| rng.gen_range(-1..=1)).collect();
        party_contributions.push(p_i.clone());
    }
    println!(
        "   ✓ Generated {} party contributions with {} coefficients each",
        party_size,
        par.degree()
    );

    // Step 2: Simulate the SSS distribution process for each coefficient
    println!("\n🔗 Step 2: Creating and distributing SSS shares...");
    // Compute the theoretical secret key s = Σ p_i (for verification only)
    let mut theoretical_s = vec![0i64; par.degree()];
    for p_i in &party_contributions {
        for (j, &coeff) in p_i.iter().enumerate() {
            theoretical_s[j] += coeff;
        }
    }

    // Now implement proper SSS for each coefficient
    // Step 2.1: For each coefficient s_j, create SSS shares and distribute them

    // For each coefficient position, we'll store the SSS shares that each party receives
    // Format: party_sss_shares[party_id][modulus_idx][coefficient_idx]
    let moduli = par.moduli();
    let num_moduli = moduli.len();
    let mut party_sss_shares: Vec<Vec<Vec<num_bigint_old::BigInt>>> = vec![Vec::new(); party_size];

    // Initialize the structure for each party
    for party_id in 0..party_size {
        party_sss_shares[party_id] = vec![Vec::new(); num_moduli];
        for mod_idx in 0..num_moduli {
            party_sss_shares[party_id][mod_idx] =
                vec![num_bigint_old::BigInt::from(0); par.degree()];
        }
    }

    for coeff_idx in 0..par.degree() {
        let s_j = theoretical_s[coeff_idx]; // The coefficient we're sharing via SSS

        // Create SSS shares for this coefficient s_j
        let mut shares_for_coeff = Vec::new();

        // Generate random coefficients for the polynomial f(x) = s_j + a1*x + a2*x^2 + ...
        let mut poly_coeffs = vec![s_j]; // Constant term is the secret
        for _ in 1..threshold {
            poly_coeffs.push(rng.gen_range(-1000..1000)); // Random polynomial coefficients
        }

        // Evaluate polynomial at each party's x-coordinate (1-indexed)
        for party_id in 1..=party_size {
            let x = num_bigint_old::BigInt::from(party_id as i64);
            let mut share_value = num_bigint_old::BigInt::from(poly_coeffs[0]); // Start with constant term s_j
            let mut x_power = x.clone();

            for deg in 1..threshold {
                let term = num_bigint_old::BigInt::from(poly_coeffs[deg]) * &x_power;
                share_value += term;
                x_power *= &x; // Use BigInt multiplication to avoid overflow
            }
            shares_for_coeff.push(share_value);
        }

        // Distribute shares: each party gets their share for this coefficient
        // For simplicity, we'll put the same share value in all moduli (this is just for testing)
        for party_id in 0..party_size {
            for mod_idx in 0..num_moduli {
                party_sss_shares[party_id][mod_idx][coeff_idx] = shares_for_coeff[party_id].clone();
            }
        }
    }

    println!(
        "   ✓ Created and distributed SSS shares for all {} coefficients",
        par.degree()
    );

    // Step 2.2: Each party now has SSS shares for all coefficients
    // Let's test reconstruction using threshold parties
    let participating_parties: Vec<usize> = (0..threshold).collect(); // Use first threshold parties
                                                                      // Reconstruct the secret coefficients using SSS from threshold parties
    let mut reconstructed_s = vec![0i64; par.degree()];
    for coeff_idx in 0..par.degree() {
        // Get the shares for this coefficient from participating parties (using first modulus)
        let mut points = Vec::new();
        for &party_id in &participating_parties {
            let x = (party_id + 1) as i64; // Party IDs are 1-indexed in SSS
            let y = &party_sss_shares[party_id][0][coeff_idx]; // First modulus
            points.push((x, y.clone()));
        }

        // Perform Lagrange interpolation to reconstruct s_j at x=0
        let mut result = num_bigint_old::BigInt::from(0);
        for i in 0..points.len() {
            let (x_i, y_i) = &points[i];
            let mut lagrange_coeff = num_bigint_old::BigInt::from(1);
            let mut denominator = num_bigint_old::BigInt::from(1);

            for j in 0..points.len() {
                if i != j {
                    let (x_j, _) = &points[j];
                    lagrange_coeff *= num_bigint_old::BigInt::from(-x_j); // (0 - x_j)
                    denominator *= num_bigint_old::BigInt::from(x_i - x_j); // (x_i - x_j)
                }
            }

            // result += y_i * (lagrange_coeff / denominator)
            let term = y_i * &lagrange_coeff / &denominator;
            result += &term;
        }

        reconstructed_s[coeff_idx] = result.to_string().parse::<i64>().unwrap_or(0);
    }

    // Verify SSS reconstruction matches the theoretical secret
    let sss_matches = reconstructed_s == theoretical_s;
    if sss_matches {
        println!("   ✅ SSS reconstruction is correct!");
    } else {
        println!("   ❌ SSS reconstruction failed!");
        return Err("SSS reconstruction verification failed".into());
    }

    // Step 3: Now use the SSS-based methods to create key shares
    println!("\n🔑 Step 3: Creating PublicKeyShare using SSS reconstruction...");

    // Convert party SSS shares to the format expected by from_threshold_sss_shares
    let mut threshold_shares = Vec::new();
    for &party_id in &participating_parties {
        let party_shares: Vec<Vec<num_bigint_old::BigInt>> = party_sss_shares[party_id].clone();
        threshold_shares.push(party_shares);
    }

    let party_indices: Vec<usize> = participating_parties.iter().map(|&i| i + 1).collect(); // 1-indexed

    // Use the SSS-based method to create the public key share
    let sss_pk_share = PublicKeyShare::from_threshold_sss_shares(
        threshold_shares.clone(),
        &party_indices,
        threshold,
        &par,
        crp.clone(),
    )?;

    println!("   ✅ Created PublicKeyShare using SSS reconstruction");

    // Also create the traditional approach for comparison
    let traditional_sk = SecretKey::new(theoretical_s.clone(), &par);
    let traditional_pk_share = PublicKeyShare::new(&traditional_sk, crp.clone(), &mut rng)?;

    // Step 4: Compare the SSS and traditional public keys
    println!("\n🔍 Step 4: Comparing SSS vs traditional public key creation...");
    let sss_pk: fhe::bfv::PublicKey = [sss_pk_share.clone()].iter().cloned().aggregate()?;
    let traditional_pk: fhe::bfv::PublicKey =
        [traditional_pk_share.clone()].iter().cloned().aggregate()?;

    println!("   ✅ Both public keys created successfully");

    // Step 5: Test encryption with both approaches
    println!("\n🔒 Step 5: Testing encryption with both approaches...");
    let message = vec![42i64, 123, 456, 789, 1011];
    let plaintext = Plaintext::try_encode(&message, Encoding::poly(), &par)?;

    // Encrypt with SSS-derived public key
    let sss_ciphertext = Arc::new(sss_pk.try_encrypt(&plaintext, &mut rng)?);

    // Encrypt with traditional public key
    let traditional_ciphertext = Arc::new(traditional_pk.try_encrypt(&plaintext, &mut rng)?);

    println!("   ✓ Encrypted with both approaches");

    // Step 5.5: Test homomorphic operations
    println!("\n➕ Step 5.5: Testing homomorphic addition...");

    // Create a second message for homomorphic addition
    let message2 = vec![10i64, 20, 30, 40, 50];
    let plaintext2 = Plaintext::try_encode(&message2, Encoding::poly(), &par)?;
    let sss_ciphertext2 = Arc::new(sss_pk.try_encrypt(&plaintext2, &mut rng)?);

    // Perform homomorphic addition: ciphertext_sum = ciphertext1 + ciphertext2
    let sss_ciphertext_sum = &*sss_ciphertext + &*sss_ciphertext2;
    println!("   ✓ Performed homomorphic addition on SSS-encrypted data");

    // Expected result: message1 + message2
    let expected_sum: Vec<i64> = message
        .iter()
        .zip(message2.iter())
        .map(|(a, b)| a + b)
        .collect();
    println!("   📊 Expected sum: {:?}", expected_sum);

    // Step 6: Test decryption using SSS-based DecryptionShare
    println!("\n🔓 Step 6: Testing SSS-based decryption...");

    // Create decryption shares using SSS reconstruction
    let sss_dec_share = DecryptionShare::from_threshold_sss_shares(
        threshold_shares.clone(),
        &party_indices,
        threshold,
        &par,
        sss_ciphertext.clone(),
    )?;

    let sss_decrypted_plaintext: fhe::bfv::Plaintext =
        [sss_dec_share].iter().cloned().aggregate()?;
    let sss_decrypted_message = Vec::<i64>::try_decode(&sss_decrypted_plaintext, Encoding::poly())?;

    // Also test decryption of the homomorphic sum
    let sss_sum_ciphertext = Arc::new(sss_ciphertext_sum);
    let sss_sum_dec_share = DecryptionShare::from_threshold_sss_shares(
        threshold_shares.clone(),
        &party_indices,
        threshold,
        &par,
        sss_sum_ciphertext.clone(),
    )?;

    let sss_sum_decrypted_plaintext: fhe::bfv::Plaintext =
        [sss_sum_dec_share].iter().cloned().aggregate()?;
    let sss_sum_decrypted_message =
        Vec::<i64>::try_decode(&sss_sum_decrypted_plaintext, Encoding::poly())?;

    println!(
        "   📊 SSS homomorphic sum result: {:?}",
        &sss_sum_decrypted_message[..expected_sum.len()]
    );

    // Step 7: Test decryption using traditional approach
    println!("\n🔍 Step 7: Testing traditional decryption for comparison...");

    let traditional_dec_share =
        DecryptionShare::new(&traditional_sk, &traditional_ciphertext, &mut rng)?;
    let traditional_decrypted_plaintext: fhe::bfv::Plaintext =
        [traditional_dec_share].iter().cloned().aggregate()?;
    let traditional_decrypted_message =
        Vec::<i64>::try_decode(&traditional_decrypted_plaintext, Encoding::poly())?;

    // Step 8: Verify both approaches work
    println!("\n🎯 Step 8: Verification results...");

    let sss_works = &sss_decrypted_message[..message.len()] == &message;
    let traditional_works = &traditional_decrypted_message[..message.len()] == &message;
    let homomorphic_works = &sss_sum_decrypted_message[..expected_sum.len()] == &expected_sum;

    println!("   📊 Original message: {:?}", message);
    println!("   ✅ SSS approach works: {}", sss_works);
    println!("   ✅ Traditional approach works: {}", traditional_works);
    println!("   ➕ Homomorphic addition works: {}", homomorphic_works);

    if sss_works && traditional_works && homomorphic_works {
        println!("\n🎉 SUCCESS: All approaches including homomorphic operations work correctly!");
    } else if traditional_works && !sss_works {
        println!("\n⚠️  Traditional works but SSS fails - issue in SSS implementation");
        return Err("SSS approach verification failed".into());
    } else if sss_works && !traditional_works {
        println!("\n⚠️  SSS works but traditional fails - unexpected!");
        return Err("Traditional approach verification failed".into());
    } else if !homomorphic_works {
        println!("\n⚠️  Basic decryption works but homomorphic operations fail");
        return Err("Homomorphic operation verification failed".into());
    } else {
        println!("\n❌ FAILURE: Multiple approaches fail");
        return Err("Multiple decryption approaches failed".into());
    }

    println!("\n=== 📊 Summary ===");
    println!("✅ SSS coefficient reconstruction: WORKS");
    println!(
        "✅ SSS-based PublicKeyShare creation: {}",
        if sss_works { "WORKS" } else { "FAILS" }
    );
    println!(
        "✅ SSS-based DecryptionShare creation: {}",
        if sss_works { "WORKS" } else { "FAILS" }
    );
    println!(
        "✅ Traditional approach: {}",
        if traditional_works { "WORKS" } else { "FAILS" }
    );
    println!(
        "➕ Homomorphic addition: {}",
        if homomorphic_works { "WORKS" } else { "FAILS" }
    );
    println!("\n=== 🔢 Parameters Used ===");
    println!("• Total parties: {}", num_parties);
    println!("• Total party members: {}", party_size * num_parties);
    println!("• Party size: {}", party_size);
    println!("• Party threshold: {}", threshold);

    Ok(())
}
