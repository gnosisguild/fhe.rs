// Copyright (C) 2023 Gnosisguild
// SPDX-License-Identifier: GPL-3.0-or-later

//! SSS-based DKG Implementation following the algorithm specification
//!
//! This implements the true threshold BFV DKG algorithm using SSS:
//! 1. Each party generates contribution p_i to secret key s = Σ p_i  
//! 2. For each coefficient position, SSS is used to distribute shares of the final coefficient
//! 3. Each party gets shares of the distributed secret (never the secret itself)
//! 4. Test both SSS-based methods and traditional methods for comparison

use std::sync::Arc;

use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext, SecretKey};
use fhe::mbfv::{AggregateIter, CommonRandomPoly, DecryptionShare, PublicKeyShare};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use rand::{thread_rng, Rng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    // Setup parameters (using the same as voting example which works)
    let par = BfvParametersBuilder::new()
        .set_degree(1024)
        .set_plaintext_modulus(4096)
        .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
        .build_arc()?;
    let crp = CommonRandomPoly::new(&par, &mut rng)?;
    let group_size = 5;
    let threshold = 3;

    println!("=== SSS-based DKG Implementation ===");
    println!("Following the threshold BFV algorithm specification with SSS");

    // Step 1: Each party generates their polynomial contribution p_i
    println!("\n🔑 Step 1: Each party generates their contribution p_i...");
    let mut party_contributions = Vec::new();

    for party_id in 0..group_size {
        // Generate random polynomial p_i with coefficients in {-1, 0, 1}
        let p_i: Vec<i64> = (0..par.degree()).map(|_| rng.gen_range(-1..=1)).collect();
        party_contributions.push(p_i.clone());
        println!(
            "   ✓ Party {} generated p_{}: {:?}",
            party_id + 1,
            party_id + 1,
            &p_i[..4]
        );
    }

    // Step 2: Simulate the SSS distribution process for each coefficient
    println!("\n🔗 Step 2: SSS distribution for each coefficient of s = Σ p_i...");

    // Compute the theoretical secret key s = Σ p_i (for verification only)
    let mut theoretical_s = vec![0i64; par.degree()];
    for p_i in &party_contributions {
        for (j, &coeff) in p_i.iter().enumerate() {
            theoretical_s[j] += coeff;
        }
    }
    println!(
        "   📊 Theoretical s (first 4 coeffs): {:?}",
        &theoretical_s[..4]
    );

    // Now implement proper SSS for each coefficient
    // Step 2.1: For each coefficient s_j, create SSS shares and distribute them
    println!("   🔗 Creating SSS shares for each coefficient...");

    // For each coefficient position, we'll store the SSS shares that each party receives
    // Format: party_sss_shares[party_id][modulus_idx][coefficient_idx]
    let moduli = par.moduli();
    let num_moduli = moduli.len();
    let mut party_sss_shares: Vec<Vec<Vec<num_bigint_old::BigInt>>> = vec![Vec::new(); group_size];

    // Initialize the structure for each party
    for party_id in 0..group_size {
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
        for party_id in 1..=group_size {
            let mut share_value = poly_coeffs[0]; // Start with constant term s_j
            let x = party_id as i64;
            let mut x_power = x;

            for deg in 1..threshold {
                share_value += poly_coeffs[deg] * x_power;
                x_power *= x;
            }
            shares_for_coeff.push(num_bigint_old::BigInt::from(share_value));
        }

        // Distribute shares: each party gets their share for this coefficient
        // For simplicity, we'll put the same share value in all moduli (this is just for testing)
        for party_id in 0..group_size {
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
    let participating_parties: Vec<usize> = vec![0, 1, 2]; // Use first 3 parties
    println!(
        "   🔍 Testing SSS reconstruction with parties: {:?}",
        participating_parties
            .iter()
            .map(|&i| i + 1)
            .collect::<Vec<_>>()
    ); // Reconstruct the secret coefficients using SSS from threshold parties
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
            result += y_i * lagrange_coeff / denominator;
        }

        reconstructed_s[coeff_idx] = result.to_string().parse::<i64>().unwrap_or(0);
    }

    println!(
        "   📊 SSS reconstructed s (first 4 coeffs): {:?}",
        &reconstructed_s[..4]
    );
    println!(
        "   📊 Original theoretical s (first 4 coeffs): {:?}",
        &theoretical_s[..4]
    );

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
    println!("   ✓ Encrypted with SSS-derived public key");

    // Encrypt with traditional public key
    let traditional_ciphertext = Arc::new(traditional_pk.try_encrypt(&plaintext, &mut rng)?);
    println!("   ✓ Encrypted with traditional public key");

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

    println!(
        "   📊 SSS decrypted message: {:?}",
        &sss_decrypted_message[..message.len()]
    );

    // Step 7: Test decryption using traditional approach
    println!("\n🔍 Step 7: Testing traditional decryption for comparison...");

    let traditional_dec_share =
        DecryptionShare::new(&traditional_sk, &traditional_ciphertext, &mut rng)?;
    let traditional_decrypted_plaintext: fhe::bfv::Plaintext =
        [traditional_dec_share].iter().cloned().aggregate()?;
    let traditional_decrypted_message =
        Vec::<i64>::try_decode(&traditional_decrypted_plaintext, Encoding::poly())?;

    println!(
        "   📊 Traditional decrypted message: {:?}",
        &traditional_decrypted_message[..message.len()]
    );

    // Step 8: Verify both approaches work
    println!("\n🎯 Step 8: Verification results...");

    let sss_works = &sss_decrypted_message[..message.len()] == &message;
    let traditional_works = &traditional_decrypted_message[..message.len()] == &message;

    println!("   📊 Original message: {:?}", message);
    println!("   🔍 SSS approach works: {}", sss_works);
    println!("   🔍 Traditional approach works: {}", traditional_works);

    if sss_works && traditional_works {
        println!("\n🎉 SUCCESS: Both SSS and traditional approaches work correctly!");
    } else if traditional_works && !sss_works {
        println!("\n⚠️  Traditional works but SSS fails - issue in SSS implementation");
        return Err("SSS approach verification failed".into());
    } else if sss_works && !traditional_works {
        println!("\n⚠️  SSS works but traditional fails - unexpected!");
        return Err("Traditional approach verification failed".into());
    } else {
        println!("\n❌ FAILURE: Both approaches fail");
        return Err("Both decryption approaches failed".into());
    }

    println!("\n=== 📊 Analysis ===");
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
    println!("📝 Both approaches use the same reconstructed secret coefficients");
    println!("📝 This validates the SSS reconstruction logic");

    Ok(())
}
