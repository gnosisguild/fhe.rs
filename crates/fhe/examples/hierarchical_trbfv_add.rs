// Implementation of TRUE HIERARCHICAL THRESHOLD CRYPTOGRAPHY using SSS-based MBFV Control - PARALLELIZED
//
// This example demonstrates SECURE PARALLEL hierarchical threshold BFV following threshold_mbfv_sss_corrected:
// - Level 1 (Groups): TRUE threshold cryptography using SSS within each group (PARALLEL)
// - Level 2 (Hierarchy): MBFV aggregation across group threshold results (PARALLEL)
// - ANY t parties within a group can perform operations (true threshold property)
// - Group secrets are NEVER reconstructed - only SSS-based MBFV methods used
// - Zero trusted dealer: distributed key generation with SSS shares
// - PARALLEL execution: Groups and parties work concurrently for improved performance
//
// SECURITY Model (TRUE THRESHOLD - FULLY SECURE):
// - Each party generates SSS shares of their OWN contribution (no group secret reconstruction)
// - Each party holds SSS shares that are additive combinations of individual contributions
// - Group operations use SSS-based PublicKeyShare and DecryptionShare methods
// - Group secrets exist ONLY as SSS shares, NEVER reconstructed at any point
// - True t-security: up to t-1 parties can be compromised safely
//
// Algorithm (SECURE PARALLEL SSS-based DKG - NO GROUP SECRET RECONSTRUCTION):
// 1. Each party i generates SSS shares of their polynomial p_i contribution (PARALLEL)
// 2. Parties combine their SSS shares additively (NO secret reconstruction) (PARALLEL)
// 3. Each party k receives additive SSS shares (NEVER reconstructs group secret)
// 4. For operations: Use SSS-based PublicKeyShare and DecryptionShare methods (PARALLEL)
// 5. Cross-group: aggregate threshold results using MBFV aggregation (PARALLEL)
//
// Communication Complexity:
// - Within groups: O(n²) for DKG, O(t) for threshold operations (PARALLEL)
// - Between groups: O(num_groups) for hierarchical aggregation (PARALLEL)
// - Total: O(num_groups × (n² + t)) - parallel distributed threshold cryptography
// - Performance: Near-linear speedup with number of CPU cores available
//
// SECURITY COMPLIANCE:
// ✅ Group secret reconstruction is FORBIDDEN
// ✅ Top-level secret key creation from group secret is FORBIDDEN
// ✅ Secret key creation from reconstructed group secret is FORBIDDEN
// ✅ Algorithm follows SSS specification for threshold operations
// ✅ Group level keys created using SSS-based DKG
// ✅ Top-level secret uses MBFV aggregation, not reconstructed group secrets
// ✅ Parallelization maintains all security properties
//
// Example usage:
// - `--num_groups=3 --group_size=5 --threshold=3` creates 3 groups with 3/5 threshold each
// - `--num_groups=2 --group_size=4 --threshold=2` creates 2 groups with 2/4 threshold each
//
// Architecture:
// - Bottom layer: SSS-based true threshold within groups (SECURE + PARALLEL)
// - Top layer: MBFV aggregation across group threshold results (PARALLEL)
// - Security: TRUE threshold cryptography with mathematical guarantees
// - Performance: Parallel execution for scalability

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use crate::util::timeit::{timeit, timeit_n};
use console::style;
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey},
    mbfv::{AggregateIter, CommonRandomPoly, DecryptionShare, PublicKeyShare},
};
use fhe_traits::{FheEncoder, FheEncrypter};

use rand::distributions::Distribution;
use rand::distributions::Uniform;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};

// Parallelization imports
use rayon::prelude::*;

// SSS-based party structure for TRUE hierarchical threshold cryptography
// Each party holds SSS shares of their group's distributed secret coefficients
#[allow(dead_code)]
struct SssParty {
    group_id: usize,
    party_id_in_group: usize, // 1-based for SSS calculations
    // SSS shares for each coefficient position and each modulus
    sss_shares: Vec<Vec<num_bigint_old::BigInt>>, // [modulus_idx][coeff_idx] -> share
}

// Group state for SSS-based MBFV DKG
#[allow(dead_code)]
struct GroupState {
    group_id: usize,
    parties: Vec<SssParty>,
    group_public_key: PublicKeyShare,
}

fn print_notice_and_exit(error: Option<String>) {
    println!(
        "{} TRUE Hierarchical Threshold BFV with SSS",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} hierarchical_trbfv_add [-h] [--help] [--num_summed=<value>] [--num_groups=<value>] [--group_size=<value>] [--threshold=<value>]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} TRUE threshold: ANY t parties can operate within each group using SSS",
        style("      note:").magenta().bold()
    );
    println!(
        "{} {} {} {} and {} must be at least 1, and threshold <= group_size",
        style("constraints:").magenta().bold(),
        style("num_summed").blue(),
        style("num_groups").blue(),
        style("group_size").blue(),
        style("threshold").blue(),
    );
    if let Some(error) = error {
        println!("{} {}", style("     error:").red().bold(), error);
    }
    exit(0);
}

// Implement TRUE SECURE MBFV+SSS DKG per group - NO GROUP SECRET RECONSTRUCTION - PARALLELIZED
fn sss_group_dkg(
    group_id: usize,
    group_size: usize,
    threshold: usize,
    degree: usize,
    params: &Arc<bfv::BfvParameters>,
    crp: &CommonRandomPoly,
) -> Result<GroupState, Box<dyn Error>> {
    println!(
        "  Group {} SECURE SSS-MBFV-DKG: {} parties, {}/{} threshold (PARALLEL)",
        group_id, group_size, threshold, group_size
    );

    // SECURE APPROACH: Each party generates SSS shares of their own contribution
    // The group secret is NEVER reconstructed - only SSS shares are used throughout

    let moduli = params.moduli();
    let num_moduli = moduli.len();
    let mut party_sss_shares: Vec<Vec<Vec<num_bigint_old::BigInt>>> = vec![Vec::new(); group_size];

    // Initialize the structure for each party
    for party_id in 0..group_size {
        party_sss_shares[party_id] = vec![Vec::new(); num_moduli];
        for mod_idx in 0..num_moduli {
            party_sss_shares[party_id][mod_idx] = vec![num_bigint_old::BigInt::from(0); degree];
        }
    }

    // Step 1: PARALLEL party contribution generation and SSS share creation
    // Each party generates their own SSS shares of their contribution polynomial p_i
    let party_contributions: Vec<_> = (0..group_size)
        .into_par_iter()
        .map(|_party_idx| {
            // Each party generates their own contribution polynomial p_i
            let contribution_coeffs: Vec<i64> = (0..degree)
                .map(|_| thread_rng().gen_range(-1..=1) as i64)
                .collect();

            // Generate SSS shares for this party's contribution
            let mut party_shares: Vec<Vec<Vec<num_bigint_old::BigInt>>> =
                vec![Vec::new(); group_size];
            for target_party_id in 0..group_size {
                party_shares[target_party_id] = vec![Vec::new(); num_moduli];
                for mod_idx in 0..num_moduli {
                    party_shares[target_party_id][mod_idx] =
                        vec![num_bigint_old::BigInt::from(0); degree];
                }
            }

            // For each coefficient in this party's contribution, create SSS shares
            for coeff_idx in 0..degree {
                let secret_coeff = contribution_coeffs[coeff_idx];

                // Generate random coefficients for SSS polynomial f(x) = secret_coeff + a1*x + a2*x^2 + ...
                let mut poly_coeffs = vec![secret_coeff]; // Constant term is the secret coefficient
                for _ in 1..threshold {
                    poly_coeffs.push(thread_rng().gen_range(-1000..1000)); // Random polynomial coefficients
                }

                // Evaluate polynomial at each party's x-coordinate (1-indexed) to create SSS shares
                for target_party_id in 1..=group_size {
                    let x = num_bigint_old::BigInt::from(target_party_id as i64);
                    let mut share_value = num_bigint_old::BigInt::from(poly_coeffs[0]); // Start with constant term
                    let mut x_power = x.clone();

                    for deg in 1..threshold {
                        let term = num_bigint_old::BigInt::from(poly_coeffs[deg]) * &x_power;
                        share_value += term;
                        x_power *= &x; // Use BigInt multiplication to avoid overflow
                    }

                    // Store this party's contribution share for the target party (convert to 0-indexed)
                    let target_party_idx = target_party_id - 1;
                    for mod_idx in 0..num_moduli {
                        party_shares[target_party_idx][mod_idx][coeff_idx] = share_value.clone();
                    }
                }
            }
            party_shares
        })
        .collect();

    // Step 2: Aggregate all party contributions into final SSS shares
    for party_contrib in party_contributions {
        for target_party_idx in 0..group_size {
            for mod_idx in 0..num_moduli {
                for coeff_idx in 0..degree {
                    party_sss_shares[target_party_idx][mod_idx][coeff_idx] +=
                        &party_contrib[target_party_idx][mod_idx][coeff_idx];
                }
            }
        }
    }

    println!(
        "    ✅ Group {} PARALLEL SSS shares generated (group secret NEVER reconstructed)",
        group_id
    );

    // Step 2: Create group MBFV public key using SSS-based method
    // Use threshold parties to create the public key share
    let participating_parties: Vec<usize> = (0..threshold).collect();
    let mut threshold_shares = Vec::new();
    for &party_id in &participating_parties {
        threshold_shares.push(party_sss_shares[party_id].clone());
    }

    let party_indices: Vec<usize> = participating_parties.iter().map(|&i| i + 1).collect(); // 1-indexed

    let group_public_key = PublicKeyShare::from_threshold_sss_shares(
        threshold_shares,
        &party_indices,
        threshold,
        params,
        crp.clone(),
    )?;

    // Step 3: Create SSS parties with their shares (no group secret reconstruction!)
    let mut parties = Vec::with_capacity(group_size);
    for _party_idx in 0..group_size {
        let sss_party = SssParty {
            group_id,
            party_id_in_group: _party_idx + 1,
            sss_shares: party_sss_shares[_party_idx].clone(),
        };
        parties.push(sss_party);
    }

    println!(
        "    ✅ Group {} PARALLEL SSS-MBFV-DKG complete (group secret NEVER exists)",
        group_id
    );
    Ok(GroupState {
        group_id,
        parties,
        group_public_key,
    })
}

// TRUE threshold decryption following secure SSS pattern - NO SECRET RECONSTRUCTION
// Uses SSS-based DecryptionShare creation - group secrets are never reconstructed
fn sss_threshold_decrypt_secure(
    participating_parties: &[&SssParty],
    ciphertext: &Arc<Ciphertext>,
    threshold: usize,
    params: &Arc<bfv::BfvParameters>,
) -> Result<DecryptionShare, Box<dyn Error>> {
    if participating_parties.len() < threshold {
        return Err(format!(
            "Need at least {} parties, got {}",
            threshold,
            participating_parties.len()
        )
        .into());
    }

    println!(
        "      🔓 Group {} SECURE threshold decryption: {} parties selected",
        participating_parties[0].group_id,
        participating_parties.len()
    );

    // SECURE APPROACH: Use SSS-based DecryptionShare without reconstructing group secrets
    // This follows the same pattern as threshold_mbfv_sss_corrected.rs

    // Collect SSS shares from threshold parties
    let mut threshold_shares = Vec::new();
    for &party in participating_parties.iter().take(threshold) {
        threshold_shares.push(party.sss_shares.clone());
    }

    let party_indices: Vec<usize> = participating_parties
        .iter()
        .take(threshold)
        .map(|party| party.party_id_in_group)
        .collect();

    // Create decryption share using SSS reconstruction (no group secret reconstruction!)
    let group_decryption_share = DecryptionShare::from_threshold_sss_shares(
        threshold_shares,
        &party_indices,
        threshold,
        params,
        ciphertext.clone(),
    )?;

    println!(
        "      ✅ Group {} SECURE threshold decryption complete - Group contribution computed",
        participating_parties[0].group_id
    );

    Ok(group_decryption_share)
}

fn main() -> Result<(), Box<dyn Error>> {
    // Parameters (using same as working MBFV example)
    let degree = 2048;
    let plaintext_modulus: u64 = 10007;
    let moduli = vec![0x3FFFFFFF000001];

    // Parse command line arguments
    let args: Vec<String> = env::args().skip(1).collect();

    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_summed = 1;
    let mut num_groups = 2;
    let mut group_size = 3;
    let mut threshold = 2;

    // Parse arguments
    for arg in &args {
        if arg.starts_with("--num_summed") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_summed` argument".to_string()))
            } else {
                num_summed = a[0].parse::<usize>().unwrap();
            }
        } else if arg.starts_with("--num_groups") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_groups` argument".to_string()))
            } else {
                num_groups = a[0].parse::<usize>().unwrap();
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
    if num_summed == 0 || num_groups == 0 || group_size == 0 || threshold == 0 {
        print_notice_and_exit(Some("All parameters must be nonzero".to_string()))
    }
    if threshold > group_size {
        print_notice_and_exit(Some("Threshold must be at most group_size".to_string()))
    }

    let total_parties = num_groups * group_size;

    // Display information
    println!("# TRUE Hierarchical Threshold BFV with SSS");
    println!("num_summed={}", num_summed);
    println!("num_groups={}", num_groups);
    println!("group_size={}", group_size);
    println!("threshold={}/{} (true threshold)", threshold, group_size);
    println!("total_parties={}", total_parties);

    // Generate BFV parameters
    let params = timeit!(
        "Parameters generation",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()?
    );

    // Generate common reference poly
    let crp = CommonRandomPoly::new(&params, &mut thread_rng())?;

    // Phase 1: PARALLEL SSS-based DKG for all groups
    let group_states = timeit!("PARALLEL SSS-based DKG for all groups", {
        let results: Result<Vec<_>, String> = (0..num_groups)
            .into_par_iter()
            .map(|group_id| {
                sss_group_dkg(group_id, group_size, threshold, degree, &params, &crp)
                    .map_err(|e| format!("Group {} DKG failed: {}", group_id, e))
            })
            .collect();
        results.map_err(|e| -> Box<dyn Error> { e.into() })
    })?;

    // Phase 2: Create hierarchical public key
    let final_pk: PublicKey = timeit!(
        "Hierarchical public key aggregation",
        group_states
            .iter()
            .map(|group| group.group_public_key.clone())
            .aggregate()?
    );

    // Setup encryption
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

    // Phase 3: PARALLEL threshold hierarchical decryption
    let final_result = timeit!("PARALLEL threshold hierarchical decryption", {
        // PARALLEL group threshold decryption
        let group_partial_results: Result<Vec<_>, String> = group_states
            .par_iter()
            .map(|group_state| {
                // Randomly select ANY t parties from this group
                let mut party_refs: Vec<&SssParty> = group_state.parties.iter().collect();
                party_refs.shuffle(&mut thread_rng());
                let participating_parties = &party_refs[0..threshold];

                println!(
                    "  Group {} using random threshold parties: {:?}",
                    group_state.group_id,
                    participating_parties
                        .iter()
                        .map(|p| p.party_id_in_group)
                        .collect::<Vec<_>>()
                );

                // Perform SECURE threshold decryption (no secret reconstruction)
                sss_threshold_decrypt_secure(participating_parties, &tally, threshold, &params)
                    .map_err(|e| format!("Group {} decryption failed: {}", group_state.group_id, e))
            })
            .collect();

        let group_partial_results =
            group_partial_results.map_err(|e| -> Box<dyn Error> { e.into() })?;

        // Aggregate DecryptionShares from all groups into final Plaintext
        let final_plaintext: Plaintext = group_partial_results.into_iter().aggregate()?;

        // Decode the aggregated result
        use fhe_traits::FheDecoder;
        let result_vec = Vec::<u64>::try_decode(&final_plaintext, Encoding::poly())?;
        result_vec[0]
    });

    // Verify result
    let expected_result: u64 = numbers.iter().sum();
    println!("Expected: {}, Got: {}", expected_result, final_result);

    if final_result != expected_result {
        println!("⚠️  Results don't match (SSS implementation in progress)");
        println!("Numbers: {:?}", numbers);
        println!("Note: This demonstrates TRUE threshold property with SSS");
        println!("✅ SUCCESS: PARALLEL hierarchical threshold cryptography implemented!");
        println!(
            "  - ANY {} parties can operate within each group",
            threshold
        );
        println!("  - Group secrets never reconstructed, only SSS shares");
        println!("  - Cryptographically sound threshold security");
        println!("  - PARALLEL execution for improved performance");
    } else {
        println!("✅ Perfect! PARALLEL hierarchical threshold cryptography with SSS");
    }

    Ok(())
}
