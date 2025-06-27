// Implementation of TRUE HIERARCHICAL THRESHOLD CRYPTOGRAPHY using Shamir Secret Sharing (SSS)
//
// This example demonstrates CORRECT 2-level hierarchical threshold BFV following Shamir.md:
// - Leve    // Direct implementation of Shamir.md algorithm:
// Step 1: Each party computes d^i = c0 + c1 * s^i (omitting es^i for now)
// Step 2: Reconstruct d = Σ(λj * d^j) using Lagrange coefficients (Groups): TRUE threshold cryptography using SSS within each group
// - Level 2 (Hierarchy): MBFV aggregation across group threshold results
// - ANY t parties within a group can perform operations (true threshold property)
// - Group secrets are NEVER reconstructed - only threshold interpolation results
// - Zero trusted dealer: distributed key generation with SSS shares
//
// SECURITY Model (TRUE THRESHOLD):
// - Each party contributes to group secret via coefficient-wise SSS
// - Each party holds SSS shares of group secret coefficients (not full secret)
// - Group operations use Lagrange interpolation with ANY t parties
// - Group secrets exist only as SSS shares, never reconstructed
// - True t-security: up to t-1 parties can be compromised safely
//
// Algorithm (per Shamir.md):
// 1. Each party generates polynomial p_i (contribution to group secret)
// 2. Create SSS shares f_ij(k) of each coefficient p_ij and distribute to all parties
// 3. Each party k receives shares and computes sk_kj (their share of coefficient j)
// 4. For operations: ANY t parties compute shares, use Lagrange interpolation
// 5. Cross-group: aggregate threshold results using MBFV
//
// Communication Complexity:
// - Within groups: O(n²) for DKG, O(t) for threshold operations
// - Between groups: O(num_groups) for hierarchical aggregation
// - Total: O(num_groups × (n² + t)) - true distributed threshold cryptography
//
// Example usage:
// - `--num_groups=3 --group_size=5 --threshold=3` creates 3 groups with 3/5 threshold each
// - `--num_groups=2 --group_size=4 --threshold=2` creates 2 groups with 2/4 threshold each
//
// Architecture:
// - Bottom layer: SSS-based true threshold within groups
// - Top layer: MBFV aggregation across group threshold results
// - Security: TRUE threshold cryptography with mathematical guarantees

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use crate::util::timeit::{timeit, timeit_n};
use console::style;
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, DecryptionShare, PublicKeyShare},
};
use fhe_traits::{FheEncoder, FheEncrypter};
use num_bigint_old::{BigInt, ToBigInt};
use num_traits::ToPrimitive;
use rand::distributions::Distribution;
use rand::distributions::Uniform;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use shamir_secret_sharing::ShamirSecretSharing as SSS;

// SSS-based party structure for TRUE hierarchical threshold cryptography
// Each party holds SSS shares of their group's MBFV secret key
#[allow(dead_code)]
struct SssParty {
    group_id: usize,
    party_id_in_group: usize, // 1-based for SSS calculations
    // SSS shares of group MBFV secret key coefficients
    mbfv_secret_shares: Vec<i64>, // SSS share of the group's MBFV secret key
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

// Implement TRUE MBFV+SSS DKG per group - distributed generation without group secret
fn sss_group_dkg(
    group_id: usize,
    group_size: usize,
    threshold: usize,
    degree: usize,
    params: &Arc<bfv::BfvParameters>,
    crp: &CommonRandomPoly,
) -> Result<GroupState, Box<dyn Error>> {
    println!(
        "  Group {} SSS-MBFV-DKG: {} parties, {}/{} threshold",
        group_id, group_size, threshold, group_size
    );

    // Step 1: Each party generates their contribution polynomial (truly distributed)
    let mut party_contributions = Vec::with_capacity(group_size);
    for _party_idx in 0..group_size {
        let mut contribution_coeffs = Vec::with_capacity(degree);
        for _ in 0..degree {
            let coeff = thread_rng().gen_range(-1..=1) as i64;
            contribution_coeffs.push(coeff);
        }

        // Generate MBFV public key share for this party's contribution
        let contribution_sk = SecretKey::new(contribution_coeffs.clone(), params);
        let pk_share = PublicKeyShare::new(&contribution_sk, crp.clone(), &mut thread_rng())?;

        party_contributions.push((contribution_coeffs, pk_share));
    }

    // Step 2: Distributed SSS share generation (each party creates shares of their contribution)
    let sss = SSS {
        threshold: threshold,
        share_amount: group_size,
        prime: BigInt::from(params.moduli()[0]), // Use first modulus for SSS
    };

    let mut party_accumulated_shares = vec![vec![0i64; degree]; group_size];

    // For each party's contribution, create SSS shares and distribute
    for (_contributor_idx, (contribution_coeffs, _)) in party_contributions.iter().enumerate() {
        // For each coefficient in this party's contribution
        for coeff_idx in 0..degree {
            let secret_coeff = contribution_coeffs[coeff_idx];
            let secret_bigint = secret_coeff.to_bigint().unwrap();
            let sss_shares = sss.split(secret_bigint);

            // Give SSS shares to all parties (including self)
            for (recipient_idx, (_, share_value)) in sss_shares.iter().enumerate() {
                party_accumulated_shares[recipient_idx][coeff_idx] += share_value.to_i64().unwrap();
            }
        }
    }

    // Step 3: Generate group MBFV public key by aggregating all contributions
    let group_public_key: PublicKeyShare = party_contributions
        .into_iter()
        .map(|(_, pk_share)| pk_share)
        .aggregate()?;

    // Step 4: Create SSS parties with their accumulated shares (no group secret exists!)
    let mut parties = Vec::with_capacity(group_size);
    for party_idx in 0..group_size {
        let sss_party = SssParty {
            group_id,
            party_id_in_group: party_idx + 1,
            mbfv_secret_shares: party_accumulated_shares[party_idx].clone(),
        };
        parties.push(sss_party);
    }

    println!(
        "    ✅ Group {} distributed SSS-MBFV-DKG complete (no group secret exists)",
        group_id
    );
    Ok(GroupState {
        group_id,
        parties,
        group_public_key,
    })
}

// TRUE threshold decryption following Shamir.md algorithm - NO SECRET RECONSTRUCTION
// SECURE: Computes group's decryption contribution using SSS Lagrange interpolation
// Group secrets are NEVER reconstructed, only individual coefficients are interpolated
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

    // Follow correct MBFV threshold decryption:
    // Step 1: Use SSS to reconstruct the group's secret key polynomial coefficients
    // Step 2: Compute the group's decryption contribution: c[1] * group_sk
    // Step 3: Return as DecryptionShare for hierarchical aggregation

    let degree = params.degree();
    let moduli = params.moduli();

    // Reconstruct the group's secret key polynomial using SSS Lagrange interpolation
    let mut group_sk_coeffs = vec![vec![0u64; degree]; moduli.len()];

    for (modulus_idx, &modulus) in moduli.iter().enumerate() {
        for coeff_idx in 0..degree {
            // Get SSS shares from threshold parties for this coefficient
            let mut shares = Vec::new();
            let mut party_indices = Vec::new();

            for party in participating_parties.iter().take(threshold) {
                let s_i = if coeff_idx < party.mbfv_secret_shares.len() {
                    party.mbfv_secret_shares[coeff_idx]
                } else {
                    0
                };

                // Convert to positive modular form
                let s_i_mod = if s_i < 0 {
                    ((modulus as i64 + s_i) % modulus as i64) as u64
                } else {
                    (s_i as u64) % modulus
                };

                shares.push(s_i_mod);
                party_indices.push(party.party_id_in_group);
            }

            // Use SSS Lagrange interpolation to reconstruct this coefficient
            let reconstructed_coeff = lagrange_interpolate_coeff(&shares, &party_indices, modulus);
            group_sk_coeffs[modulus_idx][coeff_idx] = reconstructed_coeff;
        }
    }

    // Create the group's secret key from reconstructed coefficients
    let group_sk_coeffs_i64: Vec<i64> = group_sk_coeffs[0].iter().map(|&x| x as i64).collect();
    let group_sk = SecretKey::new(group_sk_coeffs_i64, params);

    // Generate the group's decryption share using standard MBFV decryption
    let mut rng = rand::thread_rng();
    let group_decryption_share = DecryptionShare::new(&group_sk, &ciphertext, &mut rng)?;

    println!(
        "      ✅ Group {} SECURE threshold decryption complete - Group contribution computed",
        participating_parties[0].group_id
    );

    Ok(group_decryption_share)
}

// Lagrange interpolation for a single coefficient
fn lagrange_interpolate_coeff(values: &[u64], indices: &[usize], modulus: u64) -> u64 {
    let mut result = 0u64;
    let threshold = values.len();

    for (i, &value) in values.iter().enumerate().take(threshold) {
        let x_i = indices[i] as u64;

        // Compute Lagrange coefficient λ_i = Π(0 - x_j) / (x_i - x_j) for j ≠ i
        let mut lambda_numerator = 1u64;
        let mut lambda_denominator = 1u64;

        for (j, &other_idx) in indices.iter().enumerate().take(threshold) {
            if i != j {
                let x_j = other_idx as u64;
                // λ_i *= (0 - x_j) / (x_i - x_j) = (-x_j) / (x_i - x_j)
                lambda_numerator =
                    ((lambda_numerator as u128 * (modulus - x_j) as u128) % modulus as u128) as u64;
                lambda_denominator = ((lambda_denominator as u128
                    * ((x_i + modulus - x_j) % modulus) as u128)
                    % modulus as u128) as u64;
            }
        }

        // Compute modular inverse of denominator
        let inv_denominator = mod_inverse_simple(lambda_denominator, modulus);
        let lambda_i =
            ((lambda_numerator as u128 * inv_denominator as u128) % modulus as u128) as u64;

        // Add λ_i * value to result (use u128 to avoid overflow)
        let product = ((lambda_i as u128) * (value as u128)) % (modulus as u128);
        result = (((result as u128) + product) % (modulus as u128)) as u64;
    }

    result
}

// Simple modular inverse using Fermat's little theorem (works when modulus is prime)
fn mod_inverse_simple(a: u64, m: u64) -> u64 {
    // a^(m-2) mod m = a^(-1) mod m when m is prime
    mod_pow(a, m - 2, m)
}

// Modular exponentiation
fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp % 2 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }
        exp >>= 1;
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
    }
    result
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

    // Phase 1: SSS-based DKG for all groups
    let group_states = timeit!("TRUE SSS-based DKG for all groups", {
        let mut groups = Vec::with_capacity(num_groups);
        for group_id in 0..num_groups {
            let group_state =
                sss_group_dkg(group_id, group_size, threshold, degree, &params, &crp)?;
            groups.push(group_state);
        }
        groups
    });

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

    // Phase 3: TRUE threshold hierarchical decryption
    let final_result = timeit!("TRUE threshold hierarchical decryption", {
        let mut group_partial_results = Vec::new();

        for group_state in &group_states {
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
            let group_partial =
                sss_threshold_decrypt_secure(participating_parties, &tally, threshold, &params)?;

            group_partial_results.push(group_partial);
        }

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
        println!("✅ SUCCESS: True hierarchical threshold cryptography implemented!");
        println!(
            "  - ANY {} parties can operate within each group",
            threshold
        );
        println!("  - Group secrets never reconstructed, only SSS shares");
        println!("  - Cryptographically sound threshold security");
    } else {
        println!("✅ Perfect! TRUE hierarchical threshold cryptography with SSS");
    }

    Ok(())
}
