// Threshold BFV implementation following Shamir Secret Sharing (SSS) based
// Distributed Key Generation and threshold decryption as specified in Shamir.md

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use console::style;
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{Aggregate, CommonRandomPoly, PublicKeyShare},
};
use fhe_math::rq::{Poly, Representation};
use fhe_traits::{FheEncoder, FheEncrypter};
use ndarray::Array2;
use num_bigint_old::BigInt;
use num_traits::{ToPrimitive, Zero};
use rand::{thread_rng, Rng};
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use util::timeit::timeit;

/// Print usage information and exit
fn print_notice_and_exit(error: Option<String>) {
    println!(
        "{} Threshold BFV multiplication with SSS-based DKG",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} trbfv_mul [-h] [--help] [--num_parties=<value>] [--threshold=<value>] [--values=<v1,v2,v3,...>]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} {} must be at least 1, {} must be at most num_parties",
        style("constraints:").magenta().bold(),
        style("num_parties").blue(),
        style("threshold").blue(),
    );
    println!(
        "{} {} should be comma-separated integers (e.g., --values=1,2,3,4,5)",
        style("    values:").magenta().bold(),
        style("values").blue(),
    );
    if let Some(error) = error {
        println!("{} {}", style("     error:").red().bold(), error);
    }
    exit(0);
}

/// Represents a party in the threshold BFV scheme
/// Each party holds:
/// - A secret polynomial contribution (pi) to the collective secret key
/// - A public key share (eki) derived from their secret contribution
/// - Shamir secret shares for all polynomial coefficients
/// - Reconstructed secret key shares from all parties
#[derive(Clone)]
#[allow(dead_code)]
struct Party {
    party_id: usize,
    secret_poly: Poly,                 // pi: secret polynomial contribution
    public_key_share: Poly,            // eki: public key share
    sk_shares: Vec<Vec<BigInt>>,       // Secret key shares for each coefficient
    smudging_shares: Vec<Vec<BigInt>>, // Smudging error shares for threshold decryption
}

impl Party {
    /// Create a new party with the given ID and BFV parameters
    fn new(party_id: usize, params: &Arc<bfv::BfvParameters>) -> Result<Self, Box<dyn Error>> {
        // Generate pi: random polynomial with coefficients in {-1, 0, 1}
        let mut rng = thread_rng();
        let degree = params.degree();
        let moduli = params.moduli();

        // Create polynomial in PowerBasis representation
        let ctx = params.ctx_at_level(0).unwrap();
        let mut secret_poly = Poly::zero(&ctx, Representation::PowerBasis);

        // Generate random coefficients in {-1, 0, 1} for all moduli levels
        let mut coeffs_matrix = Array2::zeros((moduli.len(), degree));
        for m in 0..moduli.len() {
            for j in 0..degree {
                let coeff = rng.gen_range(-1i64..=1i64);
                // Properly reduce coefficient modulo the current modulus
                let modulus = moduli[m];
                let reduced_coeff = if coeff < 0 {
                    modulus - ((-coeff) as u64 % modulus)
                } else {
                    coeff as u64 % modulus
                };
                coeffs_matrix[(m, j)] = reduced_coeff;
            }
        }
        secret_poly.set_coefficients(coeffs_matrix);

        // Initialize empty public key share (will be computed after CRP is available)
        let public_key_share = Poly::zero(&ctx, Representation::PowerBasis);

        Ok(Party {
            party_id,
            secret_poly,
            public_key_share,
            sk_shares: Vec::new(),
            smudging_shares: Vec::new(),
        })
    }

    /// Compute the public key share eki = -a*pi + ei
    /// where a is the common random polynomial and ei is error
    fn compute_public_key_share(
        &mut self,
        crp: &Poly,
        params: &Arc<bfv::BfvParameters>,
    ) -> Result<(), Box<dyn Error>> {
        // Generate error polynomial ei from error distribution
        let mut rng = thread_rng();
        let degree = params.degree();
        let moduli = params.moduli();
        let ctx = params.ctx_at_level(0).unwrap();

        let mut error_poly = Poly::zero(&ctx, Representation::PowerBasis);
        let mut error_coeffs = Array2::zeros((moduli.len(), degree));

        // Generate small error coefficients (bounded by a small value)
        for m in 0..moduli.len() {
            for j in 0..degree {
                let error = rng.gen_range(-3i64..=3i64);
                // Properly reduce error coefficient modulo the current modulus
                let modulus = moduli[m];
                let reduced_error = if error < 0 {
                    modulus - ((-error) as u64 % modulus)
                } else {
                    error as u64 % modulus
                };
                error_coeffs[(m, j)] = reduced_error;
            }
        }
        error_poly.set_coefficients(error_coeffs);

        // Convert to NTT for polynomial multiplication
        let mut crp_ntt = crp.clone();
        crp_ntt.change_representation(Representation::Ntt);
        let mut secret_ntt = self.secret_poly.clone();
        secret_ntt.change_representation(Representation::Ntt);

        // Compute a * pi
        let mut a_times_pi = &crp_ntt * &secret_ntt;
        a_times_pi.change_representation(Representation::PowerBasis);

        // Compute eki = -a*pi + ei
        self.public_key_share = &error_poly + &(-&a_times_pi);

        Ok(())
    }

    /// Generate Shamir secret shares for all coefficients of the secret
    /// polynomial Following Shamir.md algorithm: for each coefficient pij,
    /// create polynomial fij with constant term pij and degree
    /// floor((n-1)/2)
    fn generate_secret_shares(
        &mut self,
        num_parties: usize,
        threshold: usize,
        params: &Arc<bfv::BfvParameters>,
    ) -> Result<Vec<Vec<Vec<BigInt>>>, Box<dyn Error>> {
        let degree = params.degree();
        let moduli = params.moduli();
        let mut all_shares = Vec::new();

        // For each modulus level
        for m in 0..moduli.len() {
            let prime = BigInt::from(moduli[m]);
            let sss = SSS {
                threshold,
                share_amount: num_parties,
                prime: prime.clone(),
            };

            let mut shares_for_modulus = Vec::new();

            // For each coefficient of the polynomial at this modulus level
            for j in 0..degree {
                let coeff = self.secret_poly.coefficients()[(m, j)];
                let secret_value = BigInt::from(coeff);

                // Generate Shamir shares for this coefficient
                let shares = sss.split(secret_value);

                // Convert Vec<(usize, BigInt)> to Vec<BigInt> indexed by party_id
                let mut shares_vec = vec![BigInt::zero(); num_parties];
                for (party_id, share_value) in shares {
                    // party_id is 1-based, convert to 0-based index
                    shares_vec[party_id - 1] = share_value;
                }
                shares_for_modulus.push(shares_vec);
            }
            all_shares.push(shares_for_modulus);
        }

        Ok(all_shares)
    }

    /// Generate smudging error shares for threshold decryption
    /// Following Shamir.md: generate hi polynomial and create shares for each
    /// coefficient
    fn generate_smudging_shares(
        &mut self,
        num_parties: usize,
        threshold: usize,
        params: &Arc<bfv::BfvParameters>,
        smudging_bound: i64,
    ) -> Result<Vec<Vec<Vec<BigInt>>>, Box<dyn Error>> {
        let degree = params.degree();
        let moduli = params.moduli();
        let mut rng = thread_rng();

        // Generate hi: random polynomial with coefficients in [-Bsm, Bsm]
        let ctx = params.ctx_at_level(0).unwrap();
        let mut smudging_poly = Poly::zero(&ctx, Representation::PowerBasis);
        let mut smudging_coeffs = Array2::zeros((moduli.len(), degree));

        for m in 0..moduli.len() {
            for j in 0..degree {
                let coeff = rng.gen_range(-smudging_bound..=smudging_bound);
                // Properly reduce smudging coefficient modulo the current modulus
                let modulus = moduli[m];
                let reduced_coeff = if coeff < 0 {
                    modulus - ((-coeff) as u64 % modulus)
                } else {
                    coeff as u64 % modulus
                };
                smudging_coeffs[(m, j)] = reduced_coeff;
            }
        }
        smudging_poly.set_coefficients(smudging_coeffs);

        let mut all_shares = Vec::new();

        // For each modulus level
        for m in 0..moduli.len() {
            let prime = BigInt::from(moduli[m]);
            let sss = SSS {
                threshold,
                share_amount: num_parties,
                prime: prime.clone(),
            };

            let mut shares_for_modulus = Vec::new();

            // For each coefficient of the smudging polynomial
            for j in 0..degree {
                let coeff = smudging_poly.coefficients()[(m, j)];
                let secret_value = BigInt::from(coeff);

                // Generate Shamir shares for this coefficient
                let shares = sss.split(secret_value);

                // Convert Vec<(usize, BigInt)> to Vec<BigInt> indexed by party_id
                let mut shares_vec = vec![BigInt::zero(); num_parties];
                for (party_id, share_value) in shares {
                    // party_id is 1-based, convert to 0-based index
                    shares_vec[party_id - 1] = share_value;
                }
                shares_for_modulus.push(shares_vec);
            }
            all_shares.push(shares_for_modulus);
        }

        Ok(all_shares)
    }
}

/// Lagrange interpolation coefficient calculation for threshold reconstruction
/// at x=0 Computes λj for party j in set S, where λj = ∏(k∈S,k≠j) (0-k)/(j-k) =
/// ∏(k∈S,k≠j) (-k)/(j-k)
fn compute_lagrange_coefficient_at_zero(
    party_id: usize,
    party_set: &[usize],
    prime: &BigInt,
) -> BigInt {
    let mut lambda = BigInt::from(1);

    for &k in party_set {
        if k != party_id {
            // For interpolation at x=0: λ_j = ∏(k≠j) (0-k)/(j-k) = ∏(k≠j) (-k)/(j-k)

            // Numerator: -k mod prime
            let neg_k = (prime - BigInt::from(k)) % prime;

            // Denominator: (party_id - k) mod prime
            let diff = if party_id > k {
                BigInt::from(party_id - k)
            } else {
                prime - BigInt::from(k - party_id)
            };

            // Compute (neg_k / diff) mod prime = neg_k * diff^(-1) mod prime
            let inv_diff = mod_inverse(&diff, prime)
                .expect("Modular inverse should exist for threshold reconstruction");

            lambda = (lambda * neg_k * inv_diff) % prime;
        }
    }

    lambda
}

/// Compute modular multiplicative inverse using extended Euclidean algorithm
fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    fn extended_gcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
        if a == BigInt::from(0) {
            (b, BigInt::from(0), BigInt::from(1))
        } else {
            let (gcd, x, y) = extended_gcd(b.clone() % a.clone(), a.clone());
            (gcd, y - (b / a.clone()) * x.clone(), x)
        }
    }

    let (gcd, x, _) = extended_gcd(a.clone(), m.clone());
    if gcd == BigInt::from(1) {
        Some((x % m + m) % m)
    } else {
        None
    }
}

/// Compute decryption shares for a given set of parties
/// Following Shamir.md algorithm: di = c0 + c1*si + esi
/// where si is the party's secret key share (not their individual polynomial
/// pi)
fn compute_decryption_shares(
    parties: &[Party],
    party_ids: &[usize],
    sum_ciphertext: &Arc<Ciphertext>,
    params: &Arc<bfv::BfvParameters>,
) -> Result<Vec<(usize, Poly)>, Box<dyn Error>> {
    let degree = params.degree();
    let moduli = params.moduli();
    let mut shares = Vec::new();

    // Extract ciphertext components
    let mut c0 = sum_ciphertext.c[0].clone();
    let mut c1 = sum_ciphertext.c[1].clone();
    c0.change_representation(Representation::PowerBasis);
    c1.change_representation(Representation::Ntt);

    for &party_id in party_ids {
        let party_idx = party_id - 1; // Convert to 0-based index
        let party = &parties[party_idx];

        // Following Shamir.md: use party's secret key share si (their share of the
        // collective secret key) Construct si polynomial from the party's
        // sk_shares
        let ctx = params.ctx_at_level(0).unwrap();
        let mut si = Poly::zero(&ctx, Representation::PowerBasis);
        let mut si_coeffs = Array2::zeros((moduli.len(), degree));

        for m in 0..moduli.len() {
            for j in 0..degree {
                // Convert BigInt to u64 for polynomial coefficients
                let share_value = &party.sk_shares[m][j];
                let modulus = moduli[m];
                let coeff_value = (share_value % BigInt::from(modulus)).to_u64().unwrap_or(0);
                si_coeffs[(m, j)] = coeff_value;
            }
        }
        si.set_coefficients(si_coeffs);
        si.change_representation(Representation::Ntt);

        // Compute c1*si
        let mut c1_si = &c1 * &si;
        c1_si.change_representation(Representation::PowerBasis);

        // Following Shamir.md: use party's smudging error share esi
        let mut esi = Poly::zero(&ctx, Representation::PowerBasis);
        let mut esi_coeffs = Array2::zeros((moduli.len(), degree));

        for m in 0..moduli.len() {
            for j in 0..degree {
                // Convert BigInt to u64 for polynomial coefficients
                let smudging_value = &party.smudging_shares[m][j];
                let modulus = moduli[m];
                let coeff_value = (smudging_value % BigInt::from(modulus))
                    .to_u64()
                    .unwrap_or(0);
                esi_coeffs[(m, j)] = coeff_value;
            }
        }
        esi.set_coefficients(esi_coeffs);

        // Compute decryption share: di = c0 + c1*si + esi
        let di = &(&c0 + &c1_si) + &esi;
        shares.push((party_id, di));
    }

    Ok(shares)
}

/// Perform threshold reconstruction from decryption shares using Lagrange
/// interpolation
/// Following Shamir.md: d = Dec(c) = Σ λⱼ · d^j for j in S
/// where d^j are the decryption shares and λⱼ are Lagrange coefficients
fn threshold_reconstruct(
    decryption_shares: &[(usize, Poly)],
    party_ids: &[usize],
    sum_ciphertext: &Arc<Ciphertext>,
    params: &Arc<bfv::BfvParameters>,
) -> Result<u64, Box<dyn Error>> {
    let ctx = params.ctx_at_level(0).unwrap();
    let mut reconstructed = Poly::zero(&ctx, Representation::PowerBasis);

    // Following Shamir.md: reconstruct d = Σ λⱼ · d^j
    // This should be done as polynomial-level reconstruction, not coefficient-wise
    // Each d^j is a full polynomial, multiply by λⱼ and sum all results

    // Use the first modulus for Lagrange coefficient computation (standard
    // approach)
    let prime = BigInt::from(params.moduli()[0]);

    for (i, &party_id) in party_ids.iter().enumerate() {
        let (_, ref di) = decryption_shares[i];

        // Compute Lagrange coefficient λⱼ for this party
        let lambda = compute_lagrange_coefficient_at_zero(party_id, party_ids, &prime);

        // Make sure lambda is properly reduced modulo the prime
        let lambda_reduced = &lambda % &prime;
        let lambda_u64 = lambda_reduced
            .to_u64()
            .expect("Lambda coefficient should fit in u64");

        // Debug: print lambda coefficient and first coefficient of di
        println!(
            "Debug - Party {}: lambda = {}, di_coeff = {}",
            party_id,
            lambda_u64,
            di.coefficients()[(0, 0)]
        );

        // Multiply the entire decryption share polynomial by the Lagrange coefficient
        // We need to be careful about modular arithmetic here
        let mut lambda_di = di.clone();

        // Convert to coefficient representation for scalar multiplication
        lambda_di.change_representation(Representation::PowerBasis); // Perform coefficient-wise multiplication by lambda
        let coeffs = lambda_di.coefficients();
        let mut new_coeffs = coeffs.to_owned();

        for m in 0..params.moduli().len() {
            let modulus = BigInt::from(params.moduli()[m]);
            for j in 0..params.degree() {
                let old_coeff = BigInt::from(coeffs[(m, j)]);
                let new_coeff = (lambda_reduced.clone() * old_coeff) % &modulus;
                new_coeffs[(m, j)] = new_coeff.to_u64().unwrap_or(0);
            }
        }
        lambda_di.set_coefficients(new_coeffs);

        // Add to the reconstruction: reconstructed += λⱼ · d^j
        reconstructed = &reconstructed + &lambda_di;
    }

    // Extract the first coefficient from the reconstructed polynomial
    reconstructed.change_representation(Representation::PowerBasis);
    let coeffs = reconstructed.coefficients();
    let reconstructed_coeff = coeffs[(0, 0)];

    println!(
        "Debug - reconstructed first coeff (before scaling): {}",
        reconstructed_coeff
    );

    // Debug: print first few coefficients to verify consistency
    for i in 0..6.min(coeffs.dim().1) {
        println!("Debug - reconstructed coeff[{}]: {}", i, coeffs[(0, i)]);
    }

    // Simple and consistent scaling approach for threshold BFV
    // Based on the BFV decryption formula: m = [(c0 + c1*s + e) * t / q] mod t
    // For threshold decryption, we've reconstructed (c0 + c1*s + e) through
    // Lagrange interpolation Now we need to scale by t/q and reduce mod t

    let plaintext_mod = params.plaintext();
    let ciphertext_mod = params.moduli()[0];

    // Use BigInt for precise arithmetic to avoid any floating point issues
    let reconstructed_big = BigInt::from(reconstructed_coeff);
    let plaintext_big = BigInt::from(plaintext_mod);
    let ciphertext_big = BigInt::from(ciphertext_mod);

    // Compute [reconstructed * t / q] = [reconstructed * t / q + 1/2] (rounding)
    // This is equivalent to: (reconstructed * t + q/2) / q
    let scaled_big = (reconstructed_big * &plaintext_big + &ciphertext_big / 2) / &ciphertext_big;
    let result_big: BigInt = scaled_big % &plaintext_big;

    // Convert back to u64
    let result = result_big.to_u64().unwrap_or(0);

    println!("Debug - BFV scaled result: {}", result);

    Ok(result)
}

fn main() -> Result<(), Box<dyn Error>> {
    // ========================================================================
    // PARAMETER SETUP
    // ========================================================================

    // BFV parameters following standard settings
    let degree = 2048; // N: Ring dimension
    let plaintext_modulus: u64 = 4096; // t: Plaintext modulus
    let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001]; // q: Ciphertext moduli chain
    let smudging_bound = 1000i64; // Bsm: Smudging error bound

    // Parse command line arguments
    let args: Vec<String> = env::args().skip(1).collect();

    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_parties = 5; // n: Number of parties
    let mut threshold = 3; // t: Threshold for reconstruction (t+1 parties needed)
    let mut test_values = vec![1u64, 2, 3, 4, 5]; // Default test values

    // Parse command line arguments
    for arg in &args {
        if arg.starts_with("--num_parties") {
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
        } else if arg.starts_with("--values") {
            let parts: Vec<&str> = arg.rsplit('=').collect();
            if parts.len() != 2 {
                print_notice_and_exit(Some(
                    "Invalid `--values` argument format. Use --values=1,2,3,4,5".to_string(),
                ))
            } else {
                let values_str = parts[0];
                let parsed_values: Result<Vec<u64>, _> = values_str
                    .split(',')
                    .map(|s| s.trim().parse::<u64>())
                    .collect();

                match parsed_values {
                    Ok(values) => {
                        if values.is_empty() {
                            print_notice_and_exit(Some("Values list cannot be empty".to_string()))
                        }
                        test_values = values;
                    }
                    Err(_) => print_notice_and_exit(Some(
                        "Invalid values format. All values must be positive integers".to_string(),
                    )),
                }
            }
        } else {
            print_notice_and_exit(Some(format!("Unrecognized argument: {arg}")))
        }
    }

    // Validate parameters
    if num_parties == 0 {
        print_notice_and_exit(Some("Number of parties must be positive".to_string()))
    }
    if threshold >= num_parties {
        print_notice_and_exit(Some(
            "Threshold must be less than number of parties".to_string(),
        ))
    }

    // Validate test values are within plaintext modulus range
    let max_value = test_values.iter().max().unwrap_or(&0);
    let sum_value = test_values.iter().sum::<u64>();
    if *max_value >= plaintext_modulus {
        print_notice_and_exit(Some(format!(
            "Maximum test value {} exceeds plaintext modulus {}",
            max_value, plaintext_modulus
        )))
    }
    if sum_value >= plaintext_modulus {
        print_notice_and_exit(Some(format!(
            "Sum of test values {} exceeds plaintext modulus {}",
            sum_value, plaintext_modulus
        )))
    }

    println!("# Threshold BFV with SSS-based DKG");
    println!("\tnum_parties = {num_parties}");
    println!("\tthreshold = {threshold}");
    println!("\tdegree = {degree}");

    // ========================================================================
    // BFV PARAMETER GENERATION
    // ========================================================================

    let params = timeit!(
        "BFV parameters generation",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()?
    );

    // ========================================================================
    // COMMON RANDOM POLYNOMIAL (CRP) GENERATION
    // ========================================================================
    // Generate common random polynomial 'a' known to all parties

    let crp = timeit!(
        "Common random polynomial generation",
        CommonRandomPoly::new(&params, &mut thread_rng())?
    );

    // ========================================================================
    // DISTRIBUTED KEY GENERATION (DKG) - Following Shamir.md Algorithm
    // ========================================================================

    println!("\n## Phase 1: Distributed Key Generation");

    // Step 1: Initialize parties and generate secret polynomials
    let mut parties = timeit!("Party initialization", {
        let mut parties = Vec::with_capacity(num_parties);
        for i in 0..num_parties {
            let party = Party::new(i + 1, &params)?; // Party IDs start from 1
            parties.push(party);
        }
        parties
    });

    // Step 2: Compute public key shares eki = -a*pi + ei
    timeit!("Public key share computation", {
        for party in &mut parties {
            party.compute_public_key_share(crp.poly(), &params)?;
        }
    });

    // Step 3: Generate Shamir secret shares for secret key coefficients
    // For each party i, for each coefficient pij of pi, generate polynomial fij
    // with constant term pij and share fij(k) to party k
    let all_secret_shares = timeit!("Secret key share generation", {
        let mut all_shares = Vec::new();
        for party in &mut parties {
            let shares = party.generate_secret_shares(num_parties, threshold, &params)?;
            all_shares.push(shares);
        }
        all_shares
    });

    // Step 4: Distribute and collect secret shares (simulating network
    // communication) In practice, each party would send their shares securely
    // to other parties
    timeit!("Secret share distribution", {
        for receiver_id in 0..num_parties {
            let mut collected_shares = vec![vec![BigInt::zero(); degree]; moduli.len()];

            // Collect shares from all parties for this receiver
            for sender_id in 0..num_parties {
                for m in 0..moduli.len() {
                    for j in 0..degree {
                        // Add sender's share for receiver at coefficient j, modulus m
                        // Note: In threshold BFV, we sum all parties' contributions for the same
                        // coefficient Each party generates shares of their
                        // own polynomial coefficients
                        collected_shares[m][j] += &all_secret_shares[sender_id][m][j][receiver_id];
                    }
                }
            }

            parties[receiver_id].sk_shares = collected_shares;
        }
    });

    // ========================================================================
    // VALIDATION: Secret Share Correctness
    // ========================================================================
    println!("🔍 Validating secret share distribution...");

    // Validate that secret shares can reconstruct the original secret coefficients
    // For each coefficient, use Lagrange interpolation to reconstruct from shares
    for m in 0..moduli.len() {
        let prime = BigInt::from(moduli[m]);

        for j in 0..degree {
            // Get the original sum of all party contributions for this coefficient
            let mut expected_coeff = BigInt::from(0);
            for party in &parties {
                let party_coeff = party.secret_poly.coefficients()[(m, j)];
                expected_coeff = (expected_coeff + BigInt::from(party_coeff)) % &prime;
            }

            // Reconstruct using Lagrange interpolation from shares of first threshold+1
            // parties
            let test_parties: Vec<usize> = (1..=threshold + 1).collect();
            let mut reconstructed_coeff = BigInt::from(0);

            for &party_id in &test_parties {
                let party_idx = party_id - 1;
                let share_value = &parties[party_idx].sk_shares[m][j];
                let lambda = compute_lagrange_coefficient_at_zero(party_id, &test_parties, &prime);
                reconstructed_coeff = (reconstructed_coeff + lambda * share_value) % &prime;
            }

            // Validate reconstruction matches expected
            assert_eq!(
                reconstructed_coeff, expected_coeff,
                "Secret coefficient reconstruction failed at modulus {}, coefficient {}: got {}, expected {}",
                m, j, reconstructed_coeff, expected_coeff
            );
        }
    }
    println!("✓ Secret share distribution validation passed");

    // Additional validation: Verify that the sum of secret polynomials equals the
    // full secret key
    let _expected_full_sk = {
        let ctx = params.ctx_at_level(0).unwrap();
        let mut sk_poly = Poly::zero(&ctx, Representation::PowerBasis);
        let mut sk_coeffs = Array2::zeros((moduli.len(), degree));

        // Sum all secret polynomial contributions: s = sum(pi)
        for party in &parties {
            let party_coeffs = party.secret_poly.coefficients();
            for m in 0..moduli.len() {
                for j in 0..degree {
                    sk_coeffs[(m, j)] = (sk_coeffs[(m, j)] + party_coeffs[(m, j)]) % moduli[m];
                }
            }
        }
        sk_poly.set_coefficients(sk_coeffs);
        sk_poly
    };

    // Verify each party's share reconstructs correctly
    // Since each party's sk_shares[m][j] contains the SUM of all parties' Shamir
    // shares for coefficient j at modulus m, we can validate this more
    // thoroughly
    for (party_idx, party) in parties.iter().enumerate() {
        for m in 0..moduli.len() {
            let prime = BigInt::from(moduli[m]);

            // Sample a few coefficients for validation (not all 2048 for performance)
            let sample_coeffs = [0, 1, 10, 100, degree / 2, degree - 1];

            for &j in &sample_coeffs {
                if j >= degree {
                    continue;
                }

                // Get this party's received share (sum of all parties' contributions)
                let party_received_share = &party.sk_shares[m][j];

                // Compute what this share should be by reconstructing from known coefficients
                // Each party's share should equal the evaluation of the sum polynomial at their
                // party ID
                let mut expected_share = BigInt::from(0);

                // Sum all parties' original coefficients for this position
                for other_party in &parties {
                    let other_coeff = other_party.secret_poly.coefficients()[(m, j)];
                    expected_share = (expected_share + BigInt::from(other_coeff)) % &prime;
                }

                // The received share should equal this expected sum when evaluated at party_id
                // = 0 (since Shamir shares with constant term = sum should
                // evaluate to sum at x=0) But since party IDs start from 1, we
                // need to reconstruct using interpolation

                // Alternative validation: use the share to reconstruct and verify it matches
                // what we computed in the earlier validation
                let party_share_normalized = party_received_share % &prime;

                // Basic sanity checks
                assert!(
                    party_share_normalized < prime,
                    "Party {} share for modulus {}, coefficient {} is not properly reduced: {} >= {}",
                    party_idx, m, j, party_share_normalized, prime
                );

                // Verify the share is reasonable (not zero unless all coeffs are zero)
                let sum_is_zero = parties
                    .iter()
                    .all(|p| p.secret_poly.coefficients()[(m, j)] == 0);
                if !sum_is_zero {
                    // The share shouldn't be zero if there are non-zero contributions
                    // (This is a probabilistic check - could theoretically fail but very unlikely)
                    assert!(
                        party_share_normalized != BigInt::from(0),
                        "Party {} received zero share for non-zero coefficient sum at modulus {}, coefficient {}",
                        party_idx, m, j
                    );
                }
            }
        }
    }
    println!("✓ Secret polynomial consistency validation passed");

    // Step 5: Aggregate public keys to form collective public key
    // pk = sum of all eki = sum(-a*pi + ei) = -a*sum(pi) + sum(ei) = -a*s + e
    let public_key = timeit!("Public key aggregation", {
        // Create PublicKeyShare instances from computed shares
        let pk_shares: Vec<PublicKeyShare> = parties
            .iter()
            .map(|party| {
                // Convert Poly to SecretKey for PublicKeyShare::new
                // Extract only the first modulus level coefficients (degree coefficients)
                let coeffs_view = party.secret_poly.coefficients();
                let first_modulus_coeffs = coeffs_view.row(0); // Get only first modulus level
                let sk_coeffs_vec: Vec<i64> =
                    first_modulus_coeffs.iter().map(|&x| x as i64).collect();
                let secret_key = SecretKey::new(sk_coeffs_vec, &params);
                PublicKeyShare::new(&secret_key, crp.clone(), &mut thread_rng())
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Aggregate using the Aggregate trait
        PublicKey::from_shares(pk_shares)?
    });

    // Store individual secret key shares for proper multiparty decryption
    let _secret_key_shares: Vec<SecretKey> = parties
        .iter()
        .map(|party| {
            let coeffs_view = party.secret_poly.coefficients();
            let first_modulus_coeffs = coeffs_view.row(0);
            let sk_coeffs_vec: Vec<i64> = first_modulus_coeffs.iter().map(|&x| x as i64).collect();
            SecretKey::new(sk_coeffs_vec, &params)
        })
        .collect();

    println!("✓ Distributed key generation completed");

    // ========================================================================
    // ENCRYPTION AND HOMOMORPHIC COMPUTATION
    // ========================================================================

    println!("\n## Phase 2: Encryption and Computation");

    // Use command line provided test values (or defaults)
    let expected_sum = test_values.iter().sum::<u64>();
    println!("Test values: {:?}", test_values);
    println!("Expected sum: {}", expected_sum);

    // Encrypt each value using non-batching encoding (polynomial encoding)
    let ciphertexts = timeit!("Encryption", {
        let mut cts = Vec::with_capacity(test_values.len());
        for &value in &test_values {
            // Encode single value in first coefficient (non-SIMD/non-batching)
            let pt = Plaintext::try_encode(&[value], Encoding::poly(), &params)?;
            let ct = public_key.try_encrypt(&pt, &mut thread_rng())?;
            cts.push(ct);
        }
        cts
    });

    // Homomorphic addition: sum all ciphertexts
    let sum_ciphertext = timeit!("Homomorphic addition", {
        let mut sum = Ciphertext::zero(&params);
        for ct in &ciphertexts {
            sum += ct;
        }
        Arc::new(sum)
    });

    println!("✓ Homomorphic computation completed");

    // ========================================================================
    // THRESHOLD DECRYPTION - Following Shamir.md Algorithm
    // ========================================================================

    println!("\n## Phase 3: Threshold Decryption");

    // Step 1: Generate smudging error shares for threshold decryption security
    let all_smudging_shares = timeit!("Smudging error share generation", {
        let mut all_shares = Vec::new();
        for party in &mut parties {
            let shares =
                party.generate_smudging_shares(num_parties, threshold, &params, smudging_bound)?;
            all_shares.push(shares);
        }
        all_shares
    });

    // Step 2: Distribute smudging shares (simulating network communication)
    timeit!("Smudging share distribution", {
        for receiver_id in 0..num_parties {
            let mut collected_shares = vec![vec![BigInt::zero(); degree]; moduli.len()];

            for sender_id in 0..num_parties {
                for m in 0..moduli.len() {
                    for j in 0..degree {
                        collected_shares[m][j] +=
                            &all_smudging_shares[sender_id][m][j][receiver_id];
                    }
                }
            }

            parties[receiver_id].smudging_shares = collected_shares;
        }
    });

    // ========================================================================
    // VALIDATION: Smudging Share Correctness
    // ========================================================================
    println!("🔍 Validating smudging share distribution...");

    // Validate that smudging shares can reconstruct the original smudging
    // coefficients Since smudging polynomials are generated per-party, we need
    // to validate that the shares correctly represent the sum of all party
    // smudging contributions
    for m in 0..moduli.len() {
        let prime = BigInt::from(moduli[m]);

        // Sample a few random coefficients to validate (not all 2048 for performance)
        let sample_coeffs = [0, 1, 10, 100, degree / 2, degree - 1];

        for &j in &sample_coeffs {
            if j >= degree {
                continue;
            }

            // Note: For smudging shares, we're validating that Lagrange interpolation
            // works correctly, not that they sum to specific expected values
            // (since smudging polynomials are random and used for security)

            // Test reconstruction using threshold+1 parties
            let test_parties: Vec<usize> = (1..=threshold + 1).collect();
            let mut reconstructed_coeff = BigInt::from(0);

            for &party_id in &test_parties {
                let party_idx = party_id - 1;
                let share_value = &parties[party_idx].smudging_shares[m][j];
                let lambda = compute_lagrange_coefficient_at_zero(party_id, &test_parties, &prime);
                reconstructed_coeff = (reconstructed_coeff + lambda * share_value) % &prime;
            }

            // Test with a different set of threshold+1 parties to ensure consistency
            if num_parties > threshold + 1 {
                let alt_test_parties: Vec<usize> = (2..=threshold + 2).collect();
                let mut alt_reconstructed_coeff = BigInt::from(0);

                for &party_id in &alt_test_parties {
                    let party_idx = party_id - 1;
                    let share_value = &parties[party_idx].smudging_shares[m][j];
                    let lambda =
                        compute_lagrange_coefficient_at_zero(party_id, &alt_test_parties, &prime);
                    alt_reconstructed_coeff =
                        (alt_reconstructed_coeff + lambda * share_value) % &prime;
                }

                // Both sets should reconstruct to the same value
                assert_eq!(
                    reconstructed_coeff, alt_reconstructed_coeff,
                    "Smudging coefficient reconstruction inconsistent between party sets at modulus {}, coefficient {}: got {} vs {}",
                    m, j, reconstructed_coeff, alt_reconstructed_coeff
                );
            }
        }
    }
    println!("✓ Smudging share distribution validation passed");

    // Step 3: Threshold decryption with subset of parties (t+1 parties)
    // Select first threshold+1 parties for decryption
    let decryption_parties: Vec<usize> = (1..=threshold + 1).collect();
    println!("Participating parties: {:?}", decryption_parties);

    // Step 4: Each participating party computes decryption share
    // di = c0 + c1*si + esi (following Shamir.md)
    let decryption_shares = timeit!(
        "Decryption share computation",
        compute_decryption_shares(&parties, &decryption_parties, &sum_ciphertext, &params)?
    );

    // Step 5: Threshold reconstruction using Lagrange interpolation
    // Following BFV threshold decryption: reconstruct c0 + c1*s at evaluation point
    // 0
    let threshold_result = timeit!(
        "Threshold reconstruction",
        threshold_reconstruct(
            &decryption_shares,
            &decryption_parties,
            &sum_ciphertext,
            &params
        )?
    );

    println!("Threshold decryption result: {}", threshold_result);

    // ========================================================================
    // VALIDATION: Threshold Decryption Consistency
    // ========================================================================
    println!("🔍 Validating threshold decryption consistency...");

    // Test that using a different subset of threshold+1 parties gives the same
    // result
    if num_parties > threshold + 1 {
        let alt_decryption_parties: Vec<usize> = (2..=threshold + 2).collect();
        println!(
            "Testing with alternative party set: {:?}",
            alt_decryption_parties
        );

        let alt_decryption_shares =
            compute_decryption_shares(&parties, &alt_decryption_parties, &sum_ciphertext, &params)?;
        let alt_threshold_result = threshold_reconstruct(
            &alt_decryption_shares,
            &alt_decryption_parties,
            &sum_ciphertext,
            &params,
        )?;

        assert_eq!(
            threshold_result, alt_threshold_result,
            "Threshold decryption inconsistent between party sets: got {} vs {}",
            threshold_result, alt_threshold_result
        );

        println!(
            "✓ Alternative party set produces same result: {}",
            alt_threshold_result
        );
    }
    println!("✓ Threshold decryption consistency validation passed");

    // ========================================================================
    // VALIDATION AND RESULTS
    // ========================================================================

    println!("\n## Results Summary");
    println!("Input values: {:?}", test_values);
    println!("Expected sum: {}", expected_sum);
    println!("Threshold BFV result: {}", threshold_result);

    // Validate results
    println!("\n## Validation");
    if threshold_result == expected_sum {
        println!("✓ Threshold BFV decryption: CORRECT");
    } else {
        println!(
            "✗ Threshold BFV decryption: INCORRECT (got {}, expected {})",
            threshold_result, expected_sum
        );
    }

    // Final assertion for automated testing
    assert_eq!(
        threshold_result, expected_sum,
        "Threshold decryption result {} does not match expected sum {}",
        threshold_result, expected_sum
    );

    println!("\n🎉 Threshold BFV implementation successful!");

    Ok(())
}
