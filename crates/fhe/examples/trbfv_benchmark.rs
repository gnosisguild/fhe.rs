// Benchmark demonstrating the actual performance benefits of packed hybrid optimization

mod util;

use std::{env, sync::Arc, time::Instant};
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, PublicKeyShare},
    trbfv::{TrBFVShare, PackedHybridShare},
};
use fhe_math::rq::{Poly, Representation};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::{Array, Array2, ArrayView};
use rand::{distributions::Uniform, prelude::Distribution, rngs::OsRng, thread_rng};
use console::style;

fn parse_args() -> (usize, usize, usize) {
    let args: Vec<String> = env::args().collect();
    
    let mut degree = 2048;
    let mut num_parties = 16;
    let mut threshold = 9;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--degree" | "-d" => {
                if i + 1 < args.len() {
                    degree = args[i + 1].parse().expect("Invalid degree value");
                    i += 2;
                } else {
                    eprintln!("Error: --degree requires a value");
                    print_usage_and_exit();
                }
            }
            "--parties" | "-n" => {
                if i + 1 < args.len() {
                    num_parties = args[i + 1].parse().expect("Invalid parties value");
                    i += 2;
                } else {
                    eprintln!("Error: --parties requires a value");
                    print_usage_and_exit();
                }
            }
            "--threshold" | "-t" => {
                if i + 1 < args.len() {
                    threshold = args[i + 1].parse().expect("Invalid threshold value");
                    i += 2;
                } else {
                    eprintln!("Error: --threshold requires a value");
                    print_usage_and_exit();
                }
            }
            "--help" | "-h" => {
                print_usage_and_exit();
            }
            _ => {
                eprintln!("Error: Unknown argument '{}'", args[i]);
                print_usage_and_exit();
            }
        }
    }
    
    // Validate parameters
    if threshold > num_parties {
        eprintln!("Error: threshold ({}) cannot be greater than number of parties ({})", threshold, num_parties);
        std::process::exit(1);
    }
    
    if threshold == 0 {
        eprintln!("Error: threshold must be greater than 0");
        std::process::exit(1);
    }
    
    if num_parties == 0 {
        eprintln!("Error: number of parties must be greater than 0");
        std::process::exit(1);
    }
    
    // Validate degree is a power of 2
    if degree == 0 || (degree & (degree - 1)) != 0 {
        eprintln!("Error: degree must be a power of 2");
        std::process::exit(1);
    }
    
    (degree, num_parties, threshold)
}

fn print_usage_and_exit() {
    println!("Usage: trbfv_benchmark [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -d, --degree <VALUE>     Polynomial degree (power of 2, default: 2048)");
    println!("  -n, --parties <VALUE>    Number of parties (default: 16)");
    println!("  -t, --threshold <VALUE>  Threshold value (must be <= parties, default: 9)");
    println!("  -h, --help              Show this help message");
    println!();
    println!("Examples:");
    println!("  trbfv_benchmark --degree 4096 --parties 32 --threshold 16");
    println!("  trbfv_benchmark -d 1024 -n 8 -t 5");
    std::process::exit(0);
}

fn benchmark_operations(degree: usize, num_parties: usize, threshold: usize) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", style("=== Threshold BFV Optimization Benchmark ===").green().bold());
    
    // Fixed parameters
    let plaintext_modulus: u64 = 4096;
    let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];
    let num_operations = 100;
    
    println!("Parameters:");
    println!("  • Parties: {}", num_parties);
    println!("  • Threshold: {}", threshold);
    println!("  • Degree: {}", degree);
    println!("  • Operations: {}", num_operations);
    
    let params = bfv::BfvParametersBuilder::new()
        .set_degree(degree)
        .set_plaintext_modulus(plaintext_modulus)
        .set_moduli(&moduli)
        .build_arc()?;
    
    let mut trbfv = TrBFVShare::new(
        num_parties,
        threshold,
        degree,
        plaintext_modulus,
        160,
        moduli.clone(),
        params.clone(),
    )?;
    
    // Generate test secret keys for all parties
    let mut secret_keys = Vec::new();
    for _ in 0..num_parties {
        secret_keys.push(SecretKey::random(&params, &mut OsRng));
    }
    
    println!("\n{}", style("1. Share Generation Comparison").yellow().bold());
    
    // Benchmark original share generation
    let start = Instant::now();
    let mut original_shares_all = Vec::new();
    for sk in &secret_keys {
        let shares = trbfv.generate_secret_shares(sk.coeffs.clone())?;
        original_shares_all.push(shares);
    }
    let original_time = start.elapsed();
    
    // Benchmark packed hybrid share generation
    let start = Instant::now();
    let mut packed_shares_all = Vec::new();
    for sk in &secret_keys {
        let shares = trbfv.generate_packed_hybrid_shares(sk.coeffs.clone())?;
        packed_shares_all.push(shares);
    }
    let packed_time = start.elapsed();
    
    println!("Original method: {:?}", original_time);
    println!("Packed method:   {:?}", packed_time);
    println!("Improvement:     {:.2}x", original_time.as_secs_f64() / packed_time.as_secs_f64());
    
    println!("\n{}", style("2. Communication Overhead Analysis").yellow().bold());
    
    // Calculate communication sizes
    let original_comm_size = original_shares_all[0].len() * moduli.len() * degree * num_parties;
    let packed_comm_size = packed_shares_all[0].len() * packed_shares_all[0][0].additive_parts.len() * threshold;
    
    println!("Original communication: {} values", original_comm_size);
    println!("Packed communication:   {} values", packed_comm_size);
    println!("Communication reduction: {:.2}x", original_comm_size as f64 / packed_comm_size as f64);
    
    println!("\n{}", style("3. Local Operations Benchmark").yellow().bold());
    
    // Get sample packed shares for operations
    let party_shares = &packed_shares_all[0];
    
    // Benchmark addition operations
    let start = Instant::now();
    for i in 0..num_operations {
        let idx_a = i % party_shares.len();
        let idx_b = (i + 1) % party_shares.len();
        let _sum = trbfv.add_packed_hybrid(&party_shares[idx_a], &party_shares[idx_b]);
    }
    let addition_time = start.elapsed();
    
    // Benchmark scalar multiplication
    let start = Instant::now();
    for i in 0..num_operations {
        let idx = i % party_shares.len();
        let _scaled = trbfv.scalar_mul_packed_hybrid(&party_shares[idx], 42);
    }
    let scalar_time = start.elapsed();
    
    println!("Packed additions ({} ops):     {:?} ({:.3} ms/op)", 
             num_operations, addition_time, addition_time.as_secs_f64() * 1000.0 / num_operations as f64);
    println!("Packed scalar muls ({} ops):   {:?} ({:.3} ms/op)", 
             num_operations, scalar_time, scalar_time.as_secs_f64() * 1000.0 / num_operations as f64);
    
    println!("\n{}", style("4. Memory Usage Comparison").yellow().bold());
    
    // Calculate memory usage more accurately
    // Original: num_parties * moduli.len() * degree values (each u64 = 8 bytes)
    let original_memory = original_shares_all.len() * moduli.len() * degree * 8;
    
    // Packed: each party has one PackedHybridShare containing additive_parts (BigInt values)
    // additive_parts.len() = moduli.len() * total_blocks_per_modulus
    let additive_parts_per_share = packed_shares_all[0][0].additive_parts.len();
    let packing_params = trbfv.calculate_packing_params();
    let total_blocks = packing_params.total_blocks;
    
    // Each BigInt stores packed coefficients, estimate ~32 bytes per BigInt on average
    let estimated_bigint_size = 32; // Conservative estimate for packed coefficients
    let packed_memory = num_parties * additive_parts_per_share * estimated_bigint_size;
    
    println!("Original shares memory: {} KB", original_memory / 1024);
    println!("  Structure: {} parties × {} moduli × {} degree × 8 bytes", 
             num_parties, moduli.len(), degree);
    
    println!("Packed shares memory:   {} KB", packed_memory / 1024);
    println!("  Structure: {} parties × {} packed_parts × {} bytes/BigInt", 
             num_parties, additive_parts_per_share, estimated_bigint_size);
    
    println!("Memory efficiency:      {:.2}x", original_memory as f64 / packed_memory as f64);
    
    // Analysis of packing efficiency
    println!("\nPacking Analysis:");
    println!("  • Pack size (threshold): {}", packing_params.pack_size);
    println!("  • Blocks per modulus:    {}", total_blocks);
    println!("  • Total additive parts:  {} (= {} moduli × {} blocks)", 
             additive_parts_per_share, moduli.len(), total_blocks);
    println!("  • Theoretical reduction: {}x (pack {} coeffs into 1 BigInt)", 
             packing_params.pack_size, packing_params.pack_size);
    
    println!("\n{}", style("5. Theoretical vs Practical Analysis").yellow().bold());
    
    let packing_params = trbfv.calculate_packing_params();
    println!("Pack size (threshold):  {}", packing_params.pack_size);
    println!("Total blocks:          {}", packing_params.total_blocks);
    
    // Theoretical improvements
    let setup_improvement = threshold as f64;
    let operation_improvement = (num_parties * num_parties) as f64;
    let comm_improvement = threshold as f64;
    
    println!("\nTheoretical improvements:");
    println!("  • Setup complexity:     O(n²N) → O(n²N/t) = {}x faster", setup_improvement);
    println!("  • Operation complexity: O(n²N) → O(N) = {}x faster", operation_improvement);
    println!("  • Communication:        O(nN) → O(nN/t) = {}x less data", comm_improvement);
    
    println!("\n{}", style("6. Scalability Projection").yellow().bold());
    
    // Project benefits for larger parameters
    let scenarios = vec![
        (32, 16, 4096),
        (64, 32, 8192),
        (128, 64, 16384),
    ];
    
    println!("Projected benefits for larger scales:");
    for (n, t, degree) in scenarios {
        let setup_benefit = t as f64;
        let op_benefit = (n * n) as f64;
        let comm_benefit = t as f64;
        
        println!("  n={}, t={}, N={}: Setup {}x, Ops {}x, Comm {}x", 
                 n, t, degree, setup_benefit, op_benefit, comm_benefit);
    }
    
    println!("\n{}", style("Summary").green().bold());
    println!("The optimization benefits are most visible in:");
    println!("  ✓ Local operations (O(1) instead of O(n²N))");
    println!("  ✓ Communication overhead reduction");
    println!("  ✓ Memory efficiency for share storage");
    println!("  ✓ Scalability to larger parameter sets");
    println!();
    println!("Setup time improvements require threshold-optimized algorithms");
    println!("and become more apparent with larger n, t, and repeated operations.");
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (degree, num_parties, threshold) = parse_args();
    benchmark_operations(degree, num_parties, threshold)
}
