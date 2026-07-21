// Simple BFV homomorphic multiplication.
//
// Verifies the first parameter set works for single-party BFV arithmetic:
// encrypt two values, multiply with relinearization, decrypt and check.
//
//   n (ciphernodes)  = 20       z (mult depth) = 3
//   k (plaintext)    = 1000     λ (stat sec)   = 28
//   d (ring dim)     = 16384    |q|            ≈ 2^244 (4 × 61-bit primes)
//
// Correctness: log₂(B_C after 1 mult) = 193.5 < log₂(Δ) = 234.0  ✓

#![allow(clippy::indexing_slicing, missing_docs)]

mod util;

use std::{error::Error, sync::Arc};

use fhe::{
    bfv::{self, CommonRandomPolyVec, Encoding, Plaintext, SecretKey},
    lbfv::{LBFVPublicKey, LBFVRelinearizationKey},
};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use util::timeit::timeit;

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = rand::rng();

    println!("=== BFV Homomorphic Multiplication ===");
    println!("n=20 ciphernodes, k=1000, d=16384, 4×61-bit moduli, λ=28\n");

    let degree = 16384usize;
    let plaintext_modulus = 1_000u64;

    // Four 61-bit NTT primes, each ≡ 1 mod 32768 (= 2n, required for
    // negacyclic NTT in Z[x]/(x^n+1) with n=16384).
    let moduli = [
        0x1fffffffffe10001u64,
        0x1fffffffffe00001,
        0x1fffffffffdd0001,
        0x1fffffffffd08001,
    ];

    let params: Arc<bfv::BfvParameters> = timeit!(
        "Parameter generation",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .set_variance(10)
            // Var(e_1) for n=20, λ=28 from the parameter tool.
            .set_error1_variance_str("4126466797617934249663747413333")?
            .build_arc()?
    );
    println!(
        "Moduli (4×61-bit): {:?}",
        params
            .moduli()
            .iter()
            .map(|q| format!("0x{q:016x}"))
            .collect::<Vec<_>>()
    );
    println!("Plaintext modulus: {}\n", plaintext_modulus);

    let sk = SecretKey::random(&params, &mut rng);

    // Shared CRP vectors: crp_a (CRS a) and crp_d1 (URS d1), established via
    // coin-tossing.  Both are ConcreteRandomPolyVectors with independent seeds.
    let crp_a = CommonRandomPolyVec::new(&params, &mut rng)?;
    let crp_d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
    let pk_lbfv = timeit!(
        "l-BFV public key",
        LBFVPublicKey::new_with_crp(&sk, &crp_a, &mut rng)?
    );

    let rlk = timeit!(
        "Relinearization key generation",
        LBFVRelinearizationKey::new_with_crp(&sk, &pk_lbfv, &crp_d1, &mut rng)?
    );
    println!("l = {}", rlk.l()?);

    // Both factors and their product must be < k = 1000.
    // sqrt(999) ≈ 31.6, so 31 × 31 = 961 is the largest safe square.
    let a = 31u64;
    let b = 31u64;
    println!("\nComputing {} × {} = {}", a, b, a * b);

    let pt_a = Plaintext::try_encode(&[a], Encoding::poly(), &params)?;
    let pt_b = Plaintext::try_encode(&[b], Encoding::poly(), &params)?;
    let ct_a = timeit!("Encrypt a", pk_lbfv.try_encrypt(&pt_a, &mut rng)?);
    let ct_b = timeit!("Encrypt b", pk_lbfv.try_encrypt(&pt_b, &mut rng)?);

    let ct_product = timeit!("Multiply and relinearize", {
        let mut ct = &ct_a * &ct_b;
        rlk.relinearizes(&mut ct)?;
        ct
    });
    println!("  Product ciphertext level: {}", ct_product.level);

    let pt_result = timeit!("Decrypt", sk.try_decrypt(&ct_product)?);
    let result = Vec::<u64>::try_decode(&pt_result, Encoding::poly())?;

    println!("\nResult:   {}", result[0]);
    println!("Expected: {}", a * b);
    assert_eq!(result[0], a * b, "BFV multiplication gave wrong answer!");
    println!("Correct — first parameter set supports BFV multiplication.");

    Ok(())
}
