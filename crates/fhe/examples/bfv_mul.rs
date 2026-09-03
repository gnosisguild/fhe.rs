// Simple BFV homomorphic multiplication.
//
// Verifies the first parameter set works for single-party BFV arithmetic:
// encrypt two values, multiply with relinearization, decrypt and check.
//
//   n (ciphernodes)  = 20       z (mult depth) = 3
//   k (plaintext)    = 1000     λ (stat sec)   = 31
//   d (ring dim)     = 16384    |q|            ≈ 2^251 (5 × 51-bit primes)
//
// Correctness: the supplied depth-3 preset has log₂(B_C) ≈ 186.3 < log₂(Δ) ≈ 240.0.

#![allow(clippy::indexing_slicing, missing_docs)]

mod util;

use std::{error::Error, sync::Arc};

use fhe::{
    bfv::{self, CommonRandomPolyVec, Encoding, Plaintext, SecretKey},
    lbfv::{LBFVPublicKey, LBFVRelinearizationKey},
    trbfv::presets,
};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use util::timeit::timeit;

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = rand::rng();

    println!("=== BFV Homomorphic Multiplication ===");
    println!("n=20 ciphernodes, k=1000, d=16384, 5×51-bit moduli, λ=31\n");

    let params: Arc<bfv::BfvParameters> = timeit!(
        "Parameter generation",
        presets::secure_16384_lbfv_parameters()?
    );
    let plaintext_modulus = params.plaintext();
    println!(
        "Moduli (5×51-bit): {:?}",
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
