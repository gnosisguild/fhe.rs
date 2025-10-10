use fhe::bfv::{BfvParameters, BfvParametersBuilder, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use rand::thread_rng;
use std::error::Error;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = thread_rng();

    println!("=== Testing BFV with different values ===\n");

    // BFV parameters matching what we use for share encryption
    let degree = 8192;
    let moduli_bfv = vec![
        0x0200000001ee0001, // 58 bits
        0x0200000001b20001, // 58 bits
    ];
    let plaintext_modulus_bfv: u64 = 144115188075855872; // 2^57

    let params: Arc<BfvParameters> = BfvParametersBuilder::new()
        .set_degree(degree)
        .set_plaintext_modulus(plaintext_modulus_bfv)
        .set_moduli(&moduli_bfv)
        .set_variance(10)
        .build_arc()?;

    println!("Parameters:");
    println!("  Degree: {}", degree);
    println!("  Plaintext modulus: {}", plaintext_modulus_bfv);
    println!("  Ciphertext moduli: {:?}\n", moduli_bfv);

    // Generate keys
    let sk = SecretKey::random(&params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);

    // // Test with small values
    // let values = vec![3u64, 5, 10, 100, 1000];
    // println!("Testing values: {:?}\n", values);

    // Test with large values (similar to Shamir shares)
    let values = vec![
        36028797055270913u64, // Max trBFV modulus (~2^56)
        20000000000000000u64,
        30000000000000000u64,
        15000000000000000u64,
        25000000000000000u64,
    ];
    println!("Testing large values: {:?}\n", values);

    // Test 1: Encode/Decode only (no encryption)
    println!("Test 1: Encode/Decode only");
    let pt = Plaintext::try_encode(&values, Encoding::poly(), &params)?;
    let decoded: Vec<u64> = Vec::<u64>::try_decode(&pt, Encoding::poly())?;

    let encode_matches = values.iter().zip(decoded.iter()).all(|(a, b)| a == b);
    println!(
        "  Result: {}",
        if encode_matches {
            "✓ PASS"
        } else {
            "✗ FAIL"
        }
    );

    if !encode_matches {
        println!("  Differences:");
        for i in 0..values.len() {
            if values[i] != decoded[i] {
                println!(
                    "    [{}] original: {}, decoded: {}, diff: {}",
                    i,
                    values[i],
                    decoded[i],
                    if decoded[i] > values[i] {
                        decoded[i] - values[i]
                    } else {
                        values[i] - decoded[i]
                    }
                );
            }
        }
    }

    // Test 2: Full Encrypt/Decrypt
    println!("\nTest 2: Full Encrypt/Decrypt");
    let ct = pk.try_encrypt(&pt, &mut rng)?;
    let pt_decrypted = sk.try_decrypt(&ct)?;
    let decrypted: Vec<u64> = Vec::<u64>::try_decode(&pt_decrypted, Encoding::poly())?;

    let full_matches = values.iter().zip(decrypted.iter()).all(|(a, b)| a == b);
    println!(
        "  Result: {}",
        if full_matches { "✓ PASS" } else { "✗ FAIL" }
    );

    if !full_matches {
        println!("  Differences:");
        for i in 0..values.len() {
            if values[i] != decrypted[i] {
                println!(
                    "    [{}] original: {}, decrypted: {}, diff: {}",
                    i,
                    values[i],
                    decrypted[i],
                    if decrypted[i] > values[i] {
                        decrypted[i] - values[i]
                    } else {
                        values[i] - decrypted[i]
                    }
                );
            }
        }
    }

    Ok(())
}
