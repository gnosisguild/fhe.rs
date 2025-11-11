use criterion::{criterion_group, criterion_main, Criterion};
use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::mbfv::{CommonRandomPoly, PublicKeyShare};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use rand::{rngs::OsRng, thread_rng};
use std::sync::Arc;

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} bytes", bytes)
    }
}

fn bench_data_sizes(c: &mut Criterion) {
    let group = c.benchmark_group("BFV Encrypted Shares Data Sizes");

    // Threshold BFV parameters
    let degree = 8192;
    let moduli_trbfv = vec![
        0x00800000022a0001,
        0x00800000021a0001,
        0x0080000002120001,
        0x0080000001f60001,
    ];
    let plaintext_modulus_trbfv: u64 = 1000;

    let params_trbfv = Arc::new(
        BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus_trbfv)
            .set_moduli(&moduli_trbfv)
            .set_variance(10)
            .set_error1_variance_str(
                "52309181128222339698631578526730685514457152477762943514050560000",
            )
            .unwrap()
            .build()
            .unwrap(),
    );

    // BFV parameters for share encryption
    let moduli_bfv = vec![
        0x0400000001460001, // 59 bits
        0x0400000000ea0001, // 59 bits
    ];
    let plaintext_modulus_bfv: u64 = 144115188075855872; // 2^57

    let params_bfv = Arc::new(
        BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus_bfv)
            .set_moduli(&moduli_bfv)
            .set_variance(10)
            .build()
            .unwrap(),
    );

    let num_parties = 3;
    let threshold = 1;

    println!("\n=== THRESHOLD BFV WITH BFV ENCRYPTED SHARES DATA SIZE BENCHMARKS ===");
    println!(
        "Parameters: {} parties, threshold {}, degree {}",
        num_parties, threshold, degree
    );
    println!("trBFV moduli: {} moduli of ~56 bits", moduli_trbfv.len());
    println!(
        "BFV encryption moduli: {} moduli of ~59 bits",
        moduli_bfv.len()
    );

    // Generate Common Reference Polynomial
    let crp = CommonRandomPoly::new(&params_trbfv, &mut thread_rng()).unwrap();

    // Setup trBFV
    let trbfv = TRBFV::new(num_parties, threshold, params_trbfv.clone()).unwrap();

    // Generate parties with threshold BFV keys and BFV encryption keys
    println!("\n📊 Generating party keys...");
    let mut parties = Vec::new();
    let mut all_sk_shares = Vec::new();
    let mut all_esi_shares = Vec::new();

    for _party_id in 0..num_parties {
        let mut rng = OsRng;
        let mut thread_rng = thread_rng();

        // Generate threshold BFV keys
        let sk_share = SecretKey::random(&params_trbfv, &mut rng);
        let pk_share = PublicKeyShare::new(&sk_share, crp.clone(), &mut thread_rng).unwrap();

        // Generate Shamir shares of the secret key
        let mut share_manager = ShareManager::new(num_parties, threshold, params_trbfv.clone());
        let sk_poly = share_manager
            .coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())
            .unwrap();

        let sk_sss = trbfv
            .generate_secret_shares_from_poly(sk_poly, rng)
            .unwrap();

        // Generate smudging error shares
        let esi_coeffs = trbfv.generate_smudging_error(100, &mut rng).unwrap();
        let esi_poly = share_manager.bigints_to_poly(&esi_coeffs).unwrap();
        let esi_sss = share_manager
            .generate_secret_shares_from_poly(esi_poly, rng)
            .unwrap();

        // Generate BFV keys for share encryption
        let sk_bfv = SecretKey::random(&params_bfv, &mut rng);
        let pk_bfv = PublicKey::new(&sk_bfv, &mut thread_rng);

        all_sk_shares.push(sk_sss.clone());
        all_esi_shares.push(esi_sss.clone());
        parties.push((sk_share, pk_share, sk_bfv, pk_bfv, sk_sss, esi_sss));
    }

    // Calculate Shamir share sizes
    let num_moduli = moduli_trbfv.len();
    let single_share_size = 8; // 64-bit coefficient
    let shamir_shares_per_party = degree * num_moduli * num_parties; // coefficients × moduli × parties
    let shamir_size_per_party = shamir_shares_per_party * single_share_size;
    let total_shamir_shares = num_parties * shamir_shares_per_party;
    let total_shamir_size = total_shamir_shares * single_share_size;

    println!("\n📏 Shamir Secret Share Sizes:");
    println!(
        "  - Shares per party: {} ({} coefficients × {} moduli × {} parties)",
        shamir_shares_per_party, degree, num_moduli, num_parties
    );
    println!(
        "  - Size per party: {}",
        format_bytes(shamir_size_per_party)
    );
    println!(
        "  - Total shares: {} ({} parties × {} per party)",
        total_shamir_shares, num_parties, shamir_shares_per_party
    );
    println!("  - Total size: {}", format_bytes(total_shamir_size));

    // Encrypt shares with BFV
    println!("\n🔐 Encrypting Shamir shares with BFV...");
    let start_time = std::time::Instant::now();

    let mut encrypted_shares_count = 0;
    let mut total_encrypted_size = 0;

    for (_, _, _, _, sk_sss, esi_sss) in parties.iter() {
        for (receiver_idx, receiver_party) in parties.iter().enumerate().take(num_parties) {
            let receiver_pk = &receiver_party.3;
            let mut rng = thread_rng();

            // Encrypt sk shares
            for sk_sss_m in sk_sss.iter().take(num_moduli) {
                let share_row = sk_sss_m.row(receiver_idx);
                let share_vec: Vec<u64> = share_row.to_vec();

                let pt = Plaintext::try_encode(&share_vec, Encoding::poly(), &params_bfv).unwrap();
                let _ct = receiver_pk.try_encrypt(&pt, &mut rng).unwrap();

                // Estimate ciphertext size (2 polynomials × degree × moduli × 8 bytes)
                let ct_size = 2 * degree * moduli_bfv.len() * 8;
                total_encrypted_size += ct_size;
                encrypted_shares_count += 1;
            }

            // Encrypt esi shares
            for esi_sss_m in esi_sss.iter().take(num_moduli) {
                let share_row = esi_sss_m.row(receiver_idx);
                let share_vec: Vec<u64> = share_row.to_vec();

                let pt = Plaintext::try_encode(&share_vec, Encoding::poly(), &params_bfv).unwrap();
                let _ct = receiver_pk.try_encrypt(&pt, &mut rng).unwrap();

                let ct_size = 2 * degree * moduli_bfv.len() * 8;
                total_encrypted_size += ct_size;
                encrypted_shares_count += 1;
            }
        }
    }

    let encryption_duration = start_time.elapsed();

    println!(
        "✅ Encrypted {} shares in {:?}",
        encrypted_shares_count, encryption_duration
    );
    println!(
        "  - Encryption rate: {:.2} encryptions/sec",
        encrypted_shares_count as f64 / encryption_duration.as_secs_f64()
    );
    println!(
        "  - Time per encryption: {:.3} ms",
        encryption_duration.as_secs_f64() * 1000.0 / encrypted_shares_count as f64
    );

    println!("\n📦 BFV Encrypted Share Sizes:");
    println!(
        "  - Total encrypted shares: {} ({} parties × {} receivers × {} moduli × 2 share types)",
        encrypted_shares_count, num_parties, num_parties, num_moduli
    );
    println!(
        "  - Encryptions per party: {} ({} receivers × {} moduli × 2 share types)",
        encrypted_shares_count / num_parties,
        num_parties,
        num_moduli
    );
    let single_ct_size = 2 * degree * moduli_bfv.len() * 8;
    println!(
        "  - Single ciphertext size: ~{} (2 polys × {} degree × {} moduli × 8 bytes)",
        format_bytes(single_ct_size),
        degree,
        moduli_bfv.len()
    );
    let broadcast_size_per_party = total_encrypted_size / num_parties;
    println!(
        "  - Broadcast size per party: {} ({} parties × {} moduli × 2 share types × {})",
        format_bytes(broadcast_size_per_party),
        num_parties,
        num_moduli,
        format_bytes(single_ct_size)
    );
    println!(
        "  - Total encrypted size: ~{}",
        format_bytes(total_encrypted_size)
    );
    println!(
        "  - Expansion factor: {:.2}x (encrypted/plaintext)",
        total_encrypted_size as f64 / total_shamir_size as f64
    );

    // Calculate key sizes
    let sk_size = degree * 8; // Secret key coefficients
    let pk_size = 2 * degree * moduli_bfv.len() * 8; // Public key is a ciphertext

    println!("\n🔑 BFV Key Sizes (for share encryption):");
    println!("  - Secret key size: {}", format_bytes(sk_size));
    println!("  - Public key size: ~{}", format_bytes(pk_size));
    println!(
        "  - Total keys ({} parties): {}",
        num_parties,
        format_bytes(num_parties * (sk_size + pk_size))
    );

    // Calculate prover witness size for BFV public key proof
    println!("\n🔍 Prover Witness Size (for BFV Public Key Proof):");
    let l = moduli_bfv.len(); // Number of moduli
    let n = degree; // Polynomial degree

    // Size calculations for each component (assuming 64-bit coefficients)
    let coeff_size = 8; // bytes per coefficient

    // Secret witness components:
    let eek_size = n * coeff_size; // Error polynomial: N coefficients
    let sk_size_witness = n * coeff_size; // Secret key polynomial: N coefficients
    let r1_size = l * (2 * n - 1) * coeff_size; // L polynomials of degree 2N-1
    let r2_size = l * n * coeff_size; // L polynomials of degree N-1

    // Public components (not part of witness, but included in proof):
    let a_size = l * n * coeff_size; // L polynomials of degree N-1
    let pk0_size = l * n * coeff_size; // L polynomials of degree N-1
    let pk1_size = l * n * coeff_size; // L polynomials of degree N-1

    // Total witness size (secret components only)
    let total_witness_size = eek_size + sk_size_witness + r1_size + r2_size;

    // Total proof size (witness + public inputs)
    let total_proof_size = total_witness_size + a_size + pk0_size + pk1_size;

    println!("  Secret Witness Components:");
    println!(
        "    - eek (error polynomial): {} ({} coefficients)",
        format_bytes(eek_size),
        n
    );
    println!(
        "    - sk (secret key polynomial): {} ({} coefficients)",
        format_bytes(sk_size_witness),
        n
    );
    println!(
        "    - r1 (modulus switching quotients): {} ({} polynomials × {} coefficients)",
        format_bytes(r1_size),
        l,
        2 * n - 1
    );
    println!(
        "    - r2 (cyclotomic reduction quotients): {} ({} polynomials × {} coefficients)",
        format_bytes(r2_size),
        l,
        n
    );
    println!(
        "  → Total witness size: {}",
        format_bytes(total_witness_size)
    );

    println!("\n  Public Components (CRS and outputs):");
    println!(
        "    - a (CRS polynomials): {} ({} polynomials × {} coefficients)",
        format_bytes(a_size),
        l,
        n
    );
    println!(
        "    - pk0 (public key component 0): {} ({} polynomials × {} coefficients)",
        format_bytes(pk0_size),
        l,
        n
    );
    println!(
        "    - pk1 (public key component 1): {} ({} polynomials × {} coefficients)",
        format_bytes(pk1_size),
        l,
        n
    );
    println!(
        "  → Total public data: {}",
        format_bytes(a_size + pk0_size + pk1_size)
    );

    println!(
        "\n  📊 Proof size per party: {}",
        format_bytes(total_proof_size)
    );
    println!("     - Witness only: {}", format_bytes(total_witness_size));
    println!(
        "     - With public data: {}",
        format_bytes(total_proof_size)
    );

    println!("\n============================\n");

    group.finish();
}

fn bench_timing_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("BFV Encrypted Shares Timing");

    // Setup parameters (same as data sizes)
    let degree = 8192;
    let moduli_trbfv = vec![
        0x00800000022a0001,
        0x00800000021a0001,
        0x0080000002120001,
        0x0080000001f60001,
    ];
    let plaintext_modulus_trbfv: u64 = 1000;

    let params_trbfv = Arc::new(
        BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus_trbfv)
            .set_moduli(&moduli_trbfv)
            .set_variance(10)
            .set_error1_variance_str(
                "52309181128222339698631578526730685514457152477762943514050560000",
            )
            .unwrap()
            .build()
            .unwrap(),
    );

    let moduli_bfv = vec![0x0400000001460001, 0x0400000000ea0001];
    let plaintext_modulus_bfv: u64 = 144115188075855873;

    let params_bfv = Arc::new(
        BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus_bfv)
            .set_moduli(&moduli_bfv)
            .set_variance(10)
            .build()
            .unwrap(),
    );

    let num_parties = 3;
    let threshold = 2;

    // Benchmark: Generate BFV key pair for share encryption
    group.bench_function("generate_bfv_keypair", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            let sk = SecretKey::random(&params_bfv, &mut rng);
            let pk = PublicKey::new(&sk, &mut thread_rng());
            (sk, pk)
        });
    });

    // Benchmark: Generate Shamir shares
    let mut rng = OsRng;
    let sk_share = SecretKey::random(&params_trbfv, &mut rng);
    let trbfv = TRBFV::new(num_parties, threshold, params_trbfv.clone()).unwrap();

    group.bench_function("generate_shamir_shares", |b| {
        let share_manager = ShareManager::new(num_parties, threshold, params_trbfv.clone());
        let sk_poly = share_manager
            .coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())
            .unwrap();

        b.iter(|| {
            trbfv
                .generate_secret_shares_from_poly(sk_poly.clone(), rng)
                .unwrap()
        });
    });

    // Benchmark: Encrypt a single share
    let sk_bfv = SecretKey::random(&params_bfv, &mut OsRng);
    let pk_bfv = PublicKey::new(&sk_bfv, &mut thread_rng());
    let test_share: Vec<u64> = (0..degree).map(|i| i as u64 % 1000).collect();

    group.bench_function("encrypt_single_share", |b| {
        b.iter(|| {
            let pt = Plaintext::try_encode(&test_share, Encoding::poly(), &params_bfv).unwrap();
            pk_bfv.try_encrypt(&pt, &mut thread_rng()).unwrap()
        });
    });

    // Benchmark: Decrypt a single share
    let pt = Plaintext::try_encode(&test_share, Encoding::poly(), &params_bfv).unwrap();
    let ct = pk_bfv.try_encrypt(&pt, &mut thread_rng()).unwrap();

    group.bench_function("decrypt_single_share", |b| {
        b.iter(|| {
            let pt_dec = sk_bfv.try_decrypt(&ct).unwrap();
            let _decoded: Vec<u64> = Vec::<u64>::try_decode(&pt_dec, Encoding::poly()).unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, bench_data_sizes, bench_timing_operations);
criterion_main!(benches);
