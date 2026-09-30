//! Criterion timings for BFV-encrypted threshold-share operations.
//!
//! Share-size and external proof-size estimates are not benchmarks: they do
//! not measure an operation. This target measures only the four operations
//! below, with their setup outside the timed loop where appropriate.

use criterion::{Criterion, criterion_group, criterion_main};
#[path = "../support/mod.rs"]
mod support;
use fhe::bfv::{Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::ShareManager;
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use rand::rng as make_rng;
use std::hint::black_box;

fn bench_timing_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("BFV Encrypted Shares Timing");
    let preset = support::presets::secure8192().unwrap();
    let params_trbfv = preset.parameters.clone();
    let params_bfv = preset.encrypted_share_parameters().unwrap();
    let degree = params_trbfv.degree();

    let num_parties = 3;
    let threshold = 1; // must be exactly (n - 1) / 2
    let mut rng = make_rng();

    group.bench_function("generate_bfv_keypair", |b| {
        b.iter(|| {
            let sk = SecretKey::random(&params_bfv, &mut rng);
            let pk = PublicKey::new(&sk, &mut rng);
            black_box((sk, pk))
        });
    });

    let secret_key = SecretKey::random(&params_trbfv, &mut rng);

    group.bench_function("generate_and_export_shamir_shares", |b| {
        let share_manager =
            ShareManager::new(num_parties, threshold, params_trbfv.clone()).unwrap();
        let secret_key_poly = share_manager
            .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
            .unwrap();

        b.iter(|| {
            black_box(
                share_manager
                    .generate_secret_key_shares(secret_key_poly.clone(), &mut rng)
                    .unwrap()
                    .into_transport(),
            )
        });
    });

    let sk_bfv = SecretKey::random(&params_bfv, &mut make_rng());
    let pk_bfv = PublicKey::new(&sk_bfv, &mut make_rng());
    // Representative polynomial-length payload, not a measured share-dealing
    // protocol. Encoding is setup; the timed operation is encryption alone.
    let test_share: Vec<u64> = (0..degree).map(|i| i as u64 % 1000).collect();
    let pt = Plaintext::try_encode(&test_share, Encoding::poly(), &params_bfv).unwrap();

    group.bench_function("encrypt_single_share", |b| {
        b.iter(|| black_box(pk_bfv.try_encrypt(&pt, &mut rng).unwrap()));
    });

    let ct = pk_bfv.try_encrypt(&pt, &mut rng).unwrap();

    group.bench_function("decrypt_single_share", |b| {
        b.iter(|| {
            let pt_dec = sk_bfv.try_decrypt(&ct).unwrap();
            let decoded: Vec<u64> = Vec::<u64>::try_decode(&pt_dec, Encoding::poly()).unwrap();
            black_box(decoded)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_timing_operations);
criterion_main!(benches);
