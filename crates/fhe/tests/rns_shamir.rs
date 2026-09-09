//! Public-path tests for direct RNS Shamir share generation.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use fhe::bfv::SecretKey;
use fhe::trbfv::ShareManager;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[path = "../support/mod.rs"]
mod support;

#[test]
fn share_manager_generation_is_deterministic_across_thread_counts() {
    let preset = support::insecure().expect("insecure test parameters must be valid");
    let params = preset.parameters;
    let mut secret_rng = ChaCha8Rng::seed_from_u64(7);
    let secret_key = SecretKey::random(&params, &mut secret_rng);

    let generate = |thread_count| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build()
            .unwrap()
            .install(|| {
                let mut manager = ShareManager::new(5, 2, params.clone()).unwrap();
                let secret = manager
                    .coeffs_to_poly_level0(secret_key.coeffs.as_ref())
                    .unwrap();
                let mut rng = ChaCha8Rng::seed_from_u64(99);
                manager
                    .generate_secret_shares_from_poly(secret, &mut rng)
                    .unwrap()
            })
    };

    let shares = generate(1);
    assert_eq!(shares, generate(2));
    assert_eq!(shares, generate(4));
    assert_eq!(shares.len(), params.moduli().len());
    for (matrix, &modulus) in shares.iter().zip(params.moduli()) {
        assert_eq!(matrix.dim(), (5, params.degree()));
        assert!(matrix.iter().all(|&value| value < modulus));
    }
}
