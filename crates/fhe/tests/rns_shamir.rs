//! Public-path tests for direct RNS Shamir share generation.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use fhe::bfv::SecretKey;
use fhe::trbfv::ShareManager;

#[path = "../support/mod.rs"]
mod support;

#[test]
fn share_manager_generation_is_deterministic_across_thread_counts() {
    let preset = support::presets::insecure().expect("insecure test parameters must be valid");
    let params = preset.parameters;
    let mut secret_rng = support::presets::rng(7);
    let secret_key = SecretKey::random(&params, &mut secret_rng);

    let generate = |thread_count| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build()
            .unwrap()
            .install(|| {
                let manager = ShareManager::new(5, 2, params.clone()).unwrap();
                let secret = manager
                    .coeffs_to_poly_level0(secret_key.coeffs.as_ref())
                    .unwrap();
                let mut rng = support::presets::rng(99);
                manager
                    .generate_secret_key_shares(secret, &mut rng)
                    .unwrap()
                    .into_transport()
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
