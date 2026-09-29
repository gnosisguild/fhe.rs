//! Share-transport plaintext-modulus regression tests (issue #253).
//!
//! Encrypted share transport encodes each Shamir share residue as a BFV
//! plaintext under a separate parameter set. BFV encoding reduces
//! coefficients modulo the share-encryption plaintext modulus, so exact
//! transport requires that modulus to exceed every transported canonical
//! residue `r ∈ [0, q_i)`, i.e. `t_transport ≥ max(q_i)` across the
//! computation moduli whose shares are transported. A residue
//! `r ≥ t_transport` silently wraps to `r mod t_transport` at encoding
//! time, so callers must verify the inequality (or otherwise bound the
//! share values) before transporting.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../support/mod.rs"]
mod support;

use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use rand::Rng;
use support::presets::Preset;

fn profiles() -> [Preset; 3] {
    support::presets::profiles().unwrap()
}

/// Every supported profile must ship share-transport parameters whose
/// plaintext modulus covers the largest computation modulus. This also pins
/// the examples' claim `k = q[0] = max(q_i)`: the transport plaintext modulus
/// equals the first (largest) computation modulus.
#[test]
fn share_transport_plaintext_covers_computation_moduli() {
    for profile in profiles() {
        let share_parameters = profile
            .share_parameters
            .clone()
            .expect("profile must ship share-transport parameters");
        let moduli = profile.parameters.moduli();
        let max_modulus = moduli.iter().copied().max().unwrap();
        assert_eq!(
            moduli.first().copied(),
            Some(max_modulus),
            "profile {} documents k = q[0]; q[0] must remain the largest \
             computation modulus",
            profile.name
        );
        assert!(
            share_parameters.plaintext() >= max_modulus,
            "profile {} share-transport plaintext modulus {} must cover every \
             transported canonical residue (largest computation modulus {}); \
             smaller values silently wrap during encoding",
            profile.name,
            share_parameters.plaintext(),
            max_modulus
        );
    }
}

/// The highest canonical residue of each supported profile — `max(q_i) - 1`,
/// transported as a full row — must round-trip exactly through
/// BFV-encrypted share transport.
#[test]
fn highest_canonical_residue_round_trips_exactly() {
    for profile in profiles() {
        let share_parameters = profile
            .share_parameters
            .clone()
            .expect("profile must ship share-transport parameters");
        let max_modulus = profile
            .parameters
            .moduli()
            .iter()
            .copied()
            .max()
            .expect("computation parameters always define at least one modulus");
        let degree = share_parameters.degree();

        // A transported share row whose coefficients all sit in the highest
        // band of canonical residues, including the exact boundary residue
        // `max(q_i) - 1` (representable iff the transport plaintext modulus
        // exceeds that value).
        let mut rng = support::presets::rng(7);
        let row: Vec<u64> = (0..degree)
            .map(|index| {
                if index == 0 {
                    max_modulus - 1
                } else {
                    rng.random_range(max_modulus - 1024..max_modulus)
                }
            })
            .collect();

        let secret_key = SecretKey::random(&share_parameters, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng);
        let plaintext = Plaintext::try_encode(&row, Encoding::poly(), &share_parameters).unwrap();
        let ciphertext = public_key.try_encrypt(&plaintext, &mut rng).unwrap();
        let decoded = Vec::<u64>::try_decode(
            &secret_key.try_decrypt(&ciphertext).unwrap(),
            Encoding::poly(),
        )
        .unwrap();
        assert_eq!(
            decoded, row,
            "profile {} share transport must be exact for the highest canonical \
             residue max(q_i) - 1",
            profile.name
        );
    }
}

/// A transport plaintext modulus smaller than the computation moduli silently
/// wraps high residues at encoding time; the documented caller-side guard
/// `r < t_transport` must flag every such residue before any encryption,
/// while residues below the transport modulus still round-trip exactly.
#[test]
fn undersized_transport_modulus_is_detectable_before_encoding() {
    let profile = profiles().first().cloned().unwrap();
    let max_modulus = profile
        .parameters
        .moduli()
        .iter()
        .copied()
        .max()
        .expect("computation parameters always define at least one modulus");
    // Deliberately undersized (and degree-128 NTT-friendly) transport modulus.
    let undersized: u64 = 65_537;
    assert!(
        undersized < max_modulus,
        "test premise: transport modulus must not cover the computation moduli"
    );
    let share_parameters = BfvParametersBuilder::new()
        .set_degree(profile.parameters.degree())
        .set_plaintext_modulus(undersized)
        .set_moduli(support::presets::insecure_128::share_enc::MODULI)
        .set_variance(support::presets::insecure_128::share_enc::VARIANCE)
        .build_arc()
        .unwrap();

    let mut rng = support::presets::rng(11);
    let secret_key = SecretKey::random(&share_parameters, &mut rng);
    let public_key = PublicKey::new(&secret_key, &mut rng);

    let mut round_trip = |value: u64| -> u64 {
        let row = vec![value; share_parameters.degree()];
        let plaintext = Plaintext::try_encode(&row, Encoding::poly(), &share_parameters).unwrap();
        let ciphertext = public_key.try_encrypt(&plaintext, &mut rng).unwrap();
        Vec::<u64>::try_decode(
            &secret_key.try_decrypt(&ciphertext).unwrap(),
            Encoding::poly(),
        )
        .unwrap()
        .first()
        .copied()
        .expect("decoded row must contain the constant coefficient")
    };

    // The highest canonical residue exceeds the undersized modulus and wraps
    // silently at encoding time: transport is no longer exact.
    let high = max_modulus - 1;
    assert!(
        high >= undersized,
        "test premise: highest residue must exceed the undersized modulus"
    );
    assert_ne!(
        round_trip(high),
        high,
        "encoding must wrap residues >= the transport plaintext modulus"
    );
    assert_eq!(round_trip(high), high % undersized);

    // The same residue is detectable by the caller-side guard before any
    // encoding happens: `r < t_transport` rejects it.
    assert!(high >= undersized);

    // Residues below the transport modulus remain representable and exact.
    assert_eq!(round_trip(undersized - 1), undersized - 1);
}
