//! Validation tests for direct RNS Shamir operations.

#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

use fhe_math::zq::Modulus;
use itertools::Itertools;
use ndarray::{Array2, array};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::rns_shamir::RnsShamir;

fn moduli() -> Vec<Modulus> {
    [1613, 2017]
        .into_iter()
        .map(|value| Modulus::new(value).unwrap())
        .collect()
}

fn party_matrices(modulus_shares: &[Array2<u64>], party_count: usize) -> Vec<Array2<u64>> {
    let modulus_count = modulus_shares.len();
    let degree = modulus_shares[0].ncols();
    (0..party_count)
        .map(|party_index| {
            Array2::from_shape_fn((modulus_count, degree), |(modulus_index, coefficient)| {
                modulus_shares[modulus_index][[party_index, coefficient]]
            })
        })
        .collect()
}

#[test]
fn reconstructs_every_threshold_subset_and_permutation() {
    let moduli = moduli();
    let shamir = RnsShamir::new(&moduli, 3, 5, 2).unwrap();
    let secrets = array![[1234, 0, 1612], [42, 2016, 900]];
    let mut rng = ChaCha8Rng::seed_from_u64(7);
    let modulus_shares = shamir
        .share(secrets.view(), &mut rng)
        .unwrap()
        .into_matrices();
    let shares = party_matrices(&modulus_shares, 5);

    for subset in (1usize..=5).combinations(3) {
        for ids in subset.into_iter().permutations(3) {
            let selected: Vec<_> = ids.iter().map(|&id| shares[id - 1].view()).collect();
            let recovered = shamir.reconstruct(&selected, &ids).unwrap().into_matrix();
            assert_eq!(recovered, secrets);
        }
    }
}

#[test]
fn sharing_is_independent_of_rayon_thread_count() {
    let moduli = moduli();
    let secrets = array![[12, 34, 56], [78, 90, 123]];

    let generate = |thread_count| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build()
            .unwrap()
            .install(|| {
                let shamir = RnsShamir::new(&moduli, 3, 5, 2).unwrap();
                let mut rng = ChaCha8Rng::seed_from_u64(99);
                shamir
                    .share(secrets.view(), &mut rng)
                    .unwrap()
                    .into_matrices()
            })
    };

    assert_eq!(generate(1), generate(2));
    assert_eq!(generate(1), generate(4));
}

#[test]
fn reconstructs_combined_dealer_contributions() {
    let moduli = moduli();
    let shamir = RnsShamir::new(&moduli, 3, 5, 2).unwrap();
    let first_secret = array![[100, 200, 300], [400, 500, 600]];
    let second_secret = array![[11, 22, 33], [44, 55, 66]];
    let mut first_rng = ChaCha8Rng::seed_from_u64(21);
    let first = shamir
        .share(first_secret.view(), &mut first_rng)
        .unwrap()
        .into_matrices();
    let mut second_rng = ChaCha8Rng::seed_from_u64(22);
    let second = shamir
        .share(second_secret.view(), &mut second_rng)
        .unwrap()
        .into_matrices();
    let mut combined: Vec<Array2<u64>> = (0..5).map(|_| Array2::zeros((2, 3))).collect();

    for (modulus_index, modulus) in moduli.iter().enumerate() {
        for party_index in 0..5 {
            for coefficient_index in 0..3 {
                combined[party_index][[modulus_index, coefficient_index]] = modulus.add(
                    first[modulus_index][[party_index, coefficient_index]],
                    second[modulus_index][[party_index, coefficient_index]],
                );
            }
        }
    }

    let party_ids = [5usize, 2, 4];
    let selected: Vec<_> = party_ids
        .iter()
        .map(|&party_id| combined[party_id - 1].view())
        .collect();
    let recovered = shamir
        .reconstruct(&selected, &party_ids)
        .unwrap()
        .into_matrix();
    for (modulus_index, modulus) in moduli.iter().enumerate() {
        for coefficient_index in 0..3 {
            assert_eq!(
                recovered[[modulus_index, coefficient_index]],
                modulus.add(
                    first_secret[[modulus_index, coefficient_index]],
                    second_secret[[modulus_index, coefficient_index]],
                )
            );
        }
    }
}

#[test]
fn rejects_invalid_inputs() {
    let moduli = moduli();
    assert!(RnsShamir::new(&[], 2, 3, 1).is_err());
    assert!(RnsShamir::new(&moduli, 2, 0, 0).is_err());
    assert!(RnsShamir::new(&moduli, 2, 3, 3).is_err());
    assert!(RnsShamir::new(&moduli, 2, 3, 4).is_err());

    let small_modulus = [Modulus::new(5).unwrap()];
    assert!(RnsShamir::new(&small_modulus, 2, 5, 2).is_err());
    assert!(RnsShamir::new(&small_modulus, 2, 4, 1).is_ok());

    let shamir = RnsShamir::new(&moduli, 2, 3, 1).unwrap();
    assert!(shamir.lagrange_weights(&moduli[0], &[]).is_err());
    let mut rng = ChaCha8Rng::seed_from_u64(4);
    assert!(
        shamir
            .share(Array2::zeros((1, 2)).view(), &mut rng)
            .is_err()
    );

    let valid = Array2::zeros((2, 2));
    let mut noncanonical = valid.clone();
    noncanonical[[1, 0]] = 2017;
    assert!(
        shamir
            .reconstruct(&[valid.view(), noncanonical.view()], &[1, 2])
            .is_err()
    );
    assert!(
        shamir
            .reconstruct(&[valid.view(), valid.view()], &[1, 1])
            .is_err()
    );
    assert!(
        shamir
            .reconstruct(&[valid.view(), valid.view()], &[0, 2])
            .is_err()
    );
}
