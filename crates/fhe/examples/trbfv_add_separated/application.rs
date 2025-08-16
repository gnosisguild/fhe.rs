use std::{array, sync::Arc};

use fhe::bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey};
use fhe::trbfv::smudging::{SmudgingBoundCalculator, SmudgingBoundCalculatorConfig};
use fhe_traits::{FheEncoder, FheEncrypter};
use num_bigint::BigUint;
use rand::{distributions::Uniform, prelude::Distribution, thread_rng};
use rayon::prelude::*;

/// Each Voter encrypts `NUM_VOTES_PER_VOTER` random bits and returns the ciphertexts along with
/// the underlying plaintexts for verification.
pub fn generate_ciphertexts<const NUM_VOTES_PER_VOTER: usize>(
    pk: &PublicKey,
    params: Arc<bfv::BfvParameters>,
    num_voters: usize,
    num_votes_per_voter: usize,
) -> (Vec<[Ciphertext; NUM_VOTES_PER_VOTER]>, Vec<[u64; NUM_VOTES_PER_VOTER]>) {
    let dist = Uniform::new_inclusive(0, 1);
    let mut rng = thread_rng();
    let numbers: Vec<[u64; NUM_VOTES_PER_VOTER]> = (0..num_voters)

        .map(|_| array::from_fn(|_| dist.sample(&mut rng)))


        .collect();

    let ciphertexts: Vec<[Ciphertext; NUM_VOTES_PER_VOTER]> = numbers
        .par_iter()
        .map(|vals| {
            let mut rng = thread_rng();

            array::from_fn(|j| {
                let pt = Plaintext::try_encode(&[vals[j]], Encoding::poly(), &params).unwrap();
                pk.try_encrypt(&pt, &mut rng).unwrap()
            })

        })
        .collect();

    (ciphertexts, numbers)
}

/// Tally the submitted ciphertexts column-wise to produce three aggregated sums.
pub fn run_application<const NUM_VOTES_PER_VOTER: usize>(
    ciphertexts: &[[Ciphertext; NUM_VOTES_PER_VOTER]],
    params: Arc<bfv::BfvParameters>,
) -> Vec<Arc<Ciphertext>> {
    let mut sums: Vec<Ciphertext> = (0..NUM_VOTES_PER_VOTER)
        .map(|_| Ciphertext::zero(&params))
        .collect();

    for ct_group in ciphertexts {
        for j in 0..NUM_VOTES_PER_VOTER {
            sums[j] += &ct_group[j];
        }
    }

    sums.into_iter().map(Arc::new).collect()
}

/// Compute the application-specific smudging error size for a given number of ciphertexts.
pub fn calculate_error_size(
    params: Arc<bfv::BfvParameters>,
    n: usize,
    num_ciphertexts: usize,
) -> BigUint {
    let config = SmudgingBoundCalculatorConfig::new(params, n, num_ciphertexts);
    let calculator = SmudgingBoundCalculator::new(config);
    calculator.calculate_sm_bound().unwrap()
}
