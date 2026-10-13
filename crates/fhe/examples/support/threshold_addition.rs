//! Complete shared workflow for the three threshold-addition examples.

#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

#[path = "simulated_key_setup.rs"]
#[allow(dead_code)]
mod simulated_key_setup;

use fhe::bfv::{
    BfvParametersBuilder, Ciphertext, CommonRandomPoly, Encoding, Plaintext, PublicKey, SecretKey,
};
use fhe::mbfv::{AggregateIter, PublicKeyShare};
use fhe::trbfv::{
    DecryptionShare, Lambda, ShareManager, SmudgingBoundCalculatorConfig, SmudgingNoiseGenerator,
    SynchronizedDecryptor,
};
use fhe_math::rq::{Ntt, Poly};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use ndarray::Array2;
use rand_distr::{Distribution, Uniform};
use rayon::prelude::*;
use std::{error::Error, time::Instant};
use zeroize::{Zeroize, Zeroizing};

pub fn run(encrypted_shares: bool, insecure: bool) -> Result<(), Box<dyn Error>> {
    let (mut num_summed, mut num_parties, mut threshold, mut lambda) = if insecure {
        (3, 5, 2, 2)
    } else {
        (50, 7, 3, 45)
    };
    for arg in std::env::args().skip(1) {
        if arg == "--help" || arg == "-h" {
            println!(
                "Threshold BFV addition: --num_summed=N --num_parties=N --threshold=T --lambda=L\n\
                 Requires n >= 3, T = (n - 1) / 2, and positive addition fan-in.\n\
                 Defaults: m={num_summed}, n={num_parties}, T={threshold}, lambda={lambda}"
            );
            return Ok(());
        }
        let (name, value) = arg.split_once('=').ok_or("expected --option=value")?;
        let value = value.parse::<usize>()?;
        match name {
            "--num_summed" => num_summed = value,
            "--num_parties" => num_parties = value,
            "--threshold" => threshold = value,
            "--lambda" => lambda = value,
            _ => return Err(format!("unrecognized argument: {arg}").into()),
        }
    }
    let security = if insecure {
        eprintln!("WARNING: insecure lambda; this noise does not statistically hide decryption.");
        Lambda::insecure(lambda)
    } else {
        Lambda::secure(lambda)?
    };
    let params = BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus(1_000_000)
        .set_moduli(&[0x0400000000c00001, 0x0400000000a40001, 0x0400000000990001])
        .set_variance(10)
        .set_error1_variance_str("17723039943798878305384094137071261013333")?
        .build_arc()?;
    let manager = ShareManager::new(num_parties, threshold, params.clone())?;
    let decryptor = SynchronizedDecryptor::new(num_parties, threshold, params.clone())?;
    let noise = SmudgingNoiseGenerator::new(SmudgingBoundCalculatorConfig::new(
        params.clone(),
        num_parties,
        num_summed,
        security,
    )?)?;
    println!(
        "# Synchronized threshold BFV addition: m={num_summed}, n={num_parties}, T={threshold}, lambda={lambda}"
    );

    let mut rng = rand::rng();
    let crp = CommonRandomPoly::new(&params, &mut rng)?;
    let start = Instant::now();
    let (pk_shares, mut dealt): (Vec<_>, Vec<_>) = (0..num_parties)
        .into_par_iter()
        .map(|_| {
            let mut rng = rand::rng();
            let key = SecretKey::random(&params, &mut rng);
            let pk = PublicKeyShare::new(&key, crp.clone(), &mut rng).unwrap();
            let mut manager = ShareManager::new(num_parties, threshold, params.clone()).unwrap();
            let poly = manager.coeffs_to_poly_level0(key.coeffs.as_ref()).unwrap();
            let shares = manager
                .generate_secret_shares_from_poly(poly, &mut rng)
                .unwrap();
            (pk, shares)
        })
        .unzip();
    println!("Distributed key setup: {:?}", start.elapsed());
    let pk: PublicKey = pk_shares.into_iter().aggregate()?;

    // Optional BFV transport protects key material only. Authentication, proofs,
    // key epochs and session/replay handling must be supplied by the application.
    let transport = if encrypted_shares {
        let params = BfvParametersBuilder::new()
            .set_degree(8192)
            .set_plaintext_modulus(288230376164294657)
            .set_moduli(&[0x1000000000024001, 0x1000000000054001])
            .set_variance(10)
            .build_arc()?;
        let keys: Vec<_> = (0..num_parties)
            .map(|_| {
                let sk = SecretKey::random(&params, &mut rng);
                let pk = PublicKey::new(&sk, &mut rng);
                (sk, pk)
            })
            .collect();
        Some((params, keys))
    } else {
        None
    };
    let start = Instant::now();
    let key_shares: Vec<Zeroizing<Poly<Ntt>>> = (0..num_parties)
        .into_par_iter()
        .map(|recipient| {
            let mut collected: Vec<Array2<u64>> = dealt
                .iter()
                .map(|sender| {
                    let mut matrix = Array2::zeros((params.moduli().len(), params.degree()));
                    for (row, shares) in sender.iter().enumerate() {
                        let mut values = Zeroizing::new(shares.row(recipient).to_vec());
                        if let Some((transport_params, keys)) = &transport {
                            let pt = Plaintext::try_encode(
                                values.as_slice(),
                                Encoding::poly(),
                                transport_params,
                            )
                            .unwrap();
                            let ct = keys[recipient]
                                .1
                                .try_encrypt(&pt, &mut rand::rng())
                                .unwrap();
                            let pt = keys[recipient].0.try_decrypt(&ct).unwrap();
                            let restored = Zeroizing::new(
                                Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap(),
                            );
                            assert_eq!(*values, *restored, "key-share transport corrupted a row");
                            values.zeroize();
                            values = restored;
                        }
                        for (cell, &value) in matrix.row_mut(row).iter_mut().zip(values.iter()) {
                            *cell = value;
                        }
                    }
                    matrix
                })
                .collect();
            let key = manager.aggregate_collected_shares(&collected).unwrap();
            for matrix in &mut collected {
                matrix.iter_mut().for_each(Zeroize::zeroize);
            }
            Zeroizing::new(key.into_ntt())
        })
        .collect();
    for sender in &mut dealt {
        for matrix in sender {
            matrix.iter_mut().for_each(Zeroize::zeroize);
        }
    }
    println!("Key-share transport and aggregation: {:?}", start.elapsed());

    // Local simulation only, NOT distributed key establishment.
    let prf_keys = simulated_key_setup::simulated_committee_prf_keys(num_parties, &mut rng)?;
    let numbers: Vec<u64> = Uniform::new_inclusive(0, 1)?
        .sample_iter(&mut rng)
        .take(num_summed)
        .collect();
    let ciphertexts: Vec<_> = numbers
        .par_iter()
        .map(|&value| {
            let pt = Plaintext::try_encode(&[value], Encoding::poly(), &params).unwrap();
            pk.try_encrypt(&pt, &mut rand::rng()).unwrap()
        })
        .collect();
    let mut tally = Ciphertext::zero(&params);
    for ct in &ciphertexts {
        tally += ct;
    }
    let designated: Vec<_> = (1..=threshold + 1).collect();
    let start = Instant::now();
    let partials: Vec<DecryptionShare> = designated
        .par_iter()
        .map(|&id| {
            // Fresh local noise for each call; no noise transport or later weighting.
            decryptor
                .decryption_share(
                    &tally,
                    &key_shares[id - 1],
                    id,
                    &designated,
                    noise.generate(&mut rand::rng()).unwrap(),
                    &prf_keys[id - 1],
                )
                .unwrap()
        })
        .collect();
    println!(
        "Partial decryption ({} parties): {:?}",
        designated.len(),
        start.elapsed()
    );
    let result = decryptor.decrypt_from_shares(&partials, &tally)?;
    let found = Vec::<u64>::try_decode(&result, Encoding::poly())?;
    let expected: u64 = numbers.iter().sum();
    assert_eq!(found[0], expected, "threshold computation failed");
    println!("Computed result: {}, expected: {expected}", found[0]);
    Ok(())
}
