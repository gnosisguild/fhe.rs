//! Threshold BFV addition over encrypted integers.
//!
//! Parties generate distributed keys, encrypt a batch of values, homomorphically
//! sum them, and decrypt the tally via threshold decryption with Shamir secret
//! sharing. Run with `--help` for CLI options (`--num_summed`, `--num_parties`,
//! `--threshold`, `--lambda`).

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use console::style;
use fhe::{
    bfv::{self, Ciphertext, CommonRandomPoly, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, PublicKeyShare},
    trbfv::{
        ContributionBinding, DecryptionShare, KeyShareContribution, Lambda, NoiseShareContribution,
        NoiseShareMatrix, ParticipantSet, SecretShareMatrix, SessionId, ShareManager,
        SmudgingCoefficients, TRBFV,
    },
};

use fhe_math::rq::PowerBasis;
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use rand_distr::{Distribution, Uniform};
use rayon::prelude::*;
use std::time::Instant;
use util::timeit::{timeit, timeit_n};

fn print_notice_and_exit(error: Option<String>) {
    println!(
        "{} Addition with threshold BFV",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} add [-h] [--help] [--num_summed=<value>] [--num_parties=<value>] [--threshold=<value>]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} {} {} and {} must be at least 1",
        style("constraints:").magenta().bold(),
        style("num_summed").blue(),
        style("num_parties").blue(),
        style("threshold").blue(),
    );
    if let Some(error) = error {
        println!("{} {}", style("     error:").red().bold(), error);
    }
    exit(0);
}

fn main() -> Result<(), Box<dyn Error>> {
    // BFV parameters
    let degree = 8192;
    let plaintext_modulus: u64 = 1000;
    let moduli = vec![
        0x00800000022a0001,
        0x00800000021a0001,
        0x0080000002120001,
        0x0080000001f60001,
    ];

    let params = timeit!(
        "Parameters generation",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .set_variance(10)?
            .set_error1_variance_str(
                "52309181128222339698631578526730685514457152477762943514050560000"
            )?
            .build_arc()?
    );

    // This executable is a command line tool which enables to specify
    // trBFV summations with party and threshold sizes.
    let args: Vec<String> = env::args().skip(1).collect();

    // Print the help if requested.
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_summed = 100;
    let mut num_parties = 10;
    let mut threshold = 4;
    let mut lambda = 80;

    // Update the number of users and/or number of parties / threshold depending on the
    // arguments provided.
    for arg in &args {
        if arg.starts_with("--num_summed") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_summed` argument".to_string()))
            } else {
                num_summed = a[0].parse::<usize>()?
            }
        } else if arg.starts_with("--num_parties") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_parties` argument".to_string()))
            } else {
                num_parties = a[0].parse::<usize>()?
            }
        } else if arg.starts_with("--threshold") {
            let parts: Vec<&str> = arg.rsplit('=').collect();
            if parts.len() != 2 || parts[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--threshold` argument".to_string()))
            } else {
                threshold = parts[0].parse::<usize>()?
            }
        } else if arg.starts_with("--lambda") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--lambda` argument".to_string()))
            } else {
                lambda = a[0].parse::<usize>()?
            }
        } else {
            print_notice_and_exit(Some(format!("Unrecognized argument: {arg}")))
        }
    }

    if num_summed == 0 || num_parties == 0 || lambda == 0 {
        print_notice_and_exit(Some(
            "Users, threshold, party sizes, and lambda must be nonzero".to_string(),
        ))
    }
    if threshold != (num_parties - 1) / 2 {
        print_notice_and_exit(Some(
            "Threshold must be exactly (num_parties - 1) / 2: maximal corruption tolerance with honest-majority reconstruction".to_string(),
        ))
    }

    // The parameters are within bound, let's go! Let's first display some
    // information about the threshold sum.
    // Secure example: rejects lambda below the secure minimum. See
    // trbfv_add_bfv_share_insecure.rs for the explicit insecure test mode.
    let security = Lambda::secure(lambda)?;

    println!("# Addition with trBFV");
    println!("\tnum_summed = {num_summed}");
    println!("\tnum_parties = {num_parties}");
    println!("\tthreshold = {threshold}");
    println!("\tlambda = {lambda}");

    // Party setup: each party generates a secret key and shares of a collective
    // public key.
    struct Party {
        pk_share: PublicKeyShare,
        sk_sss: Vec<SecretShareMatrix>,
        esi_sss: Vec<NoiseShareMatrix>,
        sk_sss_collected: Vec<SecretShareMatrix>,
        es_sss_collected: Vec<NoiseShareMatrix>,
        sk_poly_sum: Option<fhe::trbfv::AggregatedKeyShare<PowerBasis>>,
        es_poly_sum: Option<fhe::trbfv::OneTimeNoiseShare>,
        d_share_poly: Option<DecryptionShare>,
    }

    // Generate a common reference poly for public key generation.
    let mut rng = rand::rng();
    let crp = CommonRandomPoly::new(&params, &mut rng)?;

    // Setup trBFV module
    let trbfv = TRBFV::new(num_parties, threshold, params.clone()).unwrap();
    let participant_set = ParticipantSet::new(
        SessionId::new(rand::random()),
        (1..=num_parties as u32).collect(),
    )?;
    let use_session = SessionId::new(rand::random());

    // Set up shares for each party in parallel
    println!("💻 Available CPU cores: {}", rayon::current_num_threads());
    let mut parties: Vec<Party> = timeit!("Party setup (parallel)", {
        (0..num_parties)
            .into_par_iter()
            .map(|party_idx| {
                // Each thread gets its own RNG to avoid contention
                let mut rng = rand::rng();

                let sk_share = SecretKey::random(&params, &mut rng);
                // MBFV public-key shares require a per-party contribution binding.
                let pk_binding =
                    ContributionBinding::new(participant_set.clone(), (party_idx + 1) as u32)
                        .unwrap();
                let pk_share =
                    PublicKeyShare::new(&sk_share, crp.clone(), pk_binding, &mut rng).unwrap();

                let mut share_manager =
                    ShareManager::new(num_parties, threshold, params.clone()).unwrap();
                let sk_poly = share_manager
                    .coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())
                    .unwrap();

                // Clone trbfv for thread safety (it's cheap since it's just config)
                let sk_sss = trbfv
                    .generate_secret_shares_from_poly(sk_poly, &mut rng)
                    .unwrap();

                // vec of 3 moduli and array2 for num_parties rows of coeffs and degree columns
                let sk_sss_collected: Vec<SecretShareMatrix> = Vec::with_capacity(num_parties);
                let es_sss_collected: Vec<NoiseShareMatrix> = Vec::with_capacity(num_parties);
                let esi_coeffs: SmudgingCoefficients = trbfv
                    .generate_smudging_error(num_summed, 0, security, &mut rng)
                    .unwrap();
                let esi_poly = share_manager.bigints_to_poly(esi_coeffs).unwrap();
                let esi_sss = share_manager
                    .generate_noise_shares_from_poly(esi_poly, &mut rng)
                    .unwrap();

                Party {
                    pk_share,
                    sk_sss,
                    esi_sss,
                    sk_sss_collected,
                    es_sss_collected,
                    sk_poly_sum: None,
                    es_poly_sum: None,
                    d_share_poly: None,
                }
            })
            .collect()
    });

    // Swap shares mocking network comms, party 1 sends share 2 to party 2 etc.
    let mut i = 0;
    timeit_n!(
        "Simulating network (share swapping per party)",
        num_parties as u32,
        {
            for j in 0..num_parties {
                let node_share_rows = (0..params.moduli().len())
                    .map(|m| parties[j].sk_sss[m].row(i).unwrap())
                    .collect::<Vec<_>>();
                let es_node_share_rows = (0..params.moduli().len())
                    .map(|m| parties[j].esi_sss[m].row(i).unwrap())
                    .collect::<Vec<_>>();
                let node_share_m = SecretShareMatrix::from_rows(&node_share_rows).unwrap();
                let es_node_share_m = NoiseShareMatrix::from_rows(&es_node_share_rows).unwrap();
                parties[i].sk_sss_collected.push(node_share_m);
                parties[i].es_sss_collected.push(es_node_share_m);
            }
            i += 1;
        }
    );

    timeit!("Sum collected shares (parallel)", {
        parties.par_iter_mut().for_each(|party| {
            let key_contributions = party
                .sk_sss_collected
                .iter()
                .enumerate()
                .map(|(index, matrix)| {
                    KeyShareContribution::new(
                        ContributionBinding::new(participant_set.clone(), (index + 1) as u32)
                            .unwrap(),
                        matrix.clone(),
                    )
                })
                .collect::<Vec<_>>();
            party.sk_poly_sum = Some(
                trbfv
                    .aggregate_collected_shares(&participant_set, &key_contributions)
                    .unwrap(),
            );
            let noise_contributions = std::mem::take(&mut party.es_sss_collected)
                .into_iter()
                .enumerate()
                .map(|(index, matrix)| {
                    NoiseShareContribution::new(
                        ContributionBinding::new(participant_set.clone(), (index + 1) as u32)
                            .unwrap(),
                        matrix,
                    )
                })
                .collect();
            party.es_poly_sum = Some(
                trbfv
                    .aggregate_noise_shares(&participant_set, use_session, noise_contributions)
                    .unwrap(),
            );
        });
    });

    // Aggregation: same as previous mbfv aggregations
    let pk = timeit!("Public key aggregation", {
        let pk: PublicKey = parties.iter().map(|p| p.pk_share.clone()).aggregate()?;
        pk
    });

    // Encrypted addition setup.
    let dist = Uniform::new_inclusive(0, 1).unwrap();
    let numbers: Vec<u64> = dist.sample_iter(&mut rng).take(num_summed).collect();

    let numbers_encrypted: Vec<Ciphertext> = timeit!("Encrypting Numbers (parallel)", {
        numbers
            .par_iter()
            .map(|&number| {
                let mut rng = rand::rng();
                let pt = Plaintext::try_encode(&[number], Encoding::poly(), &params).unwrap();
                pk.try_encrypt(&pt, &mut rng).unwrap()
            })
            .collect()
    });

    // calculation
    let tally = timeit!("Number tallying", {
        let mut sum = Ciphertext::zero(&params);
        for ct in &numbers_encrypted {
            sum += ct;
        }
        Arc::new(sum)
    });

    // Measure decryption share generation (average per party)
    let share_generation_start = Instant::now();

    parties
        .par_iter_mut()
        .enumerate()
        .try_for_each(|(party_index, party)| -> fhe::Result<()> {
            party.d_share_poly = Some(trbfv.decryption_share(
                tally.clone(),
                (party_index + 1) as u32,
                party.sk_poly_sum.take().unwrap().into_ntt()?,
                use_session,
                party.es_poly_sum.take().unwrap(),
            )?);
            Ok(())
        })?;

    let total_share_generation_time = share_generation_start.elapsed();
    let avg_time_per_party = total_share_generation_time.as_millis() as f64 / num_parties as f64;

    println!("Decryption share generation:");
    println!(
        "  Total time (parallel): {:.2?}",
        total_share_generation_time
    );
    println!("  Average time per party: {:.2} ms", avg_time_per_party);

    // Gather decryption shares from threshold+1 parties
    let d_share_polys: Vec<DecryptionShare> = parties
        .iter_mut()
        .take(threshold + 1)
        .map(|party| party.d_share_poly.take().unwrap())
        .collect();

    // decrypt result
    let result = timeit!("Threshold decrypt (combine shares)", {
        // Parties are 1-based for Shamir x-coordinates; we used the first (threshold+1) parties
        let open_results = trbfv.decrypt(d_share_polys, tally.clone()).unwrap();
        let result_vec = Vec::<u64>::try_decode(&open_results, Encoding::poly())?;
        Ok::<u64, Box<dyn Error>>(result_vec[0])
    })?;

    // Verify correctness
    let expected_result: u64 = numbers.iter().sum();
    println!("Computed result: {result}");
    println!("Expected result: {expected_result}");

    assert_eq!(result, expected_result, "Threshold computation failed!");
    println!("Threshold BFV computation successful!");

    Ok(())
}
