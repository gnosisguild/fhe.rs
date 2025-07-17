// Implementation of threshold addition using the `fhe` and `trbfv` crate.

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use console::style;
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, PublicKeyShare},
    trbfv::{ShareManager, TRBFV},
};
use fhe_math::rq::{Poly, Representation};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::{Array, Array2, ArrayView};
use rand::{distributions::Uniform, prelude::Distribution, rngs::OsRng, thread_rng};
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
    // Parameters
    let degree = 4096;
    let plaintext_modulus: u64 = 65537;
    let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];

    // This executable is a command line tool which enables to specify
    // trBFV summations with party and threshold sizes.
    let args: Vec<String> = env::args().skip(1).collect();

    // Print the help if requested.
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_summed = 5;
    let mut num_parties = 10;
    let mut threshold = 7;

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
        } else {
            print_notice_and_exit(Some(format!("Unrecognized argument: {arg}")))
        }
    }

    if num_summed == 0 || num_parties == 0 || threshold == 0 {
        print_notice_and_exit(Some(
            "Users, threshold, and party sizes must be nonzero".to_string(),
        ))
    }
    if threshold >= num_parties {
        print_notice_and_exit(Some(
            "Threshold must be less than number of parties".to_string(),
        ))
    }

    // The parameters are within bound, let's go! Let's first display some
    // information about the threshold sum.
    println!("# Addition with trBFV");
    println!("\tnum_summed = {num_summed}");
    println!("\tnum_parties = {num_parties}");
    println!("\tthreshold = {threshold}");

    // Let's generate the BFV parameters structure. This will be shared between parties
    let params = timeit!(
        "Parameters generation",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()?
    );

    // Party setup: each party generates a secret key and shares of a collective
    // public key.
    struct Party {
        pk_share: PublicKeyShare,
        sk_sss: Vec<Array2<u64>>,
        esi_sss: Vec<Array2<u64>>,
        sk_sss_collected: Vec<Array2<u64>>,
        es_sss_collected: Vec<Array2<u64>>,
        sk_poly_sum: Poly,
        es_poly_sum: Poly,
        d_share_poly: Poly,
    }
    let mut parties = Vec::with_capacity(num_parties);

    // Generate a common reference poly for public key generation.
    let crp = CommonRandomPoly::new(&params, &mut thread_rng())?;

    // Setup trBFV module
    let mut trbfv = TRBFV::new(num_parties, threshold, params.clone()).unwrap();

    // Set up shares for each party.
    timeit_n!("Party setup (per party)", num_parties as u32, {
        let sk_share = SecretKey::random(&params, &mut OsRng);
        let pk_share = PublicKeyShare::new(&sk_share, crp.clone(), &mut thread_rng())?;
        let sk_sss = trbfv.generate_secret_shares(sk_share.coeffs.clone())?;

        // vec of 3 moduli and array2 for num_parties rows of coeffs and degree columns
        let sk_sss_collected: Vec<Array2<u64>> = Vec::with_capacity(num_parties);
        let es_sss_collected: Vec<Array2<u64>> = Vec::with_capacity(num_parties);
        let sk_poly_sum = Poly::zero(params.ctx_at_level(0).unwrap(), Representation::PowerBasis);
        let es_poly_sum = Poly::zero(params.ctx_at_level(0).unwrap(), Representation::PowerBasis);
        let d_share_poly = Poly::zero(params.ctx_at_level(0).unwrap(), Representation::PowerBasis);

        let esi_coeffs = trbfv.generate_smudging_error(
            num_summed,
            es_poly_sum.clone(),
            sk_poly_sum.clone(),
            &mut OsRng,
        )?;
        let share_manager = ShareManager::new(num_parties, threshold, params.clone());
        let esi_poly: Poly = share_manager.bigints_to_poly(&esi_coeffs)?;
        let esi_sss = trbfv.generate_secret_shares(
            esi_poly
                .coefficients()
                .as_slice()
                .unwrap()
                .iter()
                .map(|&x| x as i64)
                .collect::<Vec<i64>>()
                .into_boxed_slice(),
        )?;

        parties.push(Party {
            pk_share,
            sk_sss,
            esi_sss,
            sk_sss_collected,
            es_sss_collected,
            sk_poly_sum,
            es_poly_sum,
            d_share_poly,
        });
    });

    // Swap shares mocking network comms, party 1 sends share 2 to party 2 etc.
    let mut i = 0;
    timeit_n!(
        "Simulating network (share swapping per party)",
        num_parties as u32,
        {
            for j in 0..num_parties {
                let mut node_share_m = Array::zeros((0, degree));
                let mut es_node_share_m = Array::zeros((0, degree));
                for m in 0..moduli.len() {
                    node_share_m
                        .push_row(ArrayView::from(&parties[j].sk_sss[m].row(i).clone()))
                        .unwrap();
                    es_node_share_m
                        .push_row(ArrayView::from(&parties[j].esi_sss[m].row(i).clone()))
                        .unwrap();
                }
                parties[i].sk_sss_collected.push(node_share_m);
                parties[i].es_sss_collected.push(es_node_share_m);
            }
            i += 1;
        }
    );

    i = 0;
    // For each party, convert shares to polys and sum the collected shares.
    timeit_n!("Sum collected shares (per party)", num_parties as u32, {
        parties[i].sk_poly_sum = trbfv
            .aggregate_collected_shares(&parties[i].sk_sss_collected)
            .unwrap();
        parties[i].es_poly_sum = trbfv
            .aggregate_collected_shares(&parties[i].es_sss_collected)
            .unwrap();
        i += 1;
    });

    // Aggregation: same as previous mbfv aggregations
    let pk = timeit!("Public key aggregation", {
        let pk: PublicKey = parties.iter().map(|p| p.pk_share.clone()).aggregate()?;
        pk
    });

    // Encrypted addition setup.
    let dist = Uniform::new_inclusive(0, 1);
    let numbers: Vec<u64> = dist
        .sample_iter(&mut thread_rng())
        .take(num_summed)
        .collect();
    let mut numbers_encrypted = Vec::with_capacity(num_summed);
    let mut _i = 0;
    timeit_n!("Encrypting Numbers (per encryption)", num_summed as u32, {
        #[allow(unused_assignments)]
        let pt = Plaintext::try_encode(&[numbers[_i]], Encoding::poly(), &params)?;
        let ct = pk.try_encrypt(&pt, &mut thread_rng())?;
        numbers_encrypted.push(ct);
        _i += 1;
    });

    // calculation
    let tally = timeit!("Number tallying", {
        let mut sum = Ciphertext::zero(&params);
        for ct in &numbers_encrypted {
            sum += ct;
        }
        Arc::new(sum)
    });

    // decrypt
    i = 0;
    timeit_n!("Generate Decrypt Share (per party)", num_parties as u32, {
        parties[i].d_share_poly = trbfv
            .decryption_share(
                tally.clone(),
                parties[i].sk_poly_sum.clone(),
                parties[i].es_poly_sum.clone(),
            )
            .unwrap();
        i += 1;
    });

    // gather d_share_polys
    let mut d_share_polys: Vec<Poly> = Vec::new();
    for party in parties.iter().take(threshold) {
        d_share_polys.push(party.d_share_poly.clone());
    }

    // decrypt result
    let open_results = trbfv.decrypt(d_share_polys, tally.clone()).unwrap();
    let result_vec = Vec::<u64>::try_decode(&open_results, Encoding::poly())?;
    let result = result_vec[0];

    // Show summation result
    println!("Sum result = {result} / {num_summed}");

    let expected_result = numbers.iter().sum();
    assert_eq!(result, expected_result);

    Ok(())
}
