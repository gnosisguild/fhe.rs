// Implementation of multiparty voting using the `fhe` crate.

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use console::style;
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, DecryptionShare, PublicKeyShare},
    thbfv::{TrBFVShare},
};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use rand::{distributions::Uniform, prelude::Distribution, rngs::OsRng, thread_rng};
use util::timeit::{timeit, timeit_n};
use num_bigint_old::{BigInt, ToBigInt};

fn print_notice_and_exit(error: Option<String>) {
    println!(
        "{} Multiplication with threshold BFV",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} multiply [-h] [--help] [--num_users=<value>] [--num_parties=<value>]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} {} and {} must be at least 1",
        style("constraints:").magenta().bold(),
        style("num_users").blue(),
        style("num_parties").blue(),
    );
    if let Some(error) = error {
        println!("{} {}", style("     error:").red().bold(), error);
    }
    exit(0);
}

fn main() -> Result<(), Box<dyn Error>> {
    let degree = 2048;
    let plaintext_modulus: u64 = 4096;
    let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];
    let sss_prime = BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",16).unwrap();

    // This executable is a command line tool which enables to specify
    // voter/election worker sizes.
    let args: Vec<String> = env::args().skip(1).collect();

    // Print the help if requested.
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_users = 1;
    let mut num_parties = 10;
    let threshold = 5; // todo get from clit input

    // Update the number of users and/or number of parties depending on the
    // arguments provided.
    for arg in &args {
        if arg.starts_with("--num_users") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_users` argument".to_string()))
            } else {
                num_users = a[0].parse::<usize>()?
            }
        } else if arg.starts_with("--num_parties") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_parties` argument".to_string()))
            } else {
                num_parties = a[0].parse::<usize>()?
            }
        } else {
            print_notice_and_exit(Some(format!("Unrecognized argument: {arg}")))
        }
    }

    if num_users == 0 || num_users == 0 {
        print_notice_and_exit(Some("Users and party sizes must be nonzero".to_string()))
    }

    // The parameters are within bound, let's go! Let's first display some
    // information about the vote.
    println!("# Multiplication with trBFV");
    println!("\tnum_users = {num_users}");
    println!("\tnum_parties = {num_parties}");

    // Let's generate the BFV parameters structure. This will be shared between parties
    let params = timeit!(
        "Parameters generation",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()?
    );

    // No crp in trBFV
    //let crp = CommonRandomPoly::new(&params, &mut thread_rng())?;

    // Party setup: each party generates a secret key and shares of a collective
    // public key.
    struct Party {
        sk_share: SecretKey,
        pk_share: PublicKey,
        sk_sss: Vec<Vec<(usize, BigInt)>>,
        smudge_error: Vec<i64>,
        smudge_sss: Vec<Vec<(usize, BigInt)>>,
    }
    let mut parties = Vec::with_capacity(num_parties);
    timeit_n!("Party setup (per party)", num_parties as u32, {
        let sk_share = SecretKey::random(&params, &mut OsRng);
        let pk_share = PublicKey::new(&sk_share, &mut OsRng);
        // encode away negative coeffs
        let sk_coeffs_encoded = TrBFVShare::encode_coeffs(&mut sk_share.coeffs.to_vec()).unwrap();
        let sk_sss = TrBFVShare::gen_sss_shares(
            degree,
            threshold,
            num_parties,
            sss_prime.clone(),
            sk_coeffs_encoded
        ).unwrap();
        let mut smudge_error = TrBFVShare::gen_smudging_error(
            degree,
            16,
            &mut OsRng
        ).unwrap();
        let smudge_error_encoded = TrBFVShare::encode_coeffs(&mut smudge_error).unwrap();
        let smudge_sss = TrBFVShare::gen_sss_shares(
            degree,
            threshold,
            num_parties,
            sss_prime.clone(),
            smudge_error_encoded
        ).unwrap();
        parties.push(Party { sk_share, pk_share, sk_sss, smudge_error, smudge_sss });
    });
    println!("{:?}", parties.len());


    // Aggregation: this could be one of the parties or a separate entity. Or the
    // parties can aggregate cooperatively, in a tree-like fashion.
    // let pk = timeit!("Public key aggregation", {
    //     let pk: PublicKey = parties.iter().map(|p| p.pk_share.clone()).aggregate()?;
    //     pk
    // });

    // encrypted mul

    Ok(())
}
