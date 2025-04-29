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
use shamir_secret_sharing::ShamirSecretSharing as SSS;

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
    let sss_prime = BigInt::parse_bytes(b"40",16).unwrap();

    // This executable is a command line tool which enables to specify
    // voter/election worker sizes.
    let args: Vec<String> = env::args().skip(1).collect();

    // Print the help if requested.
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_users = 1;
    let mut num_parties = 10;
    let threshold = 8; // todo get from cli input

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

    // No crp in trBFV?
    //let crp = CommonRandomPoly::new(&params, &mut thread_rng())?;

    // Party setup: each party generates a secret key and shares of a collective
    // public key.
    struct Party {
        sk_share: SecretKey,
        pk_share: PublicKeyShare,
        sk_sss: Vec<Vec<(usize, BigInt)>>,
        smudge_error: Vec<i64>,
        smudge_sss: Vec<Vec<(usize, BigInt)>>,
    }
    let mut parties = Vec::with_capacity(num_parties);

    let crp = CommonRandomPoly::new(&params, &mut thread_rng())?;

    let sss = SSS {
        threshold: threshold,
        share_amount: num_parties,
        prime: sss_prime.clone()
    };

    timeit_n!("Party setup (per party)", num_parties as u32, {
        let sk_share = SecretKey::random(&params, &mut OsRng);
        let pk_share = PublicKeyShare::new(&sk_share, crp.clone(), &mut thread_rng())?;
        // encode away negative coeffs for secret key shamir shares
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

    // collect secret key shares: all parties will share the same set of shares after sharing
    // p_0 sends index 0 of points to [p_1 - p_n]
    // p_1 sends index 1 of points to [p_0], [p_2 - p_n]
    // p_2 sends index 2 of points to [p_0 - p_1], [p_3 - p_n]
    // p_3 sends index 3 of points to [p_0 - p_2], [p_4 - p_n]
    let mut p0_sks: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(degree);
    for i in 0..degree {
        let mut sss_vec = Vec::with_capacity(num_parties);
        sss_vec.push(parties[0].sk_sss[i][0].clone());
        for j in 1..num_parties {
            sss_vec.push(parties[j].sk_sss[i][j].clone()); // this should be parties[j].sk_sss[i][0] for party 0
        }
        p0_sks.push(sss_vec);
    }

    // collect smudge shares: all parties will share the same set of shares after sharing
    // p_0 sends index 0 of points to [p_1 - p_n]
    // p_1 sends index 1 of points to [p_0], [p_2 - p_n]
    // p_2 sends index 2 of points to [p_0 - p_1], [p_3 - p_n]
    // p_3 sends index 3 of points to [p_0 - p_2], [p_4 - p_n]
    let mut p0_smudges: Vec<Vec<(usize, BigInt)>> = Vec::with_capacity(degree);
    for i in 0..degree {
        let mut sss_vec = Vec::with_capacity(num_parties);
        sss_vec.push(parties[0].smudge_sss[i][0].clone());
        for j in 1..num_parties {
            sss_vec.push(parties[j].smudge_sss[i][j].clone());
        }
        p0_smudges.push(sss_vec);
    }

    //println!("{:?}", p0_smudges[0]);
    println!("{:?}", parties[0].smudge_sss[1000]);

    // Aggregation: same as previous mbfv aggregations
    let pk = timeit!("Public key aggregation", {
        let pk: PublicKey = parties.iter().map(|p| p.pk_share.clone()).aggregate()?;
        pk
    });

    // encrypted mul
    let amount = 5;
    let dist = Uniform::new_inclusive(0, 1);
    let numbers: Vec<u64> = dist
        .sample_iter(&mut thread_rng())
        .take(amount)
        .collect();
    let mut numbers_encrypted = Vec::with_capacity(amount);
    let mut _i = 0;
    timeit_n!("Encrypting Numbers (per encryption)", amount as u32, {
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

    // threshold decrypt. We will assume the last two parties in the set drop out
    let t = num_parties - 2;

    //let mut threshold_decryption_shares = Vec::with_capacity(t);
    let mut sum_esm: Vec<(BigInt)> = Vec::with_capacity(degree);
    let mut esm_open: Vec<(BigInt)> = Vec::with_capacity(degree);
    let mut _i = 0;
    // sum esm
        timeit_n!("Summing smudge noise (per party up to threshold)", degree as u32, {
        // summ smudge from collected shares in p0_smudge
        let mut esm_i_sum = 0.to_bigint().unwrap();
        // sum esm up to the threshold of honest nodes
        for j in 0..threshold {
            esm_i_sum = p0_smudges[_i][j].1.clone() + esm_i_sum;
        }
        sum_esm.push(esm_i_sum);
        esm_open.push(sss.recover(&p0_smudges[_i][0..threshold as usize]));
        _i += 1;
    });
    //println!("{:?}", sum_esm[0]);
    //println!("{:?}", esm_open[100]);
    let open_p0_esm = sss.recover(&parties[0].smudge_sss[0][0..threshold as usize]);
    //println!("{:?}", open_p0_esm);

    // sum sk
    let mut sum_sk: Vec<(BigInt)> = Vec::with_capacity(degree);
    let mut _i = 0;
    // sum esm
        timeit_n!("Summing sk shares (per party up to threshold)", degree as u32, {
        // sum sk from collected shares in p0_sks
        let mut sk_i_sum = 0.to_bigint().unwrap();
        // sum sk up to the threshold of honest nodes
        for j in 0..threshold {
            sk_i_sum = p0_sks[_i][j].1.clone() + sk_i_sum;
        }
        sum_sk.push(sk_i_sum);
        _i += 1;
    });
    println!("{:?}", sum_sk[0]);
    //println!("{:?}", tally);

    // convert esm and sk summed shares into polynomals

    timeit_n!("Decryption (per party up to threshold)", 1 as u32, {

        let sh = TrBFVShare::decryption_share(tally.clone(), sum_esm.clone(), sum_sk.clone())?;
        _i += 1;
    });   

    //decrypt
    let mut decryption_shares = Vec::with_capacity(num_parties);
    let mut _i = 0;
    timeit_n!("Decryption (per party)", num_parties as u32, {
        let sh = DecryptionShare::new(&parties[_i].sk_share, &tally, &mut thread_rng())?;
        decryption_shares.push(sh);
        _i += 1;
    });

    // aggregate decrypted shares
    let tally_pt = timeit!("Decryption share aggregation", {
        let pt: Plaintext = decryption_shares.into_iter().aggregate()?;
        pt
    });
    let tally_vec = Vec::<u64>::try_decode(&tally_pt, Encoding::poly())?;
    let tally_result = tally_vec[0];

    // Show vote result
    println!("Sum result = {} / {}", tally_result, amount);

    let expected_tally = numbers.iter().sum();
    assert_eq!(tally_result, expected_tally);

    Ok(())
}
