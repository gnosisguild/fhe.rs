// Implementation of multiparty voting using the `fhe` crate.

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use console::style;
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, DecryptionShare, PublicKeyShare},
    thbfv::{TrBFVShare},
};
use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use rand::{distributions::Uniform, prelude::Distribution, rngs::OsRng, thread_rng};
use util::timeit::{timeit, timeit_n};
use num_bigint_old::{BigInt, ToBigInt};
use num_traits::ToPrimitive;
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use ndarray::{array, Array2, Array3, Axis, Array, ArrayView};
use zeroize::{Zeroizing};

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
    let threshold = 7; // todo get from cli input

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
    struct Party{
        sk_share: SecretKey,
        pk_share: PublicKeyShare,
        sk_sss: Vec<Array2<u64>>,
        sk_sss_collected: Vec<Array2<u64>>,
        sk_poly_sum: Poly,
        d_share_poly: Poly,
        trbfv: TrBFVShare,
    }
    let mut parties = Vec::with_capacity(num_parties);

    let crp = CommonRandomPoly::new(&params, &mut thread_rng())?;

    timeit_n!("Party setup (per party)", num_parties as u32, {
        let sk_share = SecretKey::random(&params, &mut OsRng);
        let pk_share = PublicKeyShare::new(&sk_share, crp.clone(), &mut thread_rng())?;
        let mut trbfv = TrBFVShare::new(
            num_parties,
            threshold,
            degree,
            16,
            moduli.clone()
        ).unwrap();
        let sk_sss = trbfv.gen_sss_shares(
            params.clone(),
            sk_share.clone()
        ).unwrap();
        // vec of 3 moduli and array2 for num_parties rows of coeffs and degree columns
        let mut sk_sss_collected: Vec<Array2<u64>> = Vec::with_capacity(num_parties);
        let mut sk_poly_sum = Poly::zero(&params.ctx_at_level(0).unwrap(), Representation::PowerBasis);
        let mut d_share_poly = Poly::zero(&params.ctx_at_level(0).unwrap(), Representation::PowerBasis);
        parties.push(Party { sk_share, pk_share, sk_sss, sk_sss_collected, sk_poly_sum, d_share_poly, trbfv });
    });

    // swap shares mocking network comms
    // party 1 sends share 2 to party 2 etc
    for i in 0..num_parties {
        for j in 0..num_parties {
            let mut node_share_m = Array::zeros((0, 2048));
            for m in 0..moduli.len() {
                node_share_m.push_row(ArrayView::from(&parties[j].sk_sss[m].row(i).clone())).unwrap();
            }
            parties[i].sk_sss_collected.push(node_share_m);
        }
    }

    // row = party id, index = moduli
    // println!("{:?}", parties[2].sk_sss[2].row(0));

    // sk_sss
    // [moduli_1, moduli_2, moduli_3]
    // [
    //  [[party_0_coeffs], [party_1_coeffs]],
    //  [[party_0_coeffs], [party_1_coeffs]],
    //  [[party_0_coeffs], [party_1_coeffs]]
    // ]
    //
    // sk_sss_collected
    // [party_0, party_1, party_2...]
    // [
    //   [[moduli_1], [moduli_2], [moduli_3]],
    //   [[moduli_1], [moduli_2], [moduli_3]],
    //   [[moduli_1], [moduli_2], [moduli_3]],
    //   ... n_times
    // ]

    // for each party, convert shares to polys and sum the collected shares
    for i in 0..num_parties {
        let mut sum_poly = Poly::zero(&params.ctx_at_level(0).unwrap(), Representation::PowerBasis);
        for j in 0..num_parties {
            // Initialize empty poly with correct context (moduli and level)
            let mut poly_j = Poly::zero(&params.ctx_at_level(0).unwrap(), Representation::PowerBasis);
            poly_j.set_coefficients(parties[i].sk_sss_collected[j].clone());
            sum_poly = &sum_poly + &poly_j;
        }
        parties[i].sk_poly_sum = sum_poly;
    }

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

    // decrypt
    // compute decryption share!
    // mul c1 * sk
    // then add c0 + (c1*sk)
    let mut c0 = tally.c[0].clone();
    c0.change_representation(Representation::PowerBasis);
    for i in 0..num_parties {
        let mut sk_i = parties[i].sk_poly_sum.clone();
        sk_i.change_representation(Representation::Ntt);
        let mut c1 = tally.c[1].clone();
        c1.change_representation(Representation::Ntt);
        let mut c1sk = &c1 * &sk_i;
        c1sk.change_representation(Representation::PowerBasis);
        let mut d_share_poly = &c0 + &c1sk;
        parties[i].d_share_poly = d_share_poly;
    }

    // party_0 d_0 =
    // [shamir, shamir, shamir... degree_shamir]
    // [shamir, shamir, shamir... degree_shamir]
    // [shamir, shamir, shamir... degree_shamir]

    // party_1 d_1 =
    // [shamir, shamir, shamir... degree_shamir]
    // [shamir, shamir, shamir... degree_shamir]
    // [shamir, shamir, shamir... degree_shamir]

    // party_2 d_2 =
    // [shamir, shamir, shamir... degree_shamir]
    // [shamir, shamir, shamir... degree_shamir]
    // [shamir, shamir, shamir... degree_shamir]

    // ...

    // party_7 d_7 =
    // [shamir, shamir, shamir... degree_shamir]
    // [shamir, shamir, shamir... degree_shamir]
    // [shamir, shamir, shamir... degree_shamir]

    // open shamir
    // [value, value, value... degree_value]
    // [value, value, value... degree_value]
    // [value, value, value... degree_value]

    // open shamir with di
    // vec<module.len> shamir [vec<threshold> vec<index, bigint coeffs>]

    let mut shamir_open_vec: Vec<(usize, BigInt)> = Vec::with_capacity(moduli.len()); // use array2 for this
    let mut shamir_open_vec_mod: Vec<(usize, BigInt)> = Vec::with_capacity(degree);
    let mut m_data: Vec<u64> = Vec::new();

    // collect shamir openings
    for m in 0..moduli.len() {

        let sss = SSS {
            threshold: threshold,
            share_amount: num_parties,
            prime: BigInt::from(moduli[m])
        };
        for i in 0..degree {
            let mut shamir_open_vec_mod: Vec<(usize, BigInt)> = Vec::with_capacity(degree);

            for j in 0..threshold {
                let coeffs = parties[j].d_share_poly.coefficients();
                if j==0 && i==0 {
                    println!("{:?}", coeffs.row(m));
                }
                let coeff_arr = coeffs.row(m);
                let coeff = coeff_arr[i];
                let coeff_formatted = (j+1, coeff.to_bigint().unwrap());
                shamir_open_vec_mod.push(coeff_formatted);
            }
           if i==0 {
                println!("{:?}", shamir_open_vec_mod);
            }
            // open shamir
            let shamir_result = sss.recover(&shamir_open_vec_mod[0..threshold as usize]);
            m_data.push(shamir_result.to_u64().unwrap());
            //println!("{:?}", shamir_result);
        }
    }
    let arr_matrix = Array2::from_shape_vec((moduli.len(), degree), m_data).unwrap();
    //println!("{:?}", arr_matrix);
    let mut result_poly = Poly::zero(&params.ctx_at_level(0).unwrap(), Representation::PowerBasis);
    result_poly.set_coefficients(arr_matrix);
    println!("{:?}", result_poly);
    result_poly..change_representation(Representation::Ntt);
    println!("{:?}", result_poly);

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
    //println!("{:?}", tally_pt);
    let tally_vec = Vec::<u64>::try_decode(&tally_pt, Encoding::poly())?;
    let tally_result = tally_vec[0];

    // Show vote result
    println!("Sum result = {} / {}", tally_result, amount);

    let expected_tally = numbers.iter().sum();
    assert_eq!(tally_result, expected_tally);

    Ok(())
}
