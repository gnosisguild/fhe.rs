// Implementation of hierarchical threshold addition using the `fhe` and `trbfv` crate.
//
// This example demonstrates a hierarchical threshold BFV setup where:
// - 9 total parties are organized into 3 groups of 3 parties each
// - Within each group: 2/3 threshold (any 2 parties can act for the group)
// - At the top level: 2/3 threshold (any 2 groups can decrypt)
//
// The hierarchical structure allows for more complex access patterns and can
// provide better fault tolerance and security properties compared to flat
// threshold schemes.
//
// Based on the MBFV example pattern from the same library.

mod util;

use std::{env, error::Error, process::exit, sync::Arc};

use console::style;
use fhe::{
    bfv::{self, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, CommonRandomPoly, PublicKeyShare},
    trbfv::TrBFVShare,
};
use fhe_math::rq::{Poly, Representation};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::{Array, Array2, ArrayView};
use rand::{distributions::Uniform, prelude::Distribution, rngs::OsRng, thread_rng};
use util::timeit::{timeit, timeit_n};

fn print_notice_and_exit(error: Option<String>) {
    println!(
        "{} Addition with hierarchical threshold BFV",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} add [-h] [--help] [--num_summed=<value>]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} Hierarchical setup: 3 groups of 3 parties each, 2/3 threshold at both levels",
        style("      note:").magenta().bold()
    );
    println!(
        "{} {} must be at least 1",
        style("constraints:").magenta().bold(),
        style("num_summed").blue(),
    );
    if let Some(error) = error {
        println!("{} {}", style("     error:").red().bold(), error);
    }
    exit(0);
}

fn main() -> Result<(), Box<dyn Error>> {
    // Parameters
    let degree = 2048;
    let plaintext_modulus: u64 = 4096;
    let moduli = vec![0xffffee001, 0xffffc4001, 0x1ffffe0001];

    // This executable is a command line tool which enables to specify
    // hierarchical trBFV summations with party and threshold sizes.
    let args: Vec<String> = env::args().skip(1).collect();

    // Print the help if requested.
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_summed = 1;
    let num_parties = 9; // Fixed: 3 groups of 3 parties each for hierarchical 2/3 setup
    let num_groups = 3;
    let parties_per_group = 3;
    let group_threshold = 2; // 2/3 threshold within each group
    let top_threshold = 2; // 2/3 threshold at top level

    // Update the number of summed values depending on the arguments provided.
    for arg in &args {
        if arg.starts_with("--num_summed") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_summed` argument".to_string()))
            } else {
                num_summed = a[0].parse::<usize>()?
            }
        } else {
            print_notice_and_exit(Some(format!("Unrecognized argument: {arg}")))
        }
    }

    if num_summed == 0 {
        print_notice_and_exit(Some("num_summed must be nonzero".to_string()))
    }

    // The parameters are within bound, let's go! Let's first display some
    // information about the hierarchical threshold sum.
    println!("# Addition with hierarchical trBFV");
    println!("\tnum_summed = {num_summed}");
    println!("\tnum_parties = {num_parties} (3 groups of 3)");
    println!("\tgroup_threshold = {group_threshold}/3");
    println!("\ttop_threshold = {top_threshold}/3");

    // Let's generate the BFV parameters structure. This will be shared between parties
    let params = timeit!(
        "Parameters generation",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()?
    );

    // Party setup: hierarchical structure with 3 groups, each with 3 parties
    // Each sub-party generates a secret key and shares of a collective public key.
    struct SubParty {
        sk_share: SecretKey,
        pk_share: PublicKeyShare,
        sk_sss: Vec<Array2<u64>>,
        esi_sss: Vec<Array2<u64>>,
        sk_sss_collected: Vec<Array2<u64>>,
        es_sss_collected: Vec<Array2<u64>>,
        sk_poly_sum: Poly,
        es_poly_sum: Poly,
        d_share_poly: Poly,
    }

    // Group-level party for the top-level threshold
    struct GroupParty {
        pk_share: PublicKeyShare, // Aggregated public key share for this group
        sk_sss: Vec<Array2<u64>>,
        esi_sss: Vec<Array2<u64>>,
        sk_sss_collected: Vec<Array2<u64>>,
        es_sss_collected: Vec<Array2<u64>>,
        sk_poly_sum: Poly,
        es_poly_sum: Poly,
        d_share_poly: Poly,
        sub_parties: Vec<SubParty>,
    }

    let mut groups = Vec::with_capacity(num_groups);

    // Generate a common reference poly for public key generation.
    let crp = CommonRandomPoly::new(&params, &mut thread_rng())?;

    // Setup trBFV module for group-level threshold (group_threshold within each group)
    let mut group_trbfv = TrBFVShare::new(
        parties_per_group,
        group_threshold,
        degree,
        plaintext_modulus,
        160,
        moduli.clone(),
        params.clone(),
    )
    .unwrap();

    // Setup trBFV module for top-level threshold (top_threshold among groups)
    let mut top_trbfv = TrBFVShare::new(
        num_groups,
        top_threshold,
        degree,
        plaintext_modulus,
        160,
        moduli.clone(),
        params.clone(),
    )
    .unwrap();

    // Set up hierarchical groups
    timeit_n!("Group setup (per group)", num_groups as u32, {
        let mut sub_parties = Vec::with_capacity(parties_per_group);

        // Create sub-parties within this group
        for _ in 0..parties_per_group {
            let sk_share = SecretKey::random(&params, &mut OsRng);
            let pk_share = PublicKeyShare::new(&sk_share, crp.clone(), &mut thread_rng())?;
            let sk_sss = group_trbfv.generate_secret_shares(sk_share.coeffs.clone())?;
            let esi_coeffs = group_trbfv.generate_smudging_error(&mut OsRng)?;
            let esi_sss = group_trbfv.generate_secret_shares(esi_coeffs.into_boxed_slice())?;

            let sk_sss_collected: Vec<Array2<u64>> = Vec::with_capacity(parties_per_group);
            let es_sss_collected: Vec<Array2<u64>> = Vec::with_capacity(parties_per_group);
            let sk_poly_sum =
                Poly::zero(&params.ctx_at_level(0).unwrap(), Representation::PowerBasis);
            let es_poly_sum =
                Poly::zero(&params.ctx_at_level(0).unwrap(), Representation::PowerBasis);
            let d_share_poly =
                Poly::zero(&params.ctx_at_level(0).unwrap(), Representation::PowerBasis);

            sub_parties.push(SubParty {
                sk_share,
                pk_share,
                sk_sss,
                esi_sss,
                sk_sss_collected,
                es_sss_collected,
                sk_poly_sum,
                es_poly_sum,
                d_share_poly,
            });
        }

        // Aggregate public key shares within this group (similar to MBFV example)
        let _group_pk: PublicKey = sub_parties.iter().map(|p| p.pk_share.clone()).aggregate()?;

        // For hierarchical threshold, we need the group to act as a single party
        // Generate a group secret key and create a public key share from it
        let group_sk = SecretKey::random(&params, &mut OsRng);
        let group_pk_share = PublicKeyShare::new(&group_sk, crp.clone(), &mut thread_rng())?;

        // Generate group-level threshold shares for top-level scheme
        let group_sk_sss = top_trbfv.generate_secret_shares(group_sk.coeffs.clone())?;
        let group_esi_coeffs = top_trbfv.generate_smudging_error(&mut OsRng)?;
        let group_esi_sss =
            top_trbfv.generate_secret_shares(group_esi_coeffs.into_boxed_slice())?;

        let group_sk_sss_collected: Vec<Array2<u64>> = Vec::with_capacity(num_groups);
        let group_es_sss_collected: Vec<Array2<u64>> = Vec::with_capacity(num_groups);
        let group_sk_poly_sum =
            Poly::zero(&params.ctx_at_level(0).unwrap(), Representation::PowerBasis);
        let group_es_poly_sum =
            Poly::zero(&params.ctx_at_level(0).unwrap(), Representation::PowerBasis);
        let group_d_share_poly =
            Poly::zero(&params.ctx_at_level(0).unwrap(), Representation::PowerBasis);

        groups.push(GroupParty {
            pk_share: group_pk_share,
            sk_sss: group_sk_sss,
            esi_sss: group_esi_sss,
            sk_sss_collected: group_sk_sss_collected,
            es_sss_collected: group_es_sss_collected,
            sk_poly_sum: group_sk_poly_sum,
            es_poly_sum: group_es_poly_sum,
            d_share_poly: group_d_share_poly,
            sub_parties,
        });
    });

    // Level 1: Swap shares within each group (group-level threshold)
    timeit!("Group-level share swapping", {
        for group_idx in 0..num_groups {
            // Collect all shares first to avoid borrowing conflicts
            let mut all_sk_shares = Vec::new();
            let mut all_es_shares = Vec::new();

            for j in 0..parties_per_group {
                all_sk_shares.push(groups[group_idx].sub_parties[j].sk_sss.clone());
                all_es_shares.push(groups[group_idx].sub_parties[j].esi_sss.clone());
            }

            // Now distribute shares to each sub-party
            for i in 0..parties_per_group {
                for j in 0..parties_per_group {
                    let mut node_share_m = Array::zeros((0, 2048));
                    let mut es_node_share_m = Array::zeros((0, 2048));
                    for m in 0..moduli.len() {
                        node_share_m
                            .push_row(ArrayView::from(&all_sk_shares[j][m].row(i).clone()))
                            .unwrap();
                        es_node_share_m
                            .push_row(ArrayView::from(&all_es_shares[j][m].row(i).clone()))
                            .unwrap();
                    }
                    groups[group_idx].sub_parties[i]
                        .sk_sss_collected
                        .push(node_share_m);
                    groups[group_idx].sub_parties[i]
                        .es_sss_collected
                        .push(es_node_share_m);
                }
            }
        }
    });

    // Level 1: Sum collected shares within each group
    timeit_n!(
        "Group-level share summing (per group)",
        num_groups as u32,
        {
            for group in &mut groups {
                for sub_party in &mut group.sub_parties {
                    sub_party.sk_poly_sum =
                        group_trbfv.sum_sk_i(&sub_party.sk_sss_collected).unwrap();
                    sub_party.es_poly_sum =
                        group_trbfv.sum_sk_i(&sub_party.es_sss_collected).unwrap();
                }
            }
        }
    );

    // Level 2: Swap shares between groups (top-level threshold)
    timeit!("Top-level share swapping", {
        // Collect all group shares first to avoid borrowing conflicts
        let mut all_group_sk_shares = Vec::new();
        let mut all_group_es_shares = Vec::new();

        for j in 0..num_groups {
            all_group_sk_shares.push(groups[j].sk_sss.clone());
            all_group_es_shares.push(groups[j].esi_sss.clone());
        }

        // Now distribute shares to each group
        for i in 0..num_groups {
            for j in 0..num_groups {
                let mut node_share_m = Array::zeros((0, 2048));
                let mut es_node_share_m = Array::zeros((0, 2048));
                for m in 0..moduli.len() {
                    node_share_m
                        .push_row(ArrayView::from(&all_group_sk_shares[j][m].row(i).clone()))
                        .unwrap();
                    es_node_share_m
                        .push_row(ArrayView::from(&all_group_es_shares[j][m].row(i).clone()))
                        .unwrap();
                }
                groups[i].sk_sss_collected.push(node_share_m);
                groups[i].es_sss_collected.push(es_node_share_m);
            }
        }
    });

    // Level 2: Sum collected shares at top level
    timeit!("Top-level share summing", {
        for group in &mut groups {
            group.sk_poly_sum = top_trbfv.sum_sk_i(&group.sk_sss_collected).unwrap();
            group.es_poly_sum = top_trbfv.sum_sk_i(&group.es_sss_collected).unwrap();
        }
    });

    // Aggregation: aggregate group public keys to create final public key
    let pk = timeit!("Public key aggregation", {
        let pk: PublicKey = groups.iter().map(|g| g.pk_share.clone()).aggregate()?;
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

    // Hierarchical decryption process

    // Level 1: Generate group-level decryption shares (only need top_threshold groups)
    timeit_n!(
        "Generate group decryption shares (per group)",
        top_threshold as u32,
        {
            for i in 0..top_threshold {
                groups[i].d_share_poly = top_trbfv
                    .decryption_share(
                        tally.clone(),
                        groups[i].sk_poly_sum.clone(),
                        groups[i].es_poly_sum.clone(),
                    )
                    .unwrap();
            }
        }
    );

    // Level 2: Collect group decryption shares for final decryption
    let mut d_share_polys: Vec<Poly> = Vec::new();
    for i in 0..top_threshold {
        d_share_polys.push(groups[i].d_share_poly.clone());
    }

    // Final decryption using group-level shares
    let open_results = top_trbfv.decrypt(d_share_polys, tally.clone()).unwrap();
    let result_vec = Vec::<u64>::try_decode(&open_results, Encoding::poly())?;
    let result = result_vec[0];

    // Show summation result
    println!("Sum result = {} / {}", result, num_summed);

    let expected_result = numbers.iter().sum();
    assert_eq!(result, expected_result);

    Ok(())
}
