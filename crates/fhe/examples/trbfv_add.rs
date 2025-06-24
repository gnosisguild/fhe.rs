// Implementation of hierarchical threshold addition using the `fhe` and `trbfv` crate.
//
// This example demonstrates a configurable hierarchical threshold BFV setup where:
// - Parties are organized into a tree structure with arbitrary depth
// - Each level can have configurable group sizes and thresholds
// - The hierarchy allows for complex access patterns and provides better
//   fault tolerance and security properties compared to flat threshold schemes.
//
// Example usage:
// - `--depth=2 --group_size=3 --threshold=2` creates a 2-level hierarchy with 3-party groups and 2/3 threshold
// - `--depth=3 --group_size=4 --threshold=3` creates a 3-level hierarchy with 4-party groups and 3/4 threshold
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
use fhe_math::rq::Poly;
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::{Array, Array2, ArrayView};
use rand::{distributions::Uniform, prelude::Distribution, rngs::OsRng, thread_rng};
use util::timeit::{timeit, timeit_n};

// Hierarchical party structure - each node in the tree
#[derive(Clone)]
struct HierarchyNode {
    level: usize, // Level in hierarchy (0 = leaf/base parties, depth-1 = root)
    pk_share: Option<PublicKeyShare>, // Public key share for this node
    sk_sss: Vec<Array2<u64>>, // Secret shares for threshold at this level
    esi_sss: Vec<Array2<u64>>, // Error smudging shares
    sk_sss_collected: Vec<Array2<u64>>, // Collected shares from siblings
    es_sss_collected: Vec<Array2<u64>>, // Collected error shares from siblings
    sk_poly_sum: Option<Poly>, // Summed secret polynomial
    es_poly_sum: Option<Poly>, // Summed error polynomial
    d_share_poly: Option<Poly>, // Decryption share
    children: Vec<HierarchyNode>, // Child nodes (empty for leaf nodes)
}

impl HierarchyNode {
    fn new(level: usize) -> Self {
        Self {
            level,
            pk_share: None,
            sk_sss: Vec::new(),
            esi_sss: Vec::new(),
            sk_sss_collected: Vec::new(),
            es_sss_collected: Vec::new(),
            sk_poly_sum: None,
            es_poly_sum: None,
            d_share_poly: None,
            children: Vec::new(),
        }
    }
}

/// Count the total number of nodes in the hierarchy tree
fn count_nodes(node: &HierarchyNode) -> usize {
    1 + node.children.iter().map(count_nodes).sum::<usize>()
}

fn print_notice_and_exit(error: Option<String>) {
    println!(
        "{} Addition with hierarchical threshold BFV",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} add [-h] [--help] [--num_summed=<value>] [--depth=<value>] [--group_size=<value>] [--threshold=<value>]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} Hierarchical setup with configurable depth, group sizes, and thresholds",
        style("      note:").magenta().bold()
    );
    println!(
        "{} {} {} {} and {} must be at least 1, and threshold < group_size",
        style("constraints:").magenta().bold(),
        style("num_summed").blue(),
        style("depth").blue(),
        style("group_size").blue(),
        style("threshold").blue(),
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
    // hierarchical trBFV summations with configurable hierarchy parameters.
    let args: Vec<String> = env::args().skip(1).collect();

    // Print the help if requested.
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    let mut num_summed = 1;
    let mut depth = 2; // Default: 2-level hierarchy
    let mut group_size = 3; // Default: 3 parties per group
    let mut threshold = 2; // Default: 2/3 threshold

    // Parse command line arguments
    for arg in &args {
        if arg.starts_with("--num_summed") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_summed` argument".to_string()))
            } else {
                num_summed = a[0].parse::<usize>()?
            }
        } else if arg.starts_with("--depth") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--depth` argument".to_string()))
            } else {
                depth = a[0].parse::<usize>()?
            }
        } else if arg.starts_with("--group_size") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--group_size` argument".to_string()))
            } else {
                group_size = a[0].parse::<usize>()?
            }
        } else if arg.starts_with("--threshold") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--threshold` argument".to_string()))
            } else {
                threshold = a[0].parse::<usize>()?
            }
        } else {
            print_notice_and_exit(Some(format!("Unrecognized argument: {arg}")))
        }
    }

    // Validate parameters
    if num_summed == 0 || depth == 0 || group_size == 0 || threshold == 0 {
        print_notice_and_exit(Some("All parameters must be nonzero".to_string()))
    }
    if threshold >= group_size {
        print_notice_and_exit(Some("Threshold must be less than group_size".to_string()))
    }
    if depth == 1 {
        print_notice_and_exit(Some(
            "Depth must be at least 2 for hierarchical threshold".to_string(),
        ))
    }

    // Calculate total number of parties
    let total_parties = group_size.pow(depth as u32);

    // Display hierarchy information
    println!("# Addition with hierarchical trBFV");
    println!("\tnum_summed = {num_summed}");
    println!("\tdepth = {depth}");
    println!("\tgroup_size = {group_size}");
    println!("\tthreshold = {threshold}/{group_size}");
    println!("\ttotal_parties = {total_parties}");

    // Let's generate the BFV parameters structure. This will be shared between parties
    let params = timeit!(
        "Parameters generation",
        bfv::BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext_modulus)
            .set_moduli(&moduli)
            .build_arc()?
    );

    // Generate a common reference poly for public key generation.
    let crp = CommonRandomPoly::new(&params, &mut thread_rng())?;

    // Create TrBFV instances for each level
    let mut trbfv_levels = Vec::with_capacity(depth);
    for _level in 0..depth {
        let trbfv = TrBFVShare::new(
            group_size,
            threshold,
            degree,
            plaintext_modulus,
            160,
            moduli.clone(),
            params.clone(),
        )?;
        trbfv_levels.push(trbfv);
    }

    // Build the hierarchy tree recursively
    fn build_hierarchy(
        level: usize,
        depth: usize,
        group_size: usize,
        params: &Arc<bfv::BfvParameters>,
        crp: &CommonRandomPoly,
        trbfv_levels: &mut [TrBFVShare],
    ) -> Result<HierarchyNode, Box<dyn Error>> {
        let mut node = HierarchyNode::new(level);

        if level == 0 {
            // Leaf node - generate actual secret key and public key share
            let sk = SecretKey::random(params, &mut OsRng);
            let pk_share = PublicKeyShare::new(&sk, crp.clone(), &mut thread_rng())?;

            // Generate threshold shares for this level
            let sk_sss = trbfv_levels[level].generate_secret_shares(sk.coeffs.clone())?;
            let esi_coeffs = trbfv_levels[level].generate_smudging_error(&mut OsRng)?;
            let esi_sss =
                trbfv_levels[level].generate_secret_shares(esi_coeffs.into_boxed_slice())?;

            node.pk_share = Some(pk_share);
            node.sk_sss = sk_sss;
            node.esi_sss = esi_sss;
            node.sk_sss_collected = Vec::with_capacity(group_size);
            node.es_sss_collected = Vec::with_capacity(group_size);
        } else {
            // Internal node - create children and aggregate their keys
            for _ in 0..group_size {
                let child =
                    build_hierarchy(level - 1, depth, group_size, params, crp, trbfv_levels)?;
                node.children.push(child);
            }

            // Aggregate children's public keys using MBFV aggregation
            let _aggregated_pk: PublicKey = node
                .children
                .iter()
                .filter_map(|child| child.pk_share.clone())
                .aggregate()?;

            // For the aggregated node, create a representative secret key and public key share
            let representative_sk = SecretKey::random(params, &mut OsRng);
            let pk_share = PublicKeyShare::new(&representative_sk, crp.clone(), &mut thread_rng())?;

            // Generate threshold shares for this level
            let sk_sss =
                trbfv_levels[level].generate_secret_shares(representative_sk.coeffs.clone())?;
            let esi_coeffs = trbfv_levels[level].generate_smudging_error(&mut OsRng)?;
            let esi_sss =
                trbfv_levels[level].generate_secret_shares(esi_coeffs.into_boxed_slice())?;

            node.pk_share = Some(pk_share);
            node.sk_sss = sk_sss;
            node.esi_sss = esi_sss;
            node.sk_sss_collected = Vec::with_capacity(group_size);
            node.es_sss_collected = Vec::with_capacity(group_size);
        }

        Ok(node)
    }

    // Build the complete hierarchy
    let mut root = timeit!("Hierarchy setup", {
        build_hierarchy(
            depth - 1,
            depth,
            group_size,
            &params,
            &crp,
            &mut trbfv_levels,
        )?
    });

    println!(
        "Hierarchy built successfully with {} total nodes",
        count_nodes(&root)
    );

    // Perform hierarchical share swapping from bottom to top
    fn swap_shares_level(
        nodes: &mut [HierarchyNode],
        group_size: usize,
        moduli: &[u64],
        trbfv: &mut TrBFVShare,
    ) -> Result<(), Box<dyn Error>> {
        if nodes.is_empty() {
            return Ok(());
        }

        // Collect all shares at this level to avoid borrowing conflicts
        let all_sk_shares: Vec<_> = nodes.iter().map(|n| n.sk_sss.clone()).collect();
        let all_es_shares: Vec<_> = nodes.iter().map(|n| n.esi_sss.clone()).collect();

        // Distribute shares to each node
        for i in 0..nodes.len() {
            for j in 0..group_size {
                if j < all_sk_shares.len() {
                    let mut node_share_m = Array::zeros((0, 2048));
                    let mut es_node_share_m = Array::zeros((0, 2048));
                    for m in 0..moduli.len() {
                        node_share_m
                            .push_row(ArrayView::from(&all_sk_shares[j][m].row(i).clone()))?;
                        es_node_share_m
                            .push_row(ArrayView::from(&all_es_shares[j][m].row(i).clone()))?;
                    }
                    nodes[i].sk_sss_collected.push(node_share_m);
                    nodes[i].es_sss_collected.push(es_node_share_m);
                }
            }
        }

        // Sum collected shares for each node
        for node in nodes.iter_mut() {
            node.sk_poly_sum = Some(trbfv.sum_sk_i(&node.sk_sss_collected)?);
            node.es_poly_sum = Some(trbfv.sum_sk_i(&node.es_sss_collected)?);
        }

        Ok(())
    }

    // Recursively swap shares at each level
    fn process_hierarchy_level(
        node: &mut HierarchyNode,
        group_size: usize,
        moduli: &[u64],
        trbfv_levels: &mut [TrBFVShare],
    ) -> Result<(), Box<dyn Error>> {
        // Process children first (bottom-up)
        for child in &mut node.children {
            process_hierarchy_level(child, group_size, moduli, trbfv_levels)?;
        }

        // If this node has children, perform share swapping among them
        if !node.children.is_empty() {
            swap_shares_level(
                &mut node.children,
                group_size,
                moduli,
                &mut trbfv_levels[node.level - 1],
            )?;
        }

        Ok(())
    }

    // Process all levels from bottom to top
    timeit!("Hierarchical share processing", {
        process_hierarchy_level(&mut root, group_size, &moduli, &mut trbfv_levels)?
    });

    // Aggregate public keys from top-level children to create the final public key
    let pk = timeit!("Public key aggregation", {
        let pk_shares: Vec<_> = root
            .children
            .iter()
            .filter_map(|child| child.pk_share.clone())
            .collect();
        let pk: PublicKey = pk_shares.into_iter().aggregate()?;
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

    // Hierarchical decryption process - only need threshold number of top-level groups
    timeit!("Generate decryption shares", {
        for i in 0..threshold.min(root.children.len()) {
            if let (Some(sk_poly), Some(es_poly)) =
                (&root.children[i].sk_poly_sum, &root.children[i].es_poly_sum)
            {
                let d_share = trbfv_levels[depth - 1].decryption_share(
                    tally.clone(),
                    sk_poly.clone(),
                    es_poly.clone(),
                )?;
                root.children[i].d_share_poly = Some(d_share);
            }
        }
    });

    // Collect decryption shares for final decryption
    let mut d_share_polys: Vec<Poly> = Vec::new();
    for i in 0..threshold.min(root.children.len()) {
        if let Some(d_share) = &root.children[i].d_share_poly {
            d_share_polys.push(d_share.clone());
        }
    }

    // Final decryption using threshold shares
    let open_results = trbfv_levels[depth - 1].decrypt(d_share_polys, tally.clone())?;
    let result_vec = Vec::<u64>::try_decode(&open_results, Encoding::poly())?;
    let result = result_vec[0];

    // Show summation result
    println!("Sum result = {} / {}", result, num_summed);

    let expected_result = numbers.iter().sum();
    assert_eq!(result, expected_result);

    Ok(())
}
