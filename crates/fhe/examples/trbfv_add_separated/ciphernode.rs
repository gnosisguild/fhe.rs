use std::sync::Arc;

use fhe::{
    bfv::{self, Ciphertext, Encoding, SecretKey},
    mbfv::{CommonRandomPoly,PublicKeyShare},
    trbfv::{smudging::SmudgingNoiseGenerator, ShareManager},
};
use fhe_math::rq::{Poly, Representation};
use fhe_traits::FheDecoder;
use ndarray::{Array, Array2, ArrayView};
use num_bigint::BigUint;
use rand::{rngs::OsRng, thread_rng};
use rayon::prelude::*;

pub struct Ciphernode {
    pub pk_share: PublicKeyShare,
    pub sk_sss: Vec<Array2<u64>>,
    pub esi_sss: Vec<Vec<Array2<u64>>>,
    pub sk_sss_collected: Vec<Array2<u64>>,
    pub es_sss_collected: Vec<Vec<Array2<u64>>>,
    pub sk_poly_sum: Poly,
    pub es_poly_sum: Vec<Poly>,
    pub d_share_poly: Vec<Poly>,
}

/// Generate public key shares and secret key shares for all ciphernodes.
pub fn calculate_pk_share_and_sk_sss(
    params: Arc<bfv::BfvParameters>,
    n: usize,
    threshold: usize,
    crp: CommonRandomPoly,
) -> Vec<Ciphernode> {
    let num_ciphernodes = n;
    (0..num_ciphernodes)
        .into_par_iter()
        .map(|_| {
            let mut rng = OsRng;
            let mut thread_rng = thread_rng();

            let sk_share = SecretKey::random(&params, &mut rng);
            let pk_share = PublicKeyShare::new(&sk_share, crp.clone(), &mut thread_rng).unwrap();

            let mut share_manager = ShareManager::new(num_ciphernodes, threshold, params.clone());
            let sk_poly = share_manager
                .coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())
                .unwrap();

            let sk_sss = share_manager
                .generate_secret_shares_from_poly(sk_poly)
                .unwrap();

            let sk_sss_collected: Vec<Array2<u64>> = Vec::with_capacity(num_ciphernodes);
            let es_sss_collected: Vec<Vec<Array2<u64>>> = Vec::new();
            let ctx = params.ctx_at_level(0).unwrap();
            let sk_poly_sum = Poly::zero(ctx, Representation::PowerBasis);
            let es_poly_sum = Vec::new();
            let d_share_poly = Vec::new();

            Ciphernode {
                pk_share,
                sk_sss,
                esi_sss: Vec::new(),
                sk_sss_collected,
                es_sss_collected,
                sk_poly_sum,
                es_poly_sum,
                d_share_poly,
            }
        })
        .collect()
}

/// Generate `count` smudging error shares for each ciphernode using the provided error size.
pub fn calculate_esi_sss(
    ciphernodes: &mut [Ciphernode],
    params: Arc<bfv::BfvParameters>,
    n: usize,
    threshold: usize,
    error_size: &BigUint,
    count: usize,
) {
    ciphernodes.par_iter_mut().for_each(|ciphernode| {
        ciphernode.esi_sss = (0..count)
            .map(|_| {
                let generator =
                    SmudgingNoiseGenerator::new(params.clone(), error_size.clone());
                let esi_coeffs = generator.generate_smudging_error().unwrap();
                let mut share_manager =
                    ShareManager::new(n, threshold, params.clone());
                let esi_poly = share_manager.bigints_to_poly(&esi_coeffs).unwrap();
                share_manager
                    .generate_secret_shares_from_poly(esi_poly)
                    .unwrap()
            })
            .collect();
        ciphernode.es_sss_collected = vec![Vec::new(); count];
    });
}

/// Aggregate collected shares to compute secret key and smudging polynomials for each ciphernode.
pub fn calculate_sk_poly_sum_and_es_poly_sum(
    ciphernodes: &mut [Ciphernode],
    params: Arc<bfv::BfvParameters>,
    n: usize,
    threshold: usize,
) {
    ciphernodes.par_iter_mut().for_each(|ciphernode| {
        let mut share_manager = ShareManager::new(n, threshold, params.clone());
        ciphernode.sk_poly_sum = share_manager
            .aggregate_collected_shares(&ciphernode.sk_sss_collected)
            .unwrap();
        ciphernode.es_poly_sum = ciphernode
            .es_sss_collected
            .iter()
            .map(|shares| {
                let mut share_manager = ShareManager::new(n, threshold, params.clone());
                share_manager.aggregate_collected_shares(shares).unwrap()
            })
            .collect();
    });
}

/// Compute decryption share polynomial for each ciphernode for each tally.
pub fn calculate_d_share_poly(
    ciphernodes: &mut [Ciphernode],
    params: Arc<bfv::BfvParameters>,
    n: usize,
    threshold: usize,
    tallies: &[Arc<Ciphertext>],
) {
    ciphernodes.par_iter_mut().for_each(|ciphernode| {
        ciphernode.d_share_poly = tallies
            .iter()
            .enumerate()
            .map(|(idx, tally)| {
                let mut share_manager = ShareManager::new(n, threshold, params.clone());
                share_manager
                    .decryption_share(
                        tally.clone(),
                        ciphernode.sk_poly_sum.clone(),
                        ciphernode.es_poly_sum[idx].clone(),
                    )
                    .unwrap()
            })
            .collect();
    });
}

/// Combine decryption shares and recover the plaintext result.
pub fn calculate_plaintext(
    params: Arc<bfv::BfvParameters>,
    n: usize,
    threshold: usize,
    ciphernodes: &[Ciphernode],
    tallies: &[Arc<Ciphertext>],
) -> Vec<u64> {
    let mut results = Vec::new();
    for (idx, tally) in tallies.iter().enumerate() {
        let mut d_share_polys: Vec<Poly> = Vec::new();
        for ciphernode in ciphernodes.iter().take(threshold + 1) {
            d_share_polys.push(ciphernode.d_share_poly[idx].clone());
        }
        // The ciphertext is required here to correctly reconstruct the plaintext from the
        // combined decryption shares.
        let mut share_manager = ShareManager::new(n, threshold, params.clone());
        let open_results =
            share_manager.decrypt_from_shares(d_share_polys, tally.clone()).unwrap();
        let result_vec = Vec::<u64>::try_decode(&open_results, Encoding::poly()).unwrap();
        results.push(result_vec[0]);
    }
    results
}

/// Simulate network share swapping among ciphernodes.
pub fn swap_shares(ciphernodes: &mut [Ciphernode], params: Arc<bfv::BfvParameters>) {
    let degree = params.degree();
    let num_ciphernodes = ciphernodes.len();
    let num_esi = ciphernodes.first().map(|p| p.esi_sss.len()).unwrap_or(0);
    let mut i = 0;
    for _ in 0..num_ciphernodes {
        for j in 0..num_ciphernodes {
            let mut node_share_m = Array::zeros((0, degree));
            for m in 0..params.moduli().len() {
                node_share_m
                    .push_row(ArrayView::from(&ciphernodes[j].sk_sss[m].row(i).clone()))
                    .unwrap();
            }
            ciphernodes[i].sk_sss_collected.push(node_share_m);

            for s in 0..num_esi {
                let mut es_node_share_m = Array::zeros((0, degree));
                for m in 0..params.moduli().len() {
                    es_node_share_m
                        .push_row(ArrayView::from(
                            &ciphernodes[j].esi_sss[s][m].row(i).clone(),
                        ))
                        .unwrap();
                }
                ciphernodes[i].es_sss_collected[s].push(es_node_share_m);
            }
        }
        i += 1;
    }
}
