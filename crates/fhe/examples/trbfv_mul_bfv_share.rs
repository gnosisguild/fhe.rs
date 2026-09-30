// Threshold BFV multiplication with distributed l-BFV RLK and encrypted share transport.
//
// Uses secure16384 computation and transport profiles from support/presets.rs.
// The transport plaintext modulus must be >= max(q_i), so canonical Shamir
// residues encode without reduction. Smudging conservatively bounds all parties'
// RLK contributions. Only odd committees match the paper's n = 2t + 1 model.
// Local simulation only; see src/trbfv/README.md for the protocol boundary.

#![allow(clippy::indexing_slicing, missing_docs)]

#[path = "../support/mod.rs"]
mod support;

use std::{env, error::Error, sync::Arc};

use fhe::{
    aggregate::AggregateIter,
    bfv::{self, Ciphertext, CommonRandomPolyVec, Encoding, Plaintext, PublicKey, SecretKey},
    lbfv::{LBFVPublicKey, LBFVRelinearizationKey},
    trbfv::{FreshNoiseModel, ShareManager, SmudgingConfig, SmudgingNoiseGenerator},
    trlbfv::{PublicKeyShare, RelinKeyShare, aggregate_relinearization_key},
};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use ndarray::{Array, ArrayView};
use rand_distr::{Distribution, Uniform};
use rayon::prelude::*;
use std::time::Instant;
use support::examples::trbfv::{TrbfvShares, parse_cli, print_notice_without_num_summed};
use support::examples::util::timeit::timeit;

fn main() -> Result<(), Box<dyn Error>> {
    let preset = support::presets::secure16384()?;
    println!("Building trBFV parameters (first set)...");
    let params_trbfv: Arc<bfv::BfvParameters> =
        timeit!("Parameters generation (trBFV)", preset.parameters.clone());
    let degree = params_trbfv.degree();
    println!(
        "✓ trBFV parameters: [{}]",
        params_trbfv
            .moduli()
            .iter()
            .map(|q| format!("0x{q:016x}"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // ── Second BFV parameter set (share encryption) ───────────────────────────
    // The plaintext modulus equals the largest computation modulus
    // (k = q[0] = max(q_i)), so every canonical Shamir share residue
    // r ∈ [0, q_i) is strictly below k and encodes exactly.
    println!("\nBuilding share-encryption parameters (second set)...");
    let params_share_enc: Arc<bfv::BfvParameters> = timeit!(
        "Parameters generation (share enc)",
        preset.encrypted_share_parameters()?
    );
    let plaintext_modulus_share_enc = params_share_enc.plaintext();
    println!(
        "✓ Share-enc parameters: [{}] (plaintext = 0x{:016x})",
        params_share_enc
            .moduli()
            .iter()
            .map(|q| format!("0x{q:016x}"))
            .collect::<Vec<_>>()
            .join(", "),
        plaintext_modulus_share_enc
    );

    // Transport exactness guard: BFV encoding reduces coefficients modulo the
    // share-encryption plaintext modulus k, so the profile must keep
    // k ≥ max(q_i); otherwise high canonical residues would silently wrap.
    let max_computation_modulus = params_trbfv.moduli().iter().copied().max().unwrap();
    assert!(
        plaintext_modulus_share_enc >= max_computation_modulus,
        "share-encryption plaintext modulus {plaintext_modulus_share_enc} does not \
         cover the largest computation modulus {max_computation_modulus}; \
         transported Shamir residues would silently wrap"
    );

    // ── CLI argument parsing ──────────────────────────────────────────────────
    let args: Vec<String> = env::args().skip(1).collect();
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_without_num_summed(None)
    }

    let cli = match parse_cli(
        &args,
        preset.num_parties,
        preset.threshold,
        preset.lambda,
        None,
    ) {
        Ok(cli) => cli,
        Err(error) => print_notice_without_num_summed(Some(error)),
    };
    let num_parties = cli.num_parties;
    let threshold = cli.threshold;
    let lambda = cli.lambda;

    // Use the secure-16384 design point supplied for the depth-3 preset.
    let mut rng = rand::rng();

    println!("\n# Threshold BFV multiplication");
    println!("  num_parties       = {num_parties}  (params: n=20, k=1000, z=3, λ=31)");
    println!("  threshold         = {threshold}");
    println!("  lambda            = {lambda}  (bounded by fhe::trbfv::smudging::MAX_LAMBDA)");
    println!(
        "  l-BFV participants = {num_parties}  (accepted RLK contributors for smudging bound)"
    );

    // ── Party setup ───────────────────────────────────────────────────────────
    // Two shared CRP vectors for the l-BFV RLK protocol. In deployment these would
    // be established via coin-tossing.
    let crp_a = CommonRandomPolyVec::new(&params_trbfv, &mut rng)?;
    let crp_d1 = CommonRandomPolyVec::new(&params_trbfv, &mut rng)?;

    struct Party {
        shares: TrbfvShares,
        decryption_share: Poly<PowerBasis>,
        pk_lbfv_share: PublicKeyShare, // l-BFV PK contribution (shared crs_a)
        rlk_share: RelinKeyShare,
        // Share-encryption key pair (second BFV parameter set).
        secret_key_enc: SecretKey,
        public_key_enc: PublicKey,
    }

    let share_manager = ShareManager::new(num_parties, threshold, params_trbfv.clone()).unwrap();
    let num_moduli = params_trbfv.moduli().len();

    println!("\n💻 Available CPU cores: {}", rayon::current_num_threads());
    let mut parties: Vec<Party> = timeit!("Party setup (parallel)", {
        (0..num_parties)
            .into_par_iter()
            .map(|_| {
                let mut rng = rand::rng();

                let secret_key = SecretKey::random(&params_trbfv, &mut rng);

                let share_manager =
                    ShareManager::new(num_parties, threshold, params_trbfv.clone()).unwrap();
                let secret_key_poly = share_manager
                    .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
                    .unwrap();

                let secret_key_shares_transport = share_manager
                    .generate_secret_key_shares(secret_key_poly, &mut rng)
                    .unwrap()
                    .into_transport();

                // Pure product ((a*b)*c)*d: depth 3, tight m=1. Use m=3 as a
                // conservative overprovision for this profile, with the l-BFV
                // model matching its wider encryption randomness.
                let config = SmudgingConfig::new(
                    params_trbfv.clone(),
                    num_parties,
                    3,
                    lambda,
                    FreshNoiseModel::LbfvPublicKey,
                )
                .unwrap()
                .with_mult_depth(preset.multiplicative_depth.unwrap());
                let generator = SmudgingNoiseGenerator::new(config).unwrap();
                let smudging_noise = generator.generate(&mut rng).unwrap();
                let smudging_shares_transport = share_manager
                    .generate_smudging_shares(smudging_noise, &mut rng)
                    .unwrap()
                    .into_transport();

                // l-BFV PK contribution (shared crp_a, same a_j across all parties).
                let pk_lbfv_share =
                    PublicKeyShare::contribute_with_crp(&secret_key, &crp_a, &mut rng).unwrap();

                // l-BFV RLK share for SK = Σ sk_j.
                let rlk_share = RelinKeyShare::contribute_with_crp(
                    &secret_key,
                    &crp_d1,
                    &crp_a,
                    0,
                    0,
                    &mut rng,
                )
                .unwrap();

                // Share-encryption key pair under the second parameter set.
                let secret_key_enc = SecretKey::random(&params_share_enc, &mut rng);
                let public_key_enc = PublicKey::new(&secret_key_enc, &mut rng);

                let ctx0 = params_trbfv.context_at_level(0).unwrap();
                Party {
                    shares: TrbfvShares::new(
                        secret_key_shares_transport,
                        smudging_shares_transport,
                    ),
                    decryption_share: Poly::<PowerBasis>::zero(ctx0),
                    pk_lbfv_share,
                    rlk_share,
                    secret_key_enc,
                    public_key_enc,
                }
            })
            .collect()
    });

    // ── Distributed pk + RLK aggregation ─────────────────────────────────────
    // pk_lbfv is used for both RLK (b_vec) and encryption (c[0]).
    let aggregated_pk: LBFVPublicKey;
    let rlk: LBFVRelinearizationKey = timeit!("Distributed pk + RLK aggregation", {
        let pk_lbfv_shares: Vec<PublicKeyShare> =
            parties.iter().map(|p| p.pk_lbfv_share.clone()).collect();
        aggregated_pk = pk_lbfv_shares.into_iter().aggregate::<LBFVPublicKey>()?;
        let rlk_shares: Vec<RelinKeyShare> = parties.iter().map(|p| p.rlk_share.clone()).collect();
        aggregate_relinearization_key(&rlk_shares, &aggregated_pk)?
    });
    let pk_lbfv = &aggregated_pk;
    println!("✓ pk_lbfv and RLK aggregated (l = {})", rlk.l()?);

    // ── Share encryption and transmission ─────────────────────────────────────
    // Each sender BFV-encrypts the share row it owes to each receiver under that
    // receiver's share-encryption public key (second parameter set). This is safe:
    //   • k = q[0] = max(q_i) → every canonical share residue r ∈ [0, q_i) is
    //     strictly below k, so encoding is exact (no silent reduction mod k)
    //   • k ≈ 2^50 < q₀/2 ≈ 2^51  → BFV decrypt is algebraically exact
    //
    // encrypted_shares[sender][receiver] = (Vec<Ciphertext>, Vec<Ciphertext>)
    //   first  vec: one ciphertext per modulus for the sk share row
    //   second vec: one ciphertext per modulus for the smudging error share row
    let public_key_enc_list: Vec<PublicKey> =
        parties.iter().map(|p| p.public_key_enc.clone()).collect();

    let encrypted_shares: Vec<Vec<(Vec<Ciphertext>, Vec<Ciphertext>)>> =
        timeit!("Share encryption (parallel)", {
            parties
                .par_iter()
                .map(|party| {
                    (0..num_parties)
                        .map(|receiver_idx| {
                            let mut rng = rand::rng();
                            let rpk = &public_key_enc_list[receiver_idx];

                            let enc_sk: Vec<Ciphertext> = (0..num_moduli)
                                .map(|m| {
                                    let row = party.shares.secret_key_shares_transport[m]
                                        .row(receiver_idx)
                                        .to_vec();
                                    let pt = Plaintext::try_encode(
                                        &row,
                                        Encoding::poly(),
                                        &params_share_enc,
                                    )
                                    .unwrap();
                                    rpk.try_encrypt(&pt, &mut rng).unwrap()
                                })
                                .collect();

                            let enc_es: Vec<Ciphertext> = (0..num_moduli)
                                .map(|m| {
                                    let row = party.shares.smudging_shares_transport[m]
                                        .row(receiver_idx)
                                        .to_vec();
                                    let pt = Plaintext::try_encode(
                                        &row,
                                        Encoding::poly(),
                                        &params_share_enc,
                                    )
                                    .unwrap();
                                    rpk.try_encrypt(&pt, &mut rng).unwrap()
                                })
                                .collect();

                            (enc_sk, enc_es)
                        })
                        .collect()
                })
                .collect()
        });

    // ── Share decryption and collection ───────────────────────────────────────
    timeit!("Share decryption and collection (parallel)", {
        parties
            .par_iter_mut()
            .enumerate()
            .for_each(|(receiver_idx, party)| {
                for sender_shares in encrypted_shares.iter() {
                    let (enc_sk, enc_es) = &sender_shares[receiver_idx];

                    let mut secret_key_rows = Array::zeros((0, degree));
                    for ct in enc_sk {
                        let pt = party.secret_key_enc.try_decrypt(ct).unwrap();
                        let row: Vec<u64> = Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();
                        secret_key_rows.push_row(ArrayView::from(&row)).unwrap();
                    }
                    let mut smudging_rows = Array::zeros((0, degree));
                    for ct in enc_es {
                        let pt = party.secret_key_enc.try_decrypt(ct).unwrap();
                        let row: Vec<u64> = Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();
                        smudging_rows.push_row(ArrayView::from(&row)).unwrap();
                    }
                    party
                        .shares
                        .collect_transport(secret_key_rows, smudging_rows);
                }
            });
    });

    // ── Lagrange share aggregation ────────────────────────────────────────────
    timeit!("Sum collected shares (parallel)", {
        parties.par_iter_mut().for_each(|party| {
            party.shares.aggregate(&share_manager).unwrap();
        });
    });

    // ── Homomorphic multiplication (depth 3) ─────────────────────────────────
    // k=1000. Three chained multiplications: ((a×b)×c)×d.
    // Values in [1,5] so the max product is 5⁴=625 < 1000.
    let dist = Uniform::new_inclusive(1u64, 5).unwrap();
    let a = dist.sample(&mut rng);
    let b = dist.sample(&mut rng);
    let c = dist.sample(&mut rng);
    let d = dist.sample(&mut rng);
    println!("\n🔢  {} × {} × {} × {} = {}", a, b, c, d, a * b * c * d);

    let ct_a = timeit!("Encrypt a", {
        let pt = Plaintext::try_encode(&[a], Encoding::poly(), &params_trbfv)?;
        pk_lbfv.try_encrypt(&pt, &mut rng)?
    });
    let ct_b = timeit!("Encrypt b", {
        let pt = Plaintext::try_encode(&[b], Encoding::poly(), &params_trbfv)?;
        pk_lbfv.try_encrypt(&pt, &mut rng)?
    });
    let ct_c = timeit!("Encrypt c", {
        let pt = Plaintext::try_encode(&[c], Encoding::poly(), &params_trbfv)?;
        pk_lbfv.try_encrypt(&pt, &mut rng)?
    });
    let ct_d = timeit!("Encrypt d", {
        let pt = Plaintext::try_encode(&[d], Encoding::poly(), &params_trbfv)?;
        pk_lbfv.try_encrypt(&pt, &mut rng)?
    });

    let product = timeit!("Multiply and relinearize (depth 3)", {
        let mut ct_ab = &ct_a * &ct_b;
        rlk.relinearizes(&mut ct_ab)?;
        let mut ct_abc = &ct_ab * &ct_c;
        rlk.relinearizes(&mut ct_abc)?;
        let mut ct_abcd = &ct_abc * &ct_d;
        rlk.relinearizes(&mut ct_abcd)?;
        Arc::new(ct_abcd)
    });
    println!("  Product ciphertext level: {}", product.level);

    // ── Threshold decryption ──────────────────────────────────────────────────
    let t_start = Instant::now();
    parties.par_iter_mut().for_each(|party| {
        let smudging = party.shares.take_smudging().unwrap();
        let secret_key = party.shares.secret_key().unwrap();
        party.decryption_share = share_manager
            .decryption_share(&product, secret_key, smudging)
            .unwrap();
    });
    println!(
        "Decryption share generation: {:.2?} ({:.2} ms/party)",
        t_start.elapsed(),
        t_start.elapsed().as_millis() as f64 / num_parties as f64
    );

    let decryption_shares: Vec<Poly<PowerBasis>> = parties
        .iter()
        .take(threshold + 1)
        .map(|p| p.decryption_share.clone())
        .collect();

    let result = timeit!("Combine shares and decrypt", {
        let party_indices: Vec<usize> = (1..=threshold + 1).collect();
        let pt = share_manager
            .decrypt_from_shares(&decryption_shares, &party_indices, &product)
            .unwrap();
        let v = Vec::<u64>::try_decode(&pt, Encoding::poly())?;
        Ok::<u64, Box<dyn Error>>(v[0])
    })?;

    println!("\nComputed result: {result}");
    println!("Expected result: {}", a * b * c * d);
    assert_eq!(result, a * b * c * d, "Threshold multiplication failed!");
    println!(
        "✅ Threshold BFV multiplication (depth 3) with BFV-encrypted share transport correct!"
    );

    Ok(())
}
