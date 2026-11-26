//! Public API coverage for distributed l-BFV keys and threshold decryption.
#![allow(clippy::indexing_slicing)]

#[path = "../examples/support/trlbfv.rs"]
mod ceremony;
#[cfg(feature = "synchronized-decryption")]
#[allow(dead_code)]
#[path = "../examples/support/simulated_key_setup.rs"]
mod simulated_key_setup;

use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, CommonRandomPolyVec, Encoding, Plaintext, SecretKey,
};
use fhe::lbfv::{LBFVPublicKey, LBFVRelinearizationKey};
use fhe::trbfv::FreshNoiseModel;
use fhe::trlbfv::{PublicKeyShare, RelinKeyShare, aggregate_key_pair};
use fhe::{Error, EvaluationKeyError, MultipartyError, ReferenceStringRole, Result};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;

fn params() -> Result<Arc<BfvParameters>> {
    BfvParametersBuilder::new()
        .set_degree(16)
        .set_plaintext_modulus(257)
        .set_moduli_sizes(&[55; 5])
        .build_arc()
}

#[test]
fn explicit_ss_threshold_product() -> Result<()> {
    let params = params()?;
    let mut rng = ChaCha8Rng::from_seed([41; 32]);
    let a = CommonRandomPolyVec::new(&params, &mut rng)?;
    let d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
    let mut committee = ceremony::Committee::deal(&params, &a, &d1, &mut rng)?;
    let config = committee.noise_config()?;
    assert_eq!(config.fresh_noise_model, FreshNoiseModel::LbfvPublicKey);
    assert_eq!(config.mult_depth, 1);
    let ct = committee.product(3, 5, &mut rng)?;
    let pt = committee.decrypt_ss(&ct, &mut rng)?;
    assert_eq!(
        Vec::<u64>::try_decode(&pt, Encoding::poly())?.first(),
        Some(&15)
    );
    Ok(())
}

#[cfg(feature = "synchronized-decryption")]
#[test]
fn seeded_synchronized_threshold_product() -> Result<()> {
    use ceremony::{OPENERS, PARTIES, THRESHOLD};
    use fhe::trbfv::{SmudgingNoiseGenerator, SynchronizedDecryptor};
    let params = params()?;
    let mut rng = ChaCha8Rng::from_seed([42; 32]);
    let a = CommonRandomPolyVec::from_seed(&params, [1; 32])?;
    let d1 = CommonRandomPolyVec::from_seed(&params, [2; 32])?;
    let committee = ceremony::Committee::deal(&params, &a, &d1, &mut rng)?;
    let ct = committee.product(3, 5, &mut rng)?;
    let keys = simulated_key_setup::simulated_committee_prf_keys(PARTIES, &mut rng)?;
    let noise = SmudgingNoiseGenerator::new(committee.noise_config()?)?;
    let decryptor = SynchronizedDecryptor::new(PARTIES, THRESHOLD, params)?;
    let partials = OPENERS
        .iter()
        .map(|&id| {
            decryptor.decryption_share(
                &ct,
                &committee.secret_shares[id - 1],
                id,
                &OPENERS,
                noise.generate(&mut rng)?,
                &keys[id - 1],
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let pt = decryptor.decrypt_from_shares(&partials, &ct)?;
    assert_eq!(
        Vec::<u64>::try_decode(&pt, Encoding::poly())?.first(),
        Some(&15)
    );
    Ok(())
}

#[test]
fn aggregate_keys_preserve_seeded_and_explicit_levels_and_wire_roles() -> Result<()> {
    let params = params()?;
    let mut rng = ChaCha8Rng::from_seed([20; 32]);
    let sks = [
        SecretKey::random(&params, &mut rng),
        SecretKey::random(&params, &mut rng),
    ];
    // Oracle for the evaluator at nonzero levels; threshold openings above
    // use Shamir shares only and never build a joint secret.
    let joint = SecretKey::new(
        sks[0]
            .coeffs
            .iter()
            .zip(&*sks[1].coeffs)
            .map(|(a, b)| a + b)
            .collect(),
        &params,
    );
    let mut used_urs = Vec::new();
    for seeded in [false, true] {
        let a_seed = rng.random();
        let a = CommonRandomPolyVec::from_seed(&params, a_seed)?;
        // One public-key contribution per dealer, reused for both levels.
        let public_shares = sks
            .iter()
            .map(|sk| {
                let pk = if seeded {
                    PublicKeyShare::contribute_with_seed(sk, a_seed, &mut rng)?
                } else {
                    PublicKeyShare::contribute_with_polys(sk, &a.to_polys(), &mut rng)?
                };
                let bytes = pk.to_bytes();
                assert!(LBFVPublicKey::from_bytes(&bytes, &params).is_err());
                PublicKeyShare::from_bytes(&bytes, &params)
            })
            .collect::<Result<Vec<_>>>()?;
        for level in [0, 1] {
            // Each level and encoding gets an independent URS, shared by its dealers.
            let d1_seed = rng.random();
            let d1 = CommonRandomPolyVec::from_seed(&params, d1_seed)?;
            let count = params.moduli().len() - level;
            let prefix = |crp: &CommonRandomPolyVec| {
                crp.to_polys()
                    .into_iter()
                    .take(count)
                    .map(|p| p.into_ntt_shoup())
                    .collect()
            };
            let mut pairs = Vec::new();
            for (sk, pk) in sks.iter().zip(&public_shares) {
                let rk = if seeded {
                    RelinKeyShare::contribute_with_seed(sk, d1_seed, a_seed, level, 0, &mut rng)?
                } else {
                    RelinKeyShare::contribute_with_polys(
                        sk,
                        prefix(&d1),
                        prefix(&a),
                        level,
                        0,
                        &mut rng,
                    )?
                };
                assert!(LBFVRelinearizationKey::from_bytes(&rk.to_bytes(), &params).is_err());
                let imported = RelinKeyShare::from_bytes(&rk.to_bytes(), &params)?;
                assert_eq!(imported, rk);
                pairs.push((pk.clone(), imported));
            }
            for row in pairs[0].1.d1_components() {
                let coefficients = row.coefficients().to_owned();
                assert!(!used_urs.contains(&coefficients), "reused a URS row");
                used_urs.push(coefficients);
            }
            let (pk, rk) = aggregate_key_pair(pairs)?;
            assert_eq!(pk.seed.is_some(), seeded);
            assert!(PublicKeyShare::from_bytes(&pk.to_bytes(), &params).is_err());
            assert!(RelinKeyShare::from_bytes(&rk.to_bytes(), &params).is_err());
            let rk = LBFVRelinearizationKey::from_bytes(&rk.to_bytes(), &params)?;
            let pk = LBFVPublicKey::from_bytes(&pk.to_bytes(), &params)?;
            let mut encrypt = |v| {
                pk.try_encrypt(
                    &Plaintext::try_encode(&[v], Encoding::poly_at_level(level), &params)?,
                    &mut rng,
                )
            };
            let mut ct = &encrypt(3u64)? * &encrypt(5u64)?;
            rk.relinearizes(&mut ct)?;
            assert_eq!(
                Vec::<u64>::try_decode(&joint.try_decrypt(&ct)?, Encoding::poly())?.first(),
                Some(&15)
            );
        }
    }
    Ok(())
}

#[test]
fn released_0_6_keys_still_read_and_write_identically() -> Result<()> {
    // Generated by the unmodified v0.6.0 public API with this exact RNG stream.
    let params = BfvParametersBuilder::new()
        .set_degree(8)
        .set_plaintext_modulus(17)
        .set_moduli_sizes(&[37; 3])
        .set_variance(3)
        .set_error1_variance_usize(8)
        .build_arc()?;
    let mut rng = ChaCha8Rng::from_seed([53; 32]);
    let sk = SecretKey::random(&params, &mut rng);
    let pk: LBFVPublicKey = LBFVPublicKey::new_with_seed(&sk, [7; 32], &mut rng);
    let level_zero = LBFVRelinearizationKey::new(&sk, &pk, None, &mut rng)?;
    let level_one = LBFVRelinearizationKey::new_leveled(
        &sk,
        &pk,
        Some([8; 32]),
        1,
        0,
        &mut ChaCha8Rng::from_seed([54; 32]),
    )?;
    let seeded = include_bytes!("fixtures/lbfv-v0.6.0/pk-seeded.bin");
    let explicit = include_bytes!("fixtures/lbfv-v0.6.0/pk-explicit.bin");
    let rlk = include_bytes!("fixtures/lbfv-v0.6.0/rlk.bin");
    let rlk_one = include_bytes!("fixtures/lbfv-v0.6.0/rlk-level1.bin");
    assert_eq!(pk.to_bytes(), seeded.as_slice());
    for (level, generated, bytes) in [
        (0, level_zero, rlk.as_slice()),
        (1, level_one, rlk_one.as_slice()),
    ] {
        assert_eq!(generated.to_bytes(), bytes);
        let rk = LBFVRelinearizationKey::from_bytes(bytes, &params)?;
        assert_eq!(rk.to_bytes(), bytes);
        for bytes in [seeded.as_slice(), explicit.as_slice()] {
            let pk = LBFVPublicKey::from_bytes(bytes, &params)?;
            assert_eq!(pk.to_bytes(), bytes);
            let ct = pk.try_encrypt(
                &Plaintext::try_encode(&[3u64], Encoding::poly_at_level(level), &params)?,
                &mut rng,
            )?;
            let mut square = &ct * &ct;
            rk.relinearizes(&mut square)?;
            assert_eq!(
                Vec::<u64>::try_decode(&sk.try_decrypt(&square)?, Encoding::poly())?.first(),
                Some(&9)
            );
        }
    }
    Ok(())
}

#[test]
fn mismatched_or_missing_contributions_are_rejected() -> Result<()> {
    let params = params()?;
    let mut rng = ChaCha8Rng::from_seed([21; 32]);
    let sk = SecretKey::random(&params, &mut rng);
    let other_sk = SecretKey::random(&params, &mut rng);
    let pk = PublicKeyShare::contribute_with_seed(&sk, [1; 32], &mut rng)?;
    let other_pk = PublicKeyShare::contribute_with_seed(&other_sk, [1; 32], &mut rng)?;
    let mut share = |sk: &SecretKey, d, a, level| {
        RelinKeyShare::contribute_with_seed(sk, [d; 32], [a; 32], level, 0, &mut rng)
    };
    assert!(matches!(
        aggregate_key_pair([]),
        Err(Error::Multiparty(MultipartyError::NoShares))
    ));
    assert!(matches!(
        share(&sk, 1, 1, 0),
        Err(Error::Multiparty(
            MultipartyError::IdenticalReferenceStringSeeds
        ))
    ));
    let first = share(&sk, 2, 1, 0)?;
    let other_crs = share(&other_sk, 2, 7, 0)?;
    assert!(matches!(
        aggregate_key_pair([(other_pk.clone(), other_crs.clone())]),
        Err(Error::Multiparty(MultipartyError::PublicKeyCrsMismatch {
            row_index: 0
        }))
    ));
    let pair = (pk, first);
    assert!(matches!(
        aggregate_key_pair([pair.clone(), (other_pk.clone(), other_crs)]),
        Err(Error::Multiparty(
            MultipartyError::ReferenceStringMismatch {
                role: ReferenceStringRole::Crs,
                share_index: 1,
                reference_share_index: 0
            }
        ))
    ));
    assert!(matches!(
        aggregate_key_pair([pair.clone(), (other_pk.clone(), share(&other_sk, 3, 1, 0)?)]),
        Err(Error::Multiparty(
            MultipartyError::ReferenceStringMismatch {
                role: ReferenceStringRole::Urs,
                share_index: 1,
                reference_share_index: 0
            }
        ))
    ));
    assert!(matches!(
        aggregate_key_pair([pair, (other_pk, share(&other_sk, 4, 1, 1)?)]),
        Err(Error::EvaluationKey(
            EvaluationKeyError::InvalidLbfvLayout {
                reason: "contributions have different parameters or levels"
            }
        ))
    ));
    Ok(())
}
