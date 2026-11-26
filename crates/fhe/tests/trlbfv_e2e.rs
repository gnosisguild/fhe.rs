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
use fhe::trlbfv::{PublicKeyShare, RelinKeyShare, aggregate_key_pair};
use fhe::{Error, MultipartyError, Result};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
};
use rand::SeedableRng;
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
    for seeded in [false, true] {
        let a = CommonRandomPolyVec::from_seed(&params, [1; 32])?;
        let d1 = CommonRandomPolyVec::from_seed(&params, [2; 32])?;
        for level in [0, 1] {
            let count = params.moduli().len() - level;
            let prefix = |crp: &CommonRandomPolyVec| {
                crp.to_polys()
                    .into_iter()
                    .take(count)
                    .map(|p| p.into_ntt_shoup())
                    .collect()
            };
            let mut pairs = Vec::new();
            for sk in &sks {
                let (pk, rk) = if seeded {
                    (
                        PublicKeyShare::contribute_with_seed(sk, [1; 32], &mut rng)?,
                        RelinKeyShare::contribute_with_seed(
                            sk, [2; 32], [1; 32], level, 0, &mut rng,
                        )?,
                    )
                } else {
                    (
                        PublicKeyShare::contribute_with_polys(sk, &a.to_polys(), &mut rng)?,
                        RelinKeyShare::contribute_with_polys(
                            sk,
                            prefix(&d1),
                            prefix(&a),
                            level,
                            0,
                            &mut rng,
                        )?,
                    )
                };
                assert!(LBFVPublicKey::from_bytes(&pk.to_bytes(), &params).is_err());
                assert!(LBFVRelinearizationKey::from_bytes(&rk.to_bytes(), &params).is_err());
                let imported = RelinKeyShare::from_bytes(&rk.to_bytes(), &params)?;
                assert_eq!(imported, rk);
                pairs.push((
                    PublicKeyShare::from_bytes(&pk.to_bytes(), &params)?,
                    imported,
                ));
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
    let rk = LBFVRelinearizationKey::new(&sk, &pk, None, &mut rng)?;
    let seeded = include_bytes!("fixtures/lbfv-v0.6.0/pk-seeded.bin");
    let explicit = include_bytes!("fixtures/lbfv-v0.6.0/pk-explicit.bin");
    let rlk = include_bytes!("fixtures/lbfv-v0.6.0/rlk.bin");
    assert_eq!(pk.to_bytes(), seeded.as_slice());
    assert_eq!(rk.to_bytes(), rlk.as_slice());
    let rk = LBFVRelinearizationKey::from_bytes(rlk, &params)?;
    assert_eq!(rk.to_bytes(), rlk.as_slice());
    for bytes in [seeded.as_slice(), explicit.as_slice()] {
        let pk = LBFVPublicKey::from_bytes(bytes, &params)?;
        assert_eq!(pk.to_bytes(), bytes);
        let ct = pk.try_encrypt(
            &Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?,
            &mut rng,
        )?;
        let mut square = &ct * &ct;
        rk.relinearizes(&mut square)?;
        assert_eq!(
            Vec::<u64>::try_decode(&sk.try_decrypt(&square)?, Encoding::poly())?.first(),
            Some(&9)
        );
    }
    Ok(())
}

#[test]
fn mismatched_or_missing_contributions_are_rejected() -> Result<()> {
    let params = params()?;
    let mut rng = ChaCha8Rng::from_seed([21; 32]);
    let sk = SecretKey::random(&params, &mut rng);
    let pk = PublicKeyShare::contribute_with_seed(&sk, [1; 32], &mut rng)?;
    let rk = |d, a, level, rng: &mut ChaCha8Rng| {
        RelinKeyShare::contribute_with_seed(&sk, [d; 32], [a; 32], level, 0, rng)
    };
    assert!(matches!(
        aggregate_key_pair([]),
        Err(Error::Multiparty(MultipartyError::NoShares))
    ));
    assert!(matches!(
        rk(1, 1, 0, &mut rng),
        Err(Error::Multiparty(
            MultipartyError::IdenticalReferenceStringSeeds
        ))
    ));
    assert!(matches!(
        aggregate_key_pair([(pk.clone(), rk(2, 3, 0, &mut rng)?)]),
        Err(Error::Multiparty(
            MultipartyError::PublicKeyCrsMismatch { .. }
        ))
    ));
    assert!(matches!(
        aggregate_key_pair([
            (pk.clone(), rk(2, 1, 0, &mut rng)?),
            (pk.clone(), rk(3, 1, 0, &mut rng)?)
        ]),
        Err(Error::Multiparty(
            MultipartyError::ReferenceStringMismatch { .. }
        ))
    ));
    assert!(
        aggregate_key_pair([
            (pk.clone(), rk(2, 1, 0, &mut rng)?),
            (pk, rk(2, 1, 1, &mut rng)?)
        ])
        .is_err()
    );
    Ok(())
}
