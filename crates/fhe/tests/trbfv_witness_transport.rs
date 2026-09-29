//! Public-API integration tests for the trBFV proof-witness and persistence
//! boundary (issue #256).
//!
//! Covers the opt-in consuming witness APIs
//! (`generate_smudging_shares_with_witness`, `decryption_share_with_witness`)
//! and the consuming import/export of `AggregatedSecretKeyShare` and
//! `AggregatedSmudgingShare`, including the documented limits: exported bytes
//! can always be copied, and importing the same bytes twice yields two
//! independent owners (replay the application must prevent).

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

use std::sync::Arc;

use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::{
    AggregatedSecretKeyShare, AggregatedSmudgingShare, FreshNoiseModel, NoiseWitnessProvenance,
    SecretKeyShare, ShareManager, SmudgingConfig, SmudgingNoiseGenerator, SmudgingNoiseWitness,
    SmudgingShare,
};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::Array2;
use rand_chacha::ChaCha8Rng;
use zeroize::Zeroizing;

#[path = "../support/mod.rs"]
mod support;

/// Small paper-conforming committee: n = 2t + 1 = 3, threshold t = 1.
const N: usize = 3;
const THRESHOLD: usize = 1;

/// Transpose one dealer's per-`q_i` `[n, degree]` matrices into the
/// `[moduli, degree]` transport matrix for one recipient.
fn recipient_matrix(
    dealt: &[Array2<u64>],
    recipient: usize,
    moduli_count: usize,
    degree: usize,
) -> Array2<u64> {
    let mut rows = Array2::zeros((0, degree));
    for matrix in dealt.iter().take(moduli_count) {
        rows.push_row(ndarray::ArrayView::from(matrix.row(recipient)))
            .expect("append share row");
    }
    rows
}

/// Build a one-recipient key aggregate from the dealer's dealt matrices.
fn key_aggregate_from(
    manager: &ShareManager,
    secret_key_transport: &[Array2<u64>],
    params: &Arc<BfvParameters>,
) -> AggregatedSecretKeyShare {
    manager
        .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(recipient_matrix(
            secret_key_transport,
            0,
            params.moduli().len(),
            params.degree(),
        ))])
        .expect("aggregate key shares")
}

/// Produce one fresh aggregated noise share for one recipient through the
/// public generate-deal-aggregate flow.
fn noise_aggregate_for_recipient(
    manager: &ShareManager,
    params: &Arc<BfvParameters>,
    rng: &mut ChaCha8Rng,
    recipient: usize,
) -> AggregatedSmudgingShare {
    let config = SmudgingConfig::new(params.clone(), N, 1, 2, FreshNoiseModel::BfvPublicKey)
        .expect("smudging config");
    let noise = SmudgingNoiseGenerator::new(config)
        .expect("smudging generator")
        .generate(rng)
        .expect("smudging noise");
    let dealt = manager
        .generate_smudging_shares(noise, rng)
        .expect("smudging dealing")
        .into_transport();
    manager
        .aggregate_smudging_shares(vec![SmudgingShare::from_transport(recipient_matrix(
            &dealt,
            recipient,
            params.moduli().len(),
            params.degree(),
        ))])
        .expect("aggregate noise shares")
}

/// A well-formed fresh ciphertext for decryption-share calls.
fn fresh_ciphertext(
    params: &Arc<BfvParameters>,
    secret_key: &SecretKey,
    rng: &mut ChaCha8Rng,
) -> Arc<Ciphertext> {
    let pk = PublicKey::new(secret_key, rng);
    let plaintext = Plaintext::try_encode(&[9u64], Encoding::poly(), params).expect("encode");
    Arc::new(pk.try_encrypt(&plaintext, rng).expect("encrypt"))
}

fn clone_envelope(envelope: &Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(envelope.as_slice().to_vec())
}

/// Run one full threshold decryption where every dealer and every decrypting
/// party uses the witness variants, validating every witness along the way.
#[test]
fn witnessed_dealing_and_decryption_recover_the_plaintext() {
    let params = support::presets::insecure().unwrap().parameters;
    let mut rng = support::presets::rng(201);
    let manager = ShareManager::new(N, THRESHOLD, params.clone()).expect("share manager");

    let secret_key = SecretKey::random(&params, &mut rng);
    let secret_key_poly = manager
        .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
        .expect("secret key to polynomial");
    let secret_key_transport = manager
        .generate_secret_key_shares(secret_key_poly, &mut rng)
        .expect("secret key dealing")
        .into_transport();

    // Every dealer deals with a witness and exports it; every exported
    // dealing witness must validate under the dealt provenance.
    let dealt_list: Vec<Vec<Array2<u64>>> = (0..N)
        .map(|_| {
            let config =
                SmudgingConfig::new(params.clone(), N, 1, 2, FreshNoiseModel::BfvPublicKey)
                    .expect("smudging config");
            let noise = SmudgingNoiseGenerator::new(config)
                .expect("smudging generator")
                .generate(&mut rng)
                .expect("smudging noise");
            let (dealt, witness) = manager
                .generate_smudging_shares_with_witness(noise, &mut rng)
                .expect("witnessed smudging dealing");
            assert_eq!(witness.provenance(), NoiseWitnessProvenance::Dealt);
            let witness_bytes = witness.into_proof_bytes().expect("witness export");
            SmudgingNoiseWitness::validate_proof_bytes(
                witness_bytes.as_slice(),
                &params,
                NoiseWitnessProvenance::Dealt,
            )
            .expect("dealing witness bytes must validate");
            dealt.into_transport()
        })
        .collect();

    // Transpose the dealt matrices into per-recipient shares and aggregate:
    // every party gets its own key and noise aggregate for its own Shamir
    // coordinate.
    let key_aggregates: Vec<AggregatedSecretKeyShare> = (0..N)
        .map(|recipient| {
            manager
                .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(
                    recipient_matrix(
                        &secret_key_transport,
                        recipient,
                        params.moduli().len(),
                        params.degree(),
                    ),
                )])
                .expect("aggregate key shares")
        })
        .collect();
    let smudging_aggregates: Vec<AggregatedSmudgingShare> = (0..N)
        .map(|recipient| {
            (0..N)
                .map(|dealer| {
                    SmudgingShare::from_transport(recipient_matrix(
                        &dealt_list[dealer],
                        recipient,
                        params.moduli().len(),
                        params.degree(),
                    ))
                })
                .collect::<Vec<SmudgingShare>>()
        })
        .map(|shares| {
            manager
                .aggregate_smudging_shares(shares)
                .expect("aggregate smudging shares")
        })
        .collect();

    // Encrypt two fresh ciphertexts and add them (the modelled circuit).
    let pk = PublicKey::new(&secret_key, &mut rng);
    let mut encrypt = |value: u64| {
        let plaintext = Plaintext::try_encode(&[value], Encoding::poly(), &params).expect("encode");
        pk.try_encrypt(&plaintext, &mut rng).expect("encrypt")
    };
    let ciphertext = Arc::new(&encrypt(2) + &encrypt(3));

    // Each decrypting party consumes its noise aggregate through the
    // witness-returning variant; the resulting decryption witnesses must
    // validate for the decryption provenance only.
    let mut decryption_shares = Vec::new();
    for (party, aggregate) in smudging_aggregates.into_iter().enumerate() {
        let (share, witness) = manager
            .decryption_share_with_witness(&ciphertext, &key_aggregates[party], aggregate)
            .expect("witnessed decryption share");
        assert_eq!(witness.provenance(), NoiseWitnessProvenance::Decryption);
        let witness_bytes = witness.into_proof_bytes().expect("witness export");
        SmudgingNoiseWitness::validate_proof_bytes(
            witness_bytes.as_slice(),
            &params,
            NoiseWitnessProvenance::Decryption,
        )
        .expect("decryption witness bytes must validate");
        assert!(
            SmudgingNoiseWitness::validate_proof_bytes(
                witness_bytes.as_slice(),
                &params,
                NoiseWitnessProvenance::Dealt,
            )
            .is_err(),
            "a decryption witness must not validate under the dealing role"
        );
        decryption_shares.push(share);
    }

    // Reconstruction needs exactly threshold + 1 shares.
    let plaintext = manager
        .decrypt_from_shares(&decryption_shares[..THRESHOLD + 1], &[1, 2], &ciphertext)
        .expect("threshold decryption");
    let decoded = Vec::<u64>::try_decode(&plaintext, Encoding::poly()).expect("decode plaintext");
    let mut expected = vec![5u64];
    expected.resize(params.degree(), 0);
    assert_eq!(decoded, expected);
}

/// The aggregated key survives a persistence round trip and stays reusable;
/// key bytes can be imported twice into two independent reusable owners (the
/// documented unpreventable copy).
#[test]
fn key_aggregate_survives_persistence_and_reusable_import() {
    let params = support::presets::insecure().unwrap().parameters;
    let mut rng = support::presets::rng(202);
    let manager = ShareManager::new(N, THRESHOLD, params.clone()).expect("share manager");

    let secret_key = SecretKey::random(&params, &mut rng);
    let secret_key_poly = manager
        .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
        .expect("secret key to polynomial");
    let secret_key_transport = manager
        .generate_secret_key_shares(secret_key_poly, &mut rng)
        .expect("secret key dealing")
        .into_transport();
    let key_aggregate = key_aggregate_from(&manager, &secret_key_transport, &params);

    // Export consumes the live owner.
    let key_bytes = key_aggregate.into_persisted_bytes().expect("key export");

    // A fresh ciphertext to decrypt after the "restart".
    let ciphertext = fresh_ciphertext(&params, &secret_key, &mut rng);

    // After a "restart", the imported key works for decryption share
    // computation — and it is reusable, like the original owner.
    let imported_key =
        AggregatedSecretKeyShare::from_persisted_bytes(clone_envelope(&key_bytes), &params)
            .expect("key import");
    manager
        .decryption_share(
            &ciphertext,
            &imported_key,
            noise_aggregate_for_recipient(&manager, &params, &mut rng, 0),
        )
        .expect("decryption share with imported key");
    manager
        .decryption_share(
            &ciphertext,
            &imported_key,
            noise_aggregate_for_recipient(&manager, &params, &mut rng, 0),
        )
        .expect("second decryption share with imported key");

    // The same key bytes can be imported again: copies cannot be prevented,
    // and each import yields an independent reusable owner.
    let replayed_key =
        AggregatedSecretKeyShare::from_persisted_bytes(clone_envelope(&key_bytes), &params)
            .expect("replayed key import");
    manager
        .decryption_share(
            &ciphertext,
            &replayed_key,
            noise_aggregate_for_recipient(&manager, &params, &mut rng, 0),
        )
        .expect("decryption share with replayed key");
}

/// The aggregated noise survives persistence into a fresh single-use owner;
/// copied noise bytes can be imported (and used) twice, which is exactly the
/// replay no in-memory type can prevent.
#[test]
fn smudging_aggregate_persistence_keeps_single_use_per_import() {
    let params = support::presets::insecure().unwrap().parameters;
    let mut rng = support::presets::rng(203);
    let manager = ShareManager::new(N, THRESHOLD, params.clone()).expect("share manager");

    let secret_key = SecretKey::random(&params, &mut rng);
    let secret_key_poly = manager
        .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
        .expect("secret key to polynomial");
    let secret_key_transport = manager
        .generate_secret_key_shares(secret_key_poly, &mut rng)
        .expect("secret key dealing")
        .into_transport();
    let key_aggregate = key_aggregate_from(&manager, &secret_key_transport, &params);

    let noise_aggregate = noise_aggregate_for_recipient(&manager, &params, &mut rng, 0);

    // Export consumes the live owner; import restores a single-use owner that
    // exactly one decryption can consume.
    let noise_bytes = noise_aggregate
        .into_persisted_bytes()
        .expect("noise export");
    let restored =
        AggregatedSmudgingShare::from_persisted_bytes(clone_envelope(&noise_bytes), &params)
            .expect("noise import");
    let ciphertext = fresh_ciphertext(&params, &secret_key, &mut rng);
    manager
        .decryption_share(&ciphertext, &key_aggregate, restored)
        .expect("decryption with restored noise");

    // The copy is importable again — documented replay, not a bug.
    let replayed =
        AggregatedSmudgingShare::from_persisted_bytes(clone_envelope(&noise_bytes), &params)
            .expect("replayed noise import");
    manager
        .decryption_share(&ciphertext, &key_aggregate, replayed)
        .expect("decryption with replayed noise");
}

/// Wrong-role, wrong-params, empty, truncated, trailing, and oversized
/// payloads are rejected by the public import APIs and by the witness
/// validator; witness bytes are freely copyable and every copy validates.
#[test]
fn transport_boundary_rejects_malformed_and_mismatched_payloads() {
    let params = support::presets::insecure().unwrap().parameters;
    let other_params = fhe::bfv::BfvParametersBuilder::new()
        .set_degree(64)
        .set_plaintext_modulus(1153)
        .set_moduli_sizes(&[40, 40])
        .build_arc()
        .unwrap();
    let mut rng = support::presets::rng(204);
    let manager = ShareManager::new(N, THRESHOLD, params.clone()).expect("share manager");

    // Build one key envelope and one noise envelope through the public flow.
    let sk = SecretKey::random(&params, &mut rng);
    let secret_key_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
    let key_aggregate = manager
        .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(
            secret_key_poly.as_ref().coefficients().to_owned(),
        )])
        .expect("aggregate key shares");
    let key_bytes = key_aggregate.into_persisted_bytes().expect("key export");
    let noise_bytes = noise_aggregate_for_recipient(&manager, &params, &mut rng, 0)
        .into_persisted_bytes()
        .expect("noise export");

    // Role separation through the public API.
    assert!(
        AggregatedSmudgingShare::from_persisted_bytes(clone_envelope(&key_bytes), &params).is_err()
    );
    assert!(
        AggregatedSecretKeyShare::from_persisted_bytes(clone_envelope(&noise_bytes), &params)
            .is_err()
    );

    // Wrong parameter set on import.
    assert!(
        AggregatedSecretKeyShare::from_persisted_bytes(clone_envelope(&key_bytes), &other_params)
            .is_err()
    );
    assert!(
        AggregatedSmudgingShare::from_persisted_bytes(clone_envelope(&noise_bytes), &other_params)
            .is_err()
    );

    // Structural rejections for both payload kinds.
    for payload in [key_bytes.as_slice(), noise_bytes.as_slice()] {
        assert!(
            AggregatedSecretKeyShare::from_persisted_bytes(Zeroizing::new(Vec::new()), &params)
                .is_err()
        );
        for cut in [1usize, 8, 14, payload.len() / 2] {
            assert!(
                AggregatedSmudgingShare::from_persisted_bytes(
                    Zeroizing::new(payload[..cut.min(payload.len())].to_vec()),
                    &params
                )
                .is_err(),
                "truncated payload ({cut} bytes) must be rejected"
            );
        }
        let mut trailing = payload.to_vec();
        trailing.push(0);
        assert!(
            AggregatedSecretKeyShare::from_persisted_bytes(Zeroizing::new(trailing), &params)
                .is_err()
        );

        let mut bad_magic = payload.to_vec();
        bad_magic[0] = b'!';
        assert!(
            AggregatedSmudgingShare::from_persisted_bytes(Zeroizing::new(bad_magic), &params)
                .is_err()
        );

        // Oversized declared section length is rejected before any decoding.
        let mut oversized = payload.to_vec();
        oversized[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            AggregatedSecretKeyShare::from_persisted_bytes(Zeroizing::new(oversized), &params)
                .is_err()
        );
    }

    // Witness validation: copied bytes validate, everything mismatched is
    // rejected.
    let (_, witness) = manager
        .generate_smudging_shares_with_witness(
            SmudgingNoiseGenerator::new(
                SmudgingConfig::new(params.clone(), N, 1, 2, FreshNoiseModel::BfvPublicKey)
                    .unwrap(),
            )
            .unwrap()
            .generate(&mut rng)
            .unwrap(),
            &mut rng,
        )
        .unwrap();
    let witness_bytes = witness.into_proof_bytes().expect("witness bytes");

    let copied = clone_envelope(&witness_bytes);
    SmudgingNoiseWitness::validate_proof_bytes(
        witness_bytes.as_slice(),
        &params,
        NoiseWitnessProvenance::Dealt,
    )
    .expect("original witness bytes validate");
    SmudgingNoiseWitness::validate_proof_bytes(
        copied.as_slice(),
        &params,
        NoiseWitnessProvenance::Dealt,
    )
    .expect("copied witness bytes validate too (copying cannot be prevented)");

    assert!(
        SmudgingNoiseWitness::validate_proof_bytes(
            witness_bytes.as_slice(),
            &other_params,
            NoiseWitnessProvenance::Dealt
        )
        .is_err()
    );
    assert!(
        SmudgingNoiseWitness::validate_proof_bytes(
            &witness_bytes[..witness_bytes.len() / 2],
            &params,
            NoiseWitnessProvenance::Dealt
        )
        .is_err()
    );
    assert!(
        SmudgingNoiseWitness::validate_proof_bytes(
            &[0xff; 32],
            &params,
            NoiseWitnessProvenance::Dealt
        )
        .is_err()
    );
    // Witness bytes are not importable share material.
    assert!(
        AggregatedSmudgingShare::from_persisted_bytes(clone_envelope(&witness_bytes), &params)
            .is_err()
    );
    assert!(
        AggregatedSecretKeyShare::from_persisted_bytes(clone_envelope(&witness_bytes), &params)
            .is_err()
    );
}

/// Copy the envelope bytes: the exported `Zeroizing<Vec<u8>>` may be cloned
/// after the boundary, and both copies stay usable. This test documents that
/// the library cannot (and does not try to) prevent copying exported bytes.
#[test]
fn exported_bytes_can_always_be_copied() {
    let params = support::presets::insecure().unwrap().parameters;
    let mut rng = support::presets::rng(205);
    let manager = ShareManager::new(N, THRESHOLD, params.clone()).expect("share manager");

    let envelope = noise_aggregate_for_recipient(&manager, &params, &mut rng, 0)
        .into_persisted_bytes()
        .expect("noise export");

    // Plain Clone on the envelope type must compile and work.
    let cloned = clone_envelope(&envelope);

    let sk = SecretKey::random(&params, &mut rng);
    let secret_key_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
    let key_aggregate = manager
        .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(
            secret_key_poly.as_ref().coefficients().to_owned(),
        )])
        .expect("aggregate key shares");
    let ciphertext = fresh_ciphertext(&params, &sk, &mut rng);

    let first = AggregatedSmudgingShare::from_persisted_bytes(envelope, &params).unwrap();
    let second = AggregatedSmudgingShare::from_persisted_bytes(cloned, &params).unwrap();
    manager
        .decryption_share(&ciphertext, &key_aggregate, first)
        .unwrap();
    manager
        .decryption_share(&ciphertext, &key_aggregate, second)
        .unwrap();
}

/// One representative restored owner is usable end to end: the noise import
/// yields an owner accepted by `decryption_share` at the parameter set's
/// level-0 context.
#[test]
fn imported_noise_owner_is_usable_end_to_end() {
    let params = support::presets::insecure().unwrap().parameters;
    let mut rng = support::presets::rng(207);
    let manager = ShareManager::new(N, THRESHOLD, params.clone()).expect("share manager");
    let noise_bytes = noise_aggregate_for_recipient(&manager, &params, &mut rng, 1)
        .into_persisted_bytes()
        .expect("noise export");
    let restored =
        AggregatedSmudgingShare::from_persisted_bytes(noise_bytes, &params).expect("import");
    let sk = SecretKey::random(&params, &mut rng);
    let ciphertext = fresh_ciphertext(&params, &sk, &mut rng);
    let secret_key_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
    let key_aggregate = manager
        .aggregate_secret_key_shares(vec![SecretKeyShare::from_transport(
            secret_key_poly.as_ref().coefficients().to_owned(),
        )])
        .unwrap();
    manager
        .decryption_share(&ciphertext, &key_aggregate, restored)
        .expect("restored owner is usable");
}
