//! Regression coverage for library-only findings from the September 2026 review.

#[path = "../support/mod.rs"]
mod support;

use std::sync::Arc;

use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, CommonRandomPolyVec, Encoding, Plaintext,
    PublicKey, RGSWCiphertext, RelinearizationKey, SecretKey,
};
use fhe::lbfv::LBFVPublicKey;
use fhe::trlbfv::{RelinKeyShare, aggregate_relinearization_key};
use fhe::{
    CiphertextError, CiphertextOperation, Error, MultipartyError, ReferenceStringRole,
    SecretKeyError, SerializationError, SerializedPolynomialComponent,
};
use fhe_traits::{DeserializeParametrized, FheDecrypter, FheEncoder, FheEncrypter, Serialize};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

fn parameters() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(16)
        .set_plaintext_modulus(1153)
        .set_moduli_sizes(&[62; 3])
        .build_arc()
        .unwrap()
}

fn invalid_secret_key_count(actual: usize, expected: usize) -> Error {
    SecretKeyError::InvalidCoefficientCount { actual, expected }.into()
}

#[test]
fn public_key_deserialization_rejects_extra_polynomials() -> fhe::Result<()> {
    let params = parameters();
    let mut rng = ChaCha8Rng::from_seed([1; 32]);
    let sk = SecretKey::random(&params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng)?;
    assert_eq!(PublicKey::from_bytes(&pk.to_bytes(), &params)?, pk);

    for count in [3, 4, 6] {
        let malformed = PublicKey {
            params: params.clone(),
            c: Ciphertext::new(vec![pk.c.first().unwrap().clone(); count], &params)?,
        };
        assert_eq!(
            PublicKey::from_bytes(&malformed.to_bytes(), &params).unwrap_err(),
            SerializationError::WrongPolynomialCount {
                component: SerializedPolynomialComponent::PublicKeyCiphertext,
                actual: count,
                expected: 2,
            }
            .into()
        );
    }
    Ok(())
}

#[test]
fn public_key_encryption_rejects_extra_polynomials_before_rng() -> fhe::Result<()> {
    let params = parameters();
    let mut rng = ChaCha8Rng::from_seed([2; 32]);
    let sk = SecretKey::random(&params, &mut rng);
    let mut pk = PublicKey::new(&sk, &mut rng)?;
    pk.c = Ciphertext::new(vec![pk.c.first().unwrap().clone(); 3], &params)?;
    for level in [0, 1] {
        let pt = Plaintext::zero(Encoding::poly_at_level(level), &params)?;
        for error in [
            pk.try_encrypt(&pt, &mut support::PanicOnUseRng).err(),
            pk.try_encrypt_with_intermediates(&pt, &mut support::PanicOnUseRng)
                .err(),
        ] {
            assert_eq!(
                error,
                Some(
                    CiphertextError::InvalidPolynomialCount {
                        operation: CiphertextOperation::PublicKeyEncryption,
                        actual: 3,
                        expected: 2,
                    }
                    .into()
                )
            );
        }
    }
    Ok(())
}

#[test]
fn plaintext_debug_redacts_messages_for_every_encoding_and_level() -> fhe::Result<()> {
    let params = parameters();
    for encoding in [
        Encoding::poly(),
        Encoding::simd(),
        Encoding::poly_at_level(1),
        Encoding::simd_at_level(1),
    ] {
        let first = Plaintext::try_encode(&[7u64, 19], encoding.clone(), &params)?;
        let second = Plaintext::try_encode(&[23u64, 31], encoding, &params)?;
        assert_ne!(first, second);
        let debug = format!("{first:?}");
        assert_eq!(debug, format!("{second:?}"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("coefficients"));
    }
    Ok(())
}

#[test]
fn secret_key_constructor_checks_exact_degree() {
    let params = parameters();
    for count in [
        0,
        params.degree() - 1,
        params.degree() + 1,
        2 * params.degree(),
    ] {
        assert_eq!(
            SecretKey::new(vec![1; count], &params).unwrap_err(),
            invalid_secret_key_count(count, params.degree())
        );
    }
}

#[test]
fn aggregated_secret_keys_still_encrypt_and_round_trip() -> fhe::Result<()> {
    let params = parameters();
    let mut rng = ChaCha8Rng::from_seed([3; 32]);
    let sk = SecretKey::new(vec![3; params.degree()], &params)?;
    let restored = SecretKey::from_bytes(&sk.to_bytes(), &params)?;
    assert_eq!(restored, sk);
    let pk = PublicKey::new(&restored, &mut rng)?;
    let pt = Plaintext::try_encode(&[7u64], Encoding::poly(), &params)?;
    assert_eq!(sk.try_decrypt(&pk.try_encrypt(&pt, &mut rng)?)?, pt);
    Ok(())
}

#[test]
fn overallocated_secret_key_coefficients_preserve_the_key() -> fhe::Result<()> {
    let params = parameters();
    let mut coefficients = Vec::with_capacity(2 * params.degree());
    coefficients.extend(std::iter::repeat_n(3, params.degree()));
    let sk = SecretKey::new(coefficients, &params)?;
    assert_eq!(sk, SecretKey::new(vec![3; params.degree()], &params)?);
    Ok(())
}

#[test]
fn mutated_secret_keys_are_rejected_before_crypto_or_rng() -> fhe::Result<()> {
    let params = parameters();
    let mut rng = ChaCha8Rng::from_seed([4; 32]);
    let mut sk = SecretKey::random(&params, &mut rng);
    let pt = Plaintext::zero(Encoding::poly(), &params)?;
    let ct: Ciphertext = sk.try_encrypt(&pt, &mut rng)?;
    let d1 = CommonRandomPolyVec::from_seed(&params, [5; 32])?;
    let a = CommonRandomPolyVec::from_seed(&params, [6; 32])?;

    for count in [
        params.degree() - 1,
        params.degree() + 1,
        2 * params.degree(),
    ] {
        sk.coeffs = vec![1; count].into_boxed_slice();
        let errors = [
            PublicKey::new(&sk, &mut support::PanicOnUseRng).err(),
            PublicKey::new_with_intermediates(&sk, &mut support::PanicOnUseRng).err(),
            <SecretKey as FheEncrypter<Plaintext, Ciphertext>>::try_encrypt(
                &sk,
                &pt,
                &mut support::PanicOnUseRng,
            )
            .err(),
            sk.try_encrypt_with_seed(&pt, [7; 32], &mut support::PanicOnUseRng)
                .err(),
            <SecretKey as FheEncrypter<Plaintext, RGSWCiphertext>>::try_encrypt(
                &sk,
                &pt,
                &mut support::PanicOnUseRng,
            )
            .err(),
            sk.try_decrypt(&ct).err(),
            unsafe { sk.measure_noise(&ct) }.err(),
            RelinearizationKey::new(&sk, &mut support::PanicOnUseRng).err(),
            LBFVPublicKey::new(&sk, &mut support::PanicOnUseRng).err(),
            RelinKeyShare::contribute_with_seed(
                &sk,
                [5; 32],
                [6; 32],
                0,
                0,
                &mut support::PanicOnUseRng,
            )
            .err(),
            RelinKeyShare::contribute_with_crp_and_witness(
                &sk,
                &d1,
                &a,
                0,
                0,
                &mut support::PanicOnUseRng,
            )
            .err(),
        ];
        for error in errors {
            assert_eq!(
                error,
                Some(invalid_secret_key_count(count, params.degree()))
            );
        }
    }
    Ok(())
}

#[cfg(feature = "experimental-mbfv")]
#[test]
fn multiparty_operations_reject_mutated_secret_keys_before_rng() -> fhe::Result<()> {
    use fhe::mbfv::{
        DecryptionShare, PublicKeyShare, PublicKeySwitchShare, RelinKeyGenerator,
        SecretKeySwitchShare,
    };
    let params = parameters();
    let mut rng = ChaCha8Rng::from_seed([8; 32]);
    let valid = SecretKey::random(&params, &mut rng);
    let pk = PublicKey::new(&valid, &mut rng)?;
    let ct = Arc::new(pk.c.clone());
    let crp = fhe::bfv::CommonRandomPoly::new(&params, &mut rng)?;
    let crps = CommonRandomPolyVec::from_seed(&params, [9; 32])?;
    let mut invalid = valid.clone();
    invalid.coeffs = vec![1; params.degree() - 1].into_boxed_slice();
    let errors = [
        PublicKeyShare::new(&invalid, crp, &mut support::PanicOnUseRng).err(),
        PublicKeySwitchShare::new(&invalid, &pk, &ct, &mut support::PanicOnUseRng).err(),
        SecretKeySwitchShare::new(&invalid, &valid, ct.clone(), &mut support::PanicOnUseRng).err(),
        SecretKeySwitchShare::new(&valid, &invalid, ct.clone(), &mut support::PanicOnUseRng).err(),
        DecryptionShare::new(&invalid, &ct, &mut support::PanicOnUseRng).err(),
        RelinKeyGenerator::new(&invalid, &crps, &mut support::PanicOnUseRng).err(),
    ];
    for error in errors {
        assert_eq!(
            error,
            Some(invalid_secret_key_count(
                params.degree() - 1,
                params.degree()
            ))
        );
    }
    Ok(())
}

#[test]
fn share_reference_string_getters_match_seeded_and_explicit_rows() -> fhe::Result<()> {
    let params = parameters();
    let mut rng = ChaCha8Rng::from_seed([10; 32]);
    let sk = SecretKey::random(&params, &mut rng);
    let d1 = CommonRandomPolyVec::from_seed(&params, [11; 32])?;
    let a = CommonRandomPolyVec::from_seed(&params, [12; 32])?;
    let explicit_d1 = CommonRandomPolyVec::from_polys(&params, d1.to_polys(), None)?;
    let explicit_a = CommonRandomPolyVec::from_polys(&params, a.to_polys(), None)?;
    let pk = LBFVPublicKey::new_with_seed(&sk, [12; 32], &mut rng)?;

    for level in [0, 1] {
        let rows = params.moduli().len() - level;
        let expected_d1: Vec<_> = d1
            .to_polys()
            .into_iter()
            .take(rows)
            .map(|p| p.into_ntt_shoup())
            .collect();
        let expected_a: Vec<_> = a
            .to_polys()
            .into_iter()
            .take(rows)
            .map(|p| p.into_ntt_shoup())
            .collect();
        for (d1_input, a_input) in [(&d1, &a), (&explicit_d1, &explicit_a)] {
            let share =
                RelinKeyShare::contribute_with_crp(&sk, d1_input, a_input, level, 0, &mut rng)?;
            assert_eq!(share.d1_components(), expected_d1);
            assert_eq!(share.a_components(), expected_a);
            let restored = RelinKeyShare::from_bytes(&share.to_bytes(), &params)?;
            assert_eq!(restored.d1_components(), share.d1_components());
            assert_eq!(restored.a_components(), share.a_components());
            let key = aggregate_relinearization_key(std::slice::from_ref(&share), &pk)?;
            assert_eq!(key.d1_components(), share.d1_components());
            assert_eq!(key.a_components(), share.a_components());
        }
    }
    Ok(())
}

#[test]
fn aggregation_reference_string_errors_name_input_indices() -> fhe::Result<()> {
    let params = parameters();
    let mut rng = ChaCha8Rng::from_seed([13; 32]);
    let sk = SecretKey::random(&params, &mut rng);
    let pk = LBFVPublicKey::new_with_seed(&sk, [14; 32], &mut rng)?;
    let honest = RelinKeyShare::contribute_with_seed(&sk, [15; 32], [14; 32], 0, 0, &mut rng)?;
    for (urs_seed, crs_seed, role) in [
        ([16; 32], [14; 32], ReferenceStringRole::Urs),
        ([15; 32], [17; 32], ReferenceStringRole::Crs),
    ] {
        let different =
            RelinKeyShare::contribute_with_seed(&sk, urs_seed, crs_seed, 0, 0, &mut rng)?;
        assert_eq!(
            aggregate_relinearization_key(
                &[honest.clone(), honest.clone(), different.clone()],
                &pk
            )
            .unwrap_err(),
            MultipartyError::ReferenceStringMismatch {
                role,
                share_index: 2,
                reference_share_index: 0
            }
            .into()
        );
        assert_eq!(
            aggregate_relinearization_key(&[different, honest.clone()], &pk).unwrap_err(),
            MultipartyError::ReferenceStringMismatch {
                role,
                share_index: 1,
                reference_share_index: 0
            }
            .into()
        );
    }
    let wrong_crs = RelinKeyShare::contribute_with_seed(&sk, [15; 32], [18; 32], 0, 0, &mut rng)?;
    assert_eq!(
        aggregate_relinearization_key(&[wrong_crs], &pk).unwrap_err(),
        MultipartyError::PublicKeyCrsMismatch {
            share_index: 0,
            row_index: 0
        }
        .into()
    );
    Ok(())
}
