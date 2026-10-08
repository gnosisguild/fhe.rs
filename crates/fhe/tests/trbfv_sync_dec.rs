//! Public-API integration and compatibility coverage for synchronized decryption.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

#[path = "../examples/support/synchronized.rs"]
mod support;

use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey,
};
use fhe::trbfv::synchronized::{
    DecryptionShare, PartyPrfKeyTransport, PartyPrfKeys, SmudgingNoiseGenerator,
    SynchronizedDecryptionError, SynchronizedDecryptor,
};
use fhe::trbfv::{Lambda, ShareManager, SmudgingBoundCalculatorConfig, TRBFV};
use fhe::{Error, ThresholdError};
use fhe_math::rq::{Ntt, Poly, PowerBasis};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use ndarray::Array2;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

struct Fixture {
    params: Arc<BfvParameters>,
    rng: ChaCha8Rng,
    decryptor: SynchronizedDecryptor,
    sk: SecretKey,
    shares: Vec<Zeroizing<Poly<Ntt>>>,
    keys: Vec<PartyPrfKeys>,
    noise: SmudgingNoiseGenerator,
}

impl Fixture {
    fn new(n: usize) -> Self {
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(17)
            .set_moduli_sizes(&[50, 50, 50])
            .build_arc()
            .unwrap();
        Self::with_params(n, params)
    }

    fn with_params(n: usize, params: Arc<BfvParameters>) -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(276_280);
        let mut manager = ShareManager::new(n, (n - 1) / 2, params.clone()).unwrap();
        let decryptor = SynchronizedDecryptor::new(n, (n - 1) / 2, params.clone()).unwrap();
        let sk = SecretKey::random(&params, &mut rng);
        let shares = support::share_key(&mut manager, &sk, &mut rng).unwrap();
        let keys = support::simulated_committee_prf_keys(n, &mut rng).unwrap();
        let noise = SmudgingNoiseGenerator::new(
            SmudgingBoundCalculatorConfig::new(params.clone(), n, 2, Lambda::secure(40).unwrap())
                .unwrap(),
        )
        .unwrap();
        Self {
            params,
            rng,
            decryptor,
            sk,
            shares,
            keys,
            noise,
        }
    }

    fn encrypt(&mut self, value: u64) -> Ciphertext {
        let pk = PublicKey::new(&self.sk, &mut self.rng);
        let pt = Plaintext::try_encode(&[value], Encoding::poly(), &self.params).unwrap();
        pk.try_encrypt(&pt, &mut self.rng).unwrap()
    }

    fn partials(&mut self, ct: &Ciphertext, ids: &[usize]) -> Vec<DecryptionShare> {
        ids.iter()
            .map(|&id| {
                self.decryptor
                    .decryption_share(
                        ct,
                        &self.shares[id - 1],
                        id,
                        ids,
                        self.noise.generate(&mut self.rng).unwrap(),
                        &self.keys[id - 1],
                    )
                    .unwrap()
            })
            .collect()
    }
}

#[test]
fn existing_sharing_supports_both_decryption_protocols_and_repeated_ciphertexts() {
    let mut f = Fixture::new(5);
    let a = f.encrypt(3);
    let b = f.encrypt(7);
    let sum = &a + &b;
    let legacy = TRBFV::new(5, 2, f.params.clone()).unwrap();
    let ctx = f.params.context_at_level(0).unwrap().clone();
    for ids in [[1, 2, 3], [5, 2, 4], [3, 5, 1]] {
        for ct in [&a, &b, &sum] {
            let mut partials = f.partials(ct, &ids);
            partials.reverse();
            let found = f.decryptor.decrypt_from_shares(&partials, ct).unwrap();
            let expected = f.sk.try_decrypt(ct).unwrap();
            assert_eq!(found, expected);
            // The legacy API and signatures remain usable in the same build.
            // Zero shared noise isolates reconstruction parity; fresh nonzero
            // local smudging is used by the synchronized path above.
            let old = ids
                .iter()
                .map(|&id| {
                    legacy
                        .decryption_share(
                            Arc::new(ct.clone()),
                            (*f.shares[id - 1]).clone(),
                            Poly::<PowerBasis>::zero(&ctx),
                        )
                        .unwrap()
                })
                .collect();
            assert_eq!(
                legacy
                    .decrypt(old, ids.to_vec(), Arc::new(ct.clone()))
                    .unwrap(),
                expected
            );
        }
    }
}

#[test]
fn transport_canonicalizes_order_and_preserves_ciphertext_binding() {
    let mut f = Fixture::new(3);
    let ct = f.encrypt(5);
    let other = f.encrypt(6);
    let shares = f.partials(&ct, &[3, 1]);
    let restored: Vec<_> = shares
        .into_iter()
        .map(|share| {
            let (poly, id, mut ids) = share.into_parts();
            ids.reverse();
            DecryptionShare::from_parts(poly, id, ids, &ct).unwrap()
        })
        .collect();
    assert_eq!(
        f.decryptor.decrypt_from_shares(&restored, &ct).unwrap(),
        f.sk.try_decrypt(&ct).unwrap()
    );
    assert!(matches!(
        f.decryptor.decrypt_from_shares(&restored, &other),
        Err(Error::SynchronizedDecryption(
            SynchronizedDecryptionError::InconsistentDecryptionShares
        ))
    ));
    let ctx = f.params.context_at_level(0).unwrap();
    for (id, ids) in [
        (0, vec![1, 2]),
        (1, vec![0, 1]),
        (1, vec![1, 1]),
        (3, vec![1, 2]),
    ] {
        assert!(DecryptionShare::from_parts(Poly::<PowerBasis>::zero(ctx), id, ids, &ct).is_err());
    }
}

#[test]
fn rejects_mixed_sets_ciphertexts_and_duplicate_or_missing_shares() {
    let mut f = Fixture::new(3);
    let ct = f.encrypt(5);
    let other = f.encrypt(6);
    let shares = f.partials(&ct, &[1, 2]);
    let different_set = f.partials(&ct, &[1, 3]);
    let different_ct = f.partials(&other, &[1, 2]);
    for mixed in [
        vec![shares[0].clone(), different_set[1].clone()],
        vec![shares[0].clone(), different_ct[1].clone()],
    ] {
        assert!(matches!(
            f.decryptor.decrypt_from_shares(&mixed, &ct),
            Err(Error::SynchronizedDecryption(
                SynchronizedDecryptionError::InconsistentDecryptionShares
            ))
        ));
    }
    assert!(matches!(
        f.decryptor
            .decrypt_from_shares(&[shares[0].clone(), shares[0].clone()], &ct),
        Err(Error::Threshold(ThresholdError::DuplicatePartyId { .. }))
    ));
    assert!(f.decryptor.decrypt_from_shares(&shares[..1], &ct).is_err());
    assert!(
        f.decryptor
            .decrypt_from_shares(
                &[shares[0].clone(), shares[1].clone(), shares[1].clone()],
                &ct
            )
            .is_err()
    );
}

#[test]
fn partial_decryption_validates_ids_keys_and_noise_binding() {
    let mut f = Fixture::new(3);
    let ct = f.encrypt(5);
    for (id, ids) in [
        (0, vec![0, 2]),
        (4, vec![1, 4]),
        (1, vec![1, 1]),
        (1, vec![1]),
        (1, vec![1, 2, 3]),
        (1, vec![2, 3]),
    ] {
        assert!(
            f.decryptor
                .decryption_share(
                    &ct,
                    &f.shares[0],
                    id,
                    &ids,
                    f.noise.generate(&mut f.rng).unwrap(),
                    &f.keys[0]
                )
                .is_err()
        );
    }
    assert!(
        f.decryptor
            .decryption_share(
                &ct,
                &f.shares[0],
                1,
                &[1, 2],
                f.noise.generate(&mut f.rng).unwrap(),
                &f.keys[1]
            )
            .is_err()
    );
    let wrong_keys = support::simulated_committee_prf_keys(5, &mut f.rng).unwrap();
    assert!(
        f.decryptor
            .decryption_share(
                &ct,
                &f.shares[0],
                1,
                &[1, 2],
                f.noise.generate(&mut f.rng).unwrap(),
                &wrong_keys[0]
            )
            .is_err()
    );
    let different_params = BfvParametersBuilder::new()
        .set_degree(f.params.degree())
        .set_moduli(f.params.moduli())
        .set_plaintext_modulus(19)
        .build_arc()
        .unwrap();
    for (params, n) in [(f.params.clone(), 5), (different_params, 3)] {
        let generator = SmudgingNoiseGenerator::new(
            SmudgingBoundCalculatorConfig::new(params, n, 2, Lambda::secure(40).unwrap()).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            f.decryptor.decryption_share(
                &ct,
                &f.shares[0],
                1,
                &[1, 2],
                generator.generate(&mut f.rng).unwrap(),
                &f.keys[0]
            ),
            Err(Error::SynchronizedDecryption(
                SynchronizedDecryptionError::SmudgingConfigurationMismatch { .. }
            ))
        ));
    }
}

#[test]
fn prf_masks_cancel_and_transport_roundtrips_without_key_generation_api() {
    let mut f = Fixture::new(5);
    let ct = f.encrypt(3);
    let other = f.encrypt(3);
    let ids = [2, 4, 5];
    let mut sum = Poly::<PowerBasis>::zero(f.params.context_at_level(0).unwrap());
    for &id in &ids {
        let before = f.keys[id - 1].mask(&ids, &ct).unwrap();
        let transport = f.keys[id - 1].clone().into_transport();
        assert_eq!(transport.party_id(), id);
        assert_eq!(transport.committee_size(), 5);
        let restored = PartyPrfKeys::from_transport(
            PartyPrfKeyTransport::new(
                id,
                5,
                transport.keys_i_j().to_vec(),
                transport.keys_j_i().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(before, restored.mask(&[5, 2, 4], &ct).unwrap());
        assert_ne!(before, restored.mask(&ids, &other).unwrap());
        assert_ne!(before, restored.mask(&[2, 3, 4], &ct).unwrap());
        sum += &before;
    }
    assert!(sum.coefficients().iter().all(|&value| value == 0));
    for (id, n, left, right) in [
        (0, 3, 3, 3),
        (4, 3, 3, 3),
        (1, 0, 0, 0),
        (1, 3, 2, 3),
        (1, 3, 3, 2),
    ] {
        assert!(
            PartyPrfKeyTransport::new(id, n, vec![[0u8; 32]; left], vec![[0u8; 32]; right])
                .is_err()
        );
    }
    let mut transport = f.keys[0].clone().into_transport();
    transport.zeroize();
    assert!(PartyPrfKeys::from_transport(transport).is_err());
}

#[test]
fn rejects_main_raw_polynomials_with_invalid_shape_residues_or_context() {
    let mut f = Fixture::new(3);
    let ct = f.encrypt(3);
    let ctx = f.params.context_at_level(0).unwrap().clone();
    let malformed = [
        Array2::zeros((1, 16)),
        Array2::from_elem((3, 16), u64::MAX),
        Array2::zeros((16, 3)).reversed_axes(),
    ];
    for coefficients in malformed {
        let mut secret = Poly::<Ntt>::zero(&ctx);
        secret.set_coefficients(coefficients.clone());
        assert!(
            f.decryptor
                .decryption_share(
                    &ct,
                    &secret,
                    1,
                    &[1, 2],
                    f.noise.generate(&mut f.rng).unwrap(),
                    &f.keys[0]
                )
                .is_err()
        );
        let mut poly = Poly::<PowerBasis>::zero(&ctx);
        poly.set_coefficients(coefficients);
        let shares = [
            DecryptionShare::from_parts(poly, 1, vec![1, 2], &ct).unwrap(),
            DecryptionShare::from_parts(Poly::<PowerBasis>::zero(&ctx), 2, vec![1, 2], &ct)
                .unwrap(),
        ];
        assert!(f.decryptor.decrypt_from_shares(&shares, &ct).is_err());
    }
    let wrong_ctx = f.params.context_at_level(1).unwrap();
    assert!(
        f.decryptor
            .decryption_share(
                &ct,
                &Poly::<Ntt>::zero(wrong_ctx),
                1,
                &[1, 2],
                f.noise.generate(&mut f.rng).unwrap(),
                &f.keys[0]
            )
            .is_err()
    );
}

#[test]
fn rejects_nonzero_levels_and_unrelinearized_ciphertexts() {
    let mut f = Fixture::new(3);
    let ct = f.encrypt(3);
    let mut switched = ct.clone();
    switched.switch_down().unwrap();
    let product = &ct * &ct;
    for unsupported in [switched, product, Ciphertext::zero(&f.params)] {
        assert!(
            f.decryptor
                .decryption_share(
                    &unsupported,
                    &f.shares[0],
                    1,
                    &[1, 2],
                    f.noise.generate(&mut f.rng).unwrap(),
                    &f.keys[0]
                )
                .is_err()
        );
        assert!(f.decryptor.decrypt_from_shares(&[], &unsupported).is_err());
    }
}

#[test]
fn prf_matches_dev_sync_dec_8c58831_reference_vector() {
    // Generated by the public PartyPrfKeys::mask API on dev-sync-dec at
    // 8c5883108a07ff192fdfed2db91832c12e6e3c8d, with the same pinned e3-safe.
    // Fixed NTT coefficients avoid coupling the fixture to BFV encryption RNGs.
    let params = BfvParametersBuilder::new()
        .set_degree(8)
        .set_plaintext_modulus(17)
        .set_moduli(&[65537, 114689])
        .build_arc()
        .unwrap();
    let ctx = params.context_at_level(0).unwrap();
    let ciphertext = Ciphertext::new(
        (0..2)
            .map(|component| {
                let mut poly = Poly::<Ntt>::zero(ctx);
                poly.set_coefficients(Array2::from_shape_fn((2, 8), |(row, column)| {
                    (component * 100 + row * 10 + column + 1) as u64
                }));
                poly
            })
            .collect(),
        &params,
    )
    .unwrap();
    let expected = [
        [
            63870, 34179, 31264, 58370, 50890, 21505, 60512, 54161, 51388, 80303, 40742, 101483,
            65676, 77778, 32952, 57840,
        ],
        [
            1667, 31358, 34273, 7167, 14647, 44032, 5025, 11376, 63301, 34386, 73947, 13206, 49013,
            36911, 81737, 56849,
        ],
    ];
    for (party_id, expected) in [1, 3].into_iter().zip(expected) {
        let keys = PartyPrfKeys::from_transport(
            PartyPrfKeyTransport::new(
                party_id,
                3,
                (1..=3).map(|j| [(party_id * 10 + j) as u8; 32]).collect(),
                (1..=3).map(|j| [(j * 10 + party_id) as u8; 32]).collect(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            keys.mask(&[3, 1], &ciphertext)
                .unwrap()
                .coefficients()
                .as_slice()
                .unwrap(),
            &expected
        );
    }
}

#[test]
fn reconstruction_lifts_through_the_plaintext_context_when_q0_is_small() {
    for t in [769, 4099] {
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(t)
            .set_moduli(&[1153, 12289])
            .build_arc()
            .unwrap();
        let decryptor = SynchronizedDecryptor::new(3, 1, params.clone()).unwrap();
        let ctx = params.context_at_level(0).unwrap();
        let values = vec![t - 1; params.degree()];
        let pt = Plaintext::try_encode(&values, Encoding::poly(), &params).unwrap();
        let zero_key = SecretKey::new(vec![0; params.degree()], &params);
        let ct = zero_key
            .try_encrypt(&pt, &mut ChaCha8Rng::seed_from_u64(t))
            .unwrap();
        let shares: Vec<_> = [1, 2]
            .into_iter()
            .map(|id| {
                DecryptionShare::from_parts(Poly::<PowerBasis>::zero(ctx), id, vec![1, 2], &ct)
                    .unwrap()
            })
            .collect();
        let found = decryptor.decrypt_from_shares(&shares, &ct).unwrap();
        assert_eq!(
            Vec::<u64>::try_decode(&found, Encoding::poly()).unwrap(),
            values
        );
    }
}

#[test]
fn validates_configuration_and_rejects_unsupported_plaintext_width_early() {
    let f = Fixture::new(3);
    for (n, threshold) in [(0, 0), (2, 0), (3, 0), (5, 1), (5, 3)] {
        assert!(SynchronizedDecryptor::new(n, threshold, f.params.clone()).is_err());
    }
    let params = BfvParametersBuilder::new()
        .set_degree(16)
        .set_plaintext_modulus_biguint((num_bigint::BigUint::from(1u32) << 80usize) + 7u32)
        .set_moduli_sizes(&[50, 50, 50])
        .build_arc()
        .unwrap();
    assert!(matches!(
        SynchronizedDecryptor::new(3, 1, params.clone()),
        Err(Error::ParametersError(_))
    ));
    let config =
        SmudgingBoundCalculatorConfig::new(params, 3, 1, Lambda::secure(40).unwrap()).unwrap();
    assert!(matches!(
        SmudgingNoiseGenerator::new(config),
        Err(Error::ParametersError(_))
    ));
}

#[test]
fn repeated_partial_decryptions_use_fresh_noise_and_clear_variable_time_flags() {
    let mut f = Fixture::new(3);
    let ct = f.encrypt(5);
    let variable_time = fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
    for share in &mut f.shares {
        // Exercise callers supplying a main-API polynomial with public-data metadata.
        share.allow_variable_time_computations(variable_time);
    }
    let first = f.partials(&ct, &[1, 3]);
    let second = f.partials(&ct, &[1, 3]);
    assert_eq!(
        f.decryptor.decrypt_from_shares(&first, &ct).unwrap(),
        f.decryptor.decrypt_from_shares(&second, &ct).unwrap()
    );
    for (a, b) in first.into_iter().zip(second) {
        let (a, _, _) = a.into_parts();
        let (b, _, _) = b.into_parts();
        assert!(!a.allows_variable_time_computations());
        assert!(!b.allows_variable_time_computations());
        assert_ne!(a.coefficients(), b.coefficients());
    }
}

#[cfg(not(debug_assertions))]
#[test]
fn larger_parameters_decrypt_with_fresh_local_noise() {
    let params = BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus(65537)
        .set_moduli_sizes(&[50, 50, 50])
        .build_arc()
        .unwrap();
    let mut f = Fixture::with_params(3, params);
    let ct = f.encrypt(4242);
    let shares = f.partials(&ct, &[3, 1]);
    assert_eq!(
        f.decryptor.decrypt_from_shares(&shares, &ct).unwrap(),
        f.sk.try_decrypt(&ct).unwrap()
    );
}
