//! Synchronized decryption: insecure mechanics and degree-8192 preset coverage.
//!
//! The `secure` section requires `experimental-mbfv` for collective-key transport.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

#[path = "../examples/support/simulated_key_setup.rs"]
mod simulated_key_setup;

#[cfg(feature = "experimental-mbfv")]
#[path = "support/trbfv_parameters.rs"]
mod parameters;

/// Small rings are computationally insecure, even with a validated noise lambda.
mod insecure {
    use super::simulated_key_setup;

    use fhe::bfv::{
        BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey,
    };
    use fhe::trbfv::{
        DecryptionShare, Lambda, PartyPrfKeyTransport, PartyPrfKeys, ShareManager,
        SmudgingBoundCalculatorConfig, SmudgingNoiseGenerator, SynchronizedDecryptionError,
        SynchronizedDecryptor,
    };
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
            let shares = simulated_key_setup::share_key(&mut manager, &sk, &mut rng).unwrap();
            let keys = simulated_key_setup::simulated_committee_prf_keys(n, &mut rng).unwrap();
            let noise = SmudgingNoiseGenerator::new(
                SmudgingBoundCalculatorConfig::new(
                    params.clone(),
                    n,
                    2,
                    Lambda::secure(40).unwrap(),
                )
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
    fn existing_sharing_supports_synchronized_repeated_decryptions() {
        let mut f = Fixture::new(5);
        let a = f.encrypt(3);
        let b = f.encrypt(7);
        let sum = &a + &b;
        for ids in [[1, 2, 3], [5, 2, 4], [3, 5, 1]] {
            for ct in [&a, &b, &sum] {
                let mut partials = f.partials(ct, &ids);
                partials.reverse();
                let found = f.decryptor.decrypt_from_shares(&partials, ct).unwrap();
                let expected = f.sk.try_decrypt(ct).unwrap();
                assert_eq!(found, expected);
                // Repeat even the same ciphertext with newly sampled local noise.
                let again = f.partials(ct, &ids);
                assert_eq!(
                    f.decryptor.decrypt_from_shares(&again, ct).unwrap(),
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
            assert!(
                DecryptionShare::from_parts(Poly::<PowerBasis>::zero(ctx), id, ids, &ct).is_err()
            );
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
        let wrong_keys = simulated_key_setup::simulated_committee_prf_keys(5, &mut f.rng).unwrap();
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
                SmudgingBoundCalculatorConfig::new(params, n, 2, Lambda::secure(40).unwrap())
                    .unwrap(),
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
    fn prf_power_basis_reference_vector() {
        // Fixed NTT storage avoids coupling the fixture to BFV encryption RNGs.
        // The reference vector pins the power-basis image of those residues.
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
                52534, 10163, 28151, 52807, 5238, 63673, 55848, 33749, 96294, 70599, 3822, 71735,
                29132, 20165, 76778, 9623,
            ],
            [
                13003, 55374, 37386, 12730, 60299, 1864, 9689, 31788, 18395, 44090, 110867, 42954,
                85557, 94524, 37911, 105066,
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
    fn decryption_share_accepts_generator_wrapped_signed_coefficients() {
        let mut f = Fixture::new(3);
        let ct = f.encrypt(9);
        let ids = [1usize, 2];
        let coeffs = vec![num_bigint::BigInt::from(0); f.params.degree()];
        let shares: Vec<_> = ids
            .iter()
            .map(|&id| {
                let noise = f.noise.wrap_signed_coefficients(&coeffs).unwrap();
                f.decryptor
                    .decryption_share(&ct, &f.shares[id - 1], id, &ids, noise, &f.keys[id - 1])
                    .unwrap()
            })
            .collect();
        assert_eq!(
            f.decryptor.decrypt_from_shares(&shares, &ct).unwrap(),
            f.sk.try_decrypt(&ct).unwrap()
        );
    }

    #[test]
    fn explicitly_insecure_lambda_decrypts_for_testing_only() {
        let mut f = Fixture::new(3);
        let lambda = Lambda::insecure(2);
        assert!(!lambda.is_secure());
        assert!(Lambda::secure(lambda.value()).is_err());
        f.noise = SmudgingNoiseGenerator::new(
            SmudgingBoundCalculatorConfig::new(f.params.clone(), 3, 2, lambda).unwrap(),
        )
        .unwrap();
        let ct = f.encrypt(9);
        let shares = f.partials(&ct, &[3, 1]);
        assert_eq!(
            f.decryptor.decrypt_from_shares(&shares, &ct).unwrap(),
            f.sk.try_decrypt(&ct).unwrap()
        );
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
}

/// Degree-8192 regression preset, not an independent security certification.
#[cfg(feature = "experimental-mbfv")]
mod secure {
    use super::parameters::{
        self, DEGREE, NUM_PARTIES, NUM_SUMMED, THRESHOLD, bound_config, transport_params,
        trbfv_params,
    };
    use super::simulated_key_setup;
    use fhe::bfv::{Ciphertext, CommonRandomPoly, Encoding, Plaintext, PublicKey, SecretKey};
    use fhe::mbfv::{AggregateIter, PublicKeyShare};
    use fhe::trbfv::{
        DecryptionShare, ShareManager, SmudgingBoundCalculator, SmudgingNoiseGenerator,
        SynchronizedDecryptor,
    };
    use fhe_math::rq::{Poly, PowerBasis};
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use ndarray::{Array, Array2, ArrayView};
    use num_bigint::{BigInt, BigUint};
    use rayon::prelude::*;
    use std::sync::Arc;

    enum NoiseMode {
        /// Each party samples uniformly in [-B_sm, B_sm].
        Random,
        /// Each designated party adds +/-B_sm on every coefficient.
        WorstCase,
    }

    fn run_threshold_sum_e2e(noise_mode: NoiseMode) {
        let params_trbfv = trbfv_params();
        let params_transport = transport_params();
        let manager = ShareManager::new(NUM_PARTIES, THRESHOLD, params_trbfv.clone()).unwrap();
        let decryptor =
            SynchronizedDecryptor::new(NUM_PARTIES, THRESHOLD, params_trbfv.clone()).unwrap();
        let noise = SmudgingNoiseGenerator::new(bound_config(params_trbfv.clone())).unwrap();

        struct Party {
            pk_share: PublicKeyShare,
            sk_sss: Vec<Array2<u64>>,
            sk_sss_collected: Vec<Array2<u64>>,
            sk_poly_sum: Poly<PowerBasis>,
            transport_sk: SecretKey,
            transport_pk: PublicKey,
        }

        let mut rng = rand::rng();
        let crp = CommonRandomPoly::new(&params_trbfv, &mut rng).unwrap();
        let mut parties: Vec<Party> = (0..NUM_PARTIES)
            .into_par_iter()
            .map(|_| {
                let mut rng = rand::rng();
                let sk_share = SecretKey::random(&params_trbfv, &mut rng);
                let pk_share = PublicKeyShare::new(&sk_share, crp.clone(), &mut rng).unwrap();
                let mut share_manager =
                    ShareManager::new(NUM_PARTIES, THRESHOLD, params_trbfv.clone()).unwrap();
                let sk_poly = share_manager
                    .coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())
                    .unwrap();
                let sk_sss = share_manager
                    .generate_secret_shares_from_poly(sk_poly, &mut rng)
                    .unwrap();
                let transport_sk = SecretKey::random(&params_transport, &mut rng);
                let transport_pk = PublicKey::new(&transport_sk, &mut rng);
                let ctx = params_trbfv.context_at_level(0).unwrap();
                Party {
                    pk_share,
                    sk_sss,
                    sk_sss_collected: Vec::with_capacity(NUM_PARTIES),
                    sk_poly_sum: Poly::<PowerBasis>::zero(ctx),
                    transport_sk,
                    transport_pk,
                }
            })
            .collect();

        // Protect key shares in transit; this is a local simulation, not a DKG.
        let transport_pks: Vec<PublicKey> = parties
            .iter()
            .map(|party| party.transport_pk.clone())
            .collect();
        // encrypted_shares[sender][receiver]: one key-share ciphertext per modulus.
        let encrypted_shares: Vec<Vec<Vec<Ciphertext>>> = parties
            .par_iter()
            .map(|party| {
                transport_pks
                    .iter()
                    .enumerate()
                    .map(|(receiver_idx, receiver_pk)| {
                        let mut rng = rand::rng();
                        party
                            .sk_sss
                            .iter()
                            .map(|share_matrix| {
                                let share_vec: Vec<u64> = share_matrix.row(receiver_idx).to_vec();
                                let pt = Plaintext::try_encode(
                                    &share_vec,
                                    Encoding::poly(),
                                    &params_transport,
                                )
                                .unwrap();
                                receiver_pk.try_encrypt(&pt, &mut rng).unwrap()
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let dealt: Vec<_> = parties
            .iter_mut()
            .map(|party| std::mem::take(&mut party.sk_sss))
            .collect();
        parties
            .par_iter_mut()
            .enumerate()
            .for_each(|(receiver_idx, party)| {
                for sender_encrypted in &encrypted_shares {
                    let encrypted_sk_shares = &sender_encrypted[receiver_idx];
                    let mut sk_rows = Array::zeros((0, DEGREE));
                    for ct in encrypted_sk_shares {
                        let pt = party.transport_sk.try_decrypt(ct).unwrap();
                        let decrypted: Vec<u64> =
                            Vec::<u64>::try_decode(&pt, Encoding::poly()).unwrap();
                        sk_rows.push_row(ArrayView::from(&decrypted)).unwrap();
                    }
                    // Verify each transport row, not just the final tally.
                    let sender_idx = party.sk_sss_collected.len();
                    for (row, expected) in dealt[sender_idx].iter().enumerate() {
                        assert_eq!(sk_rows.row(row), expected.row(receiver_idx));
                    }
                    party.sk_sss_collected.push(sk_rows);
                }
            });
        parties.par_iter_mut().for_each(|party| {
            party.sk_poly_sum = manager
                .aggregate_collected_shares(&party.sk_sss_collected)
                .unwrap();
        });
        let pk: PublicKey = parties
            .iter()
            .map(|party| party.pk_share.clone())
            .aggregate()
            .unwrap();

        let numbers: Vec<u64> = vec![1; NUM_SUMMED];
        let encrypted: Vec<Ciphertext> = numbers
            .par_iter()
            .map(|&number| {
                let mut rng = rand::rng();
                let pt = Plaintext::try_encode(&[number], Encoding::poly(), &params_trbfv).unwrap();
                pk.try_encrypt(&pt, &mut rng).unwrap()
            })
            .collect();
        let mut sum = Ciphertext::zero(&params_trbfv);
        for ct in &encrypted {
            sum += ct;
        }
        let tally = Arc::new(sum);
        let reconstructing: Vec<usize> = (2..=NUM_PARTIES).step_by(2).collect();
        assert_eq!(reconstructing.len(), THRESHOLD + 1);

        let keys =
            simulated_key_setup::simulated_committee_prf_keys(NUM_PARTIES, &mut rng).unwrap();
        let key_shares: Vec<_> = parties
            .iter()
            .map(|party| zeroize::Zeroizing::new(party.sk_poly_sum.clone().into_ntt()))
            .collect();
        // Reuse key shares, never noise. Exercise both signed worst-case endpoints.
        for sign in [-1, 1] {
            let partials: Vec<DecryptionShare> = reconstructing
                .iter()
                .map(|&party_id| {
                    let local_noise = match noise_mode {
                        NoiseMode::Random => noise.generate(&mut rng).unwrap(),
                        NoiseMode::WorstCase => noise
                            .wrap_signed_coefficients(&vec![
                                BigInt::from(sign)
                                    * BigInt::from(
                                        noise.smudging_bound().clone()
                                    );
                                DEGREE
                            ])
                            .unwrap(),
                    };
                    decryptor
                        .decryption_share(
                            &tally,
                            &key_shares[party_id - 1],
                            party_id,
                            &reconstructing,
                            local_noise,
                            &keys[party_id - 1],
                        )
                        .unwrap()
                })
                .collect();
            let decrypted = decryptor.decrypt_from_shares(&partials, &tally).unwrap();
            let result = Vec::<u64>::try_decode(&decrypted, Encoding::poly()).unwrap();
            assert_eq!(result[0], numbers.iter().sum::<u64>());
        }
    }

    #[test]
    fn random_smudging_noise_and_encrypted_key_transport() {
        run_threshold_sum_e2e(NoiseMode::Random);
    }

    #[test]
    fn worst_case_signed_smudging_noise() {
        run_threshold_sum_e2e(NoiseMode::WorstCase);
    }

    #[test]
    fn transport_plaintext_covers_every_share_residue() {
        parameters::assert_transport_range();
    }

    #[test]
    fn smudging_bound_is_feasible_for_the_preset() {
        let config = bound_config(trbfv_params());
        let bound = SmudgingBoundCalculator::new(config.clone())
            .calculate_sm_bound()
            .unwrap();
        assert!(bound > BigUint::from(0u32));
        let generator = SmudgingNoiseGenerator::new(config).unwrap();
        assert_eq!(generator.smudging_bound(), &bound);
    }

    #[test]
    fn smudging_bound_matches_the_preset_and_strict_correctness_budget() {
        let bound = SmudgingBoundCalculator::new(bound_config(trbfv_params()))
            .calculate_sm_bound()
            .unwrap();
        parameters::assert_correctness_budget(&bound);
    }

    #[test]
    fn default_accepted_count_matches_explicit_n() {
        let config = bound_config(trbfv_params());
        let default = SmudgingBoundCalculator::new(config.clone())
            .calculate_sm_bound()
            .unwrap();
        let explicit = SmudgingBoundCalculator::new(config)
            .with_accepted_participant_count(NUM_PARTIES)
            .calculate_sm_bound()
            .unwrap();
        assert_eq!(default, explicit);
    }
}
