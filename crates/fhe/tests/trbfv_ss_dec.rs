//! SS decryption: insecure mechanics and degree-8192 preset coverage.
//!
//! The `secure` section requires `experimental-mbfv` for collective-key transport.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

#[cfg(feature = "experimental-mbfv")]
#[path = "support/trbfv_parameters.rs"]
mod parameters;
#[cfg(feature = "synchronized-decryption")]
#[path = "../examples/support/simulated_key_setup.rs"]
mod simulated_key_setup;
#[cfg(feature = "experimental-mbfv")]
#[path = "../examples/support/ss_smudging.rs"]
mod ss_smudging;

/// Small rings are computationally insecure, even with a validated noise lambda.
mod insecure {
    #[cfg(feature = "synchronized-decryption")]
    use super::simulated_key_setup;

    use fhe::bfv::{
        BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey,
    };
    use fhe::trbfv::{
        AggregatedSmudgingShare, DealerSmudgingNoise, Lambda, RecipientSmudgingShare,
        ShamirSecretSharing, ShareManager, SmudgingBoundCalculator, SmudgingBoundCalculatorConfig,
        SsSmudgingDecryptionConfig, SsSmudgingDecryptionShare, SsSmudgingDecryptor,
        SsSmudgingNoiseGenerator,
    };
    use fhe::{Error, ThresholdError};
    use fhe_math::rq::{Ntt, Poly, PowerBasis};
    use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
    use ndarray::Array2;
    use num_bigint::{BigInt, BigUint};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use std::sync::Arc;
    use zeroize::{Zeroize, Zeroizing};

    fn params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(17)
            .set_moduli_sizes(&[50, 50, 50])
            .build_arc()
            .unwrap()
    }

    fn recipient(dealt: &[Array2<u64>], party: usize) -> Array2<u64> {
        Array2::from_shape_fn((dealt.len(), dealt[0].ncols()), |(row, column)| {
            dealt[row][[party, column]]
        })
    }

    fn malformed_matrices() -> Vec<Array2<u64>> {
        vec![
            Array2::zeros((1, 8)),
            Array2::from_elem((3, 8), u64::MAX),
            Array2::zeros((8, 3)).reversed_axes(),
        ]
    }

    struct Fixture {
        params: Arc<BfvParameters>,
        manager: ShareManager,
        decryptor: SsSmudgingDecryptor,
        sk: SecretKey,
        keys: Vec<Zeroizing<Poly<Ntt>>>,
        noise: SsSmudgingNoiseGenerator,
        rng: ChaCha8Rng,
    }

    impl Fixture {
        fn new(n: usize) -> Self {
            let params = params();
            let mut manager = ShareManager::new(n, (n - 1) / 2, params.clone()).unwrap();
            let decryptor = SsSmudgingDecryptor::new(
                SsSmudgingDecryptionConfig::new(n, (n - 1) / 2, params.clone()).unwrap(),
            );
            let mut rng = ChaCha8Rng::seed_from_u64(410 + n as u64);
            let sk = SecretKey::random(&params, &mut rng);
            let poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref()).unwrap();
            let mut dealt = manager
                .generate_secret_shares_from_poly(poly, &mut rng)
                .unwrap();
            let keys = (0..n)
                .map(|party| {
                    Zeroizing::new(
                        manager
                            .aggregate_collected_shares(&[recipient(&dealt, party)])
                            .unwrap()
                            .into_ntt(),
                    )
                })
                .collect();
            for matrix in &mut dealt {
                matrix.iter_mut().for_each(Zeroize::zeroize);
            }
            let noise = SsSmudgingNoiseGenerator::new(
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
                manager,
                decryptor,
                sk,
                keys,
                noise,
                rng,
            }
        }

        fn preprocess(&mut self, dealers: usize) -> Vec<Option<AggregatedSmudgingShare>> {
            let mut dealt: Vec<_> = (0..dealers)
                .map(|_| {
                    self.manager
                        .generate_smudging_shares(
                            self.noise.generate(&mut self.rng).unwrap(),
                            &mut self.rng,
                        )
                        .unwrap()
                        .into_transport()
                })
                .collect();
            let shares = (0..self.manager.n)
                .map(|party| {
                    Some(
                        self.manager
                            .aggregate_smudging_shares(
                                dealt
                                    .iter()
                                    .map(|dealer| {
                                        RecipientSmudgingShare::from_transport(recipient(
                                            dealer, party,
                                        ))
                                    })
                                    .collect(),
                            )
                            .unwrap(),
                    )
                })
                .collect();
            for dealer in &mut dealt {
                for matrix in dealer {
                    matrix.iter_mut().for_each(Zeroize::zeroize);
                }
            }
            shares
        }

        fn encrypt(&mut self, value: u64) -> Ciphertext {
            let pk = PublicKey::new(&self.sk, &mut self.rng);
            let pt = Plaintext::try_encode(&[value], Encoding::poly(), &self.params).unwrap();
            pk.try_encrypt(&pt, &mut self.rng).unwrap()
        }

        fn partials(
            &self,
            ct: &Ciphertext,
            ids: &[usize],
            mut noise: Vec<Option<AggregatedSmudgingShare>>,
        ) -> Vec<SsSmudgingDecryptionShare> {
            ids.iter()
                .map(|&id| {
                    self.decryptor
                        .decryption_share(ct, &self.keys[id - 1], noise[id - 1].take().unwrap())
                        .unwrap()
                })
                .collect()
        }
    }

    #[test]
    fn dealing_and_transport_preserve_the_aggregate_noise() {
        let params = params();
        let mut manager = ShareManager::new(5, 2, params.clone()).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(200);
        let mut dealt: Vec<_> = [-9, 3, 2]
            .into_iter()
            .map(|value| {
                let coefficients: Vec<_> = (1..=params.degree())
                    .map(|column| BigInt::from(value) * BigInt::from(column))
                    .collect();
                let noise =
                    DealerSmudgingNoise::from_signed_coefficients(&coefficients, &params).unwrap();
                let matrices = manager
                    .generate_smudging_shares(noise, &mut rng)
                    .unwrap()
                    .into_transport();
                assert_eq!(matrices.len(), params.moduli().len());
                assert!(
                    matrices
                        .iter()
                        .all(|matrix| matrix.dim() == (5, params.degree()))
                );
                matrices
            })
            .collect();
        let ids = [5, 2, 4];
        let aggregates: Vec<_> = ids
            .iter()
            .map(|&id| {
                let shares = dealt
                    .iter()
                    .map(|dealer| {
                        let matrix = recipient(dealer, id - 1);
                        let restored =
                            RecipientSmudgingShare::from_transport(matrix.clone()).into_transport();
                        assert_eq!(restored, matrix);
                        RecipientSmudgingShare::from_transport(restored)
                    })
                    .collect();
                let aggregate = manager.aggregate_smudging_shares(shares).unwrap();
                AggregatedSmudgingShare::from_transport(aggregate.into_transport()).into_transport()
            })
            .collect();
        for (row, &q) in params.moduli().iter().enumerate() {
            let q = BigInt::from(q);
            let shamir = ShamirSecretSharing::new(2, 5, q.clone());
            for column in 0..params.degree() {
                let points: Vec<_> = ids
                    .iter()
                    .zip(&aggregates)
                    .map(|(&id, poly)| (id, BigInt::from(poly.coefficients()[[row, column]])))
                    .collect();
                let expected = BigInt::from(-4) * BigInt::from(column + 1);
                assert_eq!(
                    shamir.recover(&points).unwrap(),
                    ((expected % &q) + &q) % &q
                );
            }
        }
        for dealer in &mut dealt {
            for matrix in dealer {
                matrix.iter_mut().for_each(Zeroize::zeroize);
            }
        }
    }

    #[test]
    fn noise_generator_preserves_calculator_overrides() {
        let params = params();
        for (depth, count, initial) in [
            (0, 5, None),
            (1, 5, None),
            (2, 3, None),
            (0, 5, Some(12345u64)),
        ] {
            let config = SmudgingBoundCalculatorConfig::new_multiplicative(
                params.clone(),
                5,
                2,
                depth,
                Lambda::secure(40).unwrap(),
            )
            .unwrap();
            let calculator = || {
                let calculator = SmudgingBoundCalculator::new(config.clone())
                    .with_accepted_participant_count(count);
                match initial {
                    Some(bound) => {
                        calculator.with_initial_ciphertext_noise_bound(BigUint::from(bound))
                    }
                    None => calculator,
                }
            };
            let expected = calculator().calculate_sm_bound().unwrap();
            let generator = SsSmudgingNoiseGenerator::from_bound_calculator(calculator()).unwrap();
            assert_eq!(generator.degree(), params.degree());
            assert_eq!(generator.smudging_bound(), &expected);
            if let Some(bound) = initial {
                assert_eq!(
                    expected,
                    (BigUint::from(1u32) << 41usize) * params.degree() * bound
                );
            }
        }
    }

    #[test]
    fn offline_noise_supports_reusable_keys_and_arbitrary_reconstruction_sets() {
        let mut f = Fixture::new(5);
        assert_eq!(f.decryptor.committee_size(), 5);
        assert_eq!(f.decryptor.threshold(), 2);
        assert_eq!(f.decryptor.params(), &f.params);
        // Subset acceptance is an arithmetic property, not a security claim for one dealer.
        for dealers in [1, 3, 5] {
            for ids in [[5, 2, 4], [3, 1, 5]] {
                let noise = f.preprocess(dealers);
                let ct = f.encrypt(9);
                let partials = f.partials(&ct, &ids, noise);
                let found = f
                    .decryptor
                    .decrypt_from_shares(&partials, &ids, &ct)
                    .unwrap();
                assert_eq!(
                    Vec::<u64>::try_decode(&found, Encoding::poly()).unwrap()[0],
                    9
                );
                let reversed: Vec<_> = partials.into_iter().rev().collect();
                let reversed_ids: Vec<_> = ids.into_iter().rev().collect();
                assert_eq!(
                    f.decryptor
                        .decrypt_from_shares(&reversed, &reversed_ids, &ct)
                        .unwrap(),
                    found
                );
            }
        }
    }

    #[test]
    fn addition_and_partial_transport_roundtrip() {
        let mut f = Fixture::new(3);
        let noise = f.preprocess(3);
        let a = f.encrypt(3);
        let b = f.encrypt(5);
        let sum = &a + &b;
        let partials: Vec<_> = f
            .partials(&sum, &[3, 1], noise)
            .into_iter()
            .map(|share| {
                assert_eq!(format!("{share:?}"), "SsSmudgingDecryptionShare { .. }");
                let poly = share.into_parts();
                assert!(!poly.allows_variable_time_computations());
                SsSmudgingDecryptionShare::from_parts(poly)
            })
            .collect();
        let found = f
            .decryptor
            .decrypt_from_shares(&partials, &[3, 1], &sum)
            .unwrap();
        assert_eq!(
            Vec::<u64>::try_decode(&found, Encoding::poly()).unwrap()[0],
            8
        );
    }

    #[test]
    fn explicitly_insecure_lambda_decrypts_for_testing_only() {
        let mut f = Fixture::new(3);
        let lambda = Lambda::insecure(2);
        assert!(!lambda.is_secure());
        assert!(Lambda::secure(lambda.value()).is_err());
        f.noise = SsSmudgingNoiseGenerator::new(
            SmudgingBoundCalculatorConfig::new(f.params.clone(), 3, 2, lambda).unwrap(),
        )
        .unwrap();
        let noise = f.preprocess(3);
        let ct = f.encrypt(9);
        let partials = f.partials(&ct, &[3, 1], noise);
        let found = f
            .decryptor
            .decrypt_from_shares(&partials, &[3, 1], &ct)
            .unwrap();
        assert_eq!(
            Vec::<u64>::try_decode(&found, Encoding::poly()).unwrap()[0],
            9
        );
    }

    #[test]
    fn validates_configuration_and_received_contributions() {
        let params = params();
        for (n, t) in [(0, 0), (2, 0), (3, 0), (5, 1), (5, 3)] {
            assert!(SsSmudgingDecryptionConfig::new(n, t, params.clone()).is_err());
        }
        let config = SsSmudgingDecryptionConfig::new(20, 9, params.clone()).unwrap();
        assert_eq!(config.committee_size(), 20);
        assert_eq!(config.threshold(), 9);
        assert_eq!(config.params(), &params);
        let manager = ShareManager::new(3, 1, params.clone()).unwrap();
        assert!(manager.aggregate_smudging_shares(vec![]).is_err());
        for matrices in [
            vec![Array2::zeros((3, 8)); 4],
            vec![Array2::zeros((8, 3))],
            vec![Array2::from_elem((3, 8), u64::MAX)],
            vec![Array2::zeros((8, 3)).reversed_axes()],
        ] {
            assert!(
                manager
                    .aggregate_smudging_shares(
                        matrices
                            .into_iter()
                            .map(RecipientSmudgingShare::from_transport)
                            .collect()
                    )
                    .is_err()
            );
        }
        let wide = BfvParametersBuilder::new()
            .set_degree(8)
            .set_moduli(params.moduli())
            .set_plaintext_modulus_biguint((BigUint::from(1u32) << 80usize) + 7u32)
            .build_arc()
            .unwrap();
        assert!(SsSmudgingDecryptionConfig::new(3, 1, wide.clone()).is_ok());
        // Explicit-bound sampling is independent of plaintext width and feasibility.
        assert!(
            SsSmudgingNoiseGenerator::from_bound(wide, BigUint::from(0u32))
                .generate(&mut ChaCha8Rng::seed_from_u64(1))
                .is_ok()
        );
    }

    #[test]
    fn rejects_invalid_partials_and_reconstruction_inputs() {
        let mut f = Fixture::new(3);
        let ct = f.encrypt(5);
        let noise = f.preprocess(3);
        let partials = f.partials(&ct, &[1, 2], noise);
        for ids in [vec![1, 1], vec![0, 2], vec![1, 4], vec![1]] {
            assert!(
                f.decryptor
                    .decrypt_from_shares(&partials, &ids, &ct)
                    .is_err()
            );
        }
        assert!(matches!(
            f.decryptor.decrypt_from_shares(&partials[..1], &[1], &ct),
            Err(Error::Threshold(ThresholdError::ShareCountMismatch { .. }))
        ));
        let mut malformed = Poly::<PowerBasis>::zero(f.params.context_at_level(0).unwrap());
        malformed.set_coefficients(Array2::zeros((1, 8)));
        let bad = [
            SsSmudgingDecryptionShare::from_parts(malformed),
            partials[1].clone(),
        ];
        assert!(f.decryptor.decrypt_from_shares(&bad, &[1, 2], &ct).is_err());
        let mut switched = ct.clone();
        switched.switch_down().unwrap();
        for unsupported in [switched.clone(), &ct * &ct, Ciphertext::zero(&f.params)] {
            let noise = AggregatedSmudgingShare::from_transport(Zeroizing::new(Poly::zero(
                f.params.context_at_level(0).unwrap(),
            )));
            assert!(
                f.decryptor
                    .decryption_share(&unsupported, &f.keys[0], noise)
                    .is_err()
            );
            assert!(
                f.decryptor
                    .decrypt_from_shares(&partials, &[1, 2], &unsupported)
                    .is_err()
            );
        }
        assert!(matches!(
            f.decryptor
                .decrypt_from_shares(&partials, &[1, 2], &switched),
            Err(Error::InvalidLevel { .. })
        ));
        let wrong_key = Poly::<Ntt>::zero(f.params.context_at_level(1).unwrap());
        let noise = AggregatedSmudgingShare::from_transport(Zeroizing::new(Poly::zero(
            f.params.context_at_level(0).unwrap(),
        )));
        assert!(matches!(
            f.decryptor.decryption_share(&ct, &wrong_key, noise),
            Err(Error::ParameterMismatch { .. })
        ));
        let too_many = [
            partials[0].clone(),
            partials[1].clone(),
            partials[0].clone(),
        ];
        assert!(
            f.decryptor
                .decrypt_from_shares(&too_many, &[1, 2, 3], &ct)
                .is_err()
        );
        let other_params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(19)
            .set_moduli(f.params.moduli())
            .build_arc()
            .unwrap();
        let other_ct = Ciphertext::zero(&other_params);
        let noise = AggregatedSmudgingShare::from_transport(Zeroizing::new(Poly::zero(
            f.params.context_at_level(0).unwrap(),
        )));
        assert!(matches!(
            f.decryptor.decryption_share(&other_ct, &f.keys[0], noise),
            Err(Error::ParameterMismatch { .. })
        ));
        assert!(matches!(
            f.decryptor
                .decrypt_from_shares(&partials, &[1, 2], &other_ct),
            Err(Error::ParameterMismatch { .. })
        ));
    }

    #[test]
    fn rejects_malformed_keys_and_imported_aggregate_noise() {
        let mut f = Fixture::new(3);
        let ct = f.encrypt(7);
        let ctx = f.params.context_at_level(0).unwrap();
        for matrix in malformed_matrices() {
            let mut key = Poly::<Ntt>::zero(ctx);
            key.set_coefficients(matrix);
            let noise = AggregatedSmudgingShare::from_transport(Zeroizing::new(Poly::zero(ctx)));
            assert!(f.decryptor.decryption_share(&ct, &key, noise).is_err());
        }
        for matrix in malformed_matrices() {
            let mut noise = Zeroizing::new(Poly::<PowerBasis>::zero(ctx));
            noise.set_coefficients(matrix);
            assert!(
                f.decryptor
                    .decryption_share(
                        &ct,
                        &f.keys[0],
                        AggregatedSmudgingShare::from_transport(noise)
                    )
                    .is_err()
            );
        }
        let noise = AggregatedSmudgingShare::from_transport(Zeroizing::new(Poly::zero(
            f.params.context_at_level(1).unwrap(),
        )));
        assert!(matches!(
            f.decryptor.decryption_share(&ct, &f.keys[0], noise),
            Err(Error::ParameterMismatch { .. })
        ));
    }

    #[test]
    fn rejects_malformed_ciphertext_components_before_arithmetic() {
        let mut f = Fixture::new(3);
        let ct = f.encrypt(7);
        let noise = f.preprocess(3);
        let partials = f.partials(&ct, &[1, 2], noise);
        let ctx = f.params.context_at_level(0).unwrap();
        for component in 0..2 {
            for matrix in malformed_matrices() {
                let mut bad = ct.clone();
                bad[component].set_coefficients(matrix);
                let noise =
                    AggregatedSmudgingShare::from_transport(Zeroizing::new(Poly::zero(ctx)));
                assert!(
                    f.decryptor
                        .decryption_share(&bad, &f.keys[0], noise)
                        .is_err()
                );
                assert!(
                    f.decryptor
                        .decrypt_from_shares(&partials, &[1, 2], &bad)
                        .is_err()
                );
            }
            let mut bad = ct.clone();
            bad[component] = Poly::zero(f.params.context_at_level(1).unwrap());
            let noise = AggregatedSmudgingShare::from_transport(Zeroizing::new(Poly::zero(ctx)));
            assert!(
                f.decryptor
                    .decryption_share(&bad, &f.keys[0], noise)
                    .is_err()
            );
            assert!(
                f.decryptor
                    .decrypt_from_shares(&partials, &[1, 2], &bad)
                    .is_err()
            );
        }
    }

    #[test]
    fn reconstruction_checks_partial_context_layout_and_residues() {
        let mut f = Fixture::new(3);
        let ct = f.encrypt(7);
        let noise = f.preprocess(3);
        let partials = f.partials(&ct, &[1, 2], noise);
        for matrix in malformed_matrices() {
            let mut poly = Poly::<PowerBasis>::zero(f.params.context_at_level(0).unwrap());
            poly.set_coefficients(matrix);
            let bad = [
                SsSmudgingDecryptionShare::from_parts(poly),
                partials[1].clone(),
            ];
            assert!(f.decryptor.decrypt_from_shares(&bad, &[1, 2], &ct).is_err());
        }
        let other = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(17)
            .set_moduli_sizes(&[49, 49, 49])
            .build_arc()
            .unwrap();
        let bad = [
            SsSmudgingDecryptionShare::from_parts(Poly::zero(other.context_at_level(0).unwrap())),
            partials[1].clone(),
        ];
        assert!(matches!(
            f.decryptor.decrypt_from_shares(&bad, &[1, 2], &ct),
            Err(Error::ParameterMismatch { .. })
        ));
    }

    #[test]
    fn raw_lazy_and_variable_time_metadata_does_not_affect_secret_arithmetic() {
        let mut f = Fixture::new(3);
        let mut noise = f.preprocess(3);
        let ct = f.encrypt(9);
        let ctx = f.params.context_at_level(0).unwrap();
        let variable_time = fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public());
        let lazy = || {
            Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                &vec![0; f.params.degree()],
                ctx,
                variable_time,
            )
        };
        let mut raw_ct = ct.clone();
        for component in 0..2 {
            let mut poly = lazy();
            poly.set_coefficients(ct[component].coefficients().to_owned());
            raw_ct[component] = poly;
        }
        let ids = [3, 1];
        let partials: Vec<_> = ids
            .iter()
            .map(|&id| {
                let mut key = Zeroizing::new(lazy());
                key.set_coefficients(f.keys[id - 1].coefficients().to_owned());
                let mut imported = noise[id - 1].take().unwrap().into_transport();
                imported.allow_variable_time_computations(variable_time);
                let partial = f
                    .decryptor
                    .decryption_share(
                        &raw_ct,
                        &key,
                        AggregatedSmudgingShare::from_transport(imported),
                    )
                    .unwrap();
                assert!(
                    !partial
                        .clone()
                        .into_parts()
                        .allows_variable_time_computations()
                );
                partial
            })
            .collect();
        let found = f
            .decryptor
            .decrypt_from_shares(&partials, &ids, &raw_ct)
            .unwrap();
        assert_eq!(
            Vec::<u64>::try_decode(&found, Encoding::poly()).unwrap()[0],
            9
        );
    }

    #[test]
    fn first_modulus_scaling_is_preserved() {
        for (p, expected) in [(769, 768), (4099, 639)] {
            let params = BfvParametersBuilder::new()
                .set_degree(16)
                .set_plaintext_modulus(p)
                .set_moduli(&[1153, 12289])
                .build_arc()
                .unwrap();
            let decryptor = SsSmudgingDecryptor::new(
                SsSmudgingDecryptionConfig::new(3, 1, params.clone()).unwrap(),
            );
            let ctx = params.context_at_level(0).unwrap();
            let zero_key = SecretKey::new(vec![0; 16], &params);
            let pt = Plaintext::try_encode(&vec![p - 1; 16], Encoding::poly(), &params).unwrap();
            let ct: Ciphertext = zero_key
                .try_encrypt(&pt, &mut ChaCha8Rng::seed_from_u64(p))
                .unwrap();
            let partial = decryptor
                .decryption_share(
                    &ct,
                    &Poly::zero(ctx),
                    AggregatedSmudgingShare::from_transport(Zeroizing::new(Poly::zero(ctx))),
                )
                .unwrap();
            let found = decryptor
                .decrypt_from_shares(&[partial.clone(), partial], &[1, 2], &ct)
                .unwrap();
            assert_eq!(
                Vec::<u64>::try_decode(&found, Encoding::poly()).unwrap(),
                vec![expected; 16]
            );
        }
    }

    #[cfg(not(feature = "synchronized-decryption"))]
    #[test]
    fn ss_decryption_is_available_without_default_features() {
        let mut f = Fixture::new(3);
        let noise = f.preprocess(3);
        let ct = f.encrypt(7);
        let partials = f.partials(&ct, &[3, 1], noise);
        let found = f
            .decryptor
            .decrypt_from_shares(&partials, &[3, 1], &ct)
            .unwrap();
        assert_eq!(
            Vec::<u64>::try_decode(&found, Encoding::poly()).unwrap()[0],
            7
        );
    }

    #[cfg(feature = "synchronized-decryption")]
    #[test]
    fn both_protocols_support_independent_decryptors() {
        use fhe::trbfv::{
            SmudgingNoiseGenerator, SynchronizedDecryptionConfig, SynchronizedDecryptor,
        };
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(19)
            .set_moduli_sizes(&[50, 50, 50])
            .build_arc()
            .unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(501);
        let config = SynchronizedDecryptionConfig::new(3, 1, params.clone()).unwrap();
        let sync = SynchronizedDecryptor::from_config(config.clone()).unwrap();
        assert_eq!(sync.committee_size(), config.committee_size());
        assert_eq!(sync.threshold(), config.threshold());
        assert_eq!(sync.params(), config.params());
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let mut manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let keys = simulated_key_setup::share_key(&mut manager, &sk, &mut rng).unwrap();
        let prf = simulated_key_setup::simulated_committee_prf_keys(3, &mut rng).unwrap();
        let generator = SmudgingNoiseGenerator::new(
            SmudgingBoundCalculatorConfig::new(params.clone(), 3, 1, Lambda::secure(40).unwrap())
                .unwrap(),
        )
        .unwrap();
        let pt = Plaintext::try_encode(&[7u64], Encoding::poly(), &params).unwrap();
        let ct = pk.try_encrypt(&pt, &mut rng).unwrap();
        let partials: Vec<_> = [1, 3]
            .iter()
            .map(|&id| {
                sync.decryption_share(
                    &ct,
                    &keys[id - 1],
                    id,
                    &[1, 3],
                    generator.generate(&mut rng).unwrap(),
                    &prf[id - 1],
                )
                .unwrap()
            })
            .collect();
        assert_eq!(
            Vec::<u64>::try_decode(
                &sync.decrypt_from_shares(&partials, &ct).unwrap(),
                Encoding::poly()
            )
            .unwrap()[0],
            7
        );
        let mut ss = Fixture::new(3);
        let noise = ss.preprocess(3);
        let ct = ss.encrypt(11);
        let partials = ss.partials(&ct, &[1, 2], noise);
        assert_eq!(
            Vec::<u64>::try_decode(
                &ss.decryptor
                    .decrypt_from_shares(&partials, &[1, 2], &ct)
                    .unwrap(),
                Encoding::poly()
            )
            .unwrap()[0],
            11
        );
    }
}

/// Degree-8192 regression preset, not an independent security certification.
#[cfg(feature = "experimental-mbfv")]
mod secure {
    use super::parameters::{
        self, LAMBDA, NUM_PARTIES, NUM_SUMMED, THRESHOLD, bound_config, transport_params,
        trbfv_params,
    };
    use super::ss_smudging::{self, NoiseMode, Scenario};
    use fhe::trbfv::{Lambda, SsSmudgingNoiseGenerator};

    fn scenario() -> Scenario {
        Scenario {
            params: trbfv_params(),
            transport: Some(transport_params()),
            n: NUM_PARTIES,
            threshold: THRESHOLD,
            m: NUM_SUMMED,
            lambda: Lambda::secure(LAMBDA).unwrap(),
            reconstructing: (2..=NUM_PARTIES).step_by(2).collect(),
        }
    }

    #[test]
    fn random_dealt_noise_and_encrypted_key_and_noise_transport() {
        assert_eq!(
            ss_smudging::run(&scenario(), NoiseMode::Random).unwrap(),
            NUM_SUMMED as u64
        );
    }

    #[test]
    fn worst_case_signed_n_times_smudging_bound() {
        for sign in [-1, 1] {
            assert_eq!(
                ss_smudging::run(&scenario(), NoiseMode::Endpoint(sign)).unwrap(),
                NUM_SUMMED as u64
            );
        }
    }

    #[test]
    fn transport_plaintext_covers_every_share_residue() {
        parameters::assert_transport_range();
    }

    #[test]
    fn smudging_bound_matches_the_preset_and_strict_correctness_budget() {
        let generator = SsSmudgingNoiseGenerator::new(bound_config(trbfv_params())).unwrap();
        parameters::assert_correctness_budget(generator.smudging_bound());
    }
}
