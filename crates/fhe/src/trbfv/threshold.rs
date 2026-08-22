use std::sync::Arc;

use crate::Error;
/// Main threshold BFV orchestrator.
///
/// This module provides the main TRBFV struct that coordinates between secret sharing,
/// smudging, and share management operations to implement the threshold BFV protocol
/// (Urban–Rambaud 2024).
///
/// # Threshold BFV Overview
///
/// Threshold BFV enables distributed decryption where:
/// - Secret keys are shared among n parties using secret sharing
/// - Only t+1 parties (threshold) are needed to decrypt
/// - Up to t parties can be compromised without breaking security
/// - Smudging noise protects intermediate values during decryption
///
/// ## What this module does NOT cover
///
/// This module implements the core sharing, smudging, and decryption logic.  It is
/// **not** the complete robust threshold protocol from Urban–Rambaud&nbsp;2024:
/// - **No distributed key generation (DKG)** — keys must be generated offline.
/// - **No broadcast channel** — all share exchanges are assumed to happen
///   out-of-band.
/// - **No FLSS** (function-linear secret sharing) pre-processing.
/// - **No GURS** (guaranteed uniform random string) generation.
/// - **No proactive refresh** or identifiable-abort mechanisms.
/// - **No PVSS** (publicly verifiable secret sharing) — the current
///   implementation is passively secure.
///
/// Callers who require full end-to-end robust threshold FHE must supply these
/// components externally.
///
/// # Protocol Flow
///
/// 1. **Setup**: Generate BFV parameters and TRBFV configuration
/// 2. **Key Generation**: Each party generates secret key shares
/// 3. **Share Distribution**: Parties exchange shares via secure channels
/// 4. **Encryption**: Standard BFV encryption (no changes needed)
/// 5. **Threshold Decryption**:
///    - Each party computes decryption share with smudging
///    - Combine threshold shares to recover plaintext
use crate::bfv::{BfvParameters, Ciphertext, Plaintext};
use crate::trbfv::config::validate_threshold_config;
use crate::trbfv::shares::{
    AggregatedKeyShare, DecryptionShare, KeyShareContribution, NoiseShareContribution,
    OneTimeNoiseShare, SecretPoly, SecretShareMatrix, ShareManager,
};
use crate::trbfv::smudging::{
    Lambda, SmudgingBoundCalculator, SmudgingBoundCalculatorConfig, SmudgingCoefficients,
    SmudgingNoiseGenerator,
};
use crate::trbfv::{ParticipantSet, SessionId};
use fhe_math::rq::{Ntt, PowerBasis};
use fhe_traits::FheParametrized;
use rand::{CryptoRng, RngCore};

/// Threshold BFV configuration and operations.
/// This struct serves as the main coordinator for threshold BFV operations, managing
/// the interaction between secret sharing, smudging, and share management components.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TRBFV {
    /// Number of parties in the threshold scheme
    pub n: usize,
    /// Threshold for reconstruction (must be exactly (n - 1) / 2; reconstruction needs threshold + 1 shares)
    pub threshold: usize,
    /// BFV parameters (contains degree, plaintext_modulus, moduli, etc.)
    pub params: Arc<BfvParameters>,
}

impl TRBFV {
    /// Creates a new threshold BFV configuration.
    ///
    /// # Arguments
    /// * `n` - Number of parties (must be >= 3)
    /// * `threshold` - Threshold for reconstruction (must be exactly (n - 1) / 2)
    /// * `params` - BFV parameters
    pub fn new(n: usize, threshold: usize, params: Arc<BfvParameters>) -> Result<Self, Error> {
        // Validate all parameters
        validate_threshold_config(n, threshold)?;

        Ok(Self {
            n,
            threshold,
            params,
        })
    }

    /// Generate Shamir Secret Shares for polynomial coefficients.
    ///
    /// This method creates secret shares that can be distributed to different parties.
    /// Each party will receive one share for each polynomial coefficient.
    ///
    /// # Arguments
    /// * `poly` - Polynomial to be shared (typically secret key polynomial), in
    ///   the protected [`SecretPoly`] wrapper
    ///
    /// # Returns
    /// Protected share matrices, one per BFV modulus. Each matrix has
    /// dimensions [n, degree] and is zeroized automatically on drop.
    pub fn generate_secret_shares_from_poly<R: RngCore + CryptoRng>(
        &self,
        poly: SecretPoly<PowerBasis>,
        rng: &mut R,
    ) -> Result<Vec<SecretShareMatrix>, Error> {
        let mut share_manager = ShareManager::new(self.n, self.threshold, self.params.clone())?;
        share_manager.generate_secret_shares_from_poly(poly, rng)
    }

    /// Aggregate identified secret-sharing contributions to compute SK_i.
    ///
    /// The explicit participant set is checked for exact one-per-member coverage.
    ///
    /// # Arguments
    /// * `participant_set` - Caller-selected key epoch and accepted set
    /// * `contributions` - Identified protected receiver matrices
    ///
    /// # Returns
    /// Metadata-bearing protected aggregate representing the combined key
    /// material.
    pub fn aggregate_collected_shares(
        &self,
        participant_set: &ParticipantSet,
        contributions: &[KeyShareContribution],
    ) -> Result<AggregatedKeyShare<PowerBasis>, Error> {
        let share_manager = ShareManager::new(self.n, self.threshold, self.params.clone())?;
        share_manager.aggregate_collected_shares(participant_set, contributions)
    }

    /// Consume and aggregate identified one-time noise contributions.
    pub fn aggregate_noise_shares(
        &self,
        participant_set: &ParticipantSet,
        use_session: SessionId,
        contributions: Vec<NoiseShareContribution>,
    ) -> Result<OneTimeNoiseShare, Error> {
        let share_manager = ShareManager::new(self.n, self.threshold, self.params.clone())?;
        share_manager.aggregate_noise_shares(participant_set, use_session, contributions)
    }

    /// Generate smudging error coefficients for noise.
    ///
    /// Creates noise that will be added to decryption shares.
    /// Uses optimal variance calculation based on security parameters and number of ciphertexts.
    ///
    /// This is a convenience wrapper that uses all parties as the accepted
    /// participant set. For explicit control over relinearization key
    /// contributors, use [`Self::generate_smudging_error_with_participant_count`].
    ///
    /// # Limitations
    ///
    /// The returned coefficients must be moved into identified noise
    /// contributions and consumed for one decryption use.
    ///
    /// # Arguments
    /// * `num_ciphertexts` - Number of ciphertexts being processed (e.g., votes to count, numbers to sum)
    /// * `mult_depth` - Multiplicative circuit depth (0 for additive-only)
    /// * `lambda` - Statistical security level (use `Lambda::secure(lambda)`
    ///   in production; `Lambda::insecure(lambda)` for fast tests)
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// The smudging error coefficients in the protected [`SmudgingCoefficients`]
    /// wrapper (best-effort BigInt cleanup on drop)
    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &self,
        num_ciphertexts: usize,
        mult_depth: u32,
        lambda: Lambda,
        rng: &mut R,
    ) -> Result<SmudgingCoefficients, Error> {
        // Forward to the explicit API using all n parties as the accepted set.
        self.generate_smudging_error_with_participant_count(
            num_ciphertexts,
            mult_depth,
            self.n,
            lambda,
            rng,
        )
    }

    /// Generate smudging error coefficients with an explicit accepted
    /// participant count.
    ///
    /// The `accepted_participant_count` must equal the number of parties that
    /// contributed to the distributed relinearization key (the *l*-BFV accepted
    /// set). The distributed RLK error scales linearly with this count, so
    /// mismatching it will produce a smudging bound that is either too loose
    /// (wasting correctness budget) or too tight (breaking statistical
    /// hiding).
    ///
    /// # Limitations
    ///
    /// The returned coefficients are one-time material and must be consumed
    /// into an identified noise aggregate before decryption.
    ///
    /// # Arguments
    /// * `num_ciphertexts` - Number of ciphertexts being processed
    /// * `mult_depth` - Multiplicative circuit depth (0 for additive-only)
    /// * `accepted_participant_count` - Number of parties in the accepted
    ///   *l*-BFV set; must be in `1..=n`
    /// * `lambda` - Statistical security level
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// The smudging error coefficients in the protected [`SmudgingCoefficients`]
    /// wrapper (best-effort BigInt cleanup on drop)
    ///
    /// # Errors
    /// Returns error if:
    /// - `accepted_participant_count` is zero or exceeds `n`
    /// - The smudging bound computation is infeasible for the given parameters
    pub fn generate_smudging_error_with_participant_count<R: RngCore + CryptoRng>(
        &self,
        num_ciphertexts: usize,
        mult_depth: u32,
        accepted_participant_count: usize,
        lambda: Lambda,
        rng: &mut R,
    ) -> Result<SmudgingCoefficients, Error> {
        let config = SmudgingBoundCalculatorConfig::new_multiplicative(
            self.params.clone(),
            self.n,
            num_ciphertexts,
            mult_depth,
            lambda,
        )?;
        let calculator = SmudgingBoundCalculator::new(config)
            .with_accepted_participant_count(accepted_participant_count);
        let generator = SmudgingNoiseGenerator::from_bound_calculator(calculator)?;

        generator.generate_smudging_error(rng)
    }
    /// Compute decryption share from ciphertext and secret/smudging polynomials.
    ///
    /// Each party calls this method to compute their contribution to the threshold decryption.
    /// The result should be sent to the party coordinating the decryption.
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext to decrypt
    /// * `party_id` - The 1-based ID attached to the returned share
    /// * `sk_i` - This party's metadata-bearing aggregated key share
    /// * `use_session` - Fresh caller-supplied ID for this decryption use
    /// * `es_i` - Consumed aggregated noise for the same epoch, set, and use
    ///
    /// # Returns
    /// Identified protected decryption share (zeroized automatically on drop
    /// after use). The ciphertext must be at level 0;
    /// non-zero levels return [`Error::InvalidCiphertext`].
    pub fn decryption_share(
        &self,
        ciphertext: Arc<Ciphertext>,
        party_id: u32,
        sk_i: AggregatedKeyShare<Ntt>,
        use_session: SessionId,
        es_i: OneTimeNoiseShare,
    ) -> Result<DecryptionShare, Error> {
        let share_manager = ShareManager::new(self.n, self.threshold, self.params.clone())?;
        share_manager.decryption_share(ciphertext, party_id, sk_i, use_session, es_i)
    }

    /// Decrypt ciphertext from collected decryption shares.
    ///
    /// This method performs the final step of threshold decryption by combining
    /// decryption shares from exactly `threshold + 1` parties.
    ///
    /// # Arguments
    /// * `d_shares` - Exactly `threshold + 1` identified shares. Embedded IDs,
    ///   unique in-range membership, and common metadata are validated.
    /// * `ciphertext` - The original ciphertext being decrypted
    ///
    /// # Returns
    /// The decrypted plaintext. The ciphertext must be at level 0;
    /// non-zero levels return [`Error::InvalidCiphertext`].
    pub fn decrypt(
        &self,
        d_shares: Vec<DecryptionShare>,
        ciphertext: Arc<Ciphertext>,
    ) -> Result<Plaintext, Error> {
        let share_manager = ShareManager::new(self.n, self.threshold, self.params.clone())?;
        share_manager.decrypt_from_shares(d_shares, ciphertext)
    }
}

impl FheParametrized for TRBFV {
    type Parameters = BfvParameters;
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::bfv::{BfvParametersBuilder, Encoding, Plaintext, PublicKey, SecretKey};
    use crate::trbfv::{ContributionBinding, NoiseShareMatrix};
    use fhe_traits::{FheEncoder, FheEncrypter};
    use num_traits::Zero;
    use rand::rng;

    fn test_params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(8192)
            .set_plaintext_modulus(16384)
            .set_moduli(&[0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001])
            .build_arc()
            .unwrap()
    }

    fn test_participant_set(n: usize) -> ParticipantSet {
        ParticipantSet::new(
            SessionId::new([9; 32]),
            (1..=n).map(|party_id| party_id as u32).collect(),
        )
        .unwrap()
    }

    fn aggregate_key(
        manager: &ShareManager,
        poly: SecretPoly<PowerBasis>,
        participant_set: &ParticipantSet,
    ) -> AggregatedKeyShare<Ntt> {
        let shape = poly.coefficients().dim();
        let mut matrices = Vec::with_capacity(participant_set.participant_ids().len());
        matrices.push(SecretShareMatrix::new(poly.coefficients().to_owned()));
        matrices.extend(
            (1..participant_set.participant_ids().len())
                .map(|_| SecretShareMatrix::new(ndarray::Array2::zeros(shape))),
        );
        let contributions = participant_set
            .participant_ids()
            .iter()
            .copied()
            .zip(matrices)
            .map(|(party_id, matrix)| {
                KeyShareContribution::new(
                    ContributionBinding::new(participant_set.clone(), party_id).unwrap(),
                    matrix,
                )
            })
            .collect::<Vec<_>>();
        manager
            .aggregate_collected_shares(participant_set, &contributions)
            .unwrap()
            .into_ntt()
            .unwrap()
    }

    fn aggregate_zero_noise(
        manager: &ShareManager,
        participant_set: &ParticipantSet,
        use_session: SessionId,
    ) -> OneTimeNoiseShare {
        let shape = (manager.params.moduli().len(), manager.params.degree());
        let contributions = participant_set
            .participant_ids()
            .iter()
            .copied()
            .map(|party_id| {
                NoiseShareContribution::new(
                    ContributionBinding::new(participant_set.clone(), party_id).unwrap(),
                    NoiseShareMatrix::new(ndarray::Array2::zeros(shape)),
                )
            })
            .collect();
        manager
            .aggregate_noise_shares(participant_set, use_session, contributions)
            .unwrap()
    }

    #[test]
    #[allow(unused_mut)]
    fn test_trbfv_new() {
        let n: usize = 16;
        let threshold = 7;
        let params = test_params();

        let mut trbfv = TRBFV::new(n, threshold, params.clone()).unwrap();
        assert_eq!(trbfv.n, n);
        assert_eq!(trbfv.threshold, threshold);
        assert_eq!(trbfv.params, params);
    }

    #[test]
    fn test_validation_errors() {
        let params = test_params();

        // Test invalid n = 0
        assert!(TRBFV::new(0, 3, params.clone()).is_err());

        // Test invalid threshold > (n-1)/2
        assert!(TRBFV::new(3, 2, params.clone()).is_err());
        assert!(TRBFV::new(3, 3, params.clone()).is_err());
        assert!(TRBFV::new(3, 4, params.clone()).is_err());
    }

    #[test]
    #[allow(unused_mut)]
    fn test_secret_sharing_integration() {
        let mut rng = rng();
        let n: usize = 5;
        let threshold = 2;
        let params = test_params();

        let mut trbfv = TRBFV::new(n, threshold, params.clone()).unwrap();

        // Generate a secret key for testing
        let sk = SecretKey::random(&params, &mut rng);
        let share_manager = ShareManager::new(n, threshold, params.clone()).unwrap();
        let sk_poly = share_manager
            .coeffs_to_poly_level0(sk.coeffs.clone().as_ref())
            .unwrap();
        let shares = trbfv
            .generate_secret_shares_from_poly(sk_poly, &mut rng)
            .unwrap();

        // Check that we got the right number of shares
        assert_eq!(shares.len(), params.moduli().len());
        for share_matrix in shares {
            assert_eq!(share_matrix.nrows(), n);
            assert_eq!(share_matrix.ncols(), params.degree());
        }
    }

    #[test]
    fn test_smudging_error_generation() {
        let params = test_params();
        let n = 3;
        let threshold = 1;
        let trbfv = TRBFV::new(n, threshold, params.clone()).unwrap();

        let mut rng = rng();
        let result = trbfv.generate_smudging_error(1, 0, Lambda::secure(80).unwrap(), &mut rng);
        //Checking if all the coefficients of the smudging noise are different than 0,
        //having one equal to zero is hardly likely to happen if the smudging noise was generated.
        //TODO: add a test that calculates the empirical variance from the coefficients, so as to
        //compare with the variance used when generating the coefficients.
        for (poly_idx, poly) in result.iter().enumerate() {
            for (coeff_idx, coeff) in poly.as_slice().iter().enumerate() {
                assert!(
                    !coeff.is_zero(),
                    "Zero coefficient at poly[{poly_idx}][{coeff_idx}] used as smudging noise"
                );
            }
        }
    }

    #[test]
    fn test_smudging_error_multiple_ciphertexts() {
        let params = test_params();
        let n = 3;
        let threshold = 1;
        let trbfv = TRBFV::new(n, threshold, params.clone()).unwrap();

        // Test with multiple ciphertexts (this should increase the bound requirements)
        let mut rng = rng();
        let result = trbfv.generate_smudging_error(10, 0, Lambda::secure(80).unwrap(), &mut rng);

        for (poly_idx, poly) in result.iter().enumerate() {
            for (coeff_idx, coeff) in poly.as_slice().iter().enumerate() {
                assert!(
                    !coeff.is_zero(),
                    "Zero coefficient at poly[{poly_idx}][{coeff_idx}], this is hardly likely to happen"
                );
            }
        }
        assert_eq!(result.unwrap().len(), params.degree());
    }

    #[test]
    fn smudging_error_rejects_zero_ciphertexts() {
        let params = test_params();
        let trbfv = TRBFV::new(3, 1, params).unwrap();
        let mut rng = rng();

        let err = trbfv
            .generate_smudging_error(0, 0, Lambda::secure(80).unwrap(), &mut rng)
            .unwrap_err();
        assert!(err.to_string().contains("ciphertexts"));
    }

    // ── generate_smudging_error_with_participant_count tests ──────────────

    #[test]
    fn smudging_error_with_valid_participant_count_succeeds() {
        let params = test_params();
        let n = 5;
        let trbfv = TRBFV::new(n, 2, params.clone()).unwrap();
        let mut rng = rng();

        // Use an accepted_participant_count that is a strict subset (3 of 5).
        let result = trbfv.generate_smudging_error_with_participant_count(
            1,
            0,
            3,
            Lambda::secure(80).unwrap(),
            &mut rng,
        );
        assert!(result.is_ok(), "valid participant count should succeed");
        let coeffs = result.unwrap();
        assert_eq!(coeffs.len(), params.degree());
        assert!(coeffs.as_slice().iter().any(|c| !c.is_zero()));
    }

    #[test]
    fn smudging_error_with_participant_count_zero_rejected() {
        let params = test_params();
        let n = 3;
        let trbfv = TRBFV::new(n, 1, params.clone()).unwrap();
        let mut rng = rng();

        let err = trbfv
            .generate_smudging_error_with_participant_count(
                1,
                0,
                0,
                Lambda::secure(80).unwrap(),
                &mut rng,
            )
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("accepted participant"),
            "zero count should be rejected; got: {msg}"
        );
    }

    #[test]
    fn smudging_error_with_participant_count_above_n_rejected() {
        let params = test_params();
        let n = 3;
        let trbfv = TRBFV::new(n, 1, params.clone()).unwrap();
        let mut rng = rng();

        let err = trbfv
            .generate_smudging_error_with_participant_count(
                1,
                0,
                4, // > n = 3
                Lambda::secure(80).unwrap(),
                &mut rng,
            )
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("accepted participant"),
            "over-limit count should be rejected; got: {msg}"
        );
    }

    #[test]
    fn smudging_error_with_all_participants_matches_default() {
        let params = test_params();
        let n = 3;
        let trbfv = TRBFV::new(n, 1, params.clone()).unwrap();

        // The default method uses all n parties as accepted participants.
        // The explicit method with accepted_participant_count = n should be
        // semantically equivalent (same calculator config).
        // We test this by verifying both produce errors or success together.
        let mut rng_default = rng();
        let default_result =
            trbfv.generate_smudging_error(1, 0, Lambda::secure(80).unwrap(), &mut rng_default);
        let mut rng_explicit = rng();
        let explicit_result = trbfv.generate_smudging_error_with_participant_count(
            1,
            0,
            n,
            Lambda::secure(80).unwrap(),
            &mut rng_explicit,
        );
        assert_eq!(
            default_result.is_ok(),
            explicit_result.is_ok(),
            "default and explicit(n) should both succeed or both fail"
        );
        if let (Ok(d), Ok(e)) = (default_result.as_ref(), explicit_result.as_ref()) {
            assert_eq!(d.len(), e.len());
        }
    }

    #[test]
    fn test_decryption_share_generation() {
        let mut rng = rng();
        let params = test_params();
        let n = 3;
        let threshold = 1;
        let trbfv = TRBFV::new(n, threshold, params.clone()).unwrap();

        // Create a test ciphertext
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let plaintext_data = vec![42u64];
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Generate polynomials for decryption share
        let share_manager = ShareManager::new(n, threshold, params.clone()).unwrap();
        let sk_poly = share_manager
            .coeffs_to_poly_level0(sk.coeffs.as_ref())
            .unwrap();
        let participant_set = test_participant_set(n);
        let use_session = SessionId::new([10; 32]);

        let decryption_share = trbfv
            .decryption_share(
                ct,
                1,
                aggregate_key(&share_manager, sk_poly, &participant_set),
                use_session,
                aggregate_zero_noise(&share_manager, &participant_set, use_session),
            )
            .unwrap();

        assert_eq!(decryption_share.coefficients().ncols(), params.degree());
    }

    //TODO Replace this with a more accurate test test_threshold_decrypt_workflow,
    //something similar to test_threshold_decryption_workflow from trbfv/shares.rs
    //but with smudging noise generated and not only equal to zero. At the end we should be checking if we get correct
    //plaintext.
    #[test]
    fn test_full_threshold_decrypt_workflow() {
        let mut rng = rng();
        let params = test_params();
        let n = 3;
        let threshold = 1;

        // Create multiple TRBFV instances (simulating parties)
        let trbfv_instances: Vec<TRBFV> = (0..n)
            .map(|_| TRBFV::new(n, threshold, params.clone()).unwrap())
            .collect();

        // Each party has their own secret key
        let secret_keys: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        // Create a test ciphertext (using first party's key for simplicity)
        let pk = PublicKey::new(&secret_keys[0], &mut rng);
        let plaintext_data = vec![123u64];
        let pt = Plaintext::try_encode(&plaintext_data, Encoding::poly(), &params).unwrap();
        let ct = Arc::new(pk.try_encrypt(&pt, &mut rng).unwrap());

        // Each party generates decryption shares
        let mut decryption_shares = Vec::new();
        let participant_set = test_participant_set(n);
        let use_session = SessionId::new([10; 32]);
        for i in 0..(threshold + 1) {
            let share_manager = ShareManager::new(n, threshold, params.clone()).unwrap();
            let sk_poly = share_manager
                .coeffs_to_poly_level0(secret_keys[i].coeffs.as_ref())
                .unwrap();

            let share = trbfv_instances[i]
                .decryption_share(
                    ct.clone(),
                    (i + 1) as u32,
                    aggregate_key(&share_manager, sk_poly, &participant_set),
                    use_session,
                    aggregate_zero_noise(&share_manager, &participant_set, use_session),
                )
                .unwrap();
            decryption_shares.push(share);
        }

        // Test the decrypt method with parties 1 and 2 reconstructing
        let result = trbfv_instances[0].decrypt(decryption_shares, ct);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fhe_parametrized_trait() {
        let params = test_params();
        let trbfv = TRBFV::new(3, 1, params.clone()).unwrap();

        // Test basic struct properties instead
        assert_eq!(trbfv.params, params);
    }

    #[test]
    fn test_clone_and_debug() {
        let params = test_params();
        let trbfv1 = TRBFV::new(5, 2, params.clone()).unwrap();

        // Test Clone
        let trbfv2 = trbfv1.clone();
        assert_eq!(trbfv1.n, trbfv2.n);
        assert_eq!(trbfv1.threshold, trbfv2.threshold);

        // Test Debug (should not panic)
        let debug_str = format!("{trbfv1:?}");
        assert!(debug_str.contains("TRBFV"));

        // Test PartialEq
        assert_eq!(trbfv1, trbfv2);
    }

    //TODO To replace with a more accurate test
    #[test]
    fn test_edge_case_minimal_threshold() {
        let params = test_params();

        // Minimal valid configuration: 3 parties, threshold 1
        let trbfv = TRBFV::new(3, 1, params.clone()).unwrap();
        assert_eq!(trbfv.n, 3);
        assert_eq!(trbfv.threshold, 1);

        // Test that basic operations work
        let mut rng = rng();
        let sk = SecretKey::random(&params, &mut rng);
        let share_manager = ShareManager::new(3, 1, params.clone()).unwrap();
        let sk_poly = share_manager
            .coeffs_to_poly_level0(sk.coeffs.as_ref())
            .unwrap();

        let shares = trbfv.generate_secret_shares_from_poly(sk_poly, &mut rng);
        assert!(shares.is_ok());
    }
}
