#![warn(missing_docs)]
#![expect(
    clippy::indexing_slicing,
    reason = "validated indices in cryptographic hot paths"
)]

//! Threshold CKKS: distributed key generation, multiparty relinearization
//! keys, and threshold decryption for the CKKS approximate homomorphic
//! encryption scheme.
//!
//! See `crates/fhe/src/trckks/README.md` for the full API map and the
//! security posture. The protocol stack, with references:
//!
//! - **Additive joint key** (Mouchet–Troncoso-Pastoriza–Bossuat–Hubaux,
//!   *Multiparty Homomorphic Encryption from Ring-Learning-with-Errors*,
//!   <https://eprint.iacr.org/2020/304>): `s = sum_i s_i` over the
//!   parties' CBD-sampled contributions. The joint public key is produced
//!   non-interactively from a common random polynomial (CRP) — Protocol 1
//!   (`EncKeyGen`): party `i` publishes `pk0_i = -a*s_i + e_i` and the
//!   aggregated key is `(sum_i pk0_i, a)`. See [`keygen`].
//! - **Relinearization key** for the joint secret by the two-round CRP
//!   protocol of the same paper, Protocol 2 (`RelinKeyGen`). It only
//!   manipulates key material, so it applies to CKKS unchanged; one
//!   instance per multiplication level for leveled circuits. See
//!   [`relin_gen`]. The HYBRID variant ([`hybrid_gen`]) runs the same
//!   protocol over `Q·P` with the digit gadget of [`crate::ckks::hybrid`]:
//!   ONE ceremony yields a key for every level, ~`dnum/L_ℓ` the size per
//!   level and `1/P` the key-switch noise.
//! - **Shamir layer** (Urban–Rambaud, *Robust Multiparty Computation from
//!   Threshold Encryption Based on RLWE*, <https://eprint.iacr.org/2024/1285>),
//!   mirroring [`crate::trbfv`]: each party Shamir-shares its `s_i` and its
//!   smudging-noise contribution coefficient-wise mod each RNS prime, so
//!   any `threshold + 1` of `n` parties can decrypt. Shares are independent
//!   per-modulus sharings: moving a share to a rescaled ciphertext's level
//!   means DROPPING RNS rows ([`TRCKKS::project_share_to_level`]), never
//!   dividing.
//! - **Threshold decryption**: party `j` publishes
//!   `d_j = c0 + c1*[s]_j + [e_sm]_j` where `[x]_j` is its aggregated
//!   Shamir share; Lagrange reconstruction of `{d_j}` yields
//!   `c0 + c1*s + e_sm`, which *is* the CKKS plaintext `delta*m + e + e_sm`
//!   (no BFV-style scaling step).
//!
//! # Security caveats (read before production use)
//!
//! CKKS decryption is approximate: the decrypted value carries the
//! evaluation noise, so publishing decryption results REQUIRES the smudging
//! noise to statistically flood that noise (IND-CPA-D / Li-Micciancio).
//! Derive the bound with [`smudging::CkksSmudgingBoundCalculator`], which
//! enforces the security floor `2^lambda * B_C` against the two CKKS
//! correctness walls (no wrap mod `Q_l`; bounded precision loss), and feed
//! its `calculate_sm_bits()` into [`TRCKKS::generate_smudging_error`]. The
//! dealt smudging sharing is SINGLE-USE per ciphertext (see
//! [`TRCKKS::decryption_share`]). The relinearization ceremony carries no
//! zero-knowledge proofs: it is verified by determinism (every party derives
//! the identical joint key from the same public shares).

mod hybrid_gen;
mod keygen;
mod relin_gen;
pub mod smudging;

pub use hybrid_gen::{CkksHybridRelinKeyGenerator, CkksHybridRelinKeyShare};
pub use keygen::{CkksCrp, CkksPublicKeyShare};
pub use relin_gen::{CkksRelinKeyGenerator, CkksRelinKeyShare, R1, R1Aggregated, R2};
pub use smudging::{CkksCircuitShape, CkksSmudgingBoundCalculator, CkksSmudgingConfig};

use crate::ckks::{CkksCiphertext, CkksParameters, CkksPlaintext};
use crate::trbfv::ShamirSecretSharing;
use crate::{Error, Result};
use fhe_math::rq::{Ntt, Poly, PowerBasis, traits::TryConvertFrom};
use fhe_math::zq::Modulus;
use fhe_util::rng08;
use ndarray::Array2;
use num_bigint::{BigInt, RandBigInt};
use num_traits::ToPrimitive;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Threshold CKKS coordinator.
///
/// Wraps the parameters and `(n, threshold)` configuration and exposes the
/// dealing, aggregation, and threshold-decryption operations. Holds no
/// secret material.
#[derive(Debug, Clone)]
pub struct TRCKKS {
    /// Number of parties.
    pub n: usize,
    /// Corruption threshold; `threshold + 1` parties reconstruct.
    pub threshold: usize,
    /// The CKKS parameters.
    pub params: Arc<CkksParameters>,
}

impl TRCKKS {
    /// Create a new threshold CKKS configuration.
    ///
    /// Requires `n >= 3`, `1 <= threshold <= (n-1)/2` (honest majority), and
    /// `n` smaller than the smallest RNS modulus.
    pub fn new(n: usize, threshold: usize, params: Arc<CkksParameters>) -> Result<Self> {
        if n < 3 {
            return Err(Error::DefaultError(format!(
                "threshold CKKS requires at least 3 parties, got {n}"
            )));
        }
        if threshold == 0 || threshold > (n - 1) / 2 {
            return Err(Error::DefaultError(format!(
                "threshold must be in 1..=(n-1)/2 = {}, got {threshold}",
                (n - 1) / 2
            )));
        }
        let min_modulus = params
            .moduli()
            .iter()
            .min()
            .ok_or_else(|| Error::DefaultError("parameters have no moduli".to_string()))?;
        if n >= usize::try_from(*min_modulus).unwrap_or(usize::MAX) {
            return Err(Error::DefaultError(format!(
                "party count {n} must be smaller than the smallest modulus {min_modulus}"
            )));
        }
        Ok(Self {
            n,
            threshold,
            params,
        })
    }

    /// Shamir-share a polynomial's coefficients mod each RNS prime.
    ///
    /// Returns one `[n, degree]` share matrix per modulus; row `j` is party
    /// `j+1`'s share vector. Each modulus is shared independently (its own
    /// forked seed), in parallel.
    pub fn generate_secret_shares_from_poly<R: RngCore + CryptoRng>(
        &self,
        poly: Zeroizing<Poly<PowerBasis>>,
        rng: &mut R,
    ) -> Result<Vec<Array2<u64>>> {
        let moduli: Vec<u64> = poly.ctx().moduli().to_vec();
        let coefficients = poly.coefficients();
        let coeff_rows: Vec<_> = coefficients.outer_iter().collect();

        let seeds: Vec<[u8; 32]> = (0..moduli.len())
            .map(|_| crate::trbfv::shamir::fork_seed(rng))
            .collect();

        moduli
            .par_iter()
            .zip(coeff_rows.par_iter())
            .enumerate()
            .map(|(i, (m, p))| -> Result<Array2<u64>> {
                let mut rng = ChaCha20Rng::from_seed(seeds[i]);
                let shamir = ShamirSecretSharing {
                    threshold: self.threshold,
                    share_amount: self.n,
                    prime: BigInt::from(*m),
                };

                let mut m_data: Vec<u64> = Vec::with_capacity(self.n * p.len());
                for c in p.iter() {
                    let c_shares = shamir
                        .split(BigInt::from(*c), &mut rng)
                        .map_err(|e| Error::DefaultError(e.to_string()))?;
                    for (_, c_share) in c_shares.iter() {
                        m_data.push(c_share.to_u64().ok_or_else(|| {
                            Error::DefaultError("Shamir share does not fit in u64".to_string())
                        })?);
                    }
                }

                let arr = Array2::from_shape_vec((self.params.degree(), self.n), m_data).map_err(
                    |_| Error::DefaultError("failed to create share matrix".to_string()),
                )?;
                Ok(arr.t().to_owned())
            })
            .collect()
    }

    /// Aggregate share matrices collected from the dealing parties into this
    /// party's share of the joint secret.
    ///
    /// Each input matrix has shape `[moduli, degree]` (this party's row from
    /// each dealer, stacked over moduli).
    pub fn aggregate_collected_shares(
        &self,
        collected: &[Array2<u64>],
    ) -> Result<Poly<PowerBasis>> {
        if collected.is_empty() {
            return Err(Error::TooFewValues {
                actual: 0,
                minimum: 1,
            });
        }
        let expected_shape = (self.params.moduli().len(), self.params.degree());
        for item in collected {
            if item.dim() != expected_shape {
                return Err(Error::DefaultError(format!(
                    "share matrix has shape {:?}, expected {expected_shape:?}",
                    item.dim()
                )));
            }
        }
        let ctx = self.params.context_at_level(0)?;

        let mut sum = Array2::<u64>::zeros(expected_shape);
        for (row, mut acc_row) in sum.outer_iter_mut().enumerate() {
            let modulus = self.params.moduli()[row];
            let q = Modulus::new(modulus).map_err(Error::MathError)?;
            let acc = acc_row
                .as_slice_mut()
                .ok_or_else(|| Error::DefaultError("non-contiguous row".to_string()))?;
            for item in collected {
                let item_row = item.row(row);
                let share = item_row
                    .as_slice()
                    .ok_or_else(|| Error::DefaultError("non-contiguous row".to_string()))?;
                q.add_vec(acc, share);
            }
        }

        let mut sum_poly = Poly::<PowerBasis>::zero(ctx);
        sum_poly.set_coefficients(sum);
        Ok(sum_poly)
    }

    /// Generate this party's smudging-noise contribution: `degree` uniform
    /// coefficients in `[-2^bits, 2^bits]`.
    ///
    /// The aggregated flooding noise must statistically hide the evaluation
    /// noise of the circuit being decrypted; choose `bits` per that analysis
    /// (see the module-level security caveats).
    pub fn generate_smudging_error<R: RngCore + CryptoRng>(
        &self,
        bits: usize,
        rng: &mut R,
    ) -> Result<Vec<BigInt>> {
        if bits == 0 {
            return Err(Error::DefaultError(
                "smudging bits must be positive".to_string(),
            ));
        }
        let bound = BigInt::from(2u32).pow(bits as u32);
        let mut coeffs = Vec::with_capacity(self.params.degree());
        let low = -&bound;
        let high = &bound + 1;
        let mut adapted = rng08::adapt(rng);
        for _ in 0..self.params.degree() {
            // Uniform in [-bound, bound].
            coeffs.push(adapted.gen_bigint_range(&low, &high));
        }
        Ok(coeffs)
    }

    /// Convert smudging coefficients into a polynomial at level 0.
    pub fn smudging_to_poly(&self, coeffs: &[BigInt]) -> Result<Zeroizing<Poly<PowerBasis>>> {
        let ctx = self.params.context_at_level(0)?;
        Poly::<PowerBasis>::from_bigints(coeffs, ctx).map_err(Error::from)
    }

    /// Convert small signed coefficients (e.g. a CBD secret contribution)
    /// into a polynomial at level 0.
    pub fn coeffs_to_poly(&self, coeffs: &[i64]) -> Result<Zeroizing<Poly<PowerBasis>>> {
        let ctx = self.params.context_at_level(0)?;
        let poly = Poly::<PowerBasis>::try_convert_from(coeffs, ctx, false)?;
        Ok(Zeroizing::new(poly))
    }

    /// Extract party `j`'s (0-based) row from dealt share matrices (the
    /// `[n, degree]`-per-modulus output of
    /// [`TRCKKS::generate_secret_shares_from_poly`]) as a level-0 polynomial.
    ///
    /// Equivalent to [`TRCKKS::aggregate_collected_shares`] with a single
    /// dealer; useful for tests and trusted-dealer setups.
    pub fn share_row_to_poly(
        &self,
        dealt: &[Array2<u64>],
        party_index: usize,
    ) -> Result<Poly<PowerBasis>> {
        let degree = self.params.degree();
        let mut collected = Array2::<u64>::zeros((dealt.len(), degree));
        for (r, m) in dealt.iter().enumerate() {
            if party_index >= m.nrows() {
                return Err(Error::DefaultError("party index out of range".to_string()));
            }
            collected.row_mut(r).assign(&m.row(party_index));
        }
        self.aggregate_collected_shares(&[collected])
    }

    /// Project a level-0 share polynomial to the context at `level`.
    ///
    /// Shamir shares are independent per-modulus sharings of the same
    /// coefficients, so moving a share to a lower level means *dropping* the
    /// trailing RNS rows — NOT divide-and-round modulus switching (which
    /// would destroy the sharing).
    pub fn project_share_to_level(
        &self,
        share: &Poly<PowerBasis>,
        level: usize,
    ) -> Result<Poly<PowerBasis>> {
        let target_ctx = self.params.context_at_level(level)?;
        let keep = target_ctx.moduli().len();
        let coeffs = share.coefficients();
        if coeffs.dim().0 < keep {
            return Err(Error::DefaultError(
                "share has fewer RNS rows than the target level".to_string(),
            ));
        }
        let truncated = coeffs.slice(ndarray::s![..keep, ..]).to_owned();
        let mut out = Poly::<PowerBasis>::zero(target_ctx);
        out.set_coefficients(truncated);
        Ok(out)
    }

    /// Compute this party's decryption share:
    /// `d_j = c0 + c1 * [s]_j + [e_sm]_j`.
    ///
    /// `sk_i` and `es_i` are this party's *aggregated* shares of the joint
    /// secret key and joint smudging noise (outputs of
    /// [`TRCKKS::aggregate_collected_shares`]), at the ciphertext's level.
    /// Three-component (unrelinearized) ciphertexts are rejected.
    ///
    /// # SECURITY: the smudging share is SINGLE-USE per ciphertext
    ///
    /// The dealt `e_sm` is a one-time Shamir sharing of ONE joint flooding
    /// polynomial. Opening two DIFFERENT ciphertexts with the same `e_sm`
    /// lets an observer subtract the two openings: the flooding cancels
    /// exactly, exposing the difference of raw ciphertext noises — the
    /// Li–Micciancio (IND-CPA-D) key-recovery channel this noise exists to
    /// close. `es_i` is taken by value so reuse requires an explicit
    /// `.clone()`; NEVER clone it across ciphertexts. Re-publishing a share
    /// for the SAME ciphertext is safe (deterministic). For multi-opening
    /// protocols, deal one smudging sharing per expected opening during the
    /// DKG.
    pub fn decryption_share(
        &self,
        ciphertext: &CkksCiphertext,
        sk_i: Poly<Ntt>,
        es_i: Poly<PowerBasis>,
    ) -> Result<Poly<PowerBasis>> {
        if ciphertext.len() != 2 {
            return Err(Error::InvalidCiphertext {
                reason: format!(
                    "expected 2 ciphertext components, got {}; relinearize before threshold \
                     decryption",
                    ciphertext.len()
                ),
            });
        }
        let c0 = ciphertext[0].clone().into_power_basis();
        let c1 = ciphertext[1].clone();
        if sk_i.ctx() != c1.ctx() || es_i.ctx() != c0.ctx() {
            return Err(Error::DefaultError(
                "share polynomial context does not match ciphertext context".to_string(),
            ));
        }
        let c1sk = (&c1 * &sk_i).into_power_basis();
        Ok(c0 + c1sk + es_i)
    }

    /// Combine exactly `threshold + 1` decryption shares into the plaintext.
    ///
    /// `reconstructing_parties` holds the 1-based party indices the shares
    /// came from, in the same order. The result is the CKKS plaintext
    /// `delta*m + e + e_sm`; decode it with
    /// [`crate::ckks::CkksEncoder::decode`]. Shares must be at the
    /// ciphertext's level (see [`TRCKKS::project_share_to_level`]).
    pub fn decrypt(
        &self,
        d_share_polys: Vec<Poly<PowerBasis>>,
        reconstructing_parties: Vec<usize>,
        ciphertext: &CkksCiphertext,
    ) -> Result<CkksPlaintext> {
        if d_share_polys.len() != self.threshold + 1 {
            return Err(Error::TooFewValues {
                actual: d_share_polys.len(),
                minimum: self.threshold + 1,
            });
        }
        if reconstructing_parties.len() != d_share_polys.len() {
            return Err(Error::DefaultError(
                "party index count does not match share count".to_string(),
            ));
        }
        let mut seen = vec![false; self.n + 1];
        for &idx in &reconstructing_parties {
            if idx == 0 || idx > self.n {
                return Err(Error::DefaultError(format!(
                    "party index {idx} out of range 1..={}",
                    self.n
                )));
            }
            if seen[idx] {
                return Err(Error::DefaultError(format!("duplicate party index {idx}")));
            }
            seen[idx] = true;
        }

        let ct_ctx = ciphertext[0].ctx();
        let ct_moduli = ct_ctx.moduli();
        let expected_shape = (ct_moduli.len(), self.params.degree());
        for d_share_poly in &d_share_polys {
            if d_share_poly.coefficients().dim() != expected_shape {
                return Err(Error::DefaultError(format!(
                    "decryption share has shape {:?}, expected {expected_shape:?}",
                    d_share_poly.coefficients().dim()
                )));
            }
        }

        let recovered: Result<Vec<Vec<u64>>> = (0..ct_moduli.len())
            .into_par_iter()
            .map(|m| {
                let shamir =
                    ShamirSecretSharing::new(self.threshold, self.n, BigInt::from(ct_moduli[m]));
                (0..self.params.degree())
                    .into_par_iter()
                    .map(|i| -> Result<u64> {
                        let mut points: Vec<(usize, BigInt)> =
                            Vec::with_capacity(self.threshold + 1);
                        for (party_idx, d_share_poly) in
                            reconstructing_parties.iter().zip(d_share_polys.iter())
                        {
                            let coeffs = d_share_poly.coefficients();
                            let coeff = coeffs.row(m)[i];
                            points.push((*party_idx, BigInt::from(coeff)));
                        }
                        let result = shamir
                            .recover(&points)
                            .map_err(|e| Error::DefaultError(e.to_string()))?;
                        result.to_u64().ok_or_else(|| {
                            Error::DefaultError(
                                "recovered Shamir coefficient does not fit in u64".to_string(),
                            )
                        })
                    })
                    .collect()
            })
            .collect();

        let m_data: Vec<u64> = recovered?.into_iter().flatten().collect();
        let arr = Array2::from_shape_vec(expected_shape, m_data)
            .map_err(|_| Error::DefaultError("failed to assemble coefficients".to_string()))?;

        let mut result_poly = Poly::<PowerBasis>::zero(ct_ctx);
        result_poly.set_coefficients(arr);

        Ok(CkksPlaintext {
            par: self.params.clone(),
            poly: result_poly.into_ntt(),
            scale: ciphertext.scale,
            level: ciphertext.level,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckks::{CkksEncoder, CkksParametersBuilder, CkksPublicKey, CkksSecretKey};
    use rand::rng;
    use std::error::Error as StdError;

    /// Tolerance for threshold-decrypted values in these tests.
    ///
    /// Opening error = encryption noise + `sum_j lambda_j * e_sm_j` over the
    /// reconstructing subset, divided by the scale. With 20-bit smudging
    /// and delta = 2^40 that is ~1e-5 even for Lagrange coefficients in the
    /// thousands, so the tolerance is set by the WRONG-VALUE gap instead:
    /// every expected value in these tests differs from any other
    /// plausible outcome (wrong slot, wrong sign, un-summed input) by at
    /// least one whole unit, so 0.5 cannot pass a wrong answer while giving
    /// subset-dependent noise ample headroom.
    const DECRYPT_TOL: f64 = 0.5;

    fn test_params() -> Arc<CkksParameters> {
        CkksParametersBuilder::new()
            .set_degree(512)
            .set_moduli_sizes(&[45, 45])
            .set_scale(2f64.powi(40))
            .build_arc()
            .unwrap()
    }

    #[test]
    fn validation() {
        let params = test_params();
        assert!(TRCKKS::new(0, 1, params.clone()).is_err());
        assert!(TRCKKS::new(3, 2, params.clone()).is_err());
        assert!(TRCKKS::new(3, 0, params.clone()).is_err());
        assert!(TRCKKS::new(5, 2, params.clone()).is_ok());
    }

    /// Full threshold flow with a single-party-style key (the multiparty
    /// keygen variant lives in keygen.rs tests): share a secret key, encrypt,
    /// compute shares, reconstruct.
    #[test]
    fn threshold_decrypt_roundtrip() -> std::result::Result<(), Box<dyn StdError>> {
        let mut rng = rng();
        let params = test_params();
        let n = 5;
        let threshold = 2;
        let trckks = TRCKKS::new(n, threshold, params.clone())?;
        let encoder = CkksEncoder::new(&params);

        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng)?;

        // Deal key shares and (dummy small) smudging shares.
        let sk_poly = trckks.coeffs_to_poly(sk.coeffs.as_ref())?;
        let sk_shares = trckks.generate_secret_shares_from_poly(sk_poly, &mut rng)?;

        let es_coeffs = trckks.generate_smudging_error(20, &mut rng)?;
        let es_poly = trckks.smudging_to_poly(&es_coeffs)?;
        let es_shares = trckks.generate_secret_shares_from_poly(es_poly, &mut rng)?;

        // Each party's aggregated shares (single dealer here, so its share
        // matrix row stack is the aggregate).
        let party_share = |shares: &[Array2<u64>], j: usize| -> Array2<u64> {
            let rows: Vec<_> = shares.iter().map(|m| m.row(j).to_owned()).collect();
            let mut arr = Array2::<u64>::zeros((shares.len(), rows[0].len()));
            for (r, row) in rows.iter().enumerate() {
                arr.row_mut(r).assign(row);
            }
            arr
        };

        // Encrypt and homomorphically add two vectors.
        let a = vec![1.5, -2.25, 10.0];
        let b = vec![0.5, 0.25, -3.0];
        let ct_a = pk.try_encrypt(&encoder.encode(&a, 0)?, &mut rng)?;
        let ct_b = pk.try_encrypt(&encoder.encode(&b, 0)?, &mut rng)?;
        let ct = ct_a.try_add(&ct_b)?;

        // threshold + 1 parties produce decryption shares.
        let parties: Vec<usize> = vec![1, 3, 5];
        let mut d_shares = Vec::new();
        for &j in &parties {
            let sk_j = trckks.aggregate_collected_shares(&[party_share(&sk_shares, j - 1)])?;
            let es_j = trckks.aggregate_collected_shares(&[party_share(&es_shares, j - 1)])?;
            let d_j = trckks.decryption_share(&ct, sk_j.into_ntt(), es_j)?;
            d_shares.push(d_j);
        }

        let pt = trckks.decrypt(d_shares, parties, &ct)?;
        let decoded = encoder.decode(&pt)?;

        for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
            assert!(
                (decoded[i] - (x + y)).abs() < DECRYPT_TOL,
                "slot {i}: {} vs {}",
                decoded[i],
                x + y
            );
        }

        Ok(())
    }

    /// End-to-end with a CALCULATOR-DERIVED flooding bound: the smudging
    /// bits come from [`CkksSmudgingBoundCalculator`] (security floor
    /// `2^lambda * B_C` cleared against both correctness walls), and the
    /// decrypted result must stay within the declared precision target.
    #[test]
    fn threshold_decrypt_with_derived_flooding_bound() -> std::result::Result<(), Box<dyn StdError>>
    {
        let mut rng = rng();
        // Wide chain + large scale so a lambda=30 flood fits under the
        // precision wall. Scale must keep delta*value inside the encoder's
        // i64 coefficients: 2^52 * 100 ~ 2^58.6 < 2^63.
        let params = CkksParametersBuilder::new()
            .set_degree(64)
            .set_moduli_sizes(&[60, 60, 60])
            .set_scale(2f64.powi(52))
            .build_arc()?;
        let n = 5;
        let threshold = 2;
        let precision_loss = 0.01;

        let calc = CkksSmudgingBoundCalculator::new(CkksSmudgingConfig {
            params: params.clone(),
            n_parties: n,
            circuit: CkksCircuitShape::additions(2),
            level: 0,
            input_bound: 100.0,
            precision_loss,
            lambda: crate::trbfv::Lambda::insecure(30),
        });
        let sm_bits = calc.calculate_sm_bits()?;
        assert!(sm_bits > 30, "flooding must include the 2^lambda factor");

        let trckks = TRCKKS::new(n, threshold, params.clone())?;
        let encoder = CkksEncoder::new(&params);
        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng)?;

        let sk_poly = trckks.coeffs_to_poly(sk.coeffs.as_ref())?;
        let sk_shares = trckks.generate_secret_shares_from_poly(sk_poly, &mut rng)?;
        // Smudging noise at the derived bound.
        let es_coeffs = trckks.generate_smudging_error(sm_bits, &mut rng)?;
        let es_poly = trckks.smudging_to_poly(&es_coeffs)?;
        let es_shares = trckks.generate_secret_shares_from_poly(es_poly, &mut rng)?;

        let a = vec![42.5, -17.25];
        let b = vec![7.5, 17.25];
        let ct = pk
            .try_encrypt(&encoder.encode(&a, 0)?, &mut rng)?
            .try_add(&pk.try_encrypt(&encoder.encode(&b, 0)?, &mut rng)?)?;

        let parties: Vec<usize> = vec![1, 2, 4];
        let mut d_shares = Vec::new();
        for &j in &parties {
            let sk_j = trckks.share_row_to_poly(&sk_shares, j - 1)?;
            let es_j = trckks.share_row_to_poly(&es_shares, j - 1)?;
            d_shares.push(trckks.decryption_share(&ct, sk_j.into_ntt(), es_j)?);
        }
        let decoded = encoder.decode(&trckks.decrypt(d_shares, parties, &ct)?)?;

        // Correctness within the declared precision target (plus the
        // scheme's own encoding/encryption noise, far below it here).
        for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
            assert!(
                (decoded[i] - (x + y)).abs() < 2.0 * precision_loss,
                "slot {i}: {} vs {} (precision target {precision_loss})",
                decoded[i],
                x + y
            );
        }
        Ok(())
    }
}
