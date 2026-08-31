//! Create parameters for the BFV encryption scheme

use crate::bfv::{context::CipherPlainContext, context::ContextLevel};
use crate::{Error, ParametersError, Result};
use fhe_math::{
    ntt::NttOperator,
    rns::{RnsContext, ScalingFactor},
    rq::{Context, Poly, PowerBasis, scaler::Scaler, traits::TryConvertFrom},
    zq::{Modulus, primes::generate_prime},
};
use fhe_traits::FheParameters;
use itertools::Itertools;
use num_bigint::{BigInt, BigUint};
use num_traits::{PrimInt as _, ToPrimitive};
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

/// Enum to support both small (u64) and large (BigUint) plaintext moduli.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum PlaintextModulus {
    Small {
        modulus: Modulus,
        modulus_big: BigUint,
    },
    Large(BigUint),
}

impl PlaintextModulus {
    /// Return the plaintext modulus as a `u64` when it is stored in the small
    /// (u64-backed) variant, and `None` for the large (`BigUint`) variant.
    #[cfg(feature = "protobuf")]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Small { modulus, .. } => Some(**modulus),
            Self::Large(_) => None,
        }
    }

    pub fn as_biguint(&self) -> &BigUint {
        match self {
            Self::Small { modulus_big, .. } => modulus_big,
            Self::Large(m) => m,
        }
    }

    pub fn reduce_vec(&self, v: &mut [BigUint]) {
        match self {
            Self::Small { modulus_big, .. } => {
                v.iter_mut().for_each(|vi| *vi %= modulus_big);
            }
            Self::Large(m) => v.iter_mut().for_each(|vi| *vi %= m),
        }
    }

    // Helper to reduce BigUint vector to i64 (centered), returning as Vec<BigUint>
    // or similar? The previous implementation used center_vec_vt returning
    // Vec<i64>. If modulus is large, we can't fit in i64.

    // We need a scalar multiplication for Plaintext::to_poly
    pub fn scalar_mul_vec(&self, a: &mut [BigUint], b: &BigUint) {
        match self {
            Self::Small { modulus_big, .. } => {
                a.iter_mut()
                    .for_each(|ai| *ai = (ai as &BigUint * b) % modulus_big);
            }
            Self::Large(m) => a.iter_mut().for_each(|ai| *ai = (ai as &BigUint * b) % m),
        }
    }

    /// Center a coefficient modulo the plaintext modulus using threshold `(p + 1) / 2`.
    pub fn center_biguint(&self, x: &BigUint, threshold: &BigUint) -> BigInt {
        let modulus = self.as_biguint();
        if x >= threshold {
            BigInt::from(x.clone()) - BigInt::from(modulus.clone())
        } else {
            BigInt::from(x.clone())
        }
    }
}

/// Parameters for the BFV encryption scheme.
///
/// This struct consolidates all parameter-specific data and pre-computed values
/// needed for BFV operations. It contains the raw parameters as well as
/// operational contexts and pre-computed scaling factors.
#[derive(PartialEq, Eq)]
pub struct BfvParameters {
    /// Number of coefficients in a polynomial.
    polynomial_degree: usize,

    /// Vector of coprime moduli q_i for the ciphertext.
    pub(crate) moduli: Box<[u64]>,

    /// Vector of the sized of the coprime moduli q_i for the ciphertext.
    moduli_sizes: Box<[usize]>,

    /// Error variance
    pub(crate) variance: usize,

    /// Error variance for e1 in threshold BFV (supports large values via `BigUint`).
    pub(crate) error1_variance: BigUint,

    /// Head of the context chain for modulus switching
    pub(crate) context_chain: Arc<ContextLevel>,

    /// NTT operator for SIMD plaintext operations, if possible
    pub(crate) ntt_operator: Option<Arc<NttOperator>>,

    /// Plaintext Modulus as a Modulus type or BigUint
    pub(crate) plaintext: PlaintextModulus,

    pub(crate) matrix_reps_index_map: Box<[usize]>,
}

impl Debug for BfvParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BfvParameters")
            .field("polynomial_degree", &self.polynomial_degree)
            .field("plaintext_modulus", &self.plaintext.as_biguint())
            .field("moduli", &self.moduli)
            .finish()
    }
}

impl FheParameters for BfvParameters {}

unsafe impl Send for BfvParameters {}

impl BfvParameters {
    /// Returns the underlying polynomial degree
    #[must_use]
    pub const fn degree(&self) -> usize {
        self.polynomial_degree
    }

    /// Returns a reference to the ciphertext moduli
    #[must_use]
    pub fn moduli(&self) -> &[u64] {
        &self.moduli
    }

    /// Returns a reference to the ciphertext moduli
    #[must_use]
    pub fn moduli_sizes(&self) -> &[usize] {
        &self.moduli_sizes
    }

    /// Returns the plaintext modulus as a `u64`, if it fits.
    ///
    /// This is a checked conversion of the authoritative [`BigUint`] value
    /// ([`Self::plaintext_big`]): it succeeds for every plaintext modulus up
    /// to and including `u64::MAX`, regardless of whether the modulus is
    /// stored in the small u64-NTT representation or the large [`BigUint`]
    /// representation.
    ///
    /// # Errors
    ///
    /// Returns [`ParametersError::PlaintextModulusNotU64`] when the plaintext
    /// modulus exceeds `u64::MAX`. Use [`Self::plaintext_big`] for arbitrary
    /// precision arithmetic or scaling.
    pub fn try_plaintext(&self) -> Result<u64> {
        self.plaintext.as_biguint().to_u64().ok_or_else(|| {
            Error::ParametersError(ParametersError::PlaintextModulusNotU64 {
                plaintext_modulus: self.plaintext.as_biguint().clone(),
            })
        })
    }

    /// Returns the plaintext modulus as [`BigUint`].
    ///
    /// This is the universal accessor: it is representation-independent
    /// (works for both the small u64-NTT representation and the large
    /// [`BigUint`] representation) and supports arbitrary precision
    /// arithmetic, scaling, and bit-length calculations.
    #[must_use]
    pub fn plaintext_big(&self) -> &BigUint {
        self.plaintext.as_biguint()
    }

    /// Returns the variance
    #[must_use]
    pub const fn variance(&self) -> usize {
        self.variance
    }

    /// Get the error1_variance
    #[must_use]
    pub fn get_error1_variance(&self) -> &BigUint {
        &self.error1_variance
    }

    /// Returns the maximum level allowed by these parameters.
    #[must_use]
    pub fn max_level(&self) -> usize {
        self.moduli.len() - 1
    }

    /// Returns the context corresponding to the level.
    /// Returns the context corresponding to the level.
    pub fn context_at_level(&self, level: usize) -> Result<&Arc<Context>> {
        let mut current: &ContextLevel = &self.context_chain;
        while current.level < level {
            current = current
                .next
                .get()
                .ok_or_else(|| Error::InvalidLevel {
                    level,
                    min_level: 0,
                    max_level: self.max_level(),
                })?
                .as_ref();
        }
        if current.level == level {
            Ok(&current.poly_context)
        } else {
            Err(Error::InvalidLevel {
                level,
                min_level: 0,
                max_level: self.max_level(),
            })
        }
    }

    /// Returns the level of a given context
    pub fn level_of_context(&self, ctx: &Arc<Context>) -> Result<usize> {
        self.context_chain
            .poly_context
            .niterations_to(ctx)
            .map_err(Error::MathError)
    }

    /// Return head of context chain
    #[must_use]
    pub fn context_chain(&self) -> Arc<ContextLevel> {
        self.context_chain.clone()
    }

    /// Get context level at a specific depth
    pub fn context_level_at(&self, level: usize) -> Result<Arc<ContextLevel>> {
        let mut current = self.context_chain.clone();
        while current.level < level {
            match current.next.get() {
                Some(n) => current = n.clone(),
                None => {
                    return Err(Error::InvalidLevel {
                        level,
                        min_level: 0,
                        max_level: self.max_level(),
                    });
                }
            }
        }
        Ok(current)
    }

    /// Iterator over default parameters providing about 128 bits of security.
    /// Filters out parameters where the modulus product bitlength is smaller
    /// than the plaintext modulus bitlength.
    ///
    /// Returns an error if no parameters are available after filtering.
    pub fn default_parameters_128(
        plaintext_nbits: usize,
    ) -> Result<impl Iterator<Item = Arc<BfvParameters>>> {
        debug_assert!(plaintext_nbits < 64);

        let mut n_and_qs = HashMap::new();
        n_and_qs.insert(1024, vec![0x7fff801]);
        n_and_qs.insert(2048, vec![0xffffffffff001]);
        n_and_qs.insert(4096, vec![0x3fffe4001, 0x3fffd0001, 0x7ffff6001]);
        n_and_qs.insert(
            8192,
            vec![
                0x1ffffff0001,
                0x1fffffb0001,
                0x1fffff24001,
                0x1ffffed8001,
                0x1ffffed0001,
            ],
        );
        n_and_qs.insert(
            16384,
            vec![
                0x1ffffff18001,
                0x1fffffee8001,
                0x1fffffe58001,
                0x3ffffff70001,
                0x3ffffff58001,
                0x3ffffff28001,
                0x3fffffe50001,
                0x3fffffe08001,
                0x3fffffce8001,
            ],
        );
        n_and_qs.insert(
            32768,
            vec![
                0xffffffff00001,
                0xfffffffe40001,
                0xfffffffe20001,
                0xfffffffbe0001,
                0xfffffffa60001,
                0xfffffff820001,
                0xfffffff750001,
                0xfffffff5d0001,
                0xfffffff480001,
                0xfffffff3f0001,
                0xfffffff390001,
                0x7fffffffe0001,
                0x7ffffffdd0001,
                0x7ffffffd20001,
                0x7ffffffd10001,
                0x7ffffffc60001,
            ],
        );

        let parameters: Vec<Arc<BfvParameters>> = n_and_qs
            .into_iter()
            .sorted_by_key(|(n, _)| *n)
            .filter_map(move |(n, moduli)| {
                generate_prime(
                    plaintext_nbits,
                    2 * n as u64,
                    u64::MAX >> (64 - plaintext_nbits),
                )
                .and_then(|plaintext_modulus| {
                    // Calculate the bitlength of the product of moduli
                    let modulus_product_bitlength = moduli
                        .iter()
                        .map(|&m| 64 - m.leading_zeros() as usize)
                        .sum::<usize>();

                    // Filter out parameters where modulus product bitlength < plaintext bitlength
                    if modulus_product_bitlength >= plaintext_nbits {
                        BfvParametersBuilder::new()
                            .set_degree(n as usize)
                            .set_plaintext_modulus(plaintext_modulus)
                            .set_moduli(&moduli)
                            .build_arc()
                            .ok()
                    } else {
                        None
                    }
                })
            })
            .collect();

        // Check if we have any valid parameters after filtering
        if parameters.is_empty() {
            return Err(Error::ParametersError(
                ParametersError::NoParametersAvailable {
                    reason: format!(
                        "No default parameters available for plaintext modulus of {plaintext_nbits} bits. All parameter sets have modulus product bitlength smaller than the plaintext modulus."
                    ),
                },
            ));
        }

        Ok(parameters.into_iter())
    }

    #[cfg(test)]
    /// Returns default parameters for tests.
    #[must_use]
    #[expect(clippy::panic, reason = "panic indicates violated internal invariant")]
    pub fn default_arc(num_moduli: usize, degree: usize) -> Arc<Self> {
        if !degree.is_power_of_two() || degree < 8 {
            panic!("Invalid degree");
        }
        BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&vec![62usize; num_moduli])
            .build_arc()
            .unwrap()
    }
}

/// Builder for parameters for the Bfv encryption scheme.
#[derive(Debug)]
pub struct BfvParametersBuilder {
    degree: usize,
    plaintext: BigUint,
    variance: usize,
    error1_variance: BigUint,
    // CHANGE 1: Added flag to track if error1_variance was explicitly set
    // This allows error1_variance to automatically follow variance unless
    // the user explicitly sets a different value
    error1_variance_explicitly_set: bool,
    ciphertext_moduli: Vec<u64>,
    ciphertext_moduli_sizes: Vec<usize>,
}

/// Greatest common divisor of two positive u64 values (Euclid's algorithm).
fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

impl BfvParametersBuilder {
    /// Creates a new instance of the builder
    #[expect(
        clippy::new_without_default,
        reason = "builder requires explicit configuration"
    )]
    #[must_use]
    pub fn new() -> Self {
        Self {
            degree: Default::default(),
            plaintext: Default::default(),
            variance: 10,
            error1_variance: BigUint::from(10u32), // Default to same as variance
            // CHANGE 2: Initialize the flag to false
            // Since error1_variance hasn't been explicitly set yet, it will
            // track variance changes
            error1_variance_explicitly_set: false,
            ciphertext_moduli: Default::default(),
            ciphertext_moduli_sizes: Default::default(),
        }
    }

    /// Sets the polynomial degree.
    ///
    /// The degree is validated at [`Self::build`] time: it must be a power of
    /// two in `[8, 65536]`. The upper bound is a resource/API policy and is
    /// enforced before any context allocation (including protobuf-driven
    /// construction).
    pub fn set_degree(&mut self, degree: usize) -> &mut Self {
        self.degree = degree;
        self
    }

    /// Sets the plaintext modulus.
    pub fn set_plaintext_modulus(&mut self, plaintext: u64) -> &mut Self {
        self.plaintext = BigUint::from(plaintext);
        self
    }

    /// Sets the plaintext modulus as BigUint.
    pub fn set_plaintext_modulus_biguint(&mut self, plaintext: BigUint) -> &mut Self {
        self.plaintext = plaintext;
        self
    }

    /// Sets the sizes of the ciphertext moduli.
    /// Only one of `set_moduli_sizes` and `set_moduli`
    /// can be specified.
    pub fn set_moduli_sizes(&mut self, sizes: &[usize]) -> &mut Self {
        sizes.clone_into(&mut self.ciphertext_moduli_sizes);
        self
    }

    /// Sets the ciphertext moduli to use.
    /// Only one of `set_moduli_sizes` and `set_moduli`
    /// can be specified.
    pub fn set_moduli(&mut self, moduli: &[u64]) -> &mut Self {
        moduli.clone_into(&mut self.ciphertext_moduli);
        self
    }

    /// Sets the error variance. Returns an error if the variance is not
    /// between one and sixteen (the domain accepted by `Poly::small` for the
    /// CBD sampler).
    ///
    /// Unless [`Self::set_error1_variance`], [`Self::set_error1_variance_usize`],
    /// or [`Self::set_error1_variance_str`] has been called explicitly, the
    /// error1 variance tracks this value (standard BFV behavior).
    ///
    /// Validation happens before any state is modified, so a rejected value
    /// leaves the builder unchanged and reusable.
    ///
    /// # Errors
    ///
    /// Returns [`ParametersError::InvalidVariance`] when `variance` is outside
    /// `1..=16`.
    pub fn set_variance(&mut self, variance: usize) -> Result<&mut Self> {
        if !(1..=16).contains(&variance) {
            return Err(Error::ParametersError(ParametersError::InvalidVariance {
                variance,
                min: 1,
                max: 16,
            }));
        }
        self.variance = variance;
        // Only update error1_variance if it hasn't been explicitly set
        // This maintains backward compatibility while allowing independent control
        if !self.error1_variance_explicitly_set {
            self.error1_variance = BigUint::from(variance as u32);
        }
        Ok(self)
    }

    /// Sets the error1 variance for threshold BFV using BigUint.
    ///
    /// The error1 variance has no fixed upper bound: values above 16 select
    /// the uniform branch of `Poly::conditional_error` (used by trBFV
    /// smudging); only zero is rejected. Once set explicitly, subsequent
    /// [`Self::set_variance`] calls no longer overwrite this value.
    ///
    /// # Errors
    ///
    /// Returns [`ParametersError::InvalidError1Variance`] when
    /// `error1_variance` is zero.
    pub fn set_error1_variance(&mut self, error1_variance: BigUint) -> Result<&mut Self> {
        if error1_variance == BigUint::from(0u32) {
            return Err(Error::ParametersError(
                ParametersError::InvalidError1Variance {
                    variance: error1_variance,
                    min: 1,
                },
            ));
        }
        self.error1_variance = error1_variance;
        self.error1_variance_explicitly_set = true;
        Ok(self)
    }

    /// Sets the error1 variance for threshold BFV from a usize.
    /// Convenience method for smaller values.
    ///
    /// Also marks the flag as true.
    ///
    /// # Errors
    ///
    /// Returns [`ParametersError::InvalidError1Variance`] when
    /// `error1_variance` is zero.
    pub fn set_error1_variance_usize(&mut self, error1_variance: usize) -> Result<&mut Self> {
        if error1_variance == 0 {
            return Err(Error::ParametersError(
                ParametersError::InvalidError1Variance {
                    variance: BigUint::from(error1_variance),
                    min: 1,
                },
            ));
        }
        self.error1_variance = BigUint::from(error1_variance);
        self.error1_variance_explicitly_set = true;
        Ok(self)
    }

    /// Sets the error1 variance for threshold BFV from a string representation.
    /// Useful for very large numbers that can't fit in standard integer types.
    ///
    /// Also marks the flag as true.
    ///
    /// # Errors
    ///
    /// Returns an error when the string is not a valid [`BigUint`] or when it
    /// represents zero ([`ParametersError::InvalidError1Variance`]).
    pub fn set_error1_variance_str(&mut self, error1_variance: &str) -> Result<&mut Self> {
        let big_uint = error1_variance.parse::<BigUint>().map_err(|_| {
            Error::DefaultError(format!(
                "Invalid BigUint string for error1_variance: {error1_variance}"
            ))
        })?;
        if big_uint == BigUint::from(0u32) {
            return Err(Error::ParametersError(
                ParametersError::InvalidError1Variance {
                    variance: big_uint,
                    min: 1,
                },
            ));
        }
        self.error1_variance = big_uint;
        self.error1_variance_explicitly_set = true;
        Ok(self)
    }

    /// Generate ciphertext moduli with the specified sizes
    fn generate_moduli(moduli_sizes: &[usize], degree: usize) -> Result<Vec<u64>> {
        let mut moduli = vec![];
        let required_counts = moduli_sizes.iter().copied().counts();
        let mut generated_counts: HashMap<usize, usize> = HashMap::new();
        for (i, size) in moduli_sizes.iter().enumerate() {
            if *size > 62 || *size < 10 {
                return Err(Error::ParametersError(
                    ParametersError::InvalidModulusSize {
                        index: i,
                        size: *size,
                        min: 10,
                        max: 62,
                    },
                ));
            }

            let mut upper_bound = 1 << size;
            loop {
                if let Some(prime) = generate_prime(*size, 2 * degree as u64, upper_bound) {
                    if !moduli.contains(&prime) {
                        moduli.push(prime);
                        *generated_counts.entry(*size).or_insert(0) += 1;
                        break;
                    } else {
                        upper_bound = prime;
                    }
                } else {
                    let needed = *required_counts.get(size).unwrap_or(&0);
                    let available = *generated_counts.get(size).unwrap_or(&0);
                    return Err(Error::ParametersError(ParametersError::NotEnoughPrimes {
                        size: *size,
                        degree,
                        needed,
                        available,
                    }));
                }
            }
        }

        Ok(moduli)
    }

    /// Validate the ciphertext moduli used by a context.
    ///
    /// Each modulus must be a valid u64 modulus (`Modulus::new`), the list
    /// must be duplicate-free and pairwise coprime, and every modulus must
    /// support the NTT of `degree`. Structural checks (distinctness,
    /// coprimality) run before the NTT-operator construction so that
    /// non-coprime pairs are reported as such even when a member is not
    /// NTT-friendly.
    fn validate_ciphertext_moduli(moduli: &[u64], degree: usize) -> Result<()> {
        for (index, modulus) in moduli.iter().enumerate() {
            Modulus::new(*modulus).map_err(|e| {
                Error::ParametersError(ParametersError::InvalidCiphertextModulus {
                    index,
                    modulus: *modulus,
                    reason: e.to_string(),
                })
            })?;
        }

        for (index, modulus) in moduli.iter().enumerate() {
            if let Some(first) = moduli.iter().position(|m| m == modulus)
                && first != index
            {
                return Err(Error::ParametersError(ParametersError::DuplicateModuli {
                    modulus: *modulus,
                    indices: vec![first, index],
                }));
            }
        }

        for (i, modulus1) in moduli.iter().enumerate() {
            for modulus2 in moduli.iter().skip(i + 1) {
                let gcd = gcd_u64(*modulus1, *modulus2);
                if gcd > 1 {
                    return Err(Error::ParametersError(ParametersError::ModuliNotCoprime {
                        modulus1: *modulus1,
                        modulus2: *modulus2,
                        gcd,
                    }));
                }
            }
        }

        for (index, modulus) in moduli.iter().enumerate() {
            let q = Modulus::new(*modulus).map_err(|e| {
                Error::ParametersError(ParametersError::InvalidCiphertextModulus {
                    index,
                    modulus: *modulus,
                    reason: e.to_string(),
                })
            })?;
            if NttOperator::new(&q, degree).is_none() {
                return Err(Error::ParametersError(
                    ParametersError::CiphertextModulusNotNttFriendly {
                        index,
                        modulus: *modulus,
                        degree,
                    },
                ));
            }
        }

        Ok(())
    }

    /// Build a new `BfvParameters` inside an `Arc`.
    pub fn build_arc(&self) -> Result<Arc<BfvParameters>> {
        self.build().map(Arc::new)
    }

    /// Build a new `BfvParameters`.
    ///
    /// Repeats the full validation of every setter (degree, variance, error1
    /// variance, plaintext modulus, and ciphertext moduli) so that builder
    /// reuse, deserialization, and internal construction can never produce
    /// parameters carrying values rejected by the arithmetic layer.
    ///
    /// # Errors
    ///
    /// Returns a [`ParametersError`] when the degree is not a power of two in
    /// `[8, 65536]`, the variance is outside `1..=16`, the error1 variance is
    /// zero, the plaintext modulus is zero, or the ciphertext moduli are
    /// empty, invalid for the NTT context, duplicated, or not pairwise
    /// coprime.
    pub fn build(&self) -> Result<BfvParameters> {
        // Check that the degree is a power of 2 in [8, 65536]. The upper
        // bound is a resource/API policy and is enforced before any context
        // allocation (including protobuf-driven construction).
        if self.degree < 8 || self.degree > 65536 || !self.degree.is_power_of_two() {
            return Err(Error::ParametersError(
                ParametersError::invalid_degree_with_bounds(self.degree),
            ));
        }

        // Standard BFV error is sampled with the CBD sampler (`Poly::small`),
        // which accepts exactly 1..=16.
        if !(1..=16).contains(&self.variance) {
            return Err(Error::ParametersError(ParametersError::InvalidVariance {
                variance: self.variance,
                min: 1,
                max: 16,
            }));
        }

        // The threshold-BFV error1 variance has no fixed upper bound (values
        // above 16 select the uniform branch of `Poly::conditional_error`);
        // only zero is rejected.
        if self.error1_variance == BigUint::from(0u32) {
            return Err(Error::ParametersError(
                ParametersError::InvalidError1Variance {
                    variance: self.error1_variance.clone(),
                    min: 1,
                },
            ));
        }

        // The plaintext modulus must be positive.
        if self.plaintext == BigUint::from(0u32) {
            return Err(Error::ParametersError(
                ParametersError::InvalidPlaintextModulus {
                    modulus: 0,
                    reason: "plaintext modulus must be positive".into(),
                },
            ));
        }

        let plaintext_modulus_struct = if let Some(p) = self.plaintext.to_u64() {
            match Modulus::new(p) {
                Ok(modulus) => PlaintextModulus::Small {
                    modulus,
                    modulus_big: BigUint::from(p),
                },
                // Values that fit in u64 but cannot construct the u64 modulus
                // (>= 2^62) use the BigUint plaintext path.
                Err(_) => PlaintextModulus::Large(self.plaintext.clone()),
            }
        } else {
            PlaintextModulus::Large(self.plaintext.clone())
        };
        let plaintext_big = plaintext_modulus_struct.as_biguint();

        // Check that one of `ciphertext_moduli` and `ciphertext_moduli_sizes` is
        // specified.
        if !self.ciphertext_moduli.is_empty() && !self.ciphertext_moduli_sizes.is_empty() {
            return Err(Error::ParametersError(ParametersError::ConflictingParameters {
                conflict: "Only one of `ciphertext_moduli` and `ciphertext_moduli_sizes` can be specified".into(),
            }));
        } else if self.ciphertext_moduli.is_empty() && self.ciphertext_moduli_sizes.is_empty() {
            return Err(Error::ParametersError(ParametersError::MissingParameter {
                parameter: "ciphertext_moduli or ciphertext_moduli_sizes".into(),
            }));
        }

        // Get or generate the moduli
        let mut moduli = self.ciphertext_moduli.clone();
        if !self.ciphertext_moduli_sizes.is_empty() {
            moduli = Self::generate_moduli(&self.ciphertext_moduli_sizes, self.degree)?
        }

        // Validate the ciphertext moduli before any context allocation: each
        // must be a valid u64 modulus, distinct, pairwise coprime, and
        // NTT-friendly for the degree. `fhe-math` remains the arithmetic
        // authority; this pass maps its checks to typed `ParametersError`
        // variants so callers can react to the specific failure.
        Self::validate_ciphertext_moduli(&moduli, self.degree)?;

        // Recomputes the moduli sizes
        let moduli_sizes = moduli
            .iter()
            .map(|m| 64 - m.leading_zeros() as usize)
            .collect_vec();

        // Determine how many moduli needed for plaintext context
        // We need product of moduli > plaintext modulus.
        let t_bits = plaintext_big.bits();
        let mut accumulated_bits = 0;
        let mut plaintext_moduli_count = 0;
        for size in &moduli_sizes {
            accumulated_bits += size;
            plaintext_moduli_count += 1;
            if accumulated_bits as u64 >= t_bits + 60 {
                break;
            }
        }
        plaintext_moduli_count = std::cmp::max(plaintext_moduli_count, 1);
        plaintext_moduli_count = std::cmp::min(plaintext_moduli_count, moduli.len());

        // Create plaintext context using sufficient moduli
        let plaintext_context = Context::new_arc(&moduli[..plaintext_moduli_count], self.degree)?;

        // Create NTT operator for SIMD operations if possible
        // Only if plaintext modulus fits in u64 for now
        let ntt_operator = match &plaintext_modulus_struct {
            PlaintextModulus::Small { modulus, .. } => {
                NttOperator::new(modulus, self.degree).map(Arc::new)
            }
            PlaintextModulus::Large(_) => None,
        };

        // Create cipher-plain bridge contexts
        let mut cipher_plain_contexts = Vec::with_capacity(moduli.len());

        // Build contexts in reverse order to establish the chain
        for i in (0..moduli.len()).rev() {
            let level_moduli = &moduli[..moduli.len() - i];
            let cipher_ctx = Context::new_arc(level_moduli, self.degree)?;
            // Compute delta (scaling polynomial)
            let mut delta_rests = vec![];
            for m in level_moduli {
                let q = Modulus::new(*m)?;
                let t_mod_q = (plaintext_big % *m).to_u64().unwrap();
                let neg_t_mod_q = q.neg(t_mod_q);
                if let Some(inv) = q.inv(neg_t_mod_q) {
                    delta_rests.push(inv);
                } else {
                    Err(Error::MathError(fhe_math::Error::Default(
                        "Inverse failed".to_string(),
                    )))?;
                }
            }

            // Use RnsContext to lift the delta values and create the scaling polynomial
            let rns = RnsContext::new(level_moduli)?;
            let delta_value = rns.lift((&delta_rests).into())?;
            let delta = Poly::<PowerBasis>::try_convert_from(&[delta_value], &cipher_ctx, true)?
                .into_ntt_shoup()?;

            // Compute q_mod_t
            let q_mod_t = rns.modulus() % plaintext_big;

            // Compute plain_threshold
            let plain_threshold = match &plaintext_modulus_struct {
                PlaintextModulus::Small { modulus, .. } => BigUint::from((**modulus + 1) >> 1),
                PlaintextModulus::Large(m) => (m + 1u32) >> 1,
            };

            // Scaler from ciphertext to plaintext context
            let scaler = Scaler::new(
                &cipher_ctx,
                &plaintext_context,
                ScalingFactor::new(plaintext_big, rns.modulus())?,
            )?;

            let cipher_plain_ctx = CipherPlainContext::new_arc(
                &plaintext_context,
                &cipher_ctx,
                delta,
                q_mod_t,
                plain_threshold,
                scaler,
            );

            cipher_plain_contexts.push(cipher_plain_ctx.clone());
        }

        // Reverse to get correct order (level 0 first)
        cipher_plain_contexts.reverse();

        // Build linked context chain
        let nodes: Vec<Arc<ContextLevel>> = cipher_plain_contexts
            .iter()
            .enumerate()
            .map(|(lvl, cp_ctx)| {
                Arc::new(ContextLevel::new(
                    cp_ctx.ciphertext_context.clone(),
                    cp_ctx.clone(),
                    lvl,
                ))
            })
            .collect();
        for i in 0..nodes.len() - 1 {
            let (prev, rest) = nodes.split_at(i + 1);
            ContextLevel::chain(&prev[i], &rest[0]);
        }
        let context_chain = nodes.first().unwrap().clone();

        // Create n+1 moduli of 62 bits for multiplication.
        let mut extended_basis = Vec::with_capacity(moduli.len() + 1);
        let mut upper_bound = 1 << 62;
        while extended_basis.len() != moduli.len() + 1 {
            let Some(prime) = generate_prime(62, 2 * self.degree as u64, upper_bound) else {
                return Err(Error::ParametersError(ParametersError::NotEnoughPrimes {
                    size: 62,
                    degree: self.degree,
                    needed: moduli.len() + 1,
                    available: extended_basis.len(),
                }));
            };
            upper_bound = prime;
            if !extended_basis.contains(&upper_bound) && !moduli.contains(&upper_bound) {
                extended_basis.push(upper_bound)
            }
        }

        // Compute multiplication parameters for each level
        for (i, node) in nodes.iter().enumerate() {
            // For the first multiplication, we want to extend to a context that
            // is ~60 bits larger.
            let modulus_size = moduli_sizes[..moduli_sizes.len() - i].iter().sum::<usize>();
            let n_moduli = (modulus_size + 60).div_ceil(62);
            let mut mul_1_moduli = vec![];
            mul_1_moduli.append(&mut moduli[..moduli_sizes.len() - i].to_vec());
            mul_1_moduli.append(&mut extended_basis[..n_moduli].to_vec());
            let mul_1_ctx = Context::new_arc(&mul_1_moduli, self.degree)?;
            let mp = MultiplicationParameters::new(
                &node.poly_context,
                &mul_1_ctx,
                ScalingFactor::one(),
                ScalingFactor::new(plaintext_big, node.poly_context.modulus())?,
            )?;
            node.mul_params.set(mp).unwrap();
        }

        // We use the same code as SEAL
        // https://github.com/microsoft/SEAL/blob/82b07db635132e297282649e2ab5908999089ad2/native/src/seal/batchencoder.cpp
        let row_size = self.degree >> 1;
        let m = self.degree << 1;
        let generator = 3;
        let mut pos = 1;
        let mut matrix_reps_index_map = vec![0usize; self.degree];
        for i in 0..row_size {
            let index1 = (pos - 1) >> 1;
            let index2 = (m - pos - 1) >> 1;
            matrix_reps_index_map[i] = index1.reverse_bits() >> (self.degree.leading_zeros() + 1);
            matrix_reps_index_map[row_size | i] =
                index2.reverse_bits() >> (self.degree.leading_zeros() + 1);
            pos *= generator;
            pos &= m - 1;
        }

        Ok(BfvParameters {
            polynomial_degree: self.degree,
            moduli: moduli.into(),
            moduli_sizes: moduli_sizes.into(),
            variance: self.variance,
            error1_variance: self.error1_variance.clone(),
            context_chain,
            ntt_operator,
            plaintext: plaintext_modulus_struct,
            matrix_reps_index_map: matrix_reps_index_map.into(),
        })
    }
}

#[cfg(feature = "protobuf")]
mod protobuf {
    use super::*;
    use crate::SerializationError;
    use crate::proto::bfv::{Parameters, parameters::PlaintextModulus as PlaintextModulusProto};
    use fhe_traits::{Deserialize, Serialize};
    use prost::Message;

    impl Serialize for BfvParameters {
        fn to_bytes(&self) -> Vec<u8> {
            let plaintext_modulus = if let Some(plaintext_u64) = self.plaintext.as_u64() {
                Some(PlaintextModulusProto::Plaintext(plaintext_u64))
            } else {
                Some(PlaintextModulusProto::PlaintextBig(
                    self.plaintext.as_biguint().to_bytes_le(),
                ))
            };

            Parameters {
                degree: self.polynomial_degree as u32,
                moduli: self.moduli.to_vec(),
                variance: self.variance as u32,
                plaintext_modulus,
            }
            .encode_to_vec()
        }
    }

    impl Deserialize for BfvParameters {
        fn try_deserialize(bytes: &[u8]) -> Result<Self> {
            let params: Parameters = Message::decode(bytes).map_err(|_| {
                Error::SerializationError(SerializationError::ProtobufError {
                    message: "Parameters decode".into(),
                })
            })?;

            let plaintext_modulus = match params.plaintext_modulus {
                Some(PlaintextModulusProto::Plaintext(value)) => BigUint::from(value),
                Some(PlaintextModulusProto::PlaintextBig(bytes)) => BigUint::from_bytes_le(&bytes),
                None => {
                    return Err(Error::SerializationError(
                        SerializationError::MissingField {
                            field_name: "Parameters.plaintext_modulus".into(),
                        },
                    ));
                }
            };

            BfvParametersBuilder::new()
                .set_degree(params.degree as usize)
                .set_plaintext_modulus_biguint(plaintext_modulus)
                .set_moduli(&params.moduli)
                .set_variance(params.variance as usize)?
                .build()
        }
        type Error = Error;
    }
}

/// Multiplication parameters
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MultiplicationParameters {
    pub(crate) extender: Scaler,
    pub(crate) down_scaler: Scaler,
    pub(crate) from: Arc<Context>,
    pub(crate) to: Arc<Context>,
}

impl MultiplicationParameters {
    fn new(
        from: &Arc<Context>,
        to: &Arc<Context>,
        up_self_factor: ScalingFactor,
        down_factor: ScalingFactor,
    ) -> Result<Self> {
        Ok(Self {
            extender: Scaler::new(from, to, up_self_factor)?,
            down_scaler: Scaler::new(to, from, down_factor)?,
            from: from.clone(),
            to: to.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{BfvParameters, BfvParametersBuilder};
    use crate::{Error as FheError, ParametersError};
    use num_bigint::BigUint;
    use std::error::Error;

    #[test]
    fn default() {
        let params = BfvParameters::default_arc(1, 16);
        assert_eq!(params.moduli.len(), 1);
        assert_eq!(params.degree(), 16);

        let params = BfvParameters::default_arc(2, 16);
        assert_eq!(params.moduli.len(), 2);
        assert_eq!(params.degree(), 16);
    }

    #[test]
    fn ciphertext_moduli() -> Result<(), Box<dyn Error>> {
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(2)
            .set_moduli_sizes(&[62, 62, 62, 61, 60, 11])
            .build()?;
        assert_eq!(
            params.moduli.to_vec(),
            &[
                4611686018427387617,
                4611686018427387329,
                4611686018427387073,
                2305843009213693921,
                1152921504606845473,
                2017
            ]
        );

        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(2)
            .set_moduli(&[
                4611686018427387617,
                4611686018427387329,
                4611686018427387073,
                2305843009213693921,
                1152921504606845473,
                2017,
            ])
            .build()?;
        assert_eq!(params.moduli_sizes.to_vec(), &[62, 62, 62, 61, 60, 11]);

        Ok(())
    }

    #[test]
    fn big_plaintext_modulus() -> Result<(), Box<dyn Error>> {
        let p = BigUint::parse_bytes(b"340282366920938463463374607431768211507", 10).unwrap();
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus_biguint(p.clone())
            .set_moduli_sizes(&[62, 62, 62, 62, 62])
            .build()?;

        assert_eq!(params.plaintext_big(), &p);
        Ok(())
    }

    #[cfg(feature = "protobuf")]
    mod protobuf {
        use super::*;
        use crate::proto::bfv::{
            Parameters, parameters::PlaintextModulus as PlaintextModulusProto,
        };
        use fhe_traits::{Deserialize, Serialize};
        use prost::Message;

        #[test]
        fn serialize() -> Result<(), Box<dyn std::error::Error>> {
            let params = BfvParametersBuilder::new()
                .set_degree(16)
                .set_plaintext_modulus(2)
                .set_moduli_sizes(&[62, 62, 62, 61, 60, 11])
                .set_variance(4)?
                .build()?;
            let bytes = params.to_bytes();
            let proto = Parameters::decode(bytes.as_slice())?;
            assert!(matches!(
                proto.plaintext_modulus,
                Some(PlaintextModulusProto::Plaintext(2))
            ));
            assert_eq!(BfvParameters::try_deserialize(&bytes)?, params);

            let p = BigUint::parse_bytes(b"340282366920938463463374607431768211507", 10).unwrap();
            let params = BfvParametersBuilder::new()
                .set_degree(16)
                .set_plaintext_modulus_biguint(p)
                .set_moduli_sizes(&[62, 62, 62, 62, 62])
                .set_variance(4)?
                .build()?;
            let bytes = params.to_bytes();
            let proto = Parameters::decode(bytes.as_slice())?;
            let proto_plaintext_bytes = match &proto.plaintext_modulus {
                Some(PlaintextModulusProto::PlaintextBig(bytes)) => bytes.as_slice(),
                _ => return Err("expected plaintext_big variant".into()),
            };
            assert_eq!(
                proto_plaintext_bytes,
                params.plaintext_big().to_bytes_le().as_slice()
            );
            let decoded = BfvParameters::try_deserialize(&bytes)?;
            assert_eq!(decoded, params);
            assert_eq!(decoded.plaintext_big(), params.plaintext_big());

            Ok(())
        }

        #[test]
        fn deserialize_missing_plaintext_modulus() {
            let proto = Parameters {
                degree: 16,
                moduli: vec![4611686018427387617, 4611686018427387329],
                variance: 4,
                plaintext_modulus: None,
            };
            let bytes = proto.encode_to_vec();
            let err = BfvParameters::try_deserialize(&bytes).unwrap_err();
            assert!(format!("{err}").contains("Missing required field"));
        }

        #[test]
        fn deserialize_rejects_invalid_variance() {
            let proto = Parameters {
                degree: 16,
                moduli: vec![4611686018427387617, 4611686018427387329],
                variance: 0,
                plaintext_modulus: Some(PlaintextModulusProto::Plaintext(1153)),
            };
            let bytes = proto.encode_to_vec();
            let err = BfvParameters::try_deserialize(&bytes).unwrap_err();
            assert!(matches!(
                err,
                FheError::ParametersError(ParametersError::InvalidVariance { variance: 0, .. })
            ));
        }

        #[test]
        fn deserialize_rejects_oversized_degree_before_allocation() {
            let proto = Parameters {
                degree: u32::MAX,
                moduli: vec![4611686018427387617],
                variance: 4,
                plaintext_modulus: Some(PlaintextModulusProto::Plaintext(1153)),
            };
            let bytes = proto.encode_to_vec();
            let err = BfvParameters::try_deserialize(&bytes).unwrap_err();
            assert!(matches!(
                err,
                FheError::ParametersError(ParametersError::InvalidDegree {
                    degree: 4_294_967_295,
                    ..
                })
            ));
        }
    }

    #[test]
    fn matrix_reps_index_map_is_permutation() -> Result<(), Box<dyn Error>> {
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(2)
            .set_moduli_sizes(&[62, 62])
            .build()?;

        let mut map = params.matrix_reps_index_map.to_vec();
        assert_eq!(map.len(), params.degree());

        map.sort_unstable();
        map.dedup();
        assert_eq!(map.len(), params.degree());

        Ok(())
    }

    #[test]
    fn error1_variance_functionality() -> Result<(), Box<dyn Error>> {
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(10)?
            .build()?;
        assert_eq!(params.get_error1_variance(), &BigUint::from(10u32));

        let error1_big = BigUint::from(20u32);
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(10)?
            .set_error1_variance(error1_big.clone())?
            .build()?;
        assert_eq!(params.get_error1_variance(), &error1_big);
        assert_eq!(params.variance(), 10);

        let large_error1 = BigUint::parse_bytes(
            b"57896044618658097711785492504343953926634992332820282019728792003956564819967",
            10,
        )
        .unwrap();
        let params_with_large_error1 = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(10)?
            .set_error1_variance(large_error1.clone())?
            .build()?;
        assert_eq!(
            params_with_large_error1.get_error1_variance(),
            &large_error1
        );

        let params_usize = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(10)?
            .set_error1_variance_usize(15)?
            .build()?;
        assert_eq!(params_usize.get_error1_variance(), &BigUint::from(15u32));

        let mut builder = BfvParametersBuilder::new();
        builder
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(10)?
            .set_error1_variance_str(
                "123456789012345678901234567890123456789012345678901234567890",
            )?;
        let params_str = builder.build()?;

        let expected = BigUint::parse_bytes(
            b"123456789012345678901234567890123456789012345678901234567890",
            10,
        )
        .unwrap();
        assert_eq!(params_str.get_error1_variance(), &expected);

        Ok(())
    }

    #[test]
    fn test_155_bit_error1_variance() -> Result<(), Box<dyn Error>> {
        let bit_155_number = BigUint::from(2u32).pow(155) - BigUint::from(1u32);

        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(10)?
            .set_error1_variance(bit_155_number.clone())?
            .build()?;

        assert_eq!(params.get_error1_variance(), &bit_155_number);

        Ok(())
    }

    #[test]
    fn test_error1_variance_tracks_variance() -> Result<(), Box<dyn Error>> {
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(15)?
            .build()?;

        assert_eq!(params.variance(), 15);
        assert_eq!(params.get_error1_variance(), &BigUint::from(15u32));

        Ok(())
    }

    #[test]
    fn test_error1_variance_independent_when_set() -> Result<(), Box<dyn Error>> {
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_error1_variance_usize(20)?
            .set_variance(15)?
            .build()?;

        assert_eq!(params.variance(), 15);
        assert_eq!(params.get_error1_variance(), &BigUint::from(20u32));

        let params2 = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(15)?
            .set_error1_variance_usize(20)?
            .build()?;

        assert_eq!(params2.variance(), 15);
        assert_eq!(params2.get_error1_variance(), &BigUint::from(20u32));

        Ok(())
    }

    #[test]
    fn test_error1_variance_follows_multiple_variance_changes() -> Result<(), Box<dyn Error>> {
        let mut builder = BfvParametersBuilder::new();
        builder
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(5)?
            .set_variance(10)?
            .set_variance(15)?;

        let params = builder.build()?;

        assert_eq!(params.variance(), 15);
        assert_eq!(params.get_error1_variance(), &BigUint::from(15u32));

        Ok(())
    }

    #[test]
    fn set_variance_rejects_invalid_and_reuse_works() -> Result<(), Box<dyn Error>> {
        let mut builder = BfvParametersBuilder::new();
        // 0 and 17 are outside the CBD domain 1..=16.
        assert!(matches!(
            builder.set_variance(0),
            Err(FheError::ParametersError(
                ParametersError::InvalidVariance {
                    variance: 0,
                    min: 1,
                    max: 16
                }
            ))
        ));
        assert!(matches!(
            builder.set_variance(17),
            Err(FheError::ParametersError(
                ParametersError::InvalidVariance { variance: 17, .. }
            ))
        ));
        // Endpoints are accepted.
        builder.set_variance(1)?;
        builder.set_variance(16)?;
        // A rejected value leaves the builder unchanged and reusable.
        assert!(builder.set_variance(0).is_err());
        let params = builder
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .build()?;
        assert_eq!(params.variance(), 16);
        assert_eq!(params.get_error1_variance(), &BigUint::from(16u32));
        Ok(())
    }

    #[test]
    fn error1_variance_rejects_zero_through_every_setter() -> Result<(), Box<dyn Error>> {
        let mut builder = BfvParametersBuilder::new();
        assert!(matches!(
            builder.set_error1_variance(BigUint::from(0u32)),
            Err(FheError::ParametersError(ParametersError::InvalidError1Variance {
                variance: ref v,
                min: 1
            })) if *v == BigUint::from(0u32)
        ));
        assert!(matches!(
            builder.set_error1_variance_usize(0),
            Err(FheError::ParametersError(ParametersError::InvalidError1Variance {
                variance: ref v,
                min: 1
            })) if *v == BigUint::from(0u32)
        ));
        assert!(matches!(
            builder.set_error1_variance_str("0"),
            Err(FheError::ParametersError(ParametersError::InvalidError1Variance {
                variance: ref v,
                min: 1
            })) if *v == BigUint::from(0u32)
        ));
        // A rejected setter must not mark the error1 variance as explicitly
        // set, so the builder remains reusable with the default variance.
        builder.set_degree(8);
        let params = builder
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .build()?;
        assert_eq!(params.get_error1_variance(), &BigUint::from(10u32));
        Ok(())
    }

    #[test]
    fn error1_variance_accepts_16_17_and_large() -> Result<(), Box<dyn Error>> {
        for variance in [16usize, 17, 1000] {
            let params = BfvParametersBuilder::new()
                .set_degree(8)
                .set_plaintext_modulus(1153)
                .set_moduli_sizes(&[62])
                .set_variance(10)?
                .set_error1_variance_usize(variance)?
                .build()?;
            assert_eq!(params.get_error1_variance(), &BigUint::from(variance));
        }
        Ok(())
    }

    #[test]
    fn build_rejects_invalid_degrees() {
        for degree in [0usize, 7, 12, 131072] {
            let err = BfvParametersBuilder::new()
                .set_degree(degree)
                .set_plaintext_modulus(1153)
                .set_moduli_sizes(&[62])
                .build()
                .unwrap_err();
            assert!(matches!(
                err,
                FheError::ParametersError(ParametersError::InvalidDegree {
                    degree: d,
                    min: 8,
                    max: 65536
                }) if d == degree
            ));
        }
    }

    #[test]
    fn build_rejects_invalid_variance_state() {
        // Install invalid state directly (as internal construction or a
        // non-setter path could): `build` repeats the full validation and
        // must reject it.
        let mut builder = BfvParametersBuilder::new();
        builder.variance = 17;
        let err = builder
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            FheError::ParametersError(ParametersError::InvalidVariance { variance: 17, .. })
        ));

        let mut builder = BfvParametersBuilder::new();
        builder.error1_variance = BigUint::from(0u32);
        let err = builder
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            FheError::ParametersError(ParametersError::InvalidError1Variance {
                variance: ref v,
                min: 1
            }) if *v == BigUint::from(0u32)
        ));
    }

    #[test]
    fn build_accepts_degree_endpoints() -> Result<(), Box<dyn Error>> {
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .build()?;
        assert_eq!(params.degree(), 8);

        let params = BfvParametersBuilder::new()
            .set_degree(65536)
            .set_plaintext_modulus(2)
            .set_moduli_sizes(&[62])
            .build()?;
        assert_eq!(params.degree(), 65536);
        Ok(())
    }

    #[test]
    fn build_rejects_zero_plaintext() {
        let err = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(0)
            .set_moduli_sizes(&[62])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            FheError::ParametersError(ParametersError::InvalidPlaintextModulus { modulus: 0, .. })
        ));

        let err = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus_biguint(BigUint::from(0u32))
            .set_moduli_sizes(&[62])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            FheError::ParametersError(ParametersError::InvalidPlaintextModulus { modulus: 0, .. })
        ));
    }

    #[test]
    fn build_rejects_invalid_ciphertext_moduli() {
        // No modulus source specified.
        let err = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            FheError::ParametersError(ParametersError::MissingParameter { .. })
        ));

        // Both modulus sources specified.
        let err = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli(&[65537])
            .set_moduli_sizes(&[62])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            FheError::ParametersError(ParametersError::ConflictingParameters { .. })
        ));

        // A modulus that cannot construct a `Modulus`.
        let err = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli(&[1])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            FheError::ParametersError(ParametersError::InvalidCiphertextModulus {
                index: 0,
                modulus: 1,
                ..
            })
        ));

        // A modulus that is not NTT-friendly for the degree.
        let err = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli(&[2])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            FheError::ParametersError(ParametersError::CiphertextModulusNotNttFriendly {
                index: 0,
                modulus: 2,
                degree: 8
            })
        ));

        // Duplicate moduli.
        let err = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli(&[65537, 65537])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            FheError::ParametersError(ParametersError::DuplicateModuli { modulus: 65537, .. })
        ));

        // Moduli that are not pairwise coprime.
        let err = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli(&[6, 10])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            FheError::ParametersError(ParametersError::ModuliNotCoprime {
                modulus1: 6,
                modulus2: 10,
                gcd: 2
            })
        ));
    }

    #[test]
    fn try_plaintext_boundaries() -> Result<(), Box<dyn Error>> {
        // Small plaintext modulus (u64 NTT path).
        let params = BfvParameters::default_arc(1, 8);
        assert_eq!(params.try_plaintext()?, 1153);
        assert_eq!(params.plaintext_big(), &BigUint::from(1153u32));

        // Exact u64::MAX is accepted by `try_plaintext` even though it cannot
        // construct the u64 NTT modulus (it is classified as Large).
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus_biguint(BigUint::from(u64::MAX))
            .set_moduli(&[4611686018427387617, 4611686018427387329])
            .build()?;
        assert_eq!(params.try_plaintext()?, u64::MAX);
        assert_eq!(params.plaintext_big(), &BigUint::from(u64::MAX));

        // Above u64::MAX, `try_plaintext` returns a typed error while
        // `plaintext_big` round-trips the value.
        let p = BigUint::parse_bytes(b"340282366920938463463374607431768211507", 10).unwrap();
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus_biguint(p.clone())
            .set_moduli_sizes(&[62, 62, 62, 62, 62])
            .build()?;
        assert_eq!(params.plaintext_big(), &p);
        let err = params.try_plaintext().unwrap_err();
        assert!(matches!(
            err,
            FheError::ParametersError(ParametersError::PlaintextModulusNotU64 {
                plaintext_modulus: ref m
            }) if *m == p
        ));
        Ok(())
    }

    #[test]
    fn default_parameters_iterator() {
        let mut it = BfvParameters::default_parameters_128(20).unwrap();
        assert!(it.next().is_some());
    }

    #[test]
    fn default_parameters_filtering() {
        let params: Vec<_> = BfvParameters::default_parameters_128(20).unwrap().collect();

        for param in &params {
            let modulus_product_bitlength = param.moduli_sizes.iter().sum::<usize>();
            assert!(modulus_product_bitlength >= 20);
        }

        let result = BfvParameters::default_parameters_128(10);
        assert!(result.is_err());

        #[expect(clippy::panic, reason = "panic indicates violated internal invariant")]
        match result {
            Err(e) => {
                let error_string = format!("{e}");
                assert!(error_string.contains("No parameters available"));
                assert!(error_string.contains("10 bits"));
            }
            Ok(_) => panic!("Expected error"),
        }
    }
}
