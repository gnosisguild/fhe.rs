//! Create parameters for the BFV encryption scheme

use crate::proto::bfv::Parameters;
use crate::{Error, ParametersError, Result};
use fhe_math::{
    ntt::{NttOperator, NttOperatorRaw},
    rns::{RnsContext, RnsContextRaw, ScalingFactor},
    rq::{
        scaler::{Scaler, ScalerRaw},
        traits::TryConvertFrom,
        Context, Poly, PolyRaw, Representation,
    },
    zq::{primes::generate_prime, Modulus},
};
use fhe_traits::{Deserialize, FheParameters, Serialize};
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use prost::Message;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

/// Parameters for the BFV encryption scheme.
#[derive(PartialEq, Eq)]
pub struct BfvParameters {
    /// Number of coefficients in a polynomial.
    polynomial_degree: usize,

    /// Modulus of the plaintext.
    plaintext_modulus: u64,

    /// Vector of coprime moduli q_i for the ciphertext.
    /// One and only one of `ciphertext_moduli` or `ciphertext_moduli_sizes`
    /// must be specified.
    pub(crate) moduli: Box<[u64]>,

    /// Vector of the sized of the coprime moduli q_i for the ciphertext.
    /// One and only one of `ciphertext_moduli` or `ciphertext_moduli_sizes`
    /// must be specified.
    moduli_sizes: Box<[usize]>,

    /// Error variance
    pub(crate) variance: usize,

    /// Error variance for e2 in threshold BFV
    /// Now supports up to 155-bit numbers using BigUint
    pub(crate) error1_variance: BigUint,

    /// Context for the underlying polynomials
    pub ctx: Vec<Arc<Context>>,

    /// Ntt operator for the SIMD plaintext, if possible.
    pub(crate) op: Option<Arc<NttOperator>>,

    /// Scaling polynomial for the plaintext
    pub(crate) delta: Box<[Poly]>,

    /// Q modulo the plaintext modulus
    pub(crate) q_mod_t: Box<[u64]>,

    /// Down scaler for the plaintext
    pub(crate) scalers: Box<[Scaler]>,

    /// Plaintext Modulus
    pub(crate) plaintext: Modulus,

    // Parameters for the multiplications
    pub(crate) mul_params: Box<[MultiplicationParameters]>,

    pub(crate) matrix_reps_index_map: Box<[usize]>,
}

impl Debug for BfvParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BfvParameters")
            .field("polynomial_degree", &self.polynomial_degree)
            .field("plaintext_modulus", &self.plaintext_modulus)
            .field("moduli", &self.moduli)
            // .field("moduli_sizes", &self.moduli_sizes)
            // .field("variance", &self.variance)
            // .field("error1_variance", &self.error1_variance)
            // .field("ctx", &self.ctx)
            // .field("op", &self.op)
            // .field("delta", &self.delta)
            // .field("q_mod_t", &self.q_mod_t)
            // .field("scaler", &self.scaler)
            // .field("plaintext", &self.plaintext)
            // .field("mul_params", &self.mul_params)
            // .field("matrix_reps_index_map", &self.matrix_reps_index_map)
            .finish()
    }
}

const RAW_SERIALIZATION_VERSION: u32 = 1;

impl FheParameters for BfvParameters {}

unsafe impl Send for BfvParameters {}

impl BfvParameters {
    /// Returns the underlying polynomial degree
    pub const fn degree(&self) -> usize {
        self.polynomial_degree
    }

    /// Returns a reference to the ciphertext moduli
    pub fn moduli(&self) -> &[u64] {
        &self.moduli
    }

    /// Returns a reference to the ciphertext moduli
    pub fn moduli_sizes(&self) -> &[usize] {
        &self.moduli_sizes
    }

    /// Returns the plaintext modulus
    pub const fn plaintext(&self) -> u64 {
        self.plaintext_modulus
    }

    /// Returns the variance
    pub const fn variance(&self) -> usize {
        self.variance
    }

    /// Get the error1_variance
    pub fn get_error1_variance(&self) -> &BigUint {
        &self.error1_variance
    }

    /// Returns the ctx
    pub fn ctx(&self) -> &[Arc<Context>] {
        &self.ctx
    }

    /// Returns the maximum level allowed by these parameters.
    pub fn max_level(&self) -> usize {
        self.moduli.len() - 1
    }

    /// Returns the context corresponding to the level.
    pub fn ctx_at_level(&self, level: usize) -> Result<&Arc<Context>> {
        self.ctx
            .get(level)
            .ok_or_else(|| Error::DefaultError("No context".to_string()))
    }

    /// Returns the level of a given context
    pub(crate) fn level_of_ctx(&self, ctx: &Arc<Context>) -> Result<usize> {
        self.ctx[0].niterations_to(ctx).map_err(Error::MathError)
    }

    /// Vector of default parameters providing about 128 bits of quantum
    /// security according to the <https://eprint.iacr.org/2024/463> standard. The number
    /// of bits represented by the moduli vector sum to the maximum logQ in
    /// table 4.2 under the quantum, gaussian secret key distribution
    /// column. Note this library uses a centered binomial distribution with
    /// variance 10≈3.19² by default for its secret and error distributions
    /// and checks that the bounds match 6σ.
    pub fn default_parameters_128(plaintext_nbits: usize) -> Vec<Arc<BfvParameters>> {
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

        let mut params = vec![];

        for n in n_and_qs.keys().sorted() {
            let moduli = n_and_qs.get(n).unwrap();
            if let Some(plaintext_modulus) = generate_prime(
                plaintext_nbits,
                2 * *n as u64,
                u64::MAX >> (64 - plaintext_nbits),
            ) {
                params.push(
                    BfvParametersBuilder::new()
                        .set_degree(*n as usize)
                        .set_plaintext_modulus(plaintext_modulus)
                        .set_moduli(moduli)
                        .build_arc()
                        .unwrap(),
                )
            }
        }

        params
    }

    #[cfg(test)]
    #[allow(missing_docs)]
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

    /// Create a new BfvParameters with custom error1_variance for threshold BFV
    pub fn with_error1_variance(mut self, error1_variance: BigUint) -> Self {
        self.error1_variance = error1_variance;
        self
    }

    /// Serialize the fully derived parameters into a raw representation.
    ///
    /// The resulting bytes capture every derived artifact (NTT tables, RNS
    /// contexts, scalers, etc.) so that [`from_raw_bytes`] can reconstruct an
    /// equivalent [`BfvParameters`] instance without recomputation. The format
    /// is versioned and currently private to this crate.
    pub fn to_raw_bytes(&self) -> Result<Vec<u8>> {
        let mut registry = ContextRegistry::default();
        let main_ctx_ids = self
            .ctx
            .iter()
            .map(|ctx| registry.get_or_insert(ctx))
            .collect::<Vec<_>>();

        let scalers = self
            .scalers
            .iter()
            .map(|scaler| RawScalerRef::from_scaler(scaler, &mut registry))
            .collect::<Vec<_>>();

        let delta = self
            .delta
            .iter()
            .map(|poly| RawPolyEntry {
                ctx_id: registry.get_or_insert(&poly.ctx),
                poly: poly.to_raw(),
            })
            .collect::<Vec<_>>();

        let mul_params = self
            .mul_params
            .iter()
            .map(|mp| RawMultiplicationParameters::from_parameters(mp, &mut registry))
            .collect::<Vec<_>>();

        let moduli_sizes = self
            .moduli_sizes
            .iter()
            .map(|value| usize_to_u32(*value, "moduli_sizes"))
            .collect::<Result<Vec<_>>>()?;

        let matrix_reps_index_map = self
            .matrix_reps_index_map
            .iter()
            .map(|value| usize_to_u32(*value, "matrix_reps_index_map"))
            .collect::<Result<Vec<_>>>()?;

        let raw = RawBfvParameters {
            version: RAW_SERIALIZATION_VERSION,
            degree: usize_to_u32(self.polynomial_degree, "degree")?,
            plaintext_modulus: self.plaintext_modulus,
            moduli: self.moduli.to_vec(),
            moduli_sizes,
            variance: usize_to_u32(self.variance, "variance")?,
            error1_variance: self.error1_variance.to_bytes_be(),
            contexts: registry.into_contexts(),
            main_ctx_ids,
            op: self.op.as_ref().map(|op| op.to_raw()),
            delta,
            q_mod_t: self.q_mod_t.to_vec(),
            scalers,
            mul_params,
            matrix_reps_index_map,
        };

        bincode::serialize(&raw).map_err(|_| Error::SerializationError)
    }

    /// Deserialize a raw representation without recomputing derived values.
    ///
    /// This expects bytes produced by [`to_raw_bytes`] using the same raw
    /// serialization version. The function performs structural validation but
    /// does not repeat the expensive mathematical checks enforced by
    /// [`BfvParametersBuilder`].
    pub fn from_raw_bytes(bytes: &[u8]) -> Result<Self> {
        let raw: RawBfvParameters =
            bincode::deserialize(bytes).map_err(|_| Error::SerializationError)?;
        if raw.version != RAW_SERIALIZATION_VERSION {
            return Err(Error::DefaultError(
                "Unsupported raw BFV parameter version".to_string(),
            ));
        }

        if raw.contexts.is_empty() {
            return Err(Error::DefaultError(
                "Raw BFV parameters contain no contexts".to_string(),
            ));
        }

        let mut cache = vec![None; raw.contexts.len()];
        for idx in 0..raw.contexts.len() {
            build_context(idx, &raw.contexts, &mut cache)?;
        }
        let built_contexts = cache
            .into_iter()
            .map(|ctx| ctx.expect("context initialized"))
            .collect::<Vec<_>>();

        let ctx = raw
            .main_ctx_ids
            .iter()
            .map(|id| ctx_by_id(&built_contexts, *id))
            .collect::<Result<Vec<_>>>()?;

        let op = if let Some(op_raw) = raw.op {
            Some(Arc::new(op_raw.into_operator()?))
        } else {
            None
        };

        let delta = raw
            .delta
            .into_iter()
            .map(|entry| entry.into_poly(&built_contexts))
            .collect::<Result<Vec<_>>>()?
            .into_boxed_slice();

        let scalers = raw
            .scalers
            .into_iter()
            .map(|entry| entry.into_scaler(&built_contexts))
            .collect::<Result<Vec<_>>>()?
            .into_boxed_slice();

        let mul_params = raw
            .mul_params
            .into_iter()
            .map(|entry| entry.into_parameters(&built_contexts))
            .collect::<Result<Vec<_>>>()?
            .into_boxed_slice();

        Ok(BfvParameters {
            polynomial_degree: raw.degree as usize,
            plaintext_modulus: raw.plaintext_modulus,
            moduli: raw.moduli.into_boxed_slice(),
            moduli_sizes: raw
                .moduli_sizes
                .iter()
                .map(|value| *value as usize)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            variance: raw.variance as usize,
            error1_variance: BigUint::from_bytes_be(&raw.error1_variance),
            ctx,
            op,
            delta,
            q_mod_t: raw.q_mod_t.into_boxed_slice(),
            scalers,
            plaintext: Modulus::new(raw.plaintext_modulus)?,
            mul_params,
            matrix_reps_index_map: raw
                .matrix_reps_index_map
                .iter()
                .map(|value| *value as usize)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        })
    }
}

/// Builder for parameters for the Bfv encryption scheme.
#[derive(Debug)]
pub struct BfvParametersBuilder {
    degree: usize,
    plaintext: u64,
    variance: usize,
    error1_variance: BigUint,
    // CHANGE 1: Added flag to track if error1_variance was explicitly set
    // This allows error1_variance to automatically follow variance unless
    // the user explicitly sets a different value
    error1_variance_explicitly_set: bool,
    ciphertext_moduli: Vec<u64>,
    ciphertext_moduli_sizes: Vec<usize>,
}

impl BfvParametersBuilder {
    /// Creates a new instance of the builder
    #[allow(clippy::new_without_default)]
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

    /// Sets the polynomial degree. Returns an error if the degree is not
    /// a power of two larger or equal to 8.
    pub fn set_degree(&mut self, degree: usize) -> &mut Self {
        self.degree = degree;
        self
    }

    /// Sets the plaintext modulus. Returns an error if the plaintext is not
    /// between 2 and 2^62 - 1.
    pub fn set_plaintext_modulus(&mut self, plaintext: u64) -> &mut Self {
        self.plaintext = plaintext;
        self
    }

    /// Sets the sizes of the ciphertext moduli.
    /// Only one of `set_moduli_sizes` and `set_moduli`
    /// can be specified.
    pub fn set_moduli_sizes(&mut self, sizes: &[usize]) -> &mut Self {
        self.ciphertext_moduli_sizes = sizes.to_owned();
        self
    }

    /// Sets the ciphertext moduli to use.
    /// Only one of `set_moduli_sizes` and `set_moduli`
    /// can be specified.
    pub fn set_moduli(&mut self, moduli: &[u64]) -> &mut Self {
        self.ciphertext_moduli = moduli.to_owned();
        self
    }

    /// Sets the error variance. Returns an error if the variance is not between
    /// one and sixteen.
    ///
    /// CHANGE 3: Modified to sync error1_variance unless it was explicitly set
    /// This ensures backward compatibility - if you only set variance,
    /// error1_variance will match it (standard BFV behavior)
    pub fn set_variance(&mut self, variance: usize) -> &mut Self {
        self.variance = variance;
        // Only update error1_variance if it hasn't been explicitly set
        // This maintains backward compatibility while allowing independent control
        if !self.error1_variance_explicitly_set {
            self.error1_variance = BigUint::from(variance as u32);
        }
        self
    }

    /// Sets the error2 variance for threshold BFV using BigUint.
    ///
    /// CHANGE 4: Mark the flag as true when explicitly setting error1_variance
    /// This prevents future set_variance() calls from overwriting this value
    pub fn set_error1_variance(&mut self, error1_variance: BigUint) -> &mut Self {
        self.error1_variance = error1_variance;
        self.error1_variance_explicitly_set = true;
        self
    }

    /// Sets the error2 variance for threshold BFV from a usize.
    /// Convenience method for smaller values.
    ///
    /// CHANGE 5: Also marks the flag as true
    pub fn set_error1_variance_usize(&mut self, error1_variance: usize) -> &mut Self {
        self.error1_variance = BigUint::from(error1_variance);
        self.error1_variance_explicitly_set = true;
        self
    }

    /// Sets the error2 variance for threshold BFV from a string representation.
    /// Useful for very large numbers that can't fit in standard integer types.
    ///
    /// CHANGE 6: Also marks the flag as true
    pub fn set_error1_variance_str(&mut self, error1_variance: &str) -> Result<&mut Self> {
        let big_uint = error1_variance.parse::<BigUint>().map_err(|_| {
            Error::ParametersError(ParametersError::InvalidPlaintext(format!(
                "Invalid BigUint string: {}",
                error1_variance
            )))
        })?;
        self.error1_variance = big_uint;
        self.error1_variance_explicitly_set = true;
        Ok(self)
    }

    /// Generate ciphertext moduli with the specified sizes
    fn generate_moduli(moduli_sizes: &[usize], degree: usize) -> Result<Vec<u64>> {
        let mut moduli = vec![];
        for size in moduli_sizes {
            if *size > 62 || *size < 10 {
                return Err(Error::ParametersError(ParametersError::InvalidModulusSize(
                    *size, 10, 62,
                )));
            }

            let mut upper_bound = 1 << size;
            loop {
                if let Some(prime) = generate_prime(*size, 2 * degree as u64, upper_bound) {
                    if !moduli.contains(&prime) {
                        moduli.push(prime);
                        break;
                    } else {
                        upper_bound = prime;
                    }
                } else {
                    return Err(Error::ParametersError(ParametersError::NotEnoughPrimes(
                        *size, degree,
                    )));
                }
            }
        }

        Ok(moduli)
    }

    /// Build a new `BfvParameters` inside an `Arc`.
    pub fn build_arc(&self) -> Result<Arc<BfvParameters>> {
        self.build().map(Arc::new)
    }

    /// Build a new `BfvParameters`.
    pub fn build(&self) -> Result<BfvParameters> {
        // Check that the degree is a power of 2 (and large enough).
        if self.degree < 8 || !self.degree.is_power_of_two() {
            return Err(Error::ParametersError(ParametersError::InvalidDegree(
                self.degree,
            )));
        }

        // This checks that the plaintext modulus is valid.
        // TODO: Check bound on the plaintext modulus.
        let plaintext_modulus = Modulus::new(self.plaintext).map_err(|e| {
            Error::ParametersError(ParametersError::InvalidPlaintext(e.to_string()))
        })?;

        // Check that one of `ciphertext_moduli` and `ciphertext_moduli_sizes` is
        // specified.
        if !self.ciphertext_moduli.is_empty() && !self.ciphertext_moduli_sizes.is_empty() {
            return Err(Error::ParametersError(ParametersError::TooManySpecified(
                "Only one of `ciphertext_moduli` and `ciphertext_moduli_sizes` can be specified"
                    .to_string(),
            )));
        } else if self.ciphertext_moduli.is_empty() && self.ciphertext_moduli_sizes.is_empty() {
            return Err(Error::ParametersError(ParametersError::TooFewSpecified(
                "One of `ciphertext_moduli` and `ciphertext_moduli_sizes` must be specified"
                    .to_string(),
            )));
        }

        // Get or generate the moduli
        let mut moduli = self.ciphertext_moduli.clone();
        if !self.ciphertext_moduli_sizes.is_empty() {
            moduli = Self::generate_moduli(&self.ciphertext_moduli_sizes, self.degree)?
        }

        // Recomputes the moduli sizes
        let moduli_sizes = moduli
            .iter()
            .map(|m| 64 - m.leading_zeros() as usize)
            .collect_vec();

        // Create n+1 moduli of 62 bits for multiplication.
        let mut extended_basis = Vec::with_capacity(moduli.len() + 1);
        let mut upper_bound = 1 << 62;
        while extended_basis.len() != moduli.len() + 1 {
            upper_bound = generate_prime(62, 2 * self.degree as u64, upper_bound).unwrap();
            if !extended_basis.contains(&upper_bound) && !moduli.contains(&upper_bound) {
                extended_basis.push(upper_bound)
            }
        }

        let op = NttOperator::new(&plaintext_modulus, self.degree);

        let plaintext_ctx = Context::new_arc(&moduli[..1], self.degree)?;

        let mut delta_rests = vec![];
        for m in &moduli {
            let q = Modulus::new(*m)?;
            delta_rests.push(q.inv(q.neg(plaintext_modulus.modulus())).unwrap())
        }

        let mut ctx = Vec::with_capacity(moduli.len());
        let mut delta = Vec::with_capacity(moduli.len());
        let mut q_mod_t = Vec::with_capacity(moduli.len());
        let mut scalers = Vec::with_capacity(moduli.len());
        let mut mul_params = Vec::with_capacity(moduli.len());
        for i in 0..moduli.len() {
            let rns = RnsContext::new(&moduli[..moduli.len() - i])?;
            let ctx_i = Context::new_arc(&moduli[..moduli.len() - i], self.degree)?;
            let mut p = Poly::try_convert_from(
                &[rns.lift((&delta_rests).into())],
                &ctx_i,
                true,
                Representation::PowerBasis,
            )?;
            p.change_representation(Representation::NttShoup);
            delta.push(p);

            q_mod_t.push(
                (rns.modulus() % plaintext_modulus.modulus())
                    .to_u64()
                    .unwrap(),
            );

            scalers.push(Scaler::new(
                &ctx_i,
                &plaintext_ctx,
                ScalingFactor::new(&BigUint::from(plaintext_modulus.modulus()), rns.modulus()),
            )?);

            // For the first multiplication, we want to extend to a context that
            // is ~60 bits larger.
            let modulus_size = moduli_sizes[..moduli_sizes.len() - i].iter().sum::<usize>();
            let n_moduli = (modulus_size + 60).div_ceil(62);
            let mut mul_1_moduli = vec![];
            mul_1_moduli.append(&mut moduli[..moduli_sizes.len() - i].to_vec());
            mul_1_moduli.append(&mut extended_basis[..n_moduli].to_vec());
            let mul_1_ctx = Context::new_arc(&mul_1_moduli, self.degree)?;
            mul_params.push(MultiplicationParameters::new(
                &ctx_i,
                &mul_1_ctx,
                ScalingFactor::one(),
                ScalingFactor::new(&BigUint::from(plaintext_modulus.modulus()), ctx_i.modulus()),
            )?);

            ctx.push(ctx_i);
        }

        // We use the same code as SEAL
        // https://github.com/microsoft/SEAL/blob/82b07db635132e297282649e2ab5908999089ad2/native/src/seal/batchencoder.cpp
        let row_size = self.degree >> 1;
        let m = self.degree << 1;
        let gen = 3;
        let mut pos = 1;
        let mut matrix_reps_index_map = vec![0usize; self.degree];
        for i in 0..row_size {
            let index1 = (pos - 1) >> 1;
            let index2 = (m - pos - 1) >> 1;
            matrix_reps_index_map[i] = index1.reverse_bits() >> (self.degree.leading_zeros() + 1);
            matrix_reps_index_map[row_size | i] =
                index2.reverse_bits() >> (self.degree.leading_zeros() + 1);
            pos *= gen;
            pos &= m - 1;
        }

        Ok(BfvParameters {
            polynomial_degree: self.degree,
            plaintext_modulus: self.plaintext,
            moduli: moduli.into_boxed_slice(),
            moduli_sizes: moduli_sizes.into_boxed_slice(),
            variance: self.variance,
            error1_variance: self.error1_variance.clone(),
            ctx,
            op: op.map(Arc::new),
            delta: delta.into_boxed_slice(),
            q_mod_t: q_mod_t.into_boxed_slice(),
            scalers: scalers.into_boxed_slice(),
            plaintext: plaintext_modulus,
            mul_params: mul_params.into_boxed_slice(),
            matrix_reps_index_map: matrix_reps_index_map.into_boxed_slice(),
        })
    }
}

impl Serialize for BfvParameters {
    fn to_bytes(&self) -> Vec<u8> {
        Parameters {
            degree: self.polynomial_degree as u32,
            plaintext: self.plaintext_modulus,
            moduli: self.moduli.to_vec(),
            variance: self.variance as u32,
        }
        .encode_to_vec()
    }
}

impl Deserialize for BfvParameters {
    fn try_deserialize(bytes: &[u8]) -> Result<Self> {
        let params: Parameters = Message::decode(bytes).map_err(|_| Error::SerializationError)?;
        BfvParametersBuilder::new()
            .set_degree(params.degree as usize)
            .set_plaintext_modulus(params.plaintext)
            .set_moduli(&params.moduli)
            .set_variance(params.variance as usize)
            .build()
    }
    type Error = Error;
}

/// Multiplication parameters
#[derive(Debug, PartialEq, Eq, Default)]
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

#[derive(Clone, SerdeSerialize, SerdeDeserialize)]
struct RawBfvParameters {
    version: u32,
    degree: u32,
    plaintext_modulus: u64,
    moduli: Vec<u64>,
    moduli_sizes: Vec<u32>,
    variance: u32,
    error1_variance: Vec<u8>,
    contexts: Vec<RawContext>,
    main_ctx_ids: Vec<u32>,
    op: Option<NttOperatorRaw>,
    delta: Vec<RawPolyEntry>,
    q_mod_t: Vec<u64>,
    scalers: Vec<RawScalerRef>,
    mul_params: Vec<RawMultiplicationParameters>,
    matrix_reps_index_map: Vec<u32>,
}

#[derive(Clone, SerdeSerialize, SerdeDeserialize)]
struct RawContext {
    moduli: Vec<u64>,
    degree: u32,
    bitrev: Vec<u32>,
    inv_last_qi_mod_qj: Vec<u64>,
    inv_last_qi_mod_qj_shoup: Vec<u64>,
    rns: RnsContextRaw,
    ops: Vec<NttOperatorRaw>,
    next_context: Option<u32>,
}

#[derive(Clone, SerdeSerialize, SerdeDeserialize)]
struct RawPolyEntry {
    ctx_id: u32,
    poly: PolyRaw,
}

impl RawPolyEntry {
    fn into_poly(self, contexts: &[Arc<Context>]) -> Result<Poly> {
        let ctx = ctx_by_id(contexts, self.ctx_id)?;
        self.poly.into_poly(&ctx).map_err(Error::MathError)
    }
}

#[derive(Clone, SerdeSerialize, SerdeDeserialize)]
struct RawScalerRef {
    scaler: ScalerRaw,
    from_ctx: u32,
    to_ctx: u32,
}

#[derive(Clone, SerdeSerialize, SerdeDeserialize)]
struct RawMultiplicationParameters {
    extender: RawScalerRef,
    down_scaler: RawScalerRef,
    from_ctx: u32,
    to_ctx: u32,
}

#[derive(Default)]
struct ContextRegistry {
    contexts: Vec<RawContext>,
    ids: HashMap<usize, u32>,
}

impl ContextRegistry {
    fn get_or_insert(&mut self, ctx: &Arc<Context>) -> u32 {
        let key = Arc::as_ptr(ctx) as usize;
        if let Some(id) = self.ids.get(&key) {
            return *id;
        }

        let next_context = ctx
            .next_context
            .as_ref()
            .map(|next| self.get_or_insert(next));

        let id = self.contexts.len() as u32;
        self.ids.insert(key, id);
        self.contexts
            .push(RawContext::from_context(ctx, next_context));
        id
    }

    fn into_contexts(self) -> Vec<RawContext> {
        self.contexts
    }
}

impl RawContext {
    fn from_context(ctx: &Arc<Context>, next_context: Option<u32>) -> Self {
        RawContext {
            moduli: ctx.moduli.to_vec(),
            degree: ctx.degree as u32,
            bitrev: ctx.bitrev.iter().map(|v| *v as u32).collect(),
            inv_last_qi_mod_qj: ctx.inv_last_qi_mod_qj.to_vec(),
            inv_last_qi_mod_qj_shoup: ctx.inv_last_qi_mod_qj_shoup.to_vec(),
            rns: ctx.rns.as_ref().to_raw(),
            ops: ctx.ops.iter().map(|op| op.to_raw()).collect(),
            next_context,
        }
    }
}

impl RawScalerRef {
    fn from_scaler(scaler: &Scaler, registry: &mut ContextRegistry) -> Self {
        Self {
            scaler: scaler.to_raw(),
            from_ctx: registry.get_or_insert(scaler.from_context()),
            to_ctx: registry.get_or_insert(scaler.to_context()),
        }
    }

    fn into_scaler(self, contexts: &[Arc<Context>]) -> Result<Scaler> {
        let from = ctx_by_id(contexts, self.from_ctx)?;
        let to = ctx_by_id(contexts, self.to_ctx)?;
        self.scaler
            .into_scaler(&from, &to)
            .map_err(Error::MathError)
    }
}

impl RawMultiplicationParameters {
    fn from_parameters(mp: &MultiplicationParameters, registry: &mut ContextRegistry) -> Self {
        Self {
            extender: RawScalerRef::from_scaler(&mp.extender, registry),
            down_scaler: RawScalerRef::from_scaler(&mp.down_scaler, registry),
            from_ctx: registry.get_or_insert(&mp.from),
            to_ctx: registry.get_or_insert(&mp.to),
        }
    }

    fn into_parameters(self, contexts: &[Arc<Context>]) -> Result<MultiplicationParameters> {
        Ok(MultiplicationParameters {
            extender: self.extender.into_scaler(contexts)?,
            down_scaler: self.down_scaler.into_scaler(contexts)?,
            from: ctx_by_id(contexts, self.from_ctx)?,
            to: ctx_by_id(contexts, self.to_ctx)?,
        })
    }
}

fn build_context(
    idx: usize,
    contexts: &[RawContext],
    cache: &mut [Option<Arc<Context>>],
) -> Result<Arc<Context>> {
    if let Some(ctx) = &cache[idx] {
        return Ok(ctx.clone());
    }

    let raw = contexts[idx].clone();
    let next_context = match raw.next_context {
        Some(next_id) => Some(build_context(next_id as usize, contexts, cache)?),
        None => None,
    };

    let RawContext {
        moduli,
        degree,
        bitrev,
        inv_last_qi_mod_qj,
        inv_last_qi_mod_qj_shoup,
        rns,
        ops,
        next_context: _,
    } = raw;

    let q = moduli
        .iter()
        .copied()
        .map(Modulus::new)
        .collect::<std::result::Result<Vec<_>, fhe_math::Error>>()
        .map_err(Error::MathError)?
        .into_boxed_slice();

    let moduli = moduli.into_boxed_slice();

    let ops = ops
        .into_iter()
        .map(|op| op.into_operator())
        .collect::<std::result::Result<Vec<_>, fhe_math::Error>>()
        .map_err(Error::MathError)?
        .into_boxed_slice();

    let ctx = Arc::new(Context {
        moduli,
        q,
        rns: Arc::new(rns.into_context().map_err(Error::MathError)?),
        ops,
        degree: degree as usize,
        bitrev: bitrev
            .into_iter()
            .map(|v| v as usize)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        inv_last_qi_mod_qj: inv_last_qi_mod_qj.into_boxed_slice(),
        inv_last_qi_mod_qj_shoup: inv_last_qi_mod_qj_shoup.into_boxed_slice(),
        next_context,
    });

    cache[idx] = Some(ctx.clone());
    Ok(ctx)
}

fn ctx_by_id(contexts: &[Arc<Context>], id: u32) -> Result<Arc<Context>> {
    contexts
        .get(id as usize)
        .cloned()
        .ok_or_else(|| Error::DefaultError(format!("Invalid context id {id}")))
}

fn usize_to_u32(value: usize, field: &str) -> Result<u32> {
    value.try_into().map_err(|_| {
        Error::DefaultError(format!("{field} value {value} does not fit into 32 bits"))
    })
}

#[cfg(test)]
mod tests {
    use super::{BfvParameters, BfvParametersBuilder};
    use fhe_traits::{Deserialize, Serialize};
    use num_bigint::BigUint;
    use std::error::Error;

    #[test]
    fn default() {
        let params = BfvParameters::default_arc(1, 8);
        assert_eq!(params.moduli.len(), 1);
        assert_eq!(params.degree(), 8);

        let params = BfvParameters::default_arc(2, 16);
        assert_eq!(params.moduli.len(), 2);
        assert_eq!(params.degree(), 16);
    }

    #[test]
    fn ciphertext_moduli() -> Result<(), Box<dyn Error>> {
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(2)
            .set_moduli_sizes(&[62, 62, 62, 61, 60, 11])
            .build()?;
        assert_eq!(
            params.moduli.to_vec(),
            &[
                4611686018427387761,
                4611686018427387617,
                4611686018427387409,
                2305843009213693921,
                1152921504606846577,
                2017
            ]
        );

        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(2)
            .set_moduli(&[
                4611686018427387761,
                4611686018427387617,
                4611686018427387409,
                2305843009213693921,
                1152921504606846577,
                2017,
            ])
            .build()?;
        assert_eq!(params.moduli_sizes.to_vec(), &[62, 62, 62, 61, 60, 11]);

        Ok(())
    }

    #[test]
    fn serialize() -> Result<(), Box<dyn Error>> {
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(2)
            .set_moduli_sizes(&[62, 62, 62, 61, 60, 11])
            .set_variance(4)
            .build()?;
        let bytes = params.to_bytes();
        assert_eq!(BfvParameters::try_deserialize(&bytes)?, params);
        Ok(())
    }

    #[test]
    fn raw_roundtrip() -> Result<(), Box<dyn Error>> {
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62, 62])
            .set_variance(6)
            .build()?;

        let raw = params.to_raw_bytes()?;
        let restored = BfvParameters::from_raw_bytes(&raw)?;
        assert_eq!(params, restored);
        Ok(())
    }

    #[test]
    fn error1_variance_functionality() -> Result<(), Box<dyn Error>> {
        // Test default behavior (error1_variance defaults to variance)
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(10)
            .build()?;
        assert_eq!(params.get_error1_variance(), &BigUint::from(10u32));

        // Test custom error1_variance with BigUint
        let error2_big = BigUint::from(20u32);
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(10)
            .set_error1_variance(error2_big.clone())
            .build()?;
        assert_eq!(params.get_error1_variance(), &error2_big);
        assert_eq!(params.variance(), 10);

        // Test with_error1_variance method using 155-bit number
        let large_error2 = BigUint::parse_bytes(
            b"57896044618658097711785492504343953926634992332820282019728792003956564819967",
            10,
        )
        .unwrap();
        let params_with_large_error2 = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(10)
            .set_error1_variance(large_error2.clone())
            .build()?;
        assert_eq!(
            params_with_large_error2.get_error1_variance(),
            &large_error2
        );
        assert_eq!(params_with_large_error2.variance(), 10); // Original variance unchanged

        // Test convenience method for usize
        let params_usize = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(10)
            .set_error1_variance_usize(15)
            .build()?;
        assert_eq!(params_usize.get_error1_variance(), &BigUint::from(15u32));

        // Test string method for very large numbers
        let mut builder = BfvParametersBuilder::new();
        builder
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(10)
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
        // Test with a 155-bit number (close to 2^155)
        let bit_155_number = BigUint::from(2u32).pow(155) - BigUint::from(1u32);

        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(10)
            .set_error1_variance(bit_155_number.clone())
            .build()?;

        assert_eq!(params.get_error1_variance(), &bit_155_number);

        Ok(())
    }

    // NEW TEST: Test that error1_variance tracks variance when not explicitly set
    #[test]
    fn test_error1_variance_tracks_variance() -> Result<(), Box<dyn Error>> {
        // When only variance is set, error1_variance should match
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(15)
            .build()?;

        assert_eq!(params.variance(), 15);
        assert_eq!(params.get_error1_variance(), &BigUint::from(15u32));

        Ok(())
    }

    // NEW TEST: Test that explicitly set error1_variance is not overwritten
    #[test]
    fn test_error1_variance_independent_when_set() -> Result<(), Box<dyn Error>> {
        // Set error1_variance first, then variance - error1_variance should stay
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_error1_variance_usize(20)
            .set_variance(15)
            .build()?;

        assert_eq!(params.variance(), 15);
        assert_eq!(params.get_error1_variance(), &BigUint::from(20u32));

        // Set variance first, then error1_variance - error1_variance should be 20
        let params2 = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(15)
            .set_error1_variance_usize(20)
            .build()?;

        assert_eq!(params2.variance(), 15);
        assert_eq!(params2.get_error1_variance(), &BigUint::from(20u32));

        Ok(())
    }

    // NEW TEST: Test multiple variance changes without explicit error1_variance
    #[test]
    fn test_error1_variance_follows_multiple_variance_changes() -> Result<(), Box<dyn Error>> {
        let mut builder = BfvParametersBuilder::new();
        builder
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62])
            .set_variance(5)
            .set_variance(10)
            .set_variance(15);

        let params = builder.build()?;

        // error1_variance should match the final variance value
        assert_eq!(params.variance(), 15);
        assert_eq!(params.get_error1_variance(), &BigUint::from(15u32));

        Ok(())
    }
}
