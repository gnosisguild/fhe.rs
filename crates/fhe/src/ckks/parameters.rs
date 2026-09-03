//! Parameters for the CKKS encryption scheme.

use crate::ckks::hybrid::HybridParams;
use crate::proto::ckks::Parameters as ParametersProto;
use crate::{Error, ParametersError, Result, SerializationError};
use fhe_math::rq::Context;
use fhe_traits::{Deserialize, FheParameters, Serialize};
use prost::Message;
use std::fmt::Debug;
use std::ops::Range;
use std::sync::Arc;

/// Parameters for the CKKS approximate homomorphic encryption scheme.
///
/// CKKS works over the ring `R_q = Z_q[X]/(X^N + 1)` with a chain of RNS
/// moduli. Plaintexts are vectors of up to `N/2` real numbers, scaled by
/// `delta` at encoding time. There is no plaintext modulus: message precision
/// is governed by the scale and the encryption noise.
///
/// Optionally the parameters carry `k` **special primes** `P = p_1…p_k` and a
/// digit count `dnum` for hybrid key switching (see [`crate::ckks::hybrid`]).
/// Ciphertexts always live over `Q` only; the special primes are used solely
/// inside key-switching keys and the key-switch operation.
#[derive(PartialEq)]
pub struct CkksParameters {
    /// Number of coefficients in a polynomial.
    polynomial_degree: usize,

    /// Vector of coprime moduli q_i for the ciphertext.
    pub(crate) moduli: Box<[u64]>,

    /// Vector of the sizes (in bits) of the coprime moduli q_i.
    moduli_sizes: Box<[usize]>,

    /// Error variance used for fresh encryption noise.
    pub(crate) variance: usize,

    /// The encoding scale factor `delta`.
    scale: f64,

    /// Head of the context chain (level 0 = all moduli).
    pub(crate) context: Arc<Context>,

    /// Hybrid key-switching tables (`None` when no special primes are set).
    pub(crate) hybrid: Option<HybridParams>,
}

impl Debug for CkksParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksParameters")
            .field("polynomial_degree", &self.polynomial_degree)
            .field("moduli", &self.moduli)
            .field("scale", &self.scale)
            .field("special_moduli", &self.special_moduli())
            .field("dnum", &self.dnum())
            .finish()
    }
}

impl FheParameters for CkksParameters {}

impl CkksParameters {
    /// Returns the underlying polynomial degree.
    #[must_use]
    pub const fn degree(&self) -> usize {
        self.polynomial_degree
    }

    /// Returns a reference to the ciphertext moduli.
    #[must_use]
    pub fn moduli(&self) -> &[u64] {
        &self.moduli
    }

    /// Returns a reference to the sizes (in bits) of the ciphertext moduli.
    #[must_use]
    pub fn moduli_sizes(&self) -> &[usize] {
        &self.moduli_sizes
    }

    /// Returns the error variance.
    #[must_use]
    pub const fn variance(&self) -> usize {
        self.variance
    }

    /// Returns the encoding scale factor `delta`.
    #[must_use]
    pub const fn scale(&self) -> f64 {
        self.scale
    }

    /// Returns the number of plaintext slots (`N/2`).
    #[must_use]
    pub const fn slots(&self) -> usize {
        self.polynomial_degree / 2
    }

    /// Returns the maximum level allowed by these parameters.
    #[must_use]
    pub fn max_level(&self) -> usize {
        self.moduli.len() - 1
    }

    /// Returns the polynomial context at the given level.
    ///
    /// Level 0 uses the complete moduli chain; each subsequent level drops the
    /// last modulus (the context chain built by [`Context::new_arc`]).
    pub fn context_at_level(&self, level: usize) -> Result<&Arc<Context>> {
        let mut current = &self.context;
        for _ in 0..level {
            current = current
                .next_context
                .as_ref()
                .ok_or_else(|| Error::InvalidLevel {
                    level,
                    min_level: 0,
                    max_level: self.max_level(),
                })?;
        }
        Ok(current)
    }

    // ── Hybrid key switching ──────────────────────────────────────────────

    /// Whether these parameters carry special primes (hybrid key switching
    /// enabled).
    #[must_use]
    pub fn hybrid_enabled(&self) -> bool {
        self.hybrid.is_some()
    }

    /// The `k` special primes `p_1…p_k` (empty when hybrid is disabled).
    #[must_use]
    pub fn special_moduli(&self) -> &[u64] {
        self.hybrid
            .as_ref()
            .map_or(&[][..], |h| h.special_moduli.as_ref())
    }

    /// Number of gadget digits `dnum` of a hybrid key (0 when disabled).
    #[must_use]
    pub fn dnum(&self) -> usize {
        self.hybrid.as_ref().map_or(0, |h| h.dnum)
    }

    /// Digit size `alpha` (limbs per digit) of the hybrid gadget (0 when
    /// disabled).
    #[must_use]
    pub fn digit_size(&self) -> usize {
        self.hybrid.as_ref().map_or(0, |h| h.alpha)
    }

    /// Number of non-empty gadget digits at `level`
    /// (`ceil(L_level / alpha)`); 0 when hybrid is disabled.
    pub fn digits_at_level(&self, level: usize) -> Result<usize> {
        let remaining = self.context_at_level(level)?.moduli().len();
        Ok(self
            .hybrid
            .as_ref()
            .map_or(0, |h| remaining.div_ceil(h.alpha)))
    }

    /// Limb index ranges of the gadget digits at `level` (each digit covers
    /// `alpha` consecutive RNS limbs; the last one may be shorter).
    pub fn digit_ranges_at_level(&self, level: usize) -> Result<Vec<Range<usize>>> {
        let remaining = self.context_at_level(level)?.moduli().len();
        let alpha = self.digit_size();
        if alpha == 0 {
            return Ok(vec![]);
        }
        Ok((0..remaining.div_ceil(alpha))
            .map(|j| j * alpha..((j + 1) * alpha).min(remaining))
            .collect())
    }

    /// Context over the special primes only (`P`), for the `P`-halves of
    /// hybrid key material. Errors when hybrid is disabled.
    ///
    /// No `Q·P` context is built: a `fhe-math` [`Context`] carries a full
    /// modulus-drop chain of NTT tables (`(L+k)^2/2` operators, ~1.7 GiB at
    /// `N = 65536, L = 38`), so `Q·P` elements are represented as a
    /// `(Q-part, P-part)` pair instead — see [`crate::ckks::CkksQpPoly`].
    pub fn context_p(&self) -> Result<&Arc<Context>> {
        self.hybrid
            .as_ref()
            .map(|h| &h.context_p)
            .ok_or_else(|| Error::DefaultError("hybrid key switching is not enabled".into()))
    }

    /// Internal accessor for the hybrid tables.
    pub(crate) fn hybrid(&self) -> Result<&HybridParams> {
        self.hybrid.as_ref().ok_or_else(|| {
            Error::DefaultError(
                "hybrid key switching is not enabled (set special moduli on the builder)".into(),
            )
        })
    }
}

/// Builder for [`CkksParameters`].
#[derive(Debug, Default)]
pub struct CkksParametersBuilder {
    degree: usize,
    moduli: Vec<u64>,
    moduli_sizes: Vec<usize>,
    special_moduli: Vec<u64>,
    special_moduli_sizes: Vec<usize>,
    dnum: Option<usize>,
    variance: usize,
    scale: f64,
}

impl Serialize for CkksParameters {
    fn to_bytes(&self) -> Vec<u8> {
        ParametersProto {
            degree: self.polynomial_degree as u32,
            moduli: self.moduli.to_vec(),
            variance: self.variance as u32,
            scale: self.scale,
            special_moduli: self.special_moduli().to_vec(),
            dnum: self.dnum() as u32,
        }
        .encode_to_vec()
    }
}

impl Deserialize for CkksParameters {
    type Error = Error;

    fn try_deserialize(bytes: &[u8]) -> Result<Self> {
        let proto: ParametersProto = Message::decode(bytes).map_err(|_| {
            Error::SerializationError(SerializationError::ProtobufError {
                message: "CkksParameters decode".into(),
            })
        })?;
        let mut b = CkksParametersBuilder::new()
            .set_degree(proto.degree as usize)
            .set_moduli(&proto.moduli)
            .set_variance(proto.variance as usize)
            .set_scale(proto.scale);
        // Backward compatible: absent fields decode as empty / 0 and leave
        // hybrid key switching disabled.
        if !proto.special_moduli.is_empty() {
            b = b.set_special_moduli(&proto.special_moduli);
            if proto.dnum != 0 {
                b = b.set_dnum(proto.dnum as usize);
            }
        }
        b.build()
    }
}

impl CkksParametersBuilder {
    /// Creates a new builder with no parameters set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            degree: 0,
            moduli: vec![],
            moduli_sizes: vec![],
            special_moduli: vec![],
            special_moduli_sizes: vec![],
            dnum: None,
            variance: 10,
            scale: 0.0,
        }
    }

    /// Sets the polynomial degree `N`. Must be a power of two, at least 8.
    #[must_use]
    pub fn set_degree(mut self, degree: usize) -> Self {
        self.degree = degree;
        self
    }

    /// Sets the ciphertext moduli explicitly.
    #[must_use]
    pub fn set_moduli(mut self, moduli: &[u64]) -> Self {
        self.moduli = moduli.to_vec();
        self.moduli_sizes.clear();
        self
    }

    /// Sets the sizes (in bits) of the ciphertext moduli; the primes are
    /// generated internally.
    #[must_use]
    pub fn set_moduli_sizes(mut self, sizes: &[usize]) -> Self {
        self.moduli_sizes = sizes.to_vec();
        self.moduli.clear();
        self
    }

    /// Sets the `k` special primes `p_1…p_k` for hybrid key switching
    /// explicitly. They must be NTT-friendly for the degree and distinct
    /// from (and coprime to) the ciphertext moduli. Passing an empty slice
    /// disables hybrid key switching.
    #[must_use]
    pub fn set_special_moduli(mut self, moduli: &[u64]) -> Self {
        self.special_moduli = moduli.to_vec();
        self.special_moduli_sizes.clear();
        self
    }

    /// Sets the sizes (in bits) of the `k` special primes; the primes are
    /// generated internally, distinct from the ciphertext moduli. `k`
    /// special primes give a default digit size `alpha = k` limbs.
    #[must_use]
    pub fn set_special_moduli_sizes(mut self, sizes: &[usize]) -> Self {
        self.special_moduli_sizes = sizes.to_vec();
        self.special_moduli.clear();
        self
    }

    /// Sets the number of gadget digits `dnum` of hybrid keys. Defaults to
    /// `ceil(L / k)` (digit size `alpha = k`). Must satisfy `dnum·k ≥ L`
    /// (so every digit product `Q_j ≤ ~P`) and be realizable as
    /// `ceil(L / ceil(L / dnum))`.
    #[must_use]
    pub fn set_dnum(mut self, dnum: usize) -> Self {
        self.dnum = Some(dnum);
        self
    }

    /// Sets the error variance. Defaults to 10.
    #[must_use]
    pub fn set_variance(mut self, variance: usize) -> Self {
        self.variance = variance;
        self
    }

    /// Sets the encoding scale factor `delta`, e.g. `2f64.powi(40)`.
    #[must_use]
    pub fn set_scale(mut self, scale: f64) -> Self {
        self.scale = scale;
        self
    }

    /// Generate primes of the requested bit sizes for the given degree,
    /// distinct from every prime in `avoid`.
    fn generate_primes(&self, sizes: &[usize], avoid: &[u64]) -> Result<Vec<u64>> {
        let mut moduli = vec![];
        for (index, size) in sizes.iter().enumerate() {
            if *size > 62 || *size < 10 {
                return Err(Error::ParametersError(
                    ParametersError::InvalidModulusSize {
                        index,
                        size: *size,
                        min: 10,
                        max: 62,
                    },
                ));
            }
            let mut upper_bound = 1 << size;
            loop {
                if let Some(prime) =
                    fhe_math::zq::primes::generate_prime(*size, 2 * self.degree as u64, upper_bound)
                {
                    if !moduli.contains(&prime) && !avoid.contains(&prime) {
                        moduli.push(prime);
                        break;
                    }
                    upper_bound = prime;
                } else {
                    return Err(Error::ParametersError(ParametersError::NotEnoughPrimes {
                        size: *size,
                        degree: self.degree,
                        needed: sizes.len(),
                        available: moduli.len(),
                    }));
                }
            }
        }
        Ok(moduli)
    }

    /// Builds the [`CkksParameters`].
    pub fn build(mut self) -> Result<CkksParameters> {
        if !self.degree.is_power_of_two() || self.degree < 8 {
            return Err(Error::ParametersError(
                ParametersError::invalid_degree_with_bounds(self.degree),
            ));
        }
        if !(self.scale.is_finite() && self.scale >= 1.0) {
            return Err(Error::InvalidPlaintext {
                reason: format!("invalid CKKS scale: {}", self.scale),
            });
        }
        if self.moduli.is_empty() && self.moduli_sizes.is_empty() {
            return Err(Error::ParametersError(ParametersError::MissingParameter {
                parameter: "moduli or moduli_sizes".to_string(),
            }));
        }
        if self.moduli.is_empty() {
            self.moduli = self.generate_primes(&self.moduli_sizes, &[])?;
        }
        let moduli_sizes = self
            .moduli
            .iter()
            .map(|m| 64 - m.leading_zeros() as usize)
            .collect::<Vec<_>>();

        let context = Context::new_arc(&self.moduli, self.degree)?;

        if self.special_moduli.is_empty() && !self.special_moduli_sizes.is_empty() {
            self.special_moduli = self.generate_primes(&self.special_moduli_sizes, &self.moduli)?;
        }
        let hybrid = if self.special_moduli.is_empty() {
            if self.dnum.is_some() {
                return Err(Error::ParametersError(ParametersError::MissingParameter {
                    parameter: "special_moduli (dnum set without special primes)".to_string(),
                }));
            }
            None
        } else {
            Some(HybridParams::new(
                &context,
                &self.special_moduli,
                self.dnum,
                self.degree,
            )?)
        };

        Ok(CkksParameters {
            polynomial_degree: self.degree,
            moduli: self.moduli.into_boxed_slice(),
            moduli_sizes: moduli_sizes.into_boxed_slice(),
            variance: self.variance,
            scale: self.scale,
            context,
            hybrid,
        })
    }

    /// Builds the [`CkksParameters`] wrapped in an [`Arc`].
    pub fn build_arc(self) -> Result<Arc<CkksParameters>> {
        self.build().map(Arc::new)
    }
}

#[cfg(test)]
mod tests {
    use super::{CkksParameters, CkksParametersBuilder};
    use fhe_traits::{Deserialize, Serialize};

    #[test]
    fn build_with_moduli_sizes() {
        let params = CkksParametersBuilder::new()
            .set_degree(16)
            .set_moduli_sizes(&[50, 40])
            .set_scale(2f64.powi(30))
            .build()
            .unwrap();
        assert_eq!(params.degree(), 16);
        assert_eq!(params.moduli().len(), 2);
        assert_eq!(params.slots(), 8);
        assert_eq!(params.max_level(), 1);
        assert!(!params.hybrid_enabled());
        assert_eq!(params.dnum(), 0);
        assert!(params.special_moduli().is_empty());
        assert!(params.context_p().is_err());
    }

    #[test]
    fn invalid_degree_rejected() {
        assert!(
            CkksParametersBuilder::new()
                .set_degree(12)
                .set_moduli_sizes(&[50])
                .set_scale(2f64.powi(30))
                .build()
                .is_err()
        );
    }

    #[test]
    fn invalid_scale_rejected() {
        assert!(
            CkksParametersBuilder::new()
                .set_degree(16)
                .set_moduli_sizes(&[50])
                .set_scale(0.0)
                .build()
                .is_err()
        );
    }

    #[test]
    fn context_chain_levels() {
        let params = CkksParametersBuilder::new()
            .set_degree(16)
            .set_moduli_sizes(&[50, 40, 40])
            .set_scale(2f64.powi(30))
            .build()
            .unwrap();
        assert!(params.context_at_level(0).is_ok());
        assert!(params.context_at_level(2).is_ok());
        assert!(params.context_at_level(3).is_err());
    }

    #[test]
    fn hybrid_params_digits_and_defaults() {
        // L = 5 limbs, k = 2 special primes => alpha = 2, dnum = 3.
        let params = CkksParametersBuilder::new()
            .set_degree(16)
            .set_moduli_sizes(&[45, 40, 40, 40, 40])
            .set_special_moduli_sizes(&[45, 45])
            .set_scale(2f64.powi(40))
            .build()
            .unwrap();
        assert!(params.hybrid_enabled());
        assert_eq!(params.special_moduli().len(), 2);
        assert_eq!(params.dnum(), 3);
        assert_eq!(params.digit_size(), 2);
        assert_eq!(params.digits_at_level(0).unwrap(), 3);
        assert_eq!(params.digits_at_level(1).unwrap(), 2);
        assert_eq!(params.digits_at_level(3).unwrap(), 1);
        assert_eq!(
            params.digit_ranges_at_level(0).unwrap(),
            vec![0..2, 2..4, 4..5]
        );
        assert_eq!(params.digit_ranges_at_level(2).unwrap(), vec![0..2, 2..3]);
        assert_eq!(params.context_p().unwrap().moduli().len(), 2);
        // Special primes are distinct from the ciphertext moduli.
        for p in params.special_moduli() {
            assert!(!params.moduli().contains(p));
        }
    }

    #[test]
    fn hybrid_params_validation() {
        // dnum·k < L is rejected.
        assert!(
            CkksParametersBuilder::new()
                .set_degree(16)
                .set_moduli_sizes(&[45, 40, 40, 40, 40])
                .set_special_moduli_sizes(&[45])
                .set_dnum(2)
                .set_scale(2f64.powi(40))
                .build()
                .is_err()
        );
        // dnum without special primes is rejected.
        assert!(
            CkksParametersBuilder::new()
                .set_degree(16)
                .set_moduli_sizes(&[45, 40])
                .set_dnum(2)
                .set_scale(2f64.powi(40))
                .build()
                .is_err()
        );
        // A special prime equal to a ciphertext modulus is rejected.
        let base = CkksParametersBuilder::new()
            .set_degree(16)
            .set_moduli_sizes(&[45, 40])
            .set_scale(2f64.powi(40))
            .build()
            .unwrap();
        assert!(
            CkksParametersBuilder::new()
                .set_degree(16)
                .set_moduli(base.moduli())
                .set_special_moduli(&[base.moduli()[0]])
                .set_scale(2f64.powi(40))
                .build()
                .is_err()
        );
        // Explicit dnum larger than the default (smaller digits) is fine.
        let p = CkksParametersBuilder::new()
            .set_degree(16)
            .set_moduli_sizes(&[45, 40, 40, 40])
            .set_special_moduli_sizes(&[45, 45])
            .set_dnum(4)
            .set_scale(2f64.powi(40))
            .build()
            .unwrap();
        assert_eq!(p.dnum(), 4);
        assert_eq!(p.digit_size(), 1);
    }

    #[test]
    fn serialization_round_trip_with_and_without_hybrid() {
        let plain = CkksParametersBuilder::new()
            .set_degree(16)
            .set_moduli_sizes(&[45, 40, 40])
            .set_scale(2f64.powi(40))
            .build()
            .unwrap();
        let back = CkksParameters::try_deserialize(&plain.to_bytes()).unwrap();
        assert!(back == plain);
        assert!(!back.hybrid_enabled());

        let hybrid = CkksParametersBuilder::new()
            .set_degree(16)
            .set_moduli_sizes(&[45, 40, 40])
            .set_special_moduli_sizes(&[45, 45])
            .set_dnum(3)
            .set_scale(2f64.powi(40))
            .build()
            .unwrap();
        let back = CkksParameters::try_deserialize(&hybrid.to_bytes()).unwrap();
        assert!(back == hybrid);
        assert_eq!(back.special_moduli(), hybrid.special_moduli());
        assert_eq!(back.dnum(), 3);

        // Old (pre-hybrid) encodings carry no fields 5/6: the plain
        // parameters' bytes must equal an encoding without them.
        let legacy = crate::proto::ckks::Parameters {
            degree: 16,
            moduli: plain.moduli().to_vec(),
            variance: plain.variance() as u32,
            scale: plain.scale(),
            special_moduli: vec![],
            dnum: 0,
        };
        assert_eq!(prost::Message::encode_to_vec(&legacy), plain.to_bytes());
    }
}
