//! Leveled evaluation keys for the BFV encryption scheme.

use crate::bfv::keys::key_switching_key::{KeySwitchingKeyWireShape, expected_wire_shape};
use crate::bfv::{BfvParameters, Ciphertext, SecretKey, keys::GaloisKey, traits::TryConvertFrom};
use crate::proto::bfv::{EvaluationKey as EvaluationKeyProto, GaloisKey as GaloisKeyProto};
use crate::serialization::{WireCursor, WireValue};
use crate::{Error, Result, SerializationError, SerializedField, SerializedObject};
use fhe_math::rq::{NttShoup, Poly, PowerBasis};
use fhe_math::zq::Modulus;
use fhe_traits::{DeserializeParametrized, FheParametrized, Serialize};
use prost::Message;
use rand::{CryptoRng, Rng as RngCore};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Evaluation key for the BFV encryption scheme.
///
/// An evaluation key enables one or several of the following operations:
/// - column rotation
/// - row rotation
/// - oblivious expansion
/// - inner sum
#[derive(Debug, PartialEq, Eq)]
pub struct EvaluationKey {
    params: Arc<BfvParameters>,

    ciphertext_level: usize,
    evaluation_key_level: usize,

    /// Map from Galois keys exponents to Galois keys
    gk: HashMap<usize, GaloisKey>,

    /// Map from rotation index to Galois key exponent
    rot_to_gk_exponent: HashMap<usize, usize>,

    /// Monomials used in expansion
    monomials: Vec<Poly<NttShoup>>,
}

impl EvaluationKey {
    /// Reports whether the evaluation key enables to compute an homomorphic
    /// inner sums.
    #[must_use]
    pub fn supports_inner_sum(&self) -> bool {
        let mut ret = self.gk.contains_key(&(self.params.degree() * 2 - 1));
        let mut i = 1;
        while i < self.params.degree() / 2 {
            ret &= self
                .gk
                .contains_key(self.rot_to_gk_exponent.get(&i).unwrap());
            i *= 2
        }
        ret
    }

    /// Computes the homomorphic inner sum.
    pub fn computes_inner_sum(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        self.validate_ciphertext(ct)?;
        if !self.supports_inner_sum() {
            Err(crate::EvaluationKeyError::Unsupported {
                operation: crate::EvaluationOperation::InnerSum,
            }
            .into())
        } else {
            let mut out = ct.clone();
            let mut tmp = Ciphertext::zero(&ct.params);

            let mut i = 1;
            while i < ct.params.degree() / 2 {
                let exponent =
                    self.rot_to_gk_exponent
                        .get(&i)
                        .ok_or(crate::EvaluationKeyError::Missing {
                            component: crate::EvaluationKeyComponent::GaloisExponent { step: i },
                        })?;
                let gk = self
                    .gk
                    .get(exponent)
                    .ok_or(crate::EvaluationKeyError::Missing {
                        component: crate::EvaluationKeyComponent::GaloisKey { element: *exponent },
                    })?;
                gk.relinearize_into(&out, &mut tmp)?;
                out += &tmp;
                i *= 2
            }

            let row_rotation_element = self.params.degree() * 2 - 1;
            let gk =
                self.gk
                    .get(&row_rotation_element)
                    .ok_or(crate::EvaluationKeyError::Missing {
                        component: crate::EvaluationKeyComponent::GaloisKey {
                            element: row_rotation_element,
                        },
                    })?;
            gk.relinearize_into(&out, &mut tmp)?;
            out += &tmp;

            Ok(out)
        }
    }

    /// Reports whether the evaluation key enables to rotate the rows of the
    /// plaintext.
    #[must_use]
    pub fn supports_row_rotation(&self) -> bool {
        self.gk.contains_key(&(self.params.degree() * 2 - 1))
    }

    /// Homomorphically rotate the rows of the plaintext
    pub fn rotates_rows(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        self.validate_ciphertext(ct)?;
        if !self.supports_row_rotation() {
            Err(crate::EvaluationKeyError::Unsupported {
                operation: crate::EvaluationOperation::RowRotation,
            }
            .into())
        } else {
            let row_rotation_element = self.params.degree() * 2 - 1;
            let gk =
                self.gk
                    .get(&row_rotation_element)
                    .ok_or(crate::EvaluationKeyError::Missing {
                        component: crate::EvaluationKeyComponent::GaloisKey {
                            element: row_rotation_element,
                        },
                    })?;
            let mut out = Ciphertext::zero(&ct.params);
            gk.relinearize_into(ct, &mut out)?;
            Ok(out)
        }
    }

    /// Reports whether the evaluation key enables to rotate the columns of the
    /// plaintext.
    #[must_use]
    pub fn supports_column_rotation_by(&self, i: usize) -> bool {
        if let Some(exp) = self.rot_to_gk_exponent.get(&i) {
            self.gk.contains_key(exp)
        } else {
            false
        }
    }

    /// Homomorphically rotate the columns of the plaintext
    pub fn rotates_columns_by(&self, ct: &Ciphertext, i: usize) -> Result<Ciphertext> {
        self.validate_ciphertext(ct)?;
        if !self.supports_column_rotation_by(i) {
            Err(crate::EvaluationKeyError::Unsupported {
                operation: crate::EvaluationOperation::ColumnRotation { step: i },
            }
            .into())
        } else {
            let exponent = self.rot_to_gk_exponent.get(&i).ok_or_else(|| {
                crate::EvaluationKeyError::InvalidRotationStep {
                    step: i,
                    min: 1,
                    max: self.params.degree() / 2 - 1,
                }
            })?;
            let gk = self
                .gk
                .get(exponent)
                .ok_or(crate::EvaluationKeyError::Missing {
                    component: crate::EvaluationKeyComponent::GaloisKey { element: *exponent },
                })?;
            let mut out = Ciphertext::zero(&ct.params);
            gk.relinearize_into(ct, &mut out)?;
            Ok(out)
        }
    }

    /// Reports whether the evaluation key supports oblivious expansion.
    #[must_use]
    pub fn supports_expansion(&self, level: usize) -> bool {
        if level == 0 {
            true
        } else if self.evaluation_key_level == self.params.moduli().len() {
            false
        } else {
            let mut ret = level <= self.params.degree().ilog2() as usize;
            for l in 0..level {
                ret &= self.gk.contains_key(&((self.params.degree() >> l) + 1));
            }
            ret
        }
    }

    /// Obliviously expands the ciphertext. Returns an error if this evaluation
    /// does not support expansion to level = ceil(log2(size)), or if the
    /// ciphertext does not have size 2. The output is a vector of `size`
    /// ciphertexts.
    pub fn expands(&self, ct: &Ciphertext, size: usize) -> Result<Vec<Ciphertext>> {
        self.validate_ciphertext(ct)?;
        if size == 0 {
            return Err(crate::EvaluationKeyError::InvalidExpansionSize {
                size,
                degree: self.params.degree(),
            }
            .into());
        }
        if size > self.params.degree() {
            return Err(crate::EvaluationKeyError::InvalidExpansionSize {
                size,
                degree: self.params.degree(),
            }
            .into());
        }

        let level = size.next_power_of_two().ilog2() as usize;
        if level == 0 {
            Ok(vec![ct.clone()])
        } else if self.supports_expansion(level) {
            let mut out = vec![Ciphertext::zero(&ct.params); 1 << level];
            out[0] = ct.clone();
            let mut sub = Ciphertext::zero(&ct.params);

            // We use the Oblivious expansion algorithm of
            // https://eprint.iacr.org/2019/1483.pdf
            for l in 0..level {
                let monomial = self
                    .monomials
                    .get(l)
                    .ok_or(crate::EvaluationKeyError::Missing {
                        component: crate::EvaluationKeyComponent::ExpansionMonomial { level: l },
                    })?;
                let element = (self.params.degree() >> l) + 1;
                let gk = self
                    .gk
                    .get(&element)
                    .ok_or(crate::EvaluationKeyError::Missing {
                        component: crate::EvaluationKeyComponent::GaloisKey { element },
                    })?;
                let step = 1 << l;
                let (low, high) = out.split_at_mut(step);
                for i in 0..step {
                    gk.relinearize_into(&low[i], &mut sub)?;
                    let j = step | i;
                    if j < size {
                        let target = &mut high[i];
                        target.clone_from(&low[i]);
                        *target -= &sub;
                        target[0] *= monomial;
                        target[1] *= monomial;
                    }
                    low[i] += &sub;
                }
            }
            out.truncate(size);
            Ok(out)
        } else {
            Err(crate::EvaluationKeyError::Unsupported {
                operation: crate::EvaluationOperation::Expansion { level },
            }
            .into())
        }
    }

    fn validate_ciphertext(&self, ct: &Ciphertext) -> Result<()> {
        ct.validate_for(&self.params)?;
        if ct.len() != 2 {
            return Err(crate::CiphertextError::InvalidPolynomialCount {
                operation: crate::CiphertextOperation::EvaluationKey,
                actual: ct.len(),
                expected: 2,
            }
            .into());
        }
        if ct.level != self.ciphertext_level {
            return Err(Error::InvalidLevel {
                level: ct.level,
                min_level: self.ciphertext_level,
                max_level: self.ciphertext_level,
            });
        }
        Ok(())
    }

    fn construct_rot_to_gk_exponent(params: &Arc<BfvParameters>) -> HashMap<usize, usize> {
        let mut m = HashMap::new();
        let q = Modulus::new(2 * params.degree() as u64).unwrap();
        for i in 1..params.degree() / 2 {
            let exp = q.pow(3, i as u64) as usize;
            m.insert(i, exp);
        }
        m
    }
}

impl EvaluationKey {
    /// Finite hard ceiling on the encoded payload accepted by
    /// [`EvaluationKey::from_bytes_with_limit`], in bytes.
    ///
    /// A caller-requested limit is clamped to this value, so even
    /// [`usize::MAX`] never disables it. The ceiling sits well above the
    /// largest evaluation keys used in practice (a degree-32768 key with nine
    /// 62-bit moduli and full inner-sum support encodes to about 309 MB), yet
    /// stays finite so the opt-in route remains a bounded resource: peak
    /// memory during decoding can reach several times the encoded payload
    /// size.
    pub const MAX_DESERIALIZATION_BYTES: usize = 1024 * 1024 * 1024;

    /// Decode an evaluation key with an explicit, caller-supplied payload
    /// bound.
    ///
    /// The default [`fhe_traits::DeserializeParametrized::from_bytes`] route
    /// rejects any payload above the global 256 MiB cap
    /// ([`fhe_traits::MAX_SERIALIZED_BYTES`]). Large parameters exceed that
    /// cap for legitimate keys: a degree-32768 key with nine 62-bit moduli
    /// and inner-sum support encodes to roughly 309 MB. This method is the
    /// opt-in route for such keys.
    ///
    /// # When to use this route
    ///
    /// Only for **authenticated, trusted** large keys whose size you have
    /// budgeted for. The size limit is a denial-of-service guard, not an
    /// authenticity check: raising it means the caller vouches for the
    /// channel that delivered the bytes (for example a key written by this
    /// same process, or delivered over an authenticated transport).
    ///
    /// # Resource requirements
    ///
    /// Decoding a large evaluation key holds the encoded buffer, the decoded
    /// Protobuf representation, and the in-memory key simultaneously, so peak
    /// memory reaches several times the encoded payload size. The end-to-end
    /// test of the 309 MB key (generate, serialize, decode with both keys in
    /// memory) peaks around 4 GiB; a decode without the original key in
    /// memory needs roughly 1.5 GiB on top of the input buffer. Callers must
    /// set `max_bytes` to their own resource budget for the *encoded*
    /// payload; it is clamped to
    /// [`EvaluationKey::MAX_DESERIALIZATION_BYTES`], which applies even when
    /// [`usize::MAX`] is requested.
    ///
    /// The route runs a lightweight, zero-copy wire preflight before `prost`
    /// materializes the message. The preflight scans the payload in place,
    /// recording only a bounded set of normalized Galois key exponents (at
    /// most one per substitution exponent), and enforces the
    /// parameter-implied shape (exact key-switching row counts and bounded row
    /// lengths, level consistency, seed placement), rejects duplicate Galois
    /// key exponents — compared after normalizing modulo `2 * degree`,
    /// matching substitution semantics — and rejects encodings the default
    /// route tolerates: repeated scalar fields (for which `prost` applies
    /// last-wins semantics) and varints wider than the declared `uint32`
    /// fields (which `prost` silently truncates). Hostile payloads of tiny
    /// repeated fields therefore fail with a typed error before significant
    /// memory is committed.
    ///
    /// # Errors
    ///
    /// Returns [`SerializationError::PayloadTooLarge`] when the payload
    /// exceeds the effective bound. Shape violations are rejected by the
    /// preflight before decoding, using the same typed errors as
    /// [`fhe_traits::DeserializeParametrized::from_bytes`]. Two honest
    /// divergences remain: where a payload violates several independent rules
    /// at once, the preflight may report a different one of those typed
    /// errors (or a different ordering) than the default route; and the
    /// strict wire canonical-form rejections above have no default-route
    /// counterpart, because the default route decodes those payloads.
    pub fn from_bytes_with_limit(
        bytes: &[u8],
        params: &Arc<BfvParameters>,
        max_bytes: usize,
    ) -> Result<Self> {
        let limit = deserialization_limit(max_bytes);
        crate::serialization::check_size_with_limit(
            bytes.len(),
            SerializedObject::EvaluationKey,
            limit,
        )?;
        preflight_wire_shape(bytes, params)?;
        let gkp =
            crate::serialization::decode_with_limit(bytes, SerializedObject::EvaluationKey, limit)?;
        EvaluationKey::try_convert_from(&gkp, params)
    }
}

/// Effective encoded-payload bound for
/// [`EvaluationKey::from_bytes_with_limit`]: the caller's budget clamped to
/// the finite hard ceiling.
fn deserialization_limit(max_bytes: usize) -> usize {
    max_bytes.min(EvaluationKey::MAX_DESERIALIZATION_BYTES)
}

impl FheParametrized for EvaluationKey {
    type Parameters = BfvParameters;
}

impl Serialize for EvaluationKey {
    fn to_bytes(&self) -> Vec<u8> {
        EvaluationKeyProto::from(self).encode_to_vec()
    }
}

impl DeserializeParametrized for EvaluationKey {
    type Error = Error;

    fn from_bytes(bytes: &[u8], params: &Arc<Self::Parameters>) -> Result<Self> {
        let gkp = crate::serialization::decode(bytes, crate::SerializedObject::EvaluationKey)?;
        EvaluationKey::try_convert_from(&gkp, params)
    }
}

/// Upper bound on the number of Galois keys a serialized evaluation key may
/// carry for a given parameter set.
///
/// Substitution exponents are odd residues modulo `2 * degree`, so at most
/// `degree` distinct exponents exist; the preflight rejects duplicates, so
/// more entries than that can never decode.
fn maximum_galois_key_count(params: &BfvParameters) -> usize {
    params.degree()
}

/// Extra allowance, in encoded bytes, on top of the parameter-implied
/// coefficient payload of one serialized key-switching row.
///
/// It covers protobuf field tags, varint length prefixes, and
/// forward-compatible unknown fields. A row outside
/// `[row_bytes + WIRE_ROW_MIN_OVERHEAD, row_bytes + WIRE_ROW_SLACK]` can
/// never decode into a polynomial for the declared context.
const WIRE_ROW_SLACK: usize = 64;

/// Minimum encoded overhead, in bytes, of the `Rq` fields that surround the
/// packed coefficient payload of one key-switching row (representation,
/// degree, and coefficient length markers).
const WIRE_ROW_MIN_OVERHEAD: usize = 6;

/// Length of the ChaCha8 seed regenerating the `c1` rows of a
/// key-switching key.
const WIRE_SEED_LENGTH: usize = 32;

/// Counts and scalar fields collected from one serialized key-switching key.
struct KeySwitchingKeyWireCounts {
    c0_count: usize,
    c1_count: usize,
    seed_length: Option<usize>,
    ciphertext_level: usize,
    ksk_level: usize,
    log_base: usize,
}

/// Records a scalar varint field, rejecting duplicate and non-varint
/// encodings.
///
/// The library's encoders write each scalar exactly once; a repeated scalar
/// would make the decoded value depend on `prost` last-wins semantics, so the
/// preflight rejects the payload as non-canonical instead.
fn read_scalar(
    slot: &mut Option<u64>,
    value: WireValue<'_>,
    field: &'static str,
) -> std::result::Result<(), SerializationError> {
    if slot.is_some() {
        return Err(SerializationError::InvalidFormat {
            reason: format!("duplicate {field} field"),
        });
    }
    match value {
        WireValue::Varint(raw) => {
            *slot = Some(raw);
            Ok(())
        }
        WireValue::Bytes(_) | WireValue::Fixed64 | WireValue::Fixed32 => {
            Err(SerializationError::InvalidFormat {
                reason: format!("{field} must be a varint"),
            })
        }
    }
}

/// Converts a declared `uint32` wire value for use as an exponent, level, or
/// decomposition size.
///
/// `prost` silently truncates wider varints when decoding `uint32` fields,
/// aliasing distinct wire values onto one decoded value; the preflight
/// rejects them instead so a bounded decode never disagrees with the bytes on
/// the wire.
fn scalar_as_u32(raw: u64, field: &'static str) -> std::result::Result<u32, SerializationError> {
    u32::try_from(raw).map_err(|_| SerializationError::InvalidFormat {
        reason: format!("{field} value {raw} exceeds uint32"),
    })
}

/// Pre-decode shape validation of a serialized evaluation key.
///
/// The scan borrows the payload in place; its only allocation on the
/// acceptance path is the set of normalized Galois key exponents (bounded by
/// [`maximum_galois_key_count`]), and rejection paths may allocate error
/// messages. It rejects, before `prost` materializes anything: malformed wire
/// structure, duplicate or non-canonical scalar fields, scalar varints wider
/// than their declared `uint32` fields, more Galois key entries than distinct
/// substitution exponents exist, even Galois key exponents and duplicate
/// Galois key exponents (both judged on the exponent normalized modulo
/// `2 * degree`, mirroring [`fhe_math::rq::SubstitutionExponent::new`]),
/// key-switching keys whose declared shape does not match the parameters
/// (levels, decomposition base, exact row counts, row lengths, seed
/// placement), and key-switching levels inconsistent with the outer
/// evaluation-key levels.
///
/// This bounds decoder work and memory for the opt-in decode route; it does
/// not replace the post-decode validation, which remains authoritative. Where
/// a payload violates several independent rules, the preflight may report a
/// different typed error than the default route would.
fn preflight_wire_shape(bytes: &[u8], params: &Arc<BfvParameters>) -> Result<()> {
    let (ciphertext_level, evaluation_key_level, gk_count) = scan_outer_fields(bytes)?;
    if gk_count > maximum_galois_key_count(params) {
        return Err(SerializationError::InvalidFormat {
            reason: format!(
                "evaluation key contains {gk_count} Galois key entries; at most {} distinct substitution exponents exist for degree {}",
                maximum_galois_key_count(params),
                params.degree()
            ),
        }
        .into());
    }

    let ciphertext_level =
        scalar_as_u32(ciphertext_level.unwrap_or(0), "ciphertext_level")? as usize;
    let evaluation_key_level =
        scalar_as_u32(evaluation_key_level.unwrap_or(0), "evaluation_key_level")? as usize;

    // Second outer pass: validate each Galois key entry against the
    // parameter-implied shape. A malformed entry fails before later entries
    // are scanned, so hostile payloads with many repeated fields cost one
    // entry's worth of work.
    let mut seen_exponents: HashSet<usize> = HashSet::new();
    let mut cursor = WireCursor::new(bytes);
    while let Some((field_number, value)) = cursor.next_field()? {
        if field_number == 2 {
            let WireValue::Bytes(gk) = value else {
                return Err(SerializationError::InvalidFormat {
                    reason: "Galois key entry must be a message".to_string(),
                }
                .into());
            };
            scan_galois_key(
                gk,
                params,
                ciphertext_level,
                evaluation_key_level,
                &mut seen_exponents,
            )?;
        }
    }
    Ok(())
}

/// Scans the outer evaluation-key message for its scalar fields and Galois
/// key entry count.
fn scan_outer_fields(
    bytes: &[u8],
) -> std::result::Result<(Option<u64>, Option<u64>, usize), SerializationError> {
    let mut ciphertext_level: Option<u64> = None;
    let mut evaluation_key_level: Option<u64> = None;
    let mut gk_count = 0;
    let mut cursor = WireCursor::new(bytes);
    while let Some((field_number, value)) = cursor.next_field()? {
        match field_number {
            2 => {
                // Entry payloads are validated per entry in the second pass.
                gk_count += 1;
            }
            3 => read_scalar(&mut ciphertext_level, value, "ciphertext_level")?,
            4 => read_scalar(&mut evaluation_key_level, value, "evaluation_key_level")?,
            _ => {}
        }
    }
    Ok((ciphertext_level, evaluation_key_level, gk_count))
}

/// Validates one serialized Galois key entry against the parameters and the
/// outer evaluation-key levels.
fn scan_galois_key(
    gk: &[u8],
    params: &Arc<BfvParameters>,
    outer_ciphertext_level: usize,
    outer_evaluation_key_level: usize,
    seen_exponents: &mut HashSet<usize>,
) -> Result<()> {
    let mut ksk: Option<&[u8]> = None;
    let mut exponent: Option<u64> = None;
    let mut cursor = WireCursor::new(gk);
    while let Some((field_number, value)) = cursor.next_field()? {
        match field_number {
            1 => {
                if ksk.is_some() {
                    return Err(SerializationError::InvalidFormat {
                        reason: "duplicate key-switching key field".to_string(),
                    }
                    .into());
                }
                let WireValue::Bytes(payload) = value else {
                    return Err(SerializationError::InvalidFormat {
                        reason: "key-switching key field must be a message".to_string(),
                    }
                    .into());
                };
                ksk = Some(payload);
            }
            2 => read_scalar(&mut exponent, value, "exponent")?,
            _ => {}
        }
    }

    let ksk = ksk.ok_or(Error::SerializationError(
        SerializationError::MissingField {
            field: SerializedField::GaloisKeySwitchingKey,
        },
    ))?;

    // Strict uint32 parse, then mirror `SubstitutionExponent::new`: it
    // normalizes modulo 2 * degree and rejects even exponents, so the
    // preflight normalizes before duplicate detection (wire exponents that
    // alias one substitution cannot both decode) and produces the same typed
    // error for even exponents, before any key material is built.
    let exponent = exponent.unwrap_or(0);
    let exponent = scalar_as_u32(exponent, "exponent")? as usize;
    let normalized = exponent % (2 * params.degree());
    if normalized & 1 == 0 {
        return Err(Error::MathError(
            fhe_math::Error::InvalidSubstitutionExponent {
                exponent: normalized,
                degree: params.degree(),
            },
        ));
    }
    if !seen_exponents.insert(normalized) {
        return Err(Error::SerializationError(
            SerializationError::DuplicateGaloisExponent {
                exponent: normalized,
            },
        ));
    }

    let counts = scan_key_switching_key_counts(ksk)?;
    let shape = expected_wire_shape(
        params,
        counts.ciphertext_level,
        counts.ksk_level,
        counts.log_base,
    )?;

    // Mirrors the level-consistency check in `TryConvertFrom`; the wire
    // encoder emits the entry levels and the outer levels together, so a
    // disagreement means the payload cannot have been produced by a
    // constructor.
    if counts.ciphertext_level != outer_ciphertext_level {
        return Err(Error::InvalidLevel {
            level: counts.ciphertext_level,
            min_level: outer_ciphertext_level,
            max_level: outer_ciphertext_level,
        });
    }
    if counts.ksk_level != outer_evaluation_key_level {
        return Err(Error::InvalidLevel {
            level: counts.ksk_level,
            min_level: outer_evaluation_key_level,
            max_level: outer_evaluation_key_level,
        });
    }

    // Row-count shape, mirroring `KeySwitchingKey::try_convert_from` with an
    // exact count: zero or missing rows are rejected here too, so `prost`
    // never materializes an entry whose rows cannot decode.
    if counts.c0_count != shape.row_count {
        return Err(Error::SerializationError(
            SerializationError::WrongPolynomialCount {
                component: crate::SerializedPolynomialComponent::KeySwitchingKeyC0,
                expected: shape.row_count,
                actual: counts.c0_count,
            },
        ));
    }
    // Seed and c1 placement, mirroring `KeySwitchingKey::try_convert_from`:
    // a seed and explicit c1 rows cannot coexist, an absent seed requires the
    // full set of c1 rows, and a present seed must be a ChaCha8 seed.
    if counts.seed_length.is_some() && counts.c1_count > 0 {
        return Err(Error::SerializationError(
            SerializationError::InvalidFormat {
                reason: "Key-switching key cannot contain both a seed and explicit c1 polynomials"
                    .to_string(),
            },
        ));
    }
    match counts.seed_length {
        Some(seed_length) => {
            if seed_length != WIRE_SEED_LENGTH {
                return Err(Error::SerializationError(
                    SerializationError::InvalidKeySwitchingSeedLength {
                        actual: seed_length,
                        expected: WIRE_SEED_LENGTH,
                    },
                ));
            }
        }
        None => {
            if counts.c1_count != shape.row_count {
                return Err(Error::SerializationError(
                    SerializationError::WrongPolynomialCount {
                        component: crate::SerializedPolynomialComponent::KeySwitchingKeyC1,
                        expected: shape.row_count,
                        actual: counts.c1_count,
                    },
                ));
            }
        }
    }

    check_key_switching_key_rows(ksk, &shape)
}

/// Collects the repeated-field counts and scalar fields of one serialized
/// key-switching key without materializing its rows.
fn scan_key_switching_key_counts(
    ksk: &[u8],
) -> std::result::Result<KeySwitchingKeyWireCounts, SerializationError> {
    let mut c0_count = 0;
    let mut c1_count = 0;
    let mut seed_length: Option<usize> = None;
    let mut ciphertext_level: Option<u64> = None;
    let mut ksk_level: Option<u64> = None;
    let mut log_base: Option<u64> = None;
    let mut cursor = WireCursor::new(ksk);
    while let Some((field_number, value)) = cursor.next_field()? {
        match field_number {
            1 | 2 => {
                let WireValue::Bytes(_) = value else {
                    return Err(SerializationError::InvalidFormat {
                        reason: "key-switching rows must be length-delimited".to_string(),
                    });
                };
                if field_number == 1 {
                    c0_count += 1;
                } else {
                    c1_count += 1;
                }
            }
            3 => {
                if seed_length.is_some() {
                    return Err(SerializationError::InvalidFormat {
                        reason: "duplicate seed field".to_string(),
                    });
                }
                let WireValue::Bytes(seed) = value else {
                    return Err(SerializationError::InvalidFormat {
                        reason: "seed must be length-delimited".to_string(),
                    });
                };
                seed_length = Some(seed.len());
            }
            4 => read_scalar(&mut ciphertext_level, value, "ciphertext_level")?,
            5 => read_scalar(&mut ksk_level, value, "ksk_level")?,
            6 => read_scalar(&mut log_base, value, "log_base")?,
            _ => {}
        }
    }

    Ok(KeySwitchingKeyWireCounts {
        c0_count,
        c1_count,
        seed_length,
        ciphertext_level: scalar_as_u32(ciphertext_level.unwrap_or(0), "ciphertext_level")?
            as usize,
        ksk_level: scalar_as_u32(ksk_level.unwrap_or(0), "ksk_level")? as usize,
        log_base: scalar_as_u32(log_base.unwrap_or(0), "log_base")? as usize,
    })
}

/// Bounds the encoded length of every key-switching row by the
/// parameter-implied row size, before `prost` copies any of them into the
/// decoded message.
fn check_key_switching_key_rows(ksk: &[u8], shape: &KeySwitchingKeyWireShape) -> Result<()> {
    let minimum = shape.row_bytes + WIRE_ROW_MIN_OVERHEAD;
    let maximum = shape.row_bytes + WIRE_ROW_SLACK;
    let mut cursor = WireCursor::new(ksk);
    while let Some((field_number, value)) = cursor.next_field()? {
        if field_number == 1 || field_number == 2 {
            let WireValue::Bytes(row) = value else {
                return Err(SerializationError::InvalidFormat {
                    reason: "key-switching rows must be length-delimited".to_string(),
                }
                .into());
            };
            if row.len() < minimum || row.len() > maximum {
                return Err(SerializationError::InvalidFormat {
                    reason: format!(
                        "key-switching row has {} bytes; the parameters imply between {minimum} and {maximum}",
                        row.len()
                    ),
                }
                .into());
            }
        }
    }
    Ok(())
}

/// Builder for a leveled evaluation key from the secret key.
#[derive(Debug)]
pub struct EvaluationKeyBuilder {
    sk: SecretKey,
    ciphertext_level: usize,
    evaluation_key_level: usize,
    inner_sum: bool,
    row_rotation: bool,
    expansion_level: usize,
    column_rotation: HashSet<usize>,
    rot_to_gk_exponent: HashMap<usize, usize>,
}

impl Zeroize for EvaluationKeyBuilder {
    fn zeroize(&mut self) {
        self.sk.zeroize()
    }
}

impl ZeroizeOnDrop for EvaluationKeyBuilder {}

impl EvaluationKeyBuilder {
    /// Creates a new builder from the [`SecretKey`].
    pub fn new(sk: &SecretKey) -> Result<Self> {
        Ok(Self {
            sk: sk.clone(),
            ciphertext_level: 0,
            evaluation_key_level: 0,
            inner_sum: false,
            row_rotation: false,
            expansion_level: 0,
            column_rotation: HashSet::new(),
            rot_to_gk_exponent: EvaluationKey::construct_rot_to_gk_exponent(&sk.params),
        })
    }

    /// Creates a new builder from the [`SecretKey`], for operations on
    /// ciphertexts at level `ciphertext_level` using keys at level
    /// `evaluation_key_level`. This raises an error if the key level is larger
    /// than the ciphertext level, or if the ciphertext level is larger than the
    /// maximum level supported by these parameters.
    pub fn new_leveled(
        sk: &SecretKey,
        ciphertext_level: usize,
        evaluation_key_level: usize,
    ) -> Result<Self> {
        if ciphertext_level > sk.params.max_level() {
            return Err(Error::InvalidLevel {
                level: ciphertext_level,
                min_level: 0,
                max_level: sk.params.max_level(),
            });
        }
        if evaluation_key_level > ciphertext_level {
            return Err(Error::InvalidLevel {
                level: evaluation_key_level,
                min_level: 0,
                max_level: ciphertext_level,
            });
        }

        Ok(Self {
            sk: sk.clone(),
            ciphertext_level,
            evaluation_key_level,
            inner_sum: false,
            row_rotation: false,
            expansion_level: 0,
            column_rotation: HashSet::new(),
            rot_to_gk_exponent: EvaluationKey::construct_rot_to_gk_exponent(&sk.params),
        })
    }

    /// Allow expansion by this evaluation key.
    pub fn enable_expansion(&mut self, level: usize) -> Result<&mut Self> {
        let max_level = self.sk.params.degree().ilog2() as usize;
        if level > max_level {
            Err(Error::InvalidLevel {
                level,
                min_level: 0,
                max_level,
            })
        } else {
            self.expansion_level = level;
            Ok(self)
        }
    }

    /// Allow this evaluation key to compute homomorphic inner sums.
    pub fn enable_inner_sum(&mut self) -> Result<&mut Self> {
        self.inner_sum = true;
        Ok(self)
    }

    /// Allow this evaluation key to homomorphically rotate the plaintext rows.
    pub fn enable_row_rotation(&mut self) -> Result<&mut Self> {
        self.row_rotation = true;
        Ok(self)
    }

    /// Allow this evaluation key to homomorphically rotate the plaintext
    /// columns.
    pub fn enable_column_rotation(&mut self, i: usize) -> Result<&mut Self> {
        if let Some(exp) = self.rot_to_gk_exponent.get(&i) {
            self.column_rotation.insert(*exp);
            Ok(self)
        } else {
            Err(crate::EvaluationKeyError::InvalidRotationStep {
                step: i,
                min: 1,
                max: self.sk.params.degree() / 2 - 1,
            }
            .into())
        }
    }

    /// Build an [`EvaluationKey`] with the specified attributes.
    pub fn build<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<EvaluationKey> {
        let mut ek = EvaluationKey {
            gk: HashMap::default(),
            params: self.sk.params.clone(),
            rot_to_gk_exponent: self.rot_to_gk_exponent.clone(),
            monomials: Vec::with_capacity(self.sk.params.degree().ilog2() as usize),
            ciphertext_level: self.ciphertext_level,
            evaluation_key_level: self.evaluation_key_level,
        };

        let mut indices = self.column_rotation.clone();

        if self.row_rotation {
            indices.insert(self.sk.params.degree() * 2 - 1);
        }

        if self.inner_sum {
            // Add the required indices to the set of indices
            indices.insert(self.sk.params.degree() * 2 - 1);
            let mut i = 1;
            while i < self.sk.params.degree() / 2 {
                let exponent =
                    ek.rot_to_gk_exponent
                        .get(&i)
                        .ok_or(crate::EvaluationKeyError::Missing {
                            component: crate::EvaluationKeyComponent::GaloisExponent { step: i },
                        })?;
                indices.insert(*exponent);
                i *= 2
            }
        }

        for l in 0..self.expansion_level {
            indices.insert((self.sk.params.degree() >> l) + 1);
        }

        let ciphertext_ctx = self.sk.params.context_at_level(self.ciphertext_level)?;
        for l in 0..self.sk.params.degree().ilog2() {
            let mut monomial = vec![0i64; self.sk.params.degree()];
            monomial[self.sk.params.degree() - (1 << l)] = -1;
            let monomial = Poly::<PowerBasis>::try_convert_from_public(
                &monomial,
                ciphertext_ctx,
                fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public()),
            )?;
            ek.monomials.push(monomial.into_ntt_shoup());
        }

        for index in indices {
            ek.gk.insert(
                index,
                GaloisKey::new(
                    &self.sk,
                    index,
                    self.ciphertext_level,
                    self.evaluation_key_level,
                    rng,
                )?,
            );
        }

        Ok(ek)
    }
}

impl From<&EvaluationKey> for EvaluationKeyProto {
    fn from(ek: &EvaluationKey) -> Self {
        let mut proto = EvaluationKeyProto::default();
        for gk in ek.gk.values() {
            proto.gk.push(GaloisKeyProto::from(gk))
        }
        proto.ciphertext_level = ek.ciphertext_level as u32;
        proto.evaluation_key_level = ek.evaluation_key_level as u32;
        proto
    }
}

impl TryConvertFrom<&EvaluationKeyProto> for EvaluationKey {
    fn try_convert_from(value: &EvaluationKeyProto, params: &Arc<BfvParameters>) -> Result<Self> {
        let mut gk = HashMap::new();
        for gkp in &value.gk {
            let key = GaloisKey::try_convert_from(gkp, params)?;
            if key.ksk.ciphertext_level != value.ciphertext_level as usize {
                return Err(Error::InvalidLevel {
                    level: key.ksk.ciphertext_level,
                    min_level: value.ciphertext_level as usize,
                    max_level: value.ciphertext_level as usize,
                });
            }
            if key.ksk.ksk_level != value.evaluation_key_level as usize {
                return Err(Error::InvalidLevel {
                    level: key.ksk.ksk_level,
                    min_level: value.evaluation_key_level as usize,
                    max_level: value.evaluation_key_level as usize,
                });
            }
            // Two Galois keys for the same exponent cannot be produced by a
            // constructor; the previous silent last-wins replacement would
            // make the decoded key depend on message ordering.
            let exponent = key.element.exponent;
            if gk.insert(exponent, key).is_some() {
                return Err(Error::SerializationError(
                    SerializationError::DuplicateGaloisExponent { exponent },
                ));
            }
        }

        let ciphertext_ctx = params.context_at_level(value.ciphertext_level as usize)?;
        let mut monomials = Vec::with_capacity(params.degree().ilog2() as usize);
        for l in 0..params.degree().ilog2() {
            let mut monomial = vec![0i64; params.degree()];
            monomial[params.degree() - (1 << l)] = -1;
            let monomial = Poly::<PowerBasis>::try_convert_from_public(
                &monomial,
                ciphertext_ctx,
                fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public()),
            )?;
            monomials.push(monomial.into_ntt_shoup());
        }

        Ok(EvaluationKey {
            gk,
            params: params.clone(),
            rot_to_gk_exponent: EvaluationKey::construct_rot_to_gk_exponent(params),
            monomials,
            ciphertext_level: value.ciphertext_level as usize,
            evaluation_key_level: value.evaluation_key_level as usize,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{EvaluationKey, EvaluationKeyBuilder};
    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey, traits::TryConvertFrom};
    use crate::proto::bfv::EvaluationKey as LeveledEvaluationKeyProto;
    use fhe_traits::{
        DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
    };
    use itertools::izip;
    use prost::Message;
    use rand::rng;
    use std::{cmp::min, error::Error, sync::Arc};

    #[test]
    fn builder() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 16);
        let sk = SecretKey::random(&params, &mut rng);

        let max_level = params.max_level();
        for ciphertext_level in 0..=max_level {
            for evaluation_key_level in 0..=min(max_level, ciphertext_level) {
                let mut builder =
                    EvaluationKeyBuilder::new_leveled(&sk, ciphertext_level, evaluation_key_level)?;

                assert!(!builder.build(&mut rng)?.supports_row_rotation());
                assert!(!builder.build(&mut rng)?.supports_column_rotation_by(0));
                assert!(!builder.build(&mut rng)?.supports_column_rotation_by(1));
                assert!(!builder.build(&mut rng)?.supports_inner_sum());
                assert!(!builder.build(&mut rng)?.supports_expansion(1));
                assert!(builder.build(&mut rng)?.supports_expansion(0));
                assert!(builder.enable_column_rotation(0).is_err());
                assert!(
                    builder
                        .enable_expansion(64 - params.degree().leading_zeros() as usize)
                        .is_err()
                );

                builder.enable_column_rotation(1)?;
                assert!(builder.build(&mut rng)?.supports_column_rotation_by(1));
                assert!(!builder.build(&mut rng)?.supports_row_rotation());
                assert!(!builder.build(&mut rng)?.supports_inner_sum());
                assert!(!builder.build(&mut rng)?.supports_expansion(1));

                builder.enable_row_rotation()?;
                assert!(builder.build(&mut rng)?.supports_row_rotation());
                assert!(!builder.build(&mut rng)?.supports_inner_sum());
                assert!(!builder.build(&mut rng)?.supports_expansion(1));

                builder.enable_inner_sum()?;
                assert!(builder.build(&mut rng)?.supports_inner_sum());
                assert!(builder.build(&mut rng)?.supports_expansion(1));
                assert!(
                    !builder
                        .build(&mut rng)?
                        .supports_expansion(64 - 1 - params.degree().leading_zeros() as usize)
                );

                builder.enable_expansion(64 - 1 - params.degree().leading_zeros() as usize)?;
                assert!(
                    builder
                        .build(&mut rng)?
                        .supports_expansion(64 - 1 - params.degree().leading_zeros() as usize)
                );

                assert!(builder.build(&mut rng).is_ok());

                // Enabling inner sum enables row rotation and a few column rotations :)
                let ek = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)?
                    .enable_inner_sum()?
                    .build(&mut rng)?;
                assert!(ek.supports_inner_sum());
                assert!(ek.supports_row_rotation());
                let mut i = 1;
                while i < params.degree() / 2 {
                    assert!(ek.supports_column_rotation_by(i));
                    i *= 2
                }
                assert!(!ek.supports_column_rotation_by(params.degree() / 2 - 1));
            }
        }

        let e = EvaluationKeyBuilder::new_leveled(&sk, 0, 1);
        assert!(e.is_err());
        assert_eq!(
            e.unwrap_err(),
            crate::Error::InvalidLevel {
                level: 1,
                min_level: 0,
                max_level: 0,
            }
        );

        Ok(())
    }

    #[test]
    fn inner_sum() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(6, 16),
            BfvParameters::default_arc(5, 16),
        ] {
            for _ in 0..25 {
                for ciphertext_level in 0..=params.max_level() {
                    for evaluation_key_level in 0..=min(params.max_level() - 1, ciphertext_level) {
                        let sk = SecretKey::random(&params, &mut rng);
                        let ek = EvaluationKeyBuilder::new_leveled(
                            &sk,
                            ciphertext_level,
                            evaluation_key_level,
                        )?
                        .enable_inner_sum()?
                        .build(&mut rng)?;

                        let v = fhe_math::zq::Modulus::new(params.plaintext())
                            .unwrap()
                            .random_vec(params.degree(), &mut rng);
                        let expected = fhe_math::zq::Modulus::new(params.plaintext())
                            .unwrap()
                            .reduce_u128(v.iter().map(|vi| *vi as u128).sum());

                        let pt = Plaintext::try_encode(
                            &v,
                            Encoding::simd_at_level(ciphertext_level),
                            &params,
                        )?;
                        let ct = sk.try_encrypt(&pt, &mut rng)?;

                        let ct2 = ek.computes_inner_sum(&ct)?;
                        let pt = sk.try_decrypt(&ct2)?;
                        assert_eq!(
                            Vec::<u64>::try_decode(&pt, Encoding::simd_at_level(ciphertext_level))?,
                            vec![expected; params.degree()]
                        )
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn row_rotation() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(6, 16),
            BfvParameters::default_arc(5, 16),
        ] {
            for _ in 0..50 {
                for ciphertext_level in 0..=params.max_level() {
                    for evaluation_key_level in 0..=min(params.max_level() - 1, ciphertext_level) {
                        let sk = SecretKey::random(&params, &mut rng);
                        let ek = EvaluationKeyBuilder::new_leveled(
                            &sk,
                            ciphertext_level,
                            evaluation_key_level,
                        )?
                        .enable_row_rotation()?
                        .build(&mut rng)?;

                        let v = fhe_math::zq::Modulus::new(params.plaintext())
                            .unwrap()
                            .random_vec(params.degree(), &mut rng);
                        let row_size = params.degree() >> 1;
                        let mut expected = vec![0u64; params.degree()];
                        expected[..row_size].copy_from_slice(&v[row_size..]);
                        expected[row_size..].copy_from_slice(&v[..row_size]);

                        let pt = Plaintext::try_encode(
                            &v,
                            Encoding::simd_at_level(ciphertext_level),
                            &params,
                        )?;
                        let ct = sk.try_encrypt(&pt, &mut rng)?;

                        let ct2 = ek.rotates_rows(&ct)?;
                        let pt = sk.try_decrypt(&ct2)?;
                        assert_eq!(
                            Vec::<u64>::try_decode(&pt, Encoding::simd_at_level(ciphertext_level))?,
                            expected
                        )
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn column_rotation() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(6, 16),
            BfvParameters::default_arc(5, 16),
        ] {
            let row_size = params.degree() >> 1;
            for _ in 0..50 {
                for i in 1..row_size {
                    for ciphertext_level in 0..=params.max_level() {
                        for evaluation_key_level in 0..=min(params.max_level(), ciphertext_level) {
                            let sk = SecretKey::random(&params, &mut rng);
                            let ek = EvaluationKeyBuilder::new_leveled(
                                &sk,
                                ciphertext_level,
                                evaluation_key_level,
                            )?
                            .enable_column_rotation(i)?
                            .build(&mut rng)?;

                            let v = fhe_math::zq::Modulus::new(params.plaintext())
                                .unwrap()
                                .random_vec(params.degree(), &mut rng);
                            let row_size = params.degree() >> 1;
                            let mut expected = vec![0u64; params.degree()];
                            expected[..row_size - i].copy_from_slice(&v[i..row_size]);
                            expected[row_size - i..row_size].copy_from_slice(&v[..i]);
                            expected[row_size..2 * row_size - i]
                                .copy_from_slice(&v[row_size + i..]);
                            expected[2 * row_size - i..]
                                .copy_from_slice(&v[row_size..row_size + i]);

                            let pt = Plaintext::try_encode(
                                &v,
                                Encoding::simd_at_level(ciphertext_level),
                                &params,
                            )?;
                            let ct = sk.try_encrypt(&pt, &mut rng)?;

                            let ct2 = ek.rotates_columns_by(&ct, i)?;
                            let pt = sk.try_decrypt(&ct2)?;
                            assert_eq!(
                                Vec::<u64>::try_decode(
                                    &pt,
                                    Encoding::simd_at_level(ciphertext_level)
                                )?,
                                expected
                            )
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn expansion() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(6, 16),
            BfvParameters::default_arc(5, 16),
        ] {
            let log_degree = 64 - 1 - params.degree().leading_zeros();
            for _ in 0..15 {
                for i in 1..1 + log_degree as usize {
                    for ciphertext_level in 0..=params.max_level() {
                        for evaluation_key_level in 0..=min(params.max_level(), ciphertext_level) {
                            let sk = SecretKey::random(&params, &mut rng);
                            let ek = EvaluationKeyBuilder::new_leveled(
                                &sk,
                                ciphertext_level,
                                evaluation_key_level,
                            )?
                            .enable_expansion(i)?
                            .build(&mut rng)?;

                            assert!(ek.supports_expansion(i));
                            assert!(!ek.supports_expansion(i + 1));
                            let v = fhe_math::zq::Modulus::new(params.plaintext())
                                .unwrap()
                                .random_vec(1 << i, &mut rng);
                            let pt = Plaintext::try_encode(
                                &v,
                                Encoding::poly_at_level(ciphertext_level),
                                &params,
                            )?;
                            let ct = sk.try_encrypt(&pt, &mut rng)?;

                            let ct2 = ek.expands(&ct, 1 << i)?;
                            assert_eq!(ct2.len(), 1 << i);
                            for (vi, ct2i) in izip!(&v, &ct2) {
                                let mut expected = vec![0u64; params.degree()];
                                expected[0] = fhe_math::zq::Modulus::new(params.plaintext())
                                    .unwrap()
                                    .mul(*vi, (1 << i) as u64);
                                let pt = sk.try_decrypt(ct2i)?;
                                assert_eq!(
                                    expected,
                                    Vec::<u64>::try_decode(
                                        &pt,
                                        Encoding::poly_at_level(ciphertext_level)
                                    )?
                                );
                                println!("Noise: {:?}", unsafe { sk.measure_noise(ct2i) })
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn expansion_rejects_invalid_sizes() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let ek = EvaluationKeyBuilder::new(&sk)?
            .enable_expansion(1)?
            .build(&mut rng)?;
        let pt = Plaintext::try_encode(&[1u64][..], Encoding::poly(), &params)?;
        let ct = sk.try_encrypt(&pt, &mut rng)?;

        assert_eq!(
            ek.expands(&ct, 0),
            Err(crate::Error::EvaluationKey(
                crate::EvaluationKeyError::InvalidExpansionSize {
                    size: 0,
                    degree: params.degree(),
                }
            ))
        );
        assert_eq!(
            ek.expands(&ct, params.degree() + 1),
            Err(crate::Error::EvaluationKey(
                crate::EvaluationKeyError::InvalidExpansionSize {
                    size: params.degree() + 1,
                    degree: params.degree(),
                }
            ))
        );
        Ok(())
    }

    #[test]
    fn proto_conversion() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 16),
            BfvParameters::default_arc(5, 16),
        ] {
            let sk = SecretKey::random(&params, &mut rng);

            let ek = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)?.build(&mut rng)?;

            let proto = LeveledEvaluationKeyProto::from(&ek);
            assert_eq!(ek, EvaluationKey::try_convert_from(&proto, &params)?);

            let ek = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)?
                .enable_row_rotation()?
                .build(&mut rng)?;

            let proto = LeveledEvaluationKeyProto::from(&ek);
            assert_eq!(ek, EvaluationKey::try_convert_from(&proto, &params)?);

            let ek = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)?
                .enable_inner_sum()?
                .build(&mut rng)?;
            let proto = LeveledEvaluationKeyProto::from(&ek);
            assert_eq!(ek, EvaluationKey::try_convert_from(&proto, &params)?);

            let ek = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)?
                .enable_expansion(params.degree().ilog2() as usize)?
                .build(&mut rng)?;
            let proto = LeveledEvaluationKeyProto::from(&ek);
            assert_eq!(ek, EvaluationKey::try_convert_from(&proto, &params)?);

            let ek = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)?
                .enable_inner_sum()?
                .enable_expansion(params.degree().ilog2() as usize)?
                .build(&mut rng)?;
            let proto = LeveledEvaluationKeyProto::from(&ek);
            assert_eq!(ek, EvaluationKey::try_convert_from(&proto, &params)?);
        }
        Ok(())
    }

    #[test]
    fn serialize() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 16),
            BfvParameters::default_arc(6, 16),
        ] {
            let sk = SecretKey::random(&params, &mut rng);

            let ek = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)?.build(&mut rng)?;
            let bytes = ek.to_bytes();
            assert_eq!(ek, EvaluationKey::from_bytes(&bytes, &params)?);

            if params.moduli.len() > 1 {
                let ek = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)?
                    .enable_row_rotation()?
                    .build(&mut rng)?;
                let bytes = ek.to_bytes();
                assert_eq!(ek, EvaluationKey::from_bytes(&bytes, &params)?);

                let ek = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)?
                    .enable_inner_sum()?
                    .build(&mut rng)?;
                let bytes = ek.to_bytes();
                assert_eq!(ek, EvaluationKey::from_bytes(&bytes, &params)?);

                let ek = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)?
                    .enable_expansion(params.degree().ilog2() as usize)?
                    .build(&mut rng)?;
                let bytes = ek.to_bytes();
                assert_eq!(ek, EvaluationKey::from_bytes(&bytes, &params)?);

                let ek = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)?
                    .enable_inner_sum()?
                    .enable_expansion(params.degree().ilog2() as usize)?
                    .build(&mut rng)?;
                let bytes = ek.to_bytes();
                assert_eq!(ek, EvaluationKey::from_bytes(&bytes, &params)?);
            }
        }
        Ok(())
    }

    /// Logical encoded size of the degree-32768, nine-62-bit-moduli
    /// inner-sum evaluation key reported in issue #246.
    const LARGE_KEY_LOGICAL_BYTES: usize = 308_554_552;

    /// Builds a small evaluation key with several Galois keys for the
    /// bounded-deserialization tests.
    fn inner_sum_key(
        num_moduli: usize,
        degree: usize,
    ) -> Result<(Arc<BfvParameters>, EvaluationKey), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(num_moduli, degree);
        let sk = SecretKey::random(&params, &mut rng);
        let ek = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)?
            .enable_inner_sum()?
            .build(&mut rng)?;
        Ok((params, ek))
    }

    #[test]
    fn bounded_route_roundtrips_like_the_default_route() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(6, 16)?;
        let bytes = ek.to_bytes();
        assert_eq!(
            ek,
            EvaluationKey::from_bytes_with_limit(&bytes, &params, usize::MAX)?
        );
        assert_eq!(
            ek,
            EvaluationKey::from_bytes_with_limit(&bytes, &params, bytes.len())?
        );
        assert_eq!(ek, EvaluationKey::from_bytes(&bytes, &params)?);
        Ok(())
    }

    #[test]
    fn bounded_route_roundtrips_leveled_decomposition_keys() -> Result<(), Box<dyn Error>> {
        // At the maximal ciphertext and key level the key context has a single
        // modulus, so the wire rows use the base-2^(log_modulus/2)
        // decomposition instead of the standard RNS decomposition; the
        // preflight must admit exactly that shape.
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let max_level = params.max_level();
        let ek = EvaluationKeyBuilder::new_leveled(&sk, max_level, max_level)?
            .enable_inner_sum()?
            .build(&mut rng)?;
        let bytes = ek.to_bytes();
        assert_eq!(
            ek,
            EvaluationKey::from_bytes_with_limit(&bytes, &params, usize::MAX)?
        );
        assert_eq!(ek, EvaluationKey::from_bytes(&bytes, &params)?);
        Ok(())
    }

    #[test]
    fn caller_limit_is_enforced_before_decoding() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(3, 16)?;
        let bytes = ek.to_bytes();
        for limit in [0, 1, bytes.len() - 1] {
            assert_eq!(
                EvaluationKey::from_bytes_with_limit(&bytes, &params, limit).unwrap_err(),
                crate::Error::SerializationError(crate::SerializationError::PayloadTooLarge {
                    object: crate::SerializedObject::EvaluationKey,
                    actual: bytes.len(),
                    maximum: limit,
                }),
                "limit {limit} must reject the {}-byte payload before decoding",
                bytes.len()
            );
        }
        Ok(())
    }

    #[test]
    fn hard_ceiling_caps_any_caller_requested_limit() {
        const {
            assert!(
                EvaluationKey::MAX_DESERIALIZATION_BYTES > LARGE_KEY_LOGICAL_BYTES,
                "the ceiling must stay above the reported 309 MB key"
            );
        }
        assert_eq!(
            super::deserialization_limit(usize::MAX),
            EvaluationKey::MAX_DESERIALIZATION_BYTES,
            "the ceiling applies even to usize::MAX"
        );
        assert_eq!(
            super::deserialization_limit(LARGE_KEY_LOGICAL_BYTES),
            LARGE_KEY_LOGICAL_BYTES,
            "a caller budget at the reported key size must be honored as-is"
        );
    }

    #[test]
    fn default_cap_rejects_large_keys_and_the_opt_in_ceiling_admits_the_length() {
        // A payload one byte over the global cap. `vec![0u8; n]` is lazily
        // backed by zero pages, so this test verifies the size policy without
        // touching 256 MiB of memory; the end-to-end roundtrip of a real
        // large key is the ignored test below.
        let oversized = vec![0u8; fhe_traits::MAX_SERIALIZED_BYTES + 1];
        let params = BfvParameters::default_arc(1, 16);

        assert_eq!(
            EvaluationKey::from_bytes(&oversized, &params).unwrap_err(),
            crate::Error::SerializationError(crate::SerializationError::PayloadTooLarge {
                object: crate::SerializedObject::EvaluationKey,
                actual: fhe_traits::MAX_SERIALIZED_BYTES + 1,
                maximum: fhe_traits::MAX_SERIALIZED_BYTES,
            }),
            "the default route must keep the global 256 MiB cap"
        );

        // The opt-in ceiling admits the length, so the failure must come from
        // the payload contents (the wire preflight rejects the zero-filled
        // bytes), not from a size rejection.
        let error =
            EvaluationKey::from_bytes_with_limit(&oversized, &params, usize::MAX).unwrap_err();
        assert!(
            !matches!(
                error,
                crate::Error::SerializationError(crate::SerializationError::PayloadTooLarge { .. })
            ),
            "the ceiling must admit a {}-byte payload, got {error}",
            oversized.len()
        );
    }

    #[test]
    fn opt_in_preflight_and_default_route_reject_duplicate_galois_exponents()
    -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(3, 16)?;
        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        let Some(duplicate) = proto.gk.first().cloned() else {
            return Err(crate::Error::DefaultError(
                "test key must contain Galois keys".to_string(),
            )
            .into());
        };
        let exponent = duplicate.exponent as usize;
        proto.gk.push(duplicate);
        let bytes = proto.encode_to_vec();

        let expected =
            crate::Error::SerializationError(crate::SerializationError::DuplicateGaloisExponent {
                exponent,
            });
        assert_eq!(
            EvaluationKey::from_bytes(&bytes, &params).unwrap_err(),
            expected,
            "the default route must reject duplicates after decoding"
        );
        assert_eq!(
            EvaluationKey::from_bytes_with_limit(&bytes, &params, usize::MAX).unwrap_err(),
            expected,
            "the opt-in preflight must reject duplicates before decoding"
        );
        Ok(())
    }

    #[test]
    fn opt_in_preflight_and_default_route_reject_excess_repeated_rows() -> Result<(), Box<dyn Error>>
    {
        let (params, ek) = inner_sum_key(3, 16)?;
        let row_count = params.moduli().len();
        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        let some_ksk = proto
            .gk
            .first_mut()
            .and_then(|gk| gk.ksk.as_mut())
            .ok_or_else(|| {
                crate::Error::DefaultError("test key must contain key-switching keys".to_string())
            })?;
        let Some(extra) = some_ksk.c0.first().cloned() else {
            return Err(crate::Error::DefaultError(
                "test key must contain key-switching rows".to_string(),
            )
            .into());
        };
        some_ksk.c0.push(extra);
        let bytes = proto.encode_to_vec();

        let expected =
            crate::Error::SerializationError(crate::SerializationError::WrongPolynomialCount {
                component: crate::SerializedPolynomialComponent::KeySwitchingKeyC0,
                expected: row_count,
                actual: row_count + 1,
            });
        assert_eq!(
            EvaluationKey::from_bytes(&bytes, &params).unwrap_err(),
            expected,
            "the default route must reject excess rows after decoding"
        );
        assert_eq!(
            EvaluationKey::from_bytes_with_limit(&bytes, &params, usize::MAX).unwrap_err(),
            expected,
            "the opt-in preflight must reject excess rows before decoding"
        );
        Ok(())
    }

    #[test]
    fn opt_in_preflight_rejects_a_flood_of_tiny_repeated_fields() -> Result<(), Box<dyn Error>> {
        // A few dozen bytes claiming 50 key-switching rows for parameters
        // that imply 3. The preflight counts rows without materializing them.
        let (params, _ek) = inner_sum_key(3, 16)?;
        let ksk = [0x0a, 0x00].repeat(50); // 50 empty c0 entries
        let mut gk = vec![0x10, 0x01]; // exponent 1 (odd, distinct from the key's exponents)
        gk.extend_from_slice(&[0x0a, ksk.len() as u8]); // ksk field, short enough for a 1-byte length
        gk.extend_from_slice(&ksk);
        let mut outer = vec![0x12, gk.len() as u8]; // gk field
        outer.extend_from_slice(&gk);

        let expected =
            crate::Error::SerializationError(crate::SerializationError::WrongPolynomialCount {
                component: crate::SerializedPolynomialComponent::KeySwitchingKeyC0,
                expected: params.moduli().len(),
                actual: 50,
            });
        assert_eq!(
            EvaluationKey::from_bytes_with_limit(&outer, &params, usize::MAX).unwrap_err(),
            expected,
            "the preflight must reject excess rows before decoding"
        );
        assert_eq!(
            EvaluationKey::from_bytes(&outer, &params).unwrap_err(),
            expected,
            "the default route must reject the same shape"
        );
        Ok(())
    }

    #[test]
    fn opt_in_preflight_rejects_exponents_that_alias_one_substitution() -> Result<(), Box<dyn Error>>
    {
        // Wire exponents e and e + 2 * degree normalize to the same
        // substitution exponent, so they must collide in the duplicate
        // check even though their wire values differ.
        let (params, ek) = inner_sum_key(3, 16)?;
        let degree = params.degree() as u32;
        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        let first = proto.gk.first().cloned().ok_or_else(|| {
            crate::Error::DefaultError("test key must contain Galois keys".to_string())
        })?;
        let second = proto.gk.get_mut(1).ok_or_else(|| {
            crate::Error::DefaultError("test key must contain two Galois keys".to_string())
        })?;
        second.exponent = first.exponent + 2 * degree;
        let aliased = first.exponent as usize;
        let bytes = proto.encode_to_vec();

        let expected =
            crate::Error::SerializationError(crate::SerializationError::DuplicateGaloisExponent {
                exponent: aliased,
            });
        assert_eq!(
            EvaluationKey::from_bytes_with_limit(&bytes, &params, usize::MAX).unwrap_err(),
            expected,
            "the preflight must detect the alias before decoding"
        );
        assert_eq!(
            EvaluationKey::from_bytes(&bytes, &params).unwrap_err(),
            expected,
            "the default route must detect the alias after decoding"
        );
        Ok(())
    }

    #[test]
    fn opt_in_preflight_mirrors_the_even_exponent_rejection() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(3, 16)?;
        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        let first = proto.gk.first_mut().ok_or_else(|| {
            crate::Error::DefaultError("test key must contain Galois keys".to_string())
        })?;
        first.exponent = 4;
        let bytes = proto.encode_to_vec();

        let expected = crate::Error::MathError(fhe_math::Error::InvalidSubstitutionExponent {
            exponent: 4,
            degree: params.degree(),
        });
        assert_eq!(
            EvaluationKey::from_bytes_with_limit(&bytes, &params, usize::MAX).unwrap_err(),
            expected,
            "the preflight must mirror the even-exponent rejection"
        );
        assert_eq!(
            EvaluationKey::from_bytes(&bytes, &params).unwrap_err(),
            expected,
            "the default route rejects the same exponent with the same error"
        );
        Ok(())
    }

    #[test]
    fn opt_in_preflight_rejects_scalar_varints_wider_than_uint32() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(3, 16)?;
        // Varint encoding of 2^32 + 1, which `prost` silently truncates to 1
        // when decoding a `uint32` field.
        let wide_varint = [0x81u8, 0x80, 0x80, 0x80, 0x10];

        // A Galois key entry with an over-u32 exponent appended to an
        // otherwise valid serialization.
        let mut wide_exponent = ek.to_bytes();
        wide_exponent
            .extend_from_slice(&[0x12, 0x08, 0x0a, 0x00, 0x10, 0x81, 0x80, 0x80, 0x80, 0x10]);
        let error =
            EvaluationKey::from_bytes_with_limit(&wide_exponent, &params, usize::MAX).unwrap_err();
        assert!(
            matches!(
                error,
                crate::Error::SerializationError(crate::SerializationError::InvalidFormat {
                    reason: _
                })
            ) && error.to_string().contains("exceeds uint32"),
            "the preflight must reject the over-u32 exponent, got {error}"
        );

        // An over-u32 ciphertext level appended to an otherwise valid
        // serialization. The default route truncates it to level 1 and fails
        // later, on level consistency; the truncation itself is exactly what
        // the opt-in route refuses, so the default outcome is intentionally
        // not asserted here.
        let mut wide_level = ek.to_bytes();
        wide_level.extend_from_slice(&[0x18]);
        wide_level.extend_from_slice(&wide_varint);
        let error =
            EvaluationKey::from_bytes_with_limit(&wide_level, &params, usize::MAX).unwrap_err();
        assert!(
            error.to_string().contains("exceeds uint32"),
            "the preflight must reject the over-u32 level, got {error}"
        );
        let _ = EvaluationKey::from_bytes(&wide_level, &params);
        Ok(())
    }

    #[test]
    fn opt_in_preflight_rejects_missing_key_switching_rows() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(3, 16)?;
        let row_count = params.moduli().len();
        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        let some_ksk = proto
            .gk
            .first_mut()
            .and_then(|gk| gk.ksk.as_mut())
            .ok_or_else(|| {
                crate::Error::DefaultError("test key must contain key-switching keys".to_string())
            })?;
        some_ksk.c0.clear();
        let bytes = proto.encode_to_vec();

        let expected =
            crate::Error::SerializationError(crate::SerializationError::WrongPolynomialCount {
                component: crate::SerializedPolynomialComponent::KeySwitchingKeyC0,
                expected: row_count,
                actual: 0,
            });
        assert_eq!(
            EvaluationKey::from_bytes_with_limit(&bytes, &params, usize::MAX).unwrap_err(),
            expected,
            "the preflight must reject missing rows before decoding"
        );
        assert_eq!(
            EvaluationKey::from_bytes(&bytes, &params).unwrap_err(),
            expected,
            "the default route must reject the same shape"
        );
        Ok(())
    }

    #[test]
    fn opt_in_preflight_rejects_the_first_malformed_entry_without_decoding()
    -> Result<(), Box<dyn Error>> {
        // Append two entries to a valid serialization: one whose key-switching
        // key has no c0 rows (a shape violation), and one whose bytes are not
        // decodable by `prost` at all. The opt-in route reports the shape
        // violation of the first entry, which proves the preflight rejected
        // the payload before the decoder ran — a decode would have surfaced
        // the trailing wire error instead, as the default route does.
        let (params, ek) = inner_sum_key(3, 16)?;
        let row_count = params.moduli().len();
        let mut bytes = ek.to_bytes();
        bytes.extend_from_slice(&[0x12, 0x04, 0x10, 0x01, 0x0a, 0x00]);
        bytes.extend_from_slice(&[0x12, 0x03, 0x0a, 0x01, 0x0a]);

        let error = EvaluationKey::from_bytes_with_limit(&bytes, &params, usize::MAX).unwrap_err();
        assert_eq!(
            error,
            crate::Error::SerializationError(crate::SerializationError::WrongPolynomialCount {
                component: crate::SerializedPolynomialComponent::KeySwitchingKeyC0,
                expected: row_count,
                actual: 0,
            }),
            "the first malformed entry must be rejected before decoding"
        );
        let default_error = EvaluationKey::from_bytes(&bytes, &params).unwrap_err();
        assert!(
            matches!(
                default_error,
                crate::Error::SerializationError(crate::SerializationError::Decode { .. })
            ),
            "the default route fails in the decoder on the same payload, got {default_error}"
        );
        Ok(())
    }

    #[test]
    fn opt_in_preflight_rejects_more_galois_entries_than_distinct_exponents()
    -> Result<(), Box<dyn Error>> {
        // Degree 16 admits 16 distinct odd substitution exponents; 17 entries
        // (each an empty Galois key message) are rejected without scanning
        // any entry.
        let (params, _ek) = inner_sum_key(1, 16)?;
        let mut outer = Vec::new();
        for _ in 0..=params.degree() {
            outer.extend_from_slice(&[0x12, 0x00]);
        }

        let error = EvaluationKey::from_bytes_with_limit(&outer, &params, usize::MAX).unwrap_err();
        assert!(
            matches!(
                error,
                crate::Error::SerializationError(crate::SerializationError::InvalidFormat { .. })
            ),
            "expected the entry-count bound, got {error}"
        );
        assert!(EvaluationKey::from_bytes(&outer, &params).is_err());
        Ok(())
    }

    #[test]
    fn opt_in_preflight_rejects_wrong_length_rows_before_decoding() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(3, 16)?;
        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        let some_ksk = proto
            .gk
            .first_mut()
            .and_then(|gk| gk.ksk.as_mut())
            .ok_or_else(|| {
                crate::Error::DefaultError("test key must contain key-switching keys".to_string())
            })?;
        // Replace the first c0 row with one that can never hold the packed
        // coefficients of the declared context. Prost decodes it happily; the
        // preflight must reject it first.
        let Some(first_row) = some_ksk.c0.first_mut() else {
            return Err(crate::Error::DefaultError(
                "test key must contain key-switching rows".to_string(),
            )
            .into());
        };
        *first_row = vec![0u8; 4];
        let bytes = proto.encode_to_vec();

        let error = EvaluationKey::from_bytes_with_limit(&bytes, &params, usize::MAX).unwrap_err();
        assert!(
            matches!(
                error,
                crate::Error::SerializationError(crate::SerializationError::InvalidFormat { .. })
            ),
            "the preflight must reject the row length, got {error}"
        );
        // The default route rejects the same payload, but only after decoding.
        assert!(EvaluationKey::from_bytes(&bytes, &params).is_err());
        Ok(())
    }

    #[test]
    fn opt_in_preflight_mirrors_the_seed_rules() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(3, 16)?;

        // A seed with the wrong length.
        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        let some_ksk = proto
            .gk
            .first_mut()
            .and_then(|gk| gk.ksk.as_mut())
            .ok_or_else(|| {
                crate::Error::DefaultError("test key must contain key-switching keys".to_string())
            })?;
        some_ksk.seed = vec![0u8; 31];
        let wrong_seed_bytes = proto.encode_to_vec();
        let wrong_seed_expected = crate::Error::SerializationError(
            crate::SerializationError::InvalidKeySwitchingSeedLength {
                actual: 31,
                expected: 32,
            },
        );
        assert_eq!(
            EvaluationKey::from_bytes_with_limit(&wrong_seed_bytes, &params, usize::MAX)
                .unwrap_err(),
            wrong_seed_expected
        );
        assert_eq!(
            EvaluationKey::from_bytes(&wrong_seed_bytes, &params).unwrap_err(),
            wrong_seed_expected
        );

        // A seed alongside explicit c1 rows.
        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        let some_ksk = proto
            .gk
            .first_mut()
            .and_then(|gk| gk.ksk.as_mut())
            .ok_or_else(|| {
                crate::Error::DefaultError("test key must contain key-switching keys".to_string())
            })?;
        let Some(row) = some_ksk.c0.first().cloned() else {
            return Err(crate::Error::DefaultError(
                "test key must contain key-switching rows".to_string(),
            )
            .into());
        };
        some_ksk.seed = vec![7u8; 32];
        some_ksk.c1.push(row);
        let conflict_bytes = proto.encode_to_vec();
        let conflict_expected =
            crate::Error::SerializationError(crate::SerializationError::InvalidFormat {
                reason: "Key-switching key cannot contain both a seed and explicit c1 polynomials"
                    .to_string(),
            });
        assert_eq!(
            EvaluationKey::from_bytes_with_limit(&conflict_bytes, &params, usize::MAX).unwrap_err(),
            conflict_expected
        );
        assert_eq!(
            EvaluationKey::from_bytes(&conflict_bytes, &params).unwrap_err(),
            conflict_expected
        );
        Ok(())
    }

    #[test]
    fn opt_in_preflight_rejects_ksk_levels_inconsistent_with_outer_levels()
    -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(6, 16)?;
        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        proto.ciphertext_level = 1;
        let bytes = proto.encode_to_vec();

        let expected = crate::Error::InvalidLevel {
            level: 0,
            min_level: 1,
            max_level: 1,
        };
        assert_eq!(
            EvaluationKey::from_bytes_with_limit(&bytes, &params, usize::MAX).unwrap_err(),
            expected
        );
        assert_eq!(
            EvaluationKey::from_bytes(&bytes, &params).unwrap_err(),
            expected
        );
        Ok(())
    }

    #[test]
    fn opt_in_preflight_rejects_duplicate_scalar_fields() -> Result<(), Box<dyn Error>> {
        // Two ciphertext_level fields (field 3, varint) with different values.
        let (params, _ek) = inner_sum_key(1, 16)?;
        let bytes = [0x18, 0x00, 0x18, 0x01];
        let error = EvaluationKey::from_bytes_with_limit(&bytes, &params, usize::MAX).unwrap_err();
        assert!(
            matches!(
                error,
                crate::Error::SerializationError(crate::SerializationError::InvalidFormat { .. })
            ),
            "expected a canonical-form rejection, got {error}"
        );
        Ok(())
    }

    #[test]
    fn bounded_route_and_default_route_reject_parameter_mismatches() -> Result<(), Box<dyn Error>> {
        let (_, ek) = inner_sum_key(6, 16)?;
        let other_params = BfvParameters::default_arc(5, 16);
        let bytes = ek.to_bytes();
        assert!(EvaluationKey::from_bytes(&bytes, &other_params).is_err());
        assert!(
            EvaluationKey::from_bytes_with_limit(&bytes, &other_params, usize::MAX).is_err(),
            "the opt-in route must reject keys serialized for other parameters"
        );
        Ok(())
    }

    /// End-to-end roundtrip of the evaluation key reported in issue #246:
    /// degree 32768, nine 62-bit moduli, inner-sum support, about 309 MB
    /// encoded. The default route must reject it and the opt-in route must
    /// decode it. Key generation, serialization, and decoding with both keys
    /// in memory peak around 4 GiB and take seconds, so the test stays out
    /// of routine CI.
    #[test]
    #[ignore = "requires ~4 GiB peak memory and generates a ~309 MB key"]
    fn oversized_evaluation_key_roundtrips_through_the_opt_in_route() -> Result<(), Box<dyn Error>>
    {
        let (params, ek) = inner_sum_key(9, 32768)?;
        let bytes = ek.to_bytes();
        assert!(
            bytes.len() > fhe_traits::MAX_SERIALIZED_BYTES,
            "the key encodes to {} bytes and must exceed the default 256 MiB cap",
            bytes.len()
        );

        assert_eq!(
            EvaluationKey::from_bytes(&bytes, &params).unwrap_err(),
            crate::Error::SerializationError(crate::SerializationError::PayloadTooLarge {
                object: crate::SerializedObject::EvaluationKey,
                actual: bytes.len(),
                maximum: fhe_traits::MAX_SERIALIZED_BYTES,
            })
        );

        let decoded = EvaluationKey::from_bytes_with_limit(&bytes, &params, usize::MAX)?;
        assert_eq!(decoded, ek);
        assert!(decoded.supports_inner_sum());
        Ok(())
    }
}
