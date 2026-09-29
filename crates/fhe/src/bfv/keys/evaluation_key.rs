//! Leveled evaluation keys for the BFV encryption scheme.

use crate::bfv::keys::key_switching_key::{
    KeySwitchingKeyWireShape, constructor_log_base, expected_wire_shape,
};
use crate::bfv::{BfvParameters, Ciphertext, SecretKey, keys::GaloisKey, traits::TryConvertFrom};
use crate::proto::bfv::{EvaluationKey as EvaluationKeyProto, GaloisKey as GaloisKeyProto};
use crate::serialization::{WireCursor, WireValue};
use crate::{Error, Result, SerializationError, SerializedField, SerializedObject};
use fhe_math::rq::{NttShoup, Poly, PowerBasis};
use fhe_math::zq::Modulus;
use fhe_traits::{DeserializeParametrized, FheParametrized, Serialize};
use prost::Message;
use rand::{CryptoRng, Rng as RngCore};
use std::collections::{BTreeSet, HashMap, HashSet};
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

/// The maximum encoded size, in bytes, of a single Protobuf field tag
/// (field numbers below 2^29, wire types up to 3 bits).
const WIRE_TAG_MAX_BYTES: usize = 5;

/// The maximum encoded size, in bytes, of a Protobuf varint length prefix
/// for a length-delimited field.
const WIRE_LEN_PREFIX_MAX_BYTES: usize = 10;

/// Conservative allowance, in encoded bytes, for the outer evaluation-key
/// message's own scalars (`ciphertext_level` and `evaluation_key_level`) and
/// the top-level framing.
const WIRE_OUTER_OVERHEAD_BYTES: usize = 64;

/// A locally authorized description of the one evaluation key a receiving
/// application is willing to decode with
/// [`EvaluationKey::from_bytes_with_request`].
///
/// The request must be constructed **locally**, from the application's own
/// key configuration (the parameters it uses, the levels it operates at, and
/// the operations it intends to run with the key). Never derive it from the
/// incoming bytes or from a remote sender's description of the key: the
/// whole point of the request is that the decoder's resource bound is fixed
/// before any payload byte is read, so an untrusted peer cannot enlarge it.
///
/// The request pins the expected ciphertext and evaluation-key levels, the
/// number (or exact set) of Galois key entries, and the wire form of the
/// key-switching rows (regenerating seed or explicit rows). The
/// decomposition base and the key-switching row count and size are not
/// caller-controlled: they are derived from the validated parameters and
/// levels, exactly as the constructors produce them.
///
/// Deriving a bound from a request is **not authentication** and not an
/// application-wide memory guarantee: a request for a large key can still
/// legitimately describe an object costing many GiB to decode. Applications
/// that want a smaller footprint can check `bytes.len()` against their own
/// policy before calling, or authorize a tighter request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationKeyDecodeRequest {
    /// The ciphertext level the evaluation key must operate at.
    pub ciphertext_level: usize,
    /// The key level of the evaluation key's key-switching keys. Must not
    /// exceed [`Self::ciphertext_level`], mirroring the constructors.
    pub evaluation_key_level: usize,
    /// Which Galois key entries the key may carry.
    pub galois_keys: GaloisKeySpec,
    /// The wire form the key-switching rows must use.
    pub seed_policy: SeedPolicy,
}

/// The Galois key entries a locally authorized
/// [`EvaluationKeyDecodeRequest`] admits.
///
/// Exponents are substitution exponents compared after normalizing modulo
/// `2 * degree`, mirroring [`fhe_math::rq::SubstitutionExponent`]: this
/// applies to the wire and to an exact set's members alike, so a member
/// such as `2 * degree + 3` authorizes the same key as `3`. For an even
/// `degree`, valid substitution exponents are the odd values below
/// `2 * degree`; the constructors obtain them from rotation steps via
/// `q^3 mod 2 * degree` and from the literal `2 * degree - 1` used by row
/// rotation and inner sums.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GaloisKeySpec {
    /// At most this many distinct Galois key entries, with any valid
    /// substitution exponents. At most `degree` distinct entries can ever
    /// decode, so counts above [`BfvParameters::degree`] — including the
    /// `usize::MAX` sentinel — are rejected when the bound is derived
    /// instead of silently loosening it.
    AtMost(usize),
    /// Exactly this set of substitution exponents: every member must be
    /// present in the payload and no other entry may appear, so a key
    /// carrying only a subset of the request is rejected. Each member is
    /// normalized modulo `2 * degree` before matching; two members that
    /// normalize to the same exponent make the request unsatisfiable and
    /// are rejected when the bound is derived, as is a member whose
    /// normalized value is even. This is the tightest authorization and
    /// yields the smallest derived bound; it models a locally known key
    /// configuration such as "the inner-sum key".
    Exactly(BTreeSet<u32>),
}

impl GaloisKeySpec {
    /// The maximum number of Galois key entries this spec admits.
    fn authorized_count(&self) -> usize {
        match self {
            GaloisKeySpec::AtMost(count) => *count,
            GaloisKeySpec::Exactly(exponents) => exponents.len(),
        }
    }
}

/// The wire form a locally authorized [`EvaluationKeyDecodeRequest`] admits
/// for the key-switching rows of each Galois key.
///
/// The constructors store the `c1` rows either as a 32-byte seed that
/// regenerates them ([`SeedPolicy::Seeded`], the default
/// [`EvaluationKeyBuilder`](crate::bfv::EvaluationKeyBuilder) route) or as
/// explicit polynomial rows ([`SeedPolicy::ExplicitRows`]); both decode to
/// equivalent keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedPolicy {
    /// Every key-switching key must carry a regenerating seed.
    Seeded,
    /// Every key-switching key must carry explicit `c1` polynomial rows.
    ExplicitRows,
    /// Either form is acceptable; the derived bound covers the larger
    /// (explicit-rows) form plus a seed.
    Either,
}

impl SeedPolicy {
    /// The number of key-switching row entries (c0 plus c1) this policy
    /// admits per key-switching key, and whether a seed is additionally
    /// possible.
    fn row_multiplicity_and_seed(&self) -> (usize, bool) {
        match self {
            SeedPolicy::Seeded => (1, true),
            SeedPolicy::ExplicitRows => (2, false),
            SeedPolicy::Either => (2, true),
        }
    }
}

impl EvaluationKeyDecodeRequest {
    /// Validate the request against `params` and derive a conservative
    /// upper bound, in bytes, on the encoded payload of any evaluation key
    /// that satisfies it.
    ///
    /// The bound is computed from the request and the parameters alone —
    /// never from a payload: the maximum entry count times the
    /// parameter-implied key-switching row count and row size, plus checked
    /// allowances for Protobuf tags, length prefixes, scalar fields, and the
    /// seed. All arithmetic is checked; overflow yields
    /// [`SerializationError::WireBoundOverflow`] rather than a wrapped
    /// bound, which keeps the derivation correct on 32-bit platforms. The
    /// same holds for the parameter-implied row size, whose per-modulus
    /// serialization lengths are computed with checked arithmetic. One
    /// irreducible limitation remains: `2 * degree` itself cannot overflow
    /// for any constructible [`BfvParameters`], because parameter
    /// construction validates the degree and builds the polynomial contexts
    /// before a request can reference them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLevel`] for levels outside the parameter
    /// range or in inverted order,
    /// [`SerializationError::ExcessiveGaloisKeySpec`] when the request
    /// authorizes more distinct entries than substitution exponents exist,
    /// [`SerializationError::DuplicateGaloisExponent`] when an exact set
    /// has two members that normalize to the same exponent,
    /// [`Error::MathError`] when an exact set has a member that normalizes
    /// to an even exponent, and
    /// [`SerializationError::WireBoundOverflow`] when the bound does not
    /// fit in a `usize`.
    pub fn wire_bound(&self, params: &Arc<BfvParameters>) -> Result<usize> {
        debug_assert!(params.degree() <= usize::MAX / 2, "2 * degree overflows");
        if self.ciphertext_level > params.max_level() {
            return Err(Error::InvalidLevel {
                level: self.ciphertext_level,
                min_level: 0,
                max_level: params.max_level(),
            });
        }
        if self.evaluation_key_level > self.ciphertext_level {
            return Err(Error::InvalidLevel {
                level: self.evaluation_key_level,
                min_level: 0,
                max_level: self.ciphertext_level,
            });
        }
        let max_entries = match &self.galois_keys {
            GaloisKeySpec::AtMost(count) => {
                if *count > params.degree() {
                    return Err(SerializationError::ExcessiveGaloisKeySpec {
                        requested: *count,
                        maximum: params.degree(),
                    }
                    .into());
                }
                *count
            }
            GaloisKeySpec::Exactly(exponents) => {
                let mut normalized_members = BTreeSet::new();
                for &exponent in exponents {
                    let normalized_exponent = exponent as usize % (2 * params.degree());
                    if normalized_exponent & 1 == 0 {
                        return Err(Error::MathError(
                            fhe_math::Error::InvalidSubstitutionExponent {
                                exponent: normalized_exponent,
                                degree: params.degree(),
                            },
                        ));
                    }
                    if !normalized_members.insert(normalized_exponent) {
                        // Two members that alias one substitution exponent
                        // make the request unsatisfiable (the payload can
                        // contain the exponent at most once) and would
                        // loosen the derived bound.
                        return Err(SerializationError::DuplicateGaloisExponent {
                            exponent: normalized_exponent,
                        }
                        .into());
                    }
                }
                // Unreachable after the duplicate check: only `degree` odd
                // residues modulo `2 * degree` exist. Kept as a checked
                // invariant so the bound can never be loosened past what the
                // parameters admit.
                if normalized_members.len() > params.degree() {
                    return Err(SerializationError::ExcessiveGaloisKeySpec {
                        requested: normalized_members.len(),
                        maximum: params.degree(),
                    }
                    .into());
                }
                normalized_members.len()
            }
        };

        // The shape the constructors produce at these levels; the
        // decomposition base is implied by the parameters, not chosen.
        let ctx_ksk = params.context_at_level(self.evaluation_key_level)?;
        let log_base = constructor_log_base(ctx_ksk.moduli())?;
        let shape = expected_wire_shape(
            params,
            self.ciphertext_level,
            self.evaluation_key_level,
            log_base,
        )?;

        derived_wire_bound(
            &shape,
            max_entries,
            self.seed_policy.row_multiplicity_and_seed(),
        )
    }
}

/// Upper bound on the encoded bytes of an evaluation key conforming to a
/// request: maximum entry count times the parameter-implied per-entry size,
/// plus checked allowances for wire framing. Pure arithmetic over the
/// derived shape, so it is unit-testable without allocating.
///
/// `row_multiplicity` is the number of key-switching row entries per key
/// (2 for explicit-rows keys, 1 for seeded ones) and `with_seed` whether a
/// 32-byte seed may also be present.
fn derived_wire_bound(
    shape: &KeySwitchingKeyWireShape,
    max_entries: usize,
    (row_multiplicity, with_seed): (usize, bool),
) -> Result<usize> {
    // One key-switching row: its parameter-implied payload, the row's
    // documented slack (tags, length prefix, unknown fields inside the row),
    // and its own tag and length prefix.
    let row_entry = shape
        .row_bytes
        .checked_add(WIRE_ROW_SLACK)
        .and_then(|v| v.checked_add(WIRE_TAG_MAX_BYTES + WIRE_LEN_PREFIX_MAX_BYTES))
        .ok_or(SerializationError::WireBoundOverflow)?;
    let rows = shape
        .row_count
        .checked_mul(row_multiplicity)
        .ok_or(SerializationError::WireBoundOverflow)?;
    let ksk_rows = rows
        .checked_mul(row_entry)
        .ok_or(SerializationError::WireBoundOverflow)?;
    // One Galois key entry: its key-switching key (rows; the ksk's three
    // scalar fields; optionally the seed) plus the gk wrapper (tag and
    // length prefix for the ksk message, tag and varint for the exponent)
    // and the outer entry tag and length prefix.
    let mut per_entry = ksk_rows
        .checked_add(3 * (WIRE_TAG_MAX_BYTES + WIRE_LEN_PREFIX_MAX_BYTES))
        .ok_or(SerializationError::WireBoundOverflow)?;
    if with_seed {
        per_entry = per_entry
            .checked_add(WIRE_SEED_LENGTH + WIRE_TAG_MAX_BYTES + WIRE_LEN_PREFIX_MAX_BYTES)
            .ok_or(SerializationError::WireBoundOverflow)?;
    }
    per_entry = per_entry
        .checked_add(2 * WIRE_TAG_MAX_BYTES + WIRE_LEN_PREFIX_MAX_BYTES + WIRE_TAG_MAX_BYTES)
        .ok_or(SerializationError::WireBoundOverflow)?;
    let entries = max_entries
        .checked_mul(per_entry)
        .ok_or(SerializationError::WireBoundOverflow)?;
    entries
        .checked_add(WIRE_OUTER_OVERHEAD_BYTES)
        .ok_or(SerializationError::WireBoundOverflow.into())
}

impl EvaluationKey {
    /// Decode an evaluation key whose shape a locally authorized request
    /// describes, enforcing a byte bound derived from that request.
    ///
    /// The default [`fhe_traits::DeserializeParametrized::from_bytes`] route
    /// rejects any payload above the global 256 MiB cap
    /// ([`fhe_traits::MAX_SERIALIZED_BYTES`]). Large parameters exceed that
    /// cap for legitimate keys: a degree-32768 key with nine 62-bit moduli
    /// and inner-sum support encodes to roughly 309 MB. This method is the
    /// opt-in route for such keys.
    ///
    /// # The bound is derived, never negotiated
    ///
    /// The bound comes from `request` — which the application constructs
    /// locally from its own key configuration — combined with the validated
    /// parameters via [`EvaluationKeyDecodeRequest::wire_bound`]. It is
    /// enforced before any Protobuf decoding allocates, so the decoder's
    /// resource envelope never depends on the payload's own length or on a
    /// sender's description of the key. Payloads above the derived bound are
    /// rejected with [`SerializationError::PayloadTooLarge`].
    ///
    /// # When to use this route
    ///
    /// Only for **authenticated, trusted** large keys. The request is a
    /// shape and resource authorization, not an authenticity check: it
    /// cannot verify who produced the bytes. Use this route only for keys
    /// delivered over a trusted, authenticated channel, whose shape you have
    /// locally authorized.
    ///
    /// # More restrictive than the default route
    ///
    /// This route pins the wire schema: the request's levels, Galois key
    /// entry set or count, and seed policy are enforced against the payload
    /// by the wire preflight. Unknown Protobuf fields at the evaluation-key,
    /// Galois-key, and key-switching-key scopes are rejected, where the
    /// default route skips them; unknown fields inside polynomial rows can
    /// be skipped if the row fits within its fixed slack allowance. A payload
    /// that is valid for the default route may therefore still be rejected
    /// here, with a typed error, and vice versa: where a payload violates
    /// several independent rules at once, the preflight may report a
    /// different one of those typed errors (or a different ordering) than
    /// the default route.
    ///
    /// # Resource requirements
    ///
    /// A request can legitimately authorize a key costing many GiB to
    /// decode: peak memory reaches several times the encoded size because
    /// the encoded buffer, the decoded Protobuf representation, and the
    /// in-memory key coexist (the 309 MB reference key peaks around 4 GiB
    /// with both keys in memory, or roughly 1.5 GiB on top of the input
    /// buffer otherwise). The derived bound bounds the encoded payload, not
    /// resident memory; applications with a smaller footprint can check
    /// `bytes.len()` against their own policy before calling.
    ///
    /// The preflight remains a lightweight, zero-copy scan that enforces the
    /// parameter-implied shape (exact key-switching row counts and bounded
    /// row lengths, level consistency, seed placement), rejects duplicate
    /// Galois key exponents — compared after normalizing modulo
    /// `2 * degree` — and rejects encodings the default route tolerates:
    /// repeated scalar fields (for which `prost` applies last-wins
    /// semantics) and varints wider than the declared `uint32` fields (which
    /// `prost` silently truncates). Post-decode validation is unchanged and
    /// remains authoritative.
    ///
    /// # Errors
    ///
    /// Returns [`SerializationError::PayloadTooLarge`] when the payload
    /// exceeds the derived bound (checked before any parsing),
    /// [`SerializationError::WireBoundOverflow`] when the request's bound
    /// cannot be derived on this platform,
    /// [`SerializationError::ExcessiveGaloisKeySpec`] when the request
    /// authorizes more distinct entries than substitution exponents exist,
    /// and [`SerializationError::DuplicateGaloisExponent`] when an exact
    /// set has two members that normalize to the same exponent. The
    /// preflight then rejects payloads that disagree with the request —
    /// [`Error::InvalidLevel`] for levels,
    /// [`SerializationError::GaloisKeyCountExceeded`] for the entry count,
    /// [`SerializationError::UnexpectedGaloisKeyExponent`] for an
    /// unauthorized exponent,
    /// [`SerializationError::MissingGaloisKeyExponent`] when an exact
    /// request's full authorized set is not present, and
    /// [`SerializationError::SeedPolicyMismatch`] when the rows use an
    /// unauthorized seed form; it rejects shape violations with the same
    /// typed errors as
    /// [`fhe_traits::DeserializeParametrized::from_bytes`].
    pub fn from_bytes_with_request(
        bytes: &[u8],
        params: &Arc<BfvParameters>,
        request: &EvaluationKeyDecodeRequest,
    ) -> Result<Self> {
        // Derived first: the decoder's resource envelope never depends on
        // the payload or on anything a sender claims.
        let bound = request.wire_bound(params)?;
        crate::serialization::check_size_with_limit(
            bytes.len(),
            SerializedObject::EvaluationKey,
            bound,
        )?;
        preflight_wire_shape(bytes, params, request)?;
        let gkp =
            crate::serialization::decode_with_limit(bytes, SerializedObject::EvaluationKey, bound)?;
        EvaluationKey::try_convert_from(&gkp, params)
    }
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

/// Extra allowance, in encoded bytes, on top of the parameter-implied
/// coefficient payload of one serialized key-switching row.
///
/// It covers protobuf field tags, varint length prefixes, and unknown fields
/// inside a row. A row outside
/// `[row_bytes + WIRE_ROW_MIN_OVERHEAD, row_bytes + WIRE_ROW_SLACK]` can
/// never decode into a polynomial for the declared context. Unknown fields
/// at the evaluation-key, Galois-key, and key-switching-key scopes are
/// rejected outright on the request-based route, so no unbounded padding
/// can hide there; the derived wire bound includes this slack per row.
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

/// Pre-decode shape validation of a serialized evaluation key against a
/// locally authorized request.
///
/// The scan borrows the payload in place and copies no payload bytes; its
/// acceptance-path allocations are bounded sets independent of the payload
/// size — for exact requests the authorized normalized-exponent set (plus a
/// sorted copy for deterministic reporting), and the set of already-seen
/// exponents (at most one per authorized entry) — and rejection paths may
/// allocate error messages. It rejects, before `prost` materializes
/// anything: malformed wire structure, unknown Protobuf fields at the
/// evaluation-key, Galois-key, and key-switching-key scopes (the request
/// pins the schema), duplicate or non-canonical scalar fields, scalar
/// varints wider than their declared `uint32` fields, Galois key entries or
/// exponents outside the request — for exact requests, a missing authorized
/// exponent is rejected too, so a subset of the requested key does not
/// decode — levels disagreeing with the request, key-switching keys whose
/// declared shape does not match the parameters (levels, decomposition
/// base, exact row counts, row lengths, seed placement, seed form), and
/// key-switching levels inconsistent with the outer evaluation-key levels.
///
/// This bounds decoder work and memory before the decoder allocates; it
/// does not replace the post-decode validation, which remains authoritative.
/// Where a payload violates several independent rules, the preflight may
/// report a different typed error than the default route would.
fn preflight_wire_shape(
    bytes: &[u8],
    params: &Arc<BfvParameters>,
    request: &EvaluationKeyDecodeRequest,
) -> Result<()> {
    let (ciphertext_level, evaluation_key_level, gk_count) = scan_outer_fields(bytes)?;

    // The request pins the levels: the wire values (defaulting to zero when
    // absent, as the schema allows) must equal the authorized ones exactly.
    let ciphertext_level =
        scalar_as_u32(ciphertext_level.unwrap_or(0), "ciphertext_level")? as usize;
    if ciphertext_level != request.ciphertext_level {
        return Err(Error::InvalidLevel {
            level: ciphertext_level,
            min_level: request.ciphertext_level,
            max_level: request.ciphertext_level,
        });
    }
    let evaluation_key_level =
        scalar_as_u32(evaluation_key_level.unwrap_or(0), "evaluation_key_level")? as usize;
    if evaluation_key_level != request.evaluation_key_level {
        return Err(Error::InvalidLevel {
            level: evaluation_key_level,
            min_level: request.evaluation_key_level,
            max_level: request.evaluation_key_level,
        });
    }

    let authorized_count = request.galois_keys.authorized_count();
    if gk_count > authorized_count {
        return Err(Error::SerializationError(
            SerializationError::GaloisKeyCountExceeded {
                authorized: authorized_count,
                actual: gk_count,
            },
        ));
    }

    // An exact request authorizes specific substitution exponents; the
    // authorized members are normalized the same way the wire exponents
    // are, and the whole set must be present (a strict subset is rejected
    // after the scan). `wire_bound` has already rejected members that
    // normalize to an even value and duplicate normalized members, so every
    // member here is a distinct decodable exponent. The sorted copy makes
    // the reported missing exponent deterministic.
    let (authorized_exponents, authorized_sorted): (Option<HashSet<usize>>, Vec<usize>) =
        match &request.galois_keys {
            GaloisKeySpec::AtMost(_) => (None, Vec::new()),
            GaloisKeySpec::Exactly(exponents) => {
                let set: HashSet<usize> = exponents
                    .iter()
                    .map(|&exponent| exponent as usize % (2 * params.degree()))
                    .collect();
                let mut sorted: Vec<usize> = set.iter().copied().collect();
                sorted.sort_unstable();
                (Some(set), sorted)
            }
        };

    // Second outer pass: validate each Galois key entry against the
    // request and the parameter-implied shape. A malformed entry fails
    // before later entries are scanned, so hostile payloads with many
    // repeated fields cost one entry's worth of work.
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
                request,
                authorized_exponents.as_ref(),
                &mut seen_exponents,
            )?;
        }
    }

    // An exact request requires the full authorized set: a payload carrying
    // only a subset decodes on the default route, but it is not the key the
    // application asked for, so it is rejected here before decoding. The
    // smallest missing exponent is reported, deterministically.
    if authorized_exponents.is_some() {
        let missing = authorized_sorted
            .iter()
            .find(|exponent| !seen_exponents.contains(*exponent));
        if let Some(&exponent) = missing {
            return Err(Error::SerializationError(
                SerializationError::MissingGaloisKeyExponent { exponent },
            ));
        }
    }
    Ok(())
}

/// Scans the outer evaluation-key message for its scalar fields and Galois
/// key entry count. Unknown field numbers are rejected: the request pins
/// the schema, so a payload carrying fields the library does not know is
/// not a payload the derived bound describes.
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
            _ => {
                return Err(SerializationError::InvalidFormat {
                    reason: format!("unknown field {field_number} in evaluation key"),
                });
            }
        }
    }
    Ok((ciphertext_level, evaluation_key_level, gk_count))
}

/// Validates one serialized Galois key entry against the request and the
/// parameters.
fn scan_galois_key(
    gk: &[u8],
    params: &Arc<BfvParameters>,
    outer_ciphertext_level: usize,
    outer_evaluation_key_level: usize,
    request: &EvaluationKeyDecodeRequest,
    authorized_exponents: Option<&HashSet<usize>>,
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
            _ => {
                return Err(SerializationError::InvalidFormat {
                    reason: format!("unknown field {field_number} in Galois key"),
                }
                .into());
            }
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
    if let Some(authorized) = authorized_exponents
        && !authorized.contains(&normalized)
    {
        return Err(Error::SerializationError(
            SerializationError::UnexpectedGaloisKeyExponent {
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
            if request.seed_policy == SeedPolicy::ExplicitRows {
                return Err(Error::SerializationError(
                    SerializationError::SeedPolicyMismatch {
                        expected: "explicit c1 rows",
                        found: "a regenerating seed",
                    },
                ));
            }
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
            if request.seed_policy == SeedPolicy::Seeded {
                return Err(Error::SerializationError(
                    SerializationError::SeedPolicyMismatch {
                        expected: "a regenerating seed",
                        found: "explicit c1 rows",
                    },
                ));
            }
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
/// key-switching key without materializing its rows. Unknown field numbers
/// are rejected: the request pins the schema.
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
            _ => {
                return Err(SerializationError::InvalidFormat {
                    reason: format!("unknown field {field_number} in key-switching key"),
                });
            }
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
    use super::{
        EvaluationKey, EvaluationKeyBuilder, EvaluationKeyDecodeRequest, GaloisKeySpec, SeedPolicy,
    };
    use crate::bfv::keys::key_switching_key::KeySwitchingKeyWireShape;
    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey, traits::TryConvertFrom};
    use crate::proto::bfv::EvaluationKey as LeveledEvaluationKeyProto;
    use fhe_math::zq::Modulus;
    use fhe_traits::{
        DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
    };
    use itertools::izip;
    use prost::Message;
    use rand::rng;
    use std::{
        cmp::min,
        collections::{BTreeSet, HashSet},
        error::Error,
        sync::Arc,
    };

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

    /// Builds a small evaluation key with several Galois keys for the
    /// request-based deserialization tests.
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

    /// The request modeling the locally known configuration "leveled
    /// evaluation key with inner-sum support at levels (0, 0)".
    ///
    /// This is what a receiving application constructs on its own side: the
    /// exponent set is computed from the parameters and the intended
    /// operation (the inner-sum key uses the substitution exponent
    /// `2 * degree - 1` plus the halving chain `q^3 mod 2 * degree` of
    /// steps 1, 2, 4, ...), never from a serialized payload.
    fn inner_sum_request(
        params: &Arc<BfvParameters>,
    ) -> Result<EvaluationKeyDecodeRequest, Box<dyn Error>> {
        let degree = params.degree();
        let q = Modulus::new(2 * degree as u64)?;
        let mut exponents = BTreeSet::from([(2 * degree - 1) as u32]);
        let mut i = 1;
        while i < degree / 2 {
            exponents.insert(q.pow(3, i as u64) as u32);
            i *= 2;
        }
        Ok(EvaluationKeyDecodeRequest {
            ciphertext_level: 0,
            evaluation_key_level: 0,
            galois_keys: GaloisKeySpec::Exactly(exponents),
            seed_policy: SeedPolicy::Either,
        })
    }

    #[test]
    fn request_route_roundtrips_like_the_default_route() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(6, 16)?;
        let bytes = ek.to_bytes();
        let request = inner_sum_request(&params)?;
        assert_eq!(
            ek,
            EvaluationKey::from_bytes_with_request(&bytes, &params, &request)?
        );
        assert_eq!(ek, EvaluationKey::from_bytes(&bytes, &params)?);
        Ok(())
    }

    #[test]
    fn request_route_roundtrips_leveled_decomposition_keys() -> Result<(), Box<dyn Error>> {
        // At the maximal ciphertext and key level the key context has a single
        // modulus, so the wire rows use the base-2^(log_modulus/2)
        // decomposition instead of the standard RNS decomposition; the
        // request derives that shape from the parameters and levels, and the
        // preflight must admit exactly that shape.
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let max_level = params.max_level();
        let ek = EvaluationKeyBuilder::new_leveled(&sk, max_level, max_level)?
            .enable_inner_sum()?
            .build(&mut rng)?;
        let bytes = ek.to_bytes();
        let degree = params.degree();
        let q = Modulus::new(2 * degree as u64)?;
        let mut exponents = BTreeSet::from([(2 * degree - 1) as u32]);
        let mut i = 1;
        while i < degree / 2 {
            exponents.insert(q.pow(3, i as u64) as u32);
            i *= 2;
        }
        let request = EvaluationKeyDecodeRequest {
            ciphertext_level: max_level,
            evaluation_key_level: max_level,
            galois_keys: GaloisKeySpec::Exactly(exponents),
            seed_policy: SeedPolicy::Either,
        };
        assert_eq!(
            ek,
            EvaluationKey::from_bytes_with_request(&bytes, &params, &request)?
        );
        assert_eq!(ek, EvaluationKey::from_bytes(&bytes, &params)?);
        Ok(())
    }

    #[test]
    fn derived_bound_is_enforced_before_decoding() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(3, 16)?;
        let bytes = ek.to_bytes();
        let request = inner_sum_request(&params)?;
        let bound = request.wire_bound(&params)?;

        // Padding past the derived bound is rejected as a size violation
        // before the preflight runs: the padding bytes are invalid wire
        // format, so a wire error here would mean the bound was not checked
        // first.
        let mut padded = bytes.clone();
        padded.extend(std::iter::repeat_n(0u8, bound - bytes.len() + 1));
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&padded, &params, &request).unwrap_err(),
            crate::Error::SerializationError(crate::SerializationError::PayloadTooLarge {
                object: crate::SerializedObject::EvaluationKey,
                actual: padded.len(),
                maximum: bound,
            }),
            "the derived bound must reject the {}-byte payload before decoding",
            padded.len()
        );

        // The bound is conservative: the unmodified payload fits, and a
        // request authorizing nothing rejects any entry through the typed
        // count error. The crafted one-entry payload is tiny, so the size
        // check cannot mask the count check.
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&bytes, &params, &request)?,
            ek
        );
        let mut nothing = request.clone();
        nothing.galois_keys = GaloisKeySpec::AtMost(0);
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&[0x12, 0x00], &params, &nothing).unwrap_err(),
            crate::Error::SerializationError(crate::SerializationError::GaloisKeyCountExceeded {
                authorized: 0,
                actual: 1,
            }),
            "a request authorizing zero entries must reject any entry before decoding"
        );
        Ok(())
    }

    #[test]
    fn request_mismatches_are_rejected_before_decoding() -> Result<(), Box<dyn Error>> {
        // The request models a locally known configuration; each mismatch
        // must surface as a typed error from the preflight, never as a
        // decode of a key the application did not ask for.
        let (params, ek) = inner_sum_key(3, 16)?;
        let bytes = ek.to_bytes();
        let request = inner_sum_request(&params)?;

        // Wrong ciphertext level.
        let mut wrong_level = request.clone();
        wrong_level.ciphertext_level = 1;
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&bytes, &params, &wrong_level).unwrap_err(),
            crate::Error::InvalidLevel {
                level: 0,
                min_level: 1,
                max_level: 1,
            },
        );

        // A request whose key level exceeds its ciphertext level is
        // rejected when the bound is derived: no constructor could have
        // produced such a key, mirroring the builder.
        let mut wrong_key_level = request.clone();
        wrong_key_level.evaluation_key_level = 1;
        assert_eq!(
            wrong_key_level.wire_bound(&params).unwrap_err(),
            crate::Error::InvalidLevel {
                level: 1,
                min_level: 0,
                max_level: 0,
            },
        );

        // A valid request whose key level differs from the payload's is
        // rejected by the preflight against the pinned level.
        let mut other_key_level_proto = LeveledEvaluationKeyProto::from(&ek);
        other_key_level_proto.evaluation_key_level = 1;
        let other_key_level_bytes = other_key_level_proto.encode_to_vec();
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&other_key_level_bytes, &params, &request)
                .unwrap_err(),
            crate::Error::InvalidLevel {
                level: 1,
                min_level: 0,
                max_level: 0,
            },
        );

        // An exact set authorizing four exponents that none of the payload's
        // entries use rejects the payload's first scanned exponent instead
        // of decoding. The entries are written in HashMap order, so the
        // reported exponent is any one of the payload's four; the typed
        // error is deterministic. The set has the payload's cardinality so
        // the derived bound covers the payload and the size check cannot
        // mask the exponent check.
        let unauthorized = EvaluationKeyDecodeRequest {
            galois_keys: GaloisKeySpec::Exactly(BTreeSet::from([5, 7, 11, 13])),
            ..request.clone()
        };
        let payload_exponents: [usize; 4] = [3, 9, 17, (2 * params.degree() - 1)];
        let error =
            EvaluationKey::from_bytes_with_request(&bytes, &params, &unauthorized).unwrap_err();
        assert!(
            matches!(
                &error,
                crate::Error::SerializationError(
                    crate::SerializationError::UnexpectedGaloisKeyExponent { exponent }
                ) if payload_exponents.contains(exponent)
            ),
            "expected UnexpectedGaloisKeyExponent for a payload exponent, got {error}"
        );

        Ok(())
    }

    #[test]
    fn exact_exponent_members_are_normalized_like_the_wire() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(3, 16)?;
        let bytes = ek.to_bytes();
        let request = inner_sum_request(&params)?;
        let degree = params.degree();
        let GaloisKeySpec::Exactly(exponents) = &request.galois_keys else {
            return Err(
                crate::Error::DefaultError("the helper builds an exact set".to_string()).into(),
            );
        };

        // A member written in non-canonical form (`3 + 2 * degree`)
        // normalizes to `3`, so the request authorizes the same key.
        let mut non_canonical = BTreeSet::new();
        for &exponent in exponents {
            if exponent == 3 {
                non_canonical.insert(3 + 2 * degree as u32);
            } else {
                non_canonical.insert(exponent);
            }
        }
        let non_canonical_request = EvaluationKeyDecodeRequest {
            galois_keys: GaloisKeySpec::Exactly(non_canonical),
            ..request.clone()
        };
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&bytes, &params, &non_canonical_request)?,
            ek
        );

        // A member that normalizes to an even value can never decode and is
        // rejected when the bound is derived, with the same typed error the
        // wire preflight produces for even exponents.
        let mut even_member = exponents.clone();
        even_member.insert(2 + 2 * degree as u32);
        assert_eq!(
            EvaluationKeyDecodeRequest {
                galois_keys: GaloisKeySpec::Exactly(even_member),
                ..request
            }
            .wire_bound(&params)
            .unwrap_err(),
            crate::Error::MathError(fhe_math::Error::InvalidSubstitutionExponent {
                exponent: 2,
                degree,
            })
        );
        Ok(())
    }

    #[test]
    fn exact_request_requires_the_full_authorized_set() -> Result<(), Box<dyn Error>> {
        // A valid smaller key: column rotation by 1 produces exactly one
        // Galois key (exponent 3). The default route decodes it; an exact
        // request that authorizes {3, 9} rejects it as missing an
        // authorized exponent instead of decoding a subset.
        let mut rng = rng();
        let params = BfvParameters::default_arc(3, 16);
        let sk = SecretKey::random(&params, &mut rng);
        let smaller = EvaluationKeyBuilder::new_leveled(&sk, 0, 0)?
            .enable_column_rotation(1)?
            .build(&mut rng)?;
        let smaller_bytes = smaller.to_bytes();
        assert_eq!(smaller, EvaluationKey::from_bytes(&smaller_bytes, &params)?);

        let subset_request = EvaluationKeyDecodeRequest {
            galois_keys: GaloisKeySpec::Exactly(BTreeSet::from([3, 9])),
            ..inner_sum_request(&params)?
        };
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&smaller_bytes, &params, &subset_request)
                .unwrap_err(),
            crate::Error::SerializationError(crate::SerializationError::MissingGaloisKeyExponent {
                exponent: 9
            }),
            "a strict subset of the authorized set must not decode"
        );

        // The same holds for a superset request on the inner-sum key: the
        // payload lacks the extra authorized exponent 5.
        let (params, ek) = inner_sum_key(3, 16)?;
        let bytes = ek.to_bytes();
        let mut superset = BTreeSet::from([5]);
        if let GaloisKeySpec::Exactly(exponents) = &inner_sum_request(&params)?.galois_keys {
            superset.extend(exponents);
        }
        let superset_request = EvaluationKeyDecodeRequest {
            galois_keys: GaloisKeySpec::Exactly(superset),
            ..inner_sum_request(&params)?
        };
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&bytes, &params, &superset_request).unwrap_err(),
            crate::Error::SerializationError(crate::SerializationError::MissingGaloisKeyExponent {
                exponent: 5
            }),
        );

        // A malformed payload with an entry count within the request is
        // still rejected by the wire scan, not by the missing-exponent
        // check: the equality check runs after the payload is fully
        // scanned, before `prost` materializes anything.
        let mut malformed = bytes.clone();
        malformed.truncate(malformed.len() - 3);
        let error = EvaluationKey::from_bytes_with_request(
            &malformed,
            &params,
            &inner_sum_request(&params)?,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                crate::Error::SerializationError(crate::SerializationError::InvalidFormat { .. })
            ),
            "the malformed payload must be rejected by the wire scan, got {error}"
        );
        Ok(())
    }

    #[test]
    fn exact_request_rejects_duplicate_normalized_members() -> Result<(), Box<dyn Error>> {
        // {3, 3 + 2 * degree} aliases one substitution exponent: the
        // request would be unsatisfiable (the payload can carry the
        // exponent at most once) and would loosen the derived bound, so it
        // is rejected when the bound is derived.
        let params = BfvParameters::default_arc(3, 16);
        let degree = params.degree() as u32;
        let error = EvaluationKeyDecodeRequest {
            ciphertext_level: 0,
            evaluation_key_level: 0,
            galois_keys: GaloisKeySpec::Exactly(BTreeSet::from([3, 3 + 2 * degree])),
            seed_policy: SeedPolicy::Either,
        }
        .wire_bound(&params)
        .unwrap_err();
        assert_eq!(
            error,
            crate::Error::SerializationError(crate::SerializationError::DuplicateGaloisExponent {
                exponent: 3
            })
        );
        Ok(())
    }

    #[test]
    fn request_count_above_degree_is_rejected() -> Result<(), Box<dyn Error>> {
        let params = BfvParameters::default_arc(3, 16);
        let degree = params.degree();

        // AtMost counts above the number of distinct substitution exponents
        // that exist — including the usize::MAX sentinel — are rejected as
        // invalid requests instead of silently loosening the derived bound.
        for count in [degree + 1, usize::MAX] {
            assert_eq!(
                EvaluationKeyDecodeRequest {
                    ciphertext_level: 0,
                    evaluation_key_level: 0,
                    galois_keys: GaloisKeySpec::AtMost(count),
                    seed_policy: SeedPolicy::Either,
                }
                .wire_bound(&params)
                .unwrap_err(),
                crate::Error::SerializationError(
                    crate::SerializationError::ExcessiveGaloisKeySpec {
                        requested: count,
                        maximum: degree,
                    }
                ),
                "AtMost({count}) must be rejected for degree {degree}"
            );
        }

        // An exact set with more raw members than distinct substitution
        // exponents exist necessarily aliases one exponent after
        // normalization, so the duplicate check catches it first.
        let members: BTreeSet<u32> = (0..=degree).map(|i| (2 * i + 1) as u32).collect();
        assert_eq!(members.len(), degree + 1);
        assert_eq!(
            EvaluationKeyDecodeRequest {
                ciphertext_level: 0,
                evaluation_key_level: 0,
                galois_keys: GaloisKeySpec::Exactly(members),
                seed_policy: SeedPolicy::Either,
            }
            .wire_bound(&params)
            .unwrap_err(),
            crate::Error::SerializationError(crate::SerializationError::DuplicateGaloisExponent {
                exponent: 1
            })
        );

        // AtMost(degree) itself stays valid and derives a finite bound.
        let bound = EvaluationKeyDecodeRequest {
            ciphertext_level: 0,
            evaluation_key_level: 0,
            galois_keys: GaloisKeySpec::AtMost(degree),
            seed_policy: SeedPolicy::Either,
        }
        .wire_bound(&params)?;
        assert!(bound > 0);
        Ok(())
    }

    #[test]
    fn derived_wire_bound_admits_more_than_one_gib_without_allocating() -> Result<(), Box<dyn Error>>
    {
        // A request authorizing a full inner-sum key for degree-4096
        // parameters derives a bound above 1 GiB purely from the request and
        // the parameters: no payload is read, nothing is allocated, and no
        // global cap clamps the result.
        let params = BfvParameters::default_arc(3, 4096);
        let degree = params.degree();
        let request = EvaluationKeyDecodeRequest {
            ciphertext_level: 0,
            evaluation_key_level: 0,
            galois_keys: GaloisKeySpec::AtMost(degree),
            seed_policy: SeedPolicy::Either,
        };
        match request.wire_bound(&params) {
            Ok(bound) => assert!(
                bound > 1024 * 1024 * 1024,
                "the derived bound {bound} must exceed the former 1 GiB ceiling"
            ),
            // On a 32-bit platform the honest outcome is a typed overflow,
            // not a silently wrapped bound.
            Err(crate::Error::SerializationError(crate::SerializationError::WireBoundOverflow)) => {
                assert!(
                    size_of::<usize>() == 4,
                    "the bound must derive on 64-bit platforms"
                );
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    #[test]
    fn derived_wire_bound_overflow_is_typed() -> Result<(), Box<dyn Error>> {
        // Pure checked arithmetic over a synthetic shape: a row size near
        // usize::MAX overflows the bound instead of wrapping.
        let shape = KeySwitchingKeyWireShape {
            row_count: 2,
            row_bytes: usize::MAX / 2,
        };
        assert!(matches!(
            super::derived_wire_bound(&shape, 3, (2, true)),
            Err(crate::Error::SerializationError(
                crate::SerializationError::WireBoundOverflow
            ))
        ));
        // A realistic shape derives a finite bound above zero.
        let shape = KeySwitchingKeyWireShape {
            row_count: 9,
            row_bytes: 9 * 8 * 32768,
        };
        let bound = super::derived_wire_bound(&shape, 15, (2, true))?;
        assert!(bound > 15 * 2 * 9 * 9 * 8 * 32768);
        Ok(())
    }

    #[test]
    fn request_rejects_unknown_fields_at_the_scanned_scopes() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(3, 16)?;
        let request = inner_sum_request(&params)?;

        // An unknown field appended to the outer evaluation-key message.
        let mut outer = ek.to_bytes();
        outer.extend_from_slice(&[0x50, 0x01]); // field 10, varint 1
        assert!(
            matches!(
                EvaluationKey::from_bytes_with_request(&outer, &params, &request).unwrap_err(),
                crate::Error::SerializationError(crate::SerializationError::InvalidFormat { .. })
            ),
            "the preflight must reject the unknown outer field"
        );

        // An unknown field inside a Galois key entry (field 3 in the Galois
        // key scope), in an entry that otherwise carries no key-switching
        // key: the unknown field is rejected before the missing-field check.
        // One own entry is dropped so the crafted entry stays within the
        // authorized entry count.
        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        proto.gk.truncate(proto.gk.len() - 1);
        let gk_scope = proto
            .encode_to_vec()
            .into_iter()
            .chain([0x12, 0x02, 0x1a, 0x00])
            .collect::<Vec<u8>>();
        let error =
            EvaluationKey::from_bytes_with_request(&gk_scope, &params, &request).unwrap_err();
        assert!(
            matches!(
                error,
                crate::Error::SerializationError(crate::SerializationError::InvalidFormat { .. })
            ) && error.to_string().contains("unknown field 3 in Galois key"),
            "the preflight must reject the unknown Galois-key field, got {error}"
        );

        // An unknown field inside a key-switching key (field 7 in that
        // scope). The entry is hand-encoded around the key's own first
        // key-switching key so the unknown field survives: re-encoding the
        // Protobuf message would drop it, which is exactly the leniency the
        // request route refuses.
        let proto = crate::proto::bfv::EvaluationKey::from(&ek);
        let ksk = proto
            .gk
            .first()
            .and_then(|gk| gk.ksk.as_ref())
            .ok_or_else(|| {
                crate::Error::DefaultError("test key must contain key-switching keys".to_string())
            })?;
        let mut ksk_bytes = ksk.encode_to_vec();
        ksk_bytes.extend_from_slice(&[0x38, 0x01]); // field 7, varint 1

        fn push_varint(out: &mut Vec<u8>, mut value: u64) {
            loop {
                let byte = (value & 0x7f) as u8;
                value >>= 7;
                if value == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
        }

        let mut entry = Vec::new();
        entry.push(0x0a); // ksk field tag
        push_varint(&mut entry, ksk_bytes.len() as u64);
        entry.extend_from_slice(&ksk_bytes);
        entry.extend_from_slice(&[0x10, 0x03]); // exponent 3, authorized

        let mut outer = Vec::new();
        outer.push(0x12); // gk field tag
        push_varint(&mut outer, entry.len() as u64);
        outer.extend_from_slice(&entry);

        let error = EvaluationKey::from_bytes_with_request(&outer, &params, &request).unwrap_err();
        assert!(
            matches!(
                error,
                crate::Error::SerializationError(crate::SerializationError::InvalidFormat { .. })
            ) && error
                .to_string()
                .contains("unknown field 7 in key-switching key"),
            "the preflight must reject the unknown key-switching-key field, got {error}"
        );

        // Rows are length-bounded, not schema-scanned. The polynomial
        // decoder skips this two-byte unknown field within the row's slack.
        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        let row = proto
            .gk
            .first_mut()
            .and_then(|gk| gk.ksk.as_mut())
            .and_then(|ksk| ksk.c0.first_mut())
            .ok_or_else(|| crate::Error::DefaultError("missing test row".to_string()))?;
        row.extend_from_slice(&[0x50, 0x01]); // field 10, varint 1
        let row_extension = proto.encode_to_vec();
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&row_extension, &params, &request)?,
            ek,
            "row-level unknown fields within the documented slack are allowed"
        );
        Ok(())
    }

    #[test]
    fn request_enforces_the_seed_policy() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(3, 16)?;
        let bytes = ek.to_bytes();

        // The generated keys store a regenerating seed, so a seeded policy
        // admits them and an explicit-rows policy does not.
        let seeded_request = EvaluationKeyDecodeRequest {
            seed_policy: SeedPolicy::Seeded,
            ..inner_sum_request(&params)?
        };
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&bytes, &params, &seeded_request)?,
            ek
        );
        let explicit_request = EvaluationKeyDecodeRequest {
            seed_policy: SeedPolicy::ExplicitRows,
            ..inner_sum_request(&params)?
        };
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&bytes, &params, &explicit_request).unwrap_err(),
            crate::Error::SerializationError(crate::SerializationError::SeedPolicyMismatch {
                expected: "explicit c1 rows",
                found: "a regenerating seed",
            }),
        );

        // An explicit-rows encoding is admitted by the explicit-rows policy
        // and rejected by the seeded policy. Every entry's rows are replaced
        // by duplicates of its c0 rows, which models the shape the
        // constructors produce for explicit c1 rows without re-deriving real
        // key material: this test is about the wire form, not the key
        // contents.
        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        for some_gk in proto.gk.iter_mut() {
            let Some(some_ksk) = some_gk.ksk.as_mut() else {
                return Err(crate::Error::DefaultError(
                    "test key must contain key-switching keys".to_string(),
                )
                .into());
            };
            let rows = some_ksk.c0.clone();
            assert!(!rows.is_empty(), "test key must contain rows");
            some_ksk.seed = Vec::new();
            some_ksk.c1 = rows;
        }
        let explicit_bytes = proto.encode_to_vec();
        assert!(
            EvaluationKey::from_bytes_with_request(&explicit_bytes, &params, &explicit_request)
                .is_ok(),
            "the explicit-rows form must decode under the explicit-rows policy"
        );
        // The seeded request's derived bound covers only the seeded form: an
        // explicit-rows payload is larger, so it is rejected on size —
        // before decoding — with the bound of the form the request actually
        // authorizes. (A payload small enough to fit would instead reach the
        // seed-form check, as in the mismatch above.)
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&explicit_bytes, &params, &seeded_request)
                .unwrap_err(),
            crate::Error::SerializationError(crate::SerializationError::PayloadTooLarge {
                object: crate::SerializedObject::EvaluationKey,
                actual: explicit_bytes.len(),
                maximum: seeded_request.wire_bound(&params)?,
            }),
        );
        Ok(())
    }

    #[test]
    fn request_rejects_more_entries_than_authorized() -> Result<(), Box<dyn Error>> {
        // Degree 16 admits 16 distinct odd substitution exponents; 17 entries
        // (each an empty Galois key message) exceed both the request's count
        // and what can ever decode, and are rejected without scanning any
        // entry.
        let (params, _ek) = inner_sum_key(1, 16)?;
        let mut outer = Vec::new();
        for _ in 0..=params.degree() {
            outer.extend_from_slice(&[0x12, 0x00]);
        }
        let request = inner_sum_request(&params)?;
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&outer, &params, &request).unwrap_err(),
            crate::Error::SerializationError(crate::SerializationError::GaloisKeyCountExceeded {
                authorized: request.galois_keys.authorized_count(),
                actual: params.degree() + 1,
            }),
            "the preflight must reject the entry excess before decoding"
        );
        assert!(EvaluationKey::from_bytes(&outer, &params).is_err());
        Ok(())
    }

    #[test]
    fn default_cap_rejects_large_keys_and_the_derived_bound_admits_the_length() {
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

        // On the request route the size rejection names the locally derived
        // bound (a few KB for these small parameters), not the global cap,
        // and it fires before the payload is parsed.
        let request = inner_sum_request(&params).unwrap();
        let bound = request.wire_bound(&params).unwrap();
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&oversized, &params, &request).unwrap_err(),
            crate::Error::SerializationError(crate::SerializationError::PayloadTooLarge {
                object: crate::SerializedObject::EvaluationKey,
                actual: oversized.len(),
                maximum: bound,
            }),
        );
    }

    #[test]
    fn request_validation_rejects_invalid_authorizations() -> Result<(), Box<dyn Error>> {
        let params = BfvParameters::default_arc(1, 16);

        // A ciphertext level above the parameter range.
        let error = EvaluationKeyDecodeRequest {
            ciphertext_level: params.max_level() + 1,
            evaluation_key_level: 0,
            galois_keys: GaloisKeySpec::AtMost(1),
            seed_policy: SeedPolicy::Either,
        }
        .wire_bound(&params)
        .unwrap_err();
        assert_eq!(
            error,
            crate::Error::InvalidLevel {
                level: params.max_level() + 1,
                min_level: 0,
                max_level: params.max_level(),
            }
        );

        // An inverted level ordering.
        let params_with_levels = BfvParameters::default_arc(3, 16);
        let error = EvaluationKeyDecodeRequest {
            ciphertext_level: 1,
            evaluation_key_level: 2,
            galois_keys: GaloisKeySpec::AtMost(1),
            seed_policy: SeedPolicy::Either,
        }
        .wire_bound(&params_with_levels)
        .unwrap_err();
        assert_eq!(
            error,
            crate::Error::InvalidLevel {
                level: 2,
                min_level: 0,
                max_level: 1,
            }
        );

        // Even substitution exponents can never decode, so an exact set
        // containing one is rejected when the bound is derived.
        let error = EvaluationKeyDecodeRequest {
            ciphertext_level: 0,
            evaluation_key_level: 0,
            galois_keys: GaloisKeySpec::Exactly(BTreeSet::from([4])),
            seed_policy: SeedPolicy::Either,
        }
        .wire_bound(&params)
        .unwrap_err();
        assert_eq!(
            error,
            crate::Error::MathError(fhe_math::Error::InvalidSubstitutionExponent {
                exponent: 4,
                degree: params.degree(),
            })
        );
        Ok(())
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
        // Drop one own entry so the payload stays within the request's
        // authorized entry count: the duplicate must be caught per entry,
        // not by the count bound.
        proto.gk.truncate(proto.gk.len() - 1);
        proto.gk.push(duplicate);
        let bytes = proto.encode_to_vec();
        let request = inner_sum_request(&params)?;

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
            EvaluationKey::from_bytes_with_request(&bytes, &params, &request).unwrap_err(),
            expected,
            "the preflight must reject duplicates before decoding"
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
        let request = inner_sum_request(&params)?;

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
            EvaluationKey::from_bytes_with_request(&bytes, &params, &request).unwrap_err(),
            expected,
            "the preflight must reject excess rows before decoding"
        );
        Ok(())
    }

    #[test]
    fn request_preflight_rejects_a_flood_of_tiny_repeated_fields() -> Result<(), Box<dyn Error>> {
        // A few dozen bytes claiming 50 key-switching rows for parameters
        // that imply 3. The preflight counts rows without materializing them.
        let (params, _ek) = inner_sum_key(3, 16)?;
        let ksk = [0x0a, 0x00].repeat(50); // 50 empty c0 entries
        let mut gk = vec![0x10, 0x03]; // exponent 3, in the inner-sum request's authorized set
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
        let request = inner_sum_request(&params)?;
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&outer, &params, &request).unwrap_err(),
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
        let request = inner_sum_request(&params)?;

        let expected =
            crate::Error::SerializationError(crate::SerializationError::DuplicateGaloisExponent {
                exponent: aliased,
            });
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&bytes, &params, &request).unwrap_err(),
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
        let request = inner_sum_request(&params)?;

        let expected = crate::Error::MathError(fhe_math::Error::InvalidSubstitutionExponent {
            exponent: 4,
            degree: params.degree(),
        });
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&bytes, &params, &request).unwrap_err(),
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
        let (params, _ek) = inner_sum_key(3, 16)?;
        let request = inner_sum_request(&params)?;

        // A Galois key entry with an over-u32 exponent, hand-encoded as the
        // only entry so the request's authorized entry count does not reject
        // the payload first.
        let wide_exponent: Vec<u8> =
            [0x12, 0x08, 0x0a, 0x00, 0x10, 0x81, 0x80, 0x80, 0x80, 0x10].to_vec();
        let error =
            EvaluationKey::from_bytes_with_request(&wide_exponent, &params, &request).unwrap_err();
        assert!(
            matches!(
                error,
                crate::Error::SerializationError(crate::SerializationError::InvalidFormat {
                    reason: _
                })
            ) && error.to_string().contains("exceeds uint32"),
            "the preflight must reject the over-u32 exponent, got {error}"
        );

        // An over-u32 ciphertext level as the only outer scalar. `prost`
        // would silently truncate it to level 1; the preflight refuses the
        // truncation itself, which is exactly what the request route must
        // not tolerate. The default route decodes the truncated payload and
        // fails later, so its outcome is intentionally not asserted here.
        let wide_level: Vec<u8> = [0x18, 0x81, 0x80, 0x80, 0x80, 0x10].to_vec();
        let error =
            EvaluationKey::from_bytes_with_request(&wide_level, &params, &request).unwrap_err();
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
        let request = inner_sum_request(&params)?;

        let expected =
            crate::Error::SerializationError(crate::SerializationError::WrongPolynomialCount {
                component: crate::SerializedPolynomialComponent::KeySwitchingKeyC0,
                expected: row_count,
                actual: 0,
            });
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&bytes, &params, &request).unwrap_err(),
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
    fn request_preflight_rejects_the_first_malformed_entry_without_decoding()
    -> Result<(), Box<dyn Error>> {
        // Two hand-built entries follow the key's own serialization: one
        // whose key-switching key has no c0 rows (a shape violation), and
        // one whose bytes are not decodable by `prost` at all. The request
        // route reports the shape violation of the first entry, which proves
        // the preflight rejected the payload before the decoder ran — a
        // decode would have surfaced the trailing wire error instead, as the
        // default route does. Two of the key's own entries are dropped so
        // the payload stays within the request's authorized entry count, and
        // the crafted shape-violating entry uses an exponent that thus
        // became free.
        let (params, ek) = inner_sum_key(3, 16)?;
        let row_count = params.moduli().len();
        let request = inner_sum_request(&params)?;
        let GaloisKeySpec::Exactly(authorized) = &request.galois_keys else {
            unreachable!("the helper builds an exact set")
        };

        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        proto.gk.truncate(proto.gk.len() - 2);
        let on_wire: HashSet<u32> = proto.gk.iter().map(|gk| gk.exponent).collect();
        let first_free = authorized
            .iter()
            .find(|e| !on_wire.contains(e))
            .copied()
            .ok_or_else(|| {
                crate::Error::DefaultError("expected a free authorized exponent".to_string())
            })?;

        let mut bytes = proto.encode_to_vec();
        // Shape violation: an exponent from the free set, then an empty
        // key-switching key message (present, with zero c0 rows).
        bytes.extend_from_slice(&[0x12, 0x04, 0x10, first_free as u8, 0x0a, 0x00]);
        // Malformed wire: a key-switching key message that ends mid-field.
        bytes.extend_from_slice(&[0x12, 0x03, 0x0a, 0x01, 0x0a]);

        let error = EvaluationKey::from_bytes_with_request(&bytes, &params, &request).unwrap_err();
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
        let request = inner_sum_request(&params)?;

        let error = EvaluationKey::from_bytes_with_request(&bytes, &params, &request).unwrap_err();
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
    fn request_preflight_mirrors_the_seed_rules() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(3, 16)?;
        let request = inner_sum_request(&params)?;

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
            EvaluationKey::from_bytes_with_request(&wrong_seed_bytes, &params, &request)
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
            EvaluationKey::from_bytes_with_request(&conflict_bytes, &params, &request).unwrap_err(),
            conflict_expected
        );
        assert_eq!(
            EvaluationKey::from_bytes(&conflict_bytes, &params).unwrap_err(),
            conflict_expected
        );
        Ok(())
    }

    #[test]
    fn request_preflight_rejects_levels_outside_the_request() -> Result<(), Box<dyn Error>> {
        let (params, ek) = inner_sum_key(6, 16)?;
        let request = inner_sum_request(&params)?;
        let mut proto = LeveledEvaluationKeyProto::from(&ek);
        proto.ciphertext_level = 1;
        let bytes = proto.encode_to_vec();

        // The request pins the outer ciphertext level, so the preflight
        // rejects the payload against the authorized level before decoding.
        assert_eq!(
            EvaluationKey::from_bytes_with_request(&bytes, &params, &request).unwrap_err(),
            crate::Error::InvalidLevel {
                level: 1,
                min_level: 0,
                max_level: 0,
            }
        );
        // The default route rejects the same payload after decoding, by the
        // post-decode level-consistency check.
        assert_eq!(
            EvaluationKey::from_bytes(&bytes, &params).unwrap_err(),
            crate::Error::InvalidLevel {
                level: 0,
                min_level: 1,
                max_level: 1,
            }
        );
        Ok(())
    }

    #[test]
    fn request_preflight_rejects_duplicate_scalar_fields() -> Result<(), Box<dyn Error>> {
        // Two ciphertext_level fields (field 3, varint) with different values.
        let (params, _ek) = inner_sum_key(1, 16)?;
        let bytes = [0x18, 0x00, 0x18, 0x01];
        let request = inner_sum_request(&params)?;
        let error = EvaluationKey::from_bytes_with_request(&bytes, &params, &request).unwrap_err();
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
    fn request_route_and_default_route_reject_parameter_mismatches() -> Result<(), Box<dyn Error>> {
        let (_, ek) = inner_sum_key(6, 16)?;
        let other_params = BfvParameters::default_arc(5, 16);
        let bytes = ek.to_bytes();
        let request = inner_sum_request(&other_params)?;
        assert!(EvaluationKey::from_bytes(&bytes, &other_params).is_err());
        assert!(
            EvaluationKey::from_bytes_with_request(&bytes, &other_params, &request).is_err(),
            "the request route must reject keys serialized for other parameters"
        );
        Ok(())
    }

    /// End-to-end roundtrip of the evaluation key reported in issue #246:
    /// degree 32768, nine 62-bit moduli, inner-sum support, about 309 MB
    /// encoded. The default route must reject it and the request route must
    /// decode it. Key generation, serialization, and decoding with both keys
    /// in memory peak around 4 GiB and take seconds, so the test stays out
    /// of routine CI.
    ///
    /// The request models the locally known inner-sum configuration for
    /// these parameters: its exponent set is computed from the parameters
    /// and the operation (the `2 * degree - 1` element plus the halving
    /// chain), never from the serialized bytes.
    #[test]
    #[ignore = "requires ~4 GiB peak memory and generates a ~309 MB key"]
    fn oversized_evaluation_key_roundtrips_through_the_request_route() -> Result<(), Box<dyn Error>>
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

        let request = inner_sum_request(&params)?;
        // The derived bound covers the real key: it must be at least the
        // payload length and must dwarf the default cap, from the request
        // alone.
        let bound = request.wire_bound(&params)?;
        assert!(bound >= bytes.len());
        assert!(bound > fhe_traits::MAX_SERIALIZED_BYTES);

        let decoded = EvaluationKey::from_bytes_with_request(&bytes, &params, &request)?;
        assert_eq!(decoded, ek);
        assert!(decoded.supports_inner_sum());
        Ok(())
    }
}
