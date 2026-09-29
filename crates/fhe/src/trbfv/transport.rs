//! The explicit persistence and proof-witness boundary for threshold owners.
//!
//! This module implements the versioned, role-tagged transport envelope used
//! by the opt-in consuming export/import APIs on
//! [`AggregatedSecretKeyShare`](crate::trbfv::AggregatedSecretKeyShare) and
//! [`AggregatedSmudgingShare`](crate::trbfv::AggregatedSmudgingShare), and the
//! non-cloneable [`SmudgingNoiseWitness`] returned by the opt-in
//! [`ShareManager::generate_smudging_shares_with_witness`](crate::trbfv::ShareManager::generate_smudging_shares_with_witness)
//! and
//! [`ShareManager::decryption_share_with_witness`](crate::trbfv::ShareManager::decryption_share_with_witness).
//!
//! # Envelope layout (version 1)
//!
//! Every payload is a fixed-size header followed by two length-delimited
//! sections. The layout is documented because integrators may need to parse
//! the envelope metadata at their own boundary; the library remains the only
//! producer and validator of the payload contents.
//!
//! ```text
//! offset 0..4    magic "FTRS"
//! offset 4       role tag (see [`TransportRole`])
//! offset 5       format version (currently 1)
//! offset 6..10   parameter-section length, u32 little-endian
//! offset 10..14  polynomial-section length, u32 little-endian
//! offset 14..    serialized BFV parameters, then the serialized RNS
//!                polynomial (the existing `Poly` protobuf encoding)
//! ```
//!
//! The polynomial payload reuses the existing `fhe_math::rq::Poly` context
//! serialization (`Poly::to_bytes` / `Poly::from_bytes`), so representation,
//! degree, coefficient count, and canonical-residue validation are inherited
//! from the math crate instead of being reinvented here. The parameter section
//! reuses the existing `BfvParameters` serialization and is compared by value
//! against the importing parameters, which binds every payload to the full
//! parameter set (plaintext modulus, moduli, variances) and not merely to the
//! ring context.
//!
//! # What this boundary does and does not guarantee
//!
//! Export and import are *consuming* operations on non-cloneable owners, and
//! every *secret-bearing* buffer this module owns is zeroized on drop: the
//! owner polynomials, the exported polynomial copy, the envelope buffer, a
//! consumed import input (wiped on success and on every failure path), and
//! the decoded polynomial of a successful witness validation. The serialized
//! parameter section is public data and is intentionally kept in an ordinary,
//! unwiped buffer — public material does not need wiping. The one exception
//! class for secret material is the `Poly` deserializer's internal transient
//! buffers, which the math crate does not wipe (documented in the trBFV
//! README's memory limits). Wiping does not extend to copies of exported
//! bytes: a `Zeroizing<Vec<u8>>` envelope can be copied after the boundary,
//! and importing the same bytes
//! twice yields two independent owners. See the trBFV README for the full
//! threat model and the integrator responsibilities (authentication, storage
//! encryption, identity binding, retries, durable replay prevention).

use std::sync::Arc;

use fhe_traits::{Deserialize, MAX_SERIALIZED_BYTES, Serialize};
use zeroize::Zeroizing;

use crate::bfv::BfvParameters;
use crate::{Error, ParameterSource, SerializationError, SerializedObject};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::DeserializeWithContext;

/// Envelope magic bytes ("fhe.rs transport share").
const ENVELOPE_MAGIC: [u8; 4] = *b"FTRS";

/// Envelope format version. Bumped for any layout change; importers reject
/// versions they do not implement instead of guessing.
const ENVELOPE_VERSION: u8 = 1;

/// Fixed header length: magic (4) + role (1) + version (1) + two `u32`
/// section lengths (4 + 4).
const HEADER_LEN: usize = 14;

/// Byte length of one `u32` section length field.
const SECTION_LENGTH_BYTES: usize = 4;

/// Which protocol role a transport envelope carries.
///
/// The role tag is part of the authenticated-content surface of the envelope:
/// importers reject payloads whose role does not match the type they are
/// importing, so a persisted key aggregate cannot be re-imported as a smudging
/// aggregate or read as a witness (and vice versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportRole {
    /// A reusable aggregated secret-key share; importable.
    AggregatedSecretKeyShare = 1,
    /// A single-use aggregated smudging share; importable.
    AggregatedSmudgingShare = 2,
    /// A proof witness for the noise a dealer dealt; export-only.
    DealtNoiseWitness = 3,
    /// A proof witness for the noise one decryption used; export-only.
    DecryptionNoiseWitness = 4,
}

impl TransportRole {
    /// Decode a role byte, rejecting unknown tags.
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::AggregatedSecretKeyShare),
            2 => Some(Self::AggregatedSmudgingShare),
            3 => Some(Self::DealtNoiseWitness),
            4 => Some(Self::DecryptionNoiseWitness),
            _ => None,
        }
    }

    /// The [`SerializedObject`] used to attribute decoding failures of this
    /// role in error messages.
    fn serialized_object(self) -> SerializedObject {
        match self {
            Self::AggregatedSecretKeyShare => SerializedObject::TrbfvAggregatedSecretKeyShare,
            Self::AggregatedSmudgingShare => SerializedObject::TrbfvAggregatedSmudgingShare,
            Self::DealtNoiseWitness | Self::DecryptionNoiseWitness => {
                SerializedObject::TrbfvSmudgingNoiseWitness
            }
        }
    }
}

/// Where a smudging-noise proof witness came from.
///
/// The provenance is recorded in the witness and written into its role tag on
/// export, so exported witness bytes are self-describing and a dealing
/// witness cannot silently stand in for a decryption witness (or vice versa)
/// when the receiving side validates the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoiseWitnessProvenance {
    /// The noise a dealer dealt via
    /// [`ShareManager::generate_smudging_shares_with_witness`](crate::trbfv::ShareManager::generate_smudging_shares_with_witness).
    Dealt,
    /// The aggregated noise one
    /// [`ShareManager::decryption_share_with_witness`](crate::trbfv::ShareManager::decryption_share_with_witness)
    /// call used.
    Decryption,
}

impl NoiseWitnessProvenance {
    /// The transport role this provenance maps to.
    fn transport_role(self) -> TransportRole {
        match self {
            Self::Dealt => TransportRole::DealtNoiseWitness,
            Self::Decryption => TransportRole::DecryptionNoiseWitness,
        }
    }
}

/// Non-cloneable proof witness holding the exact smudging noise behind one
/// dealing or decryption event, in RNS polynomial encoding.
///
/// The witness exists so an external zero-knowledge proof system (for example
/// a C6-style proof of correct decryption) can refer to the *exact* noise
/// values that entered one protocol event, without the library exposing a raw
/// noise accessor or allowing the live owner to be used twice:
///
/// - [`ShareManager::generate_smudging_shares_with_witness`](crate::trbfv::ShareManager::generate_smudging_shares_with_witness)
///   consumes the sampled noise owner and returns the dealt shares together
///   with a witness of the dealt noise.
/// - [`ShareManager::decryption_share_with_witness`](crate::trbfv::ShareManager::decryption_share_with_witness)
///   consumes one aggregated noise owner — so no second decryption can use
///   the live owner — and returns the decryption share together with a
///   witness of the noise that entered that decryption share.
///
/// The witness is deliberately not `Clone` and has no coefficient accessor:
/// its only escape is the consuming
/// [`into_proof_bytes`](Self::into_proof_bytes), which returns owned
/// [`Zeroizing<Vec<u8>>`] bytes in the transport envelope described in the
/// [module documentation](self). The values stay in RNS residue encoding;
/// converting them into the centered integers a specific proof system
/// expects is an integrator responsibility, as is binding the witness to the
/// ciphertext, decryption domain, and proof statement it belongs to.
///
/// Once [`into_proof_bytes`](Self::into_proof_bytes) (or any copy made of its
/// output) exists, the library no longer controls the material: bytes are
/// infinitely copyable and replayable, and no one-time semantics are promised
/// for them.
///
/// ```compile_fail
/// # use fhe::trbfv::SmudgingNoiseWitness;
/// fn duplicate(witness: &SmudgingNoiseWitness) -> SmudgingNoiseWitness {
///     witness.clone()
/// }
/// ```
///
/// The polynomial stays private; there is no raw-noise accessor:
///
/// ```compile_fail
/// # use fhe::trbfv::SmudgingNoiseWitness;
/// fn read_noise(witness: &SmudgingNoiseWitness) {
///     let _ = &witness.poly;
/// }
/// ```
pub struct SmudgingNoiseWitness {
    pub(crate) provenance: NoiseWitnessProvenance,
    pub(crate) params: Arc<BfvParameters>,
    pub(crate) poly: Zeroizing<Poly<PowerBasis>>,
}

impl SmudgingNoiseWitness {
    /// Build a witness from a guarded copy of the noise polynomial.
    pub(crate) fn new(
        provenance: NoiseWitnessProvenance,
        poly: Zeroizing<Poly<PowerBasis>>,
        params: Arc<BfvParameters>,
    ) -> Self {
        Self {
            provenance,
            params,
            poly,
        }
    }

    /// Returns which protocol event this witness refers to.
    #[must_use]
    pub fn provenance(&self) -> NoiseWitnessProvenance {
        self.provenance
    }

    /// Returns the parameter set the witnessed noise was sampled under.
    #[must_use]
    pub fn params(&self) -> &Arc<BfvParameters> {
        &self.params
    }

    /// Consume the witness into proof-boundary bytes.
    ///
    /// The returned [`Zeroizing<Vec<u8>>`] envelope is wiped when dropped and
    /// carries the provenance role tag, the format version, the full
    /// parameter set, and the noise polynomial in its RNS encoding. It may be
    /// *cloned after this boundary*: the returned bytes are ordinary data and
    /// the library cannot prevent copies from being made, stored, or
    /// replayed. Integrators own authentication, storage encryption, and the
    /// binding of the bytes to the proof statement they support.
    ///
    /// The consuming signature means one live witness can be exported once;
    /// that is a move-safety property of the live value only and is *not* a
    /// one-time guarantee for the exported bytes.
    pub fn into_proof_bytes(self) -> Result<Zeroizing<Vec<u8>>, Error> {
        // Guard the serializer's output copy; the encoder below copies it
        // into the wipe-on-drop envelope. The `Poly::to_bytes` call itself
        // also builds short-lived internal buffers that the math crate does
        // not wipe; see the README's documented memory limits.
        let poly_bytes = Zeroizing::new(self.poly.to_bytes());
        encode_envelope(self.provenance.transport_role(), &self.params, &poly_bytes)
    }

    /// Validate witness-shaped bytes against a parameter set and provenance
    /// without producing a live owner.
    ///
    /// This is the receiving-side check for bytes produced by
    /// [`into_proof_bytes`](Self::into_proof_bytes): it verifies the magic,
    /// role tag, format version, section bounds, the embedded parameter set
    /// (by full value equality against `params`), and the polynomial payload
    /// (representation, shape, and canonical RNS residues at level 0).
    ///
    /// A successfully decoded polynomial is immediately placed under a
    /// wipe-on-drop owner, so its backing storage is wiped when this call
    /// returns. Honest limitation: the `Poly` deserializer's internal
    /// transient buffers — and any buffers abandoned on a decode *error*
    /// path — are not wiped by the math crate (documented limitation), so
    /// this check does not erase every copy the decode creates. Validation
    /// is *not* authentication: any party can craft bytes that pass. It only
    /// establishes that the payload is well-formed for the supplied
    /// parameters and provenance.
    pub fn validate_proof_bytes(
        bytes: &[u8],
        params: &Arc<BfvParameters>,
        provenance: NoiseWitnessProvenance,
    ) -> Result<(), Error> {
        let poly_bytes = decode_envelope(bytes, provenance.transport_role(), params)?;
        let ctx = params.context_at_level(0)?;
        // Decode only to validate; the decoded polynomial is held in a
        // wipe-on-drop owner so its storage is zeroized when it is dropped
        // at the end of this scope.
        let _validated = Zeroizing::new(Poly::<PowerBasis>::from_bytes(poly_bytes, ctx)?);
        Ok(())
    }
}

impl std::fmt::Debug for SmudgingNoiseWitness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SmudgingNoiseWitness")
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

/// Encode one transport envelope around a serialized polynomial payload.
///
/// The envelope buffer is a [`Zeroizing<Vec<u8>>`] from allocation onward, so
/// the secret polynomial bytes only ever live in wipe-on-drop storage at this
/// boundary (plus the serializer-internal transients documented in the
/// README). The parameter section is public data and is stored in an
/// ordinary, unwiped buffer. The total envelope length is bounds-checked —
/// with checked additions — before allocating the envelope buffer.
pub(crate) fn encode_envelope(
    role: TransportRole,
    params: &Arc<BfvParameters>,
    poly_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    // The parameter section is public data and is stored unguarded.
    let params_bytes = params.to_bytes();
    let params_len =
        u32::try_from(params_bytes.len()).map_err(|_| SerializationError::PayloadTooLarge {
            object: SerializedObject::Parameters,
            actual: params_bytes.len(),
            maximum: u32::MAX as usize,
        })?;
    let poly_len =
        u32::try_from(poly_bytes.len()).map_err(|_| SerializationError::PayloadTooLarge {
            object: role.serialized_object(),
            actual: poly_bytes.len(),
            maximum: u32::MAX as usize,
        })?;

    // Symmetric to the decode-side whole-envelope bound: the exact total is
    // computed with checked additions and capped at the common serialization
    // bound before the buffer is allocated.
    let total = checked_envelope_total(params_bytes.len(), poly_bytes.len(), role)?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(total));
    envelope.extend_from_slice(&ENVELOPE_MAGIC);
    envelope.push(role as u8);
    envelope.push(ENVELOPE_VERSION);
    envelope.extend_from_slice(&params_len.to_le_bytes());
    envelope.extend_from_slice(&poly_len.to_le_bytes());
    envelope.extend_from_slice(&params_bytes);
    envelope.extend_from_slice(poly_bytes);
    Ok(envelope)
}

/// Parse and validate one transport envelope.
///
/// Returns the polynomial-payload section after checking, in order: the
/// whole input is within the common serialization bound, the header is
/// complete, the magic matches, the role tag matches `expected_role`, the
/// version is implemented, both declared section lengths are within the
/// common serialization bound, both sections are fully present (no
/// truncation), and there is no trailing data. The embedded parameters are
/// then decoded and compared by value against `params`, which is the
/// parameter-set binding that ring-context equality alone cannot provide.
///
/// The whole-input bound and the length/header checks are envelope-level:
/// they run before either section is decoded, so oversized or truncated
/// input is rejected without a decoder running. The parameter section is
/// decoded next; this function does not decode the polynomial payload at
/// all — the caller's decode performs the polynomial's own representation,
/// shape, and canonical-residue validation. Declared lengths are
/// bounds-checked against the actual input before any section is sliced or
/// decoded.
pub(crate) fn decode_envelope<'a>(
    bytes: &'a [u8],
    expected_role: TransportRole,
    params: &Arc<BfvParameters>,
) -> Result<&'a [u8], Error> {
    let object = expected_role.serialized_object();
    let invalid = |reason: String| -> Error { SerializationError::InvalidFormat { reason }.into() };

    // Finite whole-envelope bound: rejected before any header parsing or
    // section decoding, symmetric to the encode-side total check.
    check_envelope_size(bytes.len(), object)?;
    if bytes.len() < HEADER_LEN {
        return Err(invalid(format!(
            "payload has {} bytes, shorter than the {HEADER_LEN}-byte transport envelope header",
            bytes.len()
        )));
    }
    if bytes.get(0..4) != Some(ENVELOPE_MAGIC.as_slice()) {
        return Err(invalid("wrong transport envelope magic".to_string()));
    }
    let role_byte = bytes
        .get(4)
        .copied()
        .ok_or_else(|| invalid("missing role byte".to_string()))?;
    match TransportRole::from_byte(role_byte) {
        Some(role) if role == expected_role => {}
        Some(_) => {
            return Err(invalid(format!(
                "payload role tag {role_byte} does not match the expected role tag {}",
                expected_role as u8
            )));
        }
        None => {
            return Err(invalid(format!("unknown payload role tag {role_byte}")));
        }
    }
    let version = bytes
        .get(5)
        .copied()
        .ok_or_else(|| invalid("missing version byte".to_string()))?;
    if version != ENVELOPE_VERSION {
        return Err(invalid(format!(
            "unsupported envelope version {version}; this build implements {ENVELOPE_VERSION}"
        )));
    }

    let params_len_bytes = bytes
        .get(6..10)
        .ok_or_else(|| invalid("truncated parameter length field".to_string()))?;
    let params_len = read_section_length(params_len_bytes, object)?;
    let poly_len_bytes = bytes
        .get(10..14)
        .ok_or_else(|| invalid("truncated polynomial length field".to_string()))?;
    let poly_len = read_section_length(poly_len_bytes, object)?;

    let params_end = HEADER_LEN
        .checked_add(params_len)
        .ok_or_else(|| invalid("parameter section length overflows".to_string()))?;
    if params_end > bytes.len() {
        return Err(invalid(format!(
            "payload declares {params_len} parameter bytes but only {} follow the header",
            bytes.len() - HEADER_LEN
        )));
    }
    let poly_end = params_end
        .checked_add(poly_len)
        .ok_or_else(|| invalid("polynomial section length overflows".to_string()))?;
    if poly_end != bytes.len() {
        return Err(invalid(format!(
            "payload sections end at byte {poly_end} but the payload has {} bytes (truncated or \
             trailing data)",
            bytes.len()
        )));
    }

    // Both sections are now fully present and bounded; slice them.
    let params_bytes = bytes
        .get(HEADER_LEN..params_end)
        .ok_or_else(|| invalid("parameter section is missing".to_string()))?;
    let poly_bytes = bytes
        .get(params_end..poly_end)
        .ok_or_else(|| invalid("polynomial section is missing".to_string()))?;

    // Parameter-set binding: decode the embedded parameters (fully validated
    // by the parameter deserializer) and require value equality with the
    // importing parameter set. This rejects payloads produced under a
    // different plaintext modulus, modulus chain, degree, or error variance —
    // differences a ring-context check cannot catch.
    let embedded_params = BfvParameters::try_deserialize(params_bytes)?;
    if embedded_params != **params {
        return Err(Error::ParameterMismatch {
            left: ParameterSource::PersistedShare,
            right: ParameterSource::Parameters,
        });
    }
    Ok(poly_bytes)
}

/// Reject a whole-envelope size before any parsing, slicing, or decoding.
///
/// This is the finite upper bound on the entire payload (header plus both
/// sections), symmetric to the encode-side total check: an import can never
/// be driven by an oversized buffer just because each section individually
/// looks bounded.
fn check_envelope_size(total: usize, object: SerializedObject) -> Result<(), Error> {
    if total > MAX_SERIALIZED_BYTES {
        return Err(SerializationError::PayloadTooLarge {
            object,
            actual: total,
            maximum: MAX_SERIALIZED_BYTES,
        }
        .into());
    }
    Ok(())
}

/// Compute the exact total envelope length with checked additions and bound
/// it before anything is allocated (encode side of
/// [`check_envelope_size`]).
fn checked_envelope_total(
    params_len: usize,
    poly_len: usize,
    role: TransportRole,
) -> Result<usize, Error> {
    let object = role.serialized_object();
    let total = HEADER_LEN
        .checked_add(params_len)
        .and_then(|partial| partial.checked_add(poly_len))
        .ok_or(SerializationError::PayloadTooLarge {
            object,
            actual: usize::MAX,
            maximum: MAX_SERIALIZED_BYTES,
        })?;
    check_envelope_size(total, object)?;
    Ok(total)
}

/// Read and bound-check one `u32` little-endian section length.
fn read_section_length(field: &[u8], object: SerializedObject) -> Result<usize, Error> {
    let field: [u8; SECTION_LENGTH_BYTES] =
        field
            .try_into()
            .map_err(|_| SerializationError::InvalidFormat {
                reason: "section length field has the wrong width".to_string(),
            })?;
    let length = u32::from_le_bytes(field) as usize;
    // Bounded input before decoding: the declared length is rejected here,
    // before any section is sliced or decoded, so a corrupt length field
    // cannot drive decoder allocation.
    if length > MAX_SERIALIZED_BYTES {
        return Err(SerializationError::PayloadTooLarge {
            object,
            actual: length,
            maximum: MAX_SERIALIZED_BYTES,
        }
        .into());
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic
    )]
    use super::*;
    use crate::support::presets::insecure;
    use fhe_math::rq::Ntt;
    use zeroize::Zeroize;

    fn sample_key_bytes() -> (Arc<BfvParameters>, Zeroizing<Vec<u8>>) {
        let params = insecure().unwrap().parameters;
        let ctx = params.context_at_level(0).unwrap();
        let mut poly = Poly::<Ntt>::zero(ctx);
        poly.disallow_variable_time_computations();
        let poly_bytes = poly.to_bytes();
        let envelope = encode_envelope(
            TransportRole::AggregatedSecretKeyShare,
            &params,
            &poly_bytes,
        )
        .unwrap();
        (params, envelope)
    }

    #[test]
    fn envelope_header_matches_documented_layout() {
        let (params, envelope) = sample_key_bytes();
        let bytes = envelope.as_slice();
        assert_eq!(&bytes[0..4], b"FTRS".as_slice());
        assert_eq!(bytes[4], TransportRole::AggregatedSecretKeyShare as u8);
        assert_eq!(bytes[5], ENVELOPE_VERSION);
        let params_len = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize;
        let poly_len = u32::from_le_bytes(bytes[10..14].try_into().unwrap()) as usize;
        assert_eq!(params_len, params.to_bytes().len());
        assert_eq!(HEADER_LEN + params_len + poly_len, bytes.len());
    }

    #[test]
    fn decode_envelope_accepts_valid_payload_and_returns_poly_section() {
        let (params, envelope) = sample_key_bytes();
        let params_len = params.to_bytes().len();
        let poly_bytes = decode_envelope(
            envelope.as_slice(),
            TransportRole::AggregatedSecretKeyShare,
            &params,
        )
        .unwrap();
        assert_eq!(poly_bytes.len(), envelope.len() - HEADER_LEN - params_len);
    }

    #[test]
    fn decode_envelope_rejects_wrong_magic() {
        let (params, mut envelope) = sample_key_bytes();
        envelope[0] = b'X';
        assert!(
            decode_envelope(
                envelope.as_slice(),
                TransportRole::AggregatedSecretKeyShare,
                &params
            )
            .is_err()
        );
    }

    #[test]
    fn decode_envelope_rejects_unknown_and_wrong_roles() {
        let (params, envelope) = sample_key_bytes();

        // A known role that differs from the payload's role is rejected.
        assert!(
            decode_envelope(
                envelope.as_slice(),
                TransportRole::AggregatedSmudgingShare,
                &params
            )
            .is_err()
        );

        // An unknown role byte is rejected.
        let mut corrupted = envelope.as_slice().to_vec();
        corrupted[4] = 200;
        assert!(
            decode_envelope(&corrupted, TransportRole::AggregatedSecretKeyShare, &params).is_err()
        );
    }

    #[test]
    fn decode_envelope_rejects_unimplemented_version() {
        let (params, mut envelope) = sample_key_bytes();
        envelope[5] = ENVELOPE_VERSION + 1;
        assert!(
            decode_envelope(
                envelope.as_slice(),
                TransportRole::AggregatedSecretKeyShare,
                &params
            )
            .is_err()
        );
    }

    #[test]
    fn decode_envelope_rejects_truncated_headers_and_sections() {
        let (params, envelope) = sample_key_bytes();
        let bytes = envelope.as_slice();

        // Shorter than the fixed header.
        for cut in 0..HEADER_LEN {
            assert!(
                decode_envelope(
                    &bytes[..cut],
                    TransportRole::AggregatedSecretKeyShare,
                    &params
                )
                .is_err()
            );
        }

        // Parameter section truncated: declared length no longer matches the
        // remaining bytes.
        assert!(
            decode_envelope(
                &bytes[..bytes.len() - 1],
                TransportRole::AggregatedSecretKeyShare,
                &params
            )
            .is_err()
        );
    }

    #[test]
    fn decode_envelope_rejects_trailing_data_and_oversized_lengths() {
        let (params, envelope) = sample_key_bytes();

        // Trailing garbage breaks the exact section-length accounting.
        let mut trailing = envelope.as_slice().to_vec();
        trailing.push(0);
        assert!(
            decode_envelope(&trailing, TransportRole::AggregatedSecretKeyShare, &params).is_err()
        );

        // A corrupted (oversized) declared polynomial length is rejected
        // before any decoding work.
        let mut oversized = envelope.as_slice().to_vec();
        oversized[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
        let error = decode_envelope(&oversized, TransportRole::AggregatedSecretKeyShare, &params)
            .unwrap_err();
        assert!(matches!(
            error,
            Error::SerializationError(SerializationError::PayloadTooLarge { .. })
        ));

        // A corrupted declared parameter length that stays within the common
        // bound but exceeds the input is reported as a truncated payload.
        let mut truncated = envelope.as_slice().to_vec();
        truncated[6..10].copy_from_slice(&(MAX_SERIALIZED_BYTES as u32).to_le_bytes());
        assert!(matches!(
            decode_envelope(&truncated, TransportRole::AggregatedSecretKeyShare, &params),
            Err(Error::SerializationError(
                SerializationError::InvalidFormat { .. }
            ))
        ));
    }

    #[test]
    fn decode_envelope_rejects_wrong_parameter_binding() {
        let (_, envelope) = sample_key_bytes();
        let other = crate::bfv::BfvParametersBuilder::new()
            .set_degree(64)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[40, 40])
            .build_arc()
            .unwrap();
        assert!(matches!(
            decode_envelope(
                envelope.as_slice(),
                TransportRole::AggregatedSecretKeyShare,
                &other
            ),
            Err(Error::ParameterMismatch {
                left: ParameterSource::PersistedShare,
                right: ParameterSource::Parameters,
            })
        ));
    }

    #[test]
    fn decode_envelope_rejects_malformed_parameter_section() {
        let (params, envelope) = sample_key_bytes();
        let mut corrupted = envelope.as_slice().to_vec();
        let params_end = HEADER_LEN + params.to_bytes().len();
        corrupted[HEADER_LEN..params_end].fill(0xff);
        assert!(matches!(
            decode_envelope(&corrupted, TransportRole::AggregatedSecretKeyShare, &params),
            Err(Error::SerializationError(SerializationError::Decode {
                object: SerializedObject::Parameters,
                ..
            }))
        ));
    }

    #[test]
    fn consumed_envelope_ownership_wipes_on_drop() {
        // The import boundary takes the envelope by value, so a successful or
        // failing import drops (and thereby wipes) the caller's buffer. This
        // checks the wipe mechanism on a buffer the test still owns; the
        // consuming signatures are checked at compile time.
        let (_, envelope) = sample_key_bytes();
        let mut buffer = envelope.as_slice().to_vec();
        assert!(buffer.iter().any(|&byte| byte != 0));
        buffer.zeroize();
        assert!(buffer.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn witness_provenance_maps_to_distinct_role_tags() {
        assert_ne!(
            NoiseWitnessProvenance::Dealt.transport_role() as u8,
            NoiseWitnessProvenance::Decryption.transport_role() as u8
        );
    }

    /// Whole-envelope bound, checked purely on lengths: the encode-side total
    /// helper rejects overflow and over-bound totals without allocating, and
    /// accepts the exact bound; the decode-side check bounds the input length
    /// before any parsing.
    #[test]
    fn whole_envelope_bound_is_enforced_on_lengths_only() {
        // Encode side: overflow and over-bound totals are rejected without
        // allocating a buffer of that size.
        assert!(matches!(
            checked_envelope_total(usize::MAX, 0, TransportRole::AggregatedSecretKeyShare),
            Err(Error::SerializationError(
                SerializationError::PayloadTooLarge { .. }
            ))
        ));
        assert!(matches!(
            checked_envelope_total(0, usize::MAX, TransportRole::AggregatedSmudgingShare),
            Err(Error::SerializationError(
                SerializationError::PayloadTooLarge { .. }
            ))
        ));
        assert!(matches!(
            checked_envelope_total(MAX_SERIALIZED_BYTES, 1, TransportRole::DealtNoiseWitness),
            Err(Error::SerializationError(
                SerializationError::PayloadTooLarge { .. }
            ))
        ));

        // The largest valid envelope sits exactly at the common bound; the
        // smallest is the bare header.
        assert_eq!(
            checked_envelope_total(
                MAX_SERIALIZED_BYTES - HEADER_LEN,
                0,
                TransportRole::AggregatedSecretKeyShare
            )
            .unwrap(),
            MAX_SERIALIZED_BYTES
        );
        assert_eq!(
            checked_envelope_total(0, 0, TransportRole::AggregatedSecretKeyShare).unwrap(),
            HEADER_LEN
        );

        // Decode side: the whole input length is bounded before parsing.
        assert!(matches!(
            check_envelope_size(
                MAX_SERIALIZED_BYTES + 1,
                SerializedObject::TrbfvSmudgingNoiseWitness
            ),
            Err(Error::SerializationError(
                SerializationError::PayloadTooLarge { .. }
            ))
        ));
        assert!(
            check_envelope_size(
                MAX_SERIALIZED_BYTES,
                SerializedObject::TrbfvSmudgingNoiseWitness
            )
            .is_ok()
        );
    }
}
