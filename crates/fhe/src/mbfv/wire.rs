//! Fail-closed wire encoding for MBFV shares (requires the `protobuf`
//! feature).
//!
//! MBFV shares are serialized as versioned [`MbfvShareEnvelope`] messages that
//! carry the contribution binding metadata (session identifier, canonical
//! participant ID list, and this share's contributor ID) plus the share
//! payload and its operation-specific level. Deserialization fails closed:
//! missing or unsupported versions, absent bindings, malformed session IDs,
//! non-canonical participant lists, and old raw polynomial bytes are all
//! rejected rather than silently interpreted as unbound shares.

use crate::identity::{ContributionBinding, ParticipantSet, SessionId};
use crate::proto::bfv::{MbfvBinding, MbfvShareEnvelope, mbfv_share_envelope};
use crate::{Error, MbfvError, Result, SerializationError};
use prost::Message;

/// The only supported MBFV share envelope schema version.
pub(crate) const MBFV_SHARE_ENVELOPE_VERSION: u32 = 1;

/// Encode a bound MBFV share payload into a versioned envelope.
pub(crate) fn encode_share(
    binding: &ContributionBinding,
    payload: mbfv_share_envelope::Payload,
) -> Vec<u8> {
    MbfvShareEnvelope {
        version: MBFV_SHARE_ENVELOPE_VERSION,
        binding: Some(encode_binding(binding)),
        payload: Some(payload),
    }
    .encode_to_vec()
}

/// Decode and version-check an MBFV share envelope.
///
/// Old raw polynomial bytes fail protobuf decoding or carry no valid version
/// and are rejected; there is no silently inferred unbound mode.
pub(crate) fn decode_share(bytes: &[u8]) -> Result<MbfvShareEnvelope> {
    let envelope = MbfvShareEnvelope::decode(bytes).map_err(|e| {
        Error::SerializationError(SerializationError::ProtobufError {
            message: e.to_string(),
        })
    })?;
    if envelope.version != MBFV_SHARE_ENVELOPE_VERSION {
        return Err(Error::Mbfv(MbfvError::UnsupportedVersion {
            found: envelope.version,
            expected: MBFV_SHARE_ENVELOPE_VERSION,
        }));
    }
    Ok(envelope)
}

/// Encode a contribution binding as wire metadata.
pub(crate) fn encode_binding(binding: &ContributionBinding) -> MbfvBinding {
    MbfvBinding {
        session_id: binding.participant_set().session_id().as_bytes().to_vec(),
        participant_ids: binding.participant_set().participant_ids().to_vec(),
        participant_id: binding.participant_id(),
    }
}

/// Decode and canonically validate contribution binding wire metadata.
///
/// Rejects a missing binding, a malformed session ID, and any participant
/// list that is not canonically sorted in strictly increasing order
/// (unsorted, duplicated, or zero IDs); the accepted lists are exactly the
/// ones [`ParticipantSet`] canonicalization would produce, so no permissive
/// re-sorting happens on the wire.
pub(crate) fn decode_binding(proto: Option<MbfvBinding>) -> Result<ContributionBinding> {
    let proto = proto.ok_or(Error::Mbfv(MbfvError::MissingBinding))?;
    let session_bytes: [u8; 32] = proto.session_id.as_slice().try_into().map_err(|_| {
        Error::SerializationError(SerializationError::InvalidFormat {
            reason: "MBFV session id must be exactly 32 bytes".to_string(),
        })
    })?;
    let ids_in_canonical_order = proto
        .participant_ids
        .iter()
        .zip(proto.participant_ids.iter().skip(1))
        .all(|(left, right)| left < right);
    if !ids_in_canonical_order {
        return Err(Error::SerializationError(
            SerializationError::InvalidFormat {
                reason: "MBFV participant IDs must be sorted in strictly increasing order"
                    .to_string(),
            },
        ));
    }
    let participant_set =
        ParticipantSet::new(SessionId::from(session_bytes), proto.participant_ids)?;
    ContributionBinding::new(participant_set, proto.participant_id)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_binding_metadata() -> Result<()> {
        let set = ParticipantSet::new(SessionId::new([5u8; 32]), vec![3, 1, 2])?;
        let binding = ContributionBinding::new(set.clone(), 2)?;
        let encoded = encode_binding(&binding);
        assert_eq!(encoded.session_id, vec![5u8; 32]);
        assert_eq!(encoded.participant_ids, vec![1, 2, 3]);
        assert_eq!(encoded.participant_id, 2);

        let decoded = decode_binding(Some(encoded))?;
        assert_eq!(decoded, binding);
        Ok(())
    }

    #[test]
    fn decode_rejects_non_canonical_participant_ordering() -> Result<()> {
        // The wire format promises a canonically sorted list; a descending
        // list must be rejected rather than silently re-sorted.
        let descending = MbfvBinding {
            session_id: vec![9u8; 32],
            participant_ids: vec![3, 2, 1],
            participant_id: 1,
        };
        assert!(matches!(
            decode_binding(Some(descending)),
            Err(Error::SerializationError(
                SerializationError::InvalidFormat { .. }
            ))
        ));

        // An unsorted but otherwise valid list is likewise rejected.
        let unsorted = MbfvBinding {
            session_id: vec![9u8; 32],
            participant_ids: vec![1, 3, 2],
            participant_id: 1,
        };
        assert!(decode_binding(Some(unsorted)).is_err());

        // The sorted equivalent still decodes.
        let sorted = MbfvBinding {
            session_id: vec![9u8; 32],
            participant_ids: vec![1, 2, 3],
            participant_id: 1,
        };
        assert!(decode_binding(Some(sorted)).is_ok());
        Ok(())
    }

    #[test]
    fn decode_rejects_missing_and_malformed_bindings() -> Result<()> {
        assert!(matches!(
            decode_binding(None),
            Err(Error::Mbfv(MbfvError::MissingBinding))
        ));

        let malformed_session = MbfvBinding {
            session_id: vec![7u8; 31],
            participant_ids: vec![1],
            participant_id: 1,
        };
        assert!(decode_binding(Some(malformed_session)).is_err());

        let duplicate_ids = MbfvBinding {
            session_id: vec![7u8; 32],
            participant_ids: vec![1, 1],
            participant_id: 1,
        };
        assert!(decode_binding(Some(duplicate_ids)).is_err());
        Ok(())
    }

    #[test]
    fn decode_rejects_old_raw_bytes_and_bad_versions() {
        // Raw polynomial-style bytes (old wire format) must not parse into a
        // valid versioned envelope.
        let raw = vec![0xaau8; 256];
        assert!(decode_share(&raw).is_err());

        let set = ParticipantSet::new(SessionId::new([5u8; 32]), vec![1]).unwrap();
        let binding = ContributionBinding::new(set, 1).unwrap();
        let mut bytes = encode_share(
            &binding,
            mbfv_share_envelope::Payload::SecretKeySwitchShare(Default::default()),
        );
        // Version field is the first varint of the message; corrupting it must
        // yield an UnsupportedVersion error rather than acceptance.
        bytes[0] ^= 0x01;
        let decoded = decode_share(&bytes).unwrap_err();
        assert!(
            matches!(decoded, Error::Mbfv(MbfvError::UnsupportedVersion { .. }))
                || matches!(
                    decoded,
                    Error::SerializationError(SerializationError::ProtobufError { .. })
                ),
            "unexpected error: {decoded}"
        );
    }
}
