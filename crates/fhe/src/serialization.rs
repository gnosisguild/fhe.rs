//! Shared safeguards for Protobuf-backed FHE serialization.

use prost::Message;

use crate::{Error, SerializationError, SerializedObject};

/// Maximum size accepted for one serialized FHE object before Protobuf
/// decoding allocates nested fields.
///
/// This is a coarse outer bound. Individual deserializers must still validate
/// context-derived dimensions, row counts, seed lengths, and semantic
/// invariants after decoding.
pub(crate) const MAX_SERIALIZED_BYTES: usize = 256 * 1024 * 1024;

/// Reject an oversized payload before the Protobuf decoder allocates from its
/// length-delimited fields.
pub(crate) fn check_size(bytes: &[u8], object: SerializedObject) -> Result<(), Error> {
    if bytes.len() > MAX_SERIALIZED_BYTES {
        return Err(SerializationError::PayloadTooLarge {
            object,
            actual: bytes.len(),
            maximum: MAX_SERIALIZED_BYTES,
        }
        .into());
    }
    Ok(())
}

/// Decode a Protobuf object after applying the common outer size bound.
pub(crate) fn decode<T: Message + Default>(
    bytes: &[u8],
    object: SerializedObject,
) -> Result<T, Error> {
    check_size(bytes, object)?;
    T::decode(bytes).map_err(|_| SerializationError::Decode { object }.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    struct Probe {
        #[prost(bytes, tag = "1")]
        value: Vec<u8>,
    }

    #[test]
    fn decodes_valid_payloads() {
        let bytes = Probe {
            value: vec![1, 2, 3],
        }
        .encode_to_vec();
        let decoded = decode::<Probe>(&bytes, SerializedObject::Ciphertext).unwrap();
        assert_eq!(decoded.value, vec![1, 2, 3]);
    }

    #[test]
    fn rejects_payloads_over_the_common_limit() {
        let bytes = vec![0; MAX_SERIALIZED_BYTES + 1];
        let error = check_size(&bytes, SerializedObject::Ciphertext).unwrap_err();
        assert_eq!(
            error,
            Error::SerializationError(SerializationError::PayloadTooLarge {
                object: SerializedObject::Ciphertext,
                actual: MAX_SERIALIZED_BYTES + 1,
                maximum: MAX_SERIALIZED_BYTES,
            })
        );
    }
}
