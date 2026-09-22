//! Shared safeguards for Protobuf-backed FHE serialization.

use prost::Message;

use crate::{Error, SerializationError, SerializedObject};
use fhe_traits::MAX_SERIALIZED_BYTES;

/// Reject an oversized payload before Protobuf decoding.
///
/// Prost checks each length-delimited field against the remaining input. This
/// outer bound instead limits total decoder work and memory use. Decoded
/// repeated fields can use substantially more memory than their encoded bytes,
/// so individual deserializers must still validate object structure.
pub(crate) fn check_size(actual: usize, object: SerializedObject) -> Result<(), Error> {
    if actual > MAX_SERIALIZED_BYTES {
        return Err(SerializationError::PayloadTooLarge {
            object,
            actual,
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
    check_size(bytes.len(), object)?;
    T::decode(bytes).map_err(|error| {
        SerializationError::Decode {
            object,
            message: error.to_string(),
        }
        .into()
    })
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
    fn decode_errors_preserve_the_prost_message() {
        let error = decode::<Probe>(&[0x0a], SerializedObject::Ciphertext).unwrap_err();
        let decoded_error = if let Error::SerializationError(SerializationError::Decode {
            object,
            message,
        }) = error
        {
            Some((object, message))
        } else {
            None
        };
        assert!(decoded_error.is_some());
        let (object, message) =
            decoded_error.unwrap_or_else(|| (SerializedObject::Ciphertext, String::new()));
        assert_eq!(object, SerializedObject::Ciphertext);
        assert!(!message.is_empty());
    }

    #[test]
    fn rejects_payloads_over_the_common_limit() {
        let error = check_size(MAX_SERIALIZED_BYTES + 1, SerializedObject::Ciphertext).unwrap_err();
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
