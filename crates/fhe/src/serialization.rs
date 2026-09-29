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
///
/// This is the default bound applied by [`decode`] through
/// [`MAX_SERIALIZED_BYTES`]; opt-in routes pass an explicit, caller-supplied
/// bound instead, and violations surface as
/// [`SerializationError::PayloadTooLarge`].
pub(crate) fn check_size_with_limit(
    actual: usize,
    object: SerializedObject,
    maximum: usize,
) -> Result<(), Error> {
    if actual > maximum {
        return Err(SerializationError::PayloadTooLarge {
            object,
            actual,
            maximum,
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
    decode_with_limit(bytes, object, MAX_SERIALIZED_BYTES)
}

/// Decode a Protobuf object after applying an explicit outer size bound.
///
/// The bound limits total decoder work and memory use before `prost` starts
/// materializing the message. Decoded repeated fields can still use
/// substantially more memory than their encoded bytes, so individual
/// deserializers must also validate object structure (see the evaluation-key
/// wire preflight).
pub(crate) fn decode_with_limit<T: Message + Default>(
    bytes: &[u8],
    object: SerializedObject,
    maximum: usize,
) -> Result<T, Error> {
    check_size_with_limit(bytes.len(), object, maximum)?;
    T::decode(bytes).map_err(|error| {
        SerializationError::Decode {
            object,
            message: error.to_string(),
        }
        .into()
    })
}

/// A Protobuf wire-format field value, viewed without copying its payload.
#[derive(Debug)]
pub(crate) enum WireValue<'a> {
    /// A base-128 varint value.
    Varint(u64),
    /// A length-delimited payload (a message, bytes, string, or repeated
    /// packed elements).
    Bytes(&'a [u8]),
    /// A 64-bit fixed-width value; reported as consumed.
    Fixed64,
    /// A 32-bit fixed-width value; reported as consumed.
    Fixed32,
}

/// A validating cursor over raw Protobuf wire format.
///
/// The cursor performs no allocation while scanning: it walks the encoded
/// bytes in place and yields borrowed payloads; only malformed structure
/// allocates, for the error message. It is the substrate of the pre-decode
/// shape preflight, which must bound decoder work and memory before `prost`
/// materializes a message. Unknown field numbers are returned to the caller
/// (who can skip them), but deprecated group wire types (3 and 4) and
/// malformed structure are rejected: the library's schemas never emit them.
#[derive(Debug)]
pub(crate) struct WireCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> WireCursor<'a> {
    /// Creates a cursor over an encoded message.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_varint(&mut self) -> Result<u64, SerializationError> {
        let mut value: u64 = 0;
        for shift in (0..10).map(|round| round * 7) {
            let byte = *self.bytes.get(self.position).ok_or_else(|| {
                SerializationError::InvalidFormat {
                    reason: "truncated varint".to_string(),
                }
            })?;
            self.position += 1;
            if shift == 63 && byte > 1 {
                return Err(SerializationError::InvalidFormat {
                    reason: "varint overflows 64 bits".to_string(),
                });
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(SerializationError::InvalidFormat {
            reason: "varint longer than 10 bytes".to_string(),
        })
    }

    fn skip(&mut self, length: usize) -> Result<(), SerializationError> {
        let end =
            self.position
                .checked_add(length)
                .ok_or_else(|| SerializationError::InvalidFormat {
                    reason: "field length overflows the payload".to_string(),
                })?;
        if end > self.bytes.len() {
            return Err(SerializationError::InvalidFormat {
                reason: "fixed-width field extends past the end of the payload".to_string(),
            });
        }
        self.position = end;
        Ok(())
    }

    /// Returns the next field, or `None` at the end of the payload.
    pub(crate) fn next_field(
        &mut self,
    ) -> Result<Option<(u32, WireValue<'a>)>, SerializationError> {
        if self.position >= self.bytes.len() {
            return Ok(None);
        }
        let tag = self.read_varint()?;
        let field_number = tag >> 3;
        if field_number == 0 || field_number > u32::MAX as u64 {
            return Err(SerializationError::InvalidFormat {
                reason: format!("invalid field number {field_number}"),
            });
        }
        let value = match tag & 0x7 {
            0 => WireValue::Varint(self.read_varint()?),
            1 => {
                self.skip(8)?;
                WireValue::Fixed64
            }
            2 => {
                // Checked on 32-bit targets too: a truncated `as usize` cast
                // could otherwise alias a huge declared length onto a small
                // in-range one.
                let length = usize::try_from(self.read_varint()?).map_err(|_| {
                    SerializationError::InvalidFormat {
                        reason: "length-delimited field length exceeds the address space"
                            .to_string(),
                    }
                })?;
                let end = self.position.checked_add(length).ok_or_else(|| {
                    SerializationError::InvalidFormat {
                        reason: "field length overflows the payload".to_string(),
                    }
                })?;
                let payload = self.bytes.get(self.position..end).ok_or_else(|| {
                    SerializationError::InvalidFormat {
                        reason: "length-delimited field extends past the end of the payload"
                            .to_string(),
                    }
                })?;
                self.position = end;
                WireValue::Bytes(payload)
            }
            5 => {
                self.skip(4)?;
                WireValue::Fixed32
            }
            3 | 4 => {
                return Err(SerializationError::InvalidFormat {
                    reason: "deprecated group wire types are not supported".to_string(),
                });
            }
            _ => {
                return Err(SerializationError::InvalidFormat {
                    reason: format!("invalid wire type {}", tag & 0x7),
                });
            }
        };
        Ok(Some((field_number as u32, value)))
    }
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
        let error = check_size_with_limit(
            MAX_SERIALIZED_BYTES + 1,
            SerializedObject::Ciphertext,
            MAX_SERIALIZED_BYTES,
        )
        .unwrap_err();
        assert_eq!(
            error,
            Error::SerializationError(SerializationError::PayloadTooLarge {
                object: SerializedObject::Ciphertext,
                actual: MAX_SERIALIZED_BYTES + 1,
                maximum: MAX_SERIALIZED_BYTES,
            })
        );
    }

    #[test]
    fn accepts_payloads_within_the_explicit_limit() {
        check_size_with_limit(16, SerializedObject::EvaluationKey, 16).unwrap();
        check_size_with_limit(16, SerializedObject::EvaluationKey, 17).unwrap();
        let error = check_size_with_limit(17, SerializedObject::EvaluationKey, 16).unwrap_err();
        assert_eq!(
            error,
            Error::SerializationError(SerializationError::PayloadTooLarge {
                object: SerializedObject::EvaluationKey,
                actual: 17,
                maximum: 16,
            })
        );
    }

    /// Walks a well-formed message with a known field layout.
    #[test]
    #[expect(
        clippy::panic,
        reason = "let-else needs a diverging branch to extract the payload"
    )]
    fn wire_cursor_reads_fields_in_place() {
        let expected = vec![7; 300];
        let probe = Probe {
            value: expected.clone(),
        }
        .encode_to_vec();
        let mut cursor = WireCursor::new(&probe);
        let (field_number, value) = cursor.next_field().unwrap().unwrap();
        assert_eq!(field_number, 1);
        let WireValue::Bytes(payload) = value else {
            panic!("expected a length-delimited payload");
        };
        assert_eq!(payload, expected.as_slice());
        assert!(cursor.next_field().unwrap().is_none());
    }

    #[test]
    fn wire_cursor_rejects_malformed_structure() {
        let mut cursor = WireCursor::new(&[0x00]);
        assert!(cursor.next_field().is_err(), "field number 0 is invalid");
        let mut cursor = WireCursor::new(&[0x13]);
        assert!(
            cursor.next_field().is_err(),
            "group wire types are rejected"
        );
        let mut cursor = WireCursor::new(&[0x0a, 0xff, 0x01]);
        assert!(
            cursor.next_field().is_err(),
            "truncated payloads are rejected"
        );
        let mut cursor = WireCursor::new(&[0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        assert!(
            cursor.next_field().is_err(),
            "lengths past the end of the payload are rejected"
        );
        let mut cursor = WireCursor::new(&[
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
        ]);
        assert!(
            cursor.next_field().is_err(),
            "varints that overflow 64 bits are rejected"
        );
        // A declared length that overflows the address space (portable) or
        // extends past the payload must be rejected before any slicing.
        let mut cursor = WireCursor::new(&[0x0a, 0x80, 0x80, 0x80, 0x80, 0x10, 1, 2, 3]);
        assert!(
            cursor.next_field().is_err(),
            "oversized length-delimited fields are rejected"
        );
    }

    #[test]
    fn wire_cursor_skips_fixed_width_and_unknown_fields() {
        // Unknown field 15, wire type 1 (64-bit): tag = (15 << 3) | 1 = 0x79,
        // followed by 8 payload bytes. Known field 1 (bytes): tag 0x0a.
        let bytes = [0x79, 1, 2, 3, 4, 5, 6, 7, 8, 0x0a, 0x01, 9];
        let mut cursor = WireCursor::new(&bytes);
        let (field_number, value) = cursor.next_field().unwrap().unwrap();
        assert_eq!(field_number, 15);
        assert!(matches!(value, WireValue::Fixed64));
        let (field_number, value) = cursor.next_field().unwrap().unwrap();
        assert_eq!(field_number, 1);
        let WireValue::Bytes(payload) = value else {
            assert!(matches!(value, WireValue::Bytes(_)));
            return;
        };
        assert_eq!(payload, [9u8]);
        assert!(cursor.next_field().unwrap().is_none());
    }
}
