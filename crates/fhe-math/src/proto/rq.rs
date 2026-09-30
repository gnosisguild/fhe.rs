include!("fhers.rq.rs");

use prost::{Message, encoding::DecodeContext};
use zeroize::{Zeroize, Zeroizing};

impl Zeroize for Rq {
    fn zeroize(&mut self) {
        self.coefficients.zeroize();
        self.representation.zeroize();
        self.degree.zeroize();
        self.allow_variable_time.zeroize();
    }
}

impl Rq {
    /// Decode with a wipe-on-drop owner already in place, including for partial
    /// messages. Preserve Protobuf's last-value-wins semantics while wiping a
    /// previous coefficient field before Prost clears or reallocates its buffer.
    pub(crate) fn decode_zeroizing(
        mut bytes: &[u8],
    ) -> Result<Zeroizing<Self>, prost::DecodeError> {
        let mut message = Zeroizing::new(Self::default());
        while !bytes.is_empty() {
            let (tag, wire_type) = prost::encoding::decode_key(&mut bytes)?;
            if tag == 3 {
                message.coefficients.zeroize();
            }
            // Rq is decoded here as a top-level, flat scalar/bytes-only message.
            // A fresh per-field recursion budget relies on that assumption;
            // revisit context propagation if nested decoding is introduced.
            message.merge_field(tag, wire_type, &mut bytes, DecodeContext::default())?;
        }
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        panic::{AssertUnwindSafe, catch_unwind},
        rc::Rc,
    };

    struct WipeProbe {
        message: Rq,
        wiped: Rc<Cell<bool>>,
    }

    impl Zeroize for WipeProbe {
        fn zeroize(&mut self) {
            self.message.zeroize();
        }
    }

    impl Drop for WipeProbe {
        fn drop(&mut self) {
            self.wiped.set(self.message == Rq::default());
        }
    }

    // Check the wipe mechanism without reading deallocated storage. Decoding
    // and encoding use the same Zeroizing<Rq> ownership and Zeroize impl.
    #[test]
    #[expect(clippy::panic, reason = "simulated unwind to exercise wipe-on-drop")]
    fn proto_guards_wipe_on_drop_and_unwind() {
        for unwind in [false, true] {
            let wiped = Rc::new(Cell::new(false));
            let result = catch_unwind(AssertUnwindSafe(|| {
                let guard = Zeroizing::new(WipeProbe {
                    message: Rq {
                        coefficients: vec![0xaa; 128],
                        ..Rq::default()
                    },
                    wiped: Rc::clone(&wiped),
                });
                if unwind {
                    panic!("simulated unwind while Protobuf residues are guarded");
                }
                drop(guard);
            }));
            assert_eq!(result.is_err(), unwind);
            assert!(wiped.get());
        }
    }

    #[test]
    fn proto_zeroize_clears_coefficients_and_metadata() {
        let mut message = Rq {
            representation: Representation::Powerbasis as i32,
            degree: 16,
            coefficients: vec![0xaa; 64],
            allow_variable_time: true,
        };
        message.zeroize();
        assert_eq!(message, Rq::default());
    }

    #[test]
    fn guarded_decode_preserves_protobuf_merge_semantics() -> Result<(), prost::DecodeError> {
        let first = Rq {
            representation: Representation::Powerbasis as i32,
            degree: 16,
            coefficients: vec![0xaa; 128],
            allow_variable_time: false,
        };
        for replacement in [vec![0xbb; 512], vec![0xcc; 3], Vec::new()] {
            let mut bytes = first.encode_to_vec();
            prost::encoding::bytes::encode(3, &replacement, &mut bytes);
            prost::encoding::uint32::encode(7, &42, &mut bytes);
            assert_eq!(
                *Rq::decode_zeroizing(&bytes)?,
                Rq::decode(bytes.as_slice())?
            );
        }
        Ok(())
    }

    #[test]
    fn guarded_decode_preserves_errors_after_partial_message() {
        let mut bytes = Rq {
            coefficients: vec![0xaa; 128],
            ..Rq::default()
        }
        .encode_to_vec();
        bytes.extend_from_slice(&[0x1a, 0x05, 0xbb]);
        assert_eq!(
            Rq::decode_zeroizing(&bytes).unwrap_err().to_string(),
            Rq::decode(bytes.as_slice()).unwrap_err().to_string()
        );
    }
}
