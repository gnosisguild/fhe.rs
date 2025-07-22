//! Protobuf serialization for TRBFV types.

use super::generated::{
    DecryptionShare as DecryptionShareProto, Parameters as ParametersProto,
    SecretShare as SecretShareProto, SecretShareModulus as SecretShareModulusProto,
    SmudgingData as SmudgingDataProto, TrbfvConfig as TrbfvConfigProto,
};
use crate::bfv::{BfvParameters, BfvParametersBuilder};
use crate::trbfv::TRBFV;
use crate::Error;
use fhe_math::rq::Poly;
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, Serialize};
use ndarray::Array2;
use prost::Message;
use std::sync::Arc;

/// Convert TRBFV to protobuf representation
impl From<&TRBFV> for TrbfvConfigProto {
    fn from(trbfv: &TRBFV) -> Self {
        TrbfvConfigProto {
            n: trbfv.n as u32,
            threshold: trbfv.threshold as u32,
            params: Some(ParametersProto::from(trbfv.params.as_ref())),
        }
    }
}

/// Convert BfvParameters to TRBFV protobuf representation
impl From<&BfvParameters> for ParametersProto {
    fn from(params: &BfvParameters) -> Self {
        ParametersProto {
            degree: params.degree() as u32,
            moduli: params.moduli().to_vec(),
            plaintext: params.plaintext(),
        }
    }
}

/// Convert Array2<u64> to protobuf representation for secret shares
impl From<&Array2<u64>> for SecretShareProto {
    fn from(share_matrix: &Array2<u64>) -> Self {
        let moduli_shares: Vec<SecretShareModulusProto> = share_matrix
            .outer_iter()
            .map(|row| SecretShareModulusProto {
                coefficients: row.to_vec(),
            })
            .collect();

        SecretShareProto { moduli_shares }
    }
}

/// Convert Poly to protobuf representation for decryption shares
impl From<&Poly> for DecryptionShareProto {
    fn from(poly: &Poly) -> Self {
        DecryptionShareProto {
            poly_data: poly.to_bytes(),
        }
    }
}

/// Convert Poly to protobuf representation for smudging data
impl From<&Poly> for SmudgingDataProto {
    fn from(poly: &Poly) -> Self {
        SmudgingDataProto {
            poly_data: poly.to_bytes(),
        }
    }
}

/// Serialize TRBFV to bytes
impl Serialize for TRBFV {
    fn to_bytes(&self) -> Vec<u8> {
        TrbfvConfigProto::from(self).encode_to_vec()
    }
}

/// Helper function to serialize Array2<u64> to bytes (for secret shares)
pub fn serialize_secret_share(share_matrix: &Array2<u64>) -> Vec<u8> {
    SecretShareProto::from(share_matrix).encode_to_vec()
}

/// Helper function to serialize Poly to bytes (for decryption shares)
pub fn serialize_decryption_share(poly: &Poly) -> Vec<u8> {
    DecryptionShareProto::from(poly).encode_to_vec()
}

/// Helper function to serialize Poly to bytes (for smudging polynomials)
pub fn serialize_smudging_data(poly: &Poly) -> Vec<u8> {
    SmudgingDataProto::from(poly).encode_to_vec()
}

/// Deserialize TRBFV from bytes
impl DeserializeParametrized for TRBFV {
    type Error = Error;

    fn from_bytes(bytes: &[u8], _par: &Arc<BfvParameters>) -> Result<Self, Self::Error> {
        let proto: TrbfvConfigProto =
            Message::decode(bytes).map_err(|_| Error::SerializationError)?;

        let params_proto = proto.params.ok_or(Error::SerializationError)?;

        // Reconstruct BfvParameters from protobuf
        let params = BfvParametersBuilder::new()
            .set_degree(params_proto.degree as usize)
            .set_moduli(&params_proto.moduli)
            .set_plaintext_modulus(params_proto.plaintext)
            .build_arc()?;

        TRBFV::new(proto.n as usize, proto.threshold as usize, params)
    }
}

/// Helper function to deserialize Array2<u64> from bytes (for secret shares)
pub fn deserialize_secret_share(bytes: &[u8]) -> Result<Array2<u64>, Error> {
    let proto: SecretShareProto = Message::decode(bytes).map_err(|_| Error::SerializationError)?;

    if proto.moduli_shares.is_empty() {
        return Err(Error::SerializationError);
    }

    let nrows = proto.moduli_shares.len();
    let ncols = proto.moduli_shares[0].coefficients.len();

    // Validate all rows have the same length
    for share in &proto.moduli_shares {
        if share.coefficients.len() != ncols {
            return Err(Error::SerializationError);
        }
    }

    // Flatten the data and create Array2
    let mut data = Vec::with_capacity(nrows * ncols);
    for share in proto.moduli_shares {
        data.extend(share.coefficients);
    }

    Array2::from_shape_vec((nrows, ncols), data).map_err(|_| Error::SerializationError)
}

/// Helper function to deserialize Poly from bytes (for decryption shares)
pub fn deserialize_decryption_share(
    bytes: &[u8],
    ctx: &Arc<fhe_math::rq::Context>,
) -> Result<Poly, Error> {
    let proto: DecryptionShareProto =
        Message::decode(bytes).map_err(|_| Error::SerializationError)?;

    Poly::from_bytes(&proto.poly_data, ctx).map_err(Error::MathError)
}

/// Helper function to deserialize Poly from bytes (for smudging polynomials)
pub fn deserialize_smudging_data(
    bytes: &[u8],
    ctx: &Arc<fhe_math::rq::Context>,
) -> Result<Poly, Error> {
    let proto: SmudgingDataProto = Message::decode(bytes).map_err(|_| Error::SerializationError)?;
    Poly::from_bytes(&proto.poly_data, ctx).map_err(Error::MathError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfv::BfvParametersBuilder;
    use fhe_traits::{DeserializeParametrized, Serialize};
    use ndarray::Array2;

    #[test]
    fn test_trbfv_serialization() {
        let params = BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(4096)
            .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
            .build_arc()
            .unwrap();

        let trbfv = TRBFV::new(5, 3, params.clone()).unwrap();

        // Test serialization and deserialization
        let bytes = trbfv.to_bytes();
        let deserialized = TRBFV::from_bytes(&bytes, &params).unwrap();

        assert_eq!(trbfv.n, deserialized.n);
        assert_eq!(trbfv.threshold, deserialized.threshold);
    }

    #[test]
    fn test_secret_share_serialization() {
        // Create a test secret share matrix
        let share_matrix = Array2::from_shape_vec((3, 8), (0..24u64).collect()).unwrap();

        // Test serialization and deserialization
        let bytes = serialize_secret_share(&share_matrix);
        let deserialized = deserialize_secret_share(&bytes).unwrap();

        assert_eq!(share_matrix, deserialized);
    }

    #[test]
    fn test_smudging_data_serialization() {
        use crate::bfv::BfvParametersBuilder;
        use fhe_math::rq::traits::TryConvertFrom;
        use fhe_math::rq::{Poly, Representation};

        let params = BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(4096)
            .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
            .build_arc()
            .unwrap();

        let ctx = params.ctx_at_level(0).unwrap();

        // Create test polynomial with some coefficients using TryConvertFrom
        let test_coeffs = vec![1i64, 2, 3, 4];
        let poly = Poly::try_convert_from(
            test_coeffs.as_slice(),
            ctx,
            false,
            Representation::PowerBasis,
        )
        .unwrap();

        // Test serialization and deserialization
        let bytes = serialize_smudging_data(&poly);
        let deserialized = deserialize_smudging_data(&bytes, ctx).unwrap();

        // Compare coefficients since Poly doesn't implement PartialEq
        assert_eq!(poly.coefficients(), deserialized.coefficients());
    }

    #[test]
    fn test_smudging_data_zero_poly() {
        use crate::bfv::BfvParametersBuilder;
        use fhe_math::rq::{Poly, Representation};

        let params = BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(4096)
            .set_moduli(&[0xffffee001, 0xffffc4001, 0x1ffffe0001])
            .build_arc()
            .unwrap();

        let ctx = params.ctx_at_level(0).unwrap();

        // Test zero polynomial
        let poly = Poly::zero(ctx, Representation::PowerBasis);
        let bytes = serialize_smudging_data(&poly);
        let deserialized = deserialize_smudging_data(&bytes, ctx).unwrap();

        assert_eq!(poly.coefficients(), deserialized.coefficients());
    }
}
