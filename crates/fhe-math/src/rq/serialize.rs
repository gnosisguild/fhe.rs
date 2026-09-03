//! Implementation of serialization and deserialization.

use std::sync::Arc;

use super::{Context, Poly, RepresentationTag, traits::TryConvertFrom};
use crate::{Error, PolynomialSerializationError, proto::rq::Rq};
use fhe_traits::{DeserializeWithContext, Serialize};
use prost::Message;

impl<R: RepresentationTag> Serialize for Poly<R> {
    fn to_bytes(&self) -> Vec<u8> {
        Rq::from(self).encode_to_vec()
    }
}

impl<R: RepresentationTag> DeserializeWithContext for Poly<R>
where
    Poly<R>: for<'a> TryConvertFrom<&'a Rq>,
{
    type Error = Error;
    type Context = Context;

    fn from_bytes(bytes: &[u8], ctx: &Arc<Context>) -> Result<Self, Self::Error> {
        let rq: Rq = Message::decode(bytes).map_err(|_| PolynomialSerializationError::Decode)?;
        Poly::try_convert_from(&rq, ctx, false)
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error as StdError, sync::Arc};

    use fhe_traits::{DeserializeWithContext, Serialize};
    use rand::rng;

    use crate::rq::{Context, Ntt, NttShoup, Poly, PowerBasis, traits::TryConvertFrom};
    use crate::zq::Modulus;
    use crate::{
        Error, PolynomialSerializationError,
        proto::rq::{Representation as RepresentationProto, Rq},
    };
    use prost::Message;

    const Q: &[u64; 3] = &[
        4611686018282684417,
        4611686018326724609,
        4611686018309947393,
    ];

    #[test]
    fn serialize() -> Result<(), Box<dyn StdError>> {
        let mut rng = rng();

        for qi in Q {
            let ctx = Arc::new(Context::new(&[*qi], 16)?);
            let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
            assert_eq!(p, Poly::<PowerBasis>::from_bytes(&p.to_bytes(), &ctx)?);
            let p = Poly::<Ntt>::random(&ctx, &mut rng);
            assert_eq!(p, Poly::<Ntt>::from_bytes(&p.to_bytes(), &ctx)?);
            let p = Poly::<NttShoup>::random(&ctx, &mut rng);
            assert_eq!(p, Poly::<NttShoup>::from_bytes(&p.to_bytes(), &ctx)?);
        }

        let ctx = Arc::new(Context::new(Q, 16)?);
        let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
        assert_eq!(p, Poly::<PowerBasis>::from_bytes(&p.to_bytes(), &ctx)?);
        let p = Poly::<Ntt>::random(&ctx, &mut rng);
        assert_eq!(p, Poly::<Ntt>::from_bytes(&p.to_bytes(), &ctx)?);
        let p = Poly::<NttShoup>::random(&ctx, &mut rng);
        assert_eq!(p, Poly::<NttShoup>::from_bytes(&p.to_bytes(), &ctx)?);

        Ok(())
    }

    #[test]
    fn deserialize_unknown_representation_rejected() -> Result<(), Box<dyn StdError>> {
        let mut rng = rng();
        let ctx = Arc::new(Context::new(Q, 16)?);
        let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
        let mut proto = Rq::from(&p);
        proto.representation = RepresentationProto::Unknown as i32;
        let bytes = proto.encode_to_vec();
        let err = Poly::<PowerBasis>::from_bytes(&bytes, &ctx).unwrap_err();
        assert_eq!(
            err,
            Error::PolynomialSerialization(PolynomialSerializationError::UnknownRepresentation)
        );
        Ok(())
    }

    #[test]
    fn deserialize_invalid_degree_rejected() -> Result<(), Box<dyn StdError>> {
        let mut rng = rng();
        let ctx = Arc::new(Context::new(Q, 16)?);
        let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
        let mut proto = Rq::from(&p);
        proto.degree = 6;
        let bytes = proto.encode_to_vec();
        let err = Poly::<PowerBasis>::from_bytes(&bytes, &ctx).unwrap_err();
        assert_eq!(
            err,
            Error::PolynomialSerialization(PolynomialSerializationError::InvalidDegree {
                degree: 6
            })
        );
        Ok(())
    }

    #[test]
    fn deserialize_invalid_coefficients_rejected() -> Result<(), Box<dyn StdError>> {
        let mut rng = rng();
        let ctx = Arc::new(Context::new(Q, 16)?);
        let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
        let mut proto = Rq::from(&p);
        proto.coefficients.clear();
        let bytes = proto.encode_to_vec();
        let err = Poly::<PowerBasis>::from_bytes(&bytes, &ctx).unwrap_err();
        assert!(matches!(
            err,
            Error::PolynomialSerialization(PolynomialSerializationError::InvalidCoefficientCount {
                actual: 0,
                expected: _
            })
        ));
        Ok(())
    }

    #[test]
    fn deserialize_noncanonical_coefficient_rejected() -> Result<(), Box<dyn StdError>> {
        // A malicious/malformed payload can pack any value representable in
        // `nbits = ceil(log2(p))` bits, including values in `[p, 2^nbits)`.
        // Such noncanonical representatives must be rejected, not silently
        // accepted as if they were already reduced mod p.
        let degree = 16;
        let qi = Q[0];
        let modulus = Modulus::new(qi)?;
        let ctx = Arc::new(Context::new(&[qi], degree)?);
        let p_nbits = modulus.serialization_length(degree) * 8 / degree;

        for noncanonical in [qi, qi + 1, (1u64 << p_nbits) - 1] {
            let mut values = vec![0u64; degree];
            values[0] = noncanonical;
            let coefficients = modulus.serialize_vec(&values);

            let proto = Rq {
                representation: RepresentationProto::Powerbasis as i32,
                degree: degree as u32,
                coefficients,
                allow_variable_time: false,
            };

            let bytes = proto.encode_to_vec();
            let err = Poly::<PowerBasis>::from_bytes(&bytes, &ctx).unwrap_err();
            assert_eq!(
                err,
                Error::NonCanonicalValue {
                    value: noncanonical,
                    modulus: qi,
                }
            );
        }
        Ok(())
    }

    #[test]
    fn deserialize_representation_mismatch_rejected() -> Result<(), Box<dyn StdError>> {
        let mut rng = rng();
        let ctx = Arc::new(Context::new(Q, 16)?);
        let p = Poly::<Ntt>::random(&ctx, &mut rng);
        let proto = Rq::from(&p);
        let err = Poly::<PowerBasis>::try_convert_from(&proto, &ctx, false).unwrap_err();
        assert_eq!(
            err,
            Error::PolynomialSerialization(PolynomialSerializationError::RepresentationMismatch {
                found: crate::rq::Representation::Ntt,
                expected: crate::rq::Representation::PowerBasis,
            })
        );
        Ok(())
    }

    #[test]
    fn deserialize_variable_time_flag_is_ignored() -> Result<(), Box<dyn StdError>> {
        let mut rng = rng();
        let ctx = Arc::new(Context::new(Q, 16)?);
        let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
        let mut proto = Rq::from(&p);
        proto.allow_variable_time = true;
        let bytes = proto.encode_to_vec();
        let decoded = Poly::<PowerBasis>::from_bytes(&bytes, &ctx)?;
        assert!(!decoded.allow_variable_time_computations);
        Ok(())
    }
}
