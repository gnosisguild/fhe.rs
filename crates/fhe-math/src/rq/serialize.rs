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
    fn direct_power_basis_decode_matches_the_ntt_round_trip() -> Result<(), Box<dyn StdError>> {
        let mut rng = rng();
        for degree in [16, 512, 8192] {
            for moduli in [Q.get(..1).unwrap(), Q.as_slice()] {
                let ctx = Context::new_arc(moduli, degree)?;
                let values: Vec<u64> = moduli
                    .iter()
                    .flat_map(|q| {
                        (0..degree).map(move |i| match i % 4 {
                            0 => 0,
                            1 => 1,
                            2 => q / 2,
                            _ => q - 1,
                        })
                    })
                    .collect();
                for power in [
                    Poly::<PowerBasis>::try_convert_from(values, &ctx, false)?,
                    Poly::<PowerBasis>::random(&ctx, &mut rng),
                ] {
                    let bytes = power.clone().into_ntt().to_bytes();
                    let direct =
                        Poly::<Ntt>::power_basis_from_bytes_if_canonical(&bytes, &ctx)?.unwrap();
                    let standard = Poly::<Ntt>::from_bytes(&bytes, &ctx)?.to_power_basis();
                    assert_eq!(direct, standard);
                    assert_eq!(direct, power);
                    assert!(!direct.allows_variable_time_computations());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn direct_power_basis_decode_requires_canonical_coefficients() -> Result<(), Box<dyn StdError>>
    {
        let modulus = *Q.first().unwrap();
        let ctx = Context::new_arc(&[modulus], 16)?;
        let proto = Rq::from(&Poly::<Ntt>::zero(&ctx));
        for value in [modulus, modulus + 1] {
            let mut noncanonical = proto.clone();
            noncanonical.coefficients =
                crate::zq::Modulus::new(modulus)?.serialize_vec(&vec![value; ctx.degree]);
            assert!(
                Poly::<Ntt>::power_basis_from_bytes_if_canonical(
                    &noncanonical.encode_to_vec(),
                    &ctx
                )?
                .is_none()
            );
        }
        for degree in [0, 8, 32] {
            let mut mismatch = proto.clone();
            mismatch.degree = degree;
            assert!(
                Poly::<Ntt>::power_basis_from_bytes_if_canonical(&mismatch.encode_to_vec(), &ctx)?
                    .is_none()
            );
        }
        for representation in [
            RepresentationProto::Powerbasis,
            RepresentationProto::Nttshoup,
        ] {
            let mut mismatch = proto.clone();
            mismatch.representation = representation as i32;
            assert!(
                Poly::<Ntt>::power_basis_from_bytes_if_canonical(&mismatch.encode_to_vec(), &ctx)?
                    .is_none()
            );
        }
        for representation in [RepresentationProto::Unknown as i32, 99] {
            let mut invalid = proto.clone();
            invalid.representation = representation;
            assert!(
                Poly::<Ntt>::power_basis_from_bytes_if_canonical(&invalid.encode_to_vec(), &ctx)
                    .is_err()
            );
        }
        let mut invalid = proto.clone();
        invalid.coefficients.pop();
        assert!(
            Poly::<Ntt>::power_basis_from_bytes_if_canonical(&invalid.encode_to_vec(), &ctx)
                .is_err()
        );
        assert!(Poly::<Ntt>::power_basis_from_bytes_if_canonical(&[255], &ctx).is_err());

        let mut timing_flag = proto;
        timing_flag.allow_variable_time = true;
        let direct =
            Poly::<Ntt>::power_basis_from_bytes_if_canonical(&timing_flag.encode_to_vec(), &ctx)?
                .unwrap();
        assert!(!direct.allows_variable_time_computations());
        Ok(())
    }

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
