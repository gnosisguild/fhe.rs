//! Implementation of serialization and deserialization.

use std::sync::Arc;

use super::{
    Context, Poly, Representation, RepresentationTag, ntt_backward_array, traits::TryConvertFrom,
};
use crate::{
    Error,
    proto::rq::{Representation as RepresentationProto, Rq},
};
use fhe_traits::{DeserializeWithContext, Serialize};
use prost::Message;

fn to_rq<R: RepresentationTag>(poly: &Poly<R>) -> Rq {
    // A valid Poly has a context-sized coefficient matrix.  Iterating rows and
    // columns rather than asking ndarray for one contiguous slice makes this
    // encoding total for valid non-contiguous polynomials as well.  The
    // canonical reduction also makes the infallible path support lazy
    // coefficients without changing their represented residue.
    let mut coefficients = poly.coefficients.clone();
    let valid_dimensions = coefficients.dim() == (poly.ctx.q.len(), poly.ctx.degree);
    for (mut row, qi) in coefficients.outer_iter_mut().zip(poly.ctx.q.iter()) {
        row.iter_mut().for_each(|coefficient| {
            *coefficient = qi.reduce(*coefficient);
        });
    }
    if valid_dimensions && !matches!(R::REPRESENTATION, Representation::PowerBasis) {
        ntt_backward_array(
            &mut coefficients,
            &poly.ctx,
            poly.allow_variable_time_computations,
        );
    }

    let representation = match R::REPRESENTATION {
        Representation::PowerBasis => RepresentationProto::Powerbasis as i32,
        Representation::Ntt => RepresentationProto::Ntt as i32,
        Representation::NttShoup => RepresentationProto::Nttshoup as i32,
    };
    let serialized = coefficients
        .outer_iter()
        .zip(poly.ctx.q.iter())
        .flat_map(|(row, qi)| {
            let mut values = row.iter().copied().collect::<Vec<_>>();
            let padding = (8 - values.len() % 8) % 8;
            values.extend(std::iter::repeat_n(0, padding));
            qi.serialize_vec(&values)
        })
        .collect();

    Rq {
        representation,
        coefficients: serialized,
        degree: poly.ctx.degree as u32,
        allow_variable_time: poly.allow_variable_time_computations,
    }
}

impl<R: RepresentationTag> Serialize for Poly<R> {
    fn to_bytes(&self) -> Vec<u8> {
        to_rq(self).encode_to_vec()
    }
}

impl<R: RepresentationTag> DeserializeWithContext for Poly<R>
where
    Poly<R>: for<'a> TryConvertFrom<&'a Rq>,
{
    type Error = Error;
    type Context = Context;

    fn from_bytes(bytes: &[u8], ctx: &Arc<Context>) -> Result<Self, Self::Error> {
        let rq: Rq = Message::decode(bytes).map_err(|e| Error::Serialization(e.to_string()))?;
        Poly::try_convert_from(&rq, ctx, false)
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, sync::Arc};

    use fhe_traits::{DeserializeWithContext, Serialize};
    use ndarray::{Array2, ShapeBuilder};
    use rand::rng;

    use crate::proto::rq::{Representation as RepresentationProto, Rq};
    use crate::rq::{Context, Ntt, NttShoup, Poly, PowerBasis, traits::TryConvertFrom};
    use prost::Message;

    const Q: &[u64; 3] = &[
        4611686018282684417,
        4611686018326724609,
        4611686018309947393,
    ];

    #[test]
    fn serialize() -> Result<(), Box<dyn Error>> {
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
    fn serialize_non_contiguous_polynomials() -> Result<(), Box<dyn Error>> {
        let ctx = Arc::new(Context::new(Q, 16)?);
        let values = (0..Q.len() * 16).map(|value| value as u64).collect();
        let mut power = Poly::<PowerBasis>::zero(&ctx);
        power.set_coefficients(Array2::from_shape_vec((Q.len(), 16).f(), values)?)?;

        let ntt = power.clone().into_ntt()?;
        assert_eq!(ntt, Poly::<Ntt>::from_bytes(&ntt.to_bytes(), &ctx)?);

        let ntt_shoup = power.into_ntt_shoup()?;
        assert_eq!(
            ntt_shoup,
            Poly::<NttShoup>::from_bytes(&ntt_shoup.to_bytes(), &ctx)?
        );
        Ok(())
    }

    #[test]
    fn deserialize_unknown_representation_rejected() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let ctx = Arc::new(Context::new(Q, 16)?);
        let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
        let mut proto = Rq::try_from(&p)?;
        proto.representation = RepresentationProto::Unknown as i32;
        let bytes = proto.encode_to_vec();
        let err = Poly::<PowerBasis>::from_bytes(&bytes, &ctx).unwrap_err();
        assert!(err.to_string().contains("Unknown representation"));
        Ok(())
    }

    #[test]
    fn deserialize_invalid_degree_rejected() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let ctx = Arc::new(Context::new(Q, 16)?);
        let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
        let mut proto = Rq::try_from(&p)?;
        proto.degree = 6;
        let bytes = proto.encode_to_vec();
        let err = Poly::<PowerBasis>::from_bytes(&bytes, &ctx).unwrap_err();
        assert!(err.to_string().contains("Invalid degree"));
        Ok(())
    }

    #[test]
    fn deserialize_invalid_coefficients_rejected() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let ctx = Arc::new(Context::new(Q, 16)?);
        let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
        let mut proto = Rq::try_from(&p)?;
        proto.coefficients.clear();
        let bytes = proto.encode_to_vec();
        let err = Poly::<PowerBasis>::from_bytes(&bytes, &ctx).unwrap_err();
        assert!(err.to_string().contains("Invalid coefficients"));
        Ok(())
    }

    #[test]
    fn deserialize_representation_mismatch_rejected() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let ctx = Arc::new(Context::new(Q, 16)?);
        let p = Poly::<Ntt>::random(&ctx, &mut rng);
        let proto = Rq::try_from(&p)?;
        let err = Poly::<PowerBasis>::try_convert_from(&proto, &ctx, false).unwrap_err();
        assert!(
            err.to_string()
                .contains("representation asked for does not match")
        );
        Ok(())
    }

    #[test]
    fn deserialize_variable_time_flag_propagates() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let ctx = Arc::new(Context::new(Q, 16)?);
        let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
        let mut proto = Rq::try_from(&p)?;
        proto.allow_variable_time = true;
        let bytes = proto.encode_to_vec();
        let decoded = Poly::<PowerBasis>::from_bytes(&bytes, &ctx)?;
        assert!(decoded.allow_variable_time_computations);
        Ok(())
    }
}
