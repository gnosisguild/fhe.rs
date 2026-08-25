//! Implementation of conversions from and to polynomials.

use super::{Context, Ntt, NttShoup, Poly, PowerBasis, traits::TryConvertFrom};
use crate::{Error, Result};
use itertools::izip;
use ndarray::{Array2, ArrayView, Axis};
use num_bigint::BigUint;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

impl TryConvertFrom<Vec<u64>> for Poly<PowerBasis> {
    fn try_convert_from(mut v: Vec<u64>, ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        if v.len() == ctx.q.len() * ctx.degree {
            // Full-RNS input: every row must contain canonical residues for
            // its modulus.
            let coefficients =
                Array2::from_shape_vec((ctx.q.len(), ctx.degree), v).map_err(|_| {
                    Error::Default(
                        "In PowerBasis representation, all coefficients must be specified"
                            .to_string(),
                    )
                })?;
            validate_canonical_rows(&coefficients, ctx)?;
            Ok(Self {
                ctx: ctx.clone(),
                allow_variable_time_computations: variable_time,
                coefficients,
                coefficients_shoup: None,
                has_lazy_coefficients: false,
                _repr: std::marker::PhantomData,
            })
        } else if v.len() <= ctx.degree {
            let mut out = Self::zero(ctx);
            if variable_time {
                unsafe {
                    izip!(out.coefficients.outer_iter_mut(), ctx.q.iter()).for_each(
                        |(mut w, qi)| {
                            let wi = w.as_slice_mut().unwrap();
                            wi[..v.len()].copy_from_slice(&v);
                            qi.reduce_vec_vt(wi);
                        },
                    );
                    out.allow_variable_time_computations();
                }
            } else {
                izip!(out.coefficients.outer_iter_mut(), ctx.q.iter()).for_each(|(mut w, qi)| {
                    let wi = w.as_slice_mut().unwrap();
                    wi[..v.len()].copy_from_slice(&v);
                    qi.reduce_vec(wi);
                });
                v.zeroize();
            }
            Ok(out)
        } else {
            Err(Error::Default(
                "In PowerBasis representation, either all coefficients must be specified, or only coefficients up to the degree".to_string(),
            ))
        }
    }
}

impl TryConvertFrom<Vec<u64>> for Poly<Ntt> {
    fn try_convert_from(v: Vec<u64>, ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        if let Ok(coefficients) = Array2::from_shape_vec((ctx.q.len(), ctx.degree), v) {
            validate_canonical_rows(&coefficients, ctx)?;
            Ok(Self {
                ctx: ctx.clone(),
                allow_variable_time_computations: variable_time,
                coefficients,
                coefficients_shoup: None,
                has_lazy_coefficients: false,
                _repr: std::marker::PhantomData,
            })
        } else {
            Err(Error::Default(
                "In Ntt representation, all coefficients must be specified".to_string(),
            ))
        }
    }
}

impl TryConvertFrom<Vec<u64>> for Poly<NttShoup> {
    fn try_convert_from(v: Vec<u64>, ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        if let Ok(coefficients) = Array2::from_shape_vec((ctx.q.len(), ctx.degree), v) {
            validate_canonical_rows(&coefficients, ctx)?;
            let mut p = Self {
                ctx: ctx.clone(),
                allow_variable_time_computations: variable_time,
                coefficients,
                coefficients_shoup: None,
                has_lazy_coefficients: false,
                _repr: std::marker::PhantomData,
            };
            p.compute_coefficients_shoup();
            Ok(p)
        } else {
            Err(Error::Default(
                "In NttShoup representation, all coefficients must be specified".to_string(),
            ))
        }
    }
}

/// Validate that every row of the coefficient matrix holds canonical residues
/// for its corresponding modulus.
fn validate_canonical_rows(coefficients: &Array2<u64>, ctx: &Context) -> Result<()> {
    for (row, qi) in coefficients.outer_iter().zip(ctx.q.iter()) {
        if let Some(value) = row.iter().find(|value| **value >= **qi) {
            return Err(Error::NonCanonicalCoefficient {
                modulus: **qi,
                value: *value,
            });
        }
    }
    Ok(())
}

/// Validate that a coefficient matrix matches the context shape exactly and
/// holds canonical residues in `[0, q_i)` for every row.
pub(crate) fn validate_coefficient_matrix(a: &Array2<u64>, ctx: &Context) -> Result<()> {
    if a.shape() != [ctx.q.len(), ctx.degree] {
        return Err(Error::InvalidPolynomialDimensions {
            expected_rows: ctx.q.len(),
            expected_columns: ctx.degree,
            actual_rows: a.nrows(),
            actual_columns: a.ncols(),
        });
    }
    validate_canonical_rows(a, ctx)
}

impl TryConvertFrom<Array2<u64>> for Poly<PowerBasis> {
    fn try_convert_from(a: Array2<u64>, ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        validate_coefficient_matrix(&a, ctx)?;
        Ok(Self {
            ctx: ctx.clone(),
            allow_variable_time_computations: variable_time,
            coefficients: a,
            coefficients_shoup: None,
            has_lazy_coefficients: false,
            _repr: std::marker::PhantomData,
        })
    }
}

impl TryConvertFrom<Array2<u64>> for Poly<Ntt> {
    fn try_convert_from(a: Array2<u64>, ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        validate_coefficient_matrix(&a, ctx)?;
        Ok(Self {
            ctx: ctx.clone(),
            allow_variable_time_computations: variable_time,
            coefficients: a,
            coefficients_shoup: None,
            has_lazy_coefficients: false,
            _repr: std::marker::PhantomData,
        })
    }
}

impl TryConvertFrom<Array2<u64>> for Poly<NttShoup> {
    fn try_convert_from(a: Array2<u64>, ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        validate_coefficient_matrix(&a, ctx)?;
        let mut p = Self {
            ctx: ctx.clone(),
            allow_variable_time_computations: variable_time,
            coefficients: a,
            coefficients_shoup: None,
            has_lazy_coefficients: false,
            _repr: std::marker::PhantomData,
        };
        p.compute_coefficients_shoup();
        Ok(p)
    }
}

impl<'a> TryConvertFrom<&'a [u64]> for Poly<PowerBasis> {
    fn try_convert_from(v: &'a [u64], ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        Poly::<PowerBasis>::try_convert_from(v.to_vec(), ctx, variable_time)
    }
}

impl<'a> TryConvertFrom<&'a [u64]> for Poly<Ntt> {
    fn try_convert_from(v: &'a [u64], ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        Poly::<Ntt>::try_convert_from(v.to_vec(), ctx, variable_time)
    }
}

impl<'a> TryConvertFrom<&'a [u64]> for Poly<NttShoup> {
    fn try_convert_from(v: &'a [u64], ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        Poly::<NttShoup>::try_convert_from(v.to_vec(), ctx, variable_time)
    }
}

impl<'a> TryConvertFrom<&'a [i64]> for Poly<PowerBasis> {
    fn try_convert_from(v: &'a [i64], ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        if v.len() <= ctx.degree {
            let mut out = Self::zero(ctx);
            if variable_time {
                unsafe { out.allow_variable_time_computations() }
            }
            izip!(out.coefficients.outer_iter_mut(), ctx.q.iter()).for_each(|(mut w, qi)| {
                let wi = w.as_slice_mut().unwrap();
                if variable_time {
                    unsafe { wi[..v.len()].copy_from_slice(&qi.reduce_vec_i64_vt(v)) }
                } else {
                    wi[..v.len()].copy_from_slice(Zeroizing::new(qi.reduce_vec_i64(v)).as_ref());
                }
            });
            Ok(out)
        } else {
            Err(Error::Default(
                "In PowerBasis representation with signed integers, only `degree` coefficients can be specified".to_string(),
            ))
        }
    }
}

impl<'a> TryConvertFrom<&'a Vec<i64>> for Poly<PowerBasis> {
    fn try_convert_from(v: &'a Vec<i64>, ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        Poly::try_convert_from(v.as_ref() as &[i64], ctx, variable_time)
    }
}

impl<'a> TryConvertFrom<&'a [BigUint]> for Poly<PowerBasis> {
    fn try_convert_from(v: &'a [BigUint], ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        if v.len() > ctx.degree {
            Err(Error::Default(
                "The slice contains too many big integers compared to the polynomial degree"
                    .to_string(),
            ))
        } else {
            let mut coefficients = Array2::zeros((ctx.q.len(), ctx.degree));

            izip!(coefficients.axis_iter_mut(Axis(1)), v).for_each(|(mut c, vi)| {
                c.assign(&ArrayView::from(&ctx.rns.project(vi)));
            });

            Ok(Self {
                ctx: ctx.clone(),
                allow_variable_time_computations: variable_time,
                coefficients,
                coefficients_shoup: None,
                has_lazy_coefficients: false,
                _repr: std::marker::PhantomData,
            })
        }
    }
}

impl<'a> TryConvertFrom<&'a [BigUint]> for Poly<Ntt> {
    fn try_convert_from(v: &'a [BigUint], ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        let p = Poly::<PowerBasis>::try_convert_from(v, ctx, variable_time)?;
        p.into_ntt()
    }
}

impl<'a> TryConvertFrom<&'a [BigUint]> for Poly<NttShoup> {
    fn try_convert_from(v: &'a [BigUint], ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        let p = Poly::<PowerBasis>::try_convert_from(v, ctx, variable_time)?;
        p.into_ntt_shoup()
    }
}

impl<'a> TryConvertFrom<&'a Vec<u64>> for Poly<PowerBasis> {
    fn try_convert_from(v: &'a Vec<u64>, ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        Poly::try_convert_from(v.to_vec(), ctx, variable_time)
    }
}

impl<'a> TryConvertFrom<&'a Vec<u64>> for Poly<Ntt> {
    fn try_convert_from(v: &'a Vec<u64>, ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        Poly::try_convert_from(v.to_vec(), ctx, variable_time)
    }
}

impl<'a> TryConvertFrom<&'a Vec<u64>> for Poly<NttShoup> {
    fn try_convert_from(v: &'a Vec<u64>, ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        Poly::try_convert_from(v.to_vec(), ctx, variable_time)
    }
}

impl<'a, const N: usize> TryConvertFrom<&'a [u64; N]> for Poly<PowerBasis> {
    fn try_convert_from(v: &'a [u64; N], ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        Poly::try_convert_from(v.as_ref(), ctx, variable_time)
    }
}

impl<'a, const N: usize> TryConvertFrom<&'a [u64; N]> for Poly<Ntt> {
    fn try_convert_from(v: &'a [u64; N], ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        Poly::try_convert_from(v.as_ref(), ctx, variable_time)
    }
}

impl<'a, const N: usize> TryConvertFrom<&'a [u64; N]> for Poly<NttShoup> {
    fn try_convert_from(v: &'a [u64; N], ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        Poly::try_convert_from(v.as_ref(), ctx, variable_time)
    }
}

impl<'a, const N: usize> TryConvertFrom<&'a [BigUint; N]> for Poly<PowerBasis> {
    fn try_convert_from(
        v: &'a [BigUint; N],
        ctx: &Arc<Context>,
        variable_time: bool,
    ) -> Result<Self> {
        Poly::try_convert_from(v.as_ref(), ctx, variable_time)
    }
}

impl<'a, const N: usize> TryConvertFrom<&'a [BigUint; N]> for Poly<Ntt> {
    fn try_convert_from(
        v: &'a [BigUint; N],
        ctx: &Arc<Context>,
        variable_time: bool,
    ) -> Result<Self> {
        Poly::try_convert_from(v.as_ref(), ctx, variable_time)
    }
}

impl<'a, const N: usize> TryConvertFrom<&'a [BigUint; N]> for Poly<NttShoup> {
    fn try_convert_from(
        v: &'a [BigUint; N],
        ctx: &Arc<Context>,
        variable_time: bool,
    ) -> Result<Self> {
        Poly::try_convert_from(v.as_ref(), ctx, variable_time)
    }
}

impl<'a, const N: usize> TryConvertFrom<&'a [i64; N]> for Poly<PowerBasis> {
    fn try_convert_from(v: &'a [i64; N], ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
        Poly::try_convert_from(v.as_ref(), ctx, variable_time)
    }
}

impl TryFrom<&Poly<PowerBasis>> for Vec<u64> {
    type Error = Error;

    fn try_from(p: &Poly<PowerBasis>) -> Result<Self> {
        p.coefficients
            .as_slice()
            .ok_or_else(|| {
                Error::Default("Polynomial coefficients are not contiguous in memory".to_string())
            })
            .map(|slice| slice.to_vec())
    }
}

impl TryFrom<&Poly<Ntt>> for Vec<u64> {
    type Error = Error;

    fn try_from(p: &Poly<Ntt>) -> Result<Self> {
        p.coefficients
            .as_slice()
            .ok_or_else(|| {
                Error::Default("Polynomial coefficients are not contiguous in memory".to_string())
            })
            .map(|slice| slice.to_vec())
    }
}

impl TryFrom<&Poly<NttShoup>> for Vec<u64> {
    type Error = Error;

    fn try_from(p: &Poly<NttShoup>) -> Result<Self> {
        p.coefficients
            .as_slice()
            .ok_or_else(|| {
                Error::Default("Polynomial coefficients are not contiguous in memory".to_string())
            })
            .map(|slice| slice.to_vec())
    }
}

impl TryFrom<&Poly<PowerBasis>> for Vec<BigUint> {
    type Error = Error;

    fn try_from(p: &Poly<PowerBasis>) -> Result<Self> {
        p.coefficients
            .axis_iter(Axis(1))
            .map(|c| p.ctx.rns.lift(c))
            .collect()
    }
}

impl TryFrom<&Poly<Ntt>> for Vec<BigUint> {
    type Error = Error;

    fn try_from(p: &Poly<Ntt>) -> Result<Self> {
        p.coefficients
            .axis_iter(Axis(1))
            .map(|c| p.ctx.rns.lift(c))
            .collect()
    }
}

impl TryFrom<&Poly<NttShoup>> for Vec<BigUint> {
    type Error = Error;

    fn try_from(p: &Poly<NttShoup>) -> Result<Self> {
        p.coefficients
            .axis_iter(Axis(1))
            .map(|c| p.ctx.rns.lift(c))
            .collect()
    }
}

#[cfg(feature = "protobuf")]
mod protobuf {
    use super::*;
    use crate::proto::rq::{Representation as RepresentationProto, Rq};
    use crate::rq::{Representation, RepresentationTag};

    impl<R: RepresentationTag> TryFrom<&Poly<R>> for Rq {
        type Error = Error;

        fn try_from(p: &Poly<R>) -> Result<Self> {
            if p.has_lazy_coefficients {
                return Err(Error::Default(
                    "Cannot serialize a polynomial with lazy coefficients".to_string(),
                ));
            }
            let (actual_rows, actual_columns) = p.coefficients.dim();
            if (actual_rows, actual_columns) != (p.ctx.q.len(), p.ctx.degree) {
                return Err(Error::InvalidPolynomialDimensions {
                    expected_rows: p.ctx.q.len(),
                    expected_columns: p.ctx.degree,
                    actual_rows,
                    actual_columns,
                });
            }
            let q: Poly<PowerBasis> = match R::REPRESENTATION {
                Representation::PowerBasis => Poly::<PowerBasis>::from_parts(p.clone()),
                Representation::Ntt => Poly::<Ntt>::from_parts(p.clone()).into_power_basis()?,
                Representation::NttShoup => {
                    Poly::<NttShoup>::from_parts(p.clone()).into_power_basis()?
                }
            };

            let mut proto = Rq::default();
            match R::REPRESENTATION {
                Representation::PowerBasis => {
                    proto.representation = RepresentationProto::Powerbasis as i32
                }
                Representation::Ntt => proto.representation = RepresentationProto::Ntt as i32,
                Representation::NttShoup => {
                    proto.representation = RepresentationProto::Nttshoup as i32
                }
            }
            let serialization: Vec<u8> = izip!(q.coefficients.outer_iter(), p.ctx.q.iter())
                .flat_map(|(v, qi)| {
                    let row = v.iter().copied().collect::<Vec<_>>();
                    qi.serialize_vec(&row)
                })
                .collect();
            proto.coefficients = serialization;
            proto.degree = p.ctx.degree as u32;
            proto.allow_variable_time = p.allow_variable_time_computations;
            Ok(proto)
        }
    }

    /// Parse a serialized `Rq` message into representation, power-basis
    /// coefficients, and the local timing policy.
    ///
    /// Timing policy is caller-controlled: only the trusted `variable_time`
    /// argument selects variable-time arithmetic. The serialized
    /// `Rq.allow_variable_time` field is non-authoritative input metadata —
    /// mathematical polynomial bytes must not elevate local policy — so it is
    /// kept on the wire for compatibility but ignored during deserialization.
    fn parse_proto(
        value: &Rq,
        ctx: &Arc<Context>,
        variable_time: bool,
    ) -> Result<(Representation, Vec<u64>, bool)> {
        let repr = value
            .representation
            .try_into()
            .map_err(|_| Error::Default("Invalid representation".to_string()))?;
        let representation_from_proto = match repr {
            RepresentationProto::Powerbasis => Representation::PowerBasis,
            RepresentationProto::Ntt => Representation::Ntt,
            RepresentationProto::Nttshoup => Representation::NttShoup,
            RepresentationProto::Unknown => {
                return Err(Error::Default("Unknown representation".to_string()));
            }
        };

        let degree = value.degree as usize;
        if !degree.is_multiple_of(8) || degree < 8 {
            return Err(Error::Default("Invalid degree".to_string()));
        }
        if degree != ctx.degree {
            return Err(Error::Default(
                "The polynomial degree does not match the context".to_string(),
            ));
        }

        let mut expected_nbytes = 0;
        ctx.q
            .iter()
            .for_each(|qi| expected_nbytes += qi.serialization_length(degree));
        if value.coefficients.len() != expected_nbytes {
            return Err(Error::Default("Invalid coefficients".to_string()));
        }

        let mut index = 0usize;
        let mut power_basis_coefficients = Vec::with_capacity(ctx.q.len() * degree);
        for qi in ctx.q.iter() {
            let size = qi.serialization_length(degree);
            // The total length was validated above, so this range is always
            // in bounds; the checked accesses keep the trust boundary free of
            // panics even on malformed inputs.
            let end = index
                .checked_add(size)
                .ok_or_else(|| Error::Default("Invalid coefficients".to_string()))?;
            let bytes = value
                .coefficients
                .get(index..end)
                .ok_or_else(|| Error::Default("Invalid coefficients".to_string()))?;
            let mut row = qi.deserialize_vec(bytes)?;
            index = end;
            power_basis_coefficients.append(&mut row);
        }

        Ok((
            representation_from_proto,
            power_basis_coefficients,
            variable_time,
        ))
    }

    impl TryConvertFrom<&Rq> for Poly<PowerBasis> {
        fn try_convert_from(value: &Rq, ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
            let (representation_from_proto, coefficients, variable_time) =
                parse_proto(value, ctx, variable_time)?;
            if representation_from_proto != Representation::PowerBasis {
                return Err(Error::Default(
                    "The representation asked for does not match the representation in the serialization".to_string(),
                ));
            }
            Poly::<PowerBasis>::try_convert_from(coefficients, ctx, variable_time)
        }
    }

    impl TryConvertFrom<&Rq> for Poly<Ntt> {
        fn try_convert_from(value: &Rq, ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
            let (representation_from_proto, coefficients, variable_time) =
                parse_proto(value, ctx, variable_time)?;
            if representation_from_proto != Representation::Ntt {
                return Err(Error::Default(
                    "The representation asked for does not match the representation in the serialization".to_string(),
                ));
            }
            let p = Poly::<PowerBasis>::try_convert_from(coefficients, ctx, variable_time)?;
            p.into_ntt()
        }
    }

    impl TryConvertFrom<&Rq> for Poly<NttShoup> {
        fn try_convert_from(value: &Rq, ctx: &Arc<Context>, variable_time: bool) -> Result<Self> {
            let (representation_from_proto, coefficients, variable_time) =
                parse_proto(value, ctx, variable_time)?;
            if representation_from_proto != Representation::NttShoup {
                return Err(Error::Default(
                    "The representation asked for does not match the representation in the serialization".to_string(),
                ));
            }
            let p = Poly::<PowerBasis>::try_convert_from(coefficients, ctx, variable_time)?;
            p.into_ntt_shoup()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rq::{Context, Ntt, NttShoup, Poly, PowerBasis, traits::TryConvertFrom};
    use ndarray::Array2;
    use num_bigint::BigUint;
    use rand::rng;
    use std::{error::Error, sync::Arc};

    use crate::Error as CrateError;

    static MODULI: &[u64; 3] = &[1153, 4611686018326724609, 4611686018309947393];

    #[test]
    fn try_convert_from_full_rns_rejects_noncanonical_rows() -> Result<(), Box<dyn Error>> {
        let ctx = Arc::new(Context::new(MODULI, 16)?);
        // Canonical full-RNS vector: row i contains canonical residues for
        // MODULI[i].
        let mut values = vec![0u64; MODULI.len() * 16];
        for (i, qi) in MODULI.iter().enumerate() {
            for j in 0..16 {
                values[i * 16 + j] = (i as u64 * 16 + j as u64) % *qi;
            }
        }
        let p = Poly::<PowerBasis>::try_convert_from(values.clone(), &ctx, false)?;
        assert_eq!(Vec::<u64>::try_from(&p)?, values);

        // A value equal to the row's modulus is rejected in every
        // representation.
        for (i, qi) in MODULI.iter().enumerate() {
            let mut tampered = values.clone();
            tampered[i * 16 + 3] = *qi;
            assert_eq!(
                Poly::<PowerBasis>::try_convert_from(tampered.clone(), &ctx, false).unwrap_err(),
                CrateError::NonCanonicalCoefficient {
                    modulus: *qi,
                    value: *qi,
                }
            );
            assert!(Poly::<Ntt>::try_convert_from(tampered.clone(), &ctx, false).is_err());
            assert!(Poly::<NttShoup>::try_convert_from(tampered, &ctx, false).is_err());
        }

        // A value strictly above the row's modulus is rejected too.
        let mut tampered = values;
        tampered[16] = MODULI[1] + 1;
        assert_eq!(
            Poly::<PowerBasis>::try_convert_from(tampered.clone(), &ctx, false).unwrap_err(),
            CrateError::NonCanonicalCoefficient {
                modulus: MODULI[1],
                value: MODULI[1] + 1,
            }
        );
        assert!(Poly::<Ntt>::try_convert_from(tampered.clone(), &ctx, false).is_err());
        assert!(Poly::<NttShoup>::try_convert_from(tampered, &ctx, false).is_err());
        Ok(())
    }

    #[test]
    fn try_convert_from_matrix_rejects_noncanonical_rows() -> Result<(), Box<dyn Error>> {
        let ctx = Arc::new(Context::new(MODULI, 16)?);
        // Canonical matrix: row i contains canonical residues for MODULI[i].
        let mut values = vec![0u64; MODULI.len() * 16];
        for (i, qi) in MODULI.iter().enumerate() {
            for j in 0..16 {
                values[i * 16 + j] = (i as u64 * 16 + j as u64) % *qi;
            }
        }
        let canonical =
            |values: &[u64]| Array2::from_shape_vec((MODULI.len(), 16), values.to_vec()).unwrap();
        let p = Poly::<PowerBasis>::try_convert_from(canonical(&values), &ctx, false)?;
        assert_eq!(Vec::<u64>::try_from(&p)?, values);

        // A non-canonical value in any row is rejected by every
        // representation.
        for (i, qi) in MODULI.iter().enumerate() {
            let mut tampered = values.clone();
            tampered[i * 16 + 3] = *qi;
            assert_eq!(
                Poly::<PowerBasis>::try_convert_from(canonical(&tampered), &ctx, false)
                    .unwrap_err(),
                CrateError::NonCanonicalCoefficient {
                    modulus: *qi,
                    value: *qi,
                }
            );
            assert!(Poly::<Ntt>::try_convert_from(canonical(&tampered), &ctx, false).is_err());
            assert!(Poly::<NttShoup>::try_convert_from(canonical(&tampered), &ctx, false).is_err());
        }

        // Wrong shapes are rejected with typed dimension errors.
        let malformed = Array2::zeros((MODULI.len() - 1, 16));
        let expected = CrateError::InvalidPolynomialDimensions {
            expected_rows: MODULI.len(),
            expected_columns: 16,
            actual_rows: MODULI.len() - 1,
            actual_columns: 16,
        };
        assert_eq!(
            Poly::<PowerBasis>::try_convert_from(malformed.clone(), &ctx, false).unwrap_err(),
            expected
        );
        assert_eq!(
            Poly::<Ntt>::try_convert_from(malformed.clone(), &ctx, false).unwrap_err(),
            expected
        );
        assert_eq!(
            Poly::<NttShoup>::try_convert_from(malformed, &ctx, false).unwrap_err(),
            expected
        );
        Ok(())
    }

    #[test]
    fn try_convert_from_short_vector_still_reduces() -> Result<(), Box<dyn Error>> {
        let ctx = Arc::new(Context::new(MODULI, 16)?);
        // Short vectors are ordinary integer coefficients and keep their
        // intended reduction semantics in every row.
        let p = Poly::<PowerBasis>::try_convert_from(vec![MODULI[0] + 3, 5], &ctx, false)?;
        let coefficients = Vec::<u64>::try_from(&p)?;
        for (i, qi) in MODULI.iter().enumerate() {
            assert_eq!(coefficients[i * 16], (MODULI[0] + 3) % *qi);
            assert_eq!(coefficients[i * 16 + 1], 5 % *qi);
        }
        Ok(())
    }

    #[test]
    fn biguint() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let ctx = Arc::new(Context::new(MODULI, 16)?);
        let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
        let values = Vec::<BigUint>::try_from(&p)?;
        let p2 = Poly::<PowerBasis>::try_convert_from(values.as_slice(), &ctx, false)?;
        assert_eq!(p, p2);
        Ok(())
    }

    #[cfg(feature = "protobuf")]
    mod protobuf {
        use super::*;
        use crate::proto::rq::Rq;
        use crate::rq::NttShoup;
        use fhe_traits::DeserializeWithContext;
        use fhe_util::transcode_to_bytes;
        use prost::Message;

        #[test]
        fn proto_rejects_noncanonical_coefficients() -> Result<(), Box<dyn std::error::Error>> {
            let ctx = Arc::new(Context::new(MODULI, 16)?);
            let mut rng = rng();

            // Build packed bytes whose second row contains a non-canonical
            // value (MODULI[1] + 1).
            let mut tampered_rows = vec![];
            for (i, qi) in MODULI.iter().enumerate() {
                let nbits = 64 - (*qi - 1).leading_zeros() as usize;
                let mut row = vec![0u64; 16];
                if i == 1 {
                    row[0] = *qi + 1;
                }
                tampered_rows.push(transcode_to_bytes(&row, nbits));
            }
            let tampered = tampered_rows.concat();

            let protos = [
                Rq::try_from(&Poly::<PowerBasis>::random(&ctx, &mut rng))?,
                Rq::try_from(&Poly::<Ntt>::random(&ctx, &mut rng))?,
                Rq::try_from(&Poly::<NttShoup>::random(&ctx, &mut rng))?,
            ];
            for mut proto in protos {
                proto.coefficients = tampered.clone();
                let bytes = proto.encode_to_vec();
                let expected = CrateError::NonCanonicalCoefficient {
                    modulus: MODULI[1],
                    value: MODULI[1] + 1,
                };
                assert_eq!(
                    Poly::<PowerBasis>::from_bytes(&bytes, &ctx).unwrap_err(),
                    expected
                );
                assert_eq!(Poly::<Ntt>::from_bytes(&bytes, &ctx).unwrap_err(), expected);
                assert_eq!(
                    Poly::<NttShoup>::from_bytes(&bytes, &ctx).unwrap_err(),
                    expected
                );
            }
            Ok(())
        }
        #[test]
        fn proto_rejects_degree_mismatch() -> Result<(), Box<dyn std::error::Error>> {
            // A validly packed message whose degree differs from the context
            // degree must be rejected, never reinterpreted (e.g. through the
            // short-vector branch of the PowerBasis conversion).
            let ctx16 = Arc::new(Context::new(&[MODULI[0]], 16)?);
            let ctx8 = Arc::new(Context::new(&[MODULI[0]], 8)?);
            let ctx16_multi = Arc::new(Context::new(MODULI, 16)?);
            let ctx8_multi = Arc::new(Context::new(MODULI, 8)?);
            let mut rng = rng();
            let expected =
                CrateError::Default("The polynomial degree does not match the context".to_string());

            for (small, large) in [(&ctx8, &ctx16), (&ctx8_multi, &ctx16_multi)] {
                let protos = [
                    Rq::try_from(&Poly::<PowerBasis>::random(small, &mut rng))?,
                    Rq::try_from(&Poly::<Ntt>::random(small, &mut rng))?,
                    Rq::try_from(&Poly::<NttShoup>::random(small, &mut rng))?,
                ];
                for proto in protos {
                    let bytes = proto.encode_to_vec();
                    assert_eq!(
                        Poly::<PowerBasis>::from_bytes(&bytes, large).unwrap_err(),
                        expected
                    );
                    assert_eq!(
                        Poly::<Ntt>::from_bytes(&bytes, large).unwrap_err(),
                        expected
                    );
                    assert_eq!(
                        Poly::<NttShoup>::from_bytes(&bytes, large).unwrap_err(),
                        expected
                    );
                }
            }

            // A larger message degree is rejected too.
            let mut proto = Rq::try_from(&Poly::<PowerBasis>::random(&ctx16, &mut rng))?;
            proto.degree = 32;
            proto.coefficients.extend(std::iter::repeat_n(0u8, 16 / 2));
            let bytes = proto.encode_to_vec();
            assert_eq!(
                Poly::<PowerBasis>::from_bytes(&bytes, &ctx16).unwrap_err(),
                expected
            );
            Ok(())
        }

        #[test]
        fn proto_rejects_malformed_coefficient_lengths() -> Result<(), Box<dyn std::error::Error>> {
            let ctx = Arc::new(Context::new(MODULI, 16)?);
            let mut rng = rng();
            let full_len = ctx
                .q
                .iter()
                .map(|qi| qi.serialization_length(16))
                .sum::<usize>();

            // A truncated or oversized coefficient stream never decodes, in
            // any representation.
            for len in [full_len - 1, full_len + 1, 0] {
                let protos = [
                    Rq::try_from(&Poly::<PowerBasis>::random(&ctx, &mut rng))?,
                    Rq::try_from(&Poly::<Ntt>::random(&ctx, &mut rng))?,
                    Rq::try_from(&Poly::<NttShoup>::random(&ctx, &mut rng))?,
                ];
                for mut proto in protos {
                    proto.coefficients.resize(len, 0);
                    let bytes = proto.encode_to_vec();
                    let expected = CrateError::Default("Invalid coefficients".to_string());
                    assert_eq!(
                        Poly::<PowerBasis>::from_bytes(&bytes, &ctx).unwrap_err(),
                        expected
                    );
                    assert_eq!(Poly::<Ntt>::from_bytes(&bytes, &ctx).unwrap_err(), expected);
                    assert_eq!(
                        Poly::<NttShoup>::from_bytes(&bytes, &ctx).unwrap_err(),
                        expected
                    );
                }
            }
            Ok(())
        }

        #[test]
        fn proto() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            for modulus in MODULI {
                let ctx = Arc::new(Context::new(&[*modulus], 16)?);
                let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
                let proto = Rq::try_from(&p)?;
                assert_eq!(
                    Poly::<PowerBasis>::try_convert_from(&proto, &ctx, false)?,
                    p
                );
                assert_eq!(
                    Poly::<Ntt>::try_convert_from(&proto, &ctx, false).unwrap_err(),
                    CrateError::Default(
                        "The representation asked for does not match the representation in the serialization".to_string()
                    )
                );
                assert_eq!(
                    Poly::<NttShoup>::try_convert_from(&proto, &ctx, false).unwrap_err(),
                    CrateError::Default(
                        "The representation asked for does not match the representation in the serialization".to_string()
                    )
                );
            }

            let ctx = Arc::new(Context::new(MODULI, 16)?);
            let p = Poly::<Ntt>::random(&ctx, &mut rng);
            let proto = Rq::try_from(&p)?;
            assert_eq!(Poly::<Ntt>::try_convert_from(&proto, &ctx, false)?, p);

            let p = Poly::<NttShoup>::random(&ctx, &mut rng);
            let proto = Rq::try_from(&p)?;
            assert_eq!(Poly::<NttShoup>::try_convert_from(&proto, &ctx, false)?, p);

            Ok(())
        }
    }

    #[test]
    fn try_convert_from_slice_zero() -> Result<(), Box<dyn Error>> {
        for modulus in MODULI {
            let ctx = Arc::new(Context::new(&[*modulus], 16)?);

            // Power Basis
            assert_eq!(
                Poly::<PowerBasis>::try_convert_from(&[0u64], &ctx, false)?,
                Poly::<PowerBasis>::zero(&ctx)
            );
            assert_eq!(
                Poly::<PowerBasis>::try_convert_from(&[0i64], &ctx, false)?,
                Poly::<PowerBasis>::zero(&ctx)
            );
            assert_eq!(
                Poly::<PowerBasis>::try_convert_from(&[0u64; 16], &ctx, false)?,
                Poly::<PowerBasis>::zero(&ctx)
            );
            assert_eq!(
                Poly::<PowerBasis>::try_convert_from(&[0i64; 16], &ctx, false)?,
                Poly::<PowerBasis>::zero(&ctx)
            );
            assert!(Poly::<PowerBasis>::try_convert_from(&[0u64; 17], &ctx, false).is_err());

            // Ntt
            assert!(Poly::<Ntt>::try_convert_from(&[0u64], &ctx, false).is_err());
            assert!(Poly::<Ntt>::try_convert_from(&[0u64; 16], &ctx, false).is_ok());
            assert!(Poly::<Ntt>::try_convert_from(&[0u64; 17], &ctx, false).is_err());
        }

        let ctx = Arc::new(Context::new(MODULI, 16)?);
        assert_eq!(
            Poly::<PowerBasis>::try_convert_from(Vec::<u64>::default(), &ctx, false)?,
            Poly::<PowerBasis>::zero(&ctx)
        );
        assert!(Poly::<Ntt>::try_convert_from(Vec::<u64>::default(), &ctx, false).is_err());

        Ok(())
    }

    #[test]
    fn try_convert_from_vec_zero() -> Result<(), Box<dyn Error>> {
        for modulus in MODULI {
            let ctx = Arc::new(Context::new(&[*modulus], 16)?);
            assert_eq!(
                Poly::<PowerBasis>::try_convert_from(vec![], &ctx, false)?,
                Poly::<PowerBasis>::zero(&ctx)
            );
            assert!(Poly::<Ntt>::try_convert_from(vec![], &ctx, false).is_err());

            assert_eq!(
                Poly::<PowerBasis>::try_convert_from(vec![0], &ctx, false)?,
                Poly::<PowerBasis>::zero(&ctx)
            );
            assert!(Poly::<Ntt>::try_convert_from(vec![0], &ctx, false).is_err());

            assert_eq!(
                Poly::<PowerBasis>::try_convert_from(vec![0; 16], &ctx, false)?,
                Poly::<PowerBasis>::zero(&ctx)
            );
            assert_eq!(
                Poly::<Ntt>::try_convert_from(vec![0; 16], &ctx, false)?,
                Poly::<Ntt>::zero(&ctx)
            );
        }

        Ok(())
    }
}
