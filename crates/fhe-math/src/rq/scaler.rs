#![warn(missing_docs, unused_imports)]

//! Polynomial scaler.

use super::{Context, Poly, Representation, ScaleRepresentation};
use crate::{
    Error, Result,
    rns::{RnsScaler, ScalingFactor, scaler::RnsScalerRaw},
};
use itertools::izip;
use ndarray::{Array2, Axis, s};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;

/// Context extender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scaler {
    from: Arc<Context>,
    to: Arc<Context>,
    number_common_moduli: usize,
    scaler: RnsScaler,
}

/// Serializable representation of [`Scaler`].
///
/// The raw data is untrusted transport state: `number_common_moduli` is
/// derived and recomputed by [`ScalerRaw::into_scaler`], which rebuilds the
/// whole scaler from the authoritative contexts and scaling factor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalerRaw {
    /// RNS scaler.
    pub rns_scaler: RnsScalerRaw,
}

impl Scaler {
    /// Create a scaler from a context `from` to a context `to`.
    pub fn new(from: &Arc<Context>, to: &Arc<Context>, factor: ScalingFactor) -> Result<Self> {
        if from.degree != to.degree {
            return Err(Error::Default("Incompatible degrees".to_string()));
        }

        let number_common_moduli = if factor.is_one {
            from.q
                .iter()
                .zip(to.q.iter())
                .take_while(|(qi, pi)| qi == pi)
                .count()
        } else {
            0
        };
        let scaler = RnsScaler::new(&from.rns, &to.rns, factor);

        Ok(Self {
            from: from.clone(),
            to: to.clone(),
            number_common_moduli,
            scaler,
        })
    }

    /// Scale a polynomial
    pub(crate) fn scale<R: ScaleRepresentation>(&self, p: &Poly<R>) -> Result<Poly<R>> {
        if p.ctx.as_ref() != self.from.as_ref() {
            Err(Error::Default(
                "The input polynomial does not have the correct context".to_string(),
            ))
        } else {
            let mut new_coefficients = Array2::<u64>::zeros((self.to.q.len(), self.to.degree));

            if self.number_common_moduli > 0 {
                new_coefficients
                    .slice_mut(s![..self.number_common_moduli, ..])
                    .assign(&p.coefficients.slice(s![..self.number_common_moduli, ..]));
            }

            if self.number_common_moduli < self.to.q.len() {
                let needs_transform = R::REPRESENTATION != Representation::PowerBasis;
                let p_coefficients_powerbasis: Cow<'_, Array2<u64>> = if needs_transform {
                    let mut owned = p.coefficients.clone();
                    // Backward NTT
                    if p.allow_variable_time_computations {
                        izip!(owned.outer_iter_mut(), p.ctx.ops.iter())
                            .for_each(|(mut v, op)| unsafe { op.backward_vt(v.as_mut_ptr()) });
                    } else {
                        izip!(owned.outer_iter_mut(), p.ctx.ops.iter())
                            .for_each(|(mut v, op)| op.backward(v.as_slice_mut().unwrap()));
                    }
                    Cow::Owned(owned)
                } else {
                    Cow::Borrowed(&p.coefficients)
                };

                // Conversion
                izip!(
                    new_coefficients
                        .slice_mut(s![self.number_common_moduli.., ..])
                        .axis_iter_mut(Axis(1)),
                    p_coefficients_powerbasis.axis_iter(Axis(1))
                )
                .for_each(|(new_column, column)| {
                    self.scaler
                        .scale(column, new_column, self.number_common_moduli)
                });

                // Forward NTT on the second half when the source required a transform
                if needs_transform {
                    if p.allow_variable_time_computations {
                        izip!(
                            new_coefficients
                                .slice_mut(s![self.number_common_moduli.., ..])
                                .outer_iter_mut(),
                            &self.to.ops[self.number_common_moduli..]
                        )
                        .for_each(|(mut v, op)| unsafe { op.forward_vt(v.as_mut_ptr()) });
                    } else {
                        izip!(
                            new_coefficients
                                .slice_mut(s![self.number_common_moduli.., ..])
                                .outer_iter_mut(),
                            &self.to.ops[self.number_common_moduli..]
                        )
                        .for_each(|(mut v, op)| op.forward(v.as_slice_mut().unwrap()));
                    }
                }
            }

            Ok(Poly {
                ctx: self.to.clone(),
                allow_variable_time_computations: p.allow_variable_time_computations,
                coefficients: new_coefficients,
                coefficients_shoup: None,
                has_lazy_coefficients: false,
                _repr: PhantomData,
            })
        }
    }
}

impl Scaler {
    /// Returns the source context associated with this scaler.
    #[must_use]
    pub fn from_context(&self) -> &Arc<Context> {
        &self.from
    }

    /// Returns the destination context associated with this scaler.
    #[must_use]
    pub fn to_context(&self) -> &Arc<Context> {
        &self.to
    }
}

impl Scaler {
    /// Export this scaler to a raw representation.
    #[must_use]
    pub fn to_raw(&self) -> ScalerRaw {
        ScalerRaw {
            rns_scaler: self.scaler.to_raw(),
        }
    }
}

impl ScalerRaw {
    /// Rebuild a [`Scaler`] using the provided contexts.
    ///
    /// The raw data is untrusted: only the scaling factor is used. The number
    /// of common moduli and all RNS precomputed tables are recomputed by
    /// [`Scaler::new`] from the authoritative contexts and factor, and
    /// incompatible source/destination degrees are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Default`] if the contexts have incompatible degrees,
    /// and [`Error::ZeroScalingDenominator`] if the raw scaling factor has a
    /// zero denominator.
    pub fn into_scaler(self, from: &Arc<Context>, to: &Arc<Context>) -> Result<Scaler> {
        let factor = self.rns_scaler.scaling_factor.into_scaling_factor()?;
        Scaler::new(from, to, factor)
    }
}

#[cfg(test)]
mod tests {
    use super::{Scaler, ScalerRaw, ScalingFactor};
    use crate::rns::ScalingFactorRaw;
    use crate::rns::scaler::RnsScalerRaw;
    use crate::rq::{Context, Ntt, Poly, PowerBasis};
    use itertools::Itertools;
    use num_bigint::BigUint;
    use num_traits::{One, Zero};
    use rand::rng;
    use std::error::Error;

    // Moduli to be used in tests.
    static Q: &[u64; 3] = &[
        4611686018282684417,
        4611686018326724609,
        4611686018309947393,
    ];

    static P: &[u64; 3] = &[
        4611686018282684417,
        4611686018309947393,
        4611686018257518593,
    ];

    #[test]
    fn raw_scaler_rebuilds_from_authoritative_inputs() -> Result<(), Box<dyn Error>> {
        let from = Context::new_arc(Q, 16)?;
        let to = Context::new_arc(P, 16)?;
        let n = BigUint::from(3u64);
        let d = BigUint::from(7u64);
        let factor = ScalingFactor::new(&n, &d)?;
        let scaler = Scaler::new(&from, &to, factor)?;

        // The DTO no longer carries derived state such as
        // `number_common_moduli`; only the scaling factor survives.
        let raw = scaler.to_raw();
        assert_eq!(raw.rns_scaler.scaling_factor.numerator, n.to_bytes_be());
        assert_eq!(raw.rns_scaler.scaling_factor.denominator, d.to_bytes_be());

        let rebuilt = raw.into_scaler(&from, &to)?;
        assert_eq!(rebuilt, scaler);

        // Functional equivalence: both scalers produce the same outputs.
        let mut rng = rng();
        for _ in 0..100 {
            let p = Poly::<PowerBasis>::random(&from, &mut rng);
            assert_eq!(scaler.scale(&p)?, rebuilt.scale(&p)?);
        }
        Ok(())
    }

    #[test]
    fn raw_scaler_rejects_mismatched_degrees_and_zero_denominator() -> Result<(), Box<dyn Error>> {
        let from = Context::new_arc(Q, 16)?;
        let to = Context::new_arc(P, 16)?;
        let to32 = Context::new_arc(P, 32)?;
        let scaler = Scaler::new(&from, &to, ScalingFactor::one())?;

        // Different source/destination degrees are rejected on import.
        assert!(scaler.to_raw().into_scaler(&from, &to32).is_err());

        // A zero denominator is rejected through the raw chain.
        let raw = ScalerRaw {
            rns_scaler: RnsScalerRaw {
                scaling_factor: ScalingFactorRaw {
                    numerator: vec![1],
                    denominator: vec![],
                },
            },
        };
        assert_eq!(
            raw.into_scaler(&from, &to).unwrap_err(),
            crate::Error::ZeroScalingDenominator
        );
        Ok(())
    }

    #[test]
    fn scaler() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let ntests = 100;
        let from = Context::new_arc(Q, 16)?;
        let to = Context::new_arc(P, 16)?;

        for numerator in &[1u64, 2, 3, 100, 1000, 4611686018326724610] {
            for denominator in &[1u64, 2, 3, 4, 100, 101, 1000, 1001, 4611686018326724610] {
                let n = BigUint::from(*numerator);
                let d = BigUint::from(*denominator);

                let scaler = Scaler::new(&from, &to, ScalingFactor::new(&n, &d)?)?;

                for _ in 0..ntests {
                    let poly = Poly::<PowerBasis>::random(&from, &mut rng);
                    let poly_biguint = Vec::<BigUint>::try_from(&poly)?;

                    let scaled_poly = scaler.scale(&poly)?;
                    let scaled_biguint = Vec::<BigUint>::try_from(&scaled_poly)?;

                    let expected = poly_biguint
                        .iter()
                        .map(|i| {
                            if i >= &(from.modulus() >> 1usize) {
                                if &d & BigUint::one() == BigUint::zero() {
                                    to.modulus()
                                        - (&(&(from.modulus() - i) * &n + ((&d >> 1usize) - 1u64))
                                            / &d)
                                            % to.modulus()
                                } else {
                                    to.modulus()
                                        - (&(&(from.modulus() - i) * &n + (&d >> 1)) / &d)
                                            % to.modulus()
                                }
                            } else {
                                ((i * &n + (&d >> 1)) / &d) % to.modulus()
                            }
                        })
                        .collect_vec();
                    assert_eq!(expected, scaled_biguint);

                    let poly_ntt: Poly<Ntt> = poly.clone().into_ntt()?;
                    let scaled_poly = scaler.scale(&poly_ntt)?;
                    let scaled_biguint = Vec::<BigUint>::try_from(&scaled_poly.to_power_basis()?)?;
                    assert_eq!(expected, scaled_biguint);
                }
            }
        }

        Ok(())
    }
}
