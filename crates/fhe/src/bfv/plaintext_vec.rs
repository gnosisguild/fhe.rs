use std::{cmp::min, ops::Deref, sync::Arc};

use fhe_math::rq::{Context, Ntt, Poly, PowerBasis, traits::TryConvertFrom};
use fhe_traits::{FheEncoder, FheEncoderVariableTime, FheParametrized, FhePlaintext, VariableTime};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use zeroize_derive::{Zeroize, ZeroizeOnDrop};

use crate::{
    Error, Result,
    bfv::{BfvParameters, Encoding, Plaintext},
};

use super::encoding::EncodingEnum;

/// A nonempty collection of plaintexts with shared parameters, level, and encoding.
///
/// It implements [`FhePlaintext`] for chunked encoding and can also be built
/// from existing plaintexts with [`Self::try_from_plaintexts`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PlaintextVec(Vec<Plaintext>);

impl Deref for PlaintextVec {
    type Target = [Plaintext];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IntoIterator for PlaintextVec {
    type Item = Plaintext;
    type IntoIter = std::vec::IntoIter<Plaintext>;

    fn into_iter(self) -> Self::IntoIter {
        self.into_vec().into_iter()
    }
}

impl<'a> IntoIterator for &'a PlaintextVec {
    type Item = &'a Plaintext;
    type IntoIter = std::slice::Iter<'a, Plaintext>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl FhePlaintext for PlaintextVec {
    type Encoding = Encoding;
}

impl FheParametrized for PlaintextVec {
    type Parameters = BfvParameters;
}

impl PlaintextVec {
    /// Wrap nonempty plaintexts with the same parameters, level, and encoding.
    ///
    /// The input is consumed; on validation failure its plaintexts are dropped
    /// and zeroized. For an encoded zero vector, use [`FheEncoder::try_encode`]
    /// instead of passing an empty collection.
    pub fn try_from_plaintexts(
        plaintexts: Vec<Plaintext>,
        encoding: Encoding,
        params: &Arc<BfvParameters>,
    ) -> Result<Self> {
        if plaintexts.is_empty() {
            return Err(crate::PlaintextError::EmptyPlaintextVec.into());
        }
        if encoding.encoding == EncodingEnum::Simd && params.ntt_operator.is_none() {
            return Err(crate::EncodingError::SimdUnavailable.into());
        }
        params.context_at_level(encoding.level)?;
        for plaintext in &plaintexts {
            plaintext.validate_for(params)?;
            if plaintext.level() != encoding.level {
                return Err(Error::InvalidLevel {
                    level: plaintext.level(),
                    min_level: encoding.level,
                    max_level: encoding.level,
                });
            }
            match plaintext.encoding.as_ref() {
                None => return Err(crate::PlaintextError::MissingEncoding.into()),
                Some(found) if found != &encoding => {
                    return Err(crate::EncodingError::Mismatch {
                        found: found.clone(),
                        expected: encoding,
                    }
                    .into());
                }
                _ => {}
            }
        }
        Ok(Self(plaintexts))
    }

    /// Borrow the plaintexts in order.
    #[must_use]
    pub fn as_slice(&self) -> &[Plaintext] {
        &self.0
    }

    /// Iterate over borrowed plaintexts in order.
    #[must_use = "iterators are lazy and do nothing unless consumed"]
    pub fn iter(&self) -> std::slice::Iter<'_, Plaintext> {
        self.0.iter()
    }

    /// Return the number of plaintexts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether the collection is empty (always `false` for a constructed
    /// `PlaintextVec`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the collection, transferring ownership of its plaintexts.
    #[must_use]
    pub fn into_vec(mut self) -> Vec<Plaintext> {
        std::mem::take(&mut self.0)
    }

    fn try_encode_with<T>(
        value: &[T],
        encoding: Encoding,
        params: &Arc<BfvParameters>,
        mut encode_chunk: impl FnMut(
            &[T],
            &Encoding,
            &Arc<BfvParameters>,
            &Arc<Context>,
        ) -> Result<Poly<Ntt>>,
    ) -> Result<Self> {
        if encoding.encoding == EncodingEnum::Simd && params.ntt_operator.is_none() {
            return Err(crate::EncodingError::SimdUnavailable.into());
        }

        let ctx = params.context_at_level(encoding.level)?;
        let num_plaintexts = value.len().div_ceil(params.degree()).max(1);
        let plaintexts = (0..num_plaintexts)
            .map(|index| {
                let start = index * params.degree();
                let end = min(value.len(), start + params.degree());
                let poly_ntt = encode_chunk(&value[start..end], &encoding, params, ctx)?;
                Ok(Plaintext {
                    params: params.clone(),
                    encoding: Some(encoding.clone()),
                    poly_ntt,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self(plaintexts))
    }

    fn encode_u64_chunk(
        value: &[u64],
        encoding: &Encoding,
        params: &Arc<BfvParameters>,
        ctx: &Arc<Context>,
        variable_time: Option<VariableTime>,
    ) -> Result<Poly<Ntt>> {
        let mut coefficients = vec![0u64; params.degree()];
        match encoding.encoding {
            EncodingEnum::Poly => coefficients[..value.len()].copy_from_slice(value),
            EncodingEnum::Simd => {
                for (index, &coefficient) in value.iter().enumerate() {
                    coefficients[params.matrix_reps_index_map[index]] = coefficient;
                }
                let ntt_operator = params
                    .ntt_operator
                    .as_ref()
                    .ok_or(crate::PlaintextError::NttOperatorUnavailable)?;
                if variable_time.is_some() {
                    unsafe { ntt_operator.backward_vt(coefficients.as_mut_ptr()) };
                } else {
                    ntt_operator.backward(&mut coefficients);
                }
            }
        }

        let poly = if let Some(variable_time) = variable_time {
            Poly::<PowerBasis>::try_convert_from_public(&coefficients, ctx, variable_time)?
        } else {
            Poly::<PowerBasis>::try_convert_from(&coefficients, ctx, false)?
        };
        Ok(poly.into_ntt())
    }

    fn encode_biguint_chunk(
        value: &[BigUint],
        encoding: &Encoding,
        params: &Arc<BfvParameters>,
        ctx: &Arc<Context>,
    ) -> Result<Poly<Ntt>> {
        match encoding.encoding {
            EncodingEnum::Poly => {
                let mut coefficients = vec![BigUint::zero(); params.degree()];
                coefficients[..value.len()].clone_from_slice(value);
                Ok(
                    Poly::<PowerBasis>::try_convert_from(coefficients.as_slice(), ctx, false)?
                        .into_ntt(),
                )
            }
            EncodingEnum::Simd => {
                let values = value
                    .iter()
                    .map(|coefficient| {
                        coefficient
                            .to_u64()
                            .ok_or(crate::PlaintextError::ValueTooLargeForU64)
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Self::encode_u64_chunk(&values, encoding, params, ctx, None)
            }
        }
    }
}

impl FheEncoderVariableTime<&[u64]> for PlaintextVec {
    type Error = Error;

    fn try_encode_vt(
        value: &[u64],
        encoding: Encoding,
        params: &Arc<BfvParameters>,
        variable_time: VariableTime,
    ) -> Result<Self> {
        Self::try_encode_with(value, encoding, params, |value, encoding, params, ctx| {
            Self::encode_u64_chunk(value, encoding, params, ctx, Some(variable_time))
        })
    }
}

impl FheEncoder<&[BigUint]> for PlaintextVec {
    type Error = Error;
    fn try_encode(
        value: &[BigUint],
        encoding: Encoding,
        params: &Arc<BfvParameters>,
    ) -> Result<Self> {
        Self::try_encode_with(value, encoding, params, Self::encode_biguint_chunk)
    }
}

impl FheEncoder<&[u64]> for PlaintextVec {
    type Error = Error;
    fn try_encode(value: &[u64], encoding: Encoding, params: &Arc<BfvParameters>) -> Result<Self> {
        Self::try_encode_with(value, encoding, params, |value, encoding, params, ctx| {
            Self::encode_u64_chunk(value, encoding, params, ctx, None)
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::bfv::{
        BfvParameters, Encoding, Plaintext, PlaintextVec, parameters::BfvParametersBuilder,
    };
    use fhe_math::rq::{Ntt, Poly};
    use fhe_traits::{FheDecoder, FheEncoder, FheEncoderVariableTime};
    use num_bigint::BigUint;
    use num_traits::Zero;
    use rand::rng;
    use std::error::Error;

    #[test]
    fn plaintext_container_validates_inputs_and_transfers_ownership() -> Result<(), Box<dyn Error>>
    {
        let params = BfvParameters::default_arc(2, 16);
        let encoding = Encoding::poly_at_level(0);
        let plaintext = Plaintext::zero(encoding.clone(), &params)?;
        let wrapped = PlaintextVec::try_from_plaintexts(
            vec![plaintext.clone(), plaintext.clone()],
            encoding.clone(),
            &params,
        )?;
        assert_eq!(wrapped.len(), 2);
        assert!(!wrapped.is_empty());
        assert_eq!(wrapped.as_slice(), &[plaintext.clone(), plaintext.clone()]);
        assert_eq!(wrapped.iter().count(), 2);
        assert_eq!((&wrapped).into_iter().count(), 2);
        assert_eq!(
            wrapped.into_vec(),
            vec![plaintext.clone(), plaintext.clone()]
        );
        assert_eq!(
            PlaintextVec::try_from_plaintexts(vec![plaintext.clone()], encoding.clone(), &params)?
                .into_iter()
                .collect::<Vec<_>>(),
            vec![plaintext.clone()]
        );

        assert!(matches!(
            PlaintextVec::try_from_plaintexts(vec![], encoding.clone(), &params),
            Err(crate::Error::Plaintext(
                crate::PlaintextError::EmptyPlaintextVec
            ))
        ));
        let other_params = BfvParameters::default_arc(2, 16);
        assert!(matches!(
            PlaintextVec::try_from_plaintexts(
                vec![
                    plaintext.clone(),
                    Plaintext::zero(encoding.clone(), &other_params)?
                ],
                encoding.clone(),
                &params
            ),
            Err(crate::Error::ParameterMismatch { .. })
        ));
        let mut wrong_context = plaintext.clone();
        wrong_context.poly_ntt =
            Poly::<Ntt>::zero(BfvParameters::default_arc(2, 32).context_at_level(0)?);
        assert!(matches!(
            PlaintextVec::try_from_plaintexts(
                vec![plaintext.clone(), wrong_context],
                encoding.clone(),
                &params
            ),
            Err(crate::Error::Plaintext(
                crate::PlaintextError::PolynomialContextMismatch { .. }
            ))
        ));
        assert!(matches!(
            PlaintextVec::try_from_plaintexts(
                vec![
                    plaintext.clone(),
                    Plaintext::zero(Encoding::poly_at_level(1), &params)?
                ],
                encoding.clone(),
                &params
            ),
            Err(crate::Error::InvalidLevel { .. })
        ));
        assert!(matches!(
            PlaintextVec::try_from_plaintexts(
                vec![
                    plaintext.clone(),
                    Plaintext::zero(Encoding::simd(), &params)?
                ],
                encoding.clone(),
                &params
            ),
            Err(crate::Error::Encoding(
                crate::EncodingError::Mismatch { .. }
            ))
        ));

        let mut missing_encoding = plaintext.clone();
        missing_encoding.encoding = None;
        assert!(matches!(
            PlaintextVec::try_from_plaintexts(vec![missing_encoding], encoding, &params),
            Err(crate::Error::Plaintext(
                crate::PlaintextError::MissingEncoding
            ))
        ));
        let no_simd_params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(17)
            .set_moduli_sizes(&[62])
            .build_arc()?;
        assert!(matches!(
            PlaintextVec::try_from_plaintexts(
                vec![Plaintext::zero(Encoding::simd(), &no_simd_params)?],
                Encoding::simd(),
                &no_simd_params
            ),
            Err(crate::Error::Encoding(
                crate::EncodingError::SimdUnavailable
            ))
        ));
        Ok(())
    }

    #[test]
    fn encode_decode() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for _ in 0..20 {
            for i in 1..5 {
                let params = BfvParameters::default_arc(1, 16);
                let a = params.plaintext();
                let q = fhe_math::zq::Modulus::new(a).unwrap();
                let a_vec = q.random_vec(params.degree() * i, &mut rng);

                let plaintexts = PlaintextVec::try_encode(
                    a_vec.as_slice(),
                    Encoding::poly_at_level(0),
                    &params,
                )?;
                assert_eq!(plaintexts.0.len(), i);

                for j in 0..i {
                    let b = Vec::<u64>::try_decode(&plaintexts.0[j], Encoding::poly_at_level(0))?;
                    assert_eq!(b, &a_vec[j * params.degree()..(j + 1) * params.degree()]);
                }

                let plaintexts_vt = PlaintextVec::try_encode_vt(
                    a_vec.as_slice(),
                    Encoding::poly_at_level(0),
                    &params,
                    fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public()),
                )?;
                assert_eq!(plaintexts_vt.0.len(), i);
                for (pt, pt_vt) in plaintexts.0.iter().zip(plaintexts_vt.0.iter()) {
                    assert_eq!(pt, pt_vt);
                }

                for j in 0..i {
                    let b =
                        Vec::<u64>::try_decode(&plaintexts_vt.0[j], Encoding::poly_at_level(0))?;
                    assert_eq!(b, &a_vec[j * params.degree()..(j + 1) * params.degree()]);
                }

                let plaintexts =
                    PlaintextVec::try_encode(a_vec.as_slice(), Encoding::simd(), &params)?;
                assert_eq!(plaintexts.0.len(), i);

                for j in 0..i {
                    let b = Vec::<u64>::try_decode(&plaintexts.0[j], Encoding::simd())?;
                    assert_eq!(b, &a_vec[j * params.degree()..(j + 1) * params.degree()]);
                }

                let plaintexts_vt = PlaintextVec::try_encode_vt(
                    a_vec.as_slice(),
                    Encoding::simd(),
                    &params,
                    fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public()),
                )?;
                assert_eq!(plaintexts_vt.0.len(), i);
                for (pt, pt_vt) in plaintexts.0.iter().zip(plaintexts_vt.0.iter()) {
                    assert_eq!(pt, pt_vt);
                }

                for j in 0..i {
                    let b = Vec::<u64>::try_decode(&plaintexts_vt.0[j], Encoding::simd())?;
                    assert_eq!(b, &a_vec[j * params.degree()..(j + 1) * params.degree()]);
                }
            }
        }
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(17)
            .set_moduli_sizes(&[62])
            .build_arc()?;
        let a = vec![1u64];
        assert!(matches!(
            PlaintextVec::try_encode(a.as_slice(), Encoding::simd(), &params),
            Err(crate::Error::Encoding(
                crate::EncodingError::SimdUnavailable
            ))
        ));
        assert!(matches!(
            PlaintextVec::try_encode_vt(
                a.as_slice(),
                Encoding::simd(),
                &params,
                fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public()),
            ),
            Err(crate::Error::Encoding(
                crate::EncodingError::SimdUnavailable
            ))
        ));
        Ok(())
    }

    #[test]
    fn biguint_encoding_uses_shared_chunking() -> Result<(), Box<dyn Error>> {
        let modulus = BigUint::parse_bytes(b"340282366920938463463374607431768211507", 10)
            .ok_or("invalid test modulus")?;
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus_biguint(modulus.clone())
            .set_moduli_sizes(&[62, 62, 62, 62, 62])
            .build_arc()?;
        let values = (0u32..20).map(BigUint::from).collect::<Vec<_>>();

        let plaintexts =
            PlaintextVec::try_encode(values.as_slice(), Encoding::poly_at_level(0), &params)?;
        assert_eq!(plaintexts.len(), 2);

        for (plaintext, chunk) in plaintexts.iter().zip(values.chunks(params.degree())) {
            let mut expected = chunk.to_vec();
            expected.resize(params.degree(), BigUint::zero());
            assert_eq!(
                Vec::<BigUint>::try_decode(plaintext, Encoding::poly_at_level(0))?,
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn empty_inputs_share_zero_encoding_path() -> Result<(), Box<dyn Error>> {
        let params = BfvParameters::default_arc(1, 16);
        let encoding = Encoding::poly();
        let constant = PlaintextVec::try_encode(&[] as &[u64], encoding.clone(), &params)?;
        let big = PlaintextVec::try_encode(&[] as &[BigUint], encoding.clone(), &params)?;
        let variable = PlaintextVec::try_encode_vt(
            &[] as &[u64],
            encoding.clone(),
            &params,
            fhe_traits::VariableTime::new(fhe_traits::PublicData::assert_public()),
        )?;

        for plaintexts in [&constant, &big, &variable] {
            assert_eq!(plaintexts.len(), 1);
            assert_eq!(
                Vec::<u64>::try_decode(&plaintexts[0], encoding.clone())?,
                vec![0; params.degree()]
            );
        }
        assert!(variable[0].poly_ntt.allows_variable_time_computations());
        Ok(())
    }
}
