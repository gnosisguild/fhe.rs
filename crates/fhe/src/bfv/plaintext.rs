//! Plaintext type in the BFV encryption scheme.
use crate::{
    bfv::{BfvParameters, Encoding, PlaintextVec},
    Error, Result,
};
use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
use fhe_traits::{FheDecoder, FheEncoder, FheParametrized, FhePlaintext};
use ndarray::Array2;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::encoding::EncodingEnum;

/// A plaintext object, that encodes a vector according to a specific encoding.
#[derive(Debug, Clone, Eq)]
pub struct Plaintext {
    /// The parameters of the underlying BFV encryption scheme.
    pub(crate) par: Arc<BfvParameters>,
    /// The value after encoding.
    pub value: Box<[u64]>,
    /// The encoding of the plaintext, if known
    pub(crate) encoding: Option<Encoding>,
    /// The plaintext as a polynomial.
    pub(crate) poly_ntt: Poly,
    /// The level of the plaintext
    pub(crate) level: usize,
}

impl FheParametrized for Plaintext {
    type Parameters = BfvParameters;
}

impl FhePlaintext for Plaintext {
    type Encoding = Encoding;
}

// Zeroizing of plaintexts.
impl ZeroizeOnDrop for Plaintext {}

impl Zeroize for Plaintext {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.poly_ntt.zeroize();
    }
}

impl Plaintext {
    // pub fn to_poly(&self) -> Poly {
    //     let mut m_v = Zeroizing::new(self.value.clone());
    //     self.par
    //         .plaintext
    //         .scalar_mul_vec(&mut m_v, self.par.q_mod_t[self.level]);
    //     let ctx = self.par.ctx_at_level(self.level).unwrap();
    //     let mut m =
    //         Poly::try_convert_from(m_v.as_ref(), ctx, false,
    // Representation::PowerBasis).unwrap();
    //     m.change_representation(Representation::Ntt);
    //     m *= &self.par.delta[self.level];
    //     m
    // }

    /// Temporary hack to fix centered reduction for Greco. Rather than
    /// multiplying the standard form m_v by the standard form delta after
    /// NTT, we first center m_v, multiply by standard form delta, reduce
    /// the i64 values and convert back to standard form. There seems to be an
    /// issue with simply converting to standard form without first
    /// converting to centered, then scaling and reducing. Note it was
    /// necessary to use BigInt as the multiplication with delta causes a very
    /// large integer, greater than 64 bits.
    pub fn to_poly(&self) -> Poly {
        // Scale plaintext by q_mod_t for the current level
        let mut m_v = Zeroizing::new(self.value.clone());
        self.par
            .plaintext
            .scalar_mul_vec(&mut m_v, self.par.q_mod_t[self.level]);

        // Get the context for the current level
        let ctx = self.par.ctx_at_level(self.level).unwrap();
        let mut m_scaled_by_delta: Vec<u64> = Vec::new();

        for qi in ctx.moduli_operators() {
            let qi_modulus = BigInt::from(qi.modulus());
            let delta = BigInt::from(qi.inv(qi.neg(self.par.plaintext())).unwrap());

            for x in m_v.iter() {
                // Scale by delta, reduce by modulus, and ensure result is non-negative
                let mut reduced =
                    BigInt::from(self.par.plaintext.center(*x)) * &delta % &qi_modulus;
                if reduced < BigInt::from(0) {
                    reduced += &qi_modulus;
                }

                // Convert to u64, panicking if the value is too large
                m_scaled_by_delta.push(
                    reduced
                        .to_u64()
                        .unwrap_or_else(|| panic!("Value {reduced:?} too large for u64")),
                );
            }
        }

        // Convert the scaled values into a polynomial
        let m_final =
            Array2::from_shape_vec((ctx.moduli().len(), self.par.degree()), m_scaled_by_delta)
                .unwrap();
        let mut m =
            Poly::try_convert_from(m_final, ctx, false, Representation::PowerBasis).unwrap();
        m.change_representation(Representation::Ntt);

        m
    }

    /// Generate a zero plaintext.
    pub fn zero(encoding: Encoding, par: &Arc<BfvParameters>) -> Result<Self> {
        let level = encoding.level;
        let ctx = par.ctx_at_level(level)?;
        let value = vec![0u64; par.degree()];
        let poly_ntt = Poly::zero(ctx, Representation::Ntt);
        Ok(Self {
            par: par.clone(),
            value: value.into_boxed_slice(),
            encoding: Some(encoding),
            poly_ntt,
            level,
        })
    }

    /// Returns the level of this plaintext.
    pub fn level(&self) -> usize {
        self.par.level_of_ctx(self.poly_ntt.ctx()).unwrap()
    }
}

unsafe impl Send for Plaintext {}

// Implement the equality manually; we want to say that two plaintexts are equal
// even if one of them doesn't store its encoding information.
impl PartialEq for Plaintext {
    fn eq(&self, other: &Self) -> bool {
        let mut eq = self.par == other.par;
        eq &= self.value == other.value;
        if self.encoding.is_some() && other.encoding.is_some() {
            eq &= self.encoding.as_ref().unwrap() == other.encoding.as_ref().unwrap()
        }
        eq
    }
}

// Conversions.
impl TryConvertFrom<&Plaintext> for Poly {
    fn try_convert_from<R>(
        pt: &Plaintext,
        ctx: &Arc<Context>,
        variable_time: bool,
        _: R,
    ) -> fhe_math::Result<Self>
    where
        R: Into<Option<Representation>>,
    {
        if ctx
            != pt
                .par
                .ctx_at_level(pt.level())
                .map_err(|e| fhe_math::Error::Default(e.to_string()))?
        {
            Err(fhe_math::Error::Default(
                "Incompatible contexts".to_string(),
            ))
        } else {
            Poly::try_convert_from(
                pt.value.as_ref(),
                ctx,
                variable_time,
                Representation::PowerBasis,
            )
        }
    }
}

// Encoding and decoding.

impl<'a, const N: usize, T> FheEncoder<&'a [T; N]> for Plaintext
where
    Plaintext: FheEncoder<&'a [T], Error = Error>,
{
    type Error = Error;
    fn try_encode(value: &'a [T; N], encoding: Encoding, par: &Arc<BfvParameters>) -> Result<Self> {
        Plaintext::try_encode(value.as_ref(), encoding, par)
    }
}

impl<'a, T> FheEncoder<&'a Vec<T>> for Plaintext
where
    Plaintext: FheEncoder<&'a [T], Error = Error>,
{
    type Error = Error;
    fn try_encode(value: &'a Vec<T>, encoding: Encoding, par: &Arc<BfvParameters>) -> Result<Self> {
        Plaintext::try_encode(value.as_ref(), encoding, par)
    }
}

impl<'a> FheEncoder<&'a [u64]> for Plaintext {
    type Error = Error;
    fn try_encode(value: &'a [u64], encoding: Encoding, par: &Arc<BfvParameters>) -> Result<Self> {
        if value.len() > par.degree() {
            return Err(Error::TooManyValues(value.len(), par.degree()));
        }
        let v = PlaintextVec::try_encode(value, encoding, par)?;
        Ok(v.0[0].clone())
    }
}

impl<'a> FheEncoder<&'a [i64]> for Plaintext {
    type Error = Error;
    fn try_encode(value: &'a [i64], encoding: Encoding, par: &Arc<BfvParameters>) -> Result<Self> {
        let w = Zeroizing::new(par.plaintext.reduce_vec_i64(value));
        Plaintext::try_encode(w.as_ref() as &[u64], encoding, par)
    }
}

impl FheDecoder<Plaintext> for Vec<u64> {
    fn try_decode<O>(pt: &Plaintext, encoding: O) -> Result<Vec<u64>>
    where
        O: Into<Option<Encoding>>,
    {
        let encoding = encoding.into();
        let enc: Encoding;
        if pt.encoding.is_none() && encoding.is_none() {
            return Err(Error::UnspecifiedInput("No encoding specified".to_string()));
        } else if pt.encoding.is_some() {
            enc = pt.encoding.as_ref().unwrap().clone();
            if let Some(arg_enc) = encoding {
                if arg_enc != enc {
                    return Err(Error::EncodingMismatch(arg_enc.into(), enc.into()));
                }
            }
        } else {
            enc = encoding.unwrap();
            if let Some(pt_enc) = pt.encoding.as_ref() {
                if pt_enc != &enc {
                    return Err(Error::EncodingMismatch(pt_enc.into(), enc.into()));
                }
            }
        }

        let mut w = pt.value.to_vec();

        match enc.encoding {
            EncodingEnum::Poly => Ok(w),
            EncodingEnum::Simd => {
                if let Some(op) = &pt.par.op {
                    op.forward(&mut w);
                    let mut w_reordered = w.clone();
                    for i in 0..pt.par.degree() {
                        w_reordered[i] = w[pt.par.matrix_reps_index_map[i]]
                    }
                    w.zeroize();
                    Ok(w_reordered)
                } else {
                    Err(Error::EncodingNotSupported(EncodingEnum::Simd.to_string()))
                }
            }
        }
    }

    type Error = Error;
}

impl FheDecoder<Plaintext> for Vec<i64> {
    fn try_decode<E>(pt: &Plaintext, encoding: E) -> Result<Vec<i64>>
    where
        E: Into<Option<Encoding>>,
    {
        let v = Vec::<u64>::try_decode(pt, encoding)?;
        Ok(unsafe { pt.par.plaintext.center_vec_vt(&v) })
    }

    type Error = Error;
}

#[cfg(test)]
mod tests {
    use super::{Encoding, Plaintext};
    use crate::bfv::parameters::{BfvParameters, BfvParametersBuilder};
    use fhe_math::rq::{Poly, Representation};
    use fhe_traits::{FheDecoder, FheEncoder};
    use rand::thread_rng;
    use std::error::Error;
    use zeroize::Zeroize;

    #[test]
    fn try_encode() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        // The default test parameters support both Poly and Simd encodings
        let params = BfvParameters::default_arc(1, 8);
        let a = params.plaintext.random_vec(params.degree(), &mut rng);

        let plaintext = Plaintext::try_encode(&[0u64; 9], Encoding::poly(), &params);
        assert!(plaintext.is_err());

        let plaintext = Plaintext::try_encode(&a, Encoding::poly(), &params);
        assert!(plaintext.is_ok());

        let plaintext = Plaintext::try_encode(&a, Encoding::simd(), &params);
        assert!(plaintext.is_ok());

        let plaintext = Plaintext::try_encode(&[1u64], Encoding::poly(), &params);
        assert!(plaintext.is_ok());

        // The following parameters do not allow for Simd encoding
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(2)
            .set_moduli(&[4611686018326724609])
            .build_arc()?;

        let a = params.plaintext.random_vec(params.degree(), &mut rng);

        let plaintext = Plaintext::try_encode(&a, Encoding::poly(), &params);
        assert!(plaintext.is_ok());

        let plaintext = Plaintext::try_encode(&a, Encoding::simd(), &params);
        assert!(plaintext.is_err());

        Ok(())
    }

    #[test]
    fn encode_decode() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(1, 8);
        let a = params.plaintext.random_vec(params.degree(), &mut rng);

        let plaintext = Plaintext::try_encode(&a, Encoding::simd(), &params);
        assert!(plaintext.is_ok());
        let b = Vec::<u64>::try_decode(&plaintext?, Encoding::simd())?;
        assert_eq!(b, a);

        let a = unsafe { params.plaintext.center_vec_vt(&a) };
        let plaintext = Plaintext::try_encode(&a, Encoding::poly(), &params);
        assert!(plaintext.is_ok());
        let b = Vec::<i64>::try_decode(&plaintext?, Encoding::poly())?;
        assert_eq!(b, a);

        let plaintext = Plaintext::try_encode(&a, Encoding::simd(), &params);
        assert!(plaintext.is_ok());
        let b = Vec::<i64>::try_decode(&plaintext?, Encoding::simd())?;
        assert_eq!(b, a);

        Ok(())
    }

    #[test]
    fn partial_eq() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(1, 8);
        let a = params.plaintext.random_vec(params.degree(), &mut rng);

        let plaintext = Plaintext::try_encode(&a, Encoding::poly(), &params)?;
        let mut same_plaintext = Plaintext::try_encode(&a, Encoding::poly(), &params)?;
        assert_eq!(plaintext, same_plaintext);

        // Equality also holds when there is no encoding specified. In this test, we use
        // the fact that we can set it to None directly, but such a partial plaintext
        // will be created during decryption since we do not specify the encoding at the
        // time.
        same_plaintext.encoding = None;
        assert_eq!(plaintext, same_plaintext);

        Ok(())
    }

    #[test]
    fn try_decode_errors() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(1, 8);
        let a = params.plaintext.random_vec(params.degree(), &mut rng);

        let mut plaintext = Plaintext::try_encode(&a, Encoding::poly(), &params)?;

        assert!(Vec::<u64>::try_decode(&plaintext, None).is_ok());
        let e = Vec::<u64>::try_decode(&plaintext, Encoding::simd());
        assert!(e.is_err());
        assert_eq!(
            e.unwrap_err(),
            crate::Error::EncodingMismatch(Encoding::simd().into(), Encoding::poly().into())
        );
        let e = Vec::<u64>::try_decode(&plaintext, Encoding::poly_at_level(1));
        assert!(e.is_err());
        assert_eq!(
            e.unwrap_err(),
            crate::Error::EncodingMismatch(
                Encoding::poly_at_level(1).into(),
                Encoding::poly().into()
            )
        );

        plaintext.encoding = None;
        let e = Vec::<u64>::try_decode(&plaintext, None);
        assert!(e.is_err());
        assert_eq!(
            e.unwrap_err(),
            crate::Error::UnspecifiedInput("No encoding specified".to_string())
        );

        Ok(())
    }

    #[test]
    fn zero() -> Result<(), Box<dyn Error>> {
        let params = BfvParameters::default_arc(1, 8);
        let plaintext = Plaintext::zero(Encoding::poly(), &params)?;

        assert_eq!(plaintext.value, Box::<[u64]>::from([0u64; 8]));
        assert_eq!(
            plaintext.poly_ntt,
            Poly::zero(&params.ctx[0], Representation::Ntt)
        );

        Ok(())
    }

    #[test]
    fn zeroize() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let params = BfvParameters::default_arc(1, 8);
        let a = params.plaintext.random_vec(params.degree(), &mut rng);
        let mut plaintext = Plaintext::try_encode(&a, Encoding::poly(), &params)?;

        plaintext.zeroize();

        assert_eq!(plaintext, Plaintext::zero(Encoding::poly(), &params)?);

        Ok(())
    }

    #[test]
    fn try_encode_level() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        // The default test parameters support both Poly and Simd encodings
        let params = BfvParameters::default_arc(10, 8);
        let a = params.plaintext.random_vec(params.degree(), &mut rng);

        for level in 0..10 {
            let plaintext = Plaintext::try_encode(&a, Encoding::poly_at_level(level), &params)?;
            assert_eq!(plaintext.level(), level);
            let plaintext = Plaintext::try_encode(&a, Encoding::simd_at_level(level), &params)?;
            assert_eq!(plaintext.level(), level);
        }

        Ok(())
    }
}
