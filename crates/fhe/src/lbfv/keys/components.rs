//! Shared construction and validation for single-party and distributed l-BFV
//! relinearization keys (Urban–Rambaud §4.2).

use super::LBFVPublicKey;
use crate::bfv::{
    BfvParameters, CommonRandomPolyVec, KeySwitchingKey, SecretKey,
    traits::TryConvertFrom as TryConvertKey,
};
use crate::proto::bfv::KeySwitchingKey as KeySwitchingKeyProto;
use crate::reference_string::{
    same_concrete_values, validate_distinct_seeds, validate_reference_string_pair,
};
use crate::{Error, EvaluationKeyError, MultipartyError, ParameterSource, Result};
use fhe_math::rq::{
    Context, Ntt, NttShoup, Poly, PowerBasis, switcher::Switcher, traits::TryConvertFrom,
};
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::Zeroizing;

type Seed = [u8; 32];

pub(crate) fn row_count(params: &BfvParameters, level: usize, key_level: usize) -> Result<usize> {
    if key_level != 0 {
        return Err(Error::InvalidLevel {
            level: key_level,
            min_level: 0,
            max_level: 0,
        });
    }
    let count = params.context_at_level(level)?.moduli().len();
    if count < 2 {
        return Err(EvaluationKeyError::KeySwitchingNotSupported.into());
    }
    Ok(count)
}

/// Concrete public rows and the optional seed known to reproduce them.
pub(crate) struct KeyRows {
    polys: Vec<Poly<NttShoup>>,
    seed: Option<Seed>,
}

/// At a nonzero ciphertext level the RLK consumes only a CRS prefix, but the
/// rest of the public key's `a` rows are public too. An active URS row must
/// not reuse any of them.
pub(crate) fn validate_crs_tail<'a>(
    crs: impl Iterator<Item = &'a Poly<Ntt>>,
    d1: &[Poly<NttShoup>],
) -> Result<()> {
    for (crs_index, a) in crs.enumerate().skip(d1.len()) {
        if let Some(urs_index) = d1.iter().position(|row| same_concrete_values(a, row)) {
            return Err(MultipartyError::OverlappingReferenceStringRows {
                crs_index,
                urs_index,
            }
            .into());
        }
    }
    Ok(())
}

impl KeyRows {
    pub(crate) fn seeded(ctx: &Arc<Context>, count: usize, seed: Seed) -> Self {
        Self {
            polys: KeySwitchingKey::c1_from_seed(ctx, seed, count),
            seed: Some(seed),
        }
    }

    pub(crate) fn explicit(polys: Vec<Poly<NttShoup>>, ctx: &Arc<Context>) -> Result<Self> {
        let polys = polys
            .into_iter()
            .map(|p| {
                if p.ctx() != ctx || !p.has_canonical_coefficients() {
                    return Err(EvaluationKeyError::InvalidLbfvLayout {
                        reason: "explicit rows must be canonical level-zero polynomials",
                    }
                    .into());
                }
                // `Poly::set_coefficients` can leave an old Shoup table in place.
                // Derive the table from the validated concrete coefficients.
                Ok(p.into_ntt().into_ntt_shoup())
            })
            .collect::<Result<_>>()?;
        Ok(Self { polys, seed: None })
    }

    pub(crate) fn from_crp(
        crp: &CommonRandomPolyVec,
        ctx: &Arc<Context>,
        count: usize,
    ) -> Result<Self> {
        let rows = crp.as_slice().get(..count).ok_or(
            MultipartyError::InvalidCommonRandomPolynomialCount {
                expected: count,
                actual: crp.len(),
            },
        )?;
        let mut polys = Vec::with_capacity(count);
        for crp in rows {
            if crp.poly().ctx() != ctx || !crp.poly().has_canonical_coefficients() {
                return Err(EvaluationKeyError::InvalidLbfvLayout {
                    reason: "CRP rows must be canonical level-zero polynomials",
                }
                .into());
            }
            polys.push(crp.poly().clone().into_ntt_shoup());
        }
        if let Some(seed) = crp.seed() {
            let expected = KeySwitchingKey::c1_from_seed(ctx, seed, count);
            if let Some(index) = polys
                .iter()
                .zip(&expected)
                .position(|(a, b)| !same_concrete_values(a, b))
            {
                return Err(MultipartyError::CommonRandomPolynomialSeedMismatch { index }.into());
            }
        }
        Ok(Self {
            polys,
            seed: crp.seed(),
        })
    }

    pub(crate) fn from_public_key(
        pk: &LBFVPublicKey,
        params: &Arc<BfvParameters>,
        count: usize,
        d1: &Self,
    ) -> Result<Self> {
        if pk.par != *params {
            return Err(Error::ParameterMismatch {
                left: ParameterSource::SecretKey,
                right: ParameterSource::PublicKey,
            });
        }
        pk.validate_rows()?;
        validate_crs_tail(pk.c.iter().filter_map(|row| row.get(1)), &d1.polys)?;
        let polys =
            pk.c.iter()
                .take(count)
                .filter_map(|row| row.get(1))
                .cloned()
                .map(Poly::<Ntt>::into_ntt_shoup)
                .collect();
        Ok(Self {
            polys,
            seed: pk.seed,
        })
    }

    pub(crate) fn check_crp_tail(&self, crs: &CommonRandomPolyVec) -> Result<()> {
        validate_crs_tail(crs.as_slice().iter().map(|row| row.poly()), &self.polys)
    }
}

/// An l-BFV contribution contains two KSKs with the same RNS layout. These
/// fields are not exposed through the operational or contribution APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Components {
    pub(crate) r_to_s: KeySwitchingKey,
    pub(crate) s_to_r: KeySwitchingKey,
}

impl Components {
    pub(crate) fn from_protos(
        r: Option<&KeySwitchingKeyProto>,
        s: Option<&KeySwitchingKeyProto>,
        params: &Arc<BfvParameters>,
    ) -> Result<Self> {
        let (Some(r), Some(s)) = (r, s) else {
            return Err(crate::SerializationError::MissingField {
                field: crate::SerializedField::RelinearizationKeySwitchingKey,
            }
            .into());
        };
        for ksk in [r, s] {
            row_count(
                params,
                ksk.ciphertext_level as usize,
                ksk.ksk_level as usize,
            )?;
            if ksk.ciphertext_level != r.ciphertext_level
                || ksk.log_base != 0
                || (!ksk.seed.is_empty() && !ksk.c1.is_empty())
            {
                return Err(EvaluationKeyError::InvalidLbfvLayout {
                    reason: "inconsistent level, decomposition or seeded/explicit KSK rows",
                }
                .into());
            }
        }
        Self::checked(
            KeySwitchingKey::try_convert_from(r, params)?,
            KeySwitchingKey::try_convert_from(s, params)?,
        )
    }

    /// Apply the same layout and reference-string invariants at both wire boundaries.
    pub(crate) fn checked(r_to_s: KeySwitchingKey, s_to_r: KeySwitchingKey) -> Result<Self> {
        let count = row_count(&r_to_s.params, r_to_s.ciphertext_level, r_to_s.ksk_level)?;
        let ctx = r_to_s.params.context_at_level(0)?;
        let ct_ctx = r_to_s.params.context_at_level(r_to_s.ciphertext_level)?;
        for ksk in [&r_to_s, &s_to_r] {
            if ksk.params != r_to_s.params
                || ksk.ksk_level != 0
                || ksk.ciphertext_level != r_to_s.ciphertext_level
                || &ksk.ctx_ksk != ctx
                || &ksk.ctx_ciphertext != ct_ctx
                || ksk.log_base != 0
                || ksk.c0.len() != count
                || ksk.c1.len() != count
                || ksk
                    .c0
                    .iter()
                    .chain(ksk.c1.iter())
                    .any(|p| p.ctx() != ctx || !p.has_canonical_coefficients())
            {
                return Err(EvaluationKeyError::InvalidLbfvLayout {
                    reason: "incompatible relinearization key-switching rows or levels",
                }
                .into());
            }
        }
        validate_reference_string_pair(ctx, &s_to_r.c1, &r_to_s.c1)?;
        Ok(Self { r_to_s, s_to_r })
    }
}

/// Reference strings validated before touching secret contributions or sampling `r`.
pub(crate) struct RelinInputs {
    d1: KeyRows,
    a: KeyRows,
    level: usize,
}

impl RelinInputs {
    pub(crate) fn new(
        params: &BfvParameters,
        level: usize,
        d1: KeyRows,
        a: KeyRows,
    ) -> Result<Self> {
        let count = row_count(params, level, 0)?;
        if let (Some(d1), Some(a)) = (d1.seed, a.seed) {
            validate_distinct_seeds(&d1, &a)
                .map_err(|_| MultipartyError::IdenticalReferenceStringSeeds)?;
        }
        for rows in [&d1, &a] {
            if rows.polys.len() != count {
                return Err(MultipartyError::InvalidCommonRandomPolynomialCount {
                    actual: rows.polys.len(),
                    expected: count,
                }
                .into());
            }
        }
        validate_reference_string_pair(params.context_at_level(0)?, &a.polys, &d1.polys)?;
        Ok(Self { d1, a, level })
    }

    pub(crate) fn generate<R: RngCore + CryptoRng>(
        self,
        sk: &SecretKey,
        r: &SecretKey,
        rng: &mut R,
    ) -> Result<Components> {
        self.generate_using(sk, r, rng, |key, from, rows, level, rng| {
            Ok((
                KeySwitchingKey::new_with_c1(key, from, rows, level, 0, rng)?,
                (),
            ))
        })
        .map(|(components, _, _)| components)
    }

    // Normal key generation does not allocate witness rows. Both paths use
    // the same sign convention, switching and verified seed metadata.
    pub(crate) fn generate_using<R: RngCore + CryptoRng, W>(
        self,
        sk: &SecretKey,
        r: &SecretKey,
        rng: &mut R,
        mut ksk: impl FnMut(
            &SecretKey,
            &Poly<PowerBasis>,
            Vec<Poly<NttShoup>>,
            usize,
            &mut R,
        ) -> Result<(KeySwitchingKey, W)>,
    ) -> Result<(Components, W, W)> {
        let ct_ctx = sk.params.context_at_level(self.level)?;
        let switcher = Switcher::new(ct_ctx, sk.params.context_at_level(0)?)?;
        let lift = |key: &SecretKey| -> Result<_> {
            let p = Zeroizing::new(Poly::<PowerBasis>::try_convert_from(
                key.coeffs.as_ref(),
                ct_ctx,
                false,
            )?);
            Ok(Zeroizing::new(p.switch(&switcher)?))
        };
        // d0 = -s*d1 + e0 + g*r; d2 = r*a + e2 + g*s (store positive a).
        let (mut r_to_s, e0) = ksk(sk, lift(r)?.as_ref(), self.d1.polys, self.level, rng)?;
        let mut neg_r = r.clone();
        neg_r.coeffs.iter_mut().for_each(|x| *x = x.wrapping_neg());
        let (mut s_to_r, e2) = ksk(&neg_r, lift(sk)?.as_ref(), self.a.polys, self.level, rng)?;
        r_to_s.seed = self.d1.seed;
        s_to_r.seed = self.a.seed;
        Ok((Components { r_to_s, s_to_r }, e0, e2))
    }
}
