#![warn(missing_docs, unused_imports)]
// Expect indexing in this performance-critical RNS implementation
#![expect(
    clippy::indexing_slicing,
    reason = "performance or example code relies on validated indices"
)]

//! Residue-Number System operations.

use crate::{Error, Result, zq::Modulus};
use itertools::{Itertools, izip};
use ndarray::ArrayView1;
use num_bigint::BigUint;
use num_bigint_dig::{BigInt as BigIntDig, BigUint as BigUintDig, ExtendedGcd, ModInverse};
use num_traits::{One, Zero, cast::ToPrimitive};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, fmt::Debug};

pub mod scaler;

pub use scaler::{RnsScaler, RnsScalerRaw, ScalingFactor, ScalingFactorRaw};

/// Context for a Residue Number System.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct RnsContext {
    moduli_u64: Vec<u64>,
    moduli: Vec<Modulus>,
    q_tilde: Vec<u64>,
    q_tilde_shoup: Vec<u64>,
    q_star: Vec<BigUint>,
    garner: Vec<BigUint>,
    /// The product of all moduli in the RNS basis
    pub product: BigUint,
}

/// Serializable form of [`RnsContext`].
///
/// This is an untrusted transport DTO: it carries only the authoritative
/// modulus list, and [`RnsContextRaw::into_context`] recomputes every derived
/// value (product, `q_star`, `q_tilde`, Shoup and Garner tables) through the
/// canonical [`RnsContext::new`] construction. Serialized precomputed tables
/// are never accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RnsContextRaw {
    /// Moduli in u64 form.
    pub moduli_u64: Vec<u64>,
}

impl Debug for RnsContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RnsContext")
            .field("moduli_u64", &self.moduli_u64)
            // .field("moduli", &self.moduli)
            // .field("q_tilde", &self.q_tilde)
            // .field("q_tilde_shoup", &self.q_tilde_shoup)
            // .field("q_star", &self.q_star)
            // .field("garner", &self.garner)
            .field("product", &self.product)
            .finish()
    }
}

impl RnsContext {
    /// Create a RNS context from a list of moduli.
    ///
    /// Returns an error if the list is empty, or if the moduli are no coprime.
    pub fn new(moduli_u64: &[u64]) -> Result<Self> {
        if moduli_u64.is_empty() {
            Err(Error::Default("The list of moduli is empty".to_string()))
        } else {
            let mut product = BigUint::one();
            let mut product_dig = BigUintDig::one();

            for i in 0..moduli_u64.len() {
                // Return an error if the moduli are not coprime.
                for j in 0..moduli_u64.len() {
                    if i != j {
                        let (d, _, _) = BigUintDig::from(moduli_u64[i])
                            .extended_gcd(&BigUintDig::from(moduli_u64[j]));
                        if d.cmp(&BigIntDig::from(1)) != Ordering::Equal {
                            return Err(Error::Default("The moduli are not coprime".to_string()));
                        }
                    }
                }

                product *= &BigUint::from(moduli_u64[i]);
                product_dig *= &BigUintDig::from(moduli_u64[i]);
            }

            #[expect(
                clippy::type_complexity,
                reason = "complex tuple is produced by multiunzip"
            )]
            let (moduli, q_tilde, q_tilde_shoup, q_star, garner): (
                Vec<Modulus>,
                Vec<u64>,
                Vec<u64>,
                Vec<BigUint>,
                Vec<BigUint>,
            ) = moduli_u64
                .iter()
                .map(|modulus| {
                    let m = Modulus::new(*modulus)?;
                    let q_star_i = &product / modulus;
                    // Coprimality was validated above, so the inverse exists
                    // and fits in a u64.
                    let q_tilde_i = (&product_dig / modulus)
                        .mod_inverse(&BigUintDig::from(*modulus))
                        .ok_or_else(|| Error::Default("The moduli are not coprime".to_string()))?
                        .to_u64()
                        .ok_or_else(|| Error::Default("The moduli are not coprime".to_string()))?;
                    let garner_i = &q_star_i * q_tilde_i;
                    let q_tilde_shoup_i = m.shoup(q_tilde_i);
                    Ok((m, q_tilde_i, q_tilde_shoup_i, q_star_i, garner_i))
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .multiunzip();

            Ok(Self {
                moduli_u64: moduli_u64.to_owned(),
                moduli,
                q_tilde,
                q_tilde_shoup,
                q_star,
                garner,
                product,
            })
        }
    }

    /// Returns the product of the moduli used when creating the RNS context.
    #[must_use]
    pub const fn modulus(&self) -> &BigUint {
        &self.product
    }

    /// Project a BigUint into its rests.
    #[must_use]
    pub fn project(&self, a: &BigUint) -> Vec<u64> {
        self.moduli_u64
            .iter()
            .map(|modulus| (a % modulus).to_u64().unwrap())
            .collect()
    }

    /// Lift rests into a BigUint.
    ///
    /// Requires exactly one residue for every modulus of the context, and
    /// requires every residue to be a canonical representative in
    /// `[0, modulus)`. The input is never truncated, reduced, or
    /// reinterpreted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidResidueCount`] if the number of residues does
    /// not match the number of moduli, and [`Error::InvalidResidue`] if a
    /// residue is not in `[0, modulus)`.
    pub fn lift(&self, rests: ArrayView1<u64>) -> Result<BigUint> {
        if rests.len() != self.moduli.len() {
            return Err(Error::InvalidResidueCount {
                expected: self.moduli.len(),
                actual: rests.len(),
            });
        }
        for (r_i, modulus) in izip!(rests.iter(), self.moduli_u64.iter()) {
            if *r_i >= *modulus {
                return Err(Error::InvalidResidue {
                    modulus: *modulus,
                    value: *r_i,
                });
            }
        }
        let mut result = BigUint::zero();
        izip!(rests.iter(), self.garner.iter())
            .for_each(|(r_i, garner_i)| result += garner_i * *r_i);
        Ok(result % &self.product)
    }

    /// Getter for the i-th garner coefficient.
    #[must_use]
    pub fn get_garner(&self, i: usize) -> Option<&BigUint> {
        self.garner.get(i)
    }
}

impl RnsContext {
    /// Export this context into a raw representation.
    #[must_use]
    pub fn to_raw(&self) -> RnsContextRaw {
        RnsContextRaw {
            moduli_u64: self.moduli_u64.clone(),
        }
    }
}

impl RnsContextRaw {
    /// Build an [`RnsContext`] from its raw parts.
    ///
    /// The raw data is untrusted: only the modulus list is used, and all
    /// internal state (product, `q_star`, `q_tilde`, Shoup and Garner tables)
    /// is recomputed by the canonical [`RnsContext::new`] construction. The
    /// moduli must form a non-empty, pairwise-coprime basis of valid moduli.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRawContext`] if the modulus list is empty,
    /// contains an invalid modulus, or is not pairwise coprime.
    pub fn into_context(self) -> Result<RnsContext> {
        RnsContext::new(&self.moduli_u64).map_err(|e| Error::InvalidRawContext(e.to_string()))
    }
}

#[cfg(test)]
mod tests {

    use std::error::Error;

    use super::{RnsContext, RnsContextRaw};
    use ndarray::ArrayView1;
    use num_bigint::BigUint;
    use rand::RngCore;

    #[test]
    fn constructor() {
        assert!(RnsContext::new(&[2]).is_ok());
        assert!(RnsContext::new(&[2, 3]).is_ok());
        assert!(RnsContext::new(&[4, 15, 1153]).is_ok());

        let e = RnsContext::new(&[]);
        assert!(e.is_err());
        assert_eq!(e.unwrap_err().to_string(), "The list of moduli is empty");
        let e = RnsContext::new(&[2, 4]);
        assert!(e.is_err());
        assert_eq!(e.unwrap_err().to_string(), "The moduli are not coprime");
        let e = RnsContext::new(&[2, 3, 5, 30]);
        assert!(e.is_err());
        assert_eq!(e.unwrap_err().to_string(), "The moduli are not coprime");
    }

    #[test]
    fn lift_rejects_wrong_length_and_noncanonical_rests() -> Result<(), Box<dyn Error>> {
        let rns = RnsContext::new(&[4, 15, 1153])?;

        // Short, long, and empty residue vectors are rejected.
        for (actual, expected) in [(0, 3), (2, 3), (4, 3)] {
            let rests = vec![0u64; actual];
            assert_eq!(
                rns.lift(ArrayView1::from(&rests)).unwrap_err(),
                crate::Error::InvalidResidueCount { expected, actual }
            );
        }

        // A residue equal to its modulus is rejected.
        assert_eq!(
            rns.lift(ArrayView1::from(&[4u64, 0, 0])).unwrap_err(),
            crate::Error::InvalidResidue {
                modulus: 4,
                value: 4,
            }
        );
        // A residue above its modulus is rejected.
        assert_eq!(
            rns.lift(ArrayView1::from(&[5u64, 0, 0])).unwrap_err(),
            crate::Error::InvalidResidue {
                modulus: 4,
                value: 5,
            }
        );
        assert_eq!(
            rns.lift(ArrayView1::from(&[0u64, 15, 0])).unwrap_err(),
            crate::Error::InvalidResidue {
                modulus: 15,
                value: 15,
            }
        );
        assert_eq!(
            rns.lift(ArrayView1::from(&[0u64, 0, 1153])).unwrap_err(),
            crate::Error::InvalidResidue {
                modulus: 1153,
                value: 1153,
            }
        );

        // Canonical values still lift correctly.
        assert_eq!(
            rns.lift(ArrayView1::from(&[3u64, 14, 1152]))?,
            BigUint::from(4u64 * 15 * 1153 - 1)
        );
        Ok(())
    }

    #[test]
    fn raw_context_round_trip_and_rebuild() -> Result<(), Box<dyn Error>> {
        let rns = RnsContext::new(&[4, 15, 1153])?;
        let raw = rns.to_raw();
        // The raw DTO carries only the authoritative modulus list; every
        // derived value is recomputed on import.
        assert_eq!(raw.moduli_u64, vec![4u64, 15, 1153]);
        let rebuilt = raw.into_context()?;
        assert_eq!(rebuilt, rns);
        // Rebuilding from a hand-built raw equals the canonical constructor.
        let hand_built = RnsContextRaw {
            moduli_u64: vec![4u64, 15, 1153],
        };
        assert_eq!(hand_built.into_context()?, rebuilt);
        // Same moduli always rebuild the same context, whatever else the raw
        // data carried.
        let again = RnsContextRaw {
            moduli_u64: vec![4u64, 15, 1153],
        }
        .into_context()?;
        assert_eq!(again, rebuilt);
        Ok(())
    }

    #[test]
    fn raw_context_rejects_invalid_moduli() {
        // Empty bases.
        assert_eq!(
            (RnsContextRaw { moduli_u64: vec![] })
                .into_context()
                .unwrap_err(),
            crate::Error::InvalidRawContext("The list of moduli is empty".to_string())
        );
        // Zero and one are not valid moduli.
        assert_eq!(
            (RnsContextRaw {
                moduli_u64: vec![0]
            })
            .into_context()
            .unwrap_err(),
            crate::Error::InvalidRawContext(
                "Invalid modulus: modulus 0 should be between 2 and (1 << 62) - 1.".to_string()
            )
        );
        assert!(
            (RnsContextRaw {
                moduli_u64: vec![1]
            })
            .into_context()
            .is_err()
        );
        // Duplicate moduli are not coprime.
        assert_eq!(
            (RnsContextRaw {
                moduli_u64: vec![4, 4]
            })
            .into_context()
            .unwrap_err(),
            crate::Error::InvalidRawContext("The moduli are not coprime".to_string())
        );
        // Non-coprime pairs.
        assert!(
            (RnsContextRaw {
                moduli_u64: vec![2, 4]
            })
            .into_context()
            .is_err()
        );
        assert!(
            (RnsContextRaw {
                moduli_u64: vec![2, 3, 5, 30]
            })
            .into_context()
            .is_err()
        );
    }

    #[test]
    fn garner() -> Result<(), Box<dyn Error>> {
        let rns = RnsContext::new(&[4, 15, 1153])?;

        for i in 0..3 {
            let gi = rns.get_garner(i);
            assert!(gi.is_some());
            assert_eq!(gi.unwrap(), &rns.garner[i]);
        }
        assert!(rns.get_garner(3).is_none());

        Ok(())
    }

    #[test]
    fn modulus() -> Result<(), Box<dyn Error>> {
        let mut rns = RnsContext::new(&[2])?;
        debug_assert_eq!(rns.modulus(), &BigUint::from(2u64));

        rns = RnsContext::new(&[2, 5])?;
        debug_assert_eq!(rns.modulus(), &BigUint::from(2u64 * 5));

        rns = RnsContext::new(&[4, 15, 1153])?;
        debug_assert_eq!(rns.modulus(), &BigUint::from(4u64 * 15 * 1153));

        Ok(())
    }

    #[test]
    fn project_lift() -> Result<(), Box<dyn Error>> {
        let ntests = 100;
        let rns = RnsContext::new(&[4, 15, 1153])?;
        let product = 4u64 * 15 * 1153;

        let mut rests = rns.project(&BigUint::from(0u64));
        assert_eq!(&rests, &[0u64, 0, 0]);
        assert_eq!(rns.lift(ArrayView1::from(&rests))?, BigUint::from(0u64));

        rests = rns.project(&BigUint::from(4u64));
        assert_eq!(&rests, &[0u64, 4, 4]);
        assert_eq!(rns.lift(ArrayView1::from(&rests))?, BigUint::from(4u64));

        rests = rns.project(&BigUint::from(15u64));
        assert_eq!(&rests, &[3u64, 0, 15]);
        assert_eq!(rns.lift(ArrayView1::from(&rests))?, BigUint::from(15u64));

        rests = rns.project(&BigUint::from(1153u64));
        assert_eq!(&rests, &[1u64, 13, 0]);
        assert_eq!(rns.lift(ArrayView1::from(&rests))?, BigUint::from(1153u64));

        rests = rns.project(&BigUint::from(product - 1));
        assert_eq!(&rests, &[3u64, 14, 1152]);
        assert_eq!(
            rns.lift(ArrayView1::from(&rests))?,
            BigUint::from(product - 1)
        );

        let mut rng = rand::rng();

        for _ in 0..ntests {
            let b = BigUint::from(rng.next_u64() % product);
            rests = rns.project(&b);
            assert_eq!(rns.lift(ArrayView1::from(&rests))?, b);
        }

        Ok(())
    }

    proptest! {
        #[test]
        fn lift_project_round_trip(x: u64) {
            let rns = RnsContext::new(&[4, 15, 1153]).unwrap();
            let product = 4u64 * 15 * 1153;
            let a = BigUint::from(x % product);
            let rests = rns.project(&a);
            prop_assert_eq!(rns.lift(ArrayView1::from(&rests)).unwrap(), a);
        }
    }
}
