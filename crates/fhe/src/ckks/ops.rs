//! Homomorphic operations for the CKKS encryption scheme.
//!
//! Implemented: addition, subtraction, negation, plaintext addition and
//! multiplication, ciphertext-ciphertext multiplication (without
//! relinearization: the result has three components and remains
//! decryptable by [`crate::ckks::CkksSecretKey`], which handles higher
//! powers of `s`; relinearize with
//! [`crate::ckks::CkksRelinearizationKey`]), rescaling, and level
//! alignment ([`CkksCiphertext::mod_switch_to_level`]).
//!
//! Scale discipline: `add`/`sub` require equal scales and levels;
//! multiplication multiplies the scales; [`CkksCiphertext::rescale`] divides
//! the scale by the dropped modulus, restoring it to ~delta after each
//! multiplication when the moduli are close to delta.

use crate::ckks::{CkksCiphertext, CkksPlaintext};
use crate::{Error, Result};
use fhe_math::rq::{Ntt, Poly, PowerBasis};
use std::ops::{Add, Mul, Neg, Sub};

/// Relative tolerance for scale equality checks in add/sub.
const SCALE_RTOL: f64 = 1e-9;

fn scales_equal(a: f64, b: f64) -> bool {
    (a - b).abs() <= SCALE_RTOL * a.abs().max(b.abs())
}

fn check_add_compatible(a: &CkksCiphertext, b: &CkksCiphertext) -> Result<()> {
    if a.par != b.par {
        return Err(Error::DefaultError(
            "Incompatible CKKS parameters".to_string(),
        ));
    }
    if a.level != b.level {
        return Err(Error::InvalidLevel {
            level: b.level,
            min_level: a.level,
            max_level: a.level,
        });
    }
    if !scales_equal(a.scale, b.scale) {
        return Err(Error::InvalidCiphertext {
            reason: format!("scale mismatch: {} vs {}", a.scale, b.scale),
        });
    }
    Ok(())
}

impl CkksCiphertext {
    /// Homomorphic addition.
    pub fn try_add(&self, other: &Self) -> Result<Self> {
        check_add_compatible(self, other)?;
        let len = self.c.len().max(other.c.len());
        let ctx = self.c[0].ctx().clone();
        let mut c = Vec::with_capacity(len);
        for i in 0..len {
            let ci = match (self.c.get(i), other.c.get(i)) {
                (Some(a), Some(b)) => a + b,
                (Some(a), None) => a.clone(),
                (None, Some(b)) => b.clone(),
                (None, None) => Poly::<Ntt>::zero(&ctx),
            };
            c.push(ci);
        }
        Ok(Self {
            par: self.par.clone(),
            c,
            level: self.level,
            scale: self.scale,
        })
    }

    /// Homomorphic subtraction.
    pub fn try_sub(&self, other: &Self) -> Result<Self> {
        check_add_compatible(self, other)?;
        let len = self.c.len().max(other.c.len());
        let ctx = self.c[0].ctx().clone();
        let mut c = Vec::with_capacity(len);
        for i in 0..len {
            let ci = match (self.c.get(i), other.c.get(i)) {
                (Some(a), Some(b)) => a - b,
                (Some(a), None) => a.clone(),
                (None, Some(b)) => -b,
                (None, None) => Poly::<Ntt>::zero(&ctx),
            };
            c.push(ci);
        }
        Ok(Self {
            par: self.par.clone(),
            c,
            level: self.level,
            scale: self.scale,
        })
    }

    /// Homomorphic negation.
    #[must_use]
    pub fn neg(&self) -> Self {
        Self {
            par: self.par.clone(),
            c: self.c.iter().map(|ci| -ci).collect(),
            level: self.level,
            scale: self.scale,
        }
    }

    /// Multiply by an encoded plaintext (e.g. a public weight vector).
    ///
    /// The result's scale is `self.scale * pt.scale`; rescale afterwards to
    /// bring it back down.
    pub fn try_mul_plaintext(&self, pt: &CkksPlaintext) -> Result<Self> {
        if self.par != pt.par {
            return Err(Error::DefaultError(
                "Incompatible CKKS parameters".to_string(),
            ));
        }
        if self.level != pt.level {
            return Err(Error::InvalidLevel {
                level: pt.level,
                min_level: self.level,
                max_level: self.level,
            });
        }
        let c = self.c.iter().map(|ci| ci * &pt.poly).collect();
        Ok(Self {
            par: self.par.clone(),
            c,
            level: self.level,
            scale: self.scale * pt.scale,
        })
    }

    /// Ciphertext-ciphertext multiplication without relinearization.
    ///
    /// Both inputs must be fresh (two-component) ciphertexts at the same
    /// level. The result has three components `(d0, d1, d2)` with
    /// `d0 + d1*s + d2*s^2 ~ delta^2*m1*m2 + e`, and decrypts correctly with
    /// [`crate::ckks::CkksSecretKey::try_decrypt`]. The scale multiplies;
    /// rescale afterwards.
    pub fn try_mul(&self, other: &Self) -> Result<Self> {
        if self.par != other.par {
            return Err(Error::DefaultError(
                "Incompatible CKKS parameters".to_string(),
            ));
        }
        if self.level != other.level {
            return Err(Error::InvalidLevel {
                level: other.level,
                min_level: self.level,
                max_level: self.level,
            });
        }
        if self.c.len() != 2 || other.c.len() != 2 {
            return Err(Error::InvalidCiphertext {
                reason: "multiplication requires two-component ciphertexts; \
                         rescale/relinearize intermediate results first"
                    .to_string(),
            });
        }

        // (a0 + a1*s)(b0 + b1*s) = a0*b0 + (a0*b1 + a1*b0)*s + a1*b1*s^2
        let d0 = &self.c[0] * &other.c[0];
        let d1 = &(&self.c[0] * &other.c[1]) + &(&self.c[1] * &other.c[0]);
        let d2 = &self.c[1] * &other.c[1];

        Ok(Self {
            par: self.par.clone(),
            c: vec![d0, d1, d2],
            level: self.level,
            scale: self.scale * other.scale,
        })
    }

    /// Homomorphic plaintext addition: level AND scale must match exactly
    /// (use `CkksEncoder::encode_with_scale` to build an aligned operand).
    pub fn try_add_plaintext(&self, pt: &crate::ckks::CkksPlaintext) -> Result<Self> {
        if self.par != pt.par {
            return Err(Error::DefaultError(
                "Incompatible CKKS parameters".to_string(),
            ));
        }
        if self.level != pt.level {
            return Err(Error::InvalidLevel {
                level: pt.level,
                min_level: self.level,
                max_level: self.level,
            });
        }
        if !scales_equal(self.scale, pt.scale) {
            return Err(Error::InvalidCiphertext {
                reason: format!(
                    "plaintext-addition scale mismatch: {} vs {}",
                    self.scale, pt.scale
                ),
            });
        }
        let mut c = self.c.clone();
        c[0] = &c[0] + &pt.poly;
        Ok(Self {
            par: self.par.clone(),
            c,
            level: self.level,
            scale: self.scale,
        })
    }

    /// Modulus-switch DOWN to `level` by dropping trailing RNS limbs — no
    /// division, so the scale is UNCHANGED (contrast `rescale`). Standard
    /// CKKS level alignment for operands of a leveled multiplication.
    pub fn mod_switch_to_level(&mut self, level: usize) -> Result<()> {
        if level < self.level {
            return Err(Error::InvalidLevel {
                level,
                min_level: self.level,
                max_level: self.par.max_level(),
            });
        }
        while self.level < level {
            let ctx = self.par.context_at_level(self.level)?;
            let next_ctx = self.par.context_at_level(self.level + 1)?;
            let keep = next_ctx.moduli().len();
            debug_assert!(keep < ctx.moduli().len());
            for ci in self.c.iter_mut() {
                let pb = ci.clone().into_power_basis();
                let truncated = pb.coefficients().slice(ndarray::s![..keep, ..]).to_owned();
                let mut out = Poly::<PowerBasis>::zero(next_ctx);
                out.set_coefficients(truncated);
                *ci = out.into_ntt();
            }
            self.level += 1;
        }
        Ok(())
    }

    /// Rescale: divide by the last modulus in the chain and drop it.
    ///
    /// Reduces the level by one modulus and divides the scale by the dropped
    /// prime. Call after multiplication to control scale and noise growth.
    pub fn rescale(&mut self) -> Result<()> {
        let ctx = self.par.context_at_level(self.level)?;
        let dropped = *ctx
            .moduli()
            .last()
            .ok_or_else(|| Error::DefaultError("empty moduli chain".to_string()))?;

        for ci in self.c.iter_mut() {
            let mut pb = ci.clone().into_power_basis();
            pb.switch_down().map_err(Error::MathError)?;
            *ci = pb.into_ntt();
        }
        self.level += 1;
        self.scale /= dropped as f64;
        Ok(())
    }
}

impl Add<&CkksCiphertext> for &CkksCiphertext {
    type Output = CkksCiphertext;

    fn add(self, rhs: &CkksCiphertext) -> CkksCiphertext {
        self.try_add(rhs).unwrap()
    }
}

impl Sub<&CkksCiphertext> for &CkksCiphertext {
    type Output = CkksCiphertext;

    fn sub(self, rhs: &CkksCiphertext) -> CkksCiphertext {
        self.try_sub(rhs).unwrap()
    }
}

impl Neg for &CkksCiphertext {
    type Output = CkksCiphertext;

    fn neg(self) -> CkksCiphertext {
        self.neg()
    }
}

impl Mul<&CkksPlaintext> for &CkksCiphertext {
    type Output = CkksCiphertext;

    fn mul(self, rhs: &CkksPlaintext) -> CkksCiphertext {
        self.try_mul_plaintext(rhs).unwrap()
    }
}

impl Mul<&CkksCiphertext> for &CkksCiphertext {
    type Output = CkksCiphertext;

    fn mul(self, rhs: &CkksCiphertext) -> CkksCiphertext {
        self.try_mul(rhs).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::ckks::{
        CkksEncoder, CkksParameters, CkksParametersBuilder, CkksPublicKey, CkksSecretKey,
    };
    use rand::rng;
    use std::error::Error;
    use std::sync::Arc;

    fn setup() -> (
        Arc<CkksParameters>,
        CkksEncoder,
        CkksSecretKey,
        CkksPublicKey,
    ) {
        let mut rng = rng();
        let params = CkksParametersBuilder::new()
            .set_degree(64)
            .set_moduli_sizes(&[50, 30, 30])
            .set_scale(2f64.powi(26))
            .build_arc()
            .unwrap();
        let encoder = CkksEncoder::new(&params);
        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng).unwrap();
        (params, encoder, sk, pk)
    }

    #[test]
    fn homomorphic_addition() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let (_params, encoder, sk, pk) = setup();

        let a = vec![1.5, -2.0, 3.25];
        let b = vec![0.5, 4.0, -1.25];

        let ct_a = pk.try_encrypt(&encoder.encode(&a, 0)?, &mut rng)?;
        let ct_b = pk.try_encrypt(&encoder.encode(&b, 0)?, &mut rng)?;

        let ct_sum = ct_a.try_add(&ct_b)?;
        let decoded = encoder.decode(&sk.try_decrypt(&ct_sum)?)?;

        for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
            assert!((decoded[i] - (x + y)).abs() < 1e-2, "slot {i}");
        }
        Ok(())
    }

    #[test]
    fn homomorphic_subtraction_and_negation() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let (_params, encoder, sk, pk) = setup();

        let a = vec![10.0, 5.5];
        let b = vec![3.0, 8.25];

        let ct_a = pk.try_encrypt(&encoder.encode(&a, 0)?, &mut rng)?;
        let ct_b = pk.try_encrypt(&encoder.encode(&b, 0)?, &mut rng)?;

        let diff = encoder.decode(&sk.try_decrypt(&ct_a.try_sub(&ct_b)?)?)?;
        assert!((diff[0] - 7.0).abs() < 1e-2);
        assert!((diff[1] + 2.75).abs() < 1e-2);

        let neg = encoder.decode(&sk.try_decrypt(&ct_a.neg())?)?;
        assert!((neg[0] + 10.0).abs() < 1e-2);
        Ok(())
    }

    #[test]
    fn plaintext_multiplication_with_rescale() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let (_params, encoder, sk, pk) = setup();

        let data = vec![2.0, -3.0, 0.5];
        let weights = vec![1.5, 2.0, 4.0];

        let ct = pk.try_encrypt(&encoder.encode(&data, 0)?, &mut rng)?;
        let w_pt = encoder.encode(&weights, 0)?;

        let mut product = ct.try_mul_plaintext(&w_pt)?;
        product.rescale()?;

        let decoded = encoder.decode(&sk.try_decrypt(&product)?)?;
        for (i, (d, w)) in data.iter().zip(weights.iter()).enumerate() {
            assert!(
                (decoded[i] - d * w).abs() < 1e-1,
                "slot {i}: {} vs {}",
                decoded[i],
                d * w
            );
        }
        Ok(())
    }

    #[test]
    fn ciphertext_multiplication_with_rescale() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let (_params, encoder, sk, pk) = setup();

        let a = vec![3.0, -2.0];
        let b = vec![4.0, 5.0];

        let ct_a = pk.try_encrypt(&encoder.encode(&a, 0)?, &mut rng)?;
        let ct_b = pk.try_encrypt(&encoder.encode(&b, 0)?, &mut rng)?;

        let mut product = ct_a.try_mul(&ct_b)?;
        assert_eq!(product.len(), 3);
        product.rescale()?;

        let decoded = encoder.decode(&sk.try_decrypt(&product)?)?;
        assert!((decoded[0] - 12.0).abs() < 1e-1, "got {}", decoded[0]);
        assert!((decoded[1] + 10.0).abs() < 1e-1, "got {}", decoded[1]);
        Ok(())
    }

    #[test]
    fn squared_values_for_variance() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let (_params, encoder, sk, pk) = setup();

        // Statistics building block: E[x^2] via self-multiplication.
        let x = vec![1.0, 2.0, 3.0, 4.0];
        let ct = pk.try_encrypt(&encoder.encode(&x, 0)?, &mut rng)?;

        let mut sq = ct.try_mul(&ct)?;
        sq.rescale()?;

        let decoded = encoder.decode(&sk.try_decrypt(&sq)?)?;
        for (i, xi) in x.iter().enumerate() {
            assert!(
                (decoded[i] - xi * xi).abs() < 1e-1,
                "slot {i}: {} vs {}",
                decoded[i],
                xi * xi
            );
        }
        Ok(())
    }

    #[test]
    fn plaintext_addition_and_mod_switch() -> std::result::Result<(), Box<dyn Error>> {
        let params = CkksParametersBuilder::new()
            .set_degree(32)
            .set_moduli_sizes(&[50, 40, 40])
            .set_scale(2f64.powi(30))
            .build_arc()?;
        let mut rng = rand::rng();
        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng)?;
        let encoder = CkksEncoder::new(&params);

        let values = vec![1.5f64, -2.25, 3.0];
        let ct = pk.try_encrypt(&encoder.encode(&values, 0)?, &mut rng)?;

        // try_add_plaintext: ct + pt at matching scale/level.
        let pt = encoder.encode(&[0.5f64, 0.25, -1.0], 0)?;
        let sum = ct.try_add_plaintext(&pt)?;
        let decoded = encoder.decode(&sk.try_decrypt(&sum)?)?;
        assert!((decoded[0] - 2.0).abs() < 1e-2);
        assert!((decoded[1] + 2.0).abs() < 1e-2);
        assert!((decoded[2] - 2.0).abs() < 1e-2);

        // scale mismatch rejected.
        let bad = encoder.encode_with_scale(&[1.0f64], 0, 2f64.powi(20))?;
        assert!(ct.try_add_plaintext(&bad).is_err());

        // mod_switch_to_level: drop to level 1, scale unchanged, still decrypts.
        let mut switched = ct.clone();
        switched.mod_switch_to_level(1)?;
        assert_eq!(switched.level, 1);
        assert!((switched.scale - ct.scale).abs() < f64::EPSILON);
        let decoded = encoder.decode(&sk.try_decrypt(&switched)?)?;
        assert!((decoded[0] - 1.5).abs() < 1e-2, "got {}", decoded[0]);

        // switching UP is rejected.
        let mut up = switched.clone();
        assert!(up.mod_switch_to_level(0).is_err());
        Ok(())
    }

    #[test]
    fn scale_mismatch_rejected() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let (_params, encoder, _sk, pk) = setup();

        let ct_a = pk.try_encrypt(&encoder.encode(&[1.0], 0)?, &mut rng)?;
        let ct_b = pk.try_encrypt(&encoder.encode(&[2.0], 0)?, &mut rng)?;

        let product = ct_a.try_mul(&ct_b)?; // scale is now delta^2
        assert!(product.try_add(&ct_a).is_err());
        Ok(())
    }

    #[test]
    fn triple_product_rejected_without_relinearization() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let (_params, encoder, _sk, pk) = setup();

        let ct = pk.try_encrypt(&encoder.encode(&[2.0], 0)?, &mut rng)?;
        let sq = ct.try_mul(&ct)?;
        // Three-component ciphertext cannot multiply again.
        assert!(sq.try_mul(&ct).is_err());
        Ok(())
    }
}
