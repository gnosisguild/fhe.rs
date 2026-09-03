//! Relinearization key for the CKKS encryption scheme.
//!
//! After a ciphertext-ciphertext multiplication, the result has three
//! components `(d0, d1, d2)` decrypting via `d0 + d1*s + d2*s^2`. The
//! relinearization key switches the `d2*s^2` term back to the `(c0, c1)`
//! basis, restoring a two-component ciphertext. Uses the same RNS
//! decomposition key-switching technique as the BFV implementation
//! (HPS optimization, <https://eprint.iacr.org/2018/117>).
//!
//! Keys are LEVELED: a key generated at level `l` (context with the first
//! `L - l` RNS limbs) only relinearizes ciphertexts at that level, so a
//! circuit of multiplicative depth `d` needs one key per level at which a
//! multiplication happens. The multiparty variant of this key is produced
//! by [`crate::trckks::CkksRelinKeyGenerator`].

use crate::ckks::wire::{decode_leveled_polys, encode_leveled_polys};
use crate::ckks::{CkksCiphertext, CkksParameters, CkksSecretKey};
use crate::{Error, Result};
use fhe_math::{
    rns::RnsContext,
    rq::{Context, Ntt, NttShoup, Poly, PowerBasis, traits::TryConvertFrom},
};
use itertools::izip;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Relinearization key for CKKS: a key-switching key from `s^2` to `s`.
///
/// Noise note: the RNS-decomposition key switch adds noise on the order of
/// `q_max * N * B_err` (and roughly `n` times that for an `n`-party key
/// from the multiparty protocol), which must remain well below the
/// ciphertext scale times the desired precision after the following
/// rescale. Rule of thumb: with ~45-bit limbs use a scale of `2^40`; with
/// 36-bit limbs `2^26..2^30` (single-key) or `2^30` (multiparty). The
/// special-modulus raise-and-divide variant would lift this restriction
/// and is a natural follow-up.
#[derive(Debug, Clone)]
pub struct CkksRelinearizationKey {
    par: Arc<CkksParameters>,
    /// Key-switching elements `c0[i] = -a_i*s + e_i + g_i*s^2`.
    c0: Box<[Poly<NttShoup>]>,
    /// Key-switching elements `c1[i] = a_i`.
    c1: Box<[Poly<NttShoup>]>,
    /// Level this key was generated at.
    level: usize,
    /// Context the key was generated at.
    ctx: Arc<Context>,
}

impl CkksRelinearizationKey {
    /// Assemble a relinearization key directly from key-switching elements
    /// (used by the multiparty generation protocol in [`crate::trckks`]).
    pub(crate) fn from_parts(
        par: Arc<CkksParameters>,
        c0: Vec<Poly<NttShoup>>,
        c1: Vec<Poly<NttShoup>>,
        level: usize,
        ctx: Arc<Context>,
    ) -> Self {
        Self {
            par,
            c0: c0.into_boxed_slice(),
            c1: c1.into_boxed_slice(),
            level,
            ctx,
        }
    }

    /// Generate a relinearization key for `sk` at level 0.
    pub fn new<R: RngCore + CryptoRng>(sk: &CkksSecretKey, rng: &mut R) -> Result<Self> {
        Self::new_leveled(sk, 0, rng)
    }

    /// Generate a relinearization key for `sk` at the given level.
    ///
    /// A relinearization only applies to ciphertexts at the key's level, so
    /// deeper circuits need one key per level where a multiplication occurs.
    pub fn new_leveled<R: RngCore + CryptoRng>(
        sk: &CkksSecretKey,
        level: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let par = sk.par.clone();
        let ctx = par.context_at_level(level)?.clone();

        // s and s^2 in NTT representation.
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk.coeffs.as_ref(), &ctx, false)?.into_ntt(),
        );
        let s2 = Zeroizing::new(s.as_ref() * s.as_ref());

        let size = ctx.moduli().len();
        let rns = RnsContext::new(ctx.moduli())?;

        // c1[i] = a_i uniformly random.
        let mut c1 = Vec::with_capacity(size);
        let mut seed_rng = {
            let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
            rng.fill(&mut seed);
            ChaCha8Rng::from_seed(seed)
        };
        for _ in 0..size {
            let mut seed_i = <ChaCha8Rng as SeedableRng>::Seed::default();
            seed_rng.fill(&mut seed_i);
            let mut a = Poly::<NttShoup>::random_from_seed(&ctx, seed_i);
            unsafe { a.allow_variable_time_computations() }
            c1.push(a);
        }

        // c0[i] = -a_i*s + e_i + g_i*s^2 where g_i is the i-th garner constant.
        let s2_pb = Zeroizing::new(s2.as_ref().clone().into_power_basis());
        let c0 = c1
            .iter()
            .enumerate()
            .map(|(i, c1i)| {
                let mut a_s = Zeroizing::new(c1i.clone().into_ntt());
                a_s.disallow_variable_time_computations();
                *a_s.as_mut() *= s.as_ref();
                let actx = a_s.ctx().clone();
                let a_s_inner = std::mem::replace(a_s.as_mut(), Poly::<Ntt>::zero(&actx));
                let a_s_pb = a_s_inner.into_power_basis();

                let mut b = Poly::<PowerBasis>::small(a_s_pb.ctx(), par.variance, rng)
                    .map_err(Error::MathError)?;
                b -= &a_s_pb;

                let gi = rns.get_garner(i).unwrap();
                let g_i_s2 = Zeroizing::new(gi * s2_pb.as_ref());
                b += &g_i_s2;

                unsafe { b.allow_variable_time_computations() }
                Ok(b.into_ntt_shoup())
            })
            .collect::<Result<Vec<Poly<NttShoup>>>>()?;

        Ok(Self {
            par,
            c0: c0.into_boxed_slice(),
            c1: c1.into_boxed_slice(),
            level,
            ctx,
        })
    }

    /// Relinearize a three-component ciphertext in place, reducing it to two
    /// components.
    ///
    /// Requires the ciphertext to be at the key's level (see
    /// [`Self::level`]) with exactly three components.
    pub fn relinearizes(&self, ct: &mut CkksCiphertext) -> Result<()> {
        if ct.c.len() != 3 {
            return Err(Error::InvalidCiphertext {
                reason: format!("relinearization expects 3 components, got {}", ct.c.len()),
            });
        }
        if ct.c[0].ctx() != &self.ctx {
            return Err(Error::InvalidLevel {
                level: ct.level,
                min_level: self.level,
                max_level: self.level,
            });
        }

        let d2 = ct.c[2].clone().into_power_basis();

        let mut k0 = Poly::<Ntt>::zero(&self.ctx);
        let mut k1 = Poly::<Ntt>::zero(&self.ctx);
        let d2_coefficients = d2.coefficients();
        for (d2_i_coefficients, c0_i, c1_i) in
            izip!(d2_coefficients.outer_iter(), self.c0.iter(), self.c1.iter())
        {
            let mut d2_i = unsafe {
                Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                    d2_i_coefficients.as_slice().unwrap(),
                    &self.ctx,
                )
            };
            k0 += &(&d2_i * c0_i);
            d2_i *= c1_i;
            k1 += &d2_i;
        }

        ct.c[0] += &k0;
        ct.c[1] += &k1;
        ct.c.truncate(2);
        Ok(())
    }

    /// Returns the parameters of this key.
    #[must_use]
    pub fn parameters(&self) -> &Arc<CkksParameters> {
        &self.par
    }

    /// The level this key relinearizes at.
    #[must_use]
    pub fn level(&self) -> usize {
        self.level
    }

    /// Serialize the key: level, then the c0/c1 key-switching polynomials,
    /// length-prefixed.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_leveled_polys(self.level, &self.c0, &self.c1)
    }

    /// Deserialize a key produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8], par: &Arc<CkksParameters>) -> Result<Self> {
        let d = decode_leveled_polys::<NttShoup>(bytes, par, "relin key")?;
        Ok(Self {
            par: par.clone(),
            c0: d.first.into_boxed_slice(),
            c1: d.second.into_boxed_slice(),
            level: d.level,
            ctx: d.ctx,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::CkksRelinearizationKey;
    use crate::ckks::{CkksEncoder, CkksParametersBuilder, CkksPublicKey, CkksSecretKey};
    use rand::rng;
    use std::error::Error;

    #[test]
    fn relinearized_product_decrypts() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        // Uniform 36-bit moduli: RNS-decomposition key-switch noise is
        // ~ N*q_max*B_err ~ 2^48, well below the message scale delta^2 = 2^52.
        let params = CkksParametersBuilder::new()
            .set_degree(64)
            .set_moduli_sizes(&[36, 36, 36])
            .set_scale(2f64.powi(26))
            .build_arc()?;
        let encoder = CkksEncoder::new(&params);
        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng)?;
        let rk = CkksRelinearizationKey::new(&sk, &mut rng)?;

        let a = vec![3.0, -2.0, 0.5];
        let b = vec![4.0, 5.0, -8.0];

        let ct_a = pk.try_encrypt(&encoder.encode(&a, 0)?, &mut rng)?;
        let ct_b = pk.try_encrypt(&encoder.encode(&b, 0)?, &mut rng)?;

        let mut product = ct_a.try_mul(&ct_b)?;
        assert_eq!(product.len(), 3);
        rk.relinearizes(&mut product)?;
        assert_eq!(product.len(), 2);
        product.rescale()?;

        let decoded = encoder.decode(&sk.try_decrypt(&product)?)?;
        for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
            assert!(
                (decoded[i] - x * y).abs() < 1e-1,
                "slot {i}: {} vs {}",
                decoded[i],
                x * y
            );
        }
        Ok(())
    }

    #[test]
    fn relinearized_ciphertext_can_multiply_again() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        // Four 36-bit moduli give Q ~ 2^144: room for scale delta^4 = 2^104
        // when squaring twice at level 0 before rescaling.
        let params = CkksParametersBuilder::new()
            .set_degree(64)
            .set_moduli_sizes(&[36, 36, 36, 36])
            .set_scale(2f64.powi(26))
            .build_arc()?;
        let encoder = CkksEncoder::new(&params);
        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng)?;
        let rk = CkksRelinearizationKey::new(&sk, &mut rng)?;

        // x^4 via two squarings at level 0 (the carried scale tracks
        // delta^4), then rescale twice.
        let x = vec![1.5, 0.8];
        let ct = pk.try_encrypt(&encoder.encode(&x, 0)?, &mut rng)?;

        let mut sq = ct.try_mul(&ct)?;
        rk.relinearizes(&mut sq)?;
        assert_eq!(sq.len(), 2);

        let mut sq2 = sq.try_mul(&sq)?;
        rk.relinearizes(&mut sq2)?;
        sq2.rescale()?;
        sq2.rescale()?;

        let decoded = encoder.decode(&sk.try_decrypt(&sq2)?)?;
        for (i, xi) in x.iter().enumerate() {
            let expected = xi.powi(4);
            assert!(
                (decoded[i] - expected).abs() < 0.5,
                "slot {i}: {} vs {expected}",
                decoded[i],
            );
        }
        Ok(())
    }

    /// Single-key leveled relinearization: a level-1 key is rejected at
    /// level 0 and accepted after a rescale; the key survives the wire.
    #[test]
    fn leveled_key_matches_only_its_level() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = CkksParametersBuilder::new()
            .set_degree(64)
            .set_moduli_sizes(&[45, 45, 45])
            .set_scale(2f64.powi(40))
            .build_arc()?;
        let encoder = CkksEncoder::new(&params);
        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng)?;
        let rk1 = CkksRelinearizationKey::new_leveled(&sk, 1, &mut rng)?;
        let rk1 = CkksRelinearizationKey::from_bytes(&rk1.to_bytes(), &params)?;
        assert_eq!(rk1.level(), 1);

        let x = vec![1.5, -2.0];
        let mut ct = pk.try_encrypt(&encoder.encode(&x, 0)?, &mut rng)?;
        let mut sq0 = ct.try_mul(&ct)?;
        assert!(
            rk1.relinearizes(&mut sq0).is_err(),
            "level-1 key at level 0"
        );

        ct.mod_switch_to_level(1)?;
        let mut sq1 = ct.try_mul(&ct)?;
        rk1.relinearizes(&mut sq1)?;
        sq1.rescale()?;
        let decoded = encoder.decode(&sk.try_decrypt(&sq1)?)?;
        for (i, xi) in x.iter().enumerate() {
            assert!(
                (decoded[i] - xi * xi).abs() < 0.1,
                "slot {i}: {}",
                decoded[i]
            );
        }
        Ok(())
    }
}
