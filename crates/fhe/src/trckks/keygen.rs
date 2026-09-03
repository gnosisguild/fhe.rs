//! Multiparty key generation for threshold CKKS.
//!
//! Non-interactive public-key generation from a common random polynomial
//! (CRP), following the multiparty BFV/CKKS pattern
//! (<https://eprint.iacr.org/2020/304.pdf>, Protocol 1):
//!
//! - All parties agree on a CRP `a` (e.g. derived from a public seed).
//! - Party `i` samples its secret contribution `s_i` and publishes
//!   `p_i = -a*s_i + e_i`.
//! - The joint public key is `(sum_i p_i, a) = (-a*s + e, a)` for the joint
//!   secret `s = sum_i s_i`.

use crate::ckks::{CkksParameters, CkksPublicKey, CkksQpPoly, CkksSecretKey};
use crate::{Error, Result};
use fhe_math::rq::{Ntt, Poly, PowerBasis, traits::TryConvertFrom};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;
use zeroize::Zeroizing;

/// A common random polynomial for CKKS multiparty protocols, derived from a
/// public seed so every party can generate it independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkksCrp {
    pub(crate) poly: Poly<Ntt>,
}

impl CkksCrp {
    /// The underlying CRP polynomial (public common randomness).
    #[must_use]
    pub fn poly(&self) -> &Poly<Ntt> {
        &self.poly
    }

    /// Derive the CRP from a public 32-byte seed at level 0.
    pub fn from_seed(par: &Arc<CkksParameters>, seed: [u8; 32]) -> Result<Self> {
        let ctx = par.context_at_level(0)?;
        let poly =
            Poly::<Ntt>::random_from_seed(ctx, <ChaCha8Rng as SeedableRng>::Seed::from(seed));
        Ok(Self { poly })
    }

    /// Derive a vector of `size` CRPs from a public seed (for the relin key
    /// protocol, which needs one CRP per RNS modulus).
    pub fn vec_from_seed(
        par: &Arc<CkksParameters>,
        seed: [u8; 32],
        size: usize,
    ) -> Result<Vec<Self>> {
        Self::vec_from_seed_leveled(par, seed, size, 0)
    }

    /// Derive a vector of `size` CRPs from a public seed at the given level
    /// (for leveled relin keys: one CRP per RNS modulus REMAINING at that
    /// level — pass `size = level_moduli_len`).
    pub fn vec_from_seed_leveled(
        par: &Arc<CkksParameters>,
        seed: [u8; 32],
        size: usize,
        level: usize,
    ) -> Result<Vec<Self>> {
        let ctx = par.context_at_level(level)?;
        let mut rng = ChaCha8Rng::from_seed(seed);
        let mut crps = Vec::with_capacity(size);
        for _ in 0..size {
            let mut seed_i = <ChaCha8Rng as SeedableRng>::Seed::default();
            rand::RngCore::fill_bytes(&mut rng, &mut seed_i);
            crps.push(Self {
                poly: Poly::<Ntt>::random_from_seed(ctx, seed_i),
            });
        }
        Ok(crps)
    }

    /// Derive the `dnum` CRPs over `Q·P` for the HYBRID relinearization
    /// protocol ([`crate::trckks::CkksHybridRelinKeyGenerator`]) from a
    /// public seed. Errors when hybrid key switching is not enabled.
    pub fn vec_from_seed_qp(par: &Arc<CkksParameters>, seed: [u8; 32]) -> Result<Vec<CkksQpPoly>> {
        let dnum = par.dnum();
        if dnum == 0 {
            return Err(Error::DefaultError(
                "hybrid key switching is not enabled on these parameters".into(),
            ));
        }
        let mut rng = ChaCha8Rng::from_seed(seed);
        (0..dnum)
            .map(|_| {
                let mut seed_j = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rng, &mut seed_j);
                CkksQpPoly::random_from_seed(par, seed_j)
            })
            .collect()
    }
}

/// A party's share of the joint CKKS public key: `p_i = -a*s_i + e_i`.
#[derive(Debug, Clone, PartialEq)]
pub struct CkksPublicKeyShare {
    pub(crate) par: Arc<CkksParameters>,
    pub(crate) p0: Poly<Ntt>,
    pub(crate) crp: CkksCrp,
}

impl CkksPublicKeyShare {
    /// Create this party's public-key share from its secret contribution.
    pub fn new<R: RngCore + CryptoRng>(
        sk_share: &CkksSecretKey,
        crp: CkksCrp,
        rng: &mut R,
    ) -> Result<Self> {
        let par = sk_share.par.clone();
        let ctx = par.context_at_level(0)?;

        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_share.coeffs.as_ref(), ctx, false)?.into_ntt(),
        );
        let e =
            Zeroizing::new(Poly::<Ntt>::small(ctx, par.variance, rng).map_err(Error::MathError)?);

        let mut p0 = -&crp.poly;
        p0.disallow_variable_time_computations();
        p0 *= s.as_ref();
        p0 += e.as_ref();

        Ok(Self { par, p0, crp })
    }

    /// Reassemble a share from its components (e.g. after network transport).
    #[must_use]
    pub fn from_parts(par: Arc<CkksParameters>, p0: Poly<Ntt>, crp: CkksCrp) -> Self {
        Self { par, p0, crp }
    }

    /// Serialize this share's `p0` polynomial.
    #[must_use]
    pub fn p0_to_bytes(&self) -> Vec<u8> {
        use fhe_traits::Serialize;
        self.p0.to_bytes()
    }

    /// Aggregate public-key shares into the joint [`CkksPublicKey`].
    ///
    /// All shares must be built over the same CRP.
    pub fn aggregate(shares: &[Self]) -> Result<CkksPublicKey> {
        let first = shares.first().ok_or(Error::TooFewValues {
            actual: 0,
            minimum: 1,
        })?;
        let mut p0 = first.p0.clone();
        for sh in &shares[1..] {
            if sh.crp != first.crp {
                return Err(Error::DefaultError(
                    "public key shares built over different CRPs".to_string(),
                ));
            }
            p0 += &sh.p0;
        }
        let mut c = vec![p0, first.crp.poly.clone()];
        c.iter_mut()
            .for_each(|p| p.disallow_variable_time_computations());
        Ok(CkksPublicKey {
            par: first.par.clone(),
            c,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckks::{CkksEncoder, CkksParametersBuilder};
    use crate::trckks::TRCKKS;
    use ndarray::Array2;
    use rand::rng;
    use std::error::Error as StdError;

    #[test]
    fn multiparty_keygen_threshold_decrypt_e2e() -> std::result::Result<(), Box<dyn StdError>> {
        let mut rng = rng();
        let params = CkksParametersBuilder::new()
            .set_degree(512)
            .set_moduli_sizes(&[45, 45])
            .set_scale(2f64.powi(40))
            .build_arc()?;
        let n = 5;
        let threshold = 2;
        let trckks = TRCKKS::new(n, threshold, params.clone())?;
        let encoder = CkksEncoder::new(&params);

        // CRP from a public seed.
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let crp = CkksCrp::from_seed(&params, seed)?;

        // Each party: secret contribution + pk share + dealt Shamir shares of
        // both the secret and its smudging contribution.
        let mut pk_shares = Vec::new();
        let mut sk_share_matrices = Vec::new(); // per party: Vec<Array2> per modulus
        let mut es_share_matrices = Vec::new();
        for _ in 0..n {
            let sk_i = CkksSecretKey::random(&params, &mut rng);
            pk_shares.push(CkksPublicKeyShare::new(&sk_i, crp.clone(), &mut rng)?);

            let sk_poly = trckks.coeffs_to_poly(sk_i.coeffs.as_ref())?;
            sk_share_matrices.push(trckks.generate_secret_shares_from_poly(sk_poly, &mut rng)?);

            let es = trckks.generate_smudging_error(20, &mut rng)?;
            let es_poly = trckks.smudging_to_poly(&es)?;
            es_share_matrices.push(trckks.generate_secret_shares_from_poly(es_poly, &mut rng)?);
        }

        let pk = CkksPublicKeyShare::aggregate(&pk_shares)?;

        // Party j's collected shares: from each dealer, row j of each modulus
        // matrix, stacked as [moduli, degree].
        let collect = |matrices: &[Vec<Array2<u64>>], j: usize| -> Vec<Array2<u64>> {
            matrices
                .iter()
                .map(|dealer| {
                    let mut arr = Array2::<u64>::zeros((dealer.len(), dealer[0].ncols()));
                    for (r, m) in dealer.iter().enumerate() {
                        arr.row_mut(r).assign(&m.row(j));
                    }
                    arr
                })
                .collect()
        };

        // Encrypt under the joint key and sum homomorphically.
        let a = vec![100.5, -3.25];
        let b = vec![-0.5, 10.75];
        let ct_a = pk.try_encrypt(&encoder.encode(&a, 0)?, &mut rng)?;
        let ct_b = pk.try_encrypt(&encoder.encode(&b, 0)?, &mut rng)?;
        let ct = ct_a.try_add(&ct_b)?;

        // threshold + 1 parties decrypt.
        let parties: Vec<usize> = vec![2, 4, 5];
        let mut d_shares = Vec::new();
        for &j in &parties {
            let sk_j = trckks.aggregate_collected_shares(&collect(&sk_share_matrices, j - 1))?;
            let es_j = trckks.aggregate_collected_shares(&collect(&es_share_matrices, j - 1))?;
            d_shares.push(trckks.decryption_share(&ct, sk_j.into_ntt(), es_j)?);
        }

        let pt = trckks.decrypt(d_shares, parties, &ct)?;
        let decoded = encoder.decode(&pt)?;

        // Tolerance reflects the whole-unit gap between right and wrong
        // answers (see `DECRYPT_TOL` in the trckks tests); subset-dependent
        // Lagrange-amplified smudging noise is ~1e-5 at this scale.
        for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
            assert!(
                (decoded[i] - (x + y)).abs() < 0.5,
                "slot {i}: {} vs {}",
                decoded[i],
                x + y
            );
        }
        Ok(())
    }
}
