//! Local simulation support, not a distributed key-establishment protocol.

#![allow(clippy::indexing_slicing)]

use fhe::bfv::SecretKey;
use fhe::trbfv::ShareManager;
use fhe::trbfv::synchronized::{PRF_KEY_LEN, PartyPrfKeyTransport, PartyPrfKeys};
use fhe_math::rq::{Ntt, Poly};
use ndarray::Array2;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

pub fn simulated_committee_prf_keys<R: RngCore + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> Result<Vec<PartyPrfKeys>, fhe::Error> {
    let len = n
        .checked_mul(n)
        .ok_or_else(|| fhe::Error::malformed_shares(0, "committee matrix too large".to_string()))?;
    let mut matrix = Zeroizing::new(vec![[0u8; PRF_KEY_LEN]; len]);
    for key in matrix.iter_mut() {
        rng.fill_bytes(key);
    }
    (0..n)
        .map(|i| {
            PartyPrfKeys::from_transport(PartyPrfKeyTransport::new(
                i + 1,
                n,
                (0..n).map(|j| matrix[i * n + j]).collect(),
                (0..n).map(|j| matrix[j * n + i]).collect(),
            )?)
        })
        .collect()
}

/// Use the unchanged main API to deal one key and assemble its recipient shares.
pub fn share_key<R: RngCore + CryptoRng>(
    manager: &mut ShareManager,
    key: &SecretKey,
    rng: &mut R,
) -> Result<Vec<Zeroizing<Poly<Ntt>>>, fhe::Error> {
    let poly = manager.coeffs_to_poly_level0(key.coeffs.as_ref())?;
    let mut dealt = manager.generate_secret_shares_from_poly(poly, rng)?;
    let shares = (0..manager.n)
        .map(|party| {
            let mut matrix = Array2::from_shape_fn(
                (manager.params.moduli().len(), manager.params.degree()),
                |(row, column)| dealt[row][[party, column]],
            );
            let result = manager.aggregate_collected_shares(std::slice::from_ref(&matrix));
            matrix.iter_mut().for_each(Zeroize::zeroize);
            result.map(|poly| Zeroizing::new(poly.into_ntt()))
        })
        .collect();
    for matrix in &mut dealt {
        matrix.iter_mut().for_each(Zeroize::zeroize);
    }
    shares
}
