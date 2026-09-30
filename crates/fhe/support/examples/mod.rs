//! Shared simulation support for tests, examples, and benchmarks.

#![allow(dead_code, clippy::expect_used)]

pub mod trbfv;
pub mod util;

use fhe::trbfv::{PRF_KEY_LEN, PartyPrfKeyTransport, PartyPrfKeys};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Create internally consistent PRF key bundles for local examples and tests.
///
/// This helper centralizes all key material in one process; it does not implement
/// or simulate a secure setup protocol. It is only repository support. Applications
/// must establish matching pairwise keys in their protocol and construct each
/// party's transport bundle themselves.
pub fn simulated_committee_prf_keys<R: RngCore + CryptoRng>(
    committee_size: usize,
    rng: &mut R,
) -> Vec<PartyPrfKeys> {
    assert!(committee_size > 0, "committee size must be nonzero");
    let matrix_len = committee_size
        .checked_mul(committee_size)
        .expect("committee PRF matrix size must fit in memory");
    let mut matrix = Zeroizing::new(vec![[0u8; PRF_KEY_LEN]; matrix_len]);
    for key in matrix.iter_mut() {
        rng.fill_bytes(key);
    }

    let rows: Vec<_> = matrix.chunks_exact(committee_size).collect();
    (0..committee_size)
        .map(|party_index| {
            let mut keys_i_j = Zeroizing::new(Vec::with_capacity(committee_size));
            let mut keys_j_i = Zeroizing::new(Vec::with_capacity(committee_size));
            let party_row = rows
                .get(party_index)
                .expect("committee matrix has one row per party");

            for peer_index in 0..committee_size {
                let peer_row = rows
                    .get(peer_index)
                    .expect("committee matrix has one row per party");
                keys_i_j.push(*party_row.get(peer_index).expect("matrix row has n keys"));
                keys_j_i.push(*peer_row.get(party_index).expect("matrix row has n keys"));
            }

            let transport = PartyPrfKeyTransport::new(
                party_index + 1,
                committee_size,
                std::mem::take(&mut *keys_i_j),
                std::mem::take(&mut *keys_j_i),
            )
            .expect("simulated party bundles have valid dimensions");
            PartyPrfKeys::from_transport(transport)
                .expect("simulated party bundles have valid metadata")
        })
        .collect()
}
