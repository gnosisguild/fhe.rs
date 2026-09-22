//! Committee PRF keys and masks for synchronous threshold decryption.
//!
//! This is the masking layer from Colin de Verdière–Passelègue–Stehlé 2026
//! (eprint 2026/031). Each party `i` holds `2n` keys `(k_{i,j}, k_{j,i})_j`
//! and, for a designated decryptor set `S` and ciphertext `ct`, the mask
//!
//! `r_i^{S,ct} = Σ_{j∈S} (F_{k_{i,j}}(S, ct) − F_{k_{j,i}}(S, ct))`.
//!
//! The masks cancel when summed over `S`. Keys are uniformly random 256-bit
//! strings. `F` is a ChaCha8 expander that stands in for Poseidon with the
//! SAFE API; only [`evaluate`] needs to be replaced when that library is
//! wired in.

use crate::Error;
use crate::bfv::Ciphertext;
use fhe_math::rq::{Poly, PowerBasis};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::fmt;
use zeroize_derive::{Zeroize, ZeroizeOnDrop};

const KEY_LEN: usize = 32;

/// A 256-bit PRF key. Randomly generated; Poseidon will consume the same
/// layout.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrfKey([u8; KEY_LEN]);

impl fmt::Debug for PrfKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PrfKey").finish_non_exhaustive()
    }
}

/// The `2n` PRF keys held by one party: outgoing `k_{i,j}` and incoming
/// `k_{j,i}` for every `j ∈ [n]`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PartyPrfKeys {
    party_id: usize,
    party_count: usize,
    outgoing: Vec<PrfKey>,
    incoming: Vec<PrfKey>,
}

impl fmt::Debug for PartyPrfKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PartyPrfKeys")
            .field("party_id", &self.party_id)
            .field("party_count", &self.party_count)
            .finish_non_exhaustive()
    }
}

impl PartyPrfKeys {
    /// Sample the committee `n × n` key matrix and give each party its `2n`
    /// keys.
    ///
    /// Party indices are 1-based, matching Shamir evaluation points.
    pub fn generate_committee<R: RngCore + CryptoRng>(
        party_count: usize,
        rng: &mut R,
    ) -> Result<Vec<Self>, Error> {
        if party_count == 0 {
            return Err(Error::invalid_party_count(0, 1));
        }

        let matrix_len = party_count
            .checked_mul(party_count)
            .ok_or_else(|| Error::invalid_party_count(party_count, 1))?;
        let mut keys = vec![PrfKey([0u8; KEY_LEN]); matrix_len];
        for key in &mut keys {
            rng.fill_bytes(&mut key.0);
        }

        (0..party_count)
            .map(|party_index| {
                let mut outgoing = Vec::with_capacity(party_count);
                let mut incoming = Vec::with_capacity(party_count);
                for other in 0..party_count {
                    let outgoing_index = party_index
                        .checked_mul(party_count)
                        .and_then(|offset| offset.checked_add(other))
                        .ok_or_else(|| Error::invalid_party_count(party_count, 1))?;
                    let incoming_index = other
                        .checked_mul(party_count)
                        .and_then(|offset| offset.checked_add(party_index))
                        .ok_or_else(|| Error::invalid_party_count(party_count, 1))?;
                    outgoing.push(
                        keys.get(outgoing_index)
                            .ok_or_else(|| Error::invalid_party_count(party_count, 1))?
                            .clone(),
                    );
                    incoming.push(
                        keys.get(incoming_index)
                            .ok_or_else(|| Error::invalid_party_count(party_count, 1))?
                            .clone(),
                    );
                }
                Ok(Self {
                    party_id: party_index + 1,
                    party_count,
                    outgoing,
                    incoming,
                })
            })
            .collect()
    }

    /// 1-based identity of the party that holds these keys.
    #[must_use]
    pub fn party_id(&self) -> usize {
        self.party_id
    }

    /// Number of parties in the committee that sampled these keys.
    #[must_use]
    pub fn party_count(&self) -> usize {
        self.party_count
    }

    /// Evaluate `r_i^{S,ct}` for this party and decryptor set `S`.
    pub fn mask(
        &self,
        decryptors: &[usize],
        ciphertext: &Ciphertext,
    ) -> Result<Poly<PowerBasis>, Error> {
        let decryptors = canonical_decryptors(decryptors);
        for &party_id in &decryptors {
            if party_id == 0 || party_id > self.party_count {
                return Err(Error::invalid_party_id(party_id, self.party_count));
            }
        }

        let ctx = ciphertext.params.context_at_level(ciphertext.level)?;
        let mut acc = Poly::<PowerBasis>::zero(ctx);
        acc.disallow_variable_time_computations();
        for &other in &decryptors {
            let key_index = other - 1;
            let outgoing = self
                .outgoing
                .get(key_index)
                .ok_or_else(|| Error::invalid_party_id(other, self.party_count))?;
            let incoming = self
                .incoming
                .get(key_index)
                .ok_or_else(|| Error::invalid_party_id(other, self.party_count))?;
            let positive = evaluate(outgoing, &decryptors, ciphertext)?;
            let negative = evaluate(incoming, &decryptors, ciphertext)?;
            acc += &positive;
            acc -= &negative;
        }
        Ok(acc)
    }
}

/// Canonicalize `S` so every party evaluates `F_k` on the same domain.
fn canonical_decryptors(decryptors: &[usize]) -> Vec<usize> {
    let mut decryptors = decryptors.to_vec();
    decryptors.sort_unstable();
    decryptors.dedup();
    decryptors
}

/// Poseidon stand-in: ChaCha8 expansion of `(S, ct)` under `key`.
///
/// Replace this function when the Poseidon SAFE API is available. The domain
/// is the designated decryptor set and the ciphertext, and the range is `R_q`.
fn evaluate(
    key: &PrfKey,
    decryptors: &[usize],
    ciphertext: &Ciphertext,
) -> Result<Poly<PowerBasis>, Error> {
    let ctx = ciphertext.params.context_at_level(ciphertext.level)?;
    let moduli = ctx.moduli_operators();
    let degree = ctx.degree;
    let coefficient_count = moduli
        .len()
        .checked_mul(degree)
        .ok_or_else(|| Error::malformed_shares(0, "PRF output dimensions overflow".to_string()))?;

    let input = serialize_prf_input(decryptors, ciphertext);
    let expanded = chacha_expand(&key.0, &input, coefficient_count.saturating_mul(8));

    let mut coefficients = ndarray::Array2::zeros((moduli.len(), degree));
    for (row_index, modulus) in moduli.iter().enumerate() {
        for column_index in 0..degree {
            let offset = (row_index * degree + column_index).saturating_mul(8);
            let mut limb = [0u8; 8];
            let src = expanded
                .get(offset..offset.saturating_add(8))
                .ok_or_else(|| {
                    Error::malformed_shares(0, "PRF expander produced a short stream".to_string())
                })?;
            limb.copy_from_slice(src);
            let coefficient = coefficients
                .get_mut((row_index, column_index))
                .ok_or_else(|| {
                    Error::malformed_shares(0, "PRF output index out of range".to_string())
                })?;
            *coefficient = modulus.reduce(u64::from_le_bytes(limb));
        }
    }

    let mut poly = Poly::<PowerBasis>::zero(ctx);
    poly.set_coefficients(coefficients);
    poly.disallow_variable_time_computations();
    Ok(poly)
}

fn serialize_prf_input(decryptors: &[usize], ciphertext: &Ciphertext) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&(decryptors.len() as u64).to_le_bytes());
    for &party_id in decryptors {
        input.extend_from_slice(&(party_id as u64).to_le_bytes());
    }
    input.extend_from_slice(&(ciphertext.level as u64).to_le_bytes());
    input.extend_from_slice(&(ciphertext.c.len() as u64).to_le_bytes());
    for poly in &ciphertext.c {
        let coefficients = poly.coefficients();
        input.extend_from_slice(&(coefficients.nrows() as u64).to_le_bytes());
        input.extend_from_slice(&(coefficients.ncols() as u64).to_le_bytes());
        for &value in coefficients.iter() {
            input.extend_from_slice(&value.to_le_bytes());
        }
    }
    input
}

fn chacha_expand(key: &[u8; KEY_LEN], input: &[u8], out_len: usize) -> Vec<u8> {
    let mut state = *key;
    for chunk in input.chunks(KEY_LEN) {
        let mut rng = ChaCha8Rng::from_seed(state);
        let mut keystream = [0u8; KEY_LEN];
        rng.fill_bytes(&mut keystream);
        state = [0u8; KEY_LEN];
        for (index, slot) in state.iter_mut().enumerate() {
            let data = chunk.get(index).copied().unwrap_or(0);
            let key_byte = keystream.get(index).copied().unwrap_or(0);
            *slot = key_byte ^ data;
        }
    }
    let mut rng = ChaCha8Rng::from_seed(state);
    let mut out = vec![0u8; out_len];
    rng.fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::bfv::{Encoding, Plaintext, PublicKey, SecretKey};
    use crate::support::insecure;
    use fhe_traits::{FheEncoder, FheEncrypter};
    use rand::rng;

    #[test]
    fn generate_committee_rejects_zero_parties() {
        let mut rng = rng();
        assert!(PartyPrfKeys::generate_committee(0, &mut rng).is_err());
    }

    #[test]
    fn committee_keys_match_across_parties() {
        let mut rng = rng();
        let keys = PartyPrfKeys::generate_committee(3, &mut rng).unwrap();
        assert_eq!(keys.len(), 3);
        for (index, party) in keys.iter().enumerate() {
            assert_eq!(party.party_id(), index + 1);
            assert_eq!(party.party_count(), 3);
        }
        // k_{1,2} held by party 1 as outgoing[1] equals party 2 incoming[0].
        assert_eq!(keys[0].outgoing[1].0, keys[1].incoming[0].0);
        assert_eq!(keys[0].incoming[1].0, keys[1].outgoing[0].0);
    }

    #[test]
    fn masks_sum_to_zero_over_the_decryptor_set() {
        let mut rng = rng();
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        let pt = Plaintext::try_encode(&[7u64], Encoding::poly(), &params).unwrap();
        let ct = pk.try_encrypt(&pt, &mut rng).unwrap();

        let keys = PartyPrfKeys::generate_committee(3, &mut rng).unwrap();
        let decryptors = [1usize, 3];
        let mut acc = keys[0].mask(&decryptors, &ct).unwrap();
        acc += &keys[2].mask(&decryptors, &ct).unwrap();

        assert!(
            acc.coefficients().iter().all(|&value| value == 0),
            "PRF masks must cancel when summed over S"
        );
    }
}
