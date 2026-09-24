//! Committee PRF keys and masks for synchronous threshold decryption.
//!
//! This is the masking layer from Colin de Verdière–Passelègue–Stehlé 2026
//! (eprint 2026/031). Each party `i` holds `2n` keys `(k_{i,j}, k_{j,i})_j`
//! and, for a designated decryptor set `S` and ciphertext `ct`, the mask
//!
//! `r_i^{S,ct} = Σ_{j∈S} (F_{k_{i,j}}(S, ct) − F_{k_{j,i}}(S, ct))`.
//!
//! The masks cancel when summed over `S`. Keys are uniformly random 256-bit
//! strings, interpreted as BN254 scalar-field elements. `F` is Poseidon2
//! via the SAFE sponge API (`e3-safe`).

use crate::Error;
use crate::bfv::Ciphertext;
use ark_ff::PrimeField;
use e3_safe::{ABSORB_FLAG, Field, SQUEEZE_FLAG, SafeSponge};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_math::zq::Modulus;
use rand::{CryptoRng, RngCore};
use std::fmt;
use zeroize_derive::{Zeroize, ZeroizeOnDrop};

const KEY_LEN: usize = 32;
const SAFE_LENGTH_MASK: u32 = 0x7FFF_FFFF;
const DOMAIN_SEPARATOR_LABEL: &[u8] = b"fhe.rs/trbfv/prf/poseidon2";

/// A 256-bit PRF key. Sampled uniformly at random and mapped into the
/// Poseidon2 field inside [`evaluate`].
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

fn domain_separator() -> [u8; 64] {
    let mut domain = [0u8; 64];
    if let Some(prefix) = domain.get_mut(..DOMAIN_SEPARATOR_LABEL.len()) {
        prefix.copy_from_slice(DOMAIN_SEPARATOR_LABEL);
    }
    domain
}

fn encode_length(length: usize, what: &str) -> Result<u32, Error> {
    u32::try_from(length)
        .ok()
        .filter(|&encoded| encoded <= SAFE_LENGTH_MASK)
        .ok_or_else(|| {
            Error::malformed_shares(0, format!("PRF {what} length does not fit in SAFE IO word"))
        })
}

fn field_from_usize(value: usize) -> Result<Field, Error> {
    let value = u64::try_from(value).map_err(|_| {
        Error::malformed_shares(
            0,
            "PRF input integer does not fit in a field element".to_string(),
        )
    })?;
    Ok(Field::from(value))
}

/// Poseidon2 SAFE evaluation of `F_k(S, ct)` in `R_q`.
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

    let input = absorb_input(key, decryptors, ciphertext)?;
    let absorb_len = encode_length(input.len(), "absorb")?;
    let squeeze_len = encode_length(coefficient_count, "squeeze")?;
    let io_pattern = [ABSORB_FLAG | absorb_len, SQUEEZE_FLAG | squeeze_len];

    let mut sponge = SafeSponge::start(io_pattern, domain_separator());
    sponge.absorb(input);
    let squeezed = sponge.squeeze();
    sponge.finish();
    if squeezed.len() != coefficient_count {
        return Err(Error::malformed_shares(
            0,
            "PRF sponge produced the wrong number of field elements".to_string(),
        ));
    }

    let mut coefficients = ndarray::Array2::zeros((moduli.len(), degree));
    for (row_index, modulus) in moduli.iter().enumerate() {
        for column_index in 0..degree {
            let field_index = row_index
                .checked_mul(degree)
                .and_then(|offset| offset.checked_add(column_index))
                .ok_or_else(|| {
                    Error::malformed_shares(0, "PRF output index overflow".to_string())
                })?;
            let field = squeezed.get(field_index).ok_or_else(|| {
                Error::malformed_shares(0, "PRF output index out of range".to_string())
            })?;
            let coefficient = coefficients
                .get_mut((row_index, column_index))
                .ok_or_else(|| {
                    Error::malformed_shares(0, "PRF output index out of range".to_string())
                })?;
            *coefficient = field_to_residue(field, modulus);
        }
    }

    let mut poly = Poly::<PowerBasis>::zero(ctx);
    poly.set_coefficients(coefficients);
    poly.disallow_variable_time_computations();
    Ok(poly)
}

fn absorb_input(
    key: &PrfKey,
    decryptors: &[usize],
    ciphertext: &Ciphertext,
) -> Result<Vec<Field>, Error> {
    let mut input = Vec::new();
    input.push(Field::from_le_bytes_mod_order(&key.0));
    input.push(field_from_usize(decryptors.len())?);
    for &party_id in decryptors {
        input.push(field_from_usize(party_id)?);
    }
    input.push(field_from_usize(ciphertext.level)?);
    input.push(field_from_usize(ciphertext.c.len())?);
    for poly in &ciphertext.c {
        let coefficients = poly.coefficients();
        input.push(field_from_usize(coefficients.nrows())?);
        input.push(field_from_usize(coefficients.ncols())?);
        for row in 0..coefficients.nrows() {
            for column in 0..coefficients.ncols() {
                let value = coefficients.get((row, column)).ok_or_else(|| {
                    Error::malformed_shares(
                        0,
                        "PRF ciphertext coefficient out of range".to_string(),
                    )
                })?;
                input.push(Field::from(*value));
            }
        }
    }
    Ok(input)
}

fn field_to_residue(field: &Field, modulus: &Modulus) -> u64 {
    let mut acc = 0u64;
    for &limb in field.into_bigint().as_ref().iter().rev() {
        acc = modulus.reduce_u128((u128::from(acc) << 64) | u128::from(limb));
    }
    acc
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;
    use crate::bfv::{Encoding, Plaintext, PublicKey, SecretKey};
    use crate::support::insecure;
    use fhe_traits::{FheEncoder, FheEncrypter};
    use rand::rng;

    fn test_ciphertext<R: RngCore + CryptoRng>(rng: &mut R) -> Ciphertext {
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, rng);
        let pk = PublicKey::new(&sk, rng);
        let pt = Plaintext::try_encode(&[7u64], Encoding::poly(), &params).unwrap();
        pk.try_encrypt(&pt, rng).unwrap()
    }

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
        let ct = test_ciphertext(&mut rng);
        let keys = PartyPrfKeys::generate_committee(3, &mut rng).unwrap();
        let decryptors = [1usize, 3];
        let mut acc = keys[0].mask(&decryptors, &ct).unwrap();
        acc += &keys[2].mask(&decryptors, &ct).unwrap();

        assert!(
            acc.coefficients().iter().all(|&value| value == 0),
            "PRF masks must cancel when summed over S"
        );
    }

    #[test]
    fn evaluate_is_deterministic() {
        let mut rng = rng();
        let ct = test_ciphertext(&mut rng);
        let keys = PartyPrfKeys::generate_committee(3, &mut rng).unwrap();
        let decryptors = [1usize, 2];
        let first = evaluate(&keys[0].outgoing[1], &decryptors, &ct).unwrap();
        let second = evaluate(&keys[0].outgoing[1], &decryptors, &ct).unwrap();
        assert_eq!(first.coefficients(), second.coefficients());
    }

    #[test]
    fn different_decryptor_sets_produce_different_masks() {
        let mut rng = rng();
        let ct = test_ciphertext(&mut rng);
        let keys = PartyPrfKeys::generate_committee(3, &mut rng).unwrap();
        let first = keys[0].mask(&[1, 2], &ct).unwrap();
        let second = keys[0].mask(&[1, 3], &ct).unwrap();
        assert_ne!(first.coefficients(), second.coefficients());
    }
}
