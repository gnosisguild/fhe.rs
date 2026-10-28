//! Pairwise PRF keys and cancelling Poseidon2/SAFE committee masks.
//!
//! `r_i = sum_{j in S, j != i} (F_{k_i_j}(H(S, ct)) - F_{k_j_i}(H(S, ct)))`.
//! The context digest absorbs one checked commitment to the ciphertext. That
//! commitment packs each power-basis row centered and high degree first, then
//! hashes the two component hashes, matching the Interfold circuit. Evaluation
//! squeezes `ceil(N/3)` field elements per limb and splits each one into three
//! residues of that limb's modulus. The third residue is the accepted
//! statistical gap.

use super::config::validate_ciphertext;
use crate::Error;
use crate::bfv::Ciphertext;
use ark_ff::{PrimeField, Zero};
use e3_safe::{ABSORB_FLAG, Field, SQUEEZE_FLAG, SafeSponge};
use fhe_math::rq::{Poly, PowerBasis};
use ndarray::Array2;
use num_bigint::BigUint;
use std::fmt;
use std::ops::{Add, Mul};
use zeroize::{Zeroize, Zeroizing};
use zeroize_derive::{Zeroize as ZeroizeFields, ZeroizeOnDrop};

/// Length in bytes of one pairwise PRF key.
pub const PRF_KEY_LEN: usize = 32;
const SAFE_LENGTH_MASK: u32 = 0x7FFF_FFFF;
const DIGEST_LEN: usize = 2;
pub(super) type ContextDigest = [Field; DIGEST_LEN];
const CTX_DOMAIN_SEPARATOR_LABEL: &[u8] = b"fhe.rs/trbfv/prf/poseidon2/ctx-cmt";
const EVAL_DOMAIN_SEPARATOR_LABEL: &[u8] = b"fhe.rs/trbfv/prf/poseidon2/eval-x3";
const CIPHERTEXT_DOMAIN_SEPARATOR_LABEL: &[u8] = b"CIPHERTEXT";

/// A uniformly sampled 256-bit key, mapped into the BN254 scalar field internally.
#[derive(Clone, ZeroizeFields, ZeroizeOnDrop)]
pub struct PrfKey([u8; PRF_KEY_LEN]);

impl fmt::Debug for PrfKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PrfKey").finish_non_exhaustive()
    }
}

/// Reusable pairwise keys held by party `i` in an `n`-party committee.
///
/// At index `j - 1`, `keys_i_j` contains `k_{i,j}` and `keys_j_i` contains
/// `k_{j,i}`. These are paper indices, not message directions. Evaluations of
/// the first vector are added to the owner's mask; the second are subtracted.
/// Applications establish matching keys across parties and import each party's
/// bundle with [`Self::from_transport`]. Committee-wide generation belongs in
/// application setup or local simulation, not in the decryption API.
#[derive(Clone, ZeroizeFields, ZeroizeOnDrop)]
pub struct PartyPrfKeys {
    party_id: usize,
    committee_size: usize,
    keys_i_j: Vec<PrfKey>,
    keys_j_i: Vec<PrfKey>,
}

impl fmt::Debug for PartyPrfKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PartyPrfKeys")
            .field("party_id", &self.party_id)
            .field("committee_size", &self.committee_size)
            .finish_non_exhaustive()
    }
}

impl PartyPrfKeys {
    /// Owner's 1-based party identity.
    #[must_use]
    pub fn party_id(&self) -> usize {
        self.party_id
    }

    /// Total committee size, including the owner.
    #[must_use]
    pub fn committee_size(&self) -> usize {
        self.committee_size
    }

    /// Evaluate this owner's cancelling mask for the set and ciphertext.
    ///
    /// Ordering and repeated set entries are canonicalized for hashing, as in
    /// the source PRF. Partial decryption separately rejects duplicate IDs and
    /// checks threshold size and owner membership before evaluating a mask.
    pub fn mask(
        &self,
        decryptors: &[usize],
        ciphertext: &Ciphertext,
    ) -> Result<Poly<PowerBasis>, Error> {
        validate_ciphertext(ciphertext)?;
        let decryptors = canonical_decryptors(decryptors);
        for &party_id in &decryptors {
            if party_id == 0 || party_id > self.committee_size {
                return Err(Error::invalid_party_id(party_id, self.committee_size));
            }
        }
        let digest = Zeroizing::new(hash_context(&decryptors, ciphertext)?);
        let ctx = ciphertext.params.context_at_level(ciphertext.level)?;
        let mut acc = Zeroizing::new(Poly::<PowerBasis>::zero(ctx));
        acc.disallow_variable_time_computations();
        for &peer in &decryptors {
            // k_i_i cancels and need not be evaluated.
            if peer == self.party_id {
                continue;
            }
            let positive_key = self
                .keys_i_j
                .get(peer - 1)
                .ok_or_else(|| Error::invalid_party_id(peer, self.committee_size))?;
            let negative_key = self
                .keys_j_i
                .get(peer - 1)
                .ok_or_else(|| Error::invalid_party_id(peer, self.committee_size))?;
            let positive = Zeroizing::new(evaluate(positive_key, &digest, ciphertext)?);
            let negative = Zeroizing::new(evaluate(negative_key, &digest, ciphertext)?);
            *acc.as_mut() += positive.as_ref();
            *acc.as_mut() -= negative.as_ref();
        }
        Ok(std::mem::replace(
            acc.as_mut(),
            Poly::<PowerBasis>::zero(ctx),
        ))
    }

    /// Consume these keys into raw-byte transport storage owned by the application.
    #[must_use]
    pub fn into_transport(mut self) -> PartyPrfKeyTransport {
        PartyPrfKeyTransport {
            party_id: self.party_id,
            committee_size: self.committee_size,
            keys_i_j: take_key_bytes(&mut self.keys_i_j),
            keys_j_i: take_key_bytes(&mut self.keys_j_i),
        }
    }

    /// Validate and rehydrate one party's externally established keys.
    ///
    /// Checks owner metadata and vector lengths. Matching keys between parties
    /// and authenticated, confidential delivery are the application's responsibility.
    pub fn from_transport(mut transport: PartyPrfKeyTransport) -> Result<Self, Error> {
        // Revalidate: the caller may have explicitly zeroized the transport.
        let mut validated = PartyPrfKeyTransport::new(
            transport.party_id,
            transport.committee_size,
            std::mem::take(&mut transport.keys_i_j),
            std::mem::take(&mut transport.keys_j_i),
        )?;
        Ok(Self {
            party_id: validated.party_id,
            committee_size: validated.committee_size,
            keys_i_j: std::mem::take(&mut validated.keys_i_j)
                .into_iter()
                .map(PrfKey)
                .collect(),
            keys_j_i: std::mem::take(&mut validated.keys_j_i)
                .into_iter()
                .map(PrfKey)
                .collect(),
        })
    }
}

/// Zeroizing raw-byte representation of one party's PRF keys and owner metadata.
///
/// Serialization and authenticated, confidential transport are supplied by the
/// application. Copied bytes are the application's responsibility to erase.
#[derive(ZeroizeFields, ZeroizeOnDrop)]
pub struct PartyPrfKeyTransport {
    party_id: usize,
    committee_size: usize,
    keys_i_j: Vec<[u8; PRF_KEY_LEN]>,
    keys_j_i: Vec<[u8; PRF_KEY_LEN]>,
}

impl fmt::Debug for PartyPrfKeyTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PartyPrfKeyTransport")
            .field("party_id", &self.party_id)
            .field("committee_size", &self.committee_size)
            .finish_non_exhaustive()
    }
}

impl PartyPrfKeyTransport {
    /// Build a transport owner from two vectors of exactly `committee_size` keys.
    pub fn new(
        party_id: usize,
        committee_size: usize,
        keys_i_j: Vec<[u8; PRF_KEY_LEN]>,
        keys_j_i: Vec<[u8; PRF_KEY_LEN]>,
    ) -> Result<Self, Error> {
        let transport = Self {
            party_id,
            committee_size,
            keys_i_j,
            keys_j_i,
        };
        if committee_size == 0 {
            return Err(Error::invalid_party_count(0, 1));
        }
        if party_id == 0 || party_id > committee_size {
            return Err(Error::invalid_party_id(party_id, committee_size));
        }
        if transport.keys_i_j.len() != committee_size || transport.keys_j_i.len() != committee_size
        {
            return Err(Error::malformed_shares(
                party_id,
                "PRF key vectors must have length n".to_string(),
            ));
        }
        Ok(transport)
    }

    /// Owner's 1-based party identity.
    #[must_use]
    pub fn party_id(&self) -> usize {
        self.party_id
    }

    /// Total committee size, including the owner.
    #[must_use]
    pub fn committee_size(&self) -> usize {
        self.committee_size
    }

    /// Keys `k_{i,j}`, indexed by `j - 1`, whose evaluations are added.
    #[must_use]
    pub fn keys_i_j(&self) -> &[[u8; PRF_KEY_LEN]] {
        &self.keys_i_j
    }

    /// Keys `k_{j,i}`, indexed by `j - 1`, whose evaluations are subtracted.
    #[must_use]
    pub fn keys_j_i(&self) -> &[[u8; PRF_KEY_LEN]] {
        &self.keys_j_i
    }
}

fn take_key_bytes(keys: &mut Vec<PrfKey>) -> Vec<[u8; PRF_KEY_LEN]> {
    std::mem::take(keys)
        .into_iter()
        .map(|mut key| {
            let bytes = key.0;
            key.0.zeroize();
            bytes
        })
        .collect()
}

pub(super) fn canonical_decryptors(decryptors: &[usize]) -> Vec<usize> {
    let mut decryptors = decryptors.to_vec();
    decryptors.sort_unstable();
    decryptors.dedup();
    decryptors
}

fn domain_separator(label: &[u8]) -> [u8; 64] {
    let mut domain = [0u8; 64];
    let copy_len = label.len().min(domain.len());
    if let Some(prefix) = domain.get_mut(..copy_len)
        && let Some(label_prefix) = label.get(..copy_len)
    {
        prefix.copy_from_slice(label_prefix);
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

pub(super) fn context_digest(
    decryptors: &[usize],
    ciphertext: &Ciphertext,
) -> Result<ContextDigest, Error> {
    validate_ciphertext(ciphertext)?;
    hash_context(&canonical_decryptors(decryptors), ciphertext)
}

fn sponge_absorb_squeeze(
    domain_label: &[u8],
    mut input: Zeroizing<Vec<Field>>,
    squeeze_len: usize,
) -> Result<Zeroizing<Vec<Field>>, Error> {
    let absorb_len = encode_length(input.len(), "absorb")?;
    let squeeze_encoded = encode_length(squeeze_len, "squeeze")?;
    let io_pattern = [ABSORB_FLAG | absorb_len, SQUEEZE_FLAG | squeeze_encoded];
    let mut sponge = SafeSponge::start(io_pattern, domain_separator(domain_label));
    sponge.absorb(std::mem::take(&mut *input));
    let squeezed = Zeroizing::new(sponge.squeeze());
    sponge.finish();
    if squeezed.len() != squeeze_len {
        return Err(Error::malformed_shares(
            0,
            "PRF sponge produced the wrong number of field elements".to_string(),
        ));
    }
    Ok(squeezed)
}

fn hash_context(decryptors: &[usize], ciphertext: &Ciphertext) -> Result<ContextDigest, Error> {
    let input = Zeroizing::new(context_absorb_input(decryptors, ciphertext)?);
    let squeezed = sponge_absorb_squeeze(CTX_DOMAIN_SEPARATOR_LABEL, input, DIGEST_LEN)?;
    let mut digest = [Field::zero(); DIGEST_LEN];
    for (index, slot) in digest.iter_mut().enumerate() {
        *slot = *squeezed.get(index).ok_or_else(|| {
            Error::malformed_shares(0, "PRF digest index out of range".to_string())
        })?;
    }
    Ok(digest)
}

fn evaluate(
    key: &PrfKey,
    digest: &ContextDigest,
    ciphertext: &Ciphertext,
) -> Result<Poly<PowerBasis>, Error> {
    let ctx = ciphertext.params.context_at_level(ciphertext.level)?;
    let moduli = ctx.moduli();
    let degree = ctx.degree;
    let groups = degree.div_ceil(3);
    let squeezed_len = moduli
        .len()
        .checked_mul(groups)
        .ok_or_else(|| Error::malformed_shares(0, "PRF output dimensions overflow".to_string()))?;
    let mut input = Zeroizing::new(Vec::with_capacity(1 + DIGEST_LEN));
    input.push(Field::from_le_bytes_mod_order(&key.0));
    input.extend_from_slice(digest);
    let squeezed = sponge_absorb_squeeze(EVAL_DOMAIN_SEPARATOR_LABEL, input, squeezed_len)?;

    let mut coefficients = super::arithmetic::SecretMatrix(Array2::zeros((moduli.len(), degree)));
    for (row_index, &modulus) in moduli.iter().enumerate() {
        for group in 0..groups {
            let field_index = row_index
                .checked_mul(groups)
                .and_then(|offset| offset.checked_add(group))
                .ok_or_else(|| {
                    Error::malformed_shares(0, "PRF output index overflow".to_string())
                })?;
            let field = squeezed.get(field_index).ok_or_else(|| {
                Error::malformed_shares(0, "PRF output index out of range".to_string())
            })?;
            let residues = split_three(field, modulus)?;
            write_residues(&mut coefficients.0, row_index, group, residues, degree)?;
        }
    }
    let mut poly = Poly::<PowerBasis>::zero(ctx);
    poly.set_coefficients(std::mem::take(&mut coefficients.0));
    poly.disallow_variable_time_computations();
    Ok(poly)
}

fn context_absorb_input(
    decryptors: &[usize],
    ciphertext: &Ciphertext,
) -> Result<Vec<Field>, Error> {
    let (commitment, limbs, degree) = ciphertext_commitment(ciphertext)?;
    let mut input = Vec::with_capacity(decryptors.len().saturating_add(6));
    input.push(field_from_usize(decryptors.len())?);
    for &party_id in decryptors {
        input.push(field_from_usize(party_id)?);
    }
    // C6 opens a level-zero ciphertext with exactly two components.
    input.push(field_from_usize(ciphertext.level)?);
    input.push(field_from_usize(ciphertext.c.len())?);
    input.push(field_from_usize(limbs)?);
    input.push(field_from_usize(degree)?);
    input.push(commitment);
    Ok(input)
}

/// Checked ciphertext commitment of the power-basis polynomials.
///
/// The bit width is the centered modulus bit of the full parameter set, the
/// same width C6 uses for `compute_ciphertext_commitment_checked`. Each row is
/// stored low degree first, reversed to high degree first, centered, and
/// packed with the circuit's shifted digit encoding.
fn ciphertext_commitment(ciphertext: &Ciphertext) -> Result<(Field, usize, usize), Error> {
    if ciphertext.c.len() != 2 {
        return Err(Error::malformed_shares(
            0,
            "PRF ciphertext must have two components".to_string(),
        ));
    }
    let ctx = ciphertext.params.context_at_level(ciphertext.level)?;
    let first = ciphertext
        .c
        .first()
        .ok_or_else(|| Error::malformed_shares(0, "PRF ciphertext is missing c0".to_string()))?
        .clone()
        .into_power_basis();
    let second = ciphertext
        .c
        .get(1)
        .ok_or_else(|| Error::malformed_shares(0, "PRF ciphertext is missing c1".to_string()))?
        .clone()
        .into_power_basis();
    if first.coefficients().shape() != second.coefficients().shape()
        || first.coefficients().nrows() != ctx.moduli().len()
        || first.coefficients().ncols() != ctx.degree
    {
        return Err(Error::malformed_shares(
            0,
            "PRF ciphertext components do not share the level context".to_string(),
        ));
    }
    let bit = modulus_bit(ciphertext.params.moduli())?;
    let commit0 = commit_power_basis(&first, bit)?;
    let commit1 = commit_power_basis(&second, bit)?;
    let squeezed = sponge_absorb_squeeze(
        CIPHERTEXT_DOMAIN_SEPARATOR_LABEL,
        Zeroizing::new(vec![commit0, commit1]),
        1,
    )?;
    let commitment = squeezed
        .first()
        .copied()
        .ok_or_else(|| Error::malformed_shares(0, "ciphertext commitment is empty".to_string()))?;
    Ok((
        commitment,
        first.coefficients().nrows(),
        first.coefficients().ncols(),
    ))
}

fn commit_power_basis(poly: &Poly<PowerBasis>, bit: u32) -> Result<Field, Error> {
    let moduli = poly.ctx().moduli();
    if poly.coefficients().nrows() != moduli.len() {
        return Err(Error::malformed_shares(
            0,
            "PRF polynomial rows do not match its moduli".to_string(),
        ));
    }
    let mut payload = Vec::new();
    for (row, &modulus) in poly.coefficients().outer_iter().zip(moduli.iter()) {
        let coefficients = row.as_slice().ok_or_else(|| {
            Error::malformed_shares(0, "PRF polynomial row is not contiguous".to_string())
        })?;
        payload.extend(pack_centered_row(coefficients, modulus, bit)?);
    }
    let squeezed = sponge_absorb_squeeze(
        CIPHERTEXT_DOMAIN_SEPARATOR_LABEL,
        Zeroizing::new(payload),
        1,
    )?;
    squeezed
        .first()
        .copied()
        .ok_or_else(|| Error::malformed_shares(0, "polynomial commitment is empty".to_string()))
}

/// Bit width of centered residues, matching `compute_modulus_bit`.
fn modulus_bit(moduli: &[u64]) -> Result<u32, Error> {
    let max_q = moduli
        .iter()
        .copied()
        .max()
        .ok_or_else(|| Error::malformed_shares(0, "PRF modulus set is empty".to_string()))?;
    let bound = max_q.saturating_sub(1) / 2;
    Ok((u64::BITS - bound.leading_zeros()).max(1))
}

/// High-degree-first centered packing. Digits and the running carrier use the
/// same field operations as Noir `pack_checked`.
fn pack_centered_row(
    low_degree_first: &[u64],
    modulus: u64,
    bit: u32,
) -> Result<Vec<Field>, Error> {
    let nibble_bits = bit.div_ceil(4) * 4;
    let slot_bits = nibble_bits + 4;
    if slot_bits == 0 || slot_bits > 254 {
        return Err(Error::malformed_shares(
            0,
            "PRF ciphertext packing width does not fit a field element".to_string(),
        ));
    }
    let group = (254 / slot_bits) as usize;
    if group < 2 {
        return Err(Error::malformed_shares(
            0,
            "PRF ciphertext packing group is smaller than two".to_string(),
        ));
    }
    let base = 1u128.checked_shl(nibble_bits).ok_or_else(|| {
        Error::malformed_shares(0, "PRF ciphertext packing base overflows".to_string())
    })?;
    let radix = 1u128.checked_shl(slot_bits).ok_or_else(|| {
        Error::malformed_shares(0, "PRF ciphertext packing radix overflows".to_string())
    })?;
    let radix_field = field_from_u128(radix);
    let mut high_degree_first: Vec<u64> = low_degree_first.iter().copied().rev().collect();
    let padded = high_degree_first.len().div_ceil(group) * group;
    high_degree_first.resize(padded, 0);

    let mut carriers = Vec::with_capacity(high_degree_first.len() / group);
    for chunk in high_degree_first.chunks(group) {
        let mut acc = Field::zero();
        for &value in chunk {
            let digit = centered_digit(value, modulus, base, radix)?;
            acc = acc.mul(radix_field).add(field_from_u128(digit));
        }
        carriers.push(acc);
    }
    Ok(carriers)
}

fn centered_digit(value: u64, modulus: u64, base: u128, radix: u128) -> Result<u128, Error> {
    if modulus < 2 || value >= modulus {
        return Err(Error::malformed_shares(
            0,
            "PRF ciphertext coefficient is outside its modulus".to_string(),
        ));
    }
    let negative = if modulus.is_multiple_of(2) {
        value >= modulus / 2
    } else {
        value > modulus / 2
    };
    let digit = if negative {
        base + u128::from(value) - u128::from(modulus)
    } else {
        base + u128::from(value)
    };
    if digit >= radix {
        return Err(Error::malformed_shares(
            0,
            "PRF ciphertext digit does not fit its packing slot".to_string(),
        ));
    }
    Ok(digit)
}

fn field_from_u128(value: u128) -> Field {
    Field::from_le_bytes_mod_order(&value.to_le_bytes())
}

/// Split one canonical field element into three residues of the same modulus.
///
/// `r0 = x mod q`, `r1 = floor(x/q) mod q`, `r2 = floor(x/q^2) mod q`.
/// `floor(x/q^3)` is discarded. That is the accepted statistical gap; a raw
/// 64-bit window is not used.
fn split_three(field: &Field, modulus: u64) -> Result<[u64; 3], Error> {
    if modulus < 2 {
        return Err(Error::malformed_shares(
            0,
            "PRF residue modulus is smaller than 2".to_string(),
        ));
    }
    let mut bytes = [0u8; 32];
    for (index, limb) in field.into_bigint().as_ref().iter().enumerate() {
        let start = index.checked_mul(8).ok_or_else(|| {
            Error::malformed_shares(0, "PRF field limb index overflow".to_string())
        })?;
        let end = start.checked_add(8).ok_or_else(|| {
            Error::malformed_shares(0, "PRF field limb index overflow".to_string())
        })?;
        let slot = bytes.get_mut(start..end).ok_or_else(|| {
            Error::malformed_shares(0, "PRF field integer does not fit 32 bytes".to_string())
        })?;
        slot.copy_from_slice(&limb.to_le_bytes());
    }
    let integer = BigUint::from_bytes_le(&bytes);
    bytes.zeroize();
    let q = BigUint::from(modulus);
    let remainder0 = &integer % &q;
    let quotient0 = &integer / &q;
    let remainder1 = &quotient0 % &q;
    let quotient1 = &quotient0 / &q;
    let remainder2 = &quotient1 % &q;
    Ok([
        biguint_to_u64(&remainder0)?,
        biguint_to_u64(&remainder1)?,
        biguint_to_u64(&remainder2)?,
    ])
}

fn biguint_to_u64(value: &BigUint) -> Result<u64, Error> {
    let bytes = value.to_bytes_le();
    if bytes.len() > 8 {
        return Err(Error::malformed_shares(
            0,
            "PRF residue does not fit in one coefficient".to_string(),
        ));
    }
    let mut encoded = [0u8; 8];
    encoded
        .get_mut(..bytes.len())
        .ok_or_else(|| Error::malformed_shares(0, "PRF residue encoding overflow".to_string()))?
        .copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(encoded))
}

fn write_residues(
    coefficients: &mut Array2<u64>,
    row: usize,
    group: usize,
    residues: [u64; 3],
    degree: usize,
) -> Result<(), Error> {
    for (offset, residue) in residues.into_iter().enumerate() {
        let column = group
            .checked_mul(3)
            .and_then(|start| start.checked_add(offset))
            .ok_or_else(|| {
                Error::malformed_shares(0, "PRF coefficient index overflow".to_string())
            })?;
        if column >= degree {
            break;
        }
        let slot = coefficients.get_mut((row, column)).ok_or_else(|| {
            Error::malformed_shares(0, "PRF output index out of range".to_string())
        })?;
        *slot = residue;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::bfv::{BfvParametersBuilder, Encoding, Plaintext, PublicKey, SecretKey};
    use fhe_traits::{FheEncoder, FheEncrypter};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn one_field_element_splits_into_three_residues() {
        let q = 65537u64;
        let qq = u128::from(q) * u128::from(q);
        let x = 3u128 + 5 * u128::from(q) + 7 * qq;
        let field = Field::from_le_bytes_mod_order(&x.to_le_bytes());
        assert_eq!(split_three(&field, q).unwrap(), [3, 5, 7]);

        let truncated = qq * u128::from(q) + 4;
        let field = Field::from_le_bytes_mod_order(&truncated.to_le_bytes());
        assert_eq!(split_three(&field, q).unwrap(), [4, 0, 0]);
    }

    #[test]
    fn centered_digits_match_the_circuit_shift() {
        // Modulus 5, nibble width 4, base 16. 4 is the negative residue -1.
        assert_eq!(centered_digit(4, 5, 16, 256).unwrap(), 15);
        assert_eq!(centered_digit(1, 5, 16, 256).unwrap(), 17);
        assert_eq!(centered_digit(0, 5, 16, 256).unwrap(), 16);
        assert_eq!(modulus_bit(&[65537]).unwrap(), 16);
    }

    fn matching_keys(party_count: usize, rng: &mut ChaCha8Rng) -> Vec<PartyPrfKeys> {
        let mut pairwise = vec![vec![[0u8; PRF_KEY_LEN]; party_count]; party_count];
        for row in &mut pairwise {
            for key in row.iter_mut() {
                rng.fill_bytes(key);
            }
        }
        (0..party_count)
            .map(|owner| {
                let keys_i_j = pairwise[owner].clone();
                let keys_j_i = (0..party_count).map(|peer| pairwise[peer][owner]).collect();
                PartyPrfKeys::from_transport(
                    PartyPrfKeyTransport::new(owner + 1, party_count, keys_i_j, keys_j_i).unwrap(),
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn masks_sum_to_zero_and_bind_the_ciphertext() {
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(17)
            .set_moduli_sizes(&[50, 50, 50])
            .build_arc()
            .unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(276_280);
        let secret = SecretKey::random(&params, &mut rng);
        let public = PublicKey::new(&secret, &mut rng);
        let first = {
            let plaintext = Plaintext::try_encode(&[1u64], Encoding::poly(), &params).unwrap();
            public.try_encrypt(&plaintext, &mut rng).unwrap()
        };
        let second = {
            let plaintext = Plaintext::try_encode(&[2u64], Encoding::poly(), &params).unwrap();
            public.try_encrypt(&plaintext, &mut rng).unwrap()
        };
        let keys = matching_keys(3, &mut rng);
        let decryptors = [1usize, 2, 3];
        let ctx = first.params.context_at_level(first.level).unwrap();
        let mut total = Poly::<PowerBasis>::zero(ctx);
        for key in &keys {
            let mask = key.mask(&decryptors, &first).unwrap();
            total += &mask;
        }
        assert!(
            total
                .coefficients()
                .iter()
                .all(|coefficient| *coefficient == 0)
        );
        assert_ne!(
            context_digest(&decryptors, &first).unwrap(),
            context_digest(&decryptors, &second).unwrap()
        );
    }
}
