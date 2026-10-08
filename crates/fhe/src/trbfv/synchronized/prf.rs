//! Poseidon2/SAFE committee masks, extracted from PRs #276 and #280.
//!
//! `r_i = sum_{j in S, j != i} (F_{k_i_j}(H(S, ct)) - F_{k_j_i}(H(S, ct)))`.
//! Domain separators, field encoding and coefficient order match `dev-sync-dec`.

use crate::Error;
use crate::bfv::Ciphertext;
use ark_ff::{PrimeField, Zero};
use e3_safe::{ABSORB_FLAG, Field, SQUEEZE_FLAG, SafeSponge};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_math::zq::Modulus;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};
use zeroize_derive::{Zeroize as ZeroizeFields, ZeroizeOnDrop};

/// Length in bytes of one pairwise PRF key.
pub const PRF_KEY_LEN: usize = 32;
const SAFE_LENGTH_MASK: u32 = 0x7FFF_FFFF;
const DIGEST_LEN: usize = 2;
pub(super) type ContextDigest = [Field; DIGEST_LEN];
const CTX_DOMAIN_SEPARATOR_LABEL: &[u8] = b"fhe.rs/trbfv/prf/poseidon2/ctx";
const EVAL_DOMAIN_SEPARATOR_LABEL: &[u8] = b"fhe.rs/trbfv/prf/poseidon2/eval";

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
        super::validate_ciphertext(ciphertext)?;
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
    super::validate_ciphertext(ciphertext)?;
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
    let moduli = ctx.moduli_operators();
    let degree = ciphertext.params.degree();
    let coefficient_count = moduli
        .len()
        .checked_mul(degree)
        .ok_or_else(|| Error::malformed_shares(0, "PRF output dimensions overflow".to_string()))?;
    let mut input = Zeroizing::new(Vec::with_capacity(1 + DIGEST_LEN));
    input.push(Field::from_le_bytes_mod_order(&key.0));
    input.extend_from_slice(digest);
    let squeezed = sponge_absorb_squeeze(EVAL_DOMAIN_SEPARATOR_LABEL, input, coefficient_count)?;

    let mut coefficients =
        super::arithmetic::SecretMatrix(ndarray::Array2::zeros((moduli.len(), degree)));
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
                .0
                .get_mut((row_index, column_index))
                .ok_or_else(|| {
                    Error::malformed_shares(0, "PRF output index out of range".to_string())
                })?;
            *coefficient = field_to_residue(field, modulus);
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
    let mut input = Vec::new();
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
        for row in coefficients.rows() {
            for &value in row {
                input.push(Field::from(value));
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
