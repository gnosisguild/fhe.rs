//! Committee PRF keys and masks for synchronous threshold decryption.
//!
//! This is the masking layer from Colin de Verdière–Passelègue–Stehlé 2026
//! (eprint 2026/031). Each party `i` holds `2n` keys `(k_{i,j}, k_{j,i})_j`
//! and, for a designated decryptor set `S` and ciphertext `ct`, the mask
//!
//! `r_i^{S,ct} = Σ_{j∈S, j≠i} (F_{k_{i,j}}(H(S, ct)) − F_{k_{j,i}}(H(S, ct)))`.
//!
//! `H(S, ct)` is a Poseidon2/SAFE digest computed once per [`PartyPrfKeys::mask`]
//! call. The `j = i` term is omitted: `k_{i,i}` appears on both sides and
//! cancels. The masks cancel when summed over `S`. Pairwise keys are 256-bit
//! strings expected to be uniformly random, interpreted as BN254 scalar-field
//! elements. `F` is
//! Poseidon2 via the SAFE sponge API (`e3-safe`).

use crate::Error;
use crate::bfv::Ciphertext;
use ark_ff::{PrimeField, Zero};
use e3_safe::{ABSORB_FLAG, Field, SQUEEZE_FLAG, SafeSponge};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_math::zq::Modulus;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};
use zeroize_derive::{Zeroize as ZeroizeFields, ZeroizeOnDrop};

const KEY_LEN: usize = 32;
/// Length in bytes of one committee PRF key.
pub const PRF_KEY_LEN: usize = KEY_LEN;
const SAFE_LENGTH_MASK: u32 = 0x7FFF_FFFF;
const DIGEST_LEN: usize = 2;
pub(crate) type ContextDigest = [Field; DIGEST_LEN];
const CTX_DOMAIN_SEPARATOR_LABEL: &[u8] = b"fhe.rs/trbfv/prf/poseidon2/ctx";
const EVAL_DOMAIN_SEPARATOR_LABEL: &[u8] = b"fhe.rs/trbfv/prf/poseidon2/eval";

/// A 256-bit PRF key. Sampled uniformly at random and mapped into the
/// Poseidon2 field inside [`evaluate`].
#[derive(Clone, ZeroizeFields, ZeroizeOnDrop)]
pub struct PrfKey([u8; KEY_LEN]);

impl fmt::Debug for PrfKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PrfKey").finish_non_exhaustive()
    }
}

/// The `2n` PRF keys held by party `i`, indexed as in the paper.
///
/// `party_id` is the owner's 1-based identity `i`; `committee_size` is the total
/// number of parties `n`, including the owner, not a counterpart's identity.
/// At index `j - 1`, `keys_i_j` holds `k_{i,j}` and `keys_j_i` holds `k_{j,i}`.
/// Their PRF evaluations are respectively added to and subtracted from `i`'s
/// mask. Both vectors belong to `i`; the names describe index order, not message
/// direction. The application protocol establishes the key material; this crate
/// only validates and evaluates each party's supplied bundle.
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
    /// 1-based identity of the party that holds these keys.
    #[must_use]
    pub fn party_id(&self) -> usize {
        self.party_id
    }

    /// Total number of parties `n` in the committee, including this owner.
    #[must_use]
    pub fn committee_size(&self) -> usize {
        self.committee_size
    }

    /// Evaluate `r_i^{S,ct}` for this party and decryptor set `S`.
    pub fn mask(
        &self,
        decryptors: &[usize],
        ciphertext: &Ciphertext,
    ) -> Result<Poly<PowerBasis>, Error> {
        let decryptors = canonical_decryptors(decryptors);
        for &party_id in &decryptors {
            if party_id == 0 || party_id > self.committee_size {
                return Err(Error::invalid_party_id(party_id, self.committee_size));
            }
        }

        let mut digest = hash_context(&decryptors, ciphertext)?;
        let ctx = ciphertext.params.context_at_level(ciphertext.level)?;
        let mut acc = Poly::<PowerBasis>::zero(ctx);
        acc.disallow_variable_time_computations();
        for &peer_party_id in &decryptors {
            // k_{i,i} appears in both key vectors, so the two
            // evaluations cancel. The paper notes this term can be ignored.
            if peer_party_id == self.party_id {
                continue;
            }
            let key_index = peer_party_id - 1;
            let key_i_j = self
                .keys_i_j
                .get(key_index)
                .ok_or_else(|| Error::invalid_party_id(peer_party_id, self.committee_size))?;
            let key_j_i = self
                .keys_j_i
                .get(key_index)
                .ok_or_else(|| Error::invalid_party_id(peer_party_id, self.committee_size))?;
            let mut positive = evaluate(key_i_j, &digest, ciphertext)?;
            let mut negative = evaluate(key_j_i, &digest, ciphertext)?;
            acc += &positive;
            acc -= &negative;
            positive.zeroize();
            negative.zeroize();
        }
        digest.zeroize();
        Ok(acc)
    }

    /// Consume these keys at an explicit application transport boundary.
    ///
    /// This exposes raw bytes to the application's serializer. It neither
    /// establishes pairwise keys nor sends any messages.
    #[must_use]
    pub fn into_transport(mut self) -> PartyPrfKeyTransport {
        let party_id = self.party_id;
        let committee_size = self.committee_size;
        let keys_i_j = take_key_bytes(&mut self.keys_i_j);
        let keys_j_i = take_key_bytes(&mut self.keys_j_i);
        PartyPrfKeyTransport {
            party_id,
            committee_size,
            keys_i_j,
            keys_j_i,
        }
    }

    /// Rehydrate one party's keys after application protocol setup and transport.
    ///
    /// This validates local metadata and vector lengths only; the application
    /// protocol must ensure the pairwise keys match across parties.
    pub fn from_transport(mut transport: PartyPrfKeyTransport) -> Result<Self, Error> {
        // Revalidate because callers can explicitly zeroize the transport owner
        // after constructing it, clearing both its keys and metadata.
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

/// Raw key bytes and owner metadata at an application transport boundary.
///
/// This is a byte representation of the same keys, not additional key material.
/// [`PartyPrfKeys`] is the validated owner used for mask evaluation. Both types
/// wipe their keys on drop; applications supply serialization and authenticated,
/// confidential transport.
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
    /// Build a transport owner from raw key bytes received at the application
    /// boundary.
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

    /// 1-based identity of the party that holds these keys.
    #[must_use]
    pub fn party_id(&self) -> usize {
        self.party_id
    }

    /// Total number of parties `n` in the committee, including this owner.
    #[must_use]
    pub fn committee_size(&self) -> usize {
        self.committee_size
    }

    /// Keys `k_{i,j}` for owner `i`, indexed by `j - 1` for each party `j`.
    /// Their PRF evaluations are added to the owner's mask.
    #[must_use]
    pub fn keys_i_j(&self) -> &[[u8; PRF_KEY_LEN]] {
        &self.keys_i_j
    }

    /// Keys `k_{j,i}` for owner `i`, indexed by `j - 1` for each party `j`.
    /// Their PRF evaluations are subtracted from the owner's mask.
    #[must_use]
    pub fn keys_j_i(&self) -> &[[u8; PRF_KEY_LEN]] {
        &self.keys_j_i
    }
}

fn take_key_bytes(keys: &mut Vec<PrfKey>) -> Vec<[u8; KEY_LEN]> {
    std::mem::take(keys)
        .into_iter()
        .map(|mut key| {
            let bytes = key.0;
            key.0.zeroize();
            bytes
        })
        .collect()
}

/// Canonicalize `S` so every party evaluates `F_k` on the same domain.
pub(crate) fn canonical_decryptors(decryptors: &[usize]) -> Vec<usize> {
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

pub(crate) fn context_digest(
    decryptors: &[usize],
    ciphertext: &Ciphertext,
) -> Result<ContextDigest, Error> {
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

/// Unkeyed Poseidon2 digest of the designated set and ciphertext.
fn hash_context(decryptors: &[usize], ciphertext: &Ciphertext) -> Result<ContextDigest, Error> {
    let input = Zeroizing::new(context_absorb_input(decryptors, ciphertext)?);
    let squeezed = sponge_absorb_squeeze(CTX_DOMAIN_SEPARATOR_LABEL, input, DIGEST_LEN)?;
    let mut digest = [Field::zero(); DIGEST_LEN];
    for (index, slot) in digest.iter_mut().enumerate() {
        let field = squeezed.get(index).ok_or_else(|| {
            Error::malformed_shares(0, "PRF digest index out of range".to_string())
        })?;
        *slot = *field;
    }
    Ok(digest)
}

/// Poseidon2 SAFE evaluation of `F_k(H(S, ct))` in `R_q`.
fn evaluate(
    key: &PrfKey,
    digest: &[Field; DIGEST_LEN],
    ciphertext: &Ciphertext,
) -> Result<Poly<PowerBasis>, Error> {
    let ctx = ciphertext.params.context_at_level(ciphertext.level)?;
    let moduli = ctx.moduli_operators();
    let degree = ctx.degree();
    let coefficient_count = moduli
        .len()
        .checked_mul(degree)
        .ok_or_else(|| Error::malformed_shares(0, "PRF output dimensions overflow".to_string()))?;

    let mut input = Zeroizing::new(Vec::with_capacity(1 + DIGEST_LEN));
    input.push(Field::from_le_bytes_mod_order(&key.0));
    input.extend_from_slice(digest);
    let squeezed = sponge_absorb_squeeze(EVAL_DOMAIN_SEPARATOR_LABEL, input, coefficient_count)?;

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
    poly.set_coefficients(coefficients)?;
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
    use crate::support::examples::simulated_committee_prf_keys;
    use crate::support::presets::insecure;
    use fhe_traits::{FheEncoder, FheEncrypter};
    use rand::rng;
    use rand::{CryptoRng, RngCore};

    fn test_ciphertext<R: RngCore + CryptoRng>(rng: &mut R) -> Ciphertext {
        let params = insecure().unwrap().parameters;
        let sk = SecretKey::random(&params, rng);
        let pk = PublicKey::new(&sk, rng);
        let pt = Plaintext::try_encode(&[7u64], Encoding::poly(), &params).unwrap();
        pk.try_encrypt(&pt, rng).unwrap()
    }

    #[test]
    fn committee_keys_match_across_parties() {
        let mut rng = rng();
        let keys = simulated_committee_prf_keys(3, &mut rng);
        assert_eq!(keys.len(), 3);
        for (index, party) in keys.iter().enumerate() {
            assert_eq!(party.party_id(), index + 1);
            assert_eq!(party.committee_size(), 3);
            for (peer_index, peer) in keys.iter().enumerate() {
                assert_eq!(party.keys_i_j[peer_index].0, peer.keys_j_i[index].0);
                assert_eq!(party.keys_j_i[peer_index].0, peer.keys_i_j[index].0);
            }
        }
    }

    #[test]
    fn masks_sum_to_zero_over_the_decryptor_set() {
        let mut rng = rng();
        let ct = test_ciphertext(&mut rng);
        let keys = simulated_committee_prf_keys(3, &mut rng);
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
        let keys = simulated_committee_prf_keys(3, &mut rng);
        let decryptors = canonical_decryptors(&[1usize, 2]);
        let digest = hash_context(&decryptors, &ct).unwrap();
        let first = evaluate(&keys[0].keys_i_j[1], &digest, &ct).unwrap();
        let second = evaluate(&keys[0].keys_i_j[1], &digest, &ct).unwrap();
        assert_eq!(first.coefficients(), second.coefficients());
    }

    #[test]
    fn context_digest_is_independent_of_the_key() {
        let mut rng = rng();
        let ct = test_ciphertext(&mut rng);
        let decryptors = canonical_decryptors(&[1usize, 2]);
        let first = hash_context(&decryptors, &ct).unwrap();
        let second = hash_context(&decryptors, &ct).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn different_decryptor_sets_produce_different_digests() {
        let mut rng = rng();
        let ct = test_ciphertext(&mut rng);
        let first = hash_context(&canonical_decryptors(&[1, 2]), &ct).unwrap();
        let second = hash_context(&canonical_decryptors(&[1, 3]), &ct).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn self_term_is_skipped() {
        let mut rng = rng();
        let ct = test_ciphertext(&mut rng);
        let keys = simulated_committee_prf_keys(3, &mut rng);
        let mask = keys[0].mask(&[1], &ct).unwrap();
        assert!(
            mask.coefficients().iter().all(|&value| value == 0),
            "mask for S = {{i}} must be zero because k_{{i,i}} cancels"
        );
    }

    #[test]
    fn different_decryptor_sets_produce_different_masks() {
        let mut rng = rng();
        let ct = test_ciphertext(&mut rng);
        let keys = simulated_committee_prf_keys(3, &mut rng);
        let first = keys[0].mask(&[1, 2], &ct).unwrap();
        let second = keys[0].mask(&[1, 3], &ct).unwrap();
        assert_ne!(first.coefficients(), second.coefficients());
    }

    #[test]
    fn different_ciphertexts_produce_different_masks() {
        let mut rng = rng();
        let first_ct = test_ciphertext(&mut rng);
        let second_ct = test_ciphertext(&mut rng);
        let keys = simulated_committee_prf_keys(3, &mut rng);
        let first = keys[0].mask(&[1, 2], &first_ct).unwrap();
        let second = keys[0].mask(&[1, 2], &second_ct).unwrap();
        assert_ne!(first.coefficients(), second.coefficients());
    }

    #[test]
    fn transport_roundtrip_preserves_masks() {
        let mut rng = rng();
        let ct = test_ciphertext(&mut rng);
        let keys = simulated_committee_prf_keys(3, &mut rng);
        let decryptors = [1usize, 2];
        let original = keys[0].mask(&decryptors, &ct).unwrap();
        let restored = PartyPrfKeys::from_transport(keys[0].clone().into_transport()).unwrap();
        let roundtrip = restored.mask(&decryptors, &ct).unwrap();
        assert_eq!(original.coefficients(), roundtrip.coefficients());
        let transport = keys[1].clone().into_transport();
        assert_eq!(transport.party_id(), 2);
        assert_eq!(transport.committee_size(), 3);
        assert_eq!(transport.keys_i_j().len(), 3);
        assert_eq!(transport.keys_j_i().len(), 3);
        let rebuilt = PartyPrfKeyTransport::new(
            transport.party_id(),
            transport.committee_size(),
            transport.keys_i_j().to_vec(),
            transport.keys_j_i().to_vec(),
        )
        .unwrap();
        let restored_from_parts = PartyPrfKeys::from_transport(rebuilt).unwrap();
        assert_eq!(
            keys[1].mask(&decryptors, &ct).unwrap().coefficients(),
            restored_from_parts
                .mask(&decryptors, &ct)
                .unwrap()
                .coefficients()
        );
    }

    #[test]
    fn transport_rejects_invalid_metadata_and_key_vector_lengths() {
        for (party_id, committee_size, keys_i_j_len, keys_j_i_len) in [
            (0, 3, 3, 3),
            (4, 3, 3, 3),
            (1, 0, 0, 0),
            (1, 3, 2, 3),
            (1, 3, 3, 2),
        ] {
            assert!(
                PartyPrfKeyTransport::new(
                    party_id,
                    committee_size,
                    vec![[0u8; PRF_KEY_LEN]; keys_i_j_len],
                    vec![[0u8; PRF_KEY_LEN]; keys_j_i_len],
                )
                .is_err()
            );
        }
    }

    #[test]
    fn transport_is_revalidated_after_explicit_zeroization() {
        let mut rng = rng();
        let keys = simulated_committee_prf_keys(3, &mut rng);
        let mut transport = keys[0].clone().into_transport();
        transport.zeroize();
        assert!(PartyPrfKeys::from_transport(transport).is_err());
    }
}
