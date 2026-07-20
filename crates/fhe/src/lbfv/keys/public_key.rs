/*!
 * Public key for the l-BFV encryption scheme.
 *
 * # Concrete vs. seed-derived polynomials
 *
 * Every public key holds `l` ciphertexts `(b_j, a_j)`.  The **concrete**
 * `a_j` polynomials are the authoritative shared reference string (CRS):
 * equality checks throughout aggregation and relinearization-key binding
 * compare the actual polynomial coefficients, never seeds alone.
 *
 * The [`seed`](LBFVPublicKey::seed) field is optional compression
 * metadata: it records the seed that *would* regenerate the same `a_j`
 * polynomials, making serialization smaller.  When present, it is
 * verified against the concrete polynomials at construction and
 * deserialization time (see [`from_parts`](LBFVPublicKey::from_parts)).
 * A seed that contradicts the concrete polynomials is rejected.
 *
 * # Bound vs. unbound construction
 *
 * Constructors come in two forms:
 *
 * - **Unbound** (`new`, `new_with_seed`, `contribute`, `from_parts`) —
 *   produce standalone keys without participant metadata.  These are intended
 *   for single-party use and backward compatibility.  They cannot be used
 *   with the strict distributed aggregation path.
 *
 * - **Bound** (`new_with_seed_and_binding`, `contribute_with_binding`,
 *   `from_parts_with_binding`) — attach an [`LBFVContributionBinding`] so
 *   that distributed aggregation can enforce exact participant-set/session
 *   equality and reject duplicate or missing contributions.
 *
 * Unbound keys remain usable for standalone encryption/decryption and can
 * still be serialized/deserialized.  Only bound contributions are accepted
 * by [`LBFVPublicKey::aggregate`].
 *
 * Participant bindings are **consistency metadata**, not authentication.
 * No signatures, broadcast protocol, or full DKG orchestration is provided
 * by this module.  See Urban–Rambaud (2024, §5) for the robust-DKG
 * adversarial model.
 */

use crate::{Error, Result};
use std::sync::Arc;

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use zeroize::Zeroizing;

use super::{LBFVContributionBinding, LBFVKeyBinding, LBFVParticipantSet};
use crate::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_math::rq::{
    Ntt, NttShoup, Poly, PowerBasis, Representation, switcher::Switcher, traits::TryConvertFrom,
};
use crate::lbfv::crs::LBFVCommonReferenceString;
use fhe_traits::{FheEncrypter, FheParametrized};

/// Public key for the L-BFV encryption scheme.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LBFVPublicKey {
    /// The BFV parameters
    pub params: Arc<BfvParameters>,
    /// The public key ciphertexts, one for each RNS modulus
    pub c: Vec<Ciphertext>,
    /// The decomposition size which is the number of RNS moduli (the l in lBFV).
    /// Note while l in https://eprint.iacr.org/2024/1285.pdf is equal to the size
    /// chosen of the Gadget vector, here it is equal the number of RNS moduli
    /// as the library uses the optimization of https://eprint.iacr.org/2018/117.pdf
    pub l: usize,
    /// Optional compression metadata: the seed that generates the same
    /// concrete `a_j` CRS polynomials as those stored in `c`. When absent
    /// (e.g. seedless deserialized or contributed keys), polynomial-level
    /// comparison is the sole consistency mechanism. When present, it is
    /// verified against the concrete polynomials at construction time.
    pub seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
    /// Optional key binding for distributed aggregation.
    pub(crate) binding: Option<LBFVKeyBinding>,
}

impl LBFVPublicKey {
    /// Generate a new [`LBFVPublicKey`] from a [`SecretKey`] using a provided
    /// seed. The seed is used to generate l seeds for the ciphertexts which are
    /// used to generate the random polynomials aᵢ for each ciphertext
    /// deterministically.
    pub fn new_with_seed<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Result<Self> {
        Self::new_with_seed_inner(sk, seed, rng)
    }

    /// Fallible version of [`new_with_seed`](Self::new_with_seed).
    ///
    /// Validates that the secret key's coefficient count matches the parameter
    /// degree before delegating.  Callers that should never panic (e.g.
    /// bound distributed-construction paths) must use this instead of the
    /// infallible [`new_with_seed`](Self::new_with_seed).
    fn new_with_seed_inner<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        rng: &mut R,
    ) -> Result<Self> {
        if sk.coeffs.len() != sk.params.degree() {
            return Err(Error::DefaultError(format!(
                "Secret key has {} coefficients, expected {}",
                sk.coeffs.len(),
                sk.params.degree()
            )));
        }

        let zero = Plaintext::zero(Encoding::poly(), &sk.params)?;
        let mut c: Vec<Ciphertext> = Vec::with_capacity(sk.params.moduli().len());
        let mut seed_rng = ChaCha8Rng::from_seed(seed);

        // Create a vector of ciphertexts, each encrypting zero, for each RNS modulus
        // [(b₁, a₁), ..., (bₗ, aₗ)].
        for _ in 0..sk.params.moduli().len() {
            let mut seed_i = <ChaCha8Rng as SeedableRng>::Seed::default();
            seed_rng.fill(&mut seed_i);
            let mut ct = sk.try_encrypt_with_seed(&zero, seed_i, rng)?;
            // The polynomials of a public key should not allow for variable time
            // computation.
            ct.c.iter_mut()
                .for_each(|p| p.disallow_variable_time_computations());
            c.push(ct);
        }

        Ok(Self {
            params: sk.params.clone(),
            c,
            l: sk.params.moduli().len(),
            seed: Some(seed),
            binding: None,
        })
    }

    /// Generate a new [`LBFVPublicKey`] from a [`SecretKey`] using a random
    /// seed.
    pub fn new<R: RngCore + CryptoRng>(sk: &SecretKey, rng: &mut R) -> Result<Self> {
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);
        Self::new_with_seed(sk, seed, rng)
    }

    /// Build an [`LBFVPublicKey`] from explicit `b` and `a` polynomials.
    ///
    /// This is the on-chain URS constructor: the caller supplies the
    /// polynomials directly rather than deriving them from a seed.
    ///
    /// # Arguments
    /// * `b_polynomials` - The `l` b-polynomials `(b₀, …, bₗ₋₁)` where
    ///   `bⱼ = -aⱼ·sk + eⱼ`.
    /// * `a_polynomials` - The `l` shared CRS polynomials `(a₀, …, aₗ₋₁)`.
    ///   These are the *concrete* shared-input polynomials whose equality must
    ///   be verifiable across all contributions and between the public key and
    ///   the relinearization key. Must be at the same context as the
    ///   `b_polynomials`.
    /// * `seed` - Optional CRS seed for backwards compatibility. When `None`,
    ///   the key carries no seed and polynomial-level comparisons are the sole
    ///   consistency check.
    pub fn from_parts(
        b_polynomials: Vec<Poly<Ntt>>,
        a_polynomials: Vec<Poly<Ntt>>,
        params: Arc<BfvParameters>,
        seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
    ) -> Result<Self> {
        if b_polynomials.len() != a_polynomials.len() {
            return Err(Error::DefaultError(
                "b and a polynomial vectors have different lengths".to_string(),
            ));
        }
        let l = b_polynomials.len();
        if l != params.moduli().len() {
            return Err(Error::DefaultError(format!(
                "Expected {} polynomial pairs (one per modulus), got {l}",
                params.moduli().len()
            )));
        }

        let ctx0 = params.context_at_level(0)?;
        let mut c: Vec<Ciphertext> = Vec::with_capacity(l);
        for (b_poly, a_poly) in b_polynomials.into_iter().zip(a_polynomials.into_iter()) {
            if b_poly.ctx() != ctx0 || a_poly.ctx() != ctx0 {
                return Err(Error::DefaultError(
                    "Public-key polynomials must be at level 0".to_string(),
                ));
            }
            let mut ct = Ciphertext {
                params: params.clone(),
                seed: None,
                c: vec![b_poly, a_poly],
                level: 0,
            };
            ct.c.iter_mut()
                .for_each(|p| p.disallow_variable_time_computations());
            c.push(ct);
        }

        // When a seed is provided, verify that the supplied a polynomials
        // match the concrete polynomials the seed would produce. A seed that
        // is inconsistent with the actual a polynomials would break CRS
        // consistency downstream (the b_vec and d2 cancellation in the
        // relinearization key relies on the same CRS a being used).
        if let Some(ref seed) = seed {
            let mut seed_rng = ChaCha8Rng::from_seed(*seed);
            for (j, ct) in c.iter().enumerate() {
                let mut seed_j = <ChaCha8Rng as SeedableRng>::Seed::default();
                seed_rng.fill(&mut seed_j);
                let expected_a = Poly::<Ntt>::random_from_seed(ctx0, seed_j);
                let actual_a = ct.c.get(1).ok_or_else(|| {
                    Error::DefaultError("Ciphertext is missing a component".to_string())
                })?;
                if expected_a != *actual_a {
                    return Err(Error::DefaultError(format!(
                        "Supplied seed does not match the concrete a polynomial at index {j}"
                    )));
                }
            }
        }

        Ok(Self {
            params,
            c,
            l,
            seed,
            binding: None,
        })
    }

    /// Compute one party's public-key contribution using explicit CRS
    /// polynomials `a_j` from the on-chain URS.
    ///
    /// Each party encrypts zero under their `sk_i` using the shared `a_j`:
    /// `b_j = -a_j·sk_i + e_j`, producing `l` ciphertexts `(b_j, a_j)`.
    /// The result is an [`LBFVPublicKey`] contribution meant to be fed into
    /// [`aggregate`](Self::aggregate).
    ///
    /// This mirrors [`new_with_seed`](Self::new_with_seed) but uses explicit
    /// polynomials instead of a seed, so `seed` is `None`.
    pub fn contribute<R: RngCore + CryptoRng>(
        sk_i: &SecretKey,
        a_polynomials: &[Poly<Ntt>],
        rng: &mut R,
    ) -> Result<Self> {
        let l = sk_i.params.moduli().len();
        if a_polynomials.len() != l {
            return Err(Error::DefaultError(format!(
                "Expected {l} a_polynomials (one per modulus), got {}",
                a_polynomials.len()
            )));
        }

        let ctx = sk_i.params.context_at_level(0)?;
        let s = Zeroizing::new(
            Poly::<PowerBasis>::try_convert_from(sk_i.coeffs.as_ref(), ctx, false)?.into_ntt(),
        );

        let mut c: Vec<Ciphertext> = Vec::with_capacity(l);
        for a_j in a_polynomials {
            if a_j.ctx() != ctx {
                return Err(Error::DefaultError(
                    "a polynomial has incorrect context".to_string(),
                ));
            }

            let a_s = Zeroizing::new(a_j * s.as_ref());
            let mut b = Poly::<Ntt>::small(ctx, sk_i.params.variance, rng)?;
            b -= a_s.as_ref();

            let mut ct = Ciphertext {
                params: sk_i.params.clone(),
                seed: None,
                c: vec![b, a_j.clone()],
                level: 0,
            };
            ct.c.iter_mut()
                .for_each(|p| p.disallow_variable_time_computations());
            c.push(ct);
        }

        Ok(Self {
            params: sk_i.params.clone(),
            c,
            l,
            seed: None,
            binding: None,
        })
    }

    // ---------------------------------------------------------------------------
    // Structural validation and safe accessors
    // ---------------------------------------------------------------------------

    /// Validate that the public-key structure is consistent: `l` matches the
    /// parameter modulus count, every ciphertext has exactly two components at
    /// level 0, and all polynomial contexts match the parameter's level-0 context.
    pub(crate) fn validate_structure(&self) -> Result<()> {
        let expected_l = self.params.moduli().len();
        if self.l != expected_l {
            return Err(Error::DefaultError(
                "LBFV public-key l does not match the parameter modulus count".to_string(),
            ));
        }
        if self.c.len() != expected_l {
            return Err(Error::DefaultError(
                "LBFV public-key ciphertext count does not match l".to_string(),
            ));
        }

        let ctx0 = self.params.context_at_level(0)?;
        for (index, ciphertext) in self.c.iter().enumerate() {
            if ciphertext.params != self.params {
                return Err(Error::DefaultError(format!(
                    "LBFV public-key ciphertext {index} has incompatible parameters"
                )));
            }
            if ciphertext.level != 0 {
                return Err(Error::DefaultError(format!(
                    "LBFV public-key ciphertext {index} is not at level 0"
                )));
            }
            if ciphertext.c.len() != 2 {
                return Err(Error::DefaultError(format!(
                    "LBFV public-key ciphertext {index} must have exactly two components"
                )));
            }
            for polynomial in &ciphertext.c {
                if polynomial.ctx() != ctx0 {
                    return Err(Error::DefaultError(format!(
                        "LBFV public-key ciphertext {index} has an incorrect polynomial context"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Returns the contribution binding for this key, or an error if the key
    /// is not a bound contribution.
    pub(crate) fn contribution_binding(&self) -> Result<&LBFVContributionBinding> {
        match self.binding.as_ref() {
            Some(LBFVKeyBinding::Contribution(binding)) => Ok(binding),
            _ => Err(Error::DefaultError(
                "LBFV public-key contribution is missing participant binding".to_string(),
            )),
        }
    }

    /// Returns the participant set for an aggregated bound key, or an error if
    /// the key is not an aggregate.
    pub(crate) fn aggregate_binding(&self) -> Result<&LBFVParticipantSet> {
        match self.binding.as_ref() {
            Some(LBFVKeyBinding::Aggregate(set)) => Ok(set),
            _ => Err(Error::DefaultError(
                "LBFV public key is not an aggregated bound key".to_string(),
            )),
        }
    }

    /// Extract the `a` polynomials from the first `ciphertext_level` ciphertexts
    /// for use as explicit CRS material.
    ///
    /// Currently requires `key_level == 0`.
    pub(crate) fn a_polynomials_for_level(
        &self,
        ciphertext_level: usize,
        key_level: usize,
    ) -> Result<Vec<Poly<NttShoup>>> {
        self.validate_structure()?;

        if key_level != 0 {
            return Err(Error::DefaultError(
                "Explicit l-BFV CRS extraction currently requires key level 0".to_string(),
            ));
        }
        if ciphertext_level > self.params.max_level() {
            return Err(Error::InvalidLevel {
                level: ciphertext_level,
                min_level: 0,
                max_level: self.params.max_level(),
            });
        }

        let count = self
            .l
            .checked_sub(ciphertext_level)
            .ok_or_else(|| Error::DefaultError("Invalid l-BFV ciphertext level".to_string()))?;

        self.c
            .iter()
            .take(count)
            .map(|ciphertext| {
                ciphertext
                    .c
                    .get(1)
                    .cloned()
                    .map(Poly::<Ntt>::into_ntt_shoup)
                    .ok_or_else(|| {
                        Error::DefaultError(
                            "LBFV public-key ciphertext is missing its a polynomial".to_string(),
                        )
                    })
            })
            .collect()
    }

    /// The participant set for this key, if any binding metadata is present.
    #[must_use]
    pub fn participant_set(&self) -> Option<&LBFVParticipantSet> {
        match self.binding.as_ref() {
            Some(LBFVKeyBinding::Contribution(binding)) => Some(binding.participant_set()),
            Some(LBFVKeyBinding::Aggregate(set)) => Some(set),
            None => None,
        }
    }

    // ---------------------------------------------------------------------------
    // Bound constructors
    // ---------------------------------------------------------------------------

    /// Generate a new [`LBFVPublicKey`] from a [`SecretKey`] using a provided
    /// seed and participant binding.
    ///
    /// Uses the fallible inner path so that a malformed `SecretKey` (coefficient
    /// count ≠ parameter degree) produces an `Err` instead of a panic.
    pub fn new_with_seed_and_binding<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
        binding: LBFVContributionBinding,
        rng: &mut R,
    ) -> Result<Self> {
        let mut key = Self::new_with_seed_inner(sk, seed, rng)?;
        key.binding = Some(LBFVKeyBinding::Contribution(binding));
        key.validate_structure()?;
        Ok(key)
    }

    /// Compute one party's public-key contribution using explicit CRS
    /// polynomials `a_j` and a participant binding.
    pub fn contribute_with_binding<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        a_polynomials: &[Poly<Ntt>],
        binding: LBFVContributionBinding,
        rng: &mut R,
    ) -> Result<Self> {
        let mut key = Self::contribute(sk, a_polynomials, rng)?;
        key.binding = Some(LBFVKeyBinding::Contribution(binding));
        key.validate_structure()?;
        Ok(key)
    }

    /// Build an [`LBFVPublicKey`] from explicit `b` and `a` polynomials with a
    /// participant binding.
    pub fn from_parts_with_binding(
        b_polynomials: Vec<Poly<Ntt>>,
        a_polynomials: Vec<Poly<Ntt>>,
        params: Arc<BfvParameters>,
        seed: Option<<ChaCha8Rng as SeedableRng>::Seed>,
        binding: LBFVContributionBinding,
    ) -> Result<Self> {
        let mut key = Self::from_parts(b_polynomials, a_polynomials, params, seed)?;
        key.binding = Some(LBFVKeyBinding::Contribution(binding));
        key.validate_structure()?;
        Ok(key)
    }

    /// Generate a new [`LBFVPublicKey`] from a [`SecretKey`] using an explicit
    /// [`LBFVCommonReferenceString`].
    ///
    /// This is the preferred constructor when following the paper's protocol:
    /// the CRS `a = (a₀,...,a_{l-1})` is a first-class shared object established
    /// by coin-tossing, and the same `crs` is passed to every party and to
    /// [`LBFVRelinKeyShare::contribution_from_crs`].
    pub fn new_from_crs<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        crs: &LBFVCommonReferenceString,
        rng: &mut R,
    ) -> Result<Self> {
        Self::new_with_seed(sk, crs.seed, rng)
    }

    // ---------------------------------------------------------------------------
    // Aggregation
    // ---------------------------------------------------------------------------

    /// Aggregate per-node public-key contributions into the threshold public key
    /// (DKG aggregation, Eq. (3) of §5.1 of
    /// [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf)).
    ///
    /// Each contribution is itself an [`LBFVPublicKey`] built by a single node
    /// from its secret-key contribution `sk_i` and the common CRS seed, i.e.
    /// `LBFVPublicKey::new_with_seed(sk_i, shared_seed, rng)`. A contribution is
    /// therefore `l` encryptions of zero `(b_{i,j}, a_j) = (-a_j·sk_i + e_{i,j},
    /// a_j)`, all sharing the CRS `a_j` derived from `shared_seed`.
    ///
    /// Aggregation sums the `b` components coordinate-wise and keeps the shared
    /// `a`:
    /// ```text
    ///   b_j = Σ_i b_{i,j} = -a_j·(Σ_i sk_i) + Σ_i e_{i,j} = -a_j·sk + e_j
    /// ```
    /// so the result is `l` encryptions of zero under the joint key
    /// `sk = Σ_i sk_i`, sharing the same CRS `a`. Component `[0]` doubles as the
    /// encryption key `(b_0, a_0)`, while the `b`-polynomials of all `l`
    /// components form the relinearization `b_vec` (via
    /// [`extract_b_polynomials`](Self::extract_b_polynomials)). Crucially, `sk`
    /// is never assembled: each node only ever holds its own `sk_i`.
    ///
    /// The shared seed is carried over to the result, so the same CRS `a` is
    /// reused when building the relinearization key's `d2` (it must match! see
    /// [`LBFVRelinKeyShare`](super::LBFVRelinKeyShare)).
    ///
    /// # Participant binding requirement
    ///
    /// Every contribution must carry an [`LBFVContributionBinding`] metadata
    /// created with the same [`LBFVParticipantSet`].  All participant IDs in
    /// the set must appear exactly once (no duplicates, no missing IDs), and
    /// all contributions must share the same concrete CRS polynomials `a_j`.
    /// The resulting key carries `LBFVKeyBinding::Aggregate`.
    ///
    /// # Errors
    /// Returns an error if `contributions` is empty, if any contribution is
    /// structurally malformed, if bindings are missing/inconsistent, or if the
    /// CRS polynomials do not match.
    pub fn aggregate(contributions: &[LBFVPublicKey]) -> Result<Self> {
        let (first, rest) = contributions.split_first().ok_or_else(|| {
            Error::DefaultError("Cannot aggregate zero public-key contributions".to_string())
        })?;

        first.validate_structure()?;
        for contribution in rest {
            contribution.validate_structure()?;
        }

        let bindings = contributions
            .iter()
            .map(LBFVPublicKey::contribution_binding)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let first_binding = bindings.first().ok_or_else(|| {
            Error::DefaultError("Cannot aggregate zero public-key contributions".to_string())
        })?;
        let participant_set = first_binding.participant_set().clone();
        participant_set.validate_contributions(bindings.iter().copied())?;

        if rest.iter().any(|key| key.params != first.params) {
            return Err(Error::DefaultError(
                "LBFV public-key contributions use different parameters".to_string(),
            ));
        }

        // Verify that the actual a_j (c[1]) polynomials match across all
        // contributions.  This is the concrete CRS check that seed equality
        // alone cannot guarantee (e.g. seedless deserialized keys).
        for (j, first_ct) in first.c.iter().enumerate() {
            let a_first = first_ct.c.get(1).ok_or_else(|| {
                Error::DefaultError("LBFV public-key ciphertext is missing a".to_string())
            })?;
            for contribution in rest {
                let ct_j = contribution.c.get(j).ok_or_else(|| {
                    Error::DefaultError("LBFV public-key ciphertext count changed".to_string())
                })?;
                let a_other = ct_j.c.get(1).ok_or_else(|| {
                    Error::DefaultError("LBFV public-key ciphertext is missing a".to_string())
                })?;
                if a_first != a_other {
                    return Err(Error::DefaultError(
                        "LBFV public-key contributions use different CRS polynomials".to_string(),
                    ));
                }
            }
        }

        let mut ciphertexts = Vec::with_capacity(first.c.len());
        for (index, first_ciphertext) in first.c.iter().enumerate() {
            let mut b = first_ciphertext.c.first().cloned().ok_or_else(|| {
                Error::DefaultError("LBFV public-key ciphertext is missing b".to_string())
            })?;
            let a = first_ciphertext.c.get(1).cloned().ok_or_else(|| {
                Error::DefaultError("LBFV public-key ciphertext is missing a".to_string())
            })?;

            for contribution in rest {
                let contribution_ciphertext = contribution.c.get(index).ok_or_else(|| {
                    Error::DefaultError("LBFV public-key ciphertext count changed".to_string())
                })?;
                let contribution_b = contribution_ciphertext.c.first().ok_or_else(|| {
                    Error::DefaultError("LBFV public-key ciphertext is missing b".to_string())
                })?;
                b += contribution_b;
            }

            let mut ciphertext = Ciphertext {
                params: first.params.clone(),
                seed: None,
                c: vec![b, a],
                level: 0,
            };
            ciphertext
                .c
                .iter_mut()
                .for_each(|polynomial| polynomial.disallow_variable_time_computations());
            ciphertexts.push(ciphertext);
        }

        let shared_seed = first.seed.filter(|seed| {
            contributions
                .iter()
                .all(|contribution| contribution.seed == Some(*seed))
        });

        Ok(Self {
            params: first.params.clone(),
            c: ciphertexts,
            l: first.l,
            seed: shared_seed,
            binding: Some(LBFVKeyBinding::Aggregate(participant_set)),
        })
    }

    /// Encrypt a plaintext with the public key.
    /// The encryption is done in the same level as the plaintext.
    /// Returns the ciphertext and the noise polynomials.
    #[allow(clippy::type_complexity)]
    pub fn try_encrypt_extended<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<(Ciphertext, Poly<Ntt>, Poly<Ntt>, Poly<Ntt>)> {
        // Validate public-key structure before using it for encryption.
        self.validate_structure()?;

        // Use only the first ciphertext from the array
        let mut ct = self.c.first().cloned().ok_or_else(|| {
            Error::DefaultError("Public key has no ciphertexts available".to_string())
        })?;
        while ct.level != pt.level {
            ct.switch_down()?;
        }

        let ctx = self.params.context_at_level(ct.level)?;
        let u = Poly::<Ntt>::small(ctx, self.params.variance, rng)?;
        let e1 = Poly::<Ntt>::small(ctx, self.params.variance, rng)?;
        let e2 = Poly::<Ntt>::small(ctx, self.params.variance, rng)?;

        let m = Zeroizing::new(pt.to_poly());
        let b = ct
            .c
            .first()
            .ok_or_else(|| Error::DefaultError("Ciphertext is missing b component".to_string()))?;
        let a = ct
            .c
            .get(1)
            .ok_or_else(|| Error::DefaultError("Ciphertext is missing a component".to_string()))?;
        let mut c0 = u.as_ref() * b;
        c0 += &e1;
        c0 += &m;
        let mut c1 = u.as_ref() * a;
        c1 += &e2;

        // It is now safe to enable variable time computations.
        unsafe {
            c0.allow_variable_time_computations();
            c1.allow_variable_time_computations()
        }

        let ciphertext = Ciphertext {
            params: self.params.clone(),
            seed: None,
            c: vec![c0, c1],
            level: ct.level,
        };

        Ok((ciphertext, u, e1, e2))
    }

    /// Extract the b polynomials from the ciphertexts in the public key at a specified key level and representation.
    ///
    /// This method extracts the first l = # moduli - ciphertext level, c[0] components from each ciphertext in the public key,
    /// mod switches them to the key level, and converts them to the specified representation.
    ///
    /// # Arguments
    /// * `ciphertext_level` - The level of the ciphertext that will use these polynomials
    /// * `key_level` - The level of the key that will be used (currently must be 0)
    /// * `rep` - The desired representation for the output polynomials
    ///
    /// # Returns
    /// * `Ok(Vec<Poly>)` - A vector of polynomials in the specified representation at the target level
    /// * `Err` if:
    ///   - The requested ciphertext level is greater than the maximum level
    ///   - The key level is not 0 (current limitation)
    ///   - The public key is not at level 0
    ///   - Any polynomial operations fail during mod switching or representation changes
    // self.c[0..new_l] is always valid (self.c has self.l elements, new_l <= self.l)
    pub fn extract_b_polynomials(
        &self,
        ciphertext_level: usize,
        key_level: usize,
        rep: Representation,
    ) -> Result<Vec<Poly<NttShoup>>> {
        // Validate public-key structure before accessing ciphertexts.
        self.validate_structure()?;

        // Necessary checks
        if ciphertext_level > self.params.max_level() {
            return Err(Error::DefaultError(
                "Level is greater than the maximum level".to_string(),
            ));
        }

        // Note: this may seem redundant, but it's because in the future, we want to experiment with different key levels
        // for the public key.
        if key_level != 0 {
            return Err(Error::DefaultError("Key level must be 0".to_string()));
        }

        let key_ctx = self.params.context_at_level(key_level)?;
        let first_ct = self
            .c
            .first()
            .ok_or_else(|| Error::DefaultError("Public key has no ciphertexts".to_string()))?;
        let first_b = first_ct.c.first().ok_or_else(|| {
            Error::DefaultError("Public-key ciphertext is missing b component".to_string())
        })?;
        if first_b.ctx() != key_ctx {
            return Err(Error::DefaultError(
                "Public key is not at level 0".to_string(),
            ));
        }

        // Note: key switching is redundant for now.
        // Create switcher to mod switch from initial to final context (for when public key is at different level than ciphertext)
        let ciphertext_ctx = self.params.context_at_level(ciphertext_level)?;
        let switcher = Switcher::new(ciphertext_ctx, key_ctx)?;

        // Extract (l - level) b polynomials and change representation accordingly
        let new_l = self
            .l
            .checked_sub(ciphertext_level)
            .ok_or_else(|| Error::DefaultError("Invalid l-BFV ciphertext level".to_string()))?;
        let mut b_polynomials = Vec::with_capacity(new_l);
        for i in 0..new_l {
            let ct = self.c.get(i).ok_or_else(|| {
                Error::DefaultError("Public-key ciphertext index out of bounds".to_string())
            })?;
            let mut poly = ct.c.first().cloned().ok_or_else(|| {
                Error::DefaultError("Public-key ciphertext is missing b component".to_string())
            })?;
            if poly.ctx() != key_ctx {
                poly = poly.switch(&switcher)?;
            }
            let poly = match rep {
                Representation::NttShoup => poly.into_ntt_shoup(),
                Representation::PowerBasis | Representation::Ntt => {
                    return Err(Error::DefaultError(
                        "l-BFV extract_b_polynomials requires NttShoup representation".to_string(),
                    ));
                }
            };
            b_polynomials.push(poly);
        }
        Ok(b_polynomials)
    }
}

impl FheParametrized for LBFVPublicKey {
    type Parameters = BfvParameters;
}

impl FheEncrypter<Plaintext, Ciphertext> for LBFVPublicKey {
    type Error = Error;

    fn try_encrypt<R: RngCore + CryptoRng>(
        &self,
        pt: &Plaintext,
        rng: &mut R,
    ) -> Result<Ciphertext> {
        // Validate public-key structure before using it for encryption.
        self.validate_structure()?;

        // Use only the first ciphertext from the array
        let mut ct = self.c.first().cloned().ok_or_else(|| {
            Error::DefaultError("Public key has no ciphertexts available".to_string())
        })?;
        while ct.level != pt.level {
            ct.switch_down()?;
        }

        let ctx = self.params.context_at_level(ct.level)?;
        let u = Zeroizing::new(Poly::<Ntt>::small(ctx, self.params.variance, rng)?);
        let e1 = Zeroizing::new(Poly::<Ntt>::small(ctx, self.params.variance, rng)?);
        let e2 = Zeroizing::new(Poly::<Ntt>::small(ctx, self.params.variance, rng)?);

        let m = Zeroizing::new(pt.to_poly());
        let b = ct
            .c
            .first()
            .ok_or_else(|| Error::DefaultError("Ciphertext is missing b component".to_string()))?;
        let a = ct
            .c
            .get(1)
            .ok_or_else(|| Error::DefaultError("Ciphertext is missing a component".to_string()))?;
        let mut c0 = u.as_ref() * b;
        c0 += &e1;
        c0 += &m;
        let mut c1 = u.as_ref() * a;
        c1 += &e2;

        // It is now safe to enable variable time computations.
        unsafe {
            c0.allow_variable_time_computations();
            c1.allow_variable_time_computations()
        }

        Ok(Ciphertext {
            params: self.params.clone(),
            seed: None,
            c: vec![c0, c1],
            level: ct.level,
        })
    }
}

#[cfg(feature = "protobuf")]
mod protobuf {
    use super::*;
    use crate::SerializationError;
    use crate::bfv::traits::TryConvertFrom;
    use crate::proto::bfv::{Ciphertext as CiphertextProto, LbfvPublicKey as LBFVPublicKeyProto};
    use fhe_traits::{DeserializeParametrized, Serialize};
    use prost::Message;

    impl From<&LBFVPublicKey> for LBFVPublicKeyProto {
        fn from(pk: &LBFVPublicKey) -> Self {
            LBFVPublicKeyProto {
                c: pk.c.iter().map(CiphertextProto::from).collect(),
                l: pk.l as u32,
                seed: pk.seed.map_or_else(Vec::new, |s| s.to_vec()),
                binding: pk
                    .binding
                    .as_ref()
                    .map(crate::lbfv::keys::binding::proto_helpers::key_binding_to_proto),
            }
        }
    }

    impl Serialize for LBFVPublicKey {
        fn to_bytes(&self) -> Vec<u8> {
            LBFVPublicKeyProto::from(self).encode_to_vec()
        }
    }

    impl DeserializeParametrized for LBFVPublicKey {
        type Error = Error;

        fn from_bytes(bytes: &[u8], par: &Arc<Self::Parameters>) -> Result<Self> {
            let proto: LBFVPublicKeyProto = Message::decode(bytes).map_err(|e| {
                Error::SerializationError(SerializationError::ProtobufError {
                    message: e.to_string(),
                })
            })?;

            if proto.c.is_empty() {
                return Err(Error::SerializationError(
                    SerializationError::InvalidFormat {
                        reason: "LBFV public key has no ciphertexts".to_string(),
                    },
                ));
            }

            let proto_l = proto.l as usize;
            let expected_l = par.moduli().len();

            // Validate that l matches the parameter modulus count
            if proto_l != expected_l {
                return Err(Error::SerializationError(
                    SerializationError::InvalidFormat {
                        reason: format!(
                            "LBFV public-key l={proto_l} does not match the parameter modulus count={expected_l}"
                        ),
                    },
                ));
            }

            // Validate that l matches the number of ciphertexts
            if proto.c.len() != proto_l {
                return Err(Error::SerializationError(
                    SerializationError::InvalidFormat {
                        reason: format!(
                            "LBFV public-key l={proto_l} does not match the ciphertext count={}",
                            proto.c.len()
                        ),
                    },
                ));
            }

            let mut c: Vec<Ciphertext> = Vec::with_capacity(proto.c.len());
            for ct_proto in proto.c {
                let mut ct = Ciphertext::try_convert_from(&ct_proto, par)?;
                if ct.level != 0 {
                    return Err(Error::SerializationError(
                        SerializationError::InvalidFormat {
                            reason: "LBFV public key ciphertext must be at level 0".to_string(),
                        },
                    ));
                }
                // The polynomials of a public key should not allow for variable time
                // computation.
                ct.c.iter_mut()
                    .for_each(|p| p.disallow_variable_time_computations());
                c.push(ct);
            }

            // Import the seed if it exists
            let seed = if !proto.seed.is_empty() {
                let mut seed_array = <ChaCha8Rng as SeedableRng>::Seed::default();
                if proto.seed.len() != seed_array.len() {
                    return Err(Error::SerializationError(
                        SerializationError::InvalidFormat {
                            reason: "Invalid LBFV public key seed length".to_string(),
                        },
                    ));
                }
                seed_array.copy_from_slice(&proto.seed);
                Some(seed_array)
            } else {
                None
            };

            // Decode the binding, preserving backward compatibility
            let binding = crate::lbfv::keys::binding::proto_helpers::key_binding_from_proto(
                proto.binding.as_ref(),
            )?;

            let key = Self {
                params: par.clone(),
                c,
                l: proto.l as usize,
                seed,
                binding,
            };

            // Validate that the seed, when present, reproduces the concrete a
            // polynomials. A mismatched seed breaks CRS consistency downstream.
            if let Some(ref seed) = key.seed {
                let ctx0 = key.params.context_at_level(0)?;
                let mut seed_rng = ChaCha8Rng::from_seed(*seed);
                for (j, ct) in key.c.iter().enumerate() {
                    let mut seed_j = <ChaCha8Rng as SeedableRng>::Seed::default();
                    seed_rng.fill(&mut seed_j);
                    let expected_a = Poly::<Ntt>::random_from_seed(ctx0, seed_j);
                    let actual_a = ct.c.get(1).ok_or_else(|| {
                        Error::DefaultError("Ciphertext is missing a component".to_string())
                    })?;
                    if expected_a != *actual_a {
                        return Err(Error::SerializationError(
                            crate::SerializationError::InvalidFormat {
                                reason: format!(
                                    "Tampered seed: derived a_j does not match serialized a_j at index {j}"
                                ),
                            },
                        ));
                    }
                }
            }

            // Structural validation before returning
            key.validate_structure()?;

            Ok(key)
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::super::{LBFVContributionBinding, LBFVParticipantSet};
    use super::super::{LBFVRelinKeyShare, LBFVRelinearizationKey};
    use super::LBFVPublicKey;
    use crate::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};
    use fhe_math::rq::{Ntt, Poly, Representation};
    use fhe_math::zq::Modulus;
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
    use rand::{Rng, SeedableRng, rng};
    use rand_chacha::ChaCha8Rng;
    use std::error::Error;

    #[test]
    fn test_aggregate_public_key() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let n = 3;

        // Common participant set and session.
        let participant_set = LBFVParticipantSet::new([7u8; 32], (1..=n as u32).collect())?;

        // Common CRS seed shared by all nodes.
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);

        // Per-node secret-key contributions, and the matching public-key
        // contributions (l zero-encryptions under sk_i with the shared seed).
        let sk_shares: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let contributions: Vec<LBFVPublicKey> = sk_shares
            .iter()
            .enumerate()
            .map(|(i, sk_i)| {
                let binding =
                    LBFVContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                LBFVPublicKey::new_with_seed_and_binding(sk_i, seed, binding, &mut rng)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;

        // Joint secret key, assembled only to check decryption in this test.
        let mut sum_coeffs = vec![0i64; params.degree()];
        for sk in &sk_shares {
            for (acc, c) in sum_coeffs.iter_mut().zip(sk.coeffs.iter()) {
                *acc = acc.wrapping_add(*c);
            }
        }
        let sk_joint = SecretKey::new(sum_coeffs, &params);

        let pk = LBFVPublicKey::aggregate(&contributions)?;

        // The aggregated key carries the shared CRS seed and the right l.
        assert_eq!(pk.seed, Some(seed));
        assert_eq!(pk.l, params.moduli().len());
        assert_eq!(pk.c.len(), params.moduli().len());

        // All l zero-encryptions decrypt to zero under the joint key.
        for ct in pk.c.iter() {
            assert_eq!(
                sk_joint.try_decrypt(ct)?,
                Plaintext::zero(Encoding::poly(), &params)?
            );
        }

        // Encrypt/decrypt roundtrip under the aggregated public key.
        let pt = Plaintext::try_encode(
            &Modulus::new(params.plaintext())?.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        assert_eq!(sk_joint.try_decrypt(&ct)?, pt);

        // A contribution under a different CRS seed must be rejected.
        let mut other_seed = seed;
        other_seed[0] ^= 0xff;
        let bad_binding = LBFVContributionBinding::new(participant_set.clone(), 1)?;
        let bad = LBFVPublicKey::new_with_seed_and_binding(
            &sk_shares[0],
            other_seed,
            bad_binding,
            &mut rng,
        )?;
        // Duplicate participant ID (both have ID 1) should be rejected.
        assert!(LBFVPublicKey::aggregate(&[contributions[0].clone(), bad]).is_err());

        Ok(())
    }

    #[test]
    fn keygen() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(1, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;
        assert_eq!(pk.params, params);
        // Check that l matches number of moduli
        assert_eq!(pk.l, params.moduli().len());
        // Check that all ciphertexts decrypt to zero
        for ct in pk.c.iter() {
            assert_eq!(
                sk.try_decrypt(ct)?,
                Plaintext::zero(Encoding::poly(), &params)?
            );
        }
        Ok(())
    }

    #[test]
    fn encrypt_decrypt() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        for params in [
            BfvParameters::default_arc(1, 8),
            BfvParameters::default_arc(6, 8),
        ] {
            for level in 0..params.max_level() {
                for _ in 0..20 {
                    let sk = SecretKey::random(&params, &mut rng);
                    let pk = LBFVPublicKey::new(&sk, &mut rng)?;

                    let pt = Plaintext::try_encode(
                        &Modulus::new(params.plaintext())?.random_vec(params.degree(), &mut rng),
                        Encoding::poly_at_level(level),
                        &params,
                    )?;
                    let ct = pk.try_encrypt(&pt, &mut rng)?;
                    let pt2 = sk.try_decrypt(&ct)?;

                    println!("Noise: {}", unsafe { sk.measure_noise(&ct)? });
                    assert_eq!(pt2, pt);
                }
            }
        }

        Ok(())
    }

    #[cfg(feature = "protobuf")]
    mod protobuf {
        use super::*;
        use crate::proto::bfv::LbfvPublicKey as LBFVPublicKeyProto;
        use fhe_traits::{DeserializeParametrized, Serialize};
        use prost::Message;

        #[test]
        fn test_serialize() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            for params in [
                BfvParameters::default_arc(1, 8),
                BfvParameters::default_arc(6, 8),
            ] {
                let sk = SecretKey::random(&params, &mut rng);
                let pk = LBFVPublicKey::new(&sk, &mut rng)?;
                let bytes = pk.to_bytes();
                assert_eq!(pk, LBFVPublicKey::from_bytes(&bytes, &params)?);
            }
            Ok(())
        }

        #[test]
        fn test_bound_public_key_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let set = LBFVParticipantSet::new([70u8; 32], vec![1, 2])?;
            let binding = LBFVContributionBinding::new(set, 1)?;
            let pk = LBFVPublicKey::new_with_seed_and_binding(&sk, [71u8; 32], binding, &mut rng)?;
            let bytes = pk.to_bytes();
            let decoded = LBFVPublicKey::from_bytes(&bytes, &params)?;
            assert_eq!(pk, decoded);
            Ok(())
        }

        #[test]
        fn test_malformed_l_rejected() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let pk = LBFVPublicKey::new(&sk, &mut rng)?;

            let mut proto: LBFVPublicKeyProto = LBFVPublicKeyProto::from(&pk);
            proto.l = 1; // Malformed: l should be the number of moduli
            let bytes = proto.encode_to_vec();
            assert!(LBFVPublicKey::from_bytes(&bytes, &params).is_err());

            // Also test: l doesn't match ciphertext count
            let mut proto2: LBFVPublicKeyProto = LBFVPublicKeyProto::from(&pk);
            proto2.c.pop(); // Remove one ciphertext but leave l unchanged
            let bytes2 = proto2.encode_to_vec();
            assert!(LBFVPublicKey::from_bytes(&bytes2, &params).is_err());

            Ok(())
        }

        #[test]
        fn test_aggregate_binding_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let set = LBFVParticipantSet::new([72u8; 32], vec![1, 2])?;
            let keys: Vec<SecretKey> = (0..2)
                .map(|_| SecretKey::random(&params, &mut rng))
                .collect();

            let contributions: Vec<LBFVPublicKey> = keys
                .iter()
                .enumerate()
                .map(|(i, sk)| {
                    let binding = LBFVContributionBinding::new(set.clone(), (i + 1) as u32)?;
                    LBFVPublicKey::new_with_seed_and_binding(sk, [73u8; 32], binding, &mut rng)
                })
                .collect::<std::result::Result<_, _>>()?;

            let pk = LBFVPublicKey::aggregate(&contributions)?;
            let bytes = pk.to_bytes();
            let decoded = LBFVPublicKey::from_bytes(&bytes, &params)?;
            assert_eq!(pk, decoded);

            // Verify the participant set is preserved.
            assert_eq!(decoded.participant_set(), Some(&set));

            Ok(())
        }

        /// A serialized public key with a tampered seed that does not match the
        /// concrete `a` polynomials must be rejected during deserialization.
        #[test]
        fn test_tampered_seed_rejected() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let pk = LBFVPublicKey::new(&sk, &mut rng)?;

            // Serialize the valid PK to proto, then replace the seed with a
            // different one that does not reproduce the concrete a_j.
            let mut proto: LBFVPublicKeyProto = LBFVPublicKeyProto::from(&pk);
            proto.seed = vec![0u8; 32]; // A seed that does not match the a_j

            let bytes = proto.encode_to_vec();
            assert!(
                LBFVPublicKey::from_bytes(&bytes, &params).is_err(),
                "PK deserialization must reject a tampered seed"
            );

            // A seedless PK with no seed must still be accepted.
            let mut seedless_proto = LBFVPublicKeyProto::from(&pk);
            seedless_proto.seed.clear();
            let seedless_bytes = seedless_proto.encode_to_vec();
            let seedless_pk = LBFVPublicKey::from_bytes(&seedless_bytes, &params)?;
            assert!(seedless_pk.seed.is_none(), "Seedless PK must carry no seed");

            Ok(())
        }

        /// A truly seedless bound public key built via `from_parts_with_binding`
        /// (seed `None`, `a` carried inline) must round-trip with its binding.
        #[test]
        fn test_seedless_from_parts_with_binding_roundtrip()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);

            let pk_seeded = LBFVPublicKey::new(&sk, &mut rng)?;
            let b_polys: Vec<Poly<Ntt>> = pk_seeded.c.iter().map(|ct| ct.c[0].clone()).collect();
            let a_polys: Vec<Poly<Ntt>> = pk_seeded.c.iter().map(|ct| ct.c[1].clone()).collect();

            let set = LBFVParticipantSet::new([80u8; 32], vec![1, 2])?;
            let binding = LBFVContributionBinding::new(set.clone(), 1)?;
            let pk = LBFVPublicKey::from_parts_with_binding(
                b_polys,
                a_polys,
                params.clone(),
                None,
                binding,
            )?;
            assert!(
                pk.seed.is_none(),
                "from_parts_with_binding(None) must be seedless"
            );

            let bytes = pk.to_bytes();
            let decoded = LBFVPublicKey::from_bytes(&bytes, &params)?;
            assert_eq!(pk, decoded);
            assert!(
                decoded.seed.is_none(),
                "decoded seedless PK must carry no seed"
            );

            Ok(())
        }

        /// Malformed binding metadata carried by a serialized public key must be
        /// rejected at deserialization: bad session length, duplicate IDs, an
        /// empty participant set, and an aggregate/participant_id inconsistency.
        #[test]
        fn test_malformed_binding_rejected() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = rng();
            let params = BfvParameters::default_arc(6, 8);
            let sk = SecretKey::random(&params, &mut rng);
            let set = LBFVParticipantSet::new([81u8; 32], vec![1, 2])?;
            let binding = LBFVContributionBinding::new(set, 1)?;
            let pk = LBFVPublicKey::new_with_seed_and_binding(&sk, [82u8; 32], binding, &mut rng)?;

            // Wrong session_id length.
            let mut p = LBFVPublicKeyProto::from(&pk);
            p.binding.as_mut().unwrap().session_id = vec![0u8; 31];
            assert!(
                LBFVPublicKey::from_bytes(&p.encode_to_vec(), &params).is_err(),
                "31-byte session_id must be rejected"
            );

            // Duplicate participant IDs.
            let mut p = LBFVPublicKeyProto::from(&pk);
            p.binding.as_mut().unwrap().participant_ids = vec![1, 1];
            assert!(
                LBFVPublicKey::from_bytes(&p.encode_to_vec(), &params).is_err(),
                "duplicate participant IDs must be rejected"
            );

            // Empty participant set.
            let mut p = LBFVPublicKeyProto::from(&pk);
            p.binding.as_mut().unwrap().participant_ids = vec![];
            assert!(
                LBFVPublicKey::from_bytes(&p.encode_to_vec(), &params).is_err(),
                "empty participant set must be rejected"
            );

            // Aggregate flag set but participant_id nonzero.
            let mut p = LBFVPublicKeyProto::from(&pk);
            {
                let b = p.binding.as_mut().unwrap();
                b.aggregate = true;
                b.participant_id = 1;
            }
            assert!(
                LBFVPublicKey::from_bytes(&p.encode_to_vec(), &params).is_err(),
                "aggregate binding with nonzero participant_id must be rejected"
            );

            Ok(())
        }
    }

    #[test]
    fn test_from_parts_roundtrip() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);

        let pk_seeded = LBFVPublicKey::new(&sk, &mut rng)?;
        let b_polys: Vec<Poly<Ntt>> = pk_seeded.c.iter().map(|ct| ct.c[0].clone()).collect();
        let a_polys: Vec<Poly<Ntt>> = pk_seeded.c.iter().map(|ct| ct.c[1].clone()).collect();
        let pk_from_parts =
            LBFVPublicKey::from_parts(b_polys, a_polys, params.clone(), pk_seeded.seed)?;

        // Roundtrip encrypt/decrypt under the from_parts key.
        let pt = Plaintext::try_encode(&[42u64], Encoding::poly(), &params)?;
        let ct = pk_from_parts.try_encrypt(&pt, &mut rng)?;
        assert_eq!(sk.try_decrypt(&ct)?, pt);

        // All l zero-encryptions decrypt to zero.
        for ct in pk_from_parts.c.iter() {
            assert_eq!(
                sk.try_decrypt(ct)?,
                Plaintext::zero(Encoding::poly(), &params)?
            );
        }

        Ok(())
    }

    /// `from_parts` must reject a seed that does not reproduce the concrete `a`
    /// polynomials — a mismatched seed breaks CRS consistency downstream.
    #[test]
    fn from_parts_rejects_inconsistent_seed() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);

        let pk_seeded = LBFVPublicKey::new(&sk, &mut rng)?;
        let b_polys: Vec<Poly<Ntt>> = pk_seeded.c.iter().map(|ct| ct.c[0].clone()).collect();
        let a_polys: Vec<Poly<Ntt>> = pk_seeded.c.iter().map(|ct| ct.c[1].clone()).collect();

        // A seed different from the one that produced those a_polys.
        let mut bad_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut bad_seed);
        // Ensure it's actually different.
        if Some(bad_seed) == pk_seeded.seed {
            bad_seed[0] ^= 0xff;
        }

        let result = LBFVPublicKey::from_parts(b_polys, a_polys, params.clone(), Some(bad_seed));
        assert!(
            result.is_err(),
            "from_parts must reject a seed that is inconsistent with the concrete a polynomials"
        );

        // The correct seed must still be accepted.
        assert!(
            LBFVPublicKey::from_parts(
                pk_seeded.c.iter().map(|ct| ct.c[0].clone()).collect(),
                pk_seeded.c.iter().map(|ct| ct.c[1].clone()).collect(),
                params,
                pk_seeded.seed,
            )
            .is_ok()
        );

        Ok(())
    }

    #[test]
    fn test_contribute_and_aggregate() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let n = 3;

        let participant_set = LBFVParticipantSet::new([11u8; 32], (1..=n as u32).collect())?;

        // Generate shared CRS a polynomials from a seed (simulating on-chain URS).
        let a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let pk_ref =
            LBFVPublicKey::new_with_seed(&SecretKey::random(&params, &mut rng), a_seed, &mut rng)?;
        let a_polys: Vec<Poly<Ntt>> = pk_ref.c.iter().map(|ct| ct.c[1].clone()).collect();

        // Each party contributes using the shared a_polys.
        let sk_shares: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();
        let contributions: Vec<LBFVPublicKey> = sk_shares
            .iter()
            .enumerate()
            .map(|(i, sk_i)| {
                let binding =
                    LBFVContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                LBFVPublicKey::contribute_with_binding(sk_i, &a_polys, binding, &mut rng)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let pk = LBFVPublicKey::aggregate(&contributions)?;

        // Verify: seed is None (from explicit polynomials) and a_j match the reference.
        assert!(pk.seed.is_none());
        for (j, ct) in pk.c.iter().enumerate() {
            assert_eq!(ct.c[1], a_polys[j]);
        }

        // Joint secret key for decryption.
        let mut sum_coeffs = vec![0i64; params.degree()];
        for sk in &sk_shares {
            for (acc, c) in sum_coeffs.iter_mut().zip(sk.coeffs.iter()) {
                *acc = acc.wrapping_add(*c);
            }
        }
        let sk_joint = SecretKey::new(sum_coeffs, &params);

        let pt = Plaintext::try_encode(&[7u64], Encoding::poly(), &params)?;
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        assert_eq!(sk_joint.try_decrypt(&ct)?, pt);

        Ok(())
    }

    #[test]
    fn test_aggregate_rejects_inconsistent_a_polys() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let n = 2;

        let participant_set = LBFVParticipantSet::new([13u8; 32], (1..=n as u32).collect())?;

        let a_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        let pk_ref =
            LBFVPublicKey::new_with_seed(&SecretKey::random(&params, &mut rng), a_seed, &mut rng)?;
        let a_polys: Vec<Poly<Ntt>> = pk_ref.c.iter().map(|ct| ct.c[1].clone()).collect();

        let sk = SecretKey::random(&params, &mut rng);
        let binding1 = LBFVContributionBinding::new(participant_set.clone(), 1)?;
        let c1 = LBFVPublicKey::contribute_with_binding(&sk, &a_polys, binding1, &mut rng)?;

        // Create a contribution with a tampered a polynomial.
        let mut bad_a = a_polys.to_vec();
        let ctx0 = params.context_at_level(0)?;
        bad_a[0] = Poly::<Ntt>::small(ctx0, params.variance, &mut rng)?; // random replacement
        let mut bad_cts = c1.c.clone();
        bad_cts[0].c[1] = bad_a[0].clone();
        let binding2 = LBFVContributionBinding::new(participant_set, 2)?;
        let c_bad = LBFVPublicKey::from_parts_with_binding(
            bad_cts.iter().map(|ct| ct.c[0].clone()).collect(),
            bad_a,
            params.clone(),
            None,
            binding2,
        )?;

        assert!(LBFVPublicKey::aggregate(&[c1, c_bad]).is_err());

        Ok(())
    }

    #[test]
    fn test_deterministic_public_key() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);

        // Create a fixed seed
        let seed = <ChaCha8Rng as SeedableRng>::Seed::default();

        // Create two public keys with the same seed
        let pk1 = LBFVPublicKey::new_with_seed(&sk, seed, &mut rng)?;
        let pk2 = LBFVPublicKey::new_with_seed(&sk, seed, &mut rng)?;

        // Verify that both public keys have the same seed
        assert_eq!(pk1.seed, pk2.seed);
        assert_eq!(pk1.seed, Some(seed));

        // Verify that all ciphertexts have the same c[1] components
        assert_eq!(pk1.c.len(), pk2.c.len());
        for (ct1, ct2) in pk1.c.iter().zip(pk2.c.iter()) {
            assert_eq!(ct1.c[1], ct2.c[1]); // The 'a' polynomials should be identical
            assert_ne!(ct1.c[0], ct2.c[0]); // The 'b' polynomials should differ due to random error

            // Verify both decrypt to zero
            let pt1 = sk.try_decrypt(ct1)?;
            let pt2 = sk.try_decrypt(ct2)?;
            assert_eq!(pt1, Plaintext::zero(Encoding::poly(), &params)?);
            assert_eq!(pt2, Plaintext::zero(Encoding::poly(), &params)?);
        }

        Ok(())
    }

    #[test]
    fn aggregate_requires_bound_complete_public_key_set() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let set = LBFVParticipantSet::new([9u8; 32], vec![1, 2, 3])?;
        let keys: Vec<SecretKey> = (0..3)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        let contributions: Vec<LBFVPublicKey> = keys
            .iter()
            .enumerate()
            .map(|(index, sk)| {
                let binding = LBFVContributionBinding::new(set.clone(), (index + 1) as u32)?;
                LBFVPublicKey::new_with_seed_and_binding(sk, [4u8; 32], binding, &mut rng)
            })
            .collect::<std::result::Result<_, _>>()?;

        let aggregate = LBFVPublicKey::aggregate(&contributions)?;
        assert_eq!(aggregate.participant_set(), Some(&set));

        assert!(LBFVPublicKey::aggregate(&contributions[..2]).is_err());

        let mut duplicate = contributions.clone();
        let replacement_binding = LBFVContributionBinding::new(set.clone(), 1)?;
        duplicate[1] = LBFVPublicKey::new_with_seed_and_binding(
            &keys[1],
            [4u8; 32],
            replacement_binding,
            &mut rng,
        )?;
        assert!(LBFVPublicKey::aggregate(&duplicate).is_err());

        let mut malformed = aggregate.clone();
        malformed.l = 1;
        assert!(LBFVPublicKey::aggregate(&[malformed]).is_err());

        Ok(())
    }

    /// `new_with_seed_and_binding` must not panic on a malformed secret key
    /// whose coefficient length does not match the parameter degree.
    #[test]
    fn new_with_seed_and_binding_rejects_malformed_secret_key() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);

        // A secret key with only 17 coefficients instead of degree().
        let bad_coeffs = vec![1i64, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1];
        assert_ne!(bad_coeffs.len(), params.degree());
        let bad_sk = SecretKey::new(bad_coeffs, &params);

        let set = LBFVParticipantSet::new([80u8; 32], vec![1])?;
        let binding = LBFVContributionBinding::new(set, 1)?;
        let seed = [0u8; 32];

        let result = LBFVPublicKey::new_with_seed_and_binding(&bad_sk, seed, binding, &mut rng);
        assert!(
            result.is_err(),
            "Malformed secret key must produce an error, not a panic"
        );

        Ok(())
    }

    /// Malformed in-memory public keys must be rejected by `try_encrypt`,
    /// `try_encrypt_extended`, and `extract_b_polynomials`.
    #[test]
    fn malformed_pk_rejected_by_encryption_and_extraction() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = LBFVPublicKey::new(&sk, &mut rng)?;

        let pt = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;

        // Normal operations succeed.
        let _ct = pk.try_encrypt(&pt, &mut rng)?;
        let (_ct, _u, _e1, _e2) = pk.try_encrypt_extended(&pt, &mut rng)?;
        let _b = pk.extract_b_polynomials(0, 0, Representation::NttShoup)?;

        // Malformed PK: wrong l value.
        let mut bad_pk = pk.clone();
        bad_pk.l = 1;
        assert!(
            bad_pk.try_encrypt(&pt, &mut rng).is_err(),
            "try_encrypt must reject a malformed PK (wrong l)"
        );
        assert!(
            bad_pk.try_encrypt_extended(&pt, &mut rng).is_err(),
            "try_encrypt_extended must reject a malformed PK (wrong l)"
        );
        assert!(
            bad_pk
                .extract_b_polynomials(0, 0, Representation::NttShoup)
                .is_err(),
            "extract_b_polynomials must reject a malformed PK (wrong l)"
        );

        // Malformed PK: truncated ciphertexts.
        let mut truncated_pk = pk.clone();
        truncated_pk.c.pop();
        assert!(
            truncated_pk.try_encrypt(&pt, &mut rng).is_err(),
            "try_encrypt must reject a PK with truncated ciphertexts"
        );
        assert!(
            truncated_pk.try_encrypt_extended(&pt, &mut rng).is_err(),
            "try_encrypt_extended must reject a PK with truncated ciphertexts"
        );
        assert!(
            truncated_pk
                .extract_b_polynomials(0, 0, Representation::NttShoup)
                .is_err(),
            "extract_b_polynomials must reject a PK with truncated ciphertexts"
        );

        Ok(())
    }

    /// Mixed seeded/explicit PK contributions with identical concrete `a`
    /// polynomials must aggregate successfully. The aggregate seed must be
    /// `None`, and the resulting key must support encryption/decryption and
    /// RLK construction.
    #[test]
    fn test_mixed_seeded_explicit_pk_aggregation() -> Result<(), Box<dyn Error>> {
        let mut rng = rng();
        let params = BfvParameters::default_arc(6, 8);
        let n = 3;

        let participant_set = LBFVParticipantSet::new([81u8; 32], (1..=n as u32).collect())?;

        // Common CRS seed shared by all nodes.
        let mut seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut seed);

        // Per-node secret-key contributions.
        let sk_shares: Vec<SecretKey> = (0..n)
            .map(|_| SecretKey::random(&params, &mut rng))
            .collect();

        // Extract the concrete a polynomials from a single seeded PK built from
        // sk_shares[0] — these will be the reference a_j we verify against.
        let pk_ref = LBFVPublicKey::new_with_seed(&sk_shares[0], seed, &mut rng)?;
        let a_polys: Vec<Poly<fhe_math::rq::Ntt>> =
            pk_ref.c.iter().map(|ct| ct.c[1].clone()).collect();

        // Two seeded contributions (parties 1 and 2).
        let c1 = {
            let binding = LBFVContributionBinding::new(participant_set.clone(), 1)?;
            LBFVPublicKey::new_with_seed_and_binding(&sk_shares[0], seed, binding, &mut rng)?
        };
        let c2 = {
            let binding = LBFVContributionBinding::new(participant_set.clone(), 2)?;
            LBFVPublicKey::new_with_seed_and_binding(&sk_shares[1], seed, binding, &mut rng)?
        };

        // One explicit contribution (party 3), using the same concrete a_j.
        let c3 = {
            let binding = LBFVContributionBinding::new(participant_set.clone(), 3)?;
            LBFVPublicKey::contribute_with_binding(&sk_shares[2], &a_polys, binding, &mut rng)?
        };

        // Aggregate all three.
        let pk = LBFVPublicKey::aggregate(&[c1, c2, c3])?;

        // The aggregate seed must be None — mixed representations.
        assert!(
            pk.seed.is_none(),
            "Aggregate PK with mixed seeded/explicit contributions must have seed=None"
        );

        // The concrete a_j in the aggregate must match the reference.
        assert_eq!(pk.c.len(), a_polys.len());
        for (j, ct) in pk.c.iter().enumerate() {
            assert_eq!(
                ct.c[1], a_polys[j],
                "Aggregate a_j[{j}] must match the reference"
            );
        }

        // Joint secret key for decryption.
        let mut sum_coeffs = vec![0i64; params.degree()];
        for sk in &sk_shares {
            for (acc, c) in sum_coeffs.iter_mut().zip(sk.coeffs.iter()) {
                *acc = acc.wrapping_add(*c);
            }
        }
        let sk_joint = SecretKey::new(sum_coeffs, &params);

        // Encrypt/decrypt roundtrip.
        let pt = Plaintext::try_encode(
            &Modulus::new(params.plaintext())?.random_vec(params.degree(), &mut rng),
            Encoding::poly(),
            &params,
        )?;
        let ct = pk.try_encrypt(&pt, &mut rng)?;
        assert_eq!(sk_joint.try_decrypt(&ct)?, pt);

        // Verify RLK construction works with the mixed-aggregated PK.
        let mut d1_seed = <ChaCha8Rng as SeedableRng>::Seed::default();
        rng.fill(&mut d1_seed);
        let rlk_shares: Vec<LBFVRelinKeyShare> = sk_shares
            .iter()
            .enumerate()
            .map(|(i, sk_i)| {
                let binding =
                    LBFVContributionBinding::new(participant_set.clone(), (i + 1) as u32)?;
                LBFVRelinKeyShare::contribution_with_binding(
                    sk_i, d1_seed, seed, binding, 0, 0, &mut rng,
                )
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let rlk = LBFVRelinearizationKey::aggregate(&rlk_shares, &pk)?;

        // Relinearization roundtrip: multiply, relinearize, decrypt.
        let pt3 = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;
        let pt5 = Plaintext::try_encode(&[5u64], Encoding::poly(), &params)?;
        let ct3 = pk.try_encrypt(&pt3, &mut rng)?;
        let ct5 = pk.try_encrypt(&pt5, &mut rng)?;
        let mut ct_product = &ct3 * &ct5;
        rlk.relinearizes(&mut ct_product)?;
        let pt_result = sk_joint.try_decrypt(&ct_product)?;
        let result = Vec::<u64>::try_decode(&pt_result, Encoding::poly())?;
        assert_eq!(result[0], 15);

        Ok(())
    }
}
