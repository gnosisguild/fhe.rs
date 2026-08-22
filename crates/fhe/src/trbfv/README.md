# Threshold BFV (TRBFV)

A pure-Rust implementation of threshold BFV homomorphic encryption based on the work of Antoine Urban and Matthieu Rambaud in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf) (Urban–Rambaud 2024).

The current implementation covers Shamir sharing, smudging noise, and
threshold decryption with additive and limited multiplicative support via
distributed *l*-BFV relinearization keys. It is **not** the complete robust
protocol from the paper: there is no distributed key generation, no broadcast
channel, no FLSS (function-linear secret sharing), and no GURS (guaranteed
uniform random string) generation. The smudging exchange is assumed to have
already happened out of band.

This module enables distributed decryption between `n` parties without necessarily involving all of them: any `threshold + 1` of the `n` parties can decrypt a ciphertext, while any coalition of at most `threshold` parties learns nothing. The threshold must be exactly `(n-1)/2` (integer division), the maximal corruption tolerance under an honest majority — see `config.rs` for the derivation.

## Architecture

The module follows a modular design with clear separation of concerns:

- `shamir-rns` - independent runtime prime-field Shamir sharing over
  canonical RNS residues; each modulus has its own field scheme and
  party-major batch matrix
- `smudging.rs` - Smudging noise generation with optimal variance calculation using arbitrary precision arithmetic  
- `shares.rs` - Share aggregation and decryption operations management
- `threshold.rs` - Main TRBFV coordinator struct
- `config.rs` - Parameter validation
- `errors.rs` - Threshold-specific error types

## Noise and Correctness Formulas (Urban–Rambaud 2024)

This section summarises the formulas implemented in
[`smudging.rs`](smudging.rs).  See the paper for full derivations.

### Delta and the strict correctness inequality

The plaintext scaling factor is **&Delta; = &lfloor;Q / t&rfloor;** (not `Q/(2t)`):

> `2 * (B&#x1d9c; + n * B&#x209b;&#x2098;) < &Delta;`

where
- `Q` is the product of all CRT moduli,
- `t` is the plaintext modulus,
- `n` is the total number of parties,
- `B&#x1d9c;` is the ciphertext noise infinity-norm bound after circuit evaluation,
- `B&#x209b;&#x2098;` is the smudging-noise coefficient bound.

Equality (`>=`) is **rejected**: a smudging bound that merely meets &Delta; does
not guarantee correct decryption.

### Ciphertext noise recursion (multiplicative circuits)

Let `mult_depth` be the number of multiplication levels.

- **Initial bound:** `B&#x1d9c;&sup0;` = either the computed
  `m &middot; (B_fresh + Q mod t)` or a caller-injected bound (see
  [`SmudgingBoundCalculator::with_initial_ciphertext_noise_bound`]).
  `B_fresh` itself is derived from the encryption-noise and key-norm bounds,
  using the sampler-specific `B_enc` (see below).

- **Recursion** (Prop.&nbsp;20 of Urban–Rambaud 2024):

  > `B&#x1d9c;&sup1;&plus;&sup1; = 2&middot;k&middot;N&sup2;&middot;||sk|| &middot; B&#x1d9c;&sup1; + B_relin`

  where
  - `k = t` (plaintext modulus),
  - `N` is the polynomial ring degree,
  - `||sk||` is the secret-key infinity-norm bound,
  - `B_relin` is the relinearisation error bound (Eq.&nbsp;30 of the paper)
    with **aggregate RLK error** `|S| &middot; B_e`, where `|S|` is the
    `accepted_participant_count` (the size of the *l*-BFV accepted set).

- **Smudging bound:** `B&#x209b;&#x2098; = 2^(lambda + 1) &middot; d &middot; B&#x1d9c;` where
  `lambda` is the statistical security parameter (see
  [`MIN_SECURE_LAMBDA`]) and `d` is the polynomial ring degree. The extra
  factor `2 &middot; d` is the whole-transcript policy (issue #108): a single
  decryption reveals all `d` coefficients of the smudging noise at once, so a
  union bound over the coefficients adds a factor `d`, and `2^(lambda + 1)`
  keeps the constant-`2` convention of the correctness inequality. The older
  `B&#x209b;&#x2098; = 2^lambda &middot; B&#x1d9c;` form only bounds the
  statistical distance for a *single* coefficient and is not what
  [`smudging.rs`](smudging.rs) implements.

### Sampler-specific `B_enc`

`B_enc` is derived from the actual BFV error sampler configuration, not from a
fixed formula:

| Error sampler branch                     | `B_enc` bound                    |
| ---------------------------------------- | -------------------------------- |
| CBD (error1 variance `< 16` as `u64`)     | `2 &middot; error1_variance`    |
| Uniform (large / non-`u64` variance)      | `&lfloor;sqrt(3 &middot; error1_variance)&rfloor;` |

This matches the branches chosen by `Poly::conditional_error` in `fhe-math`.

`SmudgingBoundCalculatorConfig::new` and
`SmudgingBoundCalculatorConfig::new_multiplicative` are fallible: they reject
zero parties or zero ciphertexts before a calculator is created. The calculator
also revalidates these counts before performing the bound computation.

## Known Limitations

### One-time pre-shared noise

Smudging noise generated by [`TRBFV::generate_smudging_error`] and
[`TRBFV::generate_smudging_error_with_participant_count`] is **one-time
material** that is converted into non-`Clone`
[`OneTimeNoiseShare`](crate::trbfv::OneTimeNoiseShare) values. Aggregation and
decryption consume the value, enforcing one use locally. Replay of copied or
serialized transport material remains an orchestration concern.

### Identity and session binding

Use one caller-supplied, fresh [`SessionId`](crate::SessionId) and explicit
[`ParticipantSet`](crate::ParticipantSet) for the key epoch. Wrap each dealt
receiver matrix in an identified [`KeyShareContribution`](crate::trbfv::KeyShareContribution)
or [`NoiseShareContribution`](crate::trbfv::NoiseShareContribution). Aggregation
requires exactly one contribution for every member of the agreed set; equal-sized
different sets and epoch mismatches are rejected. Supply a fresh `SessionId` for
each noise/decryption use. These tags provide consistency, not authenticated
sender identity, transcript binding, replay prevention, or proof of correct
decryption. Decrypting party IDs are checked for range and uniqueness during
reconstruction, but need not belong to the key/noise accepted set; selecting and
authenticating those parties is an external orchestration responsibility.

### Even-`n` party counts

Party counts where `n` is even are accepted for compatibility, but
Urban–Rambaud&nbsp;2024 proves security only for odd `n` (under the
`n = 2t + 1` honest-majority model).  Even-`n` deployments fall outside the
paper's theorem and have not been independently analyzed.

### Incomplete protocol orchestration

This module implements sharing, smudging, and decryption — it does **not**
include the complete robust protocol stack from Urban–Rambaud&nbsp;2024:
- No distributed key generation (DKG).
- No authenticated broadcast channel.
- No FLSS pre-processing or GURS generation.
- No proactive refresh or identifiable-abort mechanisms.

Callers who need full end-to-end robust threshold FHE must provide these
components externally.

### `MIN_SECURE_LAMBDA` is a statistical-hiding policy

[`MIN_SECURE_LAMBDA`] is a policy threshold for statistical hiding — a larger
`lambda` produces a stronger noise-flooding guarantee.  It is **not** a
computational-security bound or a claim about bit-security.  See the
[`Lambda`] type documentation.

## Usage

For a complete working example demonstrating multi-party setup, share distribution, and threshold decryption, see [`examples/trbfv_add.rs`](../../examples/trbfv_add.rs). A variant that transports the Shamir shares encrypted under per-party BFV keys is in [`examples/trbfv_add_bfv_share.rs`](../../examples/trbfv_add_bfv_share.rs). A multiplicative example using distributed *l*-BFV relinearization keys is in [`examples/trbfv_mul_bfv_share.rs`](../../examples/trbfv_mul_bfv_share.rs).

The example can be run with configurable parameters (threshold must equal `(num_parties - 1) / 2`):
```bash
cargo run --release --example trbfv_add -- --num_parties=10 --threshold=4
```

Basic usage pattern:

```rust
use fhe::trbfv::{
    ContributionBinding, DecryptionShare, KeyShareContribution, NoiseShareContribution,
    NoiseShareMatrix, ParticipantSet, SecretShareMatrix, SessionId, ShareManager, TRBFV,
};
use rand::random;

// Setup threshold scheme
let trbfv = TRBFV::new(n_parties, threshold, params.clone())?;
let mut share_manager = ShareManager::new(n_parties, threshold, params.clone())?;

// Each dealer produces one protected matrix per RNS modulus. Key and noise
// matrices have distinct types and the noise path is consuming.
let sk_shares: Vec<SecretShareMatrix> =
    trbfv.generate_secret_shares_from_poly(sk_poly, &mut rng)?;
let es_coeffs = trbfv.generate_smudging_error(num_ciphertexts, mult_depth, lambda, &mut rng)?;
let es_poly = share_manager.bigints_to_poly(es_coeffs)?;
let es_shares: Vec<NoiseShareMatrix> =
    share_manager.generate_noise_shares_from_poly(es_poly, &mut rng)?;

let epoch = ParticipantSet::new(SessionId::new(random()), (1..=n_parties as u32).collect())?;
let use_session = SessionId::new(random());

// The network sends the receiver row from every per-modulus dealer matrix.
// `received_key_rows` and `received_noise_rows` are one row-vector list per
// dealer; each inner list has one row for every RNS modulus. Assemble the
// protected receiver matrices before binding them to dealer IDs.
let collected_sk_shares: Vec<SecretShareMatrix> = received_key_rows
    .iter()
    .map(|rows| SecretShareMatrix::from_rows(rows))
    .collect::<Result<_, fhe::Error>>()?;
let collected_es_shares: Vec<NoiseShareMatrix> = received_noise_rows
    .iter()
    .map(|rows| NoiseShareMatrix::from_rows(rows))
    .collect::<Result<_, fhe::Error>>()?;

// Aggregate identified key matrices and move identified noise matrices into
// the one-time aggregate. Noise contributions cannot be cloned or reused.
let key_contributions: Vec<KeyShareContribution> = collected_sk_shares
    .into_iter()
    .enumerate()
    .map(|(i, matrix)| Ok(KeyShareContribution::new(
        ContributionBinding::new(epoch.clone(), (i + 1) as u32)?, matrix)))
    .collect::<Result<_, fhe::Error>>()?;
let sk_poly_sum = trbfv.aggregate_collected_shares(&epoch, &key_contributions)?;
let noise_contributions: Vec<NoiseShareContribution> = collected_es_shares
    .into_iter()
    .enumerate()
    .map(|(i, matrix)| Ok(NoiseShareContribution::new(
        ContributionBinding::new(epoch.clone(), (i + 1) as u32)?, matrix)))
    .collect::<Result<_, fhe::Error>>()?;
let es_poly_sum = trbfv.aggregate_noise_shares(&epoch, use_session, noise_contributions)?;

// Repeat receiver collection and aggregation above for each decrypting party.
// For the command-line example (n = 10, threshold = 4), parties 1 through 5
// contribute exactly threshold + 1 shares. `per_party_decryption_inputs` owns
// one `(party_id, key_sum, noise_sum)` tuple per selected party; each key/noise
// pair was produced from that receiver's collected rows, and each noise value
// is consumed exactly once here.
let decryption_shares: Vec<DecryptionShare> = per_party_decryption_inputs
    .into_iter()
    .map(|(party_id, sk_poly_sum, es_poly_sum)| {
        trbfv.decryption_share(
            ciphertext.clone(),
            party_id,
            sk_poly_sum.into_ntt()?,
            use_session,
            es_poly_sum,
        )
    })
    .collect::<Result<_, fhe::Error>>()?;
assert_eq!(decryption_shares.len(), threshold + 1);

// Combine exactly threshold + 1 identified shares; input order is irrelevant.
let plaintext = trbfv.decrypt(decryption_shares, ciphertext)?;
```

### Protected (zeroizing) wrappers

Secret material crossing the `TRBFV`/`ShareManager` flow is held in owning
 wrappers that zeroize automatically on drop (`ZeroizeOnDrop`, including early
 returns and unwinding): generated and collected key share matrices are
 [`SecretShareMatrix`](shares.rs) values, generated and collected one-time
 noise matrices are [`NoiseShareMatrix`](shares.rs) values, aggregated keys are
 [`AggregatedKeyShare`](shares.rs) values, one-time noise is
 [`OneTimeNoiseShare`](shares.rs), identified decryption shares are
 [`DecryptionShare`](shares.rs) values, and generated smudging coefficients are
[`SmudgingCoefficients`](smudging.rs) values. The wrappers expose
only borrowed views (e.g. `SecretShareMatrix::row` for transport) and
representation conversions that return another protected owner; there is no
raw-value escape. The Shamir core is supplied by the independent
`shamir-rns` crate and accepts and returns canonical residues in `[0, q)`.
It does not provide commitments, verifiability, authenticated transport,
robust DKG, or complete protocol orchestration; those boundaries remain
external. This is a hardening measure, not an independently audited
guarantee: copies made outside the library (transport buffers), allocator
behavior, swap, core dumps, and deliberate `mem::forget`/`ManuallyDrop` are
outside its scope. The remaining `SmudgingCoefficients` path intentionally
retains signed `BigInt`-backed arbitrary-size noise and its documented
best-effort cleanup.
Callers hold protected values, use them for transport/reconstruction, and let
them drop; explicit `Zeroize::zeroize` is optional hygiene, never a required
part of the API contract.

## Security Considerations

This implementation has not been independently audited. Use with appropriate caution in production environments.

The security of the threshold scheme relies on:
- Proper parameter selection for the underlying BFV scheme
- Secure distribution of shares among parties
- Protection of individual secret key shares
- Appropriate smudging noise generation

Exact accepted-set equality is checked within these APIs, but agreement across
PK/SK/RLK/noise and authenticated dealer identity is external. Party tags prevent
accidental metadata mismatch, not malicious relabeling or invalid-share
injection. This library still has no DKG, authenticated broadcast, FLSS/GURS,
PVSS, proof system, transcript binding, or complete replay-prevention protocol.

The field kernels and fixed-exponent Fermat inversion in `shamir-rns` have a
narrow constant-time-oriented design boundary. Rejection sampling, rayon
scheduling, RNG internals, allocation, transport, and the complete TRBFV
protocol are not claimed constant time. The library has not been
independently audited.
