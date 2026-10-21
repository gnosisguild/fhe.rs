# Threshold BFV (TRBFV)

A pure-Rust implementation of threshold BFV homomorphic encryption based on the work of Antoine Urban and Matthieu Rambaud in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf) (Urban–Rambaud 2024).

The current implementation covers Shamir sharing, smudging noise, and
threshold decryption with additive and limited multiplicative support via
distributed *l*-BFV relinearization keys. It is **not** the complete robust
protocol from the paper: there is no distributed key generation, no broadcast
channel, no FLSS (function-linear secret sharing), and no GURS (guaranteed
uniform random string) generation. Applications establish and authenticate
pairwise PRF keys out of band; smudging noise is sampled locally, never shared.

This module enables distributed decryption between `n` parties without necessarily involving all of them: any `threshold + 1` of the `n` parties can decrypt a ciphertext, while any coalition of at most `threshold` parties learns nothing. The threshold must be exactly `(n-1)/2` (integer division), the maximal corruption tolerance under an honest majority — see `config.rs` for the derivation.

## Architecture

Public types are available directly from `fhe::trbfv`. Each implementation
module has one responsibility:

```text
trbfv/
├── mod.rs              # Public exports
├── config.rs           # Shared parameter and ciphertext validation
├── errors.rs           # Threshold and decryption errors
├── shamir.rs           # Shamir secret-sharing arithmetic
├── shares.rs           # Key-share generation, conversion, and aggregation
├── arithmetic.rs       # Internal interpolation weights and guarded buffers
├── decryption.rs       # Partial shares, transport boundary, and reconstruction
├── prf.rs              # Pairwise PRF keys, context digest, and cancelling masks
└── smudging/
    ├── mod.rs          # Smudging exports
    ├── bounds.rs       # Lambda, circuit-noise bounds, and correctness budget
    └── noise.rs        # Fresh-noise generation and one-use ownership
```

The bound calculator determines `B_sm`; the noise generator uses that bound;
the decryptor consumes the generated noise. The `threshold-decryption`
feature enables decryption, PRF masks, and noise generation. Key sharing and
bound calculation remain available without it.

## Synchronized decryption (default)

The `threshold-decryption` feature enables threshold decryption based on
[On Threshold Fully Homomorphic Encryption with Synchronized Decryptors](https://eprint.iacr.org/2026/031)
(Colin de Verdière–Passelègue–Stehlé 2026). It is enabled by default on this
development branch for the planned **breaking 0.5 release**. The manifests
remain at 0.4.1 until release preparation; published 0.4.1 is unchanged.

```toml
# Development checkout with synchronized decryption enabled by default:
fhe = { path = "path/to/fhe.rs/crates/fhe" }
# Core BFV and Shamir key sharing only, without the optional PRF dependencies:
# fhe = { path = "path/to/fhe.rs/crates/fhe", default-features = false }
```

The module is independent of `experimental-mbfv`. Its PRF dependencies
(`ark-ff` and pinned `e3-safe`) remain optional and are activated only by
`threshold-decryption`. Import `SynchronizedDecryptor`, `SmudgingNoiseGenerator`,
`SmudgingNoise`, `PartyPrfKeys`, `PartyPrfKeyTransport`, and `DecryptionShare`
directly from `fhe::trbfv`.

### Setup and decryption

1. Use `ShareManager::generate_secret_shares_from_poly` and
   `aggregate_collected_shares` as before. Convert each recipient's aggregate
   to NTT form and keep it in a `Zeroizing<Poly<Ntt>>` owner.
2. Construct `SynchronizedDecryptor::new(n, threshold, params)`.
3. Establish matching pairwise keys externally. Import each party's bundle
   through `PartyPrfKeyTransport::new` and `PartyPrfKeys::from_transport`.
   The vectors `keys_i_j` and `keys_j_i` use paper indices, not message
   directions: the first vector's evaluations are added, the second subtracted.
4. Agree on a designated set `S` of exactly `threshold + 1` distinct parties
   before producing any partial decryptions. `S` may change for a later
   decryption; key shares and pairwise keys are reusable within their key epoch.
5. Create `SmudgingNoiseGenerator` from
   `SmudgingBoundCalculatorConfig` or `SmudgingBoundCalculator`. `Lambda` and
   the calculator's bound/circuit assumptions are unchanged.
   Here `m` is the fresh-input addition fan-in, not the number of independent
   decryptions. Sample new noise for every party and every partial-decryption
   call. Each noise owner is consumed by the call and wiped on drop.
   Proof-producing callers can use
   `SmudgingNoiseGenerator::wrap_signed_coefficients` with integers freshly and
   independently sampled uniformly in `[-B_sm, B_sm]`. Wrapping validates the
   length and bound, not freshness or uniformity. Callers retain the integers
   for the witness and are responsible for erasing their copies when no longer
   needed.
6. Call `SynchronizedDecryptor::decryption_share` for each designated party,
   then `decrypt_from_shares` with the resulting typed `DecryptionShare`s.

PartDec computes `lambda_i * c1 * sk_i + e_i + r_i`; FinDec adds the partial
decryptions and `c0`. Local noise is added **after** weighting the key term.
The masks cancel over the agreed set, so smudging is never Shamir-shared or
multiplied by reconstruction weights. The API accepts level-zero, two-component
BFV ciphertexts and plaintext moduli fitting in `u64`.

`DecryptionShare::into_parts` / `from_parts` provide an application transport
boundary. Reconstruction rejects inconsistent sets/ciphertexts, duplicate or
missing parties, and malformed polynomials. Noise must match the full BFV
parameter set and committee size. Protocol-specific errors are available as
`Error::SynchronizedDecryption(SynchronizedDecryptionError::...)`.

The context digest absorbs power-basis ciphertext residues, low degree first.
That order matches the Interfold decryption circuit. `dev-sync-dec` at `8c58831`
absorbed NTT residues, so its reference vector does not describe this digest.
A fixed regression test guards the power-basis encoding. The digest binds
the set and ciphertext coefficients, not the application session, key epoch or
parameter negotiation. Applications authenticate these separately, establish
matching pairwise keys, prevent replay, and supply any proofs of correct
decryption. `from_parts` recomputes the digest from caller-supplied context; it
does not authenticate or prove the received polynomial.

### Example and tests

```bash
cargo run --release --example trbfv_sync_dec
cargo test -p fhe
cargo test -p fhe --release --features experimental-mbfv --test trbfv_secure_e2e
```

The example uses the existing sharing API, simulates committee-key setup in
one process, and decrypts two ciphertexts with fresh local noise. Its small
parameters demonstrate mechanics only. The release integration tests also
exercise degree 8192.

## Migrating from 0.4 to 0.5

The legacy shared-smudging protocol is retired, not deprecated behind a second
feature. Update callers and their proof/transport bindings together:

| Removed API | Replacement |
| --- | --- |
| `TRBFV::new` / `trbfv::threshold::TRBFV` | `ShareManager::new` for setup; `SynchronizedDecryptor::new` for decryption |
| `TRBFV` key-sharing/aggregation wrappers | The corresponding `ShareManager` methods |
| `TRBFV::generate_smudging_error` / `generate_smudging_error_with_participant_count` | `SmudgingNoiseGenerator::new(config)` or `from_bound_calculator(calculator)`, then `generate` per partial call; use the calculator's accepted-participant-count builder for RLK accounting |
| `trbfv::smudging::SmudgingNoiseGenerator::new(params, bound)` (arbitrary bound) | `trbfv::SmudgingNoiseGenerator::new(config)` (calculated bound, consumed local-noise owner) |
| `ShareManager::decryption_share` / `TRBFV::decryption_share` | `SynchronizedDecryptor::decryption_share` with a designated set, fresh `SmudgingNoise`, and external `PartyPrfKeys` |
| `ShareManager::decrypt_from_shares` / `TRBFV::decrypt` | `SynchronizedDecryptor::decrypt_from_shares(&[DecryptionShare], &Ciphertext)` |
| `trbfv::synchronized::*` imports | `trbfv::*` imports; the nested namespace is removed |
| Cargo feature `synchronized-decryption` | `threshold-decryption`, enabled by default |

**Transport incompatibility:** legacy partials include `c0` and require Shamir
interpolation after collection. Synchronized partials already weight the key
term locally, do **not** include `c0`, and carry set/ciphertext metadata. Sum
exactly one typed share from each designated party and add `c0` once. Never
apply post-share Lagrange weighting, feed legacy shares to the new aggregator,
or transport/deal smudging noise. Use `DecryptionShare::into_parts` / `from_parts`
for the new application transport boundary.

Key shares remain reusable and unchanged. Agree on exactly `threshold + 1`
distinct party IDs, matching pairwise keys, BFV parameters, ciphertext, and
authenticated session/key epoch **before** producing partials. Pairwise key
establishment, authenticated transport, replay prevention and proofs remain
application responsibilities; the example helper only simulates external setup.

**Witness API:** retain freshly and independently sampled centered integers for
the proof witness, and pass them through the generator's
`wrap_signed_coefficients`. Bound/length validation does not prove freshness or
uniform sampling, and caller copies must be erased separately. Callers using
the earlier `from_signed_coefficients` API must migrate to
`generator.wrap_signed_coefficients(&coeffs)`. The generator supplies the
parameters, committee size, and calculated bound. The power-basis PRF digest
is unchanged by this consolidation.

## Noise and Correctness Formulas (Urban–Rambaud 2024)

This section summarises the formulas implemented in
[`smudging/bounds.rs`](smudging/bounds.rs). See the paper for full derivations.

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

Only `|S| = threshold + 1` parties add local noise in synchronized decryption,
so their worst-case sum is `|S| * B_sm`. The calculator retains the conservative
`n * B_sm` correctness budget; `n` is not the number of partials to collect.

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
  `B&#x209b;&#x2098; = 2^lambda &middot; B&#x1d9c;` form only bounds the statistical distance for
  a *single* coefficient and is not what [`smudging/bounds.rs`](smudging/bounds.rs)
  implements.

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

### Fresh local noise

Every partial-decryption call consumes a non-cloneable, zeroizing
`SmudgingNoise` owner, including on validation failure. Sample independently
for every call, even when repeating the same ciphertext and designated set.
The witness-wrapping API cannot enforce how caller-supplied integers were sampled.

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

See [`trbfv_add.rs`](../../examples/trbfv_add.rs) for distributed key setup and
synchronized addition/decryption, and [`trbfv_add_bfv_share.rs`](../../examples/trbfv_add_bfv_share.rs)
for BFV-encrypted key-share transport. The `_insecure` variant also encrypts
key shares but explicitly uses insecure statistical noise. These local
simulations are not a complete robust or authenticated protocol.

The example can be run with configurable parameters (threshold must equal `(num_parties - 1) / 2`):
```bash
cargo run --release --example trbfv_add --features experimental-mbfv -- --num_parties=10 --threshold=4
```

Basic usage pattern:

```rust
use fhe::trbfv::{ShareManager, SynchronizedDecryptor, SmudgingNoiseGenerator};

let mut manager = ShareManager::new(n_parties, threshold, params.clone())?;
let key_shares = manager.generate_secret_shares_from_poly(sk_poly, &mut rng)?;
// Securely exchange key shares only, then aggregate each recipient's matrices.
let key = zeroize::Zeroizing::new(
    manager.aggregate_collected_shares(&collected_key_shares)?.into_ntt()
);
let decryptor = SynchronizedDecryptor::new(n_parties, threshold, params)?;
let generator = SmudgingNoiseGenerator::new(bound_config)?;
// prf_keys were established externally; designated contains exactly T + 1 IDs.
let partial = decryptor.decryption_share(
    &ciphertext, &key, party_id, &designated,
    generator.generate(&mut rng)?, &prf_keys,
)?;
// Collect typed partials for the agreed set: sum them and add c0 once.
let plaintext = decryptor.decrypt_from_shares(&partials, &ciphertext)?;
```

## Security Considerations

This implementation has not been independently audited. Use with appropriate caution in production environments.

The security of the threshold scheme relies on:
- Proper parameter selection for the underlying BFV scheme
- Secure distribution of shares among parties
- Protection of individual secret key shares
- Appropriate smudging noise generation

Note that the Shamir secret sharing operations use arbitrary-precision integer
arithmetic that is not constant-time. These computations are local to each
party (shares and secrets never traverse a timing-observable boundary during
them), so this is a low-severity caveat, but co-located attacker models should
take it into account.
