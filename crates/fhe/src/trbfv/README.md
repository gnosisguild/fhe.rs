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

- `shamir.rs` - Shamir Secret Sharing implementation with field operations and polynomial interpolation
- `smudging.rs` - Smudging noise generation with optimal variance calculation using arbitrary precision arithmetic  
- `shares.rs` - Share aggregation and decryption operations management
- `threshold.rs` - Main TRBFV coordinator struct
- `config.rs` - Parameter validation
- `errors.rs` - Threshold-specific error types
- `synchronized/` - Additional designated-decryptor API, enabled by the
  `synchronized-decryption` Cargo feature

## Opt-in synchronized decryption

The `synchronized-decryption` feature adds `trbfv::synchronized` based on
[On Threshold Fully Homomorphic Encryption with Synchronized Decryptors](https://eprint.iacr.org/2026/031)
(Colin de Verdière–Passelègue–Stehlé 2026), extracted from PRs #276 and #280.
Enable it when selecting this protocol:

```toml
fhe = { git = "https://github.com/gnosisguild/fhe.rs", branch = "main", features = ["synchronized-decryption"] }
```

`TRBFV`, `ShareManager`, the shared-smudging decryption methods, and their
transport formats retain their existing behavior. Interfold can continue using
them while synchronized-decryption circuits and integration are developed.
The new module is independent of the `experimental-mbfv` feature. Its PRF
dependencies (`ark-ff` and pinned `e3-safe`) are activated only by the new feature.

### Reuse key sharing, select a decryption protocol

1. Use `ShareManager::generate_secret_shares_from_poly` and
   `aggregate_collected_shares` as before. Convert each recipient's aggregate
   to NTT form and keep it in a `Zeroizing<Poly<Ntt>>` owner.
2. Construct `synchronized::SynchronizedDecryptor::new(n, threshold, params)`.
3. Establish matching pairwise keys externally. Import each party's bundle
   through `PartyPrfKeyTransport::new` and `PartyPrfKeys::from_transport`.
   The vectors `keys_i_j` and `keys_j_i` use paper indices, not message
   directions: the first vector's evaluations are added, the second subtracted.
4. Agree on a designated set `S` of exactly `threshold + 1` distinct parties
   before producing any partial decryptions. `S` may change for a later
   decryption; key shares and pairwise keys are reusable within their key epoch.
5. Create `synchronized::SmudgingNoiseGenerator` from the existing
   `SmudgingBoundCalculatorConfig` or `SmudgingBoundCalculator`. `Lambda` and
   the bound/circuit assumptions are the same as in the legacy calculator.
   Here `m` is the fresh-input addition fan-in, not the number of independent
   decryptions. Sample new noise for every party and every partial-decryption
   call. Each noise owner is consumed by the call and wiped on drop.
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

The context digest and PRF encoding match `dev-sync-dec` at `8c58831`; a fixed
reference-vector regression test guards that compatibility. The digest binds
the set and ciphertext coefficients, not the application session, key epoch or
parameter negotiation. Applications authenticate these separately, establish
matching pairwise keys, prevent replay, and supply any proofs of correct
decryption. `from_parts` recomputes the digest from caller-supplied context; it
does not authenticate or prove the received polynomial.

### Example and tests

```bash
cargo run --release --example trbfv_sync_dec --features synchronized-decryption
cargo test -p fhe --features synchronized-decryption
cargo test -p fhe --release --features synchronized-decryption --test trbfv_sync_dec
```

The example uses the existing sharing API, simulates committee-key setup in
one process, and decrypts two ciphertexts with fresh local noise. Its small
parameters demonstrate mechanics only. The release integration tests also
exercise degree 8192.

The legacy and synchronized APIs will be consolidated after Interfold's
synchronized-decryption circuits and main-branch integration are ready. That
migration must update callers and proof/transport bindings before making the
new protocol the default and retiring the old entry points. Follow-up:
[#285](https://github.com/gnosisguild/fhe.rs/issues/285).

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
  `B&#x209b;&#x2098; = 2^lambda &middot; B&#x1d9c;` form only bounds the statistical distance for
  a *single* coefficient and is not what [`smudging.rs`](smudging.rs)
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

### One-time pre-shared noise

Smudging noise generated by [`TRBFV::generate_smudging_error`] and
[`TRBFV::generate_smudging_error_with_participant_count`] is **one-time
material** that must never be reused across decryptions.  The current API does
**not** track or enforce consumption — callers are responsible for freshness.

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
use fhe::trbfv::TRBFV;

// Setup threshold scheme
let trbfv = TRBFV::new(n_parties, threshold, params.clone())?;

// Each party: deal secret shares of its key and smudging noise contributions
let sk_shares = trbfv.generate_secret_shares_from_poly(sk_poly, &mut rng)?;
let es_coeffs = trbfv.generate_smudging_error(num_ciphertexts, mult_depth, lambda, &mut rng)?;

// Each party: aggregate the share matrices received from the other parties
// into its share of the joint secret key (and likewise for the noise)
let sk_poly_sum = trbfv.aggregate_collected_shares(&collected_sk_shares)?;
let es_poly_sum = trbfv.aggregate_collected_shares(&collected_es_shares)?;

// Each decrypting party: compute a decryption share from its aggregated shares
let d_share = trbfv.decryption_share(ciphertext.clone(), sk_poly_sum.into_ntt(), es_poly_sum)?;

// Combine exactly threshold + 1 decryption shares; reconstructing_parties
// holds the 1-based indices of the parties the shares came from
let plaintext = trbfv.decrypt(d_share_polys, reconstructing_parties, ciphertext)?;
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
