# Threshold BFV (TRBFV)

A pure-Rust implementation of threshold BFV homomorphic encryption based on the work of Antoine Urban and Matthieu Rambaud in [Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf) (Urban–Rambaud 2024).

The implementation covers Shamir sharing, smudging noise, and threshold
decryption of level-zero, two-component BFV ciphertexts. The bound calculator
supports additive and multiplicative circuit budgets; compatible ciphertext
evaluation and relinearization keys can be generated with
[`fhe::trlbfv`](../trlbfv/mod.rs). For the paper's robust protocol, applications
supply authenticated broadcast, the linear secret sharing functionality
(`F_LSS`, §3.2), and the global uniform random string functionality (`G_URS`,
§2.7). Two distinct decryption protocols coexist:
**synchronized decryption** (default), with fresh local noise and externally
established pairwise PRF keys, and **SS (secret-sharing) smudging** (always
available), with offline sampling/dealing and interpolation-based reconstruction.

The reconstruction set contains exactly `threshold + 1` of the `n` parties.
The library requires `n >= 3` and `threshold = (n - 1) / 2` (integer division);
see [`config.rs`](config.rs) for the validation policy. These arithmetic APIs
alone do not establish a complete malicious-secure protocol: parameter analysis,
authenticated transport, proofs, and coordination remain application responsibilities.

## Architecture

Public types are available directly from `fhe::trbfv`. Each implementation
module has one responsibility:

```text
trbfv/
├── mod.rs              # Public exports
├── buffers.rs          # Shared guards for temporary secret RNS matrices
├── config.rs           # Common parameter and ciphertext validation
├── errors.rs           # Threshold and decryption errors
├── shamir.rs           # Shamir secret-sharing arithmetic
├── shares.rs           # Key-share generation, conversion, and aggregation
├── smudging.rs         # Common bounds, statistical policy, and correctness budget
├── ss/
│   ├── mod.rs          # SS protocol exports
│   ├── smudging.rs     # BigInt sampling and dealer-noise owner
│   ├── shares.rs       # Typed adapters over common Shamir dealing/aggregation
│   └── decryption.rs   # Complete partials, interpolation, and decoding
└── synchronized/
    ├── mod.rs          # Synchronized protocol exports
    ├── arithmetic.rs   # Designated-set validation and interpolation weights
    ├── decryption.rs   # Weighted partials, transport, and reconstruction
    ├── prf.rs          # Pairwise PRF keys, context digest, and cancelling masks
    └── smudging.rs     # Fresh local noise and one-use ownership
```

The bound calculator determines `B_sm`; the noise generator uses that bound;
the decryptor consumes the generated noise. The `synchronized-decryption`
feature enables synchronized decryption, PRF masks, and local noise generation.
BFV, key sharing, bound calculation, and SS decryption are always available.
SS decryption has no `ark-ff` or `e3-safe` dependency. Enabling synchronized
decryption adds its API alongside SS; it never changes an existing type's meaning.

| Cargo selection | Available decryption |
| --- | --- |
| Defaults | Both, with distinct configurations and material |
| `default-features = false` | SS smudging, no PRF dependencies |
| No defaults + `synchronized-decryption` | Both, with distinct configurations and material |

To explicitly build and test both protocols together:

```bash
cargo test -p fhe --no-default-features --features synchronized-decryption
```

`SynchronizedDecryptionConfig` and `SsSmudgingDecryptionConfig` contain
independently selected BFV parameters, committee sizes, and thresholds.
Construct synchronized decryption with `SynchronizedDecryptor::new(n, threshold, params)`
or `SynchronizedDecryptor::from_config(config)`. Select one
protocol per deployment/key epoch; coexistence is not a security claim for
cross-protocol reuse of the same key.

### Generating keys for a threshold multiplication

1. Agree on two independent uniform random strings (§4.3): the public-key vector
   `a` (called CRS in this library) and the relinearization vector `d1` (called
   URS). Each may be explicit or reproducible from a seed. For each accepted
   party, generate a `trlbfv::PublicKeyShare` with `a` and a `trlbfv::RelinKeyShare`
   with `(d1, a)`, using the **same secret summand** for both. Privately
   Shamir-share that summand with `ShareManager` for the decryption committee.
   **Generate the relinearization contribution once.** Publishing two
   independently generated contributions for the same summand with reused
   `d1` rows can reveal the summand. Use fresh, disjoint URS rows for every
   ciphertext level and ceremony; a prefix of the previous level's URS is
   reuse. All dealers in a given level's ceremony use the same agreed rows.
   Persist the public contribution bytes before first transmission. On timeout
   or restart **resend the exact bytes**, including when a witness was needed.
   If those bytes are lost, do not regenerate with the old `d1`.
2. Exchange the two typed contribution envelopes as a pair. Pass the accepted
   pairs to `trlbfv::aggregate_key_pair`; each recipient sums the Shamir shares
   from exactly those dealers. Matching rows detects inconsistent randomness,
   not duplicate contributors or inconsistent secrets. Admit at most one pair
   per authenticated dealer for each level's ceremony in the key epoch. Count
   a byte-identical retry just once. With malicious dealers, authentication
   alone does not protect **confidentiality**: a dealer that chooses its pair
   after seeing the others' contributions can arrange to know the aggregate
   decryption key. Bind the parameters, epoch, level, dealer, and pair in
   hiding, binding commitments from all dealers before revealing any pair,
   or verify proofs of knowledge and correct formation tied to the ceremony.
   A commitment prevents adaptive choice; it does not prove the Shamir shares
   use the same secret. When adding a level to an existing key, pin its original
   public-key contributions and dealer set; do not reopen public-key admission
   after the shares are public. The library does not implement these checks.
3. Use the resulting `LBFVPublicKey` to encrypt, multiply the ciphertexts, and
   call `LBFVRelinearizationKey::relinearizes` to return to two components.
   Key generation and evaluation support key level zero and ciphertext levels
   with at least two remaining moduli. Use **ciphertext level zero** for either
   threshold decryptor.
4. Use `SmudgingBoundCalculatorConfig::new_with_fresh_noise_model` and pass
   `FreshNoiseModel::LbfvPublicKey` for any l-BFV input. For one product with
   no prior additions use `m = 1` and `mult_depth = 1`; use `mult_depth = 0`
   for addition alone. The ordinary-BFV default in the v0.6 constructors
   underestimates the fresh noise of l-BFV encryptions. The RLK count
   defaults to the committee size `n`; if fewer contributed, pass their actual
   count to `with_accepted_participant_count` and use `from_bound_calculator`.
   The number of parties opening the product is a separate quantity.

[`trlbfv_mul`](../../examples/trlbfv_mul.rs) runs this flow locally with SS
decryption. [`trlbfv_e2e`](../../tests/trlbfv_e2e.rs) also exercises the
synchronized decryptor, with a separate key ceremony. Neither opening
reconstructs the joint secret.

### Compatibility with v0.6.0

Operational l-BFV public and relinearization keys generated with independent
reference strings keep their v0.6.0 wire formats. Only `PublicKeyShare` and
`RelinKeyShare` use the new contribution envelopes. The public-key share
embeds the v0.6.0 PK message; `dev`'s later compact PK format is incompatible.
That format change did not change the relinearization-share schema.

Some inputs accepted by v0.6.0 now return errors:

- Fallible l-BFV key generation requires exactly `params.degree()` secret
  coefficients. The infallible `LBFVPublicKey::new_with_seed` retains its
  v0.6.0 behavior.
- A public key's `l` and row count must match the modulus count. Its master
  seed, per-row seeds, and explicit `a` rows must agree wherever supplied.
- Reference strings cannot contain repeated rows. The RLK's URS and the PK's
  CRS must be disjoint: using the PK seed for `d1_seed` is rejected. If such
  a v0.6.0 relinearization key was published, treat its secret as compromised.
  Replace the secret and its dependent keys; generating a fresh RLK for that
  same secret does not restore confidentiality.
- An l-BFV key-switching component must encode `c1` explicitly or by seed,
  never both. The shared polynomial decoder also requires the serialized
  degree to match the supplied context.

### Test organization and parameter sets

Each protocol has one integration-test file, with `insecure::` and `secure::`
sections:

- [`trbfv_sync_dec.rs`](../../tests/trbfv_sync_dec.rs): synchronized decryption.
- [`trbfv_ss_dec.rs`](../../tests/trbfv_ss_dec.rs): SS decryption.

The insecure sections cover small/synthetic parameter sets, API validation,
transport, and explicitly insecure `Lambda::insecure(2)` decryption. A validated
`Lambda::secure(40)` in an existing small-ring regression does not make its BFV
parameters computationally secure.

The secure sections additionally require `experimental-mbfv` for collective-key
and encrypted-share transport. Both use the single degree-8192 regression preset
in [`support/trbfv_parameters.rs`](../../tests/support/trbfv_parameters.rs):
`n = 20`, `T = 9`, `m = 50`, `lambda = 50`, and plaintext modulus `1_000_000`.
Tests pin the calculator's expected additive noise budget, check the full strict inequality
`2 * (B_C + n * B_sm) < floor(Q / p)`, and verify that every Shamir residue fits
the transport plaintext space. SS tests encrypt both key and noise shares;
synchronized tests encrypt key shares and keep smudging local. Both exercise
positive and negative worst-case noise endpoints.

These checks establish consistency with the calculator and its default
[BFV encryption-error support bound](#sampler-specific-b_enc), not the validity
of arbitrary caller-supplied noise bounds or a complete deployment.
The `secure` label is not an independent computational-security certification.
The retained even-party preset is a compatibility regression outside Urban–Rambaud's
`n = 2T + 1` theorem; it must not be presented as a theorem-backed deployment.

## Synchronized decryption (default)

The `synchronized-decryption` feature enables threshold decryption based on
[On Threshold Fully Homomorphic Encryption with Synchronized Decryptors](https://eprint.iacr.org/2026/031)
(Colin de Verdière–Passelègue–Stehlé 2026). It is enabled by default.

```toml
# Development checkout with synchronized decryption enabled by default:
fhe = { path = "path/to/fhe.rs/crates/fhe" }
# BFV, Shamir key sharing, and SS decryption, without the optional PRF dependencies:
# fhe = { path = "path/to/fhe.rs/crates/fhe", default-features = false }
```

The module is independent of `experimental-mbfv`. Its PRF dependencies
(`ark-ff` and pinned `e3-safe`) remain optional and are activated only by
`synchronized-decryption`. Import `SynchronizedDecryptor`, `SmudgingNoiseGenerator`,
`SmudgingNoise`, `PartyPrfKeys`, `PartyPrfKeyTransport`, and `DecryptionShare`
directly from `fhe::trbfv`.

### Setup and decryption

1. Use `ShareManager::generate_secret_shares_from_poly` and
   `aggregate_collected_shares`. Convert each recipient's aggregate
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
   `SmudgingBoundCalculatorConfig` or `SmudgingBoundCalculator`, using the
   circuit assumptions and statistical policy described below.
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
A fixed regression test pins this encoding. The digest binds
the set and ciphertext coefficients, not the application session, key epoch or
parameter negotiation. Applications authenticate these separately, establish
matching pairwise keys, prevent replay, and supply any proofs of correct
decryption. `from_parts` recomputes the digest from caller-supplied context; it
does not authenticate or prove the received polynomial.

### Example and tests

```bash
cargo run --release --example trbfv_sync_dec
cargo test -p fhe
cargo test -p fhe --release --features experimental-mbfv --test trbfv_sync_dec secure::
```

The example uses the Shamir sharing API, simulates committee-key setup in
one process, and decrypts two ciphertexts with fresh local noise. Its small
parameters demonstrate mechanics only. The release integration tests also
exercise degree 8192.

## SS smudging decryption (always available)

No feature flag is required. Import `SsSmudgingDecryptor`,
`SsSmudgingDecryptionConfig`, `SsSmudgingNoiseGenerator`,
`DealerSmudgingNoise`, `DealtSmudgingShares`, `RecipientSmudgingShare`,
`AggregatedSmudgingShare`, and `SsSmudgingDecryptionShare` from `fhe::trbfv`.
The primitives do not require `experimental-mbfv` or any PRF dependency.

The SS-smudging flow is:

1. Deal and aggregate key shares using `ShareManager`. Key shares
   remain reusable and in NTT form for partial decryption.
2. Create `SsSmudgingNoiseGenerator::new(bound_config)` or
   `from_bound_calculator(calculator)`. Both use the common bound
   calculator. Its RLK-count and initial-noise overrides remain available.
3. Each dealer calls `generate`, then
    `ShareManager::generate_smudging_shares(noise, rng)`. The sampled noise owner
   is consumed, including on error. Dealing checks the polynomial's level-zero
   context, shape, storage layout, and canonical residues before sampling shares.
   Sampling uses the centered-uniform BigInt helper, not
   the synchronized RNS sampler; the same signed integer is reduced in every RNS row.
4. Consume `DealtSmudgingShares::into_transport`: each entry is a per-modulus
   `[n, degree]` matrix. Select each recipient's row and transpose into one
   `[number_of_moduli, degree]` matrix per dealer/recipient. Protect both key
   and noise shares in transit. Import received noise matrices through
   `RecipientSmudgingShare::from_transport`.
5. Call `ShareManager::aggregate_smudging_shares`, consuming those contributions
   into an `AggregatedSmudgingShare`. Nonempty subsets of at most `n`
   contributions are accepted. Recipients must agree externally on the same
   dealer set; this acceptance rule does not establish any subset's security.
6. Construct `SsSmudgingDecryptor::new(ss_config)`. After a ciphertext is
   available, call `decryption_share(&ciphertext, &key_share, aggregate_noise)`.
   This consumes the aggregate even on error, computing
   `c0 + c1 * sk_i + es_i`. No designated-set argument or PRF key is needed.
7. Collect exactly `threshold + 1` SS partials and call
   `decrypt_from_shares(&partials, &party_ids, &ciphertext)`. Party IDs are
   distinct, 1-based, and in the same order as the partials. Shamir interpolation
   recovers the phase, followed by the SS-specific scaling and decoding path.

Noise dealing can happen offline, before the ciphertext or reconstructing subset
is known. Do not reuse the resulting noise shares for a different decryption.
`AggregatedSmudgingShare::into_transport` / `from_transport` explicitly transfer
guarded ownership to/from application storage; these adapters cannot prevent
replay or rollback of saved material. No batch-ID or allocation service is added.

The explicitly low-level
`SsSmudgingNoiseGenerator::from_bound(params, bound)`: it does not check
security or correctness feasibility. Proof-producing callers can retain freshly
sampled integers and import them with
`DealerSmudgingNoise::from_signed_coefficients(&coeffs, &params)`. This checks length, not bounds,
uniformity or freshness; caller copies must be erased separately.

`SsSmudgingDecryptionShare::into_parts` / `from_parts` transport the partial
polynomial. These do not authenticate the
sender, associate the share with a ciphertext, or verify its correctness.
Decryption and reconstruction validate ciphertext structure, polynomial contexts,
matrix shapes/layouts, and canonical residues before arithmetic. Imported key and
noise coefficients are rebuilt into fresh constant-time polynomial storage so
caller-supplied lazy/timing metadata cannot control secret polynomial operations.
Never pass SS partials to synchronized FinDec, or local synchronized noise
to the SS protocol. Explicit raw transport is a trust boundary, not a proof.

```bash
cargo test -p fhe --no-default-features --test trbfv_ss_dec
cargo run --release --example trbfv_add_ss_smudging --no-default-features --features experimental-mbfv
cargo test -p fhe --release --no-default-features --features experimental-mbfv --test trbfv_ss_dec secure::
```

The example uses degree-8192 parameters. Self-contained unit and integration tests
cover signed sampling, RNS conversion, dealing/transport, aggregation,
interpolation, decryption, and encryption of both key and noise shares, including
worst-case `n * B_sm` noise. The SS decoder remains separate: it does not
include the synchronized decoder's extensions for a first RNS modulus too small
to hold scaled plaintexts.
For example, the `q0 = 1153, t = 4099` SS-decoder regression yields `639` for an
input of `4098`; this is recorded behavior, not supported-correctness guidance.

## Protocol boundaries

Import public types directly from `fhe::trbfv`; `ss/` and `synchronized/` are
private implementation modules. The protocols reuse key-sharing arithmetic and
the bound calculator, but have distinct configurations, noise owners, and partials.

**Transport incompatibility between protocols:** SS partials include `c0` and require Shamir
interpolation after collection. Synchronized partials already weight the key
term locally, do **not** include `c0`, and carry set/ciphertext metadata. Sum
exactly one typed share from each designated party and add `c0` once. Never
apply post-share Lagrange weighting to synchronized shares, feed SS shares
to synchronized aggregation, or deal noise for the synchronized protocol.
Use each protocol's `into_parts` / `from_parts` adapters at its transport boundary.

Key shares are reusable within a protocol and key epoch. For synchronized decryption, agree on exactly `threshold + 1`
distinct party IDs, matching pairwise keys, BFV parameters, ciphertext, and
authenticated session/key epoch **before** producing partials. Pairwise key
establishment, authenticated transport, replay prevention and proofs remain
application responsibilities; the example helper only simulates external setup.

**Synchronized witness API:** retain freshly and independently sampled centered integers for
the proof witness, and pass them through the generator's
`wrap_signed_coefficients`. Bound/length validation does not prove freshness or
uniform sampling, and caller copies must be erased separately. Call
`generator.wrap_signed_coefficients(&coeffs)` so the generator supplies the
parameters, committee size, and calculated bound.

## Noise and Correctness Formulas (Urban–Rambaud 2024)

Both protocols use the same bound calculator. This section summarises the formulas
implemented in [`smudging.rs`](smudging.rs). See the paper for full derivations.

### Delta and the strict correctness inequality

The plaintext scaling factor is `Delta = floor(Q / p)`:

```text
2 * (B_C + n * B_sm) < Delta
```

where
- `Q` is the product of all CRT moduli,
- `p` is the plaintext modulus,
- `n` is the total number of parties,
- `B_C` is the ciphertext noise infinity-norm bound after circuit evaluation,
- `B_sm` is the smudging-noise coefficient bound.

Equality (`>=`) is **rejected**: a smudging bound that merely meets `Delta` does
not guarantee correct decryption.

Only `|S| = threshold + 1` parties add local noise in synchronized decryption,
so their worst-case sum is `|S| * B_sm`. The calculator retains the conservative
`n * B_sm` correctness budget; `n` is not the number of partials to collect.
For SS smudging, this budgets the dealer contributions.
Do not replace `n` by the number of reconstructing parties or reinterpret the
RLK contributor count as a noise-dealer count. `m` is addition fan-in in both flows.

### Ciphertext noise recursion (multiplicative circuits)

Let `mult_depth` be the number of multiplication levels.

- **Initial bound:** `B_C^(0)` is either the computed
  `m * (B_fresh + Q mod p)` or a caller-injected bound (see
  [`SmudgingBoundCalculator::with_initial_ciphertext_noise_bound`](smudging.rs)).
  `B_fresh` itself is derived from the encryption-noise and key-norm bounds,
  using the sampler-specific `B_enc` (see below). For ring degree `N`,

  ```text
  B_fresh = N * ||u||∞ * public_key_error + B_enc + N * B_e * secret_key_bound
  ```

  Ordinary BFV (the default) samples ternary `u`, so `||u||∞ ≤ 1`.
  For `LBFVPublicKey` encryption, select `FreshNoiseModel::LbfvPublicKey`:
  the centered-binomial sampler gives `||u||∞ ≤ 2 * params.variance()`.
  Only the term multiplying the public-key error changes. Ciphertext bytes
  do not identify the sampler. This adapts the fresh-noise bound of Appendix
  C.3, Eq. (25), for correctness and for the `B_C / B_sm` condition in
  §7.1, Eq. (8).

  The second condition in Eq. (8) concerns joint-key encryption. Section 4.3
  samples `u` from the key distribution, and Appendix D.2, Lemma 23 uses
  `||u||∞ ≤ 1`. Under its other norm bounds, the two terms masked by the
  encryption error have norms at most `N * n * B` and `N * n * B * ||u||∞`,
  where `B` bounds each small error. With the v0.6 l-BFV sampler, that step
  would require `N * n * B * (1 + 2 * params.variance()) / B_enc` to be
  negligible in `lambda`, in place of `2 * N * n * B / B_enc`. The calculator
  does not check this condition; callers choose the encryption-error
  distribution through `error1_variance`. The norm bound alone does not
  establish Lemma 23 for this sampler.

- **Recursion** (Prop.&nbsp;20 of Urban–Rambaud 2024):

  ```text
  B_C^(i+1) = 2 * p * N^2 * ||sk||_inf * B_C^i + B_relin
  ```

  where
  - `p` is the plaintext modulus,
  - `N` is the polynomial ring degree,
  - `||sk||_inf` is the secret-key infinity-norm bound,
  - `B_relin` is the relinearisation error bound (Eq.&nbsp;30 of the paper)
    with **aggregate RLK error** `r * B_e`, where `r` is the
    `accepted_participant_count` (the size of the *l*-BFV accepted set).

- **Smudging bound:** `B_sm = 2^(lambda + 1) * N * B_C`, where
  `lambda` is the statistical security parameter (see
  [`MIN_SECURE_LAMBDA`](smudging.rs)) and `N` is the polynomial ring degree.
  The degree factor accounts for a transcript containing `N` noisy coefficients;
  the factor of 2 retains the calculator's constant convention. This is a
  whole-transcript bound, not a single-coefficient budget.

### Sampler-specific `B_enc`

The calculator derives `B_enc` from the support of the configured
[BFV encryption-error `e1` sampler](../../../fhe-math/src/rq/mod.rs), not either
protocol's smudging-noise sampler. This bound feeds `B_C` and therefore the
smudging bound for both protocols.

| Sampler branch | `B_enc` value |
| -------------- | ------------- |
| CBD (error1 variance `<= 16`) | `2 * error1_variance` |
| Uniform (error1 variance `> 16`, including non-`u64` values) | Smallest integer `B` with `B * (B + 1) >= 3 * error1_variance` |

The uniform branch calls the same `variance_to_uniform_bound` helper as the
sampler, including its exact discrete-uniform rounding. Thus variance 16 has
`B_enc = 32`, while variance 20 has `B_enc = 8`.

For a different encryption path, callers must justify its actual noise bounds
and can set `SmudgingBoundCalculatorConfig::b_enc` explicitly before constructing
a calculator. Custom noise/key bounds and circuit assumptions remain the
caller's responsibility; passing the feasibility check is not a deployment
security certification.

`SmudgingBoundCalculatorConfig::new` and
`SmudgingBoundCalculatorConfig::new_multiplicative` are fallible: they reject
zero parties or zero ciphertexts before a calculator is created and propagate
encryption-error support calculation failures. The calculator also revalidates
these counts before performing the bound computation.

## Known Limitations

### Fresh local noise

Every partial-decryption call consumes a non-cloneable, zeroizing
`SmudgingNoise` owner, including on validation failure. Sample independently
for every call, even when repeating the same ciphertext and designated set.
The witness-wrapping API cannot enforce how caller-supplied integers were sampled.

### One-use SS noise and variable-time arithmetic

SS noise must be freshly sampled and dealt for each decryption. Reusing it
across ciphertexts cancels the masking noise when partials are subtracted.
Non-cloneable owners enforce only in-memory consumption. Applications must
protect transported material and prevent persisted copies from being reused.
Recipient shares are Shamir evaluations, not coefficients bounded by `B_sm`.
Partial-decryption products, recovered RNS coefficients, decoding scratch space,
and common dealing/aggregation buffers have zeroizing owners. Drop cleanup also
covers malformed imported matrix layouts. Borrowed key shares and copies made
outside these owners remain the application's responsibility.
BigInt sampling and interpolation are variable-time. RNS owners do not erase
all temporary BigInt allocations or make this arithmetic constant-time.

### Even-`n` party counts

Party counts where `n` is even are accepted for compatibility, but
Urban–Rambaud&nbsp;2024 proves security only for odd `n` (under the
`n = 2T + 1` honest-majority model). Even-`n` deployments fall outside the
paper's theorem and have not been independently analyzed.

### Incomplete protocol orchestration

This module implements sharing, smudging, and decryption — it does **not**
include the complete robust protocol stack from Urban–Rambaud&nbsp;2024:
- The distributed l-BFV key arithmetic does not implement robust dealer agreement or prove correct shares.
- No authenticated broadcast channel.
- No `F_LSS` preprocessing or `G_URS` setup.
- No proactive refresh or identifiable-abort mechanisms.

Callers who need full end-to-end robust threshold FHE must provide these
components externally.

### `MIN_SECURE_LAMBDA` is a statistical-hiding policy

[`MIN_SECURE_LAMBDA`](smudging.rs) is a policy threshold for statistical hiding — a larger
`lambda` produces a stronger noise-flooding guarantee.  It is **not** a
computational-security bound or a claim about bit-security.  See the
[`Lambda`](smudging.rs) type documentation. Use `Lambda::secure` to check the
minimum; constructing a public enum variant directly bypasses that constructor check.

## Usage

See [`trbfv_add.rs`](../../examples/trbfv_add.rs) for simulated collective-key setup and
synchronized addition/decryption, and [`trbfv_add_bfv_share.rs`](../../examples/trbfv_add_bfv_share.rs)
for BFV-encrypted key-share transport. The `_insecure` variant also encrypts
key shares but explicitly uses insecure statistical noise. These local
simulations are not a complete robust or authenticated protocol.

The example can be run with configurable parameters (threshold must equal `(num_parties - 1) / 2`):
```bash
cargo run --release --example trbfv_add --features experimental-mbfv -- --num_parties=7 --threshold=3
```

For an SS partial, the caller supplies a reusable aggregate NTT key share and
a fresh, already-dealt aggregate noise owner. The owner is consumed by the call:

```rust
use fhe::bfv::Ciphertext;
use fhe::trbfv::{
    AggregatedSmudgingShare, SsSmudgingDecryptionConfig,
    SsSmudgingDecryptionShare, SsSmudgingDecryptor,
};
use fhe_math::rq::{Ntt, Poly};

fn ss_partial(
    config: SsSmudgingDecryptionConfig,
    ciphertext: &Ciphertext,
    key_share: &Poly<Ntt>,
    noise: AggregatedSmudgingShare,
) -> Result<SsSmudgingDecryptionShare, fhe::Error> {
    let decryptor = SsSmudgingDecryptor::new(config);
    decryptor.decryption_share(ciphertext, key_share, noise)
}
```

Full, runnable workflows are in the examples linked above and in
[`trbfv_add_ss_smudging.rs`](../../examples/trbfv_add_ss_smudging.rs).

## Security Considerations

This implementation has not been independently audited. Examples and test presets
are not security certifications or complete deployment protocols.

The security of the threshold scheme relies on:
- Proper parameter selection for the underlying BFV scheme
- Secure distribution of shares among parties
- Protection of individual secret key shares
- Appropriate smudging noise generation

Note that the Shamir secret sharing operations use arbitrary-precision integer
arithmetic that is not constant-time. Applications must assess timing and
co-location threats in their actual execution environment; the library does not
establish that secret-dependent timing is unobservable.
