# Threshold BFV (TRBFV)

A pure-Rust implementation of threshold BFV homomorphic encryption. Shamir
sharing of the secret key follows Antoine Urban and Matthieu Rambaud in
[Robust Multiparty Computation from Threshold Encryption Based on RLWE](https://eprint.iacr.org/2024/1285.pdf)
(Urban–Rambaud 2024). Partial decryption follows Colin de Verdière, Alain
Passelègue, and Damien Stehlé in
[On Threshold Fully Homomorphic Encryption with Synchronized Decryptors](https://eprint.iacr.org/2026/031.pdf)
(eprint 2026/031): the designated decryptor set `S` is known up front, each
party applies its Lagrange coefficient locally, adds fresh smudging noise, and
masks the share with committee PRF keys.

The current implementation covers Shamir sharing, local smudging noise, PRF
masks, and threshold decryption with additive and limited multiplicative
support via distributed *l*-BFV relinearization keys. It is **not** the
complete robust protocol from Urban–Rambaud 2024: there is no distributed key
generation, no broadcast channel, no FLSS, and no GURS generation. Committee
PRF keys are sampled locally as uniformly random 256-bit strings and
evaluated with Poseidon2 through the SAFE sponge API.

This module enables distributed decryption between `n` parties without necessarily involving all of them: any `threshold + 1` of the `n` parties can decrypt a ciphertext, while any coalition of at most `threshold` parties learns nothing. The threshold must be exactly `(n-1)/2` (integer division), the maximal corruption tolerance under an honest majority — see `config.rs` for the derivation.

## Implementation Boundary

This crate exposes the cryptographic component used by a threshold FHE
application. It does not expose the complete multiparty protocol described in
the paper. The following table is the boundary for callers and integrators:

| Paper or application component | Responsibility |
| ------------------------------ | -------------- |
| BFV and l-BFV operations (Sections 4 and 6) | Implemented by `fhe.rs`. |
| Shamir sharing, share aggregation, smudging bounds, PRF masks, and threshold decryption | Implemented by `fhe.rs`. |
| DKG, PVSS, FLSS, and GURS | Must be supplied externally. |
| Authenticated transport, broadcast, retries, and identifiable aborts | Must be supplied externally. |
| Committee membership, accepted-party policy, and application lifecycle | Must be supplied externally. |
| ZK proofs and application wire formats | Must be supplied externally. |

The public trBFV setup and decryption flow is:

1. Create a `ShareManager` instance with BFV parameters.
2. Generate and distribute Shamir shares for each party's secret contribution.
3. Sample committee PRF keys once with `PartyPrfKeys::generate_committee(n, rng)`
   and securely distribute each party's `2n` keys. This is independent of
   `ShareManager`. Applications that move keys across a transport boundary use
   `PartyPrfKeys::into_transport` / `from_transport`.
4. Aggregate the received secret-key contributions for the same externally
   agreed party set.
5. For a designated decryptor set `S` of size `threshold + 1`, each party in
   `S` samples local smudging noise and computes a partial decryption.
6. Sum the `|S|` partial decryptions (FinDec) to recover the plaintext.

`PartyPrfKeys::generate_committee` returns all parties' key bundles to its
caller. It is suitable for local simulations or a trusted setup; it performs no
network exchange or secret sharing. Distributed applications must securely
establish matching pairwise keys externally rather than invoking this factory
independently on each node.

The examples in `crates/fhe/examples/` simulate the external setup and share
transport locally. They demonstrate the supported component flow, but they do
not implement DKG, authenticated broadcast, PVSS, ZK validation, or the paper's
robustness protocol.

Paper-conforming deployments use odd `n` with `n = 2t + 1`. The current API
also accepts even `n` for compatibility; those deployments are an
implementation-specific extension and must not be presented as covered by the
paper's theorem. The API likewise does not bind a contribution matrix to a
party identity or session, so callers must enforce a common participant set and
identity/session binding at their protocol boundary.

## Architecture

The module follows a modular design with clear separation of concerns:

- `rns_shamir.rs` - crate-private direct RNS Shamir arithmetic
- `prf.rs` - committee PRF keys and partial-decryption masks
- `smudging/` - Smudging noise generation with optimal variance calculation using arbitrary precision arithmetic
- `shares/` - typed secret-key share owners, aggregation, and partial decryption
- `config.rs` - Parameter validation
- `errors.rs` - Threshold-specific error types

The former public `trbfv::shamir` module and `ShamirSecretSharing` type were
removed when share generation and reconstruction moved to direct RNS
arithmetic. Callers should use `ShareManager`; its high-level share
generation, aggregation, and reconstruction APIs retain the same logical share
layout.

> **Breaking change:** the `TRBFV` orchestrator struct has been removed;
> `ShareManager` is the single public trBFV type (`ShareManager::
> decrypt_from_shares` is the former `TRBFV::decrypt`). Partial decryption
> no longer consumes Shamir-shared smudging noise.
> `ShareManager::generate_smudging_shares` has been removed. Callers sample
> local noise at decryption time and pass committee PRF keys into
> `decryption_share` together with the designated set `S`. FinDec sums the
> partial decryptions instead of Lagrange-reconstructing them. Smudging
> noise is generated with `SmudgingConfig::new` (chain `.with_mult_depth(depth)`
> when needed) → `SmudgingNoiseGenerator::new` → `generate`. The sampled
> `SmudgingNoise` owner is consumed by `decryption_share`. Secret-key
> material uses the typed owners `DealtSecretKeyShares`, `SecretKeyShare`,
> and `AggregatedSecretKeyShare`. `ShareManager::bigints_to_poly` has been
> removed.

## Noise and Correctness Formulas

This section summarises the formulas implemented in
[`smudging/`](smudging/). Ciphertext-noise growth follows Urban–Rambaud 2024
(Prop. 20 and Eq. 30). The smudging bound instantiates
`B_SM = Ω(2^λ · B_Dec)` from the 2026 synchronized-decryptor paper, with
`B_Dec` taken to be this crate's `B_C` after circuit evaluation.

### Delta and the strict correctness inequality

BFV encodes a plaintext `m` as `Δ · m` with scaling factor
`Δ = ⌊Q / t⌋`. Rounding back to the nearest multiple of `Δ` is correct only
when the total noise is strictly less than half a gap, `Δ / 2`:

```text
2 * (B_C + n * B_sm) < Δ
```

where
- `Q` is the product of all CRT moduli,
- `t` is the plaintext modulus,
- `n` is the total number of parties (used even when only `|S| = threshold + 1`
  parties smudge; this is conservative),
- `B_C` is the ciphertext noise infinity-norm bound after circuit evaluation,
- `B_sm` is the smudging-noise coefficient bound.

`SmudgingNoiseGenerator::new` also requires `2 * B_C < Δ` before adding
smudging. Equality is rejected on both checks (`>= Δ`): a bound that only
meets `Δ / 2` does not guarantee correct rounding.

### Ciphertext noise recursion (multiplicative circuits)

Let `d` be the polynomial ring degree, `ℓ` the number of CRT moduli,
`B_g` the largest CRT modulus, and `mult_depth` the number of multiplication
levels. The code uses `||sk||_∞ = n` and `B_e = 2 · variance` (the BFV
error-polynomial variance, distinct from `error1_variance` used for `B_enc`).

- **Fresh encryption noise:**

  ```text
  ||e_ek||_∞ = n * (2 * variance)
  B_fresh    = d * ||e_ek||_∞ + B_enc + d * B_e * ||sk||_∞
  ```

  `B_enc` comes from the error sampler (see below).

- **Initial bound** (additive circuit, `mult_depth = 0`):

  ```text
  B_C^(0) = m * (B_fresh + (Q mod t))
  ```

- **Recursion** (Prop. 20 of Urban–Rambaud 2024), applied `mult_depth` times:

  ```text
  B_C^(i+1) = 2 * k * d^2 * ||sk||_∞ * B_C^(i) + B_relin
  ```

  with `k = t`. The relinearisation error (Eq. 30) uses aggregate RLK error
  `B_e^agg = n * B_e`:

  ```text
  B_relin = d * ℓ * ||sk||_∞ * B_g * B_e^agg
          + 2 * d^2 * ℓ^2 * ||sk||_∞^2 * B_g * B_e^agg
  ```

  Using all `n` parties is conservative when fewer relinearization
  contributions are aggregated.

- **Smudging bound:**

  ```text
  B_sm = 2^(lambda + 1) * d * B_C
  ```

  `lambda` is the statistical security parameter. The extra factor `2 * d`
  is the whole-transcript policy (issue #108): a single decryption reveals
  all `d` coefficients of the smudging noise at once, so a union bound over
  the coefficients adds a factor `d`, and `2^(lambda + 1)` keeps the
  constant-`2` convention of the correctness inequality. The older form
  `B_sm = 2^lambda * B_C` only bounds the statistical distance for a
  *single* coefficient and is not what this module implements.

### Sampler-specific `B_enc`

`B_enc` is the worst-case coefficient magnitude returned by
`fhe_math::rq::error_coefficient_bound(error1_variance)`. This shared helper
selects the same CBD or uniform sampler as `Poly::conditional_error`, so the
smudging bound tracks the encryption sampler's actual coefficient bound.

`SmudgingConfig::new` is fallible: it rejects zero parties, zero ciphertexts,
and unsupported lambda values. Its fields are private; use accessors to inspect
them and `.with_mult_depth(depth)` before passing the config to
`SmudgingNoiseGenerator::new`. The generator checks feasibility, including
during the multiplicative-depth recursion.

## Known Limitations

### One-time local noise

Smudging noise generated by [`SmudgingNoiseGenerator`] is **one-time
material** that must never be reused across decryptions. Noise is sampled
inside PartDec and consumed by `decryption_share`; it is not Shamir-shared
at setup. The type is non-cloneable, so safe Rust cannot pass one live
`SmudgingNoise` into two decryption calls. Serialized copies of PRF keys
or share matrices can still be replayed, so authenticated transport and
durable replay prevention remain the integrator's responsibility.

Secret-key share material follows a reusable-owner path. Dealing
returns a non-cloneable `DealtSecretKeyShares`; applications explicitly convert
the per-`q_i` output at their transport boundary into `SecretKeyShare`
values. `aggregate_secret_key_shares` consumes those owners and returns a
non-cloneable `AggregatedSecretKeyShare`, which is borrowed by each decryption
call and zeroized when the key epoch ends. This allows multiple decryptions with
one aggregated key while keeping the in-memory owner protected.

### Even-`n` party counts

Party counts where `n` is even are accepted for compatibility, but
Urban–Rambaud&nbsp;2024 proves security only for odd `n` (under the
`n = 2t + 1` honest-majority model).  Even-`n` deployments fall outside the
paper's theorem and have not been independently analyzed.

### Incomplete protocol orchestration

This module implements sharing, local smudging, PRF masks, and decryption —
it does **not** include the complete robust protocol stack from
Urban–Rambaud&nbsp;2024:
- No distributed key generation (DKG).
- No authenticated broadcast channel.
- No FLSS pre-processing or GURS generation.
- No proactive refresh or identifiable-abort mechanisms.
- The PRF is Poseidon2 via the SAFE sponge (`e3-safe`).

Callers who need full end-to-end robust threshold FHE must provide these
components externally.

### `lambda` is a caller-chosen policy

The statistical security parameter `lambda` is a plain `usize` in
`0..=smudging::MAX_LAMBDA`. A larger `lambda` produces a stronger noise-flooding
guarantee — it is **not** a computational-security bound or a claim about
bit-security. The library enforces only representability: values above
`smudging::MAX_LAMBDA` are rejected, while values below the deployment's own
policy minimum are accepted and are simply weaker. Since achievability
depends on the full parameter set (degree, moduli, plaintext modulus,
circuit depth), the library does not impose a universal minimum; callers
validate against their own policy.

## Usage

For a complete working example demonstrating multi-party setup, share distribution, and threshold decryption, see [`examples/trbfv_add.rs`](../../examples/trbfv_add.rs). A variant that transports secret-key Shamir shares encrypted under per-party BFV keys is in [`examples/trbfv_add_bfv_share.rs`](../../examples/trbfv_add_bfv_share.rs). A multiplicative example using distributed *l*-BFV relinearization keys is in [`examples/trbfv_mul_bfv_share.rs`](../../examples/trbfv_mul_bfv_share.rs).

The example can be run with configurable parameters (threshold must equal `(num_parties - 1) / 2`):
```bash
cargo run --release --example trbfv_add -- --num_parties=10 --threshold=4
```

Decrypting two ciphertexts with the same committee keys (a fresh mask `H(S, ct)` per ciphertext) is in [`examples/trbfv_two_ciphertexts.rs`](../../examples/trbfv_two_ciphertexts.rs):
```bash
cargo run --release --example trbfv_two_ciphertexts
```

Basic usage pattern:

```rust
use fhe::trbfv::{
    PartyPrfKeyMaterial, PartyPrfKeys, SecretKeyShare, ShareManager, SmudgingConfig,
    SmudgingNoiseGenerator,
};

// Setup threshold scheme; each party holds its own manager instance
let share_manager = ShareManager::new(n_parties, threshold, params.clone())?;

// Each party: deal secret shares of its key contribution.
let secret_key_dealt = share_manager.generate_secret_key_shares(secret_key_poly, &mut rng)?;
// Explicit application transport boundary; the dealt owner is consumed here.
let secret_key_dealt = secret_key_dealt.into_transport();

// Simulation or trusted setup: sample committee PRF keys once, independently
// of ShareManager, and securely give party i its 2n keys. Distributed key
// establishment is external; do not sample independently on each node.
let prf_keys = PartyPrfKeys::generate_committee(n_parties, &mut rng)?;
let transported = prf_keys[party_index].clone().into_transport();
let prf_keys_i = PartyPrfKeys::from_transport(PartyPrfKeyMaterial::new(
    transported.party_id(),
    transported.party_count(),
    transported.outgoing().to_vec(),
    transported.incoming().to_vec(),
)?)?;

// Each party: aggregate the share matrices received from the other parties
// into its share of the joint secret key
let secret_key_aggregate = share_manager.aggregate_secret_key_shares(
    collected_secret_key
        .into_iter()
        .map(SecretKeyShare::from_transport)
        .collect(),
)?;

// Designated set S. Each decrypting party samples local smudging and
// computes PartDec.
let config = SmudgingConfig::new(
    params.clone(), n_parties, num_ciphertexts, lambda,
)?.with_mult_depth(mult_depth);
let generator = SmudgingNoiseGenerator::new(config)?;
let es_noise = generator.generate(&mut rng)?;
let decryption_share = share_manager.decryption_share(
    &ciphertext,
    &secret_key_aggregate,
    party_id,
    &reconstructing_parties,
    es_noise,
    &prf_keys_i,
)?;

// Combine exactly threshold + 1 typed decryption shares. Each share is bound
// to its party, designated set S, and H(S, ct); FinDec rejects mixed sets.
let plaintext =
    share_manager.decrypt_from_shares(&decryption_shares, &ciphertext)?;
```

`decryption_share` borrows the ciphertext and aggregated secret-key share
but consumes the one-time `SmudgingNoise`. It returns a `DecryptionShare`
bound to the party, designated set, and ciphertext. After transport, rebuild
the share with `DecryptionShare::from_parts` (the digest is recomputed from
`S` and `ct`). `decrypt_from_shares` borrows those shares and the ciphertext.

## Security Considerations

This implementation has not been independently audited. Use with appropriate caution in production environments.

The security of the threshold scheme relies on:
- Proper parameter selection for the underlying BFV scheme
- Secure distribution of shares among parties
- Protection of individual secret key shares and committee PRF keys
- Fresh local smudging noise at each partial decryption

Shamir secret sharing operates directly on canonical RNS residues. Operations
on secret coefficients use the constant-time `Modulus` arithmetic; Lagrange
inversion depends only on public party coordinates and prime ciphertext
moduli.
