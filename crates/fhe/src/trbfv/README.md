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
PRF keys are sampled locally as uniformly random 256-bit strings; Poseidon
(SAFE API) will replace the ChaCha expander later.

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

The public `ShareManager` flow is:

1. Create a `ShareManager` instance with BFV parameters.
2. Generate and distribute Shamir shares for each party's secret contribution.
3. Sample committee PRF keys (`ShareManager::generate_prf_keys`) and give each
   party its `2n` keys.
4. Aggregate the received secret-key contributions for the same externally
   agreed party set.
5. For a designated decryptor set `S` of size `threshold + 1`, each party in
   `S` samples local smudging noise and computes a partial decryption.
6. Sum the `|S|` partial decryptions (FinDec) to recover the plaintext.

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

- `../rns_shamir.rs` - crate-private direct RNS Shamir arithmetic shared by threshold schemes
- `prf.rs` - committee PRF keys and partial-decryption masks
- `smudging.rs` - Smudging noise generation with optimal variance calculation using arbitrary precision arithmetic  
- `shares.rs` - Share aggregation and decryption operations management
- `config.rs` - Parameter validation
- `errors.rs` - Threshold-specific error types

The former public `trbfv::shamir` module and `ShamirSecretSharing` type were
removed when share generation and reconstruction moved to direct RNS
arithmetic. Callers should use `ShareManager`; its high-level share
generation, aggregation, and reconstruction APIs retain the same logical share
layout.

> **Breaking change:** partial decryption no longer consumes Shamir-shared
> smudging noise. `ShareManager::generate_secret_shares_from_smudging_noise`
> has been removed. Callers sample local noise at decryption time and pass
> committee PRF keys into `decryption_share` together with the designated
> set `S`. FinDec sums the partial decryptions instead of Lagrange-
> reconstructing them.

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

- **Initial bound:** `B&#x1d9c;&sup0;` = `m &middot; (B_fresh + Q mod t)`
  `B_fresh` itself is derived from the encryption-noise and key-norm bounds,
  using the sampler-specific `B_enc` (see below).

- **Recursion** (Prop.&nbsp;20 of Urban–Rambaud 2024):

  > `B&#x1d9c;&sup1;&plus;&sup1; = 2&middot;k&middot;N&sup2;&middot;||sk|| &middot; B&#x1d9c;&sup1; + B_relin`

  where
  - `k = t` (plaintext modulus),
  - `N` is the polynomial ring degree,
  - `||sk||` is the secret-key infinity-norm bound,
  - `B_relin` is the relinearisation error bound (Eq.&nbsp;30 of the paper)
    with **aggregate RLK error** `n &middot; B_e`. This is conservative when fewer
    than all `n` relinearization contributions are aggregated.

- **Smudging bound:** `B&#x209b;&#x2098; = 2^(lambda + 1) &middot; d &middot; B&#x1d9c;` where
  `lambda` is the statistical security parameter and `d` is the polynomial
  ring degree. The extra
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
| CBD (error1 variance `<= 16` as `u64`)    | `2 &middot; error1_variance` |
| Uniform (larger / non-`u64` variance)     | Smallest `B` with `B(B + 1) >= 3 &middot; error1_variance` |

This matches the branches chosen by `Poly::conditional_error` in `fhe-math`.

`SmudgingConfig::new` is fallible: it rejects zero parties, zero ciphertexts,
and unsupported lambda values. `SmudgingNoiseGenerator::new` revalidates the
public configuration fields before computing the bound.

## Known Limitations

### One-time local noise

Smudging noise generated by [`SmudgingNoiseGenerator`] is **one-time
material** that must never be reused across decryptions.  The current API does
**not** track or enforce consumption — callers are responsible for freshness.
Noise is sampled inside PartDec; it is not Shamir-shared at setup.

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
- The PRF is a ChaCha expander until Poseidon is wired in.

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

For a complete working example demonstrating multi-party setup, share distribution, and threshold decryption, see [`examples/trbfv_add.rs`](../../examples/trbfv_add.rs). A variant that transports the Shamir shares encrypted under per-party BFV keys is in [`examples/trbfv_add_bfv_share.rs`](../../examples/trbfv_add_bfv_share.rs). A multiplicative example using distributed *l*-BFV relinearization keys is in [`examples/trbfv_mul_bfv_share.rs`](../../examples/trbfv_mul_bfv_share.rs).

The example can be run with configurable parameters (threshold must equal `(num_parties - 1) / 2`):
```bash
cargo run --release --example trbfv_add -- --num_parties=10 --threshold=4
```

Basic usage pattern:

```rust
use fhe::trbfv::{
    ShareManager, SmudgingConfig, SmudgingNoiseGenerator,
};

// Setup threshold scheme; each party holds its own manager instance
let mut share_manager = ShareManager::new(n_parties, threshold, params.clone())?;

// Each party: deal secret shares of its key contribution.
let sk_shares = share_manager.generate_secret_shares_from_poly(sk_poly, &mut rng)?;

// Committee: sample PRF keys once and give party i its 2n keys.
let prf_keys = share_manager.generate_prf_keys(&mut rng)?;

// Each party: aggregate the share matrices received from the other parties
// into its share of the joint secret key
let sk_poly_sum = share_manager.aggregate_collected_shares(&collected_sk_shares)?;

// Designated set S. Each decrypting party samples local smudging and
// computes PartDec.
let mut config = SmudgingConfig::new(
    params.clone(), n_parties, num_ciphertexts, lambda,
)?;
config.mult_depth = mult_depth;
let generator = SmudgingNoiseGenerator::new(config)?;
let es_noise = generator.generate(&mut rng)?;
let d_share = share_manager.decryption_share(
    ciphertext.clone(),
    sk_poly_sum.into_ntt(),
    party_id,
    &reconstructing_parties,
    es_noise,
    &prf_keys[party_index],
)?;

// Combine exactly threshold + 1 decryption shares; reconstructing_parties
// holds the 1-based indices of the parties the shares came from
let plaintext = share_manager.decrypt_from_shares(d_share_polys, reconstructing_parties, ciphertext)?;
```

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
